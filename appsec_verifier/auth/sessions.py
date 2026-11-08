"""Obtain and cache a session per test identity, and return the headers to
attach to target requests (VER-016, VER-028, VER-040).

A session is the set of headers an identity attaches to its own origin
(`target_origin`, else the target base URL), with an optional expiry. It comes
from environment variables (`bearer`, `basic`, `session`), from a login the
Verifier performs (`form`, the OIDC grants), or from the operator's login
program (`command`, see program.py). Secret values are named by `*_env`
variables (or `headers_env`); the `env` mapping may also hold values the
operator entered hidden in an interactive run. Values are never logged,
returned in any structure other than the request header, or placed in a report
(VER-016).

Every credential is sent only to the endpoint the identity names, or that its
issuer's discovery document names, and every such request goes through the
GuardedHttpClient with purpose="auth", so the endpoint must be the target or a
scope `auth_hosts` entry. The operator's browser is sent only to an authorize
URL the scope allows for authentication. The authorization-code and
device-code flows need a person: they run only while `ui` is set and before
`end_interactive()`, which the run calls before its first finding; later such
a session that cannot be renewed makes its identity unavailable, without a
prompt (VER-028).

A session is obtained once per role and reused. One whose expiry is known is
renewed shortly before it: with the refresh token where the flow issued one,
else by logging in again where the method can. A static session that has
expired is not used. A login the target refused, or a renewal that failed, is
not tried again in the run, so a run cannot lock the test account. After a
401, `renew()` drops the session so the next request logs in again; when the
request is answered 401 again with the new session, the 401 is the target's
answer to that request, not an expired session, and the role is not logged in
again until one of its requests is accepted.

`redact()` replaces every credential value the run knows (the identities'
`*_env` values and every header value, cookie value and token obtained from
them, also JSON-escaped and URL-encoded) with "[redacted]". The agent loop
applies it to every tool result before the planner sees it, and the runner to
the results before the report is written (VER-016). Values shorter than 4
characters are not replaced, because they would mask ordinary text.

`accounts()` names the account a role's token belongs to (`iss` and `sub` of
an unverified JWT), so the pre-flight check can refuse two roles that are the
same account (VER-010, VER-032).
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, quote_plus

REDACTED = "[redacted]"
_MIN_SECRET_LEN = 4
RENEW_MARGIN_S = 60                      # renew a session this long before it expires
INTERACTIVE_METHODS = ("oidc-authorization-code", "oidc-device-code")
LOGIN_METHODS = ("form", "oidc-password", "oidc-client-credentials", *INTERACTIVE_METHODS, "command")
STATIC_METHODS = ("bearer", "basic", "session")

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
# Never set by an identity: they change how the request is framed or routed, not who sends it.
_FORBIDDEN_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive",
    "proxy-authorization", "proxy-connection", "expect", "content-type",
})
_MAX_HEADER_VALUE = 16 * 1024
_ERROR_CODE = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")


class AuthError(Exception):
    """A test identity could not obtain a session. Fails closed (VER-028)."""


def header_problem(name, value=None) -> str | None:
    """Why `name` (and `value`) cannot be an identity header, or None. A value may not
    contain CR, LF, NUL or other control characters, which could split the request."""
    if not isinstance(name, str) or not _HEADER_NAME.match(name):
        return f"{str(name)[:40]!r} is not a valid header name"
    if name.lower() in _FORBIDDEN_HEADERS:
        return f"header {name} cannot be set by an identity"
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return f"header {name} has no value"
    if len(value) > _MAX_HEADER_VALUE:
        return f"header {name} is longer than {_MAX_HEADER_VALUE // 1024} KiB"
    if any(ord(ch) < 0x20 and ch != "\t" or ord(ch) == 0x7F for ch in value):
        return f"header {name} contains a control character"
    return None


def jwt_claims(token: str) -> dict | None:
    """The payload of a JWT, unverified, or None. Used only to read `exp`, `iss` and
    `sub` of a token the run already holds; never to decide whom to trust."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _bearer_token(headers: dict) -> str | None:
    value = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def _extract_token(resp) -> str | None:
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    for key in ("access_token", "token", "id_token", "jwt"):
        if body.get(key):
            return str(body[key])
    nested = body.get("authentication")
    if isinstance(nested, dict) and nested.get("token"):
        return str(nested["token"])
    return None


def _json(resp) -> dict:
    try:
        body = resp.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def _error_code(body: dict) -> str:
    """The OAuth `error` code of a response, if it is a plain code; never free text (VER-016)."""
    code = body.get("error")
    return f" ({code})" if isinstance(code, str) and _ERROR_CODE.match(code) else ""


@dataclass
class Session:
    headers: dict
    expires_at: float | None = None      # epoch seconds, when known
    renewable: bool = True               # False: the value is fixed (env, pasted), a new login cannot change it
    refresh_token: str | None = None
    account: tuple[str, str] | None = None   # (iss, sub) of the token, when it is a JWT that names them
    renew_at: float | None = None            # set when kept: when to renew a renewable session


class SessionManager:
    def __init__(self, identities: list[dict], http, *, env=None, ui=None, base_dir=None,
                 clock=time.time, sleep=time.sleep, run_program=None):
        self._by_role = {i["role"]: i for i in identities if i.get("role")}
        self._http = http                      # GuardedHttpClient
        if env is None:
            import os
            env = os.environ
        self._env = env
        self._ui = ui                          # LoginUI in an interactive run, else None
        self._base_dir = Path(base_dir) if base_dir else Path.cwd()
        self._clock = clock
        self._sleep = sleep
        self._run_program = run_program
        self._cache: dict[str, Session] = {}
        self._refresh: dict[str, str] = {}     # role -> refresh token, kept across invalidate()
        self._accounts: dict[str, tuple[str, str]] = {}
        self._discovery: dict[str, dict] = {}
        self._cookie_secrets: set[str] = set()
        self._issued: set[str] = set()         # header values and tokens obtained, kept after invalidate()
        self._refused: dict[str, str] = {}     # role -> why its session could not be obtained
        self._renewed: set[str] = set()        # roles renewed after a 401 and not accepted since
        self._no_renewal: set[str] = set()     # roles whose renewal was answered 401 again

    # ── public interface ─────────────────────────────────────────────────────

    def headers_for(self, role: str) -> dict:
        """Headers to attach to target requests for `role`. Cached per role and
        renewed before a known expiry (VER-028)."""
        ident = self._by_role.get(role)
        if ident is None:
            raise AuthError(f"unknown identity role {role!r}")
        cached = self._cache.get(role)
        if cached is not None:
            now = self._clock()
            if cached.renew_at is None or now < cached.renew_at:
                return dict(cached.headers)
            if not cached.renewable and now < cached.expires_at:
                return dict(cached.headers)     # nothing can renew it; use it while it lasts
            self._cache.pop(role, None)
        if role in self._refused:
            raise AuthError(f"{self._refused[role]}; not tried again in this run")
        try:
            session = self._obtain(role, ident)
        except AuthError as exc:
            self._refused[role] = str(exc)
            raise
        self._keep(role, session)
        return dict(session.headers)

    def end_interactive(self) -> None:
        """No more logins that need a person: the run is about to test findings (VER-028)."""
        self._ui = None

    def accounts(self) -> dict[str, tuple[str, str]]:
        """Role -> (iss, sub) for every role whose token names its account."""
        return dict(self._accounts)

    def invalidate(self, role: str) -> None:
        self._cache.pop(role, None)

    def remember_secret(self, value: str) -> None:
        """Keep observed session values out of later responses, prompts and evidence (VER-016)."""
        self._issued.add(value)
        self._cookie_secrets.add(value)

    def renew(self, role: str) -> bool:
        """After a 401 for `role`: drop its session so the next headers_for() logs in again, and return True;
        False, keeping the session, while a renewal was already answered 401 and nothing accepted since (VER-028)."""
        if role in self._no_renewal:
            return False
        self.invalidate(role)
        self._renewed.add(role)
        return True

    def answered(self, role: str, status) -> None:
        """Note the target's answer to a request sent with `role`'s session."""
        if status != 401:
            self._renewed.discard(role)
            self._no_renewal.discard(role)
        elif role in self._renewed:
            self._renewed.discard(role)
            self._no_renewal.add(role)

    def redact(self, value):
        """`value` (str, or dicts and lists of them) with every credential value
        replaced by "[redacted]" (VER-016). Other types pass unchanged."""
        forms = self._secret_forms()

        def walk(v):
            if isinstance(v, str):
                for form in forms:
                    v = v.replace(form, REDACTED)
                return v
            if isinstance(v, dict):
                return {k: walk(x) for k, x in v.items()}
            if isinstance(v, list | tuple):
                return [walk(x) for x in v]
            return v

        return walk(value)

    def origin_for(self, role: str) -> str | None:
        """The identity's declared `target_origin`, or None for the target base
        URL. Its credentials are attached only to that origin (VER-018)."""
        ident = self._by_role.get(role) or {}
        return (ident.get("auth") or {}).get("target_origin") or None

    # ── bookkeeping ──────────────────────────────────────────────────────────

    def _keep(self, role: str, session: Session) -> None:
        for name, value in session.headers.items():
            self._issued.update((value, value.partition(" ")[2]))   # "Bearer <token>" and the bare token
            if name.lower() == "cookie":
                for part in value.split(";"):
                    self._issued.add(part.partition("=")[2].strip())
        self._issued.discard("")
        self._http.protect_headers(session.headers)
        if session.refresh_token:
            self._refresh[role] = session.refresh_token
            self._issued.add(session.refresh_token)
        if session.account:
            self._accounts[role] = session.account
        session.renew_at = self._renew_at(session)
        self._cache[role] = session

    def _renew_at(self, session: Session) -> float | None:
        """A minute before the expiry, but not before half the lifetime has passed, so a short-lived token is
        not renewed on every request. A renewable token that looks expired when issued (the clocks differ) is
        renewed only after a 401. A static session is due at its expiry."""
        if session.expires_at is None:
            return None
        if not session.renewable:
            return session.expires_at
        now = self._clock()
        if session.expires_at <= now:
            return None
        return max(session.expires_at - RENEW_MARGIN_S, now + (session.expires_at - now) / 2)

    def _secret_forms(self) -> list[str]:
        values = set(self._issued)
        for ident in self._by_role.values():
            for name in _env_names(ident.get("auth") or {}):
                if self._env.get(name):
                    values.add(self._env[name])
        forms = set()
        for v in values:
            if len(v) >= _MIN_SECRET_LEN or v in self._cookie_secrets:
                forms.update((v, json.dumps(v)[1:-1], quote(v, safe=""), quote_plus(v)))
        return sorted(forms, key=len, reverse=True)      # longest first, so no fragment of a value is left

    def _env_get(self, name: str | None) -> str:
        value = self._env.get(name) if name else None
        if not value:
            raise AuthError(f"missing environment variable {name!r} for a test identity")
        return value

    # ── acquisition ──────────────────────────────────────────────────────────

    def _obtain(self, role: str, ident: dict) -> Session:
        method, auth = ident.get("method", "none"), ident.get("auth") or {}
        refresh = self._refresh.get(role)
        if refresh:
            try:
                return self._refreshed(auth, refresh)
            except AuthError:
                self._refresh.pop(role, None)
                if method in INTERACTIVE_METHODS and self._ui is None:
                    raise AuthError(f"{method}: the session expired and its renewal failed; a new sign-in "
                                    "needs a person, so this identity is unavailable for the rest of the run") from None
        session = self._acquire(role, method, auth)
        if not session.renewable and session.expires_at is not None and self._clock() >= session.expires_at:
            raise AuthError(f"{method}: the session has expired; supply a fresh one")
        return session

    def _acquire(self, role: str, method: str, auth: dict) -> Session:
        if method == "none":
            return Session({}, renewable=False)
        if method == "bearer":
            return self._static({"Authorization": f"Bearer {self._env_get(auth.get('token_env'))}"})
        if method == "basic":
            raw = f"{self._env_get(auth.get('username_env'))}:{self._env_get(auth.get('password_env'))}".encode()
            return Session({"Authorization": "Basic " + base64.b64encode(raw).decode()}, renewable=False)
        if method == "session":
            return self._static(self._session_headers(auth))
        if method == "form":
            return self._form_login(auth)
        if method == "oidc-password":
            return self._grant(auth, {"grant_type": "password",
                                      "username": self._env_get(auth.get("username_env")),
                                      "password": self._env_get(auth.get("password_env"))})
        if method == "oidc-client-credentials":
            return self._grant(auth, {"grant_type": "client_credentials"})
        if method in INTERACTIVE_METHODS:
            if self._ui is None:
                raise AuthError(f"{method} needs a person to sign in, and this run cannot ask one now")
            from . import interactive
            endpoints = self._endpoints(auth)
            if method == "oidc-authorization-code":
                data = interactive.authorization_code(self._http, auth, endpoints, self._client_id(auth),
                                                      self._ui, role=role)
                return self._grant(auth, data)
            resp = interactive.device_code(self._http, auth, endpoints, self._client_fields(auth), self._ui,
                                           role=role, sleep=self._sleep, clock=self._clock,
                                           remember=self._issued.add)
            return self._token_session(resp, auth, "device_code")
        if method == "command":
            from . import program
            headers, expires_at = program.obtain(auth, base_dir=self._base_dir, interactive=self._ui is not None,
                                                 run=self._run_program, clock=self._clock)
            return self._with_token_facts(Session(headers, expires_at=expires_at))
        raise AuthError(f"unknown auth method {method!r}")

    def _static(self, headers: dict) -> Session:
        return self._with_token_facts(Session(headers, renewable=False))

    def _session_headers(self, auth: dict) -> dict:
        headers = {}
        for name, var in (auth.get("headers_env") or {}).items():
            value = self._env_get(var)
            problem = header_problem(name, value)
            if problem:
                raise AuthError(f"session: {problem}")
            headers[name] = value
        if not headers:
            raise AuthError("session: headers_env names no header")
        return headers

    def _with_token_facts(self, session: Session) -> Session:
        """Expiry and account from a bearer JWT, where the session did not say."""
        claims = jwt_claims(_bearer_token(session.headers) or "")
        if claims:
            if session.expires_at is None and isinstance(claims.get("exp"), int | float):
                session.expires_at = float(claims["exp"])
            session.account = session.account or _account(claims)
        return session

    def _form_login(self, auth: dict) -> Session:
        login_url = auth.get("login_url")
        if not login_url:
            raise AuthError("form login needs a login_url")
        payload = {
            auth.get("username_field", "username"): self._env_get(auth.get("username_env")),
            auth.get("password_field", "password"): self._env_get(auth.get("password_env")),
        }
        resp = self._http.request("POST", login_url, {"Accept": "application/json"},
                                  purpose="auth", json=payload)
        token = _extract_token(resp)
        if not token:
            raise AuthError(f"form login did not return a recognisable token (HTTP {resp.status_code})")
        return self._with_token_facts(Session({"Authorization": f"Bearer {token}"}))

    # ── OAuth / OIDC ─────────────────────────────────────────────────────────

    def _endpoints(self, auth: dict) -> dict:
        """token, authorization and device endpoints: as given, else from the issuer's discovery document.
        The GuardedHttpClient refuses a request to one the scope does not allow for authentication; the
        authorize URL, which only the operator's browser opens, is checked here (VER-028, VER-029)."""
        found = {"token": auth.get("token_url"), "authorize": auth.get("authorize_url"),
                 "device": auth.get("device_url")}
        issuer = auth.get("issuer")
        if issuer and not all(found.values()):
            doc = self._discover(issuer)
            for key, field in (("token", "token_endpoint"), ("authorize", "authorization_endpoint"),
                               ("device", "device_authorization_endpoint")):
                found[key] = found[key] or (doc.get(field) if isinstance(doc.get(field), str) else None)
        if found["authorize"]:
            decision = self._http.authorize(found["authorize"], "auth")
            if not decision.allowed:
                raise AuthError(f"the authorize endpoint is refused for authentication: {decision.reason}")
        return found

    def _discover(self, issuer: str) -> dict:
        if issuer in self._discovery:
            return self._discovery[issuer]
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        resp = self._http.request("GET", url, {"Accept": "application/json"}, purpose="auth")
        doc = _json(resp)
        if not 200 <= resp.status_code < 300 or not doc:
            raise AuthError(f"the issuer's discovery document could not be read (HTTP {resp.status_code})")
        if str(doc.get("issuer", "")).rstrip("/") != issuer.rstrip("/"):
            raise AuthError("the discovery document names another issuer")
        self._discovery[issuer] = doc
        return doc

    def _client_id(self, auth: dict) -> str | None:
        if auth.get("client_id_env"):
            return self._env_get(auth["client_id_env"])
        return auth.get("client_id") or None

    def _client_fields(self, auth: dict) -> tuple[dict, dict]:
        """Client authentication as (form fields, headers): the secret in the body (client_secret_post, the
        default) or as HTTP Basic (client_secret_basic, RFC 6749 2.3.1); a public client sends only its id."""
        client_id = self._client_id(auth)
        secret = self._env_get(auth["client_secret_env"]) if auth.get("client_secret_env") else None
        if secret and auth.get("client_auth") == "basic":
            if not client_id:
                raise AuthError("client_auth basic needs a client_id")
            pair = f"{quote_plus(client_id or '')}:{quote_plus(secret)}".encode()
            return {}, {"Authorization": "Basic " + base64.b64encode(pair).decode()}
        fields = {"client_id": client_id} if client_id else {}
        if secret:
            fields["client_secret"] = secret
        return fields, {}

    def _grant(self, auth: dict, data: dict) -> Session:
        """One token request to the identity's token endpoint; the session carries the chosen token, its
        expiry and the refresh token, where the response has them."""
        endpoints = self._endpoints(auth)
        if not endpoints["token"]:
            raise AuthError("OIDC flow needs a token_url or an issuer")
        fields, headers = self._client_fields(auth)
        body = {**fields, **data}
        if data.get("grant_type") in ("password", "client_credentials"):   # the other grants asked for them earlier
            body.update({key: auth[key] for key in ("scope", "audience", "resource") if auth.get(key)})
        resp = self._http.request("POST", endpoints["token"], {"Accept": "application/json", **headers},
                                  purpose="auth", data=body)
        return self._token_session(resp, auth, str(data.get("grant_type")))

    def _refreshed(self, auth: dict, refresh_token: str) -> Session:
        session = self._grant(auth, {"grant_type": "refresh_token", "refresh_token": refresh_token})
        session.refresh_token = session.refresh_token or refresh_token
        return session

    def _token_session(self, resp, auth: dict, grant: str) -> Session:
        body = _json(resp)
        key = "id_token" if auth.get("token") == "id" else "access_token"
        token = body.get(key)
        if not 200 <= resp.status_code < 300 or not isinstance(token, str) or not token:
            raise AuthError(f"OIDC {grant.rsplit(':', 1)[-1]} grant did not return an {key.replace('_', ' ')} "
                            f"(HTTP {resp.status_code}){_error_code(body)}")
        session = Session({"Authorization": f"Bearer {token}"})
        lifetime = body.get("expires_in")
        if isinstance(lifetime, int | float) and not isinstance(lifetime, bool) and lifetime > 0:
            session.expires_at = self._clock() + float(lifetime)
        refresh = body.get("refresh_token")
        session.refresh_token = refresh if isinstance(refresh, str) and refresh else None
        id_claims = jwt_claims(body.get("id_token")) if isinstance(body.get("id_token"), str) else None
        if isinstance(body.get("id_token"), str):
            self._issued.add(body["id_token"])
        session.account = _account(id_claims or {})
        return self._with_token_facts(session)


def _account(claims: dict) -> tuple[str, str] | None:
    sub = claims.get("sub")
    return (str(claims.get("iss", "")), str(sub)) if isinstance(sub, str | int) and str(sub) else None


def _env_names(auth: dict) -> list[str]:
    names = [name for key, name in auth.items() if key.endswith("_env") and isinstance(name, str) and name]
    names += [name for name in (auth.get("headers_env") or {}).values() if isinstance(name, str) and name]
    return names
