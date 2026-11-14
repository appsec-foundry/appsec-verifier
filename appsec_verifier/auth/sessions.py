"""Obtain and cache a session per test identity, and return the headers to
attach to target requests (VER-016, VER-028, VER-040, VER-062).

A session is the set of headers an identity attaches to its own origin
(`target_origin`, else the target base URL), with an optional expiry. It comes
from environment variables (`bearer`, `basic`, `session`), from a login the
Verifier performs (`form`, the OIDC grants), or from the operator's login
program (`command`, see program.py). Secret values are named by `*_env`
variables (or `headers_env`), a user name by `username_env`; the `env`
mapping may also hold values the operator entered hidden in an interactive run. Values are never logged,
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

A session is obtained once per role and reused. A declared login-cookie check may repeat a configured form
login once per role, retaining only the issuing requests and value-free cookie observations (VER-062).
One whose expiry is known is
renewed shortly before it: with the refresh token where the flow issued one,
else by logging in again where the method can. A static session that has
expired is not used. A login the target refused, or a renewal that failed, is
not tried again in the run, so a run cannot lock the test account. After a
401, `renew()` drops the session so the next request logs in again; when the
request is answered 401 again with the new session, the 401 is the target's
answer to that request, not an expired session, and the role is not logged in
again until one of its requests is accepted.

`redact()` replaces every credential value the run knows (the identities'
`*_env` values but their user names, which are no secret, and every header
value, cookie value and token obtained from them, also JSON-escaped and
URL-encoded) with a placeholder naming its account and kind, such as
"[account-1 password]", or "[redacted]" where no single one does. The agent loop
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
from urllib.parse import quote, quote_plus, urljoin, urlsplit

from ..tools.http import same_origin

REDACTED = "[redacted]"
_MIN_SECRET_LEN = 4
RENEW_MARGIN_S = 60                      # renew a session this long before it expires
_FORM_REDIRECTS = 5                      # redirects an HTML form login follows within its origin
_HTML_ACCEPT = "text/html,application/xhtml+xml,*/*;q=0.8"
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
                 clock=time.time, sleep=time.sleep, run_program=None, target: str | None = None):
        self._by_role = {i["role"]: i for i in identities if i.get("role")}
        self._http = http                      # GuardedHttpClient
        self._target = target                  # the target URL, which an HTML form login is checked against
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
        self._issued_by: dict[str, str] = {}   # issued value -> the role whose session it is, for its placeholder
        self._refused: dict[str, str] = {}     # role -> why its session could not be obtained
        self._renewed: set[str] = set()        # roles renewed after a 401 and not accepted since
        self._login_cookie_observations: list[dict] = []
        self._observing_role = None
        self._cookie_repeated: set[str] = set()
        self._no_renewal: set[str] = set()     # roles whose renewal was answered 401 again

    # ── public interface ─────────────────────────────────────────────────────

    def headers_for(self, role: str) -> dict:
        """Headers to attach to target requests for `role`. Cached per role and
        renewed before a known expiry (VER-028)."""
        ident = self._by_role.get(role)
        if ident is None:
            available = ", ".join(sorted(self._by_role)) or "no identities configured"
            raise AuthError(f"unknown identity role {role!r}; available: {available}")
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

    def sign_in_with_fields(self, role: str, candidates: list[tuple[str, str]]) -> tuple[str, str]:
        """VER-041: log the `form` identity `role` in with the first (username_field, password_field) pair whose
        login obtains a session, at most two attempts, and return the pair the login used (an HTML login form
        names its own fields). That pair, and the login page found from the target URL, are kept on the identity
        for renewals. When none works, the role is refused for the rest of the run, like any rejected login
        (VER-028)."""
        ident = self._by_role.get(role)
        if ident is None or ident.get("method") != "form":
            raise AuthError(f"unknown form identity {role!r}")
        if role in self._refused:
            raise AuthError(f"{self._refused[role]}; not tried again in this run")
        auth, tried, cause = ident.setdefault("auth", {}), [], ""
        for username_field, password_field in candidates[:2]:
            attempt = dict(auth, username_field=username_field, password_field=password_field)
            tried.append(f"{username_field}/{password_field}")
            try:
                session = self._acquire(role, "form", attempt)
            except AuthError as exc:
                cause = f": {exc}"
                continue
            except Exception as exc:      # not a refused login: stop, and never fall back to default fields
                self._refused[role] = f"form login failed ({type(exc).__name__})"
                raise
            ident["auth"] = attempt
            self._keep(role, session)
            return attempt["username_field"], attempt["password_field"]
        self._refused[role] = f"form login obtained no session with the fields {', '.join(tried)}{cause}"
        raise AuthError(self._refused[role])

    def refuse(self, role: str, reason: str) -> None:
        """`role` obtains no session in this run; asking for one names `reason` and logs nothing in (VER-028)."""
        self._refused[role] = reason

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
        """`value` (str, or dicts and lists of them) with every credential value replaced by its placeholder
        (VER-016), in one pass, so no replacement is made inside a placeholder. Other types pass unchanged."""
        placeholders = self._placeholders()
        pattern = re.compile("|".join(map(re.escape, sorted(placeholders, key=len, reverse=True)))) \
            if placeholders else None       # longest first, so no fragment of a value is left

        def walk(v):
            if isinstance(v, str):
                return pattern.sub(lambda m: placeholders[m.group(0)], v) if pattern else v
            if isinstance(v, dict):     # keys too: a target may key its answer by a token or session id
                return {walk(k): walk(x) for k, x in v.items()}
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
        values = set()
        for name, value in session.headers.items():
            values.update((value, value.partition(" ")[2]))   # "Bearer <token>" and the bare token
            if name.lower() == "cookie":
                values.update(part.partition("=")[2].strip() for part in value.split(";"))
        if session.refresh_token:
            self._refresh[role] = session.refresh_token
            values.add(session.refresh_token)
        values.discard("")
        self._issued.update(values)
        self._issued_by.update(dict.fromkeys(values, role))
        self._http.protect_headers(session.headers)
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

    def _placeholders(self) -> dict[str, str]:
        """Each form of each secret value the run knows (as is, JSON-escaped, URL-encoded) -> its placeholder
        (VER-016): `[<role> <kind>]` where one account holds it as one kind of secret, such as `[account-1
        password]` or `[account-1 session]` for what its session obtained, else `[redacted]`: for a value several
        accounts or kinds share, one no account obtained, one that is also a user name (its label would tell that
        user name and secret are equal) and one whose label would carry a secret."""
        found: dict[str, set[str]] = {}
        for value in self._issued:
            role = self._issued_by.get(value)
            found.setdefault(value, set()).add(f"[{role} session]" if role else REDACTED)
        users = set()
        for role, ident in self._by_role.items():
            auth = ident.get("auth") or {}
            users.add(self._env.get(auth.get("username_env") or "") or "")
            for key, name in _secret_vars(auth):
                if self._env.get(name):
                    found.setdefault(self._env[name], set()).add(f"[{role} {_KINDS.get(key, 'secret')}]")
        values = {v for v in found if len(v) >= _MIN_SECRET_LEN or v in self._cookie_secrets}
        out: dict[str, str] = {}
        for value in values:
            labels = found[value]
            label = labels.pop() if len(labels) == 1 else REDACTED
            if value in users or any(v in label for v in values):
                label = REDACTED
            for form in (value, json.dumps(value)[1:-1], quote(value, safe=""), quote_plus(value)):
                out[form] = label if out.get(form, label) == label else REDACTED
        return out

    def holds_placeholder(self, text: str) -> bool:
        """Whether `text` holds a placeholder of a secret value, so it does not show the value (VER-016)."""
        return REDACTED in text or any(label in text for label in set(self._placeholders().values()))

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

    def _observe_cookies(self, response, method, url):
        from ..agent.session_proof import cookie_observations

        cookies = cookie_observations(response, self)
        if self._observing_role and cookies and len(self._login_cookie_observations) < 100:
            self._login_cookie_observations.append({
                "observation_id": len(self._login_cookie_observations) + 1,
                "role": self._observing_role, "method": method,
                "path": urlsplit(url).path or "/",
                "origin": urlsplit(url)._replace(path="", query="", fragment="").geturl(),
                "status": response.status_code, "session_cookies": cookies})

    def observe_login(self, role):
        """Repeat a configured noninteractive login once, retaining only cookie facts (VER-062)."""
        ident = self._by_role.get(role, {})
        if ident.get("method") != "form" or role in self._refused:
            raise AuthError("cookie observation needs an available configured form login")
        self.headers_for(role)
        if role not in self._cookie_repeated:
            self._cookie_repeated.add(role)
            session = self._acquire(role, "form", ident["auth"])
            self._keep(role, session)
        return [dict(o) for o in self._login_cookie_observations if o["role"] == role]

    def _acquire(self, role: str, method: str, auth: dict) -> Session:
        previous, start = self._observing_role, len(self._login_cookie_observations)
        self._observing_role = role
        try:
            return self._acquire_impl(role, method, auth)
        except Exception:
            del self._login_cookie_observations[start:]
            raise
        finally:
            self._observing_role = previous

    def _acquire_impl(self, role: str, method: str, auth: dict) -> Session:
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
        """Where `login_url` serves an HTML login form, submit it as a browser does and take the token the login
        returns or else the cookies it sets; otherwise POST the user name and password as JSON and take the token
        (VER-028, VER-041). With `login_from_target` (VER-041), `login_url` is the target URL, the login form is
        the one it shows or redirects to, and the form may send the password to any address on that origin;
        `login_url` becomes the page found. `auth` keeps the field names the HTML form used."""
        from . import html_login

        login_url, found = auth.get("login_url"), bool(auth.get("login_from_target"))
        if not login_url:
            raise AuthError("form login needs a login_url")
        user = (auth.get("username_field", "username"), self._env_get(auth.get("username_env")))
        password = (auth.get("password_field", "password"), self._env_get(auth.get("password_env")))
        cookies: dict[str, str] = {}
        page, page_url = self._exchange("GET", login_url, cookies)
        form = html_login.find_form(page.text) if html_login.is_html(page) and 200 <= page.status_code < 300 else None
        if form is None and found:
            raise AuthError("form login: the target URL leads to no HTML login form; give the login endpoint with "
                            "--login-url")
        if form is None:
            resp = self._http.request("POST", login_url, {"Accept": "application/json"},
                                      purpose="auth", json={user[0]: user[1], password[0]: password[1]})
            self._observe_cookies(resp, "POST", login_url)
            token = _extract_token(resp)
            if not token:
                raise AuthError(f"form login did not return a recognisable token (HTTP {resp.status_code})")
            return self._with_token_facts(Session({"Authorization": f"Bearer {token}"}))
        if form.method != "post":
            raise AuthError("form login: the login form sends GET, which would put the password in the URL")
        action = urljoin(page_url, form.action) if form.action else page_url
        if not same_origin(action, login_url) or (not found and urlsplit(action).path != urlsplit(login_url).path):
            raise AuthError("form login: the login form at login_url sends the password to another address, "
                            "and credentials go only to login_url")
        data, auth["username_field"], auth["password_field"] = html_login.submission(form, user, password)
        resp, landed = self._exchange("POST", action, cookies, data=data)
        token = _extract_token(resp)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        if not token and not 200 <= resp.status_code < 300:
            raise AuthError(f"form login: the login form was answered HTTP {resp.status_code}")
        if not token and html_login.is_html(resp) and html_login.find_form(resp.text):
            raise AuthError("form login ended on the login form again; check the user name and password")
        self._check_target(page_url, landed, cookies, headers)
        if found:
            auth["login_url"] = page_url          # renewals start at the page found
        if token:
            return self._with_token_facts(Session(headers))
        cookie = "; ".join(f"{name}={value}" for name, value in cookies.items())
        problem = header_problem("Cookie", cookie) if cookie else "the login set no cookie"
        if problem:
            raise AuthError(f"form login: {problem}")
        return Session({"Cookie": cookie})

    def _check_target(self, login_page: str, landed: str, cookies: dict, headers: dict) -> None:
        """After an HTML form login the target URL must no longer lead to the login form; where it still does, the
        target did not take the login, e.g. because it sent it to a setup page, and the cause names the page the
        login `landed` on (VER-041). Skipped where the target URL is the login page itself or on another origin.
        Cookies the target sets meanwhile join the session."""
        from . import html_login

        target = self._target
        if not target or not same_origin(target, login_page) or \
                (urlsplit(target).path or "/") == (urlsplit(login_page).path or "/"):
            return
        resp, _ = self._exchange("GET", target, cookies, headers)
        if 200 <= resp.status_code < 300 and html_login.is_html(resp) and html_login.find_form(resp.text):
            page = urlsplit(landed).path.split(";", 1)[0] or "/"      # no parameters such as ;jsessionid, no query
            led = "" if page == (urlsplit(login_page).path or "/") else f"the login led to {self.redact(page)}, but "
            raise AuthError(f"form login: {led}the target URL still leads to the login form after the login, so the "
                            "target did not accept it")

    def _exchange(self, method: str, url: str, cookies: dict, extra: dict | None = None, **body):
        """One request of an HTML form login and its redirects within the origin, each sent with the cookies set
        so far, because the GuardedHttpClient keeps none, and the `extra` headers. A redirect is followed as a
        GET. Returns the last answer and its URL."""
        from . import html_login

        for hop in range(_FORM_REDIRECTS + 1):
            headers = {"Accept": _HTML_ACCEPT, **(extra or {})}
            if cookies:
                headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
            resp = self._http.request(method, url, headers, purpose="auth", follow_redirects=False, **body)
            self._observe_cookies(resp, method, url)
            html_login.keep_cookies(resp, cookies, self._clock())
            found = getattr(resp, "headers", None) or {}
            location = found.get("Location") or found.get("location")
            try:
                target = urljoin(url, location) if location and 300 <= resp.status_code < 400 else None
            except ValueError:
                target = None
            if target is None or hop == _FORM_REDIRECTS or not same_origin(target, url):
                return resp, url
            method, url, body = "GET", target, {}

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


# What a secret variable holds, as its placeholder names it (VER-016); another `*_env` is a "secret".
_KINDS = {"password_env": "password", "token_env": "token", "client_secret_env": "client secret",
          "client_id_env": "client id", "headers_env": "session"}


def _secret_vars(auth: dict) -> list[tuple[str, str]]:
    """(key, variable) of each variable that holds an identity's secret: every `*_env` but `username_env`, and each
    of `headers_env`. A user name identifies an account without granting access, so it is no secret (VER-016); one
    that equals a secret of the run is still replaced as that secret."""
    names = [(key, name) for key, name in auth.items()
             if key.endswith("_env") and key != "username_env" and isinstance(name, str) and name]
    names += [("headers_env", name) for name in (auth.get("headers_env") or {}).values()
              if isinstance(name, str) and name]
    return names
