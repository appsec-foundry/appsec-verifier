"""Obtain and cache a session per test identity, and return the headers to
attach to target requests (VER-028).

Credentials and tokens come from environment variables named by the identity
(`*_env`); their values are never logged, returned in any structure other than
the request header, or placed in a report (VER-016). Every credential is sent
only to the endpoint the identity names, and that endpoint is authorised by the
ScopeGuard (purpose="auth"), so it must be the target or a scope `auth_hosts`
entry. A token is fetched once per role and reused. A login the target refused
is not tried again in the run, so a run cannot lock the test account. After a
401, `renew()` drops the session so the next request logs in again; when the
request is answered 401 again with the new session, the 401 is the target's
answer to that request, not an expired session, and the role is not logged in
again until one of its requests is accepted.

`redact()` replaces every credential value the run knows (the identities'
`*_env` values and every header value and token obtained from them, also
JSON-escaped and URL-encoded) with "[redacted]". The agent loop applies it to
every tool result before the planner sees it, and the runner to the results
before the report is written (VER-016). Values shorter than 4 characters are
not replaced, because they would mask ordinary text.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote, quote_plus

REDACTED = "[redacted]"
_MIN_SECRET_LEN = 4


class AuthError(Exception):
    """A test identity could not obtain a session. Fails closed (VER-028)."""


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


class SessionManager:
    def __init__(self, identities: list[dict], http, *, env=None):
        self._by_role = {i["role"]: i for i in identities if i.get("role")}
        self._http = http                      # GuardedHttpClient
        if env is None:
            import os
            env = os.environ
        self._env = env
        self._cache: dict[str, dict] = {}
        self._cookie_secrets: set[str] = set()
        self._issued: set[str] = set()         # header values and tokens obtained, kept after invalidate()
        self._refused: dict[str, str] = {}     # role -> why its session could not be obtained
        self._renewed: set[str] = set()        # roles renewed after a 401 and not accepted since
        self._no_renewal: set[str] = set()     # roles whose renewal was answered 401 again

    def _env_get(self, name: str | None) -> str:
        value = self._env.get(name) if name else None
        if not value:
            raise AuthError(f"missing environment variable {name!r} for a test identity")
        return value

    def headers_for(self, role: str) -> dict:
        """Headers to attach to target requests for `role`. Cached per role."""
        if role in self._cache:
            return dict(self._cache[role])
        ident = self._by_role.get(role)
        if ident is None:
            raise AuthError(f"unknown identity role {role!r}")
        if role in self._refused:
            raise AuthError(f"{self._refused[role]}; not tried again in this run")
        try:
            headers = self._acquire(ident.get("method", "none"), ident.get("auth") or {})
        except AuthError as exc:
            self._refused[role] = str(exc)
            raise
        for value in headers.values():
            self._issued.update((value, value.partition(" ")[2]))   # "Bearer <token>" and the bare token
        self._cache[role] = headers
        return dict(headers)

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

    def _secret_forms(self) -> list[str]:
        values = set(self._issued)
        for ident in self._by_role.values():
            for key, name in (ident.get("auth") or {}).items():
                if key.endswith("_env") and name and self._env.get(name):
                    values.add(self._env[name])
        forms = set()
        for v in values:
            if len(v) >= _MIN_SECRET_LEN or v in self._cookie_secrets:
                forms.update((v, json.dumps(v)[1:-1], quote(v, safe=""), quote_plus(v)))
        return sorted(forms, key=len, reverse=True)      # longest first, so no fragment of a value is left

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

    # ── per-method acquisition ────────────────────────────────────────────────

    def _acquire(self, method: str, auth: dict) -> dict:
        if method == "none":
            return {}
        if method == "bearer":
            return {"Authorization": f"Bearer {self._env_get(auth.get('token_env'))}"}
        if method == "basic":
            raw = f"{self._env_get(auth.get('username_env'))}:{self._env_get(auth.get('password_env'))}".encode()
            return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
        if method == "form":
            return self._form_login(auth)
        if method == "oidc-password":
            return self._oidc(auth, grant="password")
        if method == "oidc-client-credentials":
            return self._oidc(auth, grant="client_credentials")
        if method == "oidc-authorization-code":
            raise AuthError("oidc-authorization-code is not implemented yet (browser-driven flow)")
        raise AuthError(f"unknown auth method {method!r}")

    def _form_login(self, auth: dict) -> dict:
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
        return {"Authorization": f"Bearer {token}"}

    def _oidc(self, auth: dict, *, grant: str) -> dict:
        token_url = auth.get("token_url")
        if not token_url:
            raise AuthError("OIDC flow needs a token_url")
        data = {"grant_type": grant}
        if auth.get("client_id"):
            data["client_id"] = auth["client_id"]
        if auth.get("client_id_env"):
            data["client_id"] = self._env_get(auth["client_id_env"])
        if auth.get("client_secret_env"):
            data["client_secret"] = self._env_get(auth["client_secret_env"])
        if auth.get("scope"):
            data["scope"] = auth["scope"]
        if grant == "password":
            data["username"] = self._env_get(auth.get("username_env"))
            data["password"] = self._env_get(auth.get("password_env"))
        resp = self._http.request("POST", token_url, {"Accept": "application/json"},
                                  purpose="auth", data=data)
        token = _extract_token(resp)
        if not token:
            raise AuthError(f"OIDC {grant} grant did not return an access token (HTTP {resp.status_code})")
        return {"Authorization": f"Bearer {token}"}
