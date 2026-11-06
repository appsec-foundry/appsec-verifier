"""Obtain and cache a session per test identity, and return the headers to
attach to target requests (VER-028).

Credentials and tokens come from environment variables named by the identity
(`*_env`); their values are never logged, returned in any structure other than
the request header, or placed in a report (VER-016). Every credential is sent
only to the endpoint the identity names, and that endpoint is authorised by the
ScopeGuard (purpose="auth"), so it must be the target or a scope `auth_hosts`
entry. A token is fetched once per role and reused; `invalidate()` drops it so a
401 can trigger a transparent refresh.
"""

from __future__ import annotations

import base64


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
        headers = self._acquire(ident.get("method", "none"), ident.get("auth") or {})
        self._cache[role] = headers
        return dict(headers)

    def invalidate(self, role: str) -> None:
        self._cache.pop(role, None)

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
            raise AuthError("form login did not return a recognisable token")
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
            raise AuthError(f"OIDC {grant} grant did not return an access token")
        return {"Authorization": f"Bearer {token}"}
