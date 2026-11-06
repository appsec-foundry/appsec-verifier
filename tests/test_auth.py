"""Session acquisition sends credentials only to the bound, in-scope endpoint,
reads secrets from env, caches tokens, and fails closed (VER-016, VER-028)."""

from __future__ import annotations

import base64

import pytest

from appsec_verifier.auth import AuthError, SessionManager
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, ScopeViolation

SCOPE = {
    "base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
    "schemes": ["https"], "path_prefixes": ["/"], "auth_hosts": ["sso.example.com:443"],
}


class FakeResp:
    def __init__(self, status=200, json=None):
        self.status_code = status
        self._json = json
        self.headers = {}

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeTransport:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers, **kw):
        self.calls.append((method, url, headers, kw))
        if url == "https://sso.example.com/token":
            return FakeResp(200, {"access_token": "OIDCTOK"})
        if url == "https://app.example.com/rest/user/login":
            return FakeResp(200, {"authentication": {"token": "FORMTOK"}})
        return FakeResp(200, {})


def _mgr(identities, env, transport=None):
    transport = transport or FakeTransport()
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), transport)
    return SessionManager(identities, http, env=env), transport


def test_bearer_from_env_no_request():
    mgr, tr = _mgr([{"role": "svc", "method": "bearer", "auth": {"token_env": "BTOK"}}], {"BTOK": "xyz"})
    assert mgr.headers_for("svc") == {"Authorization": "Bearer xyz"}
    assert tr.calls == []


def test_basic_builds_base64():
    mgr, _ = _mgr([{"role": "u", "method": "basic",
                    "auth": {"username_env": "U", "password_env": "P"}}], {"U": "user", "P": "pw"})
    expect = "Basic " + base64.b64encode(b"user:pw").decode()
    assert mgr.headers_for("u") == {"Authorization": expect}


def test_form_login_posts_json_to_login_url_and_returns_only_token():
    ident = {"role": "a", "method": "form", "auth": {
        "login_url": "https://app.example.com/rest/user/login",
        "username_field": "email", "username_env": "AU", "password_env": "AP"}}
    mgr, tr = _mgr([ident], {"AU": "a@x.test", "AP": "secretpw"})
    headers = mgr.headers_for("a")
    assert headers == {"Authorization": "Bearer FORMTOK"}           # only the token travels onward
    method, url, _, kw = tr.calls[0]
    assert method == "POST" and url == "https://app.example.com/rest/user/login"
    assert kw["json"] == {"email": "a@x.test", "password": "secretpw"}  # creds sent to the bound endpoint


def test_oidc_password_grant_posts_to_token_url():
    ident = {"role": "ua", "method": "oidc-password", "auth": {
        "token_url": "https://sso.example.com/token", "client_id": "cli",
        "client_secret_env": "CS", "scope": "openid", "username_env": "UN", "password_env": "PW"}}
    mgr, tr = _mgr([ident], {"CS": "shh", "UN": "bob", "PW": "pw"})
    assert mgr.headers_for("ua") == {"Authorization": "Bearer OIDCTOK"}
    _, url, _, kw = tr.calls[0]
    assert url == "https://sso.example.com/token"
    assert kw["data"] == {"grant_type": "password", "client_id": "cli",
                          "client_secret": "shh", "scope": "openid", "username": "bob", "password": "pw"}


def test_missing_env_fails_closed():
    mgr, _ = _mgr([{"role": "svc", "method": "bearer", "auth": {"token_env": "NOPE"}}], {})
    with pytest.raises(AuthError):
        mgr.headers_for("svc")


def test_auth_endpoint_outside_scope_is_refused():
    ident = {"role": "x", "method": "oidc-password", "auth": {
        "token_url": "https://rogue.example/token", "username_env": "UN", "password_env": "PW"}}
    mgr, _ = _mgr([ident], {"UN": "a", "PW": "b"})
    with pytest.raises(ScopeViolation):
        mgr.headers_for("x")


def test_token_cached_then_refetched_after_invalidate():
    ident = {"role": "ua", "method": "oidc-password", "auth": {
        "token_url": "https://sso.example.com/token", "username_env": "UN", "password_env": "PW"}}
    mgr, tr = _mgr([ident], {"UN": "a", "PW": "b"})
    mgr.headers_for("ua")
    mgr.headers_for("ua")
    assert len(tr.calls) == 1          # cached
    mgr.invalidate("ua")
    mgr.headers_for("ua")
    assert len(tr.calls) == 2          # refetched
