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
        self.headers, self.text = {}, ""

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
    (page, page_url, _, page_kw), (method, url, _, kw) = tr.calls    # the page holds no login form: a JSON login
    assert page == "GET" and page_url == url and not {"json", "data"} & page_kw.keys()
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


FORM = {"role": "a", "method": "form", "auth": {"login_url": "https://app.example.com/rest/user/login",
                                                "username_env": "AU", "password_env": "AP"}}
BASIC = {"role": "b", "method": "basic", "auth": {"username_env": "BU", "password_env": "BP"}}
ENV = {"AU": "alice@shop.test", "AP": "pa ss/wörd\"1", "BU": "bob", "BP": "hunter22"}


def test_redact_replaces_env_values_and_obtained_tokens_in_every_form():
    mgr, _ = _mgr([FORM, BASIC], ENV)
    mgr.headers_for("a")
    mgr.headers_for("b")
    basic = base64.b64encode(b"bob:hunter22").decode()
    text = (f'token FORMTOK user alice@shop.test pw pa ss/wörd"1 json "pa ss/w\\u00f6rd\\"1" '
            f"url pa%20ss%2Fw%C3%B6rd%221 form pa+ss%2Fw%C3%B6rd%221 basic {basic} hunter22 name bob")
    out = mgr.redact({"body": text, "list": [text], "n": 3, "flag": True})
    for secret in ("FORMTOK", "wörd", "w\\u00f6rd", "w%C3%B6rd", basic, "hunter22"):
        assert secret not in out["body"] and secret not in out["list"][0]
    assert "user alice@shop.test pw" in out["body"]        # a user name is no secret (VER-016)
    assert out["n"] == 3 and out["flag"] is True
    assert "bob" in out["body"]        # shorter than 4 characters: left alone, it would mask ordinary text


def test_redact_keeps_masking_a_token_after_invalidate():
    mgr, _ = _mgr([FORM], ENV)
    mgr.headers_for("a")
    mgr.invalidate("a")
    assert mgr.redact("old FORMTOK") == "old [redacted]"


def test_a_user_name_that_equals_a_secret_of_the_run_stays_redacted():
    """VER-016: a user name is no secret, unless it is the value of one, here another identity's password."""
    env = {**ENV, "AU": "hunter22"}
    mgr, _ = _mgr([FORM, BASIC], env)
    assert mgr.redact("Welcome hunter22") == "Welcome [redacted]"
    mgr, _ = _mgr([FORM], env)                             # without that identity it is a user name only
    assert mgr.redact("Welcome hunter22") == "Welcome hunter22"


def test_a_page_with_a_user_name_may_reach_a_model_and_one_with_a_password_may_not():
    """The screenshot check (VER-042) follows the same rule: a user name in the page text clears the image."""
    from appsec_verifier.verify.runner import _private_text

    mgr, _ = _mgr([FORM], ENV)
    private = _private_text(mgr, {})
    assert private("Signed in as alice@shop.test") is False
    assert private('Your password is pa ss/wörd"1') is True


def test_redact_masks_configured_secrets_before_any_login():
    mgr, tr = _mgr([FORM], ENV)
    assert mgr.redact('echo pa ss/wörd"1 hunter22 alice@shop.test') == "echo [redacted] hunter22 alice@shop.test"
    assert tr.calls == []
