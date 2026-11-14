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
            return FakeResp(200, {"authentication": {"token": "FORMTOK7f3a"}})
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
    assert headers == {"Authorization": "Bearer FORMTOK7f3a"}           # only the token travels onward
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
    text = (f'token FORMTOK7f3a user alice@shop.test pw pa ss/wörd"1 json "pa ss/w\\u00f6rd\\"1" '
            f"url pa%20ss%2Fw%C3%B6rd%221 form pa+ss%2Fw%C3%B6rd%221 basic {basic} hunter22 name bob")
    out = mgr.redact({"body": text, "list": [text], "n": 3, "flag": True})
    for secret in ("FORMTOK7f3a", "wörd", "w\\u00f6rd", "w%C3%B6rd", basic, "hunter22"):
        assert secret not in out["body"] and secret not in out["list"][0]
    assert "user alice@shop.test pw" in out["body"]        # a user name is no secret (VER-016)
    assert out["n"] == 3 and out["flag"] is True
    assert "bob" in out["body"]        # shorter than 4 characters: left alone, it would mask ordinary text


def test_redact_masks_a_credential_that_keys_a_json_object():
    """VER-016: an answer keyed by a session or token, such as {"<session id>": {...}}, shows no credential."""
    mgr, _ = _mgr([FORM, BASIC], ENV)
    mgr.headers_for("a")
    out = mgr.redact({"sessions": {"FORMTOK7f3a": {"user": "alice@shop.test"}, "hunter22": 1}, 7: "x"})
    assert "FORMTOK7f3a" not in str(out) and "hunter22" not in str(out)
    assert out["sessions"]["[a session]"] == {"user": "alice@shop.test"} and out[7] == "x"


def test_redact_keeps_masking_a_token_after_invalidate():
    mgr, _ = _mgr([FORM], ENV)
    mgr.headers_for("a")
    mgr.invalidate("a")
    assert mgr.redact("old FORMTOK7f3a") == "old [a session]"


def test_a_user_name_that_equals_a_secret_of_the_run_stays_redacted():
    """VER-016: a user name is no secret, unless it is the value of one, here another identity's password."""
    env = {**ENV, "AU": "hunter22"}
    mgr, _ = _mgr([FORM, BASIC], env)
    assert mgr.redact("Welcome hunter22") == "Welcome [test credential]"
    mgr, _ = _mgr([FORM], env)                             # without that identity it is a user name only
    assert mgr.redact("Welcome hunter22") == "Welcome hunter22"


def test_a_placeholder_names_the_account_and_the_kind_of_the_secret():
    bearer = {"role": "c", "method": "bearer", "auth": {"token_env": "CT"}}
    mgr, _ = _mgr([FORM, BASIC, bearer], {**ENV, "CT": "tok-c-123456"})
    mgr.headers_for("a")
    out = mgr.redact('pw pa ss/wörd"1 basic hunter22 bearer tok-c-123456 session FORMTOK7f3a')
    assert out == "pw [a password] basic [b password] bearer [c token] session [a session]"
    assert mgr.holds_placeholder("x [b password]") and mgr.holds_placeholder("[test credential]")
    assert not mgr.holds_placeholder("x [b passwd]")


@pytest.mark.parametrize("env, text, out", [
    ({**ENV, "BP": 'pa ss/wörd"1'}, 'pw pa ss/wörd"1', "pw [a/b password]"),                 # two accounts share it
    ({**ENV, "AU": "hunter22"}, "user hunter22", "user [test credential]"),                # also a user name
    ({**ENV, "AU": "pa ss/wörd\"1"}, 'pw pa ss/wörd"1', "pw [test credential]"),           # user name = password
    ({**ENV, "BP": "a pass"}, 'pw pa ss/wörd"1 and a pass', 'pw [test credential] and [b password]'),  # in a label
])
def test_a_placeholder_says_what_it_hides_without_telling_more(env, text, out):
    """VER-016: a value two accounts share names both; a user name that equals a secret, and a secret whose label
    would carry another secret, read [test credential]. The one pass never replaces inside a placeholder."""
    mgr, _ = _mgr([FORM, BASIC], env)
    assert mgr.redact(text) == out


def test_a_password_that_is_a_plain_word_is_masked_only_where_it_stands_as_a_value():
    """VER-016: DVWA's password `password`, shared by two accounts. It is masked as a query, form or cookie value
    and as a JSON or dict value, never in the page's text or in a name, where masking it would mask the word and
    tell the password."""
    mgr, _ = _mgr([FORM, BASIC], {**ENV, "AP": "password", "BP": "password"})
    label = "[a/b password]"
    for text in ("Username and/or password incorrect.", '<input type="password" name="password">',
                 '{"field": "password reset"}'):
        assert mgr.redact(text) == text
    assert (mgr.redact("GET /brute/?username=admin&password=password HTTP/1.1")
            == f"GET /brute/?username=admin&password={label} HTTP/1.1")
    assert mgr.redact("user=admin&password=password") == f"user=admin&password={label}"
    assert mgr.redact('{"password": "password"}') == f'{{"password": "{label}"}}'
    assert (mgr.redact({"params": {"password": "password"}, "input_name": "password", "inputs": ["password"]})
            == {"params": {"password": label}, "input_name": "password", "inputs": ["password"]})
    assert mgr.holds_placeholder(label)


def test_a_token_that_is_not_a_word_stays_masked_in_any_text():
    """VER-016: only a plain word gets the value rule; a token or a password with digits is masked anywhere."""
    mgr, _ = _mgr([FORM, BASIC], ENV)
    mgr.headers_for("a")
    assert mgr.redact("your token FORMTOK7f3a and hunter22") == "your token [a session] and [b password]"


def test_only_a_cookie_value_that_can_be_a_session_is_a_secret():
    """VER-016: a pasted session's `security=low` is a setting and stays readable, also inside other words; its
    session id is masked. A cookie observed during the run counts only when it can be a session."""
    ident = {"role": "s", "method": "session", "auth": {"headers_env": {"Cookie": "SC"}}}
    mgr, _ = _mgr([ident], {"SC": "PHPSESSID=k3j4h5g6f7d8s9a0q1w2; security=low"})
    mgr.headers_for("s")
    assert mgr.redact("allowing a follow-up below") == "allowing a follow-up below"
    assert mgr.redact("Cookie: PHPSESSID=k3j4h5g6f7d8s9a0q1w2; security=low") == "Cookie: [s session]"
    assert mgr.redact("id k3j4h5g6f7d8s9a0q1w2, level low") == "id [s session], level low"
    mgr.remember_secret("medium", "session cookie")
    mgr.remember_secret("a1b2c3d4e5", "session cookie")
    assert mgr.redact("medium a1b2c3d4e5") == "medium [session cookie]"


def test_a_page_with_a_user_name_may_reach_a_model_and_one_with_a_password_may_not():
    """The screenshot check (VER-042) follows the same rule: a user name in the page text clears the image."""
    from appsec_verifier.verify.runner import _private_text

    mgr, _ = _mgr([FORM], ENV)
    private = _private_text(mgr, {})
    assert private("Signed in as alice@shop.test") is False
    assert private('Your password is pa ss/wörd"1') is True


def test_redact_masks_configured_secrets_before_any_login():
    mgr, tr = _mgr([FORM], ENV)
    assert mgr.redact('echo pa ss/wörd"1 hunter22 alice@shop.test') == "echo [a password] hunter22 alice@shop.test"
    assert tr.calls == []
