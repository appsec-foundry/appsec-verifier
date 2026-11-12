"""HTML login forms (VER-028, VER-041): a `form` login whose login URL serves an HTML login form submits it as a
browser does, with its hidden fields, follows redirects within the origin with the cookies the login sets, and takes
those cookies as the session. The password goes only to the login URL, never in a URL, never across origins.
Offline: the target is a fake of DVWA's login as the Verifier sees it."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
import pytest

from appsec_verifier.auth import AuthError, SessionManager
from appsec_verifier.auth.html_login import find_form, keep_cookies, submission
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient

URL = "http://localhost:4280"
LOGIN = URL + "/login.php"
PASSWORD = "pw-for-the-test-1"
PAGE = ("<html><body><form action='{action}' method='{method}'>"
        "<input type='text' class='loginInput' name='username'><br />"
        "<input type='password' class='loginInput' AUTOCOMPLETE='off' name='password'><br />"
        "<input type='submit' value='Login' name='Login'>"
        "<input type='hidden' name='user_token' value='{token}' /></form></body></html>")
ADMIN = {"role": "admin", "method": "form", "auth": {"login_url": LOGIN, "username_env": "DU", "password_env": "DP"}}


class Dvwa:
    """DVWA's login: a new session id on every answer (security level impossible), the session cookie with
    `Domain=localhost`, the CSRF token user_token, the submit button `Login` it requires, relative redirects."""

    def __init__(self, *, action="login.php", method="post", after_login="index.php", set_up=True):
        self.action, self.method, self.after_login, self.set_up = action, method, after_login, set_up
        self.sessions, self.calls, self.n = {}, [], 0

    def __call__(self, method, url, headers, **kw):
        self.calls.append((method, url, dict(headers), kw))
        sent = dict(p.strip().split("=", 1) for p in headers.get("Cookie", "").split(";") if "=" in p)
        self.n += 1
        sid = f"sid{self.n:04d}"
        state = self.sessions[sid] = dict(self.sessions.get(sent.get("PHPSESSID"), {}))
        cookies = [("set-cookie", f"PHPSESSID={sid}; expires=Fri, 13-Nov-2099 20:00:00 GMT; Max-Age=86400; "
                                  "path=/; domain=localhost; HttpOnly; SameSite=Strict")]
        if "security" not in sent:
            cookies.append(("set-cookie", "security=impossible; path=/; HttpOnly"))
        html = [*cookies, ("content-type", "text/html;charset=utf-8")]
        path = urlsplit(url).path
        if method == "POST":
            form = kw.get("data") or {}
            if form.get("user_token") == state.get("token") and "Login" in form and \
                    (form.get("username"), form.get("password")) == ("admin", PASSWORD):
                if not self.set_up:                 # no users table yet: DVWA sends every login to its setup
                    return httpx.Response(302, headers=[*cookies, ("location", "setup.php")])
                state["user"] = "admin"
                return httpx.Response(302, headers=[*cookies, ("location", self.after_login)])
            return httpx.Response(302, headers=[*cookies, ("location", "login.php")])
        if path == "/login.php":
            state["token"] = f"{self.n:032x}"
            return httpx.Response(200, headers=html,
                                  text=PAGE.format(action=self.action, method=self.method, token=state["token"]))
        if path in ("/", "/index.php") and state.get("user"):
            return httpx.Response(200, headers=html, text="<h1>Welcome to Damn Vulnerable Web Application!</h1>")
        if path == "/setup.php":
            return httpx.Response(200, headers=html, text="<form method='post'><input type='submit' "
                                                          "name='create_db' value='Create / Reset Database'></form>")
        return httpx.Response(302, headers=[*cookies, ("location", "login.php")])


def manager(target, identities=(ADMIN,), password=PASSWORD, url=None):
    http = GuardedHttpClient(ScopeGuard({"base_url": URL}), RunBudget(Limits(rate_rps=0)), target)
    return SessionManager([dict(i, auth=dict(i["auth"])) for i in identities], http,
                          env={"DU": "admin", "DP": password}, target=url)


def test_a_login_form_is_submitted_with_its_hidden_fields_and_its_cookies_become_the_session():
    target = Dvwa()
    sessions = manager(target)
    assert sessions.headers_for("admin") == {"Cookie": "PHPSESSID=sid0003; security=impossible"}
    (page, _, page_headers, _), (post, url, headers, kw), (follow, index, follow_headers, follow_kw) = target.calls
    assert (page, post, url, follow, index) == ("GET", "POST", LOGIN, "GET", URL + "/index.php")
    assert "Cookie" not in page_headers                              # nothing was set before the first answer
    assert kw["data"] == {"username": "admin", "password": PASSWORD, "Login": "Login", "user_token": f"{1:032x}"}
    assert headers["Cookie"] == "PHPSESSID=sid0001; security=impossible"   # Domain=localhost does not drop it
    assert follow_headers["Cookie"] == "PHPSESSID=sid0002; security=impossible" and "data" not in follow_kw
    assert all(PASSWORD not in str(call) for call in target.calls if call[0] == "GET")
    assert sessions.redact("session sid0003 and sid0001") == "session [redacted] and sid0001"


def test_a_login_that_ends_on_the_login_form_again_is_refused_and_not_tried_again():
    target = Dvwa()
    sessions = manager(target, password="wrong-password")
    with pytest.raises(AuthError, match="ended on the login form again"):
        sessions.headers_for("admin")
    with pytest.raises(AuthError, match="not tried again"):
        sessions.headers_for("admin")
    assert [c[0] for c in target.calls] == ["GET", "POST", "GET"]   # page, login, its redirect back to the form


@pytest.mark.parametrize("action", ["https://collect.example/login.php", "//collect.example/login.php",
                                    "/other.php", "https://localhost:4280/login.php"])
def test_a_form_that_sends_the_password_elsewhere_is_not_submitted(action):
    target = Dvwa(action=action)
    with pytest.raises(AuthError, match="sends the password to another address"):
        manager(target).headers_for("admin")
    assert [c[0] for c in target.calls] == ["GET"]


def test_a_form_that_sends_get_is_not_submitted():
    target = Dvwa(method="get")
    with pytest.raises(AuthError, match="sends GET"):
        manager(target).headers_for("admin")
    assert [c[0] for c in target.calls] == ["GET"] and PASSWORD not in str(target.calls)


def test_a_redirect_to_another_origin_after_the_login_is_not_followed():
    target = Dvwa(after_login="https://sso.example.com/next")
    with pytest.raises(AuthError, match="answered HTTP 302"):
        manager(target).headers_for("admin")
    assert {urlsplit(c[1]).netloc for c in target.calls} == {"localhost:4280"}


def test_an_account_named_on_the_command_line_uses_the_fields_the_form_names():
    target = Dvwa()
    ident = {"role": "account-1", "method": "form", "auth": {"login_url": LOGIN, "username_env": "DU",
                                                              "password_env": "DP"}}
    sessions = manager(target, [ident])
    assert sessions.sign_in_with_fields("account-1", [("email", "pass")]) == ("username", "password")
    assert sessions.headers_for("account-1") == {"Cookie": "PHPSESSID=sid0003; security=impossible"}


def test_a_login_page_without_a_content_type_is_read_as_html():
    target = Dvwa()

    def untyped(method, url, headers, **kw):
        resp = target(method, url, headers, **kw)
        return httpx.Response(resp.status_code, headers=[h for h in resp.headers.multi_items()
                                                         if h[0] != "content-type"], content=resp.content)

    assert manager(untyped).headers_for("admin") == {"Cookie": "PHPSESSID=sid0003; security=impossible"}


def test_a_page_without_a_password_form_falls_back_to_the_json_login():
    def target(method, url, headers, **kw):
        if method == "GET":
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text="<form action='/search'><input name='q'></form>")
        return httpx.Response(200, json={"authentication": {"token": "T0K3N"}})

    sessions = manager(target)
    assert sessions.headers_for("admin") == {"Authorization": "Bearer T0K3N"}


def test_submission_is_what_a_browser_sends_on_enter():
    form = find_form("<form method=post><input type=hidden name=csrf value='c1'><input name=user value=x>"
                     "<input type=password name=pw><input type=checkbox name=remember>"
                     "<input type=checkbox name=agree checked><input type=radio name=r value=a checked>"
                     "<input type=file name=f><input type=reset name=reset><button name=go value=1>Go</button>"
                     "<input type=submit name=other value=2></form>")
    data, user_field, password_field = submission(form, ("email", "u@x.test"), ("password", "pw"))
    assert (user_field, password_field) == ("user", "pw")           # the form's only text field and its password
    assert data == {"csrf": "c1", "user": "u@x.test", "pw": "pw", "agree": "on", "r": "a", "go": "1"}


def test_only_a_form_with_exactly_one_password_field_is_a_login_form():
    assert find_form("<form><input type=password name=a><input type=password name=b></form>") is None
    assert find_form("<input type=password name=a>") is None        # outside any form
    assert find_form("<form id=s><input name=q></form><form><input type=password name=p></form>").fields == [
        ("password", "p", "", False)]


def test_cookies_are_kept_by_name_and_expired_or_invalid_ones_are_dropped():
    cookies = {"old": "1", "gone": "2"}
    resp = httpx.Response(200, headers=[
        ("set-cookie", "sid=abc; Domain=localhost; Path=/x"),
        ("set-cookie", "old=new"),
        ("set-cookie", "gone=deleted; Max-Age=0; Expires=Fri, 13-Nov-2099 20:00:00 GMT"),
        ("set-cookie", "past=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
        ("set-cookie", 'quoted="v1"'),
        ("set-cookie", "spaced=a b"),
        ("set-cookie", "bad name=x"),
        ("set-cookie", "novalue"),
    ])
    keep_cookies(resp, cookies, now=1_800_000_000.0)
    assert cookies == {"old": "new", "sid": "abc", "quoted": '"v1"'}


# ── the login form found from the target URL, and the check after the login (VER-041) ─────────────────────

FOUND = {"role": "admin", "method": "form",
         "auth": {"login_url": URL + "/", "login_from_target": True, "username_env": "DU", "password_env": "DP"}}


def test_the_login_form_the_target_url_redirects_to_is_found_and_kept_for_renewals():
    target = Dvwa()
    sessions = manager(target, [FOUND], url=URL + "/")
    assert sessions.sign_in_with_fields("admin", [("username", "password")]) == ("username", "password")
    assert [(c[0], c[1]) for c in target.calls][:3] == [("GET", URL + "/"), ("GET", LOGIN), ("POST", LOGIN)]
    assert sessions._by_role["admin"]["auth"]["login_url"] == LOGIN          # renewals start at the page found
    assert (target.calls[-1][0], target.calls[-1][1]) == ("GET", URL + "/")  # the check: the target, no form


def test_a_form_found_from_the_target_url_may_post_anywhere_on_its_origin_but_no_further():
    target = Dvwa(action="/auth/session.php", after_login="/index.php")
    manager(target, [FOUND], url=URL + "/").headers_for("admin")
    assert [c[1] for c in target.calls if c[0] == "POST"] == [URL + "/auth/session.php"]
    elsewhere = Dvwa(action="https://collect.example/session")
    with pytest.raises(AuthError, match="sends the password to another address"):
        manager(elsewhere, [FOUND], url=URL + "/").headers_for("admin")
    assert all(c[0] == "GET" for c in elsewhere.calls)


def test_a_target_url_without_a_login_form_sends_no_credentials():
    sent = []

    def target(method, url, headers, **kw):
        sent.append((method, kw))
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<h1>Shop</h1><a href=/x>x</a>")

    with pytest.raises(AuthError, match="leads to no HTML login form; give the login endpoint with --login-url"):
        manager(target, [FOUND], url=URL + "/").headers_for("admin")
    assert [m for m, _ in sent] == ["GET"] and PASSWORD not in str(sent)


def test_a_login_the_target_did_not_take_is_refused_when_the_target_url_still_leads_to_the_form():
    target = Dvwa(set_up=False)                               # the login ends on a setup page, signed out
    with pytest.raises(AuthError, match="target URL still leads to the login form"):
        manager(target, url=URL + "/").headers_for("admin")
    assert [(c[0], urlsplit(c[1]).path) for c in target.calls] == [
        ("GET", "/login.php"), ("POST", "/login.php"), ("GET", "/setup.php"),     # the login
        ("GET", "/"), ("GET", "/login.php")]                                      # the check


def test_the_check_is_skipped_where_the_target_url_is_the_login_page_itself():
    target = Dvwa(set_up=False)
    assert "Cookie" in manager(target, url=LOGIN).headers_for("admin")              # nothing to compare with
    assert [c[0] for c in target.calls] == ["GET", "POST", "GET"]
