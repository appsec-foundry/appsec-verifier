"""Test accounts named on the command line (VER-041): the login endpoint comes from --login-url or the single
login entry point of the assessment, the model chooses only the field names and never sees a value, each
account gets at most two attempts, credentials go to no other endpoint, and a privileged account only reads.
Offline: fake transports and a fake model host."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import yaml

from appsec_verifier import cli
from appsec_verifier.agent import AgentTools, ToolError
from appsec_verifier.agent.hosts import HostReply
from appsec_verifier.auth import AuthError, SessionManager
from appsec_verifier.auth.accounts import (
    AccountError,
    account_identities,
    choose_fields,
    login_entry_points,
    parse_account,
    resolve_login_url,
)
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, httpx_transport

URL = "http://localhost:3000"
LOGIN = URL + "/rest/user/login"
SURFACE = {"attack_surface": [
    {"entry_point": "POST /rest/user/login", "notes": "handler: server.ts:596"},
    {"entry_point": "GET /rest/saveLoginIp"},
    {"entry_point": "POST /rest/user/reset-password"},
    {"entry_point": "POST /api/Users/:id/login"},                # a path parameter is not a login endpoint
]}


# ── options and the login endpoint ────────────────────────────────────────────

@pytest.mark.parametrize("value, expected", [
    ("jim@juice-sh.op", ("jim@juice-sh.op", None)),
    ("jim@juice-sh.op=JIM_PASS", ("jim@juice-sh.op", "JIM_PASS")),
    ("a=b c", ("a=b c", None)),                                   # not a variable name: all of it is the user
])
def test_an_account_is_a_user_name_and_optionally_its_password_variable(value, expected):
    assert parse_account(value) == expected


@pytest.mark.parametrize("value", ["", " jim", "jim\nx", "jim\x1b[2J", "x" * 300])
def test_unusable_account_names_are_refused(value):
    with pytest.raises(AccountError):
        parse_account(value)


def test_the_single_login_entry_point_of_the_assessment_is_found():
    assert login_entry_points(SURFACE) == ["/rest/user/login"]
    assert resolve_login_url(None, SURFACE, URL) == (LOGIN, "from the assessment")
    assert resolve_login_url(None, SURFACE, URL + "/app/")[0] == URL + "/app/rest/user/login"


@pytest.mark.parametrize("doc, expected", [
    ({}, "it names none"),
    ({"attack_surface": [{"entry_point": "POST /login"}, {"entry_point": "POST /api/sessions"}]},
     "found POST /login, POST /api/sessions"),
    ({"attack_surface": [{"entry_point": "POST /a b/login"}, {"entry_point": "POST /x/../login"}]}, "names none"),
])
def test_no_single_login_entry_point_needs_login_url(doc, expected):
    with pytest.raises(AccountError, match="--login-url") as exc:
        resolve_login_url(None, doc, URL)
    assert expected in str(exc.value)


@pytest.mark.parametrize("login_url, ok", [
    ("https://auth.example.com/api/login", True),
    ("http://localhost:4000/login", True),                       # this machine
    ("http://localhost:3000/other/login", True),                 # the target itself
    ("http://auth.example.com/login", False),                    # a password across the network unencrypted
    ("https://user:pw@auth.example.com/login", False),
    ("ftp://auth.example.com/login", False),
    ("https://auth.example.com/lo gin", False),
])
def test_login_url_as_given(login_url, ok):
    if ok:
        assert resolve_login_url(login_url, {}, URL) == (login_url, "--login-url")
    else:
        with pytest.raises(AccountError):
            resolve_login_url(login_url, {}, URL)


def test_accounts_get_neutral_roles_and_internal_variables():
    identities, users, pending = account_identities(["jim@juice-sh.op", "bender@juice-sh.op=B_PASS"],
                                                    ["admin@juice-sh.op"], LOGIN)
    assert [i["role"] for i in identities] == ["account-1", "account-2", "admin-1"]
    assert all(i["method"] == "form" and i["auth"]["login_url"] == LOGIN for i in identities)
    assert identities[1]["auth"]["password_env"] == "B_PASS"
    assert set(users.values()) == {"jim@juice-sh.op", "bender@juice-sh.op", "admin@juice-sh.op"}
    assert [(r, v) for r, _, _, v in pending] == [("account-1", None), ("account-2", "B_PASS"), ("admin-1", None)]


# ── the model chooses the field names ─────────────────────────────────────────

class FakeHost:
    model, label = "fake-model", "fake"

    def __init__(self, args=None, *, action="login_fields", error=None, breach=None):
        self.args = {"candidates": [{"username_field": "username", "password_field": "password"},
                                    {"username_field": "email", "password_field": "password"}]} \
            if args is None else args
        self.action, self.error, self.breach, self.prompts, self.broken = action, error, breach, [], None

    def call(self, system, prompt, timeout, budget):
        self.prompts.append(system + prompt)
        return HostReply(step={"action": self.action, "args_json": json.dumps(self.args), "note": "fields"},
                         error=self.error, breach=self.breach, usd=0.0)


def test_the_model_answers_with_up_to_two_field_pairs_counted_against_the_run():
    budget = RunBudget(Limits(max_calls=5))
    host = FakeHost()
    assert choose_fields(host, budget, endpoint="POST /rest/user/login") == [("username", "password"),
                                                                            ("email", "password")]
    assert budget.calls == 1 and "/rest/user/login" in host.prompts[0]


@pytest.mark.parametrize("host, expected", [
    (FakeHost(action="submit_verdict", args={"verdict": "inconclusive", "rationale": "x"}), "did not answer"),
    (FakeHost(args={"candidates": [{"username_field": "user\"; drop", "password_field": "p"}]}), "did not answer"),
    (FakeHost(args={"candidates": [{"username_field": "a", "password_field": "b"}] * 3}), "did not answer"),
    (FakeHost(args={"candidates": [{"username_field": "p", "password_field": "p"}]}), "no usable pair"),
    (FakeHost(error="timeout"), "call for the login fields failed"),
    (FakeHost(breach="used a tool"), "confinement check failed"),
])
def test_an_unusable_model_answer_stops_the_sign_in(host, expected):
    with pytest.raises(AccountError, match=expected):
        choose_fields(host, RunBudget(Limits()), endpoint="POST /login")
    assert (host.broken == "used a tool") == (host.breach is not None)


def test_the_call_cap_stops_the_field_question_before_the_model_is_asked():
    host = FakeHost()
    budget = RunBudget(Limits(max_calls=1))
    budget.note_call()
    with pytest.raises(AccountError, match="limit"):
        choose_fields(host, budget, endpoint="POST /login")
    assert host.prompts == []


# ── at most two attempts per account, only at the login endpoint ──────────────

def _json_response(status, body):
    return SimpleNamespace(status_code=status, headers={}, text=json.dumps(body), json=lambda: body)


class JuiceShop:
    """Fake target: answers a JSON login with {email, password} and records every request."""

    def __init__(self, accounts):
        self.accounts, self.calls = accounts, []

    def __call__(self, method, url, headers, **kw):
        self.calls.append((method, url, dict(kw.get("json") or {}), headers.get("Authorization")))
        if method == "POST" and url == LOGIN:
            body = kw.get("json") or {}
            if self.accounts.get(body.get("email")) == body.get("password") and set(body) == {"email", "password"}:
                return _json_response(200, {"authentication": {"token": f"tok-{body['email']}", "bid": 2}})
            return _json_response(401, {"error": "Invalid email or password."})
        return _json_response(200, {"status": "ok"})


def _sessions(target, env):
    identities, users, _ = account_identities(["jim@juice-sh.op=JP", "bender@juice-sh.op=BP"], [], LOGIN)
    http = GuardedHttpClient(ScopeGuard({"base_url": URL}), RunBudget(Limits()), target)
    return SessionManager(identities, http, env={**users, **env}), identities


def test_the_first_working_pair_signs_the_account_in_and_is_kept_for_renewal():
    target = JuiceShop({"jim@juice-sh.op": "ncc-1701"})
    sessions, identities = _sessions(target, {"JP": "ncc-1701", "BP": "x"})
    assert sessions.sign_in_with_fields("account-1", [("username", "password"), ("email", "password")]) == \
        ("email", "password")
    assert [c[0:2] for c in target.calls] == [("POST", LOGIN)] * 2
    assert sessions.headers_for("account-1") == {"Authorization": "Bearer tok-jim@juice-sh.op"}
    assert identities[0]["auth"]["username_field"] == "email" and len(target.calls) == 2


def test_an_account_whose_login_returns_no_token_is_tried_twice_and_then_never_again():
    target = JuiceShop({})
    sessions, _ = _sessions(target, {"JP": "wrong", "BP": "x"})
    with pytest.raises(AuthError, match="no token with the fields username/password, email/password"):
        sessions.sign_in_with_fields("account-1", [("username", "password"), ("email", "password"),
                                                   ("login", "password")])
    assert len(target.calls) == 2                                # never a third attempt
    with pytest.raises(AuthError, match="not tried again"):
        sessions.headers_for("account-1")                        # no fallback to default field names
    with pytest.raises(AuthError, match="not tried again"):
        sessions.sign_in_with_fields("account-1", [("email", "password")])
    assert len(target.calls) == 2


def test_a_transport_failure_ends_the_attempts_without_falling_back_to_default_fields():
    import httpx

    def broken(method, url, headers, **kw):
        broken.calls += 1
        raise httpx.ConnectError("refused")

    broken.calls = 0
    sessions, _ = _sessions(broken, {"JP": "p", "BP": "x"})
    with pytest.raises(httpx.ConnectError):
        sessions.sign_in_with_fields("account-1", [("username", "password"), ("email", "password")])
    with pytest.raises(AuthError, match="not tried again"):
        sessions.headers_for("account-1")
    assert broken.calls == 1


def test_the_account_values_are_redacted_and_never_reach_the_model():
    target = JuiceShop({"jim@juice-sh.op": "ncc-1701"})
    sessions, _ = _sessions(target, {"JP": "ncc-1701", "BP": "x"})
    sessions.sign_in_with_fields("account-1", [("email", "password")])
    assert sessions.redact("user jim@juice-sh.op pw ncc-1701 tok-jim@juice-sh.op") == \
        "user [redacted] pw [redacted] [redacted]"


# ── a privileged account only reads ───────────────────────────────────────────

def test_a_privileged_account_never_writes(tmp_path):
    from appsec_verifier.loader import FindingPlan
    from appsec_verifier.verify.probes import ProbeContext

    sent = []
    scope = {"base_url": URL}
    http = GuardedHttpClient(ScopeGuard(scope), RunBudget(Limits()),
                             lambda m, u, h, **k: sent.append((m, u)) or _json_response(200, {}))
    idents = [{"role": "admin-1", "method": "bearer", "auth": {"token_env": "T"}, "privileged": True},
              {"role": "account-1", "method": "bearer", "auth": {"token_env": "U"}}]
    sessions = SessionManager(idents, http, env={"T": "admin-token", "U": "user-token"})
    plan = FindingPlan(id="T-1", cwe="CWE-862", severity="High", title="t", match_key="k", instance="a.ts:1",
                       status="dynamic", cls="access-control", reason="p")
    ctx = ProbeContext(plan=plan, scope=scope, guard=ScopeGuard(scope), budget=RunBudget(Limits()), http=http,
                       identities=idents, callback={}, safe=False, read_only=False, sessions=sessions,
                       source=None, target_base=URL)
    tools = AgentTools(ctx)
    for method in ("POST", "PUT", "PATCH"):
        with pytest.raises(ToolError, match="privileged account and only reads"):
            tools.http_request(role="admin-1", method=method, path="/api/Products/1", json={"x": "y"})
    assert sent == []
    tools.http_request(role="admin-1", method="GET", path="/api/Users")
    tools.http_request(role="account-1", method="PUT", path="/api/Products/1", json={"x": "y"})
    assert sent == [("GET", URL + "/api/Users"), ("PUT", URL + "/api/Products/1")]


# ── through verify ────────────────────────────────────────────────────────────

THREAT = {"id": "T-1", "cwe": "CWE-89", "severity": "high", "title": "sqli", "scenario": "GET /rest/products/search",
          "evidence": {"file": "routes/search.ts", "line": 1}}


def _verify(tmp_path, monkeypatch, target, host, *extra, env=None, surface=SURFACE, threats=(THREAT,)):
    seen = {}

    class Planner:
        def next_step(self, ctx, history):
            seen["identities"] = [(i["role"], bool(i.get("privileged"))) for i in ctx.identities]
            return {"verdict": {"verdict": "inconclusive", "rationale": "x"}}

    Planner.host = host
    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: target)
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: False)
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"threats": list(threats), **surface}))
    rc = cli.main(["verify", "--assessment", str(tmp_path / "a.yaml"), "--url", URL, "--yes", "--test-all",
                   "--output", str(tmp_path / "out"), *extra])
    return rc, seen


def test_verify_signs_accounts_in_at_the_assessments_login_and_shows_it_before_the_confirmation(
        tmp_path, monkeypatch, capsys):
    target, host = JuiceShop({"jim@juice-sh.op": "ncc-1701", "bender@juice-sh.op": "liquor",
                              "admin@juice-sh.op": "admin123"}), FakeHost()
    rc, seen = _verify(tmp_path, monkeypatch, target, host, "--account", "jim@juice-sh.op=JP",
                       "--account", "bender@juice-sh.op=BP", "--admin-account", "admin@juice-sh.op=AP",
                       env={"JP": "ncc-1701", "BP": "liquor", "AP": "admin123"})
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK, out
    assert f"sign in at POST {LOGIN} (from the assessment)" in out and "admin-1 (privileged, read-only)" in out
    assert "email/password worked" in out
    logins = [c for c in target.calls if c[0] == "POST"]
    assert len(logins) == 4                     # account-1 tries two pairs, the others use the one that worked
    assert all(url == LOGIN for _, url, _, _ in logins)
    assert seen["identities"] == [("account-1", False), ("account-2", False), ("admin-1", True)]
    prompt = host.prompts[0]
    for value in ("jim@juice-sh.op", "bender", "ncc-1701", "liquor", "admin123"):
        assert value not in prompt and value not in out
    report = (tmp_path / "out" / "verification.md").read_text() + (tmp_path / "out" / "agent-log.jsonl").read_text()
    assert "ncc-1701" not in report and "jim@juice-sh.op" not in report


def test_with_accounts_the_settings_name_the_roles_once(tmp_path, monkeypatch, capsys):
    idor = {"id": "T-2", "cwe": "CWE-639", "severity": "high", "title": "idor", "scenario": "GET /rest/basket/1",
            "evidence": {"file": "routes/basket.ts", "line": 1}}
    target, host = JuiceShop({"jim@juice-sh.op": "ncc-1701", "bender@juice-sh.op": "liquor"}), FakeHost()
    rc, _ = _verify(tmp_path, monkeypatch, target, host, "--account", "jim@juice-sh.op=JP", "--account",
                    "bender@juice-sh.op=BP", env={"JP": "ncc-1701", "BP": "liquor"}, threats=(THREAT, idor))
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK, out
    assert "  Accounts   : account-1, account-2 · sign in at POST" in out and "Identities :" not in out


def test_a_failed_account_login_stops_the_run_and_points_to_identities(tmp_path, monkeypatch, capsys):
    target = JuiceShop({"jim@juice-sh.op": "ncc-1701"})
    rc, seen = _verify(tmp_path, monkeypatch, target, FakeHost(), "--account", "jim@juice-sh.op=JP",
                       "--account", "bender@juice-sh.op=BP", env={"JP": "ncc-1701", "BP": "wrong"})
    out = capsys.readouterr().out
    assert rc == cli.EXIT_BLOCKED and seen == {}
    assert "no token for account-2" in out and "needs --identities" in out
    assert len([c for c in target.calls if c[0] == "POST" and c[2].get("email") == "bender@juice-sh.op"]) == 1


@pytest.mark.parametrize("extra, surface, env, expected", [
    (("--account", "jim@juice-sh.op=JP", "--identities", "x.yaml"), SURFACE, {"JP": "p"}, "not both"),
    (("--login-url", LOGIN), SURFACE, {}, "--login-url needs --account"),
    (("--account", "jim@juice-sh.op=JP"), {}, {"JP": "p"}, "no single login entry point"),
    (("--account", "jim@juice-sh.op=JP", "--account", "jim@juice-sh.op=JP"), SURFACE, {"JP": "p"},
     "the same user name is given twice"),
    (("--account", "jim@juice-sh.op=JP"), SURFACE, {}, "environment variable JP is not set"),
    (("--account", "jim@juice-sh.op"), SURFACE, {}, "no password"),
    (("--account", "jim@juice-sh.op=JP", "--login-url", "http://auth.example.com/login"), SURFACE, {"JP": "p"},
     "must be https"),
])
def test_unusable_account_options_block_before_anything_is_contacted(tmp_path, monkeypatch, capsys, extra,
                                                                     surface, env, expected):
    target, host = JuiceShop({}), FakeHost()
    rc, _ = _verify(tmp_path, monkeypatch, target, host, *extra, env=env, surface=surface)
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and expected in err and "Nothing was contacted." in err
    assert target.calls == [] and host.prompts == []


def test_a_login_url_on_another_host_is_a_login_host_for_this_run_only(tmp_path, monkeypatch, capsys):
    auth = "https://auth.example.com/api/login"
    sent = []

    def target(method, url, headers, **kw):
        sent.append((method, url))
        if url == auth:
            return _json_response(200, {"token": "tok-" + (kw.get("json") or {}).get("username", "")})
        return _json_response(200, {})

    host = FakeHost({"candidates": [{"username_field": "username", "password_field": "password"}]})
    rc, _ = _verify(tmp_path, monkeypatch, target, host, "--account", "jim=JP", "--account", "bender=BP",
                    "--login-url", auth, env={"JP": "p1", "BP": "p2"})
    assert rc == cli.EXIT_OK, capsys.readouterr()
    assert [u for m, u in sent if m == "POST"] == [auth, auth]
    assert all(u == auth or u.startswith(URL) for _, u in sent)             # nothing is tested on the login host


def test_offline_preflight_checks_the_accounts_without_asking_for_passwords(tmp_path, monkeypatch, capsys):
    asked = []
    monkeypatch.setattr(cli, "_ask_secret", lambda prompt: asked.append(prompt) or "")
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: True)
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args, check_access=True: (
        SimpleNamespace(host=FakeHost()), {"profile": "claude", "model": "m", "runtime": "fake", "auth": "none",
                                           "check": "ok"}))
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"threats": [THREAT], **SURFACE}))
    cli.main(["preflight", "--assessment", str(tmp_path / "a.yaml"), "--url", URL, "--offline", "--json",
              "--account", "jim@juice-sh.op", "--admin-account", "admin@juice-sh.op"])
    check = next(c for c in json.loads(capsys.readouterr().out)["checks"] if c["check"] == "Accounts")
    assert check["status"] == "ok" and f"sign in at POST {LOGIN}" in check["message"]
    assert "jim@juice-sh.op" not in check["message"] and asked == []


def test_a_scope_file_keeps_the_login_url_inside_its_auth_hosts(tmp_path, monkeypatch, capsys):
    scope = tmp_path / "scope.yaml"
    scope.write_text(yaml.safe_dump({"schema_version": 1, "base_url": URL, "owner": {"name": "t"},
                                     "window": {"from": "2020-01-01T00:00:00Z", "until": "2099-01-01T00:00:00Z"}}))
    target = JuiceShop({})
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"threats": [THREAT]}))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda s: target)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "a.yaml"), "--scope", str(scope), "--yes",
                   "--output", str(tmp_path / "out"), "--account", "jim=JP",
                   "--login-url", "https://auth.example.com/login"])
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and "add its host to auth_hosts" in err and target.calls == []
