"""Pre-flight checks before the first model call (VER-032): the assessment's
structure, the proxy settings, the target's reachability, one login per identity
and its check_url, the model's metadata and the opt-in generation test. Every
refused case is covered: nothing is contacted before the confirmation, a login
is never retried, credentials go only to their origin, and no secret, raw error
or response body reaches the output (VER-002, VER-016, VER-028, VER-029)."""

from __future__ import annotations

import json
import socket
import ssl
from types import SimpleNamespace

import httpx
import pytest
import yaml

from appsec_verifier import cli, guided
from appsec_verifier.agent.host_anthropic import AnthropicHost
from appsec_verifier.agent.host_openai import MODELS_ENDPOINT, OpenAIHost
from appsec_verifier.agent.hosts import HostReply, HostUnavailable
from appsec_verifier.auth import SessionManager
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.loader import AssessmentError, read_assessment
from appsec_verifier.preflight import (
    _TEST_PROMPT,
    _TEST_SYSTEM,
    check_identities,
    check_target,
    generation_test,
    proxy_for,
)
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, httpx_transport
from appsec_verifier.tools.browser import BrowserUnavailable, ProofBrowser

BASE = "https://app.example.com"
SCOPE = {"schema_version": 1, "base_url": BASE, "owner": {"name": "tester"},
         "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
         "auth_hosts": ["sso.example.com"]}
PROXY = {"url": "http://proxy.corp.example:8080", "username_env": "PROXY_USER", "password_env": "PROXY_PASS"}
THREAT = {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor", "evidence": {"file": "a.ts", "line": 1}}
SECRET = "s3cr3t-pa55"


def _resp(status=200, body=None, headers=None):
    return SimpleNamespace(status_code=status, headers=headers or {},
                           json=lambda: body if body is not None else (_ for _ in ()).throw(ValueError("no json")))


class Target:
    """Fake transport: answers by (method, url) and records every call."""

    def __init__(self, answers=None, default=None):
        self.answers, self.default, self.calls = dict(answers or {}), default, []

    def __call__(self, method, url, headers, **kw):
        self.calls.append((method, url, dict(headers), kw))
        out = self.answers.get((method, url), self.default)
        if out is None:
            raise AssertionError(f"unexpected request {method} {url}")
        if isinstance(out, Exception):
            raise out
        return out


def _http(transport, scope=SCOPE, limits=None):
    return GuardedHttpClient(ScopeGuard(scope), RunBudget(limits or Limits(rate_rps=0)), transport)


def _write(path, doc):
    path.write_text(yaml.safe_dump(doc))
    return path


# ── assessment (VER-005) ──────────────────────────────────────────────────────

def test_a_valid_assessment_is_read(tmp_path):
    doc = read_assessment(_write(tmp_path / "a.yaml", {"meta": {"project": "shop"}, "threats": [THREAT]}))
    assert doc["threats"][0]["id"] == "T-1"


@pytest.mark.parametrize("doc, expected", [
    ({"meta": {}}, "file: 'threats' is a required property"),
    ({"threats": {"T-1": THREAT}}, "threats: must be array"),
    ({"threats": ["T-1"]}, "threats/0: must be object"),
    ({"threats": [{"cwe": "CWE-79"}]}, "threats/0: 'id' is a required property"),
    ({"threats": [dict(THREAT, id="")]}, "threats/0/id: must not be empty"),
    ({"threats": [dict(THREAT, cwe=["leak-marker"])]}, "threats/0/cwe: must be string"),
    ({"threats": [dict(THREAT, evidence={"file": ["leak-marker"]})]}, "threats/0/evidence/file: must be string"),
])
def test_a_malformed_assessment_is_refused_without_its_values(tmp_path, doc, expected):
    with pytest.raises(AssessmentError) as err:
        read_assessment(_write(tmp_path / "a.yaml", doc))
    assert expected in err.value.errors and "leak-marker" not in str(err.value)


def test_repeated_ids_are_refused_and_quoted_escaped(tmp_path):
    rogue = "T-1\x1b[31m"
    with pytest.raises(AssessmentError) as err:
        read_assessment(_write(tmp_path / "a.yaml", {"threats": [dict(THREAT, id=rogue), dict(THREAT, id=rogue)]}))
    assert "is used 2 times" in str(err.value) and "\x1b" not in str(err.value)


def test_the_guided_run_blocks_on_a_malformed_assessment_before_any_question(tmp_path, capsys):
    path = _write(tmp_path / "a.yaml", {"findings": []})
    args = cli.build_guided_parser().parse_args([str(path)])
    assert guided.run_guided(args, interactive=True, ask=lambda prompt: pytest.fail(prompt)) == cli.EXIT_BLOCKED
    assert "'threats' is a required property" in capsys.readouterr().err


# ── proxy settings (VER-016, VER-029) ─────────────────────────────────────────

def test_proxy_credentials_must_be_set_and_never_inline():
    scope = dict(SCOPE, proxy=PROXY)
    assert cli._check_proxy(scope, {"PROXY_USER": "u", "PROXY_PASS": SECRET}) == []
    assert cli._check_proxy(scope, {"PROXY_USER": "u"}) == ["proxy: environment variable PROXY_PASS is not set"]
    inline = dict(SCOPE, proxy={"url": f"http://u:{SECRET}@proxy.corp.example:8080"})
    errors = cli._check_proxy(inline, {})
    assert errors and "must not contain credentials" in errors[0] and SECRET not in errors[0]
    assert cli._check_proxy(dict(SCOPE, proxy={"url": "http://p:8080", "username_env": "U"}), {"U": "u"}) == [
        "proxy: username_env and password_env are needed together"]
    assert "http or https URL" in cli._check_proxy(dict(SCOPE, proxy={"url": "socks5://p:1080"}), {})[0]
    assert cli._check_proxy(SCOPE, {}) == []


def test_proxy_for_names_host_and_port_only():
    scope = dict(SCOPE, proxy={"url": f"http://u:{SECRET}@proxy.corp.example:8080", "no_proxy": ["intra.example"]})
    assert proxy_for(scope, BASE) == "proxy.corp.example:8080"
    assert proxy_for(scope, "https://intra.example/x") is None
    assert proxy_for(SCOPE, BASE) is None


def test_verify_blocks_on_a_missing_proxy_variable_before_any_contact(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PROXY_PASS", raising=False)
    monkeypatch.setenv("PROXY_USER", "u")
    target = Target()
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: target)
    rc = cli.main(["verify", "--assessment", str(_write(tmp_path / "a.yaml", {"threats": [THREAT]})),
                   "--scope", str(_write(tmp_path / "s.yaml", dict(SCOPE, proxy=PROXY))), "--yes",
                   "--output", str(tmp_path / "out")])
    assert rc == cli.EXIT_BLOCKED and target.calls == []
    assert "PROXY_PASS is not set" in capsys.readouterr().err


# ── target (VER-003, VER-029) ─────────────────────────────────────────────────

def test_an_answering_target_passes():
    target = Target({("GET", BASE): _resp(302, headers={"Location": "/login"})})
    check = check_target(_http(target), BASE, proxy=None)
    assert check.status == "ok" and "HTTP 302" in check.message
    assert len(target.calls) == 1                                    # the redirect is not followed


def test_a_server_error_warns_and_a_proxy_407_fails():
    assert check_target(_http(Target(default=_resp(503))), BASE, proxy=None).status == "warn"
    check = check_target(_http(Target(default=_resp(407))), BASE, proxy="proxy.corp.example:8080")
    assert check.status == "fail" and "requires authentication (HTTP 407)" in check.message


def _raised(exc, cause):
    try:
        raise exc from cause
    except type(exc) as raised:
        return raised


@pytest.mark.parametrize("error, proxy, expected", [
    (httpx.ProxyError("407 Proxy Authentication Required"), "p:8080", "the proxy p:8080 requires authentication"),
    (httpx.ProxyError("403 Forbidden"), "p:8080", "the proxy p:8080 refused the connection (HTTP 403)"),
    (_raised(httpx.ConnectError(f"http://u:{SECRET}@p:8080"), ConnectionRefusedError()), "p:8080",
     "the proxy p:8080 refused the connection"),
    (_raised(httpx.ConnectError(f"cannot resolve {SECRET}"), socket.gaierror()), None,
     "the host name of the server does not resolve"),
    (_raised(httpx.ConnectError(SECRET), ssl.SSLCertVerificationError()), None, "TLS certificate is not accepted"),
    (httpx.ConnectTimeout(SECRET), None, "no connection to the server in time"),
    (httpx.ReadTimeout(SECRET), None, "no answer in time"),
])
def test_a_failed_connection_names_a_fixed_cause_never_the_error_text(error, proxy, expected):
    check = check_target(_http(Target(default=error)), BASE, proxy=proxy)
    assert check.status == "fail" and expected in check.message and SECRET not in check.message


def test_an_out_of_scope_url_is_refused_before_any_connection():
    target = Target(default=_resp())
    check = check_target(_http(target), "https://elsewhere.example.com/", proxy=None)
    assert check.status == "fail" and "refused by the scope" in check.message and target.calls == []


def test_a_closed_window_stops_the_check():
    closed = dict(SCOPE, window={"from": "2020-01-01T00:00:00Z", "until": "2020-01-02T00:00:00Z"})
    target = Target(default=_resp())
    check = check_target(_http(target, scope=closed), BASE, proxy=None)
    assert check.status == "fail" and "limit" in check.message and target.calls == []


# ── identities (VER-016, VER-028) ─────────────────────────────────────────────

FORM = {"role": "alice", "method": "form",
        "auth": {"login_url": f"{BASE}/rest/user/login", "username_env": "AU", "password_env": "AP"}}
ENV = {"AU": "alice@example.com", "AP": SECRET, "TOK": "tok-" + SECRET}


def _identities(identities, target, env=ENV):
    http = _http(target)
    return check_identities(SessionManager(identities, http, env=env), identities, http, BASE, scope=SCOPE)


def test_a_form_login_passes_once_and_its_token_is_reused():
    target = Target({("POST", f"{BASE}/rest/user/login"): _resp(200, {"authentication": {"token": "T0K3N"}})})
    http = _http(target)
    sessions = SessionManager([FORM], http, env=ENV)
    [check] = check_identities(sessions, [FORM], http, BASE, scope=SCOPE)
    assert check.status == "ok" and check.message == "form: logged in"
    sessions.headers_for("alice")                                     # the run reuses it, no second login
    assert len(target.calls) == 1


def test_a_rejected_login_is_not_retried_and_shows_no_secret_or_body():
    body = {"error": f"wrong password {SECRET} for alice@example.com"}
    target = Target({("POST", f"{BASE}/rest/user/login"): _resp(401, body)})
    [check] = _identities([FORM], target)
    assert check.status == "fail" and "HTTP 401" in check.message
    assert SECRET not in check.message and "wrong password" not in check.message and "alice@" not in check.message
    assert len(target.calls) == 1


def test_an_unreachable_login_endpoint_names_the_cause():
    error = _raised(httpx.ConnectError(SECRET), ConnectionRefusedError())
    [check] = _identities([FORM], Target(default=error))
    assert check.status == "fail" and "refused the connection" in check.message and SECRET not in check.message


def test_a_static_token_without_check_url_is_reported_as_unchecked():
    target = Target()
    checks = _identities([{"role": "svc", "method": "bearer", "auth": {"token_env": "TOK"}},
                          {"role": "anonymous", "method": "none"}], target)
    assert [(c.status, c.message) for c in checks] == [
        ("info", "bearer: credentials set; not checked against the target (no check_url)"),
        ("info", "no credentials")]
    assert target.calls == []


@pytest.mark.parametrize("status, expected", [(200, "ok"), (204, "ok"), (401, "fail"), (403, "fail"),
                                              (302, "warn"), (404, "warn")])
def test_check_url_decides_by_status(status, expected):
    ident = {"role": "svc", "method": "bearer", "auth": {"token_env": "TOK", "check_url": f"{BASE}/rest/me"}}
    target = Target({("GET", f"{BASE}/rest/me"): _resp(status)})
    [check] = _identities([ident], target)
    assert check.status == expected and f"HTTP {status}" in check.message and ENV["TOK"] not in check.message
    assert target.calls[0][2] == {"Authorization": f"Bearer {ENV['TOK']}"}


def test_check_url_on_another_origin_gets_no_credentials():
    ident = {"role": "svc", "method": "bearer",
             "auth": {"token_env": "TOK", "check_url": "https://sso.example.com/userinfo"}}
    target = Target(default=_resp())
    [check] = _identities([ident], target)
    assert check.status == "fail" and "not on https://app.example.com" in check.message and target.calls == []


def test_check_url_is_checked_offline(tmp_path):
    path = _write(tmp_path / "i.yaml", {"identities": [
        {"role": "anon", "method": "none", "auth": {"check_url": f"{BASE}/rest/me"}},
        {"role": "svc", "method": "bearer", "auth": {"token_env": "TOK", "check_url": "https://evil.example/"}}]})
    _, errors = cli._check_identities(str(path), ScopeGuard(SCOPE), ENV)
    assert errors[0] == "anon: check_url needs an identity with credentials, not method none"
    assert errors[1].startswith("svc: check_url is outside the scope")


# ── model (VER-023) ───────────────────────────────────────────────────────────

class Models:
    def __init__(self, outcome=None):
        self.outcome, self.options, self.retrieved = outcome, [], []
        self.models = self

    def with_options(self, **options):
        self.options.append(options)
        return self

    def retrieve(self, model):
        self.retrieved.append(model)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return SimpleNamespace(id=model)


def _status_error(status):
    error = Exception(f"provider prose {SECRET}")
    error.status_code = status
    return error


def test_anthropic_access_check_reads_metadata_once():
    client = Models()
    AnthropicHost(model="claude-opus-5-5", prices={}, client=client).check_access(30)
    assert client.retrieved == ["claude-opus-5-5"] and client.options == [{"timeout": 30, "max_retries": 0}]


@pytest.mark.parametrize("status, reason", [(401, "authentication_failed"), (404, "model_unavailable")])
def test_anthropic_access_check_fails_with_a_fixed_reason(status, reason):
    host = AnthropicHost(model="claude-opus-5-5", prices={}, client=Models(_status_error(status)))
    with pytest.raises(HostUnavailable) as err:
        host.check_access(30)
    assert reason in str(err.value) and SECRET not in str(err.value)


def test_openai_access_check_sends_the_key_only_to_the_models_endpoint():
    seen = []

    def get(url, headers, timeout):
        seen.append((url, headers, timeout))
        return 200

    OpenAIHost(model="gpt-6-luna", prices={}, api_key=SECRET, get=get).check_access(30)
    assert seen == [(f"{MODELS_ENDPOINT}/gpt-6-luna", {"Authorization": f"Bearer {SECRET}"}, 30)]


@pytest.mark.parametrize("outcome, reason", [(401, "authentication_failed (HTTP 401)"),
                                             (404, "model_unavailable (HTTP 404)"),
                                             (httpx.ConnectTimeout("x"), "timeout"),
                                             (httpx.ConnectError(SECRET), "connection_failed")])
def test_openai_access_check_fails_with_a_fixed_reason(outcome, reason):
    def get(url, headers, timeout):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    with pytest.raises(HostUnavailable) as err:
        OpenAIHost(model="gpt-6-luna", prices={}, api_key="k", get=get).check_access(30)
    assert reason in str(err.value) and SECRET not in str(err.value)


def test_only_api_hosts_are_asked_and_only_when_requested(monkeypatch):
    from appsec_verifier.agent import profiles
    from appsec_verifier.agent.host_claude import ClaudeHost

    asked = []
    api = SimpleNamespace(model="m", label="API", version="", auth="API key", api_billing=True,
                          check_access=lambda timeout: asked.append(timeout))
    monkeypatch.setattr(AnthropicHost, "resolve", classmethod(lambda cls, model, environ: api))
    assert profiles.resolve("anthropic-api", environ={})[1]["check"] == "local configuration checked"
    assert asked == []
    assert profiles.resolve("anthropic-api", environ={}, check_access=True)[1]["check"] == "model metadata accessible"
    assert asked == [profiles.ACCESS_TIMEOUT_S]
    cli_host = SimpleNamespace(model="m", label="Claude CLI", version="2", auth="login", api_billing=False)
    monkeypatch.setattr(ClaudeHost, "resolve", classmethod(lambda cls, model, environ: cli_host))
    assert profiles.resolve("claude", environ={}, check_access=True)[1]["check"] == "local configuration checked"


# ── generation test (VER-017, VER-019) ────────────────────────────────────────

class Host:
    model = "m"

    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def call(self, system, prompt, timeout, budget):
        self.calls.append((system, prompt))
        return self.reply


VALID = {"action": "submit_verdict",
         "args_json": json.dumps({"verdict": "inconclusive", "rationale": "appsec-verifier connectivity test"})}


def _budget(cost=0.05):
    return RunBudget(Limits(cost_limit_usd=cost, max_calls=1))


def test_the_requested_step_passes_with_a_fixed_prompt_only():
    host = Host(HostReply(step=VALID, usd=0.001))
    check = generation_test(host, _budget())
    assert check.status == "ok" and "$0.0010" in check.message
    assert host.calls == [(_TEST_SYSTEM, _TEST_PROMPT)]
    budget = _budget()      # subscription without --show-costs: no amount shown, the limit still counts it
    hidden = generation_test(Host(HostReply(step=VALID, usd=0.001)), budget, show_costs=False)
    assert hidden.status == "ok" and "$" not in hidden.message and budget.cost == 0.001


@pytest.mark.parametrize("reply, expected", [
    (HostReply(step={"action": "submit_verdict", "args_json": "{}"}), "not the requested step"),
    (HostReply(step={"action": "http_request", "args_json": json.dumps({"path": "/"})}), "not the requested step"),
    (HostReply(error="authentication_failed (exit 1)"), "the call failed: authentication_failed"),
    (HostReply(breach="the session offered tools ['Bash']"), "confinement check failed"),
    (HostReply(step=VALID, usd=0.5), "stopped by the test limit"),
])
def test_anything_else_fails(reply, expected):
    check = generation_test(Host(reply), _budget())
    assert check.status == "fail" and expected in check.message


def test_no_call_beyond_the_one_allowed():
    budget = _budget()
    budget.note_call()
    host = Host(HostReply(step=VALID))
    assert generation_test(host, budget).status == "fail" and host.calls == []


# ── the preflight command ─────────────────────────────────────────────────────

INFO = {"profile": "anthropic-api", "model": "m", "runtime": "Anthropic API", "auth": "API key",
        "check": "model metadata accessible", "api_billing": True}


@pytest.fixture
def run(tmp_path, monkeypatch):
    """`appsec-verifier preflight` against a fake target and a fake model host."""
    monkeypatch.setenv("AU", ENV["AU"])
    monkeypatch.setenv("AP", SECRET)
    files = {"assessment": _write(tmp_path / "a.yaml", {"meta": {"project": "shop", "generated": "2026-11-01"},
                                                        "threats": [THREAT]}),
             "scope": _write(tmp_path / "s.yaml", {**SCOPE, "test_resources": [{"id": "owned", "finding_id": "T-1",
                       "path": "/resource", "allowed_roles": ["alice"], "denied_roles": ["anonymous"],
                       "pointer": "/marker", "value": "fixture-resource"}]}),
             "identities": _write(tmp_path / "i.yaml", {"identities": [FORM]})}
    state = SimpleNamespace(target=Target({("GET", BASE): _resp(200),
                                           ("POST", f"{BASE}/rest/user/login"): _resp(200, {"token": "T0K3N"})}),
                            host=Host(HostReply(step=VALID, usd=0.001)), access=[], files=files)

    def factory(args, environ=None, check_access=True):
        state.access.append(check_access)
        return SimpleNamespace(host=state.host), dict(INFO)

    monkeypatch.setattr(cli, "_build_planner_factory", factory)
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: state.target)

    def go(*extra):
        argv = ["preflight", *(f"--{k}={v}" for k, v in files.items()), "--profile", "anthropic-api", *extra]
        return cli.main(argv)

    state.go = go
    return state


def test_preflight_passes_and_prints_json_without_secrets(run, capsys):
    assert run.go("--json", "--yes") == cli.EXIT_OK
    out, err = capsys.readouterr()
    result = json.loads(out)
    assert result["ok"] and result["verification"] == "not_run"
    assert [c["check"] for c in result["checks"]] == ["Assessment", "Scope", "Identities", "Test plan", "Model",
                                                      "Target", "alice"]
    assert "shop · 2026-11-01 · 1 findings: 1 dynamic" in result["checks"][0]["message"]
    assert SECRET not in out + err and "T0K3N" not in out + err
    assert [c[0] for c in run.target.calls] == ["GET", "POST"] and run.host.calls == []


def test_without_confirmation_nothing_is_contacted(run, capsys):
    assert run.go("--non-interactive") == cli.EXIT_BLOCKED
    assert run.target.calls == [] and "confirm with --yes, or use --offline" in capsys.readouterr().out


def test_offline_contacts_neither_target_nor_provider(run, capsys):
    assert run.go("--offline", "--non-interactive") == cli.EXIT_OK
    assert run.target.calls == [] and run.access == [False]
    assert "not contacted (--offline)" in capsys.readouterr().out


def test_preflight_shows_the_test_plan_and_what_the_others_need(run, monkeypatch, capsys):
    _write(run.files["assessment"], {"threats": [THREAT, dict(THREAT, id="T-2", cwe="CWE-79"),
                                                 dict(THREAT, id="T-3", cwe="CWE-918")]})

    def no_playwright():
        raise BrowserUnavailable("Playwright is not installed; run `pip install …`")

    monkeypatch.setattr(ProofBrowser, "check_available", staticmethod(no_playwright))
    assert run.go("--offline", "--non-interactive") == cli.EXIT_OK      # what is missing warns, never fails
    out = capsys.readouterr().out
    assert "⚠ Test plan    1 of 3 findings can be tested; the others need what this run does not have" in out
    assert "1 of 3 findings will be tested" in out and "Not testable" in out
    assert "Playwright is not installed" in out and "callback: {host: 127.0.0.1" in out
    assert out.index("Not testable") < out.index("preflight passed")
    assert run.target.calls == [] and run.host.calls == []


def test_preflight_warns_when_no_finding_can_be_tested(run, capsys):
    run.files.pop("identities")
    assert run.go("--offline", "--json") == cli.EXIT_OK
    out, err = capsys.readouterr()
    plan = next(c for c in json.loads(out)["checks"] if c["check"] == "Test plan")
    assert plan["status"] == "warn" and "verify stops before contacting the target" in plan["message"]
    assert "test identity" in err and "Not testable" not in out          # the plan goes to stderr with --json


def test_with_json_the_test_plan_goes_to_stderr(run, capsys):
    assert run.go("--offline", "--json") == cli.EXIT_OK
    out, err = capsys.readouterr()
    plan = next(c for c in json.loads(out)["checks"] if c["check"] == "Test plan")
    assert plan == {"check": "Test plan", "status": "ok", "message": "1 finding can be tested"}
    assert "1 of 1 finding will be tested" in err and "will be tested" not in out


def test_no_test_plan_when_an_input_cannot_be_used(run, monkeypatch, capsys):
    monkeypatch.delenv("AP")
    assert run.go("--offline") == cli.EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "Test plan" not in out and "preflight failed" in out


def test_a_malformed_assessment_stops_before_any_contact(run, capsys):
    _write(run.files["assessment"], {"threats": [{"title": "no id"}]})
    assert run.go("--yes") == cli.EXIT_BLOCKED
    assert run.target.calls == [] and "'id' is a required property" in capsys.readouterr().out


def test_an_unreachable_target_skips_the_logins(run):
    run.target.answers[("GET", BASE)] = _raised(httpx.ConnectError(SECRET), ConnectionRefusedError())
    assert run.go("--yes") == cli.EXIT_BLOCKED
    assert [c[0] for c in run.target.calls] == ["GET"]


@pytest.mark.parametrize("extra, problem", [
    ((), "--test-model needs --cost-limit of at least 0.01"),
    (("--cost-limit", "0.001"), "--test-model needs --cost-limit of at least 0.01"),
    (("--cost-limit", "0.10", "--offline"), "cannot run with --offline"),
])
def test_the_generation_test_needs_its_own_limit(run, capsys, extra, problem):
    assert run.go("--test-model", "--yes", *extra) == cli.EXIT_BLOCKED
    assert problem in capsys.readouterr().out and run.host.calls == [] and run.target.calls == []


def test_a_subscription_profile_needs_a_call_limit_instead(run, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args, environ=None, check_access=True: (
        SimpleNamespace(host=run.host), dict(INFO, profile="codex-cli", check="local configuration checked")))
    assert run.go("--test-model", "--yes") == cli.EXIT_BLOCKED
    assert "needs --max-calls 1" in capsys.readouterr().out and run.host.calls == []
    assert run.go("--test-model", "--max-calls", "1", "--yes") == cli.EXIT_OK and len(run.host.calls) == 1


def test_the_generation_test_runs_once_on_request(run, capsys):
    assert run.go("--test-model", "--cost-limit", "0.10", "--yes") == cli.EXIT_OK
    assert run.host.calls == [(_TEST_SYSTEM, _TEST_PROMPT)]
    assert "m answered with a valid step" in capsys.readouterr().out


# ── verify runs the same checks before the first model call ───────────────────

def _verify(tmp_path, monkeypatch, target, identities=None):
    asked = []

    class Planner:
        def next_step(self, ctx, history):
            asked.append(1)
            return {"verdict": {"verdict": "inconclusive", "rationale": "x"}}

    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, dict(INFO)))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: target)
    argv = ["verify", "--assessment", str(_write(tmp_path / "a.yaml", {"threats": [THREAT]})),
            "--scope", str(_write(tmp_path / "s.yaml", SCOPE)), "--yes", "--test-all",
            "--output", str(tmp_path / "out")]
    if identities:
        argv += ["--identities", str(_write(tmp_path / "i.yaml", {"identities": identities}))]
    return cli.main(argv), asked


def test_verify_stops_before_any_model_call_when_the_target_does_not_answer(tmp_path, monkeypatch, capsys):
    tested = []
    monkeypatch.setattr(cli, "_model_test", lambda factory, budget: tested.append(1))
    rc, asked = _verify(tmp_path, monkeypatch, Target(default=httpx.ConnectTimeout(SECRET)))
    assert rc == cli.EXIT_BLOCKED and asked == [] and tested == [] and not (tmp_path / "out").exists()
    assert "no finding was tested" in capsys.readouterr().err


def test_verify_stops_before_any_model_call_when_a_login_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("AU", ENV["AU"])
    monkeypatch.setenv("AP", SECRET)
    target = Target({("GET", BASE): _resp(200), ("POST", f"{BASE}/rest/user/login"): _resp(401, {"error": "no"})})
    rc, asked = _verify(tmp_path, monkeypatch, target, identities=[FORM])
    assert rc == cli.EXIT_BLOCKED and asked == [] and len(target.calls) == 2


def test_verify_runs_after_passing_checks(tmp_path, monkeypatch, capsys):
    rc, asked = _verify(tmp_path, monkeypatch, Target({("GET", BASE): _resp(200)}))
    assert rc == cli.EXIT_OK and asked == [1]
    out = capsys.readouterr().out
    preflight = out[out.index("Preflight"):].splitlines()[1:4]
    assert [line.split()[1] for line in preflight] == ["Target", "Identities", "Model"]
    assert "none given; only anonymous requests are possible" in preflight[1]


def test_verify_shows_the_login_programs_before_the_confirmation(tmp_path, monkeypatch, capsys):
    import sys

    program = {"role": "p", "method": "command",
               "auth": {"command": [sys.executable, "-c", "print('tok-' + 'from-prog')"]}}
    rc, asked = _verify(tmp_path, monkeypatch, Target({("GET", BASE): _resp(200)}), identities=[program])
    out = capsys.readouterr().out
    settings = out[:out.index("Preflight")]
    assert rc == cli.EXIT_OK and asked == [1]
    assert "Login programs" in settings and "outside the scope and limits" in settings and "print(" in settings
    assert "tok-from-prog" not in out                                 # the session never reaches the console


def test_verify_without_a_terminal_refuses_a_sign_in_that_needs_a_person(tmp_path, monkeypatch, capsys):
    ident = {"role": "a", "method": "oidc-authorization-code",
             "auth": {"authorize_url": f"{BASE}/auth", "token_url": f"{BASE}/token", "client_id": "cli"}}
    target = Target({("GET", BASE): _resp(200)})
    rc, asked = _verify(tmp_path, monkeypatch, target, identities=[ident])
    assert rc == cli.EXIT_BLOCKED and asked == [] and target.calls == []          # nothing contacted
    assert "needs a person to sign in" in capsys.readouterr().err


def test_verify_stops_when_two_roles_are_the_same_account(tmp_path, monkeypatch, capsys):
    import base64
    import json

    payload = base64.urlsafe_b64encode(json.dumps({"iss": BASE, "sub": "alice"}).encode()).rstrip(b"=").decode()
    monkeypatch.setenv("TOK_A", f"eyJhbGciOiJub25lIn0.{payload}.c2lnLWE")
    monkeypatch.setenv("TOK_B", f"eyJhbGciOiJub25lIn0.{payload}.c2lnLWI")
    identities = [{"role": r, "method": "bearer", "auth": {"token_env": f"TOK_{r.upper()}"}} for r in ("a", "b")]
    rc, asked = _verify(tmp_path, monkeypatch, Target({("GET", BASE): _resp(200)}), identities=identities)
    assert rc == cli.EXIT_BLOCKED and asked == []
    assert "a and b are signed in as the same account" in capsys.readouterr().out


class _Factory:
    """A planner factory over a fake host, as `_build_planner_factory` returns one."""

    def __init__(self, host, asked):
        self.host, self.asked = host, asked

    def __call__(self):
        asked = self.asked

        class Planner:
            def next_step(self, ctx, history):
                asked.append(ctx.plan.id)
                return {"verdict": {"verdict": "inconclusive", "rationale": "x"}}

        return Planner()


def _verify_with_host(tmp_path, monkeypatch, host):
    from conftest import REAL_MODEL_TEST

    asked = []
    monkeypatch.setattr(cli, "_model_test", REAL_MODEL_TEST)
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (_Factory(host, asked), dict(INFO)))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: Target({("GET", BASE): _resp(200)}))
    argv = ["verify", "--assessment", str(_write(tmp_path / "a.yaml", {"threats": [THREAT]})),
            "--scope", str(_write(tmp_path / "s.yaml", SCOPE)), "--yes", "--test-all",
            "--output", str(tmp_path / "out")]
    return cli.main(argv), asked


def test_verify_asks_the_model_one_fixed_prompt_before_the_first_finding(tmp_path, monkeypatch, capsys):
    host = Host(HostReply(step=VALID, usd=0.002))
    rc, asked = _verify_with_host(tmp_path, monkeypatch, host)
    assert rc == cli.EXIT_OK and host.calls == [(_TEST_SYSTEM, _TEST_PROMPT)] and asked == ["T-1"]
    captured = capsys.readouterr().out
    assert "✓ Model test   m answered with a valid step · $0.0020" in captured
    assert " · 1 model call · " in captured                               # the test counts against the run


@pytest.mark.parametrize("reply, cause", [
    (HostReply(error="quota_exhausted (exit 1)"), "the call failed: quota_exhausted"),
    (HostReply(breach="the session offered tools ['Bash']"), "confinement check failed"),
    (HostReply(step={"action": "http_request", "args_json": json.dumps({"path": "/"})}), "not the requested step"),
])
def test_verify_does_not_test_any_finding_when_the_model_test_fails(tmp_path, monkeypatch, capsys, reply, cause):
    rc, asked = _verify_with_host(tmp_path, monkeypatch, Host(reply))
    assert rc == cli.EXIT_BLOCKED and asked == [] and not (tmp_path / "out" / "verification.yaml").exists()
    captured = capsys.readouterr()
    assert cause in captured.out and "no finding was tested" in captured.err
