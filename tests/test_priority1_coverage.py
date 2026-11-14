"""Runtime proof regressions for VER-010/031/049/057/061/062, with fake targets only."""
from __future__ import annotations

import copy
import json
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest
from test_access_policy import policy
from test_agent_tools import Resp, _ctx

from appsec_verifier.agent import AgentProbe
from appsec_verifier.agent.proof import check_proof
from appsec_verifier.agent.session_proof import session_check
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.cli import _blocker, _validate_scope
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.verify.probes import ProbeResult

PATH = "/admin/config"
MARKER = "harmless-management-marker"
AUTH_CHECK = {"finding_id": "T-1", "login_path": "/login", "path": "/protected",
              "pointer": "/marker", "value": "owned-test-marker"}


def resource(**extra):
    return {"id": "config", "finding_id": "T-1", "path": PATH, "allowed_roles": ["admin"],
            "denied_roles": ["anonymous"], "pointer": "/marker", "value": MARKER,
            "anonymous_only": True, "restriction": "Configuration requires administrator access.",
            "source": "Operator access policy", **extra}


def run_access(tmp_path, *, anonymous_only=False, control_marker=False, denied_marker=True):
    calls = []

    def target(method, url, headers, **kwargs):
        calls.append((method, urlsplit(url).path, dict(headers)))
        is_target = urlsplit(url).path == PATH
        match = (is_target and (bool(headers) or denied_marker)) or (not is_target and control_marker)
        return Resp(200, json.dumps({"marker": MARKER if match else "public", "counter": len(calls)}))

    ctx = _ctx(tmp_path, target)
    ctx.plan = replace(ctx.plan, cwe="CWE-306", endpoints=(Endpoint("GET", PATH, None),))
    ctx.marker = ("vrf12345678", "12345678")
    ctx.evidence_dir = tmp_path / "evidence"
    if anonymous_only:
        ctx.identities = []
        ctx.scope = {**ctx.scope, "test_resources": [resource()]}
        plan = {"kind": "access-control", "path": PATH, "resource": "config",
                "hypothesis": "Protected configuration exposed"}
    else:
        ctx.scope = {**ctx.scope, "access_policies": [{**policy(PATH), "allowed_roles": ["customer-a"],
                     "observation": {"pointer": "/marker", "value": MARKER}}]}
        plan = {"kind": "access-control", "path": PATH, "signed_in": "customer-a",
                "hypothesis": "Protected configuration exposed"}

    class Planner:
        def next_step(self, context, history):
            if not history:
                return {"tool": "plan_test", "args": plan}
            feedback = next((h["result"] for h in reversed(history) if h["tool"] == "experiment"), {})
            if feedback.get("proof") == "holds":
                return {"verdict": {"verdict": "confirmed", "rationale": "checked marker", "proof_steps": [2, 3, 4]}}
            return {"verdict": {"verdict": "inconclusive", "rationale": "marker comparison failed"}}

    return AgentProbe("access-control", Planner).run(ctx), calls, ctx


@pytest.mark.parametrize("anonymous_only", [False, True])
@pytest.mark.parametrize("control_marker,denied_marker,confirmed", [(False, True, True), (True, True, False),
                                                                  (False, False, False)])
def test_dynamic_answers_require_declared_marker_and_real_control(tmp_path, anonymous_only,
                                                                 control_marker, denied_marker, confirmed):
    result, calls, ctx = run_access(tmp_path, anonymous_only=anonymous_only, control_marker=control_marker,
                                   denied_marker=denied_marker)
    assert (result.verdict == "confirmed") == confirmed, result.rationale
    assert len(calls) == 3
    if anonymous_only:
        assert all(not headers for _, _, headers in calls)
        assert _blocker(ctx.plan, identities=[], browser=None, listener=None, scope=ctx.scope, safe=True) is None
    if confirmed:
        assert result.proof["form"] == ("declared-exposure" if anonymous_only else "selected-access")


@pytest.mark.parametrize("change", [{"source": ""}, {"method": "POST"}, {"denied_roles": ["customer-a"]}])
def test_exposure_declarations_fail_closed(tmp_path, change):
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("must not contact target"))
    ctx.plan = replace(ctx.plan, cwe="CWE-306")
    ctx.scope = {**ctx.scope, "test_resources": [resource(**change)]}
    with pytest.raises(ToolError):
        AgentTools(ctx).plan_test(kind="access-control", path=PATH, resource="config", hypothesis="exposure")


@pytest.mark.parametrize("value,sent", [(True, {"params": {"flag": True}}),
                                       ("harmless", {"path": "/%68armless"}),
                                       ("harmless", {"params": {"q": "%2568armless"}})])
def test_selected_observation_refuses_literal_and_encoded_reflections(value, sent):
    from appsec_verifier.agent.access_observation import matches

    observation = {"pointer": "/marker", "value": value}
    assert matches(json.dumps({"marker": value}), observation, {"path": "/private"})
    assert not matches(json.dumps({"marker": value}), observation, sent)


@pytest.mark.parametrize("same_identity,marker_present", [(False, True), (True, True), (False, False)])
def test_selected_privileged_comparison_preserves_independent_identity_requirement(tmp_path,
                                                                                  same_identity, marker_present):
    from test_own_access import ENV, IDENTITIES

    calls = []

    def target(method, url, headers, **kwargs):
        calls.append(dict(headers))
        if not headers:
            return Resp(401, "login required")
        match = headers.get("Authorization") == "Bearer " + ENV["C"] or marker_present
        return Resp(200, json.dumps({"marker": MARKER if match else "public", "counter": len(calls)}))

    env = {**ENV, **({"A": ENV["C"]} if same_identity else {})}
    ctx = _ctx(tmp_path, target, env=env, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, cwe="CWE-862", endpoints=(Endpoint("GET", PATH, None),))
    ctx.scope = {**ctx.scope, "access_policies": [{**policy(PATH, allowed=("admin-1",), denied=("account-1",)),
                                                "observation": {"pointer": "/marker", "value": MARKER}}]}
    from test_cost_followup import Script

    script = Script([{"tool": "plan_test", "args": {"kind": "access-control", "reference": "admin-1",
                      "path": PATH, "hypothesis": "normal account reads protected configuration"}},
                     *[{"tool": "http_request", "args": {"method": "GET", "path": PATH, **role}}
                       for role in ({"role": "admin-1"}, {}, {"role": "account-1"})],
                     {"verdict": {"verdict": "confirmed", "rationale": "compare marker", "proof_steps": [2, 3, 4]}}])
    result = AgentProbe("access-control", lambda: script).run(ctx)
    assert (result.verdict == "confirmed") is (not same_identity and marker_present), result.rationale


@pytest.mark.parametrize("usable,public", [(True, False), (False, False), (True, True)])
def test_auth_followup_uses_only_obtained_artifact_and_never_renews(tmp_path, usable, public):
    secret = "isolated-test-artifact-123456789"
    sent = []

    def target(method, url, headers, **kwargs):
        sent.append((method, url, dict(headers)))
        if url.endswith("/login"):
            return Resp(200, json.dumps({"token": secret}))
        allowed = public or usable and headers.get("Authorization") == "Bearer " + secret
        return Resp(200 if allowed else 401, json.dumps({"marker": "owned-test-marker" if allowed else "absent"}))

    ctx = _ctx(tmp_path, target, safe=False, read_only=False)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89")
    ctx.scope = {**ctx.scope, "auth_checks": [AUTH_CHECK]}
    tools = AgentTools(ctx)
    tools._experiment = {"kind": "boolean", "path": "/login", "auth_artifact": True, "pointer": "/token"}
    result = tools.http_request(method="POST", path="/login", json={"email": "test"})
    assert result["auth_access"]["matched"] is (usable or public)
    assert len(sent) == 2 and sent[-1][2] == {"Authorization": "Bearer " + secret}
    assert secret not in str(result) + str(tools._last_response) + str(tools.take_exchanges())


def test_login_bypass_rejects_artifact_presence_without_followup():
    from test_proof import _AUTH_HISTORY
    from test_proof import _ctx as proof_context

    history = copy.deepcopy(_AUTH_HISTORY)
    check = {**AUTH_CHECK, "login_path": "/rest/user/login"}
    ctx = proof_context("injection", scope={"auth_checks": [check]})
    for step in history[1:]:
        step["result"].pop("auth_access", None)
    result = check_proof(ctx, history, ProbeResult("confirmed"), [2, 3, 4, 5, 6])
    assert result.verdict == "inconclusive"


def test_cookie_observations_include_post_redirect_and_keep_no_values(tmp_path):
    from appsec_verifier.auth import SessionManager

    cookie = "fixture-cookie-0123456789"
    observations = []
    manager = SessionManager([], None)
    manager._observing_role = "account"
    for _ in range(2):
        response = httpx.Response(302, headers={"set-cookie": f"sid={cookie}; HttpOnly; SameSite=Lax"})
        manager._observe_cookies(response, "POST", "https://app.example.com/login")
    observations = manager._login_cookie_observations
    assert cookie not in str(observations)
    check = {"id": "login-cookie", "finding_id": "T-1", "path": "/login", "role": "account",
             "cookie_name": "sid", "source": "login"}
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-1", cwe="CWE-614"), scope={"session_checks": [check]})
    history = [{"tool": "plan_test", "args": {"kind": "session", "resource": "login-cookie"},
                "result": {"accepted": True, "login_observations": observations}}]
    assert session_check(ctx, history, [1]) is None
    assert session_check(ctx, history, [1], negative=True)
    observations[1]["session_cookies"][0]["secure"] = True
    assert session_check(ctx, history, [1])
    observations.pop()
    assert session_check(ctx, history, [1, 1])  # one observation cited twice is still one


def test_scope_refuses_external_followup_and_ambiguous_observations():
    from test_guided import SCOPE

    scope = copy.deepcopy(SCOPE)
    scope["auth_checks"] = [{**AUTH_CHECK, "path": "https://outside.example/protected"}]
    assert _validate_scope(scope)


def test_guided_preparation_is_run_only_validated_and_declining_contacts_nothing():
    from test_guided import SCOPE

    from appsec_verifier.guided import Dialog, _access_preparation
    from appsec_verifier.loader import classify, load_verifiable_cwes

    plan = classify({"id": "T-1", "cwe": "CWE-306", "title": "Management exposure",
                     "severity": "high", "evidence": {"file": "app.py", "line": 1}}, load_verifiable_cwes())
    from appsec_verifier.cli import build_guided_parser

    args = build_guided_parser().parse_args(["assessment.yaml"])
    answers = iter(["yes", "yes", PATH, "admin", "anonymous", "Only administrators may read configuration",
                    "Operator policy", "/marker", MARKER, "yes"])
    scope = copy.deepcopy(SCOPE)
    before = copy.deepcopy(scope)
    _access_preparation(Dialog(lambda _: next(answers), lambda _: None), args, scope, [plan])
    assert args._guided_resources[0]["anonymous_only"] is True
    assert _validate_scope(scope) == []
    assert {k: v for k, v in scope.items() if k != "test_resources"} == before
    assert scope["test_resources"][0]["source"] == "Operator policy"


def test_real_form_login_observations_are_bounded_and_survive_redirects():
    from test_html_login import Dvwa, manager

    target = Dvwa()
    sessions = manager(target)
    sessions.headers_for("admin")
    observations = sessions.observe_login("admin")
    count = len(target.calls)
    assert len([o for o in observations if o["method"] == "POST" and o["status"] == 302]) == 2
    assert sessions.observe_login("admin") == observations and len(target.calls) == count
    assert "sid0001" not in str(observations)


@pytest.mark.parametrize("changed", ["negative_access", "positive_denied", "missing_followup"])
def test_login_bypass_requires_positive_access_and_denied_controls(changed):
    from test_proof import _AUTH_HISTORY
    from test_proof import _ctx as proof_context

    history = copy.deepcopy(_AUTH_HISTORY)
    if changed == "negative_access":
        history[4]["result"]["auth_access"]["matched"] = True
    elif changed == "positive_denied":
        history[1]["result"]["auth_access"]["matched"] = False
    else:
        history[1]["result"].pop("auth_access")
    check = {**AUTH_CHECK, "login_path": "/rest/user/login"}
    result = check_proof(proof_context("injection", scope={"auth_checks": [check]}), history,
                         ProbeResult("confirmed"), [2, 3, 4, 5, 6])
    assert result.verdict == "inconclusive"


@pytest.mark.parametrize("verdict", ["confirmed", "inconclusive"])
def test_session_probe_retains_login_cookie_evidence_without_replaying_model_credentials(tmp_path, verdict):
    from test_html_login import ADMIN, URL, Dvwa, manager
    from test_poc import RenderBrowser

    target = Dvwa()
    sessions = manager(target)
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no agent target request expected"))
    ctx.plan = replace(ctx.plan, cls="session", cwe="CWE-614", endpoints=(Endpoint("POST", "/login.php", None),))
    ctx.target_base = URL
    ctx.sessions = sessions
    ctx.identities = [ADMIN]
    check = {"id": "cookie", "finding_id": "T-1", "path": "/login.php", "role": "admin",
             "cookie_name": "PHPSESSID", "source": "login"}
    ctx.scope = {"base_url": URL, "session_checks": [check]}
    from appsec_verifier.scope import ScopeGuard
    ctx.guard = ScopeGuard(ctx.scope)
    ctx.evidence_dir = tmp_path / "evidence"
    ctx.browser = RenderBrowser(screenshots=["session"])

    class Planner:
        def next_step(self, context, history):
            if not history:
                return {"tool": "plan_test", "args": {"kind": "session", "path": "/login.php",
                        "resource": "cookie", "hypothesis": "Login session cookie has no Secure flag"}}
            return {"verdict": {"verdict": verdict, "rationale": "observed missing Secure", "proof_steps": [1]}}

    result = AgentProbe("session", Planner).run(ctx)
    assert result.verdict == verdict, result.rationale
    assert result.proof["checked"] is (verdict == "confirmed")
    assert result.identities_used == ["admin"]
    record = tmp_path / "evidence" / "T-1-cookie-observations.json"
    assert record.exists() and "sid0001" not in record.read_text()
    assert any(o["method"] == "POST" and o["status"] == 302 for o in result.proof["cookie_observations"])
    assert len(target.calls) == 6
    page = ctx.browser.exchanges[0]["html"]
    assert "Recorded login-cookie observations" in page and "Secure=False" in page
    assert "sid0001" not in page and "sid0002" not in page


@pytest.mark.parametrize("mode", ["redirect", "budget", "invalid-token", "outside-scope"])
def test_auth_followup_refuses_redirects_bad_tokens_and_scope_or_budget_bypasses(tmp_path, mode):
    from appsec_verifier.limits import LimitExceeded
    from appsec_verifier.tools.http import ScopeViolation

    sent = []
    token = "invalid\r\ninjected: value" if mode == "invalid-token" else "fake-artifact-token"

    def target(method, url, headers, **kwargs):
        sent.append(url)
        if url.endswith("/login"):
            return Resp(200, json.dumps({"token": token}))
        response = Resp(302, "")
        response.headers = {"Location": "https://outside.example/steal"}
        return response

    ctx = _ctx(tmp_path, target, safe=False, read_only=False)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89")
    ctx.scope = {**ctx.scope, "auth_checks": [{**AUTH_CHECK,
                 **({"path": "https://outside.example/protected"} if mode == "outside-scope" else {})}]}
    if mode == "budget":
        ctx.http._budget.limits.max_requests = 1
    tools = AgentTools(ctx)
    tools._experiment = {"kind": "boolean", "path": "/login", "auth_artifact": True, "pointer": "/token"}
    if mode == "redirect":
        out = tools.http_request(method="POST", path="/login", json={"input": "test"})
        assert out["auth_access"]["matched"] is False and len(sent) == 2
    else:
        with pytest.raises((ToolError, ScopeViolation, LimitExceeded)):
            tools.http_request(method="POST", path="/login", json={"input": "test"})
        assert len(sent) == 1
    assert not any("outside.example" in url for url in sent)
    assert token not in str(tools.take_exchanges())


def test_run_only_declarations_preserve_the_url_scope_boundary():
    from appsec_verifier.cli import url_scope

    scope, errors = url_scope("https://app.example.com")
    assert not errors
    scope["test_resources"] = [resource()]
    assert not _validate_scope(scope, url_only=True)
    assert _validate_scope(scope)  # A persisted scope still requires owner and window.
    scope["test_resources"][0]["path"] = "https://outside.example/private"
    assert _validate_scope(scope, url_only=True)
