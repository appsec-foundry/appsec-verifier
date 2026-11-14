"""Reported DVWA paths exercised offline, including unsupported steps (VER-008..014, VER-017, VER-047).

These fixtures test the Verifier's contracts, not the running DVWA or a model's choice of attack.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_agent_tools import Resp, _ctx
from test_cost_followup import Script, _confirm, _inj_ctx
from test_text_observation import _arithmetic

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.experiments import injection_check
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.steps import check_action
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.endpoints import Endpoint


@pytest.mark.parametrize("finding,cwe,cls", [("T-002", "CWE-89", "injection"), ("T-019", "CWE-79", "xss")])
def test_reported_header_steps_are_refused_before_target_contact(tmp_path, finding, cwe, cls):
    sent = []
    ctx = _ctx(tmp_path, lambda *a, **k: sent.append(a) or Resp(), safe=False, read_only=False)
    ctx.plan = replace(ctx.plan, id=finding, cls=cls, cwe=cwe,
                       endpoints=(Endpoint("GET", "/vulnerabilities/bac/", None),))
    script = Script([{"tool": "http_request", "args": {
        "path": "/vulnerabilities/bac/", "headers": {"X-Forwarded-For": "fixture-marker"}}}])
    result = AgentProbe(cls, lambda: script).run(ctx)
    assert not sent and result.verdict == "inconclusive"
    assert any("headers" in h.get("result", {}).get("error", "") for h in script.history)


@pytest.mark.parametrize("generated", [False, True])
def test_reported_command_post_cannot_send_unmarked_or_agent_chosen_controls(tmp_path, generated):
    sent = []
    ctx = _inj_ctx(tmp_path, lambda *a, **k: sent.append(a) or Resp(200, '{"status":"OK"}'),
                   cwe="CWE-78", method="POST", path="/vulnerabilities/api/v2/health/connectivity",
                   safe=False, read_only=False)
    ctx.marker = ("vrfcommand", "fixture")
    args = {"kind": "boolean", "hypothesis": "The target value reaches the connectivity shell command",
            "method": "POST", "path": "/vulnerabilities/api/v2/health/connectivity",
            "input_location": "json", "input_name": "target", "baseline": "127.0.0.1", "pointer": "/status"}
    if generated:
        args["expression_template"] = "127.0.0.1; printf '%s' \"$(({{expression}}))\""
    else:
        args.update(positive="127.0.0.1; true", negative="127.0.0.1; false")
    script = Script([{"tool": "plan_test", "args": args}, {"tool": "send_controls", "args": {}}, _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert script.history[0]["result"]["accepted"]
    assert result.verdict != "confirmed" and not sent
    errors = [h.get("result", {}).get("error", "") for h in script.history]
    assert any(("a write must carry" if generated else "not a challenge") in e for e in errors)


def test_status_only_answers_do_not_meet_arithmetic_proof():
    bodies = {name: '{"status":"OK"}' for name in
              ("baseline", "positive", "negative", "positive_other", "negative_other")}
    ctx, history, cited = _arithmetic(bodies)
    assert "were not returned" in injection_check(ctx, history, cited)


def test_reported_setup_get_and_comparison_cannot_become_a_post_reset_proof(tmp_path):
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no reset or target request"), safe=False, read_only=False)
    ctx.plan = replace(ctx.plan, id="T-036", cls="access-control", cwe="CWE-306",
                       endpoints=(Endpoint("POST", "/setup.php", None),))
    controller, tools = Controller(ctx), AgentTools(ctx)
    with pytest.raises(ToolError, match="no matching route"):
        controller.before("http_request", {"path": "/setup.php"})
    with pytest.raises(ToolError, match="no matching route"):
        controller.before("plan_test", {"kind": "access-control", "path": "/setup.php",
                                        "signed_in": "customer-a"})
    # A prerequisite flag passes the route check but not the separate exposure-resource boundary.
    controller.before("http_request", {"path": "/setup.php", "prerequisite": True})
    with pytest.raises(ToolError, match="operator-declared harmless read-only resource"):
        tools.http_request(path="/setup.php", prerequisite=True)
    assert ctx.budget.requests == 0


@pytest.mark.parametrize("level,status,expected", [("low", 200, "not-observed"),
                                                 ("medium", 200, "observed"),
                                                 ("medium", 500, "not-observed")])
def test_reported_medium_xss_requires_runtime_medium_observation(tmp_path, level, status, expected):
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("observation reads recorded data only"))
    ctx.plan = replace(ctx.plan, id="T-001", cls="xss", cwe="CWE-79")
    ctx.agent_history = [{"tool": "http_request", "args": {"path": "/vulnerabilities/xss_r/"},
                          "result": {"status": status}}]
    ctx.responses = {1: {"complete": True, "body": f"Security level: {level}"}}
    result = AgentTools(ctx).check_prerequisite(condition="Medium security level is active", steps=[1],
                                                text="Security level: medium")
    assert result["status"] == expected and ctx.budget.requests == 0
    assert "proof" not in result  # Observing the prerequisite is not execution of an XSS marker.


def test_reported_post_xss_reflection_does_not_supply_browser_execution(tmp_path):
    calls = []
    ctx = _ctx(tmp_path, lambda *a, **kw: calls.append(kw) or Resp(200, "<h3>fixture reflection</h3>"),
               safe=False, read_only=False)
    path = "/vulnerabilities/csrf/test_credentials.php"
    ctx.plan = replace(ctx.plan, id="T-001", cls="xss", cwe="CWE-79",
                       endpoints=(Endpoint("POST", path, None),))
    ctx.marker = ("vrfpostxss", "fixture")
    controller = Controller(ctx)
    args = {"method": "POST", "path": path, "form": {"username": "vrfpostxss", "Login": "Login"}}
    controller.before("http_request", args)
    assert AgentTools(ctx).http_request(**args)["status"] == 200 and len(calls) == 1
    invalid = check_action({"tool": "browser_check", "args": {"method": "POST", "path": path}})
    assert invalid["refused"] == "browser_check" and "method" in invalid["error"]
    with pytest.raises(ToolError, match="no matching route"):
        controller.before("browser_check", {"path": path})
    assert len(calls) == 1
