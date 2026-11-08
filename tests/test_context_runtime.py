"""Exercise targeted experiments against isolated application behavior (VER-008, VER-011, VER-017)."""

from __future__ import annotations

import copy
import json
import sqlite3
from dataclasses import replace
from urllib.parse import unquote

import pytest
from test_agent_tools import Resp, _ctx
from test_experiments import STRATEGY, verification_context

from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.cli import _blocker


def test_filter_order_drives_a_repeatable_query_experiment(tmp_path):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    db.execute("INSERT INTO items VALUES (7, 'pear')")
    seen = []

    def target(method, url, headers, **kwargs):
        value = kwargs["params"]["q"]
        seen.append(value)
        if "AND" in value:
            return Resp(400, '{"error":"filtered"}')
        # Deliberately vulnerable fixture: its filter runs before decoding.
        rows = db.execute("SELECT id FROM items WHERE name = '" + unquote(value) + "'").fetchall()
        return Resp(200, json.dumps({"ids": [r[0] for r in rows], "noise": len(seen), "echo": value}))

    ctx = _ctx(tmp_path, target)
    ctx.scope = {
        **ctx.scope,
        "injection_inputs": [
            {
                "finding_id": "T-1",
                "path": "/search",
                "input_location": "params",
                "input_name": "q",
                "semantics": "literal",
            }
        ],
    }
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", verification_context=verification_context())
    variant = ctx.plan.verification_context["variants"][0]
    variant["mechanism"]["expression"] = "SELECT id FROM items WHERE name = '<q>'"
    variant["processing"][0]["description"] = "Reject uppercase AND before percent-decoding"
    declared = {
        "kind": "boolean",
        "strategy": STRATEGY,
        "sql_template": "pear' %41%4e%44 {{predicate}} -- ",
        "hypothesis": "Decoding introduces a predicate after the keyword filter",
        "variant": "search",
        "path": "/search",
        "input_location": "params",
        "input_name": "q",
        "baseline": "pear",
        "positive": "pear' %41%4e%44 '1'='1",
        "negative": "pear' %41%4e%44 '1'='2",
        "pointer": "/ids",
    }
    variant_id = ctx.plan.verification_context["variants"][0]["id"]
    declared["variant"] = variant_id
    actions = [{"tool": "read_context", "args": {"variant": variant_id}}, {"tool": "plan_test", "args": declared}]
    actions += [
        {"tool": "run_experiment", "args": {}},
        {
            "verdict": {
                "verdict": "confirmed",
                "rationale": "Repeatable query controls",
                "proof_steps": list(range(3, 13)),
            }
        },
    ]

    class Planner:
        def next_step(self, context, history):
            if history:
                assert history[0]["result"]["context"]["processing"][0]["operation"] == "filter"
                assert history[0]["result"]["context"]["mechanism"]["binding"] == "concatenated"
            return actions.pop(0)

    try:
        result = AgentProbe("injection", Planner).run(ctx)
        assert result.verdict == "confirmed" and len(seen) == 10
        assert result.proof["variant"] == variant_id and result.proof["observation_pointer"] == "/ids"
        assert target("GET", "/search", {}, params={"q": "pear' AND '1'='1"}).status_code == 400
    finally:
        db.close()


def test_feedback_allows_a_missing_plan_to_be_repaired(tmp_path):
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(200, '{"result":"stable"}'))
    ctx.scope = {
        **ctx.scope,
        "injection_inputs": [
            {
                "finding_id": "T-1",
                "path": "/search",
                "input_location": "params",
                "input_name": "q",
                "semantics": "literal",
            }
        ],
    }
    ctx.plan = replace(ctx.plan, cls="injection")
    from test_experiments import plan

    declaration = plan()["args"]
    actions = [
        {"tool": "http_request", "args": {"path": "/search"}},
        {"verdict": {"verdict": "confirmed", "rationale": "premature", "proof_steps": [1]}},
        {"tool": "plan_test", "args": declaration},
    ]
    actions += [
        {"tool": "http_request", "args": {"path": "/search", "params": {"q": declaration[name]}}}
        for _ in range(2)
        for name in ("baseline", "positive", "negative")
    ]
    actions += [
        {
            "verdict": {
                "verdict": "not-reproducible",
                "rationale": "Stable observation under all inputs",
                "proof_steps": list(range(4, 10)),
            }
        }
    ]
    histories = []

    class Planner:
        def next_step(self, context, history):
            histories.append(copy.deepcopy(history))
            return actions.pop(0)

    result = AgentProbe("injection", Planner).run(ctx)
    assert result.verdict == "not-reproducible" and result.proof["checked"]
    assert histories[2][-1]["tool"] == "proof_feedback"
    assert histories[2][-1]["result"]["missing"]


def test_response_inspection_is_redacted_bounded_and_finding_local(tmp_path):
    secret = "fixture-only-credential"
    ctx = _ctx(
        tmp_path, lambda *a, **k: Resp(200, json.dumps({"value": secret, "tail": "x" * 5000})), env={"TA": secret}
    )
    tools = AgentTools(ctx)
    tools.http_request(path="/search")
    ctx.responses[1] = tools.take_response()
    assert secret not in ctx.responses[1]["body"]
    assert "[redacted]" in tools.read_response(steps=[1], pointer="/value")["responses"][0]["text"]
    window = tools.read_response(steps=[1])["responses"][0]
    assert len(window["text"]) == 1500 and window["more"]
    with pytest.raises(ToolError, match="this finding"):
        tools.read_response(steps=[2])
    assert AgentTools(ctx).take_response() is None


def test_forms_obey_guard_mode_and_marker_steering(tmp_path):
    sent = []
    ctx = _ctx(tmp_path, lambda m, u, h, **k: sent.append((m, u, k)) or Resp())
    tools = AgentTools(ctx)
    with pytest.raises(ToolError, match="safe"):
        tools.http_request(method="POST", path="/submit", form={"q": "value"})
    ctx.safe = ctx.read_only = False
    with pytest.raises(ToolError, match="one body format"):
        tools.http_request(method="POST", path="/submit", form={}, json={})
    with pytest.raises(ToolError, match="out of scope"):
        tools.http_request(method="POST", path="https://outside.invalid/submit", form={"q": "value"})
    tools.http_request(method="POST", path="/submit", form={"q": "value"})
    assert sent == [("POST", "https://app.example.com/submit", {"data": {"q": "value"}})]
    ctx.plan = replace(ctx.plan, cls="path-traversal")
    with pytest.raises(ToolError, match="marker file"):
        tools.http_request(method="POST", path="/submit", form={"q": "../../etc/passwd"})
    assert len(sent) == 1


@pytest.mark.parametrize("missing", ["header", "browser-interaction"])
def test_missing_capability_is_reported_before_an_attempt(tmp_path, missing):
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no request allowed"))
    v = verification_context()
    v["variants"][0]["required_capabilities"] = [missing]
    ctx.plan = replace(ctx.plan, cls="injection", verification_context=v)
    reason = _blocker(ctx.plan, identities=[], browser=None, listener=None, scope=ctx.scope, safe=True)
    assert reason[0] == "capability" and missing in reason[1]
    from test_experiments import plan

    declaration = plan()["args"] | {"variant": v["variants"][0]["id"]}
    with pytest.raises(ToolError, match="unavailable"):
        AgentTools(ctx).plan_test(**declaration)
    declaration["path"] = "/unrelated"
    with pytest.raises(ToolError, match="path"):
        AgentTools(ctx).plan_test(**declaration)
    declaration["path"] = "https://[::1/x"
    with pytest.raises(ToolError, match="path"):
        AgentTools(ctx).plan_test(**declaration)


def test_scope_resources_do_not_authorize_other_hosts_or_roles():
    from appsec_verifier.cli import _validate_scope

    resource = {
        "id": "known",
        "finding_id": "T-1",
        "path": "/known",
        "allowed_roles": ["owner"],
        "denied_roles": ["other"],
        "pointer": "/marker",
        "value": "known-fixture",
    }
    scope = {
        "schema_version": 1,
        "base_url": "https://app.example.com",
        "owner": {"name": "tester"},
        "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
        "test_resources": [resource],
    }
    assert _validate_scope(scope) == []
    for mutation in (dict(path="https://other.invalid/known"), dict(denied_roles=["owner"]), dict(json={}, form={})):
        assert _validate_scope({**scope, "test_resources": [{**resource, **mutation}]})
