"""Runtime regressions for planned and supplemental verification (VER-005/008/011/026/035)."""

from __future__ import annotations

import copy
import json
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from test_agent_tools import Resp, _ctx
from test_experiments import STRATEGY, plan

from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.session_proof import cookie_observations
from appsec_verifier.loader import plans_from
from appsec_verifier.planning import dependency_order, expand_variants, supplement
from appsec_verifier.tools.browser import execution_context
from appsec_verifier.verify.report import merge_reports, remaining_variants


@pytest.mark.parametrize("vulnerable", [False, True])
def test_parameter_binding_and_real_query_injection(tmp_path, vulnerable):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE products(id INTEGER, name TEXT)")
    db.execute("INSERT INTO products VALUES (7, 'apple')")

    def target(m, u, h, **kwargs):
        value = kwargs["params"]["q"]
        rows = (
            db.execute("SELECT id FROM products WHERE name = '" + value + "'")
            if vulnerable
            else db.execute("SELECT id FROM products WHERE lower(name)=lower(?)", (value,))
        ).fetchall()
        return Resp(200, json.dumps({"result": [r[0] for r in rows]}))

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
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89")
    declaration = plan(baseline="apple")["args"]
    if vulnerable:
        declaration["sql_template"] = "apple' AND {{predicate}} -- "
    else:
        declaration.update(positive="APPLE", negative="banana")

    class Planner:
        def next_step(self, context, history):
            if not history:
                return {"tool": "plan_test", "args": declaration}
            if vulnerable and len(history) == 1:
                return {"tool": "run_experiment", "args": {}}
            if not vulnerable and len(history) < 7:
                group = ("baseline", "positive", "negative")[(len(history) - 1) % 3]
                return {"tool": "http_request", "args": {"path": "/search", "params": {"q": declaration[group]}}}
            if history[-1].get("tool") == "proof_feedback":
                return {"verdict": {"verdict": "inconclusive", "rationale": "controls insufficient"}}
            return {
                "verdict": {
                    "verdict": "confirmed",
                    "rationale": "test",
                    "proof_steps": list(range(2, len(history) + 1)),
                }
            }

    try:
        result = AgentProbe("injection", Planner).run(ctx)
        assert result.verdict == ("confirmed" if vulnerable else "inconclusive")
        assert result.planning
    finally:
        db.close()


def test_variants_keep_independent_coverage():
    doc = {"threats": [{"id": "T-1", "cwe": "CWE-89", "evidence": {"file": "a.py", "line": 1}}]}
    p = plans_from(doc)[0]
    p.verification_context = {
        "variants": [{"id": "a", "request": {"path": "/a"}}, {"id": "b", "request": {"path": "/b"}}]
    }
    variants = expand_variants([p])

    def report(v):
        return {
            "meta": {},
            "results": [
                {
                    "finding_ref": {"id": p.id, "variant_digest": v.variant_digest},
                    "verdict": "confirmed",
                    "proof": {"checked": True, "contract": 3},
                }
            ],
        }

    assert [x.variant_id for x in remaining_variants([p], report(variants[0]))] == ["b"]
    assert len(merge_reports(report(variants[0]), report(variants[1]))["results"]) == 2
    old = report(variants[0])
    old["results"][0]["proof"]["contract"] = 2
    assert len(remaining_variants([p], old)) == 2


def test_related_architecture_and_supplement_are_bounded():
    doc = {
        "threats": [
            {
                "id": "T-1",
                "cwe": "CWE-89",
                "severity": "high",
                "component_id": "api",
                "verification_dependencies": ["T-2"],
                "evidence": {"file": "a", "line": 1},
            },
            {
                "id": "T-2",
                "cwe": "CWE-862",
                "severity": "low",
                "scenario": "GET /actuator/metrics",
                "evidence": {"file": "b", "line": 1},
            },
            {
                "id": "T-3",
                "cwe": "CWE-862",
                "severity": "low",
                "scenario": "GET /actuator/health",
                "evidence": {"file": "c", "line": 1},
            },
        ],
        "components": [{"id": "api", "description": "relevant"}, {"id": "other", "description": "unrelated"}],
    }
    plans = plans_from(doc)
    assert plans[0].context["architecture"]["components"] == [doc["components"][0]]
    selected = supplement(plans[:1], plans)
    assert [p.id for p in dependency_order(selected)] == ["T-2", "T-1"]
    assert selected[1].selection_reason
    assert supplement(plans[:1], plans, enabled=False) == plans[:1]


@pytest.mark.parametrize("frame_kind", ["main", "child", "foreign", "old-page", "isolated"])
def test_browser_execution_attribution(frame_kind):
    main = SimpleNamespace(url="https://app.example.com/page")
    page = SimpleNamespace(main_frame=main)
    frame = (
        main
        if frame_kind not in ("child", "foreign")
        else SimpleNamespace(
            url="https://app.example.com/child" if frame_kind == "child" else "https://foreign.invalid/"
        )
    )
    source = {"frame": frame, "page": page if frame_kind != "old-page" else object()}
    assert execution_context(source, page, main.url, frame_kind == "isolated")["verified"] == (frame_kind == "main")


@pytest.mark.parametrize("secure", [False, True])
def test_session_attributes_and_secret_redaction(tmp_path, secure):
    cookie = "fixture-session-value-12345"

    def target(*a, **k):
        return httpx.Response(
            200,
            text=cookie,
            headers={"Set-Cookie": "sid=" + cookie + "; HttpOnly; SameSite=Lax" + ("; Secure" if secure else "")},
        )

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
    ctx.plan = replace(ctx.plan, cls="session", cwe="CWE-614")
    ctx.scope = {
        **ctx.scope,
        "session_checks": [{"id": "s", "finding_id": "T-1", "path": "/session", "cookie_name": "sid"}],
    }
    actions = [
        {
            "tool": "plan_test",
            "args": {
                "kind": "session",
                "hypothesis": "Session cookie lacks Secure",
                "path": "/session",
                "resource": "s",
                "strategy": copy.deepcopy(STRATEGY),
            },
        },
        *[{"tool": "http_request", "args": {"path": "/session"}} for _ in range(2)],
        {
            "verdict": {
                "verdict": "not-reproducible" if secure else "confirmed",
                "rationale": "cookie attributes",
                "proof_steps": [2, 3],
            }
        },
    ]

    class Planner:
        def next_step(self, context, history):
            assert cookie not in str(history)
            return actions.pop(0)

    result = AgentProbe("session", Planner).run(ctx)
    assert result.verdict == ("not-reproducible" if secure else "confirmed")
    assert cookie not in str(result)
    assert cookie_observations(httpx.Response(200, headers={"set-cookie": "sid=; Max-Age=0"}))[0]["active"] is False


@pytest.mark.parametrize("cwe", ["CWE-78", "CWE-1336", "CWE-643"])
@pytest.mark.parametrize("evaluate", [False, True])
def test_expression_challenges_require_computed_results(tmp_path, cwe, evaluate):
    import re

    def target(m, u, h, **kwargs):
        value = kwargs["params"]["q"]
        match = re.search(r"(\d+)([+*])(\d+)", value)
        result = value
        if evaluate and match:
            a, op, b = match.groups()
            result = int(a) * int(b) if op == "*" else int(a) + int(b)
        return Resp(200, json.dumps({"result": result}))

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
    ctx.plan = replace(ctx.plan, cwe=cwe, cls="injection")
    declaration = plan()["args"] | {"expression_template": "calc[{{expression}}]"}
    if cwe == "CWE-78":
        declaration["expression_template"] = "plain; printf '%s' \"$(({{expression}}))\""
    actions = [
        {"tool": "plan_test", "args": declaration},
        {"tool": "run_experiment", "args": {}},
        {"verdict": {"verdict": "confirmed", "rationale": "arithmetic evaluation", "proof_steps": list(range(2, 12))}},
    ]

    class Planner:
        def next_step(self, context, history):
            return actions.pop(0) if actions else {"verdict": {"verdict": "inconclusive", "rationale": "no evaluation"}}

    result = AgentProbe("injection", Planner).run(ctx)
    assert result.verdict == ("confirmed" if evaluate else "inconclusive")


def test_batch_stops_at_request_budget(tmp_path):
    from appsec_verifier.limits import Limits, RunBudget

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
    ctx.plan = replace(ctx.plan, cwe="CWE-89", cls="injection")
    budget = RunBudget(Limits(max_requests=3, rate_rps=0))
    ctx.budget = ctx.http._budget = budget
    actions = [
        {"tool": "plan_test", "args": plan()["args"] | {"sql_template": "plain' AND {{predicate}} -- "}},
        {"tool": "run_experiment", "args": {}},
    ]

    class Planner:
        def next_step(self, context, history):
            return actions.pop(0)

    result = AgentProbe("injection", Planner).run(ctx)
    assert result.verdict == "inconclusive" and result.limits_hit == "requests"


def test_unidentified_cookie_never_confirms(tmp_path):
    from appsec_verifier.agent.session_proof import session_check

    ctx = _ctx(tmp_path, lambda *a, **k: Resp())
    ctx.plan = replace(ctx.plan, cwe="CWE-614", cls="session")
    assert session_check(ctx, [], [])


def test_session_screenshot_selection_and_console_plan(tmp_path):
    import io

    from appsec_verifier.cli import screenshot_option
    from appsec_verifier.progress import RunProgress

    assert screenshot_option("session") == "session"
    stream = io.StringIO()
    progress = RunProgress(stream=stream, live=False)
    p = plans_from({"threats": [{"id": "T-1", "cwe": "CWE-614", "evidence": {"file": "a", "line": 1}}]})[0]
    progress.begin([p])
    progress.finding(p)
    progress.step(
        {
            "step": 1,
            "tool": "plan_test",
            "args": {"path": "/session", "strategy": STRATEGY},
            "result": {"accepted": True},
        }
    )
    progress.close()
    assert "counter_hypothesis" in stream.getvalue() and "/session" in stream.getvalue()


def test_expression_proof_needs_an_operator_input_contract(tmp_path):
    from appsec_verifier.agent.tools import AgentTools, ToolError

    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no request before input contract"))
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-1336")
    with pytest.raises(ToolError, match="literal input semantics"):
        AgentTools(ctx).plan_test(**(plan()["args"] | {"expression_template": "{{ {{expression}} }}"}))


@pytest.mark.parametrize("mechanism", ["nosql", "ldap"])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_literal_inputs_vs_query_operators(tmp_path, mechanism, vulnerable):
    def target(m, u, h, **kwargs):
        value = kwargs["json"]["q"] if mechanism == "nosql" else kwargs["params"]["q"]
        found = value == "apple"
        if vulnerable and isinstance(value, dict):
            found = value.get("$eq") == "apple" or value.get("$in") == ["apple"]
        if vulnerable and mechanism == "ldap" and isinstance(value, str) and value != "apple":
            found = "(|" in value and "(&" not in value
        return Resp(200, json.dumps({"result": [7] if found else []}))

    ctx = _ctx(tmp_path, target)
    location = "json" if mechanism == "nosql" else "params"
    ctx.scope = {
        **ctx.scope,
        "injection_inputs": [
            {
                "finding_id": "T-1",
                "path": "/search",
                "input_location": location,
                "input_name": "q",
                "semantics": "literal",
            }
        ],
    }
    ctx.plan = replace(ctx.plan, cwe="CWE-943" if mechanism == "nosql" else "CWE-90", cls="injection")
    declaration = plan(baseline="apple", input_location=location)["args"]
    declaration.update(
        {"operator_challenge": "nosql"}
        if mechanism == "nosql"
        else {"predicate_template": "apple){{predicate}}", "predicate_attribute": "uid"}
    )
    actions = [
        {"tool": "plan_test", "args": declaration},
        {"tool": "run_experiment", "args": {}},
        {"verdict": {"verdict": "confirmed", "rationale": "operator controls", "proof_steps": list(range(2, 12))}},
    ]

    class Planner:
        def next_step(self, context, history):
            return actions.pop(0) if actions else {"verdict": {"verdict": "inconclusive", "rationale": "literal input"}}

    result = AgentProbe("injection", Planner).run(ctx)
    assert result.verdict == ("confirmed" if vulnerable else "inconclusive")


def test_command_controls_reject_side_effects(tmp_path):
    from appsec_verifier.agent.tools import AgentTools, ToolError

    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no command sent"))
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-78")
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
    with pytest.raises(ToolError, match="harmless printf arithmetic"):
        AgentTools(ctx).plan_test(**(plan()["args"] | {"expression_template": "rm file; {{expression}}"}))
