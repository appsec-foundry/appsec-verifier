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
from appsec_verifier.planning import dependency_order, expand_variants, severity_order, supplement
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
            # The vulnerable plan carries a sql_template, so the Verifier runs its controls on acceptance; the
            # non-vulnerable plan has explicit controls only, so this planner sends them by hand.
            if not history:
                return {"tool": "plan_test", "args": declaration}
            if not vulnerable and len(history) < 7:
                group = ("baseline", "positive", "negative")[(len(history) - 1) % 3]
                return {"tool": "http_request", "args": {"path": "/search", "params": {"q": declaration[group]}}}
            if history[-1].get("tool") == "proof_feedback":
                return {"verdict": {"verdict": "inconclusive", "rationale": "controls insufficient"}}
            steps = [n for n, h in enumerate(history, 1) if h.get("tool") == "http_request"]
            return {"verdict": {"verdict": "confirmed", "rationale": "test", "proof_steps": steps}}

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


def test_severity_order_is_most_severe_first_but_keeps_prerequisites_ahead():
    """VER-026: most severe first with the finding number as a stable tiebreaker; a lower-severity
    prerequisite still runs before the finding that depends on it once dependency_order runs."""
    doc = {"threats": [
        {"id": "T-10", "cwe": "CWE-79", "severity": "high", "evidence": {"file": "a", "line": 1}},
        {"id": "T-2", "cwe": "CWE-89", "severity": "critical", "evidence": {"file": "b", "line": 1}},
        {"id": "T-3", "cwe": "CWE-200", "severity": "medium", "evidence": {"file": "c", "line": 1}},
        {"id": "T-1", "cwe": "CWE-89", "severity": "critical", "evidence": {"file": "d", "line": 1}},
    ]}
    plans = plans_from(doc)
    # critical before high before medium; T-1 before T-2 by number within critical
    assert [p.id for p in severity_order(plans)] == ["T-1", "T-2", "T-10", "T-3"]
    # a critical that depends on a medium prerequisite: dependency_order hoists the prerequisite,
    # severity_order keeps the rest severity-ordered.
    dep = {"threats": [
        {"id": "T-1", "cwe": "CWE-89", "severity": "critical", "verification_dependencies": ["T-9"],
         "evidence": {"file": "a", "line": 1}},
        {"id": "T-9", "cwe": "CWE-200", "severity": "medium", "evidence": {"file": "b", "line": 1}},
        {"id": "T-2", "cwe": "CWE-79", "severity": "high", "evidence": {"file": "c", "line": 1}},
    ]}
    dep_plans = plans_from(dep)
    assert [p.id for p in dependency_order(severity_order(dep_plans))] == ["T-9", "T-1", "T-2"]


def test_within_one_severity_findings_a_read_can_reach_come_first():
    """VER-026: within one severity a named read request first, then named writes only, then no request; a
    critical finding without a request still precedes a high one with a read; variants stay together."""
    from appsec_verifier.endpoints import Endpoint

    doc = {"threats": [
        {"id": "T-1", "cwe": "CWE-639", "severity": "critical", "evidence": {"file": "a", "line": 1}},
        {"id": "T-2", "cwe": "CWE-89", "severity": "critical", "evidence": {"file": "b", "line": 1}},
        {"id": "T-3", "cwe": "CWE-89", "severity": "critical", "evidence": {"file": "c", "line": 1}},
        {"id": "T-4", "cwe": "CWE-79", "severity": "high", "evidence": {"file": "d", "line": 1}},
    ]}
    by_id = {p.id: p for p in plans_from(doc)}
    plans = [by_id["T-1"],                                                            # no named request
             replace(by_id["T-2"], endpoints=(Endpoint("POST", "/rest/user/login", None),)),   # write only
             replace(by_id["T-3"], endpoints=(Endpoint("GET", "/rest/products/search", None),)),  # read
             replace(by_id["T-4"], endpoints=(Endpoint("GET", "/#/search", None),))]
    assert [p.id for p in severity_order(plans)] == ["T-3", "T-2", "T-1", "T-4"]
    p = replace(by_id["T-3"], endpoints=(Endpoint("GET", "/rest/products/search", None),))
    p.verification_context = {"variants": [{"id": "a", "request": {"method": "GET", "path": "/x"}},
                                           {"id": "b", "request": {"method": "POST", "path": "/y"}}]}
    ordered = severity_order([by_id["T-1"], *expand_variants([p])])
    assert [q.id for q in ordered] == ["T-3", "T-3", "T-1"]           # the variants are not split up


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


@pytest.mark.parametrize("secure", [False, True])
def test_session_observations_before_the_plan_count_only_for_a_confirmation(tmp_path, secure):
    """VER-043: the plan guides; for a negative verdict the observations must still follow it (VER-013)."""
    def target(*a, **k):
        return httpx.Response(200, text="ok", headers={
            "Set-Cookie": "sid=fixture-session-value-12345; HttpOnly; SameSite=Lax" + ("; Secure" if secure else "")})

    ctx = _ctx(tmp_path, target)
    ctx.plan = replace(ctx.plan, cls="session", cwe="CWE-614")
    ctx.scope = {**ctx.scope,
                 "session_checks": [{"id": "s", "finding_id": "T-1", "path": "/session", "cookie_name": "sid"}]}
    actions = [
        *[{"tool": "http_request", "args": {"path": "/session"}} for _ in range(2)],
        {"tool": "plan_test", "args": {"kind": "session", "hypothesis": "Session cookie lacks Secure",
                                       "path": "/session", "resource": "s", "strategy": copy.deepcopy(STRATEGY)}},
        {"verdict": {"verdict": "not-reproducible" if secure else "confirmed", "rationale": "cookie attributes",
                     "proof_steps": [1, 2]}},
        {"verdict": {"verdict": "inconclusive", "rationale": "no fresh observation"}},
    ]

    class Planner:
        def next_step(self, context, history):
            return actions.pop(0)

    result = AgentProbe("session", Planner).run(ctx)
    if secure:
        assert result.verdict == "inconclusive" and "must follow the declared plan" in result.rationale
    else:
        assert result.verdict == "confirmed"


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
    ]

    class Planner:
        def next_step(self, context, history):
            return actions.pop(0) if actions else {"verdict": {"verdict": "inconclusive", "rationale": "stop"}}

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
    progress.step(
        {
            "step": 2,
            "tool": "plan_test",
            "args": {"path": "/session", "strategy": STRATEGY | {"revision_reason": "cookie set on login only"}},
            "result": {"accepted": True},
        }
    )
    progress.close()
    out = stream.getvalue()
    # one row per accepted plan; the report keeps the whole plan
    assert "test plan · /session\n" in out and "plan revised · /session · cookie set on login only\n" in out
    assert not any(key in out for key in ("data_flow", "counter_hypothesis", "expected:", "stop:", "prerequisite"))


def test_expression_proof_without_a_scope_contract_accepts_the_agents_input(tmp_path):
    """VER-011: the agent chooses the input from a read request the finding names; a scope entry pins it instead.
    An entry for another finding does not pin this one."""
    from appsec_verifier.agent.tools import AgentTools, ToolError

    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no request before plan"))
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-1336")
    agents_plan = plan()["args"] | {"expression_template": "{{ {{expression}} }}"}
    assert AgentTools(ctx).plan_test(**agents_plan)["accepted"] is True
    # A pin for another finding does not block this finding's agent-chosen input.
    ctx.scope = {**ctx.scope, "injection_inputs": [{"finding_id": "T-9", "path": "/other",
                 "input_location": "params", "input_name": "x", "semantics": "literal"}]}
    assert AgentTools(ctx).plan_test(**agents_plan)["accepted"] is True
    # A pin for THIS finding must match the plan's input.
    ctx.scope = {**ctx.scope, "injection_inputs": [{"finding_id": ctx.plan.id, "path": "/other",
                 "input_location": "params", "input_name": "x", "semantics": "literal"}]}
    with pytest.raises(ToolError, match="does not match a declared injection_inputs entry"):
        AgentTools(ctx).plan_test(**agents_plan)


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


def _quick_plans():
    from appsec_verifier.endpoints import Endpoint

    doc = {"threats": [
        {"id": "T-1", "cwe": "CWE-89", "severity": "critical", "evidence": {"file": "a", "line": 1}},
        {"id": "T-2", "cwe": "CWE-79", "severity": "medium", "evidence": {"file": "b", "line": 1}},
        {"id": "T-3", "cwe": "CWE-89", "severity": "medium", "evidence": {"file": "c", "line": 1}},
        {"id": "T-4", "cwe": "CWE-79", "severity": "medium", "evidence": {"file": "d", "line": 1}},
        {"id": "T-5", "cwe": "CWE-639", "severity": "medium", "evidence": {"file": "e", "line": 1}},
    ]}
    by_id = {p.id: p for p in plans_from(doc)}
    get, post = Endpoint("GET", "/search", None), Endpoint("POST", "/login", None)
    return [replace(by_id["T-1"], endpoints=(get,)),
            replace(by_id["T-2"], endpoints=(get,)),            # quick: XSS a read can reach
            replace(by_id["T-3"], endpoints=(post,)),           # not quick: only a write
            by_id["T-4"],                                       # not quick: names no request
            replace(by_id["T-5"], endpoints=(get,))]            # not quick: access control


def _selected(plans, **kw):
    import argparse

    from appsec_verifier import cli

    args = dict(category=None, cls=None, severity=None, min_severity=None, cwe=None, only=None, strict_severity=False)
    return cli._select(argparse.Namespace(**{**args, **kw}), plans)


def test_quick_findings_are_cheap_xss_and_sql_injection_a_read_can_reach():
    from appsec_verifier.planning import quick

    assert [p.id for p in _quick_plans() if quick(p)] == ["T-1", "T-2"]
    assert [p.id for p in _selected(_quick_plans(), category="quick")] == ["T-1", "T-2"]


@pytest.mark.parametrize("selector", [{"severity": "critical,high"}, {"min_severity": "high"}])
def test_a_severity_selection_adds_the_quick_findings_of_other_severities(selector):
    """VER-026: critical and high, plus every quick finding below, marked as added; nothing else below."""
    from appsec_verifier.planning import QUICK_REASON

    selected = _selected(_quick_plans(), **selector)
    assert [p.id for p in selected] == ["T-1", "T-2"]
    assert selected[0].selection_reason is None and selected[1].selection_reason == QUICK_REASON


@pytest.mark.parametrize("selector", [{"severity": "critical", "strict_severity": True},
                                      {"min_severity": "critical", "strict_severity": True},
                                      {"severity": "critical", "only": "T-1"},
                                      {"severity": "critical", "category": "idor"}])
def test_strict_severity_only_and_other_filters_keep_quick_findings_out(selector):
    """Refused cases: --strict-severity and --only add nothing; the other selectors still apply to additions."""
    assert "T-2" not in [p.id for p in _selected(_quick_plans(), **selector)]
