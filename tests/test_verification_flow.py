"""Cross-variant budgets, actionable review and honest proof readiness (VER-008, VER-011, VER-042, VER-046, VER-051)."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_evidence_review import CLEAR, issue, pair
from test_runner import _plan, _run
from test_technical_review import CLEAR as QA_CLEAR
from test_technical_review import consider, context, reviewer

from appsec_verifier import cli
from appsec_verifier.agent.steps import _experiment_state
from appsec_verifier.limits import LimitExceeded, Limits, RunBudget
from appsec_verifier.verification_context import proof_limitations
from appsec_verifier.verify.evidence_review import review_finding
from appsec_verifier.verify.probes import ProbeRegistry, ProbeResult


def test_finding_accounting_resumes_after_another_finding_and_excludes_preflight():
    budget = RunBudget(Limits(cost_limit_usd=20))
    budget.note_cost(6)  # Before findings: preflight has only the run ceiling.
    budget.note_call()
    budget.begin_finding("one")
    budget.note_cost(3)
    budget.begin_finding("two")
    budget.note_cost(1)
    budget.begin_finding("one")
    budget.note_cost(2)
    with pytest.raises(LimitExceeded, match="per-finding"):
        budget.note_call()
    budget.begin_finding("two")
    budget.note_call()
    assert budget.calls == 2


def test_runner_stops_sibling_variants_at_shared_cap_but_continues_other_findings():
    seen, summaries = [], []

    class SpendingProbe:
        cls = "xss"

        def run(self, ctx):
            ctx.budget.note_call()
            ctx.budget.note_cost(1.3)
            seen.append((ctx.plan.id, ctx.plan.variant_id))
            summaries.append(ctx.variant_status)
            return ProbeResult("inconclusive", rationale="prerequisite unresolved")

    registry = ProbeRegistry()
    registry.register(SpendingProbe())
    first = _plan("T-1", "xss")
    plans = [replace(first, variant_id="a"), _plan("T-2", "xss"),
             replace(first, variant_id="b"), replace(first, variant_id="c"), _plan("T-3", "xss")]
    results = _run(plans, registry=registry)["results"]
    assert seen == [("T-1", "a"), ("T-2", None), ("T-1", "b"), ("T-3", None)]
    assert results[3]["verdict"] == "not-attempted" and results[3]["limits_hit"] == "finding-cost"
    assert results[4]["verdict"] == "inconclusive"
    assert [s["status"] for s in summaries[2]] == ["inconclusive", "active", "pending"]
    assert summaries[2][0]["reason"] == "prerequisite unresolved"


def test_review_calls_obey_shared_finding_cap_without_overwriting_proof():
    ctx, res, host, original, _ = pair([issue()], limits=Limits(cost_limit_usd=10))
    ctx.budget.begin_finding("T-1")
    ctx.budget.note_cost(2.495)  # First review crosses the 2.50 cap; no correction may follow.
    assert review_finding([(ctx, res)]) == "finding-cost"
    assert len(host.calls) == 1 and not original.requests
    assert res.verdict == "confirmed" and res.proof["checked"]
    assert res.evidence_review["status"] == "stopped"


def test_missing_citations_are_reported_without_impossible_presentation_correction():
    ctx, res, host, original, _ = pair([issue("excerpt")])
    ctx.represent = lambda presentation: pytest.fail("an impossible correction must not be attempted")
    res.verdict = "inconclusive"
    res.proof = None
    res.poc["steps"][0]["decisive"] = False
    res.poc["presentation"] = {"composed_by": "verifier", "reason": "the verdict cites no step"}
    review_finding([(ctx, res)])
    assert len(host.calls) == 1 and not original.requests
    assert all(i["code"] == "missing-evidence" for i in res.evidence_review["issues"])
    assert res.verdict == "inconclusive"


def test_missing_presentation_with_citations_still_gets_a_correction():
    from test_evidence_review import revision

    ctx, res, _, original, _ = pair([CLEAR, revision(), CLEAR])
    ctx.represent = lambda presentation: None
    res.poc["presentation"] = {"composed_by": "verifier", "reason": "the test agent composed no presentation"}
    review_finding([(ctx, res)])
    assert len(original.requests) == 1
    assert original.requests[0][1]["feedback"][0]["code"] == "excerpt"


def test_qa_gets_redacted_variant_coverage_without_sibling_proof_or_permission(tmp_path):
    ctx = context(tmp_path)
    ctx.sessions.remember_secret("fixture-private-value")
    ctx.variant_status = [{"variant": "prior", "status": "confirmed", "proof_checked": True,
                           "reason": "fixture-private-value", "request": [{"method": "GET", "path": "/other"}]}]
    qa, host = reviewer(ctx, [QA_CLEAR])
    assert consider(ctx, qa) is None
    system, payload, _ = host.calls[0]
    assert "fixture-private-value" not in json.dumps(payload)
    assert payload["variant_status"][0]["status"] == "confirmed"
    assert "/other" not in payload["proof_contract"]["routes"]
    assert "not transferable" in system and "active variant" in system
    assert ctx.budget.requests == 0


def test_qa_cannot_start_after_another_variant_spent_the_finding_cap(tmp_path):
    ctx = context(tmp_path)
    ctx.budget.begin_finding("T-1")
    ctx.budget.note_cost(ctx.budget.finding_cost_cap())
    qa, host = reviewer(ctx, [QA_CLEAR])
    result = ProbeResult("inconclusive")
    assert consider(ctx, qa, result=result) is None
    assert not host.calls and result.limits_hit == "finding-cost"


def test_spent_finding_budget_refuses_followup_execution(tmp_path):
    from appsec_verifier.agent.controller import Controller

    ctx = context(tmp_path)
    ctx.budget.begin_finding("T-1")
    ctx.budget.note_cost(ctx.budget.finding_cost_cap())
    with pytest.raises(LimitExceeded) as exc:
        Controller(ctx).run(lambda: pytest.fail("no operation after exhaustion"))
    assert exc.value.kind == "finding-cost" and ctx.budget.requests == 0


def accepted(**updates):
    plan = {"kind": "boolean", "method": "POST", "input_location": "json", "input_name": "q",
            "baseline": "x", "sql_template": "x' AND {{predicate}}-- ", **updates}
    return {"tool": "plan_test", "args": plan, "result": {"accepted": True, "experiment": plan}}


def test_write_plan_state_distinguishes_acceptance_from_execution_and_failed_controls():
    ctx = SimpleNamespace(plan=SimpleNamespace(cls="injection", cwe="CWE-89"))
    history = [accepted()]
    state = _experiment_state(ctx, history)
    assert state["answered_requests_since_plan"] == [] and not state["plan_has_http_response"]
    assert "send_controls once" in state["next"]
    history.append({"tool": "http_request", "experiment": True, "result": {"error": "refused"}})
    state = _experiment_state(ctx, history)
    assert state["generated_control_attempts"] == [2] and state["answered_requests_since_plan"] == []
    assert "send_controls once" not in state["next"]
    history.append({"tool": "http_request", "experiment": True,
                    "result": {"status": 200, "body_excerpt": "private target answer"}})
    assert _experiment_state(ctx, history)["answered_requests_since_plan"] == [3]
    assert "private target answer" not in json.dumps(_experiment_state(ctx, history))


def test_agent_controls_cannot_be_confused_with_generated_write_controls():
    ctx = SimpleNamespace(plan=SimpleNamespace(cls="injection", cwe="CWE-78"))
    history = [accepted(sql_template=None, positive="yes", negative="no")]
    state = _experiment_state(ctx, history)
    assert state["confirmation"] == "negative-only"
    assert "cannot send" in state["next"] and "expression_template" in state["next"]


def test_revised_plan_does_not_inherit_old_execution_or_proof():
    ctx = SimpleNamespace(plan=SimpleNamespace(cls="injection", cwe="CWE-89"))
    history = [accepted(), {"tool": "experiment", "result": {"plan_step": 1, "proof": "holds"}}, accepted()]
    state = _experiment_state(ctx, history)
    assert state["accepted_plan"] == 3 and state["proof"] == "not checked"
    assert state["generated_control_attempts"] == []


def test_executed_controls_use_recorded_proof_feedback_without_resending():
    ctx = SimpleNamespace(plan=SimpleNamespace(cls="injection", cwe="CWE-89"))
    history = [accepted(), {"tool": "http_request", "experiment": True, "result": {"status": 200}},
               {"tool": "experiment", "result": {"plan_step": 1, "proof": "missing",
                                                    "next": "The recorded contrast does not suffice."}}]
    state = _experiment_state(ctx, history)
    assert state["proof"] == "missing" and state["answered_requests_since_plan"] == [2]
    assert state["next"] == "The recorded contrast does not suffice."


@pytest.mark.parametrize("method,location,needle", [("POST", "form", "GET only"),
                                                  ("GET", "header", "custom header")])
def test_plan_and_agent_explain_unavailable_paths_without_disallowing_alternatives(method, location, needle):
    from test_endpoints import _blocker

    plan = replace(_plan("T-1", "xss"), variant_id="v1", verification_context={"variants": [
        {"id": "v1", "request": {"method": method, "path": "/comment",
                                  "inputs": [{"location": location, "name": "input"}]},
         "hypothesis": "Untrusted input reaches an HTML context"}]})
    assert needle in " ".join(proof_limitations(plan))
    assert _blocker(plan, safe=False, source=True, browser=True) is None
    text = "\n".join(cli._test_cases(cli.Style(False), [plan], {}))
    assert needle in " ".join(text.split()) and "T-1" in text


def test_get_xss_has_no_false_post_limitation():
    assert proof_limitations(_plan("T-1", "xss")) == []


@pytest.mark.parametrize("parameterized,confirmed", [(False, True), (True, False)])
def test_update_with_constant_success_response_needs_a_distinguishing_observation(
        tmp_path, parameterized, confirmed):
    """A quoted UPDATE field can use the existing engine-error proof; parameterized SQL cannot.
    SQLite is an offline syntax fixture, not a claim about any running application's database."""
    import sqlite3

    from test_agent_tools import Resp
    from test_cost_followup import Script, _confirm, _error_plan, _inj_ctx

    from appsec_verifier.agent.loop import AgentProbe

    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, name TEXT)")
        db.execute("INSERT INTO records VALUES (1, 'fixture')")

        def target(method, url, headers, **kw):
            assert method == "POST" and url.endswith("/update")
            values = kw["json"]
            try:
                if parameterized:
                    db.execute("UPDATE records SET name = ? WHERE id = ?", (values["name"], values["id"]))
                else:
                    # Intentionally vulnerable, local test database; there is no record with id -1.
                    db.execute("UPDATE records SET name = '" + values["name"] + "' WHERE id = " + str(values["id"]))
            except sqlite3.Error as exc:
                return Resp(200, str(exc))
            return Resp(200, '{"result":"ok"}')

        ctx = _inj_ctx(tmp_path, target, method="POST", path="/update", safe=False, read_only=False)
        ctx.marker = ("vrfupdate", "fixture")
        marker = "".join(ctx.marker)
        plan = _error_plan(method="POST", path="/update", input_location="json", input_name="name",
                           baseline=marker, fixed={"json": {"id": -1}})
        script = Script([plan, {"tool": "send_controls", "args": {}}, _confirm])
        result = AgentProbe("injection", lambda: script).run(ctx)
        assert (result.verdict == "confirmed") is confirmed, result.rationale
        assert db.execute("SELECT * FROM records").fetchall() == [(1, "fixture")]
