"""VER-011/055: correct observations over complete, fixed evidence through the shared agent contract.

Only the existing fake transport and scripted model run; SQLite supplies the actual SQL behavior.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest
from test_agent_tools import Resp
from test_cost_followup import Script, _confirm, _js_plan, _reviews_ctx
from test_presentation import Browser
from test_text_observation import (
    _expression_plan,
    _inj_ctx,
    _negative,
    _page_target,
    _sql_plan,
    _template_target,
)

from appsec_verifier.agent.experiments import latest_plan, plan_view
from appsec_verifier.agent.loop import EXPERIMENT_NO_PROOF, AgentProbe
from appsec_verifier.agent.steps import parse_step, step_schema
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.verify import poc
from appsec_verifier.verify.report import why_not_confirmed


def revision(plan_step=1, **observation):
    # Exercise the same JSON-string boundary used by every host, then the loop's independent validation.
    return parse_step({"action": "revise_observation", "args_json": json.dumps({"plan_step": plan_step, **observation}),
                       "note": "Correct the observation using recorded responses"})


def context(tmp_path, sent, *, json_answer=False, parameterised=False):
    target = _page_target(sent, parameterised=parameterised)

    def transport(*args, **kwargs):
        response = target(*args, **kwargs)
        if json_answer and response.status_code == 200:
            return Resp(200, json.dumps({"answer": ["found"] if "Item number 2" in response.text else []}))
        return response

    ctx = _inj_ctx(tmp_path, transport)
    ctx.http._budget.limits.rate_rps = 0  # no pacing needed for this in-process fake; all request checks still run
    return ctx


def wrong_pointer():
    plan = _sql_plan("Item number 2")
    del plan["args"]["text"]
    plan["args"]["pointer"] = "/html"
    return plan


@pytest.mark.parametrize("json_answer, initial, correction", [
    (False, wrong_pointer(), {"text": "Item number 2"}),
    (True, wrong_pointer(), {"pointer": "/answer"}),
    (True, _sql_plan("not a result"), {"pointer": "/answer"}),
])
def test_correcting_the_observation_reuses_all_controls_and_preserves_the_original_plan(
        tmp_path, json_answer, initial, correction):
    sent, log = [], []
    ctx = context(tmp_path, sent, json_answer=json_answer)
    ctx.log = lambda record: log.append(copy.deepcopy(record))
    script = Script([initial, revision(**correction), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert len(sent) == 10 and result.proof["steps"] == list(range(2, 12))
    assert not any(o.startswith(EXPERIMENT_NO_PROOF) for o in result.observations)   # a confirmation needs no reason
    assert result.proof.get("observation_text") == correction.get("text")
    assert result.proof["observation_pointer"] == correction.get("pointer")
    original = script.history[0]["result"]["experiment"]
    assert original.get("pointer") == initial["args"].get("pointer")
    assert original.get("text") == initial["args"].get("text")
    assert ctx.accepted_plans[1] == original
    correction_log = next(r for r in log if r.get("tool") == "revise_observation")
    assert correction_log["result"]["observation"] == correction
    assert correction_log["result"]["plan_step"] == 1
    assert correction_log["result"]["steps"] == list(range(2, 12))
    effective = latest_plan(script.history)[1]
    assert {k: v for k, v in effective.items() if k not in ("text", "pointer")} == {
        k: v for k, v in original.items() if k not in ("text", "pointer")}


def test_incomplete_citations_get_the_observation_error_instead_of_missing_baseline(tmp_path):
    ctx = context(tmp_path, [])
    partial = {"verdict": {"verdict": "confirmed", "rationale": "The conditions split the result",
                           "proof_steps": list(range(3, 12))}}
    script = Script([wrong_pointer(), partial, revision(text="Item number 2"), partial])
    result = AgentProbe("injection", lambda: script).run(ctx)
    feedback = next(h["result"] for h in script.history if h["tool"] == "proof_feedback")
    assert "not valid JSON" in feedback["missing"][0]
    assert "baseline" not in feedback["missing"][0]
    assert result.verdict == "confirmed" and result.proof["steps"] == list(range(2, 12))
    assert {s["step"] for s in result.poc["steps"] if s["decisive"]} == set(range(2, 12))
    assert {s["step"] for s in result.poc["shown"]} == set(range(2, 12))


def test_an_application_view_can_select_a_control_used_by_the_code_proof(tmp_path):
    sent, calls = [], []
    ctx = context(tmp_path, sent)
    ctx.browser = Browser()

    def capture(url, **kwargs):
        calls.append((url, kwargs))
        return {"status": 200, "evidence": [{"kind": "screenshot", "path": "evidence/application.png",
                                           "presentation": "application"}]}

    ctx.browser.check = capture
    verdict = {"verdict": {"verdict": "confirmed", "rationale": "The controls split",
                           "proof_steps": [4], "browser_evidence": {
                               "step": 3, "path": "/products/search", "values": ["Item number 2"]}}}
    script = Script([wrong_pointer(), revision(text="Item number 2"), verdict])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and len(sent) == 10
    assert len(calls) == 1 and calls[0][1]["safe"] is True
    assert calls[0][1]["observation"]["step"] == 3
    assert {s["step"] for s in result.poc["shown"]} == set(range(2, 12))


@pytest.mark.parametrize("damaged", ["missing", "truncated", "failed", "unstable"])
def test_a_correction_and_partial_citations_cannot_hide_bad_evidence(tmp_path, damaged):
    sent = []
    ctx = context(tmp_path, sent)

    def damage(history):
        if damaged == "missing":
            del ctx.responses[2]
        elif damaged == "truncated":
            ctx.responses[2]["complete"] = False
        elif damaged == "failed":
            history[1]["result"]["status"] = 500
        else:
            ctx.responses[3]["body"] = "a different result"
        return revision(text="Item number 2")

    verdict = {"verdict": {"verdict": "confirmed", "rationale": "claim", "proof_steps": list(range(4, 12))}}
    script = Script([wrong_pointer(), damage, verdict])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "inconclusive" and len(sent) == 10
    feedback = [h["result"] for h in script.history if h["tool"] == "experiment"][-1]
    assert feedback["proof"] == "missing"
    if damaged in ("missing", "truncated"):
        assert "unavailable or incomplete" in feedback["reason"]


@pytest.mark.parametrize("text", ["pear", "Product search", "nonexistent text"])
def test_a_correction_cannot_confirm_reflection_static_text_or_missing_text(tmp_path, text):
    sent = []
    ctx = context(tmp_path, sent)
    script = Script([wrong_pointer(), revision(text=text), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "inconclusive" and len(sent) == 10


def test_a_corrected_observation_does_not_confirm_a_parameterised_query(tmp_path):
    ctx = context(tmp_path, [], parameterised=True)
    script = Script([wrong_pointer(), revision(text="Item number 2"), _confirm])
    assert AgentProbe("injection", lambda: script).run(ctx).verdict == "inconclusive"


def test_correction_of_an_earlier_experiment_does_not_change_the_later_plan(tmp_path):
    sent = []
    ctx = context(tmp_path, sent)
    other = _sql_plan("not the selected result", "pear' AND NOT (NOT {{predicate}}) -- ")
    script = Script([wrong_pointer(), other, revision(text="Item number 2"), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and len(sent) == 20
    assert result.proof["steps"] == list(range(2, 12))
    assert latest_plan(script.history)[1]["text"] == "not the selected result"
    assert latest_plan(plan_view(script.history, result.proof["steps"]))[1]["text"] == "Item number 2"


def test_two_corrected_contexts_can_support_a_negative_verdict(tmp_path):
    sent = []
    ctx = context(tmp_path, sent, json_answer=True, parameterised=True)
    second = wrong_pointer()
    second["args"]["sql_template"] = "pear AND {{predicate}}"

    def revise_second(history):
        return revision(latest_plan(history)[0], pointer="/answer")

    def negative(history):
        verdict = _negative(history)
        verdict["verdict"]["proof_steps"] = sorted(set(verdict["verdict"]["proof_steps"]))
        return verdict

    script = Script([wrong_pointer(), revision(pointer="/answer"), second, revise_second, negative])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "not-reproducible" and result.proof["checked"] is True
    assert len(sent) == 20 and len(result.proof["steps"]) == 20


def test_arithmetic_proof_rechecks_its_computed_values_after_an_observation_correction(tmp_path):
    sent = []
    ctx = _inj_ctx(tmp_path, _template_target(sent), cwe="CWE-1336", path="/hello")
    ctx.http._budget.limits.rate_rps = 0
    script = Script([_expression_plan(pointer="/html"), revision(text="Hello"), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["form"] == "computed-expression"
    assert len(sent) == 10
    for n in range(3, 7):
        entry = {"response": {"content": {"text": ctx.responses[n]["body"]}}}
        assert poc._proof_observation(ctx, script.history, n, entry)[:2] == ("result_returned", True)
    assert "compared: each result in the answer" in poc._test_line(ctx, script.history)


@pytest.mark.parametrize("vulnerable", [True, False])
def test_nosql_path_experiment_uses_the_same_correction_and_proof_checks(tmp_path, vulnerable):
    sent = []
    ctx = _reviews_ctx(tmp_path, sent, vulnerable=vulnerable)
    ctx.http._budget.limits.rate_rps = 0
    plan = _js_plan()
    plan["args"]["pointer"] = "/missing"
    script = Script([plan, revision(pointer="/data"), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == ("confirmed" if vulnerable else "inconclusive")
    assert len(sent) == 10


def test_correcting_a_write_observation_does_not_resend_or_release_its_controls(tmp_path):
    sent = []
    ctx = context(tmp_path, sent)
    ctx.safe = ctx.read_only = False
    ctx.marker = ("vrfaa", "bb")
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("POST", "/products/search", None),))
    plan = wrong_pointer()
    plan["args"].update(method="POST", fixed={"params": {"marker": "vrfaa"}})
    send = {"tool": "send_controls", "args": {}}
    script = Script([plan, send, revision(text="Item number 2"), send, _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and len(sent) == 10
    refused = [h for h in script.history if h["tool"] == "send_controls"]
    assert "already sent" in refused[-1]["result"]["error"]


def test_an_old_success_does_not_override_a_failing_corrected_observation(tmp_path):
    ctx = context(tmp_path, [])
    script = Script([_sql_plan("Item number 2"), revision(text="Product search"), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "inconclusive"
    experiments = [h["result"] for h in script.history if h["tool"] == "experiment"]
    assert experiments[0]["proof"] == "holds" and experiments[1]["proof"] == "missing"
    # VER-024: the experiment without proof, not the one that held, is recorded in the code's words as the reason.
    assert [o for o in result.observations if o.startswith(EXPERIMENT_NO_PROOF)] == [
        EXPERIMENT_NO_PROOF + experiments[1]["reason"]]
    why = why_not_confirmed({"verdict": result.verdict, "rationale": result.rationale,
                             "observations": result.observations, "proof": result.proof})
    assert why == ("No proof: the agent's confirmation failed the proof check: the true and false conditions got the "
                   "same answer, so the answer does not show the injected condition.")


@pytest.mark.parametrize("extra", [
    {"path": "/other"}, {"role": "admin"}, {"baseline": "other"}, {"positive": "chosen"},
    {"steps": [3, 4]}, {"method": "POST"}, {"sql_template": "other {{predicate}}"},
    {"pointer": "/answer"}, {"text": None},
])
def test_correction_rejects_changes_to_requests_controls_citations_and_ambiguous_selectors(tmp_path, extra):
    sent = []
    ctx = context(tmp_path, sent)
    action = revision(**{"text": "Item number 2", **extra})
    script = Script([wrong_pointer(), action])
    AgentProbe("injection", lambda: script).run(ctx)
    refused = next(h for h in script.history if h["tool"] == "revise_observation")
    assert "error" in refused["result"] and len(sent) == 10
    assert latest_plan(script.history)[1]["pointer"] == "/html"


@pytest.mark.parametrize("start", [0, 2, 1000])
def test_correction_needs_an_accepted_plan_of_this_finding(tmp_path, start):
    sent = []
    ctx = context(tmp_path, sent)
    script = Script([wrong_pointer(), revision(start, text="Item number 2")])
    AgentProbe("injection", lambda: script).run(ctx)
    assert any(h["tool"] == "revise_observation" and "error" in h["result"] for h in script.history)
    assert len(sent) == 10


@pytest.mark.parametrize("special", ["auth_artifact", "error_probe", "sql_marker", "oob_template"])
def test_withheld_and_mechanism_owned_observations_cannot_be_reinterpreted(tmp_path, special):
    ctx = context(tmp_path, [])
    ctx.accepted_plans[1] = {**wrong_pointer()["args"], special: True}
    with pytest.raises(ToolError, match="no revisable"):
        AgentTools(ctx).revise_observation(plan_step=1, text="anything")


def test_other_classes_and_an_unexecuted_plan_cannot_use_the_correction(tmp_path):
    ctx = context(tmp_path, [])
    ctx.accepted_plans[1] = wrong_pointer()["args"]
    with pytest.raises(ToolError, match="no completed"):
        AgentTools(ctx).revise_observation(plan_step=1, text="anything")
    ctx.plan = replace(ctx.plan, cls="access-control")
    assert "revise_observation" not in step_schema(ctx)["properties"]["action"]["enum"]
    with pytest.raises(ToolError, match="only to injection"):
        AgentTools(ctx).revise_observation(plan_step=1, text="anything")


def test_observation_revisions_use_the_existing_decision_budget(tmp_path):
    sent = []
    ctx = context(tmp_path, sent)
    script = Script([wrong_pointer(), *[revision(text=f"absent {n}") for n in range(10)]])
    result = AgentProbe("injection", lambda: script, max_steps=4).run(ctx)
    assert result.verdict == "inconclusive" and result.limits_hit is not None
    assert script.calls == 4 and len(sent) == 10
