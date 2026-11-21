"""The name test of code evaluation and the verdict it gives, shown without exploit (VER-066): fresh unknown names
fail where names the language knows do not, so the input is evaluated; the verdict is never a confirmation, and
inputs that are only looked up or kept as data show nothing. Offline: a fake target stands in for the evaluator, a
fake planner for the model."""

from __future__ import annotations

import json
import re
from dataclasses import replace

import pytest
import yaml
from test_agent_tools import Resp, _ctx
from test_cost_followup import Script, _holding_steps
from test_report import SCHEMA, _analyzer_threat, _confirmed_doc, _doc

from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.verify.rating import rate
from appsec_verifier.verify.report import to_markdown

_NAME = re.compile(r"\((\w+)\)")
_JS_KNOWN = {"undefined", "Number"}


def _evaluator(sent, *, status=500, message=True, known=_JS_KNOWN):
    """Evaluates the input as JavaScript would: a name it does not know raises a ReferenceError."""
    def target(m, u, h, **kw):
        value = str((kw.get("params") or {}).get("q", ""))
        sent.append(value)
        unknown = [n for n in _NAME.findall(value) if n not in known]
        if unknown:
            return Resp(status, f"ReferenceError: {unknown[0]} is not defined\n    at evaluate (lib/calc.js:12:5)"
                        if message else "Internal Server Error")
        return Resp(200, json.dumps({"result": "ok"}))

    return target


def _looked_up(sent):
    """Looks the input up as a global name (x in globalThis), evaluating nothing."""
    def target(m, u, h, **kw):
        value = str((kw.get("params") or {}).get("q", ""))
        sent.append(value)
        return Resp(200, "{}") if value in ("undefined", "Number") else Resp(500, "unknown name")

    return target


def _kept_as_data(sent):
    def target(m, u, h, **kw):
        sent.append(str((kw.get("params") or {}).get("q", "")))
        return Resp(200, json.dumps({"stored": True}))

    return target


def _parsed_as_json(sent):
    def target(m, u, h, **kw):
        value = str((kw.get("params") or {}).get("q", ""))
        sent.append(value)
        try:
            json.loads(value)
        except ValueError:
            return Resp(500, "SyntaxError: Unexpected token in JSON")
        return Resp(200, "{}")

    return target


def _code_ctx(tmp_path, target, *, cwe="CWE-94", instance="routes/calc.ts:12"):
    ctx = _ctx(tmp_path, target)
    ctx.plan = replace(ctx.plan, cls="injection", cwe=cwe, instance=instance,
                       endpoints=(Endpoint("GET", "/calc", None),))
    return ctx


def _name_plan(**extra):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The expression in q is evaluated and its result never returns",
        "path": "/calc", "input_location": "params", "input_name": "q", "name_template": "1+{{name}}", **extra}}


def _claim(verdict):
    def step(history):
        return {"verdict": {"verdict": verdict, "rationale": "the unknown names fail, the known ones do not",
                            "proof_steps": _holding_steps(history) or [2, 3, 4, 5, 6, 7, 8, 9]}}

    return step


def _run(ctx, *steps):
    script = Script(list(steps))
    return AgentProbe("injection", lambda: script).run(ctx), script


def test_the_name_test_shows_code_evaluation_without_an_exploit(tmp_path):
    """T-025: the evaluator fails on fresh names and not on undefined or Number. A claimed confirmation becomes
    shown without exploit, at medium confidence, since the answers name the error for the fresh name; the model
    sees only the class, never the error text."""
    sent = []
    result, script = _run(_code_ctx(tmp_path, _evaluator(sent)), _name_plan(), _claim("confirmed"))
    assert result.verdict == "shown-without-exploit" and result.confidence == "medium"
    assert result.proof["checked"] is True and result.proof["form"] == "name-error"
    assert len(sent) == 8 and {"1+(undefined)", "1+(Number)"} <= set(sent)
    assert all(re.fullmatch(r"1\+\((vrf[0-9a-f]{10}|undefined|Number)\)", v) for v in sent)
    controls = [h["result"] for h in script.history if h.get("experiment")]
    assert {c.get("name_error") for c in controls} == {True, False}
    assert not any("is not defined" in c.get("body_excerpt", "") for c in controls)
    feedback = next(h["result"] for h in script.history if h.get("tool") == "experiment")
    assert feedback["proof"] == "holds" and feedback["level"] == "shown-without-exploit"
    assert "shown-without-exploit" in feedback["next"]


def test_a_server_error_without_the_error_text_shows_it_at_low_confidence(tmp_path):
    sent = []
    result, _ = _run(_code_ctx(tmp_path, _evaluator(sent, message=False)), _name_plan(),
                     _claim("shown-without-exploit"))
    assert result.verdict == "shown-without-exploit" and result.confidence == "low"


@pytest.mark.parametrize("message", [True, False])
def test_a_refusal_counts_only_when_it_names_the_error_for_the_fresh_name(tmp_path, message):
    """A handler that catches the error may answer 400 with it; a 400 without it may be an ordinary input check."""
    sent = []
    result, _ = _run(_code_ctx(tmp_path, _evaluator(sent, status=400, message=message)), _name_plan(),
                     _claim("shown-without-exploit"))
    assert result.verdict == ("shown-without-exploit" if message else "inconclusive")


@pytest.mark.parametrize("target", [_looked_up, _kept_as_data, _parsed_as_json])
def test_inputs_that_are_not_evaluated_show_nothing(tmp_path, target):
    """Refused case: an input looked up as a name, kept as data or parsed as JSON treats the parenthesised names
    alike, so neither claim stands."""
    sent = []
    for claim in ("shown-without-exploit", "confirmed"):
        result, _ = _run(_code_ctx(tmp_path, target(sent)), _name_plan(), _claim(claim))
        assert result.verdict == "inconclusive" and result.proof["checked"] is False


def test_an_evaluator_that_knows_only_one_of_the_names_shows_nothing(tmp_path):
    """Refused case: every pair must hold; a known name that fails as well shows no evaluation."""
    sent = []
    result, _ = _run(_code_ctx(tmp_path, _evaluator(sent, known={"Number"})), _name_plan(),
                     _claim("shown-without-exploit"))
    assert result.verdict == "inconclusive"


@pytest.mark.parametrize(("cwe", "instance", "error"), [
    ("CWE-94", "src/Calc.java:3", "needs the finding's language"),
    ("CWE-89", "routes/calc.ts:12", "applies to a boolean code-evaluation experiment"),
])
def test_the_name_test_is_refused_without_a_language_or_outside_code_evaluation(tmp_path, cwe, instance, error):
    sent = []
    _, script = _run(_code_ctx(tmp_path, _evaluator(sent), cwe=cwe, instance=instance), _name_plan())
    refused = next(h["result"] for h in script.history if h.get("tool") == "plan_test")
    assert error in refused["error"] and sent == []


def test_a_negative_verdict_cannot_rest_on_the_name_test(tmp_path):
    sent = []
    result, _ = _run(_code_ctx(tmp_path, _kept_as_data(sent)), _name_plan(), _claim("not-reproducible"))
    assert result.verdict == "inconclusive" and "no checked negative form" in result.rationale


def test_no_other_class_can_be_shown_without_exploit(tmp_path):
    from appsec_verifier.agent.proof import check_proof
    from appsec_verifier.verify.probes import ProbeResult

    ctx = _ctx(tmp_path, lambda *a, **k: Resp())
    result = check_proof(ctx, [], ProbeResult(verdict="shown-without-exploit", rationale="looks evaluated"), [])
    assert result.verdict == "inconclusive" and "no indirect proof exists for this class" in result.rationale


def test_the_rating_stays_and_the_report_shows_the_verdict_like_a_confirmation_but_weaker():
    """VER-066, VER-039: the colour of a confirmed finding, without bold, counted apart, the rating unchanged."""
    threat = _analyzer_threat()
    assert rate(threat, "shown-without-exploit", True)["changed"] is False
    doc = _confirmed_doc()
    row = doc["results"][0]
    row.update(verdict="shown-without-exploit", confidence="medium",
               proof={**row["proof"], "form": "name-error"})
    md = to_markdown(doc, {"threats": [threat]})
    summary = md.split("## Summary", 1)[1].split("## Tested findings", 1)[0]
    assert summary.splitlines()[2].startswith("🟥 1 shown without exploit · ")
    assert "| 🟥 Shown without exploit | [T-037](#t-037)" in summary and "**Shown" not in summary
    assert "🟥 confirmed or shown without exploit" in md


def test_the_verdict_and_its_count_are_schema_valid():
    from jsonschema.validators import validator_for

    doc = _doc()
    doc["results"][0]["verdict"] = "shown-without-exploit"
    doc["meta"]["summary"]["shown_without_exploit"] = 1
    schema = yaml.safe_load(SCHEMA.read_text())
    assert not list(validator_for(schema)(schema).iter_errors(doc))
