"""Injection proofs and negative verdicts observed in page or text answers (VER-055, VER-011, VER-013)."""

from __future__ import annotations

import html
import re
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_agent_tools import Resp, _ctx
from test_cost_followup import Script, _confirm

from appsec_verifier.agent.experiments import injection_check
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.endpoints import Endpoint

PATH = "/products/search"


def _page_target(sent, *, parameterised=False):
    """A server-rendered search page that echoes the term and lists the matches; the term is concatenated into
    SQL unless `parameterised`."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE products(id INTEGER, name TEXT)")
    db.executemany("INSERT INTO products VALUES (?, ?)", [(1, "apple"), (2, "pear")])

    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "")
        sent.append(q)
        try:
            rows = (db.execute("SELECT id FROM products WHERE name = ?", (q,)) if parameterised
                    else db.execute("SELECT id FROM products WHERE name = '" + q + "'")).fetchall()
        except sqlite3.Error:
            return Resp(500, "<html><body><p>Server error</p></body></html>")
        items = "".join(f"<li>Item number {r[0]}</li>" for r in rows)
        return Resp(200, f"<html><body><h1>Product search</h1><p>You searched for {html.escape(q)}</p>"
                         f"<ul>{items}</ul></body></html>")

    return target


def _template_target(sent, *, evaluates=True):
    """A greeting page that evaluates `{{ a*b }}` and `{{ a+b }}` in the name, or shows it as text."""
    def target(m, u, h, **kw):
        name = (kw.get("params") or {}).get("name", "")
        sent.append(name)
        if evaluates:
            name = re.sub(r"\{\{\s*(\d+)\s*([*+])\s*(\d+)\s*\}\}",
                          lambda g: str(int(g[1]) * int(g[3]) if g[2] == "*" else int(g[1]) + int(g[3])), name)
        return Resp(200, f"<html><body><p>Hello {html.escape(name)}</p></body></html>")

    return target


def _inj_ctx(tmp_path, target, *, cwe="CWE-89", path=PATH):
    ctx = _ctx(tmp_path, target)
    ctx.plan = replace(ctx.plan, cls="injection", cwe=cwe, instance="app/search.py:12",
                       endpoints=(Endpoint("GET", path, None),))
    return ctx


def _sql_plan(text, template="pear' AND {{predicate}} -- "):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The term is concatenated into the WHERE clause of the search",
        "path": PATH, "input_location": "params", "input_name": "q", "baseline": "pear",
        "sql_template": template, "text": text}}


def _experiments(history):
    return [h["result"] for h in history if h.get("tool") == "experiment"]


def test_a_page_answer_confirms_sql_injection_through_a_selected_text(tmp_path):
    """VER-055: the true predicates show the matching row on the page, the false ones do not; the echoed term
    does not decide anything."""
    sent = []
    ctx = _inj_ctx(tmp_path, _page_target(sent))
    script = Script([_sql_plan("Item number 2"), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert result.proof["observation_text"] == "Item number 2" and result.proof["observation_pointer"] is None
    assert result.confidence == "medium"


def test_a_text_that_is_part_of_a_sent_value_never_confirms(tmp_path):
    """Refused case: the page echoes the term, so a text taken from it may be the echo, not the result."""
    ctx = _inj_ctx(tmp_path, _page_target([]))
    script = Script([_sql_plan("pear"), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict != "confirmed"
    assert "part of a sent value" in _experiments(script.history)[0]["reason"]


def test_a_text_the_controls_do_not_split_does_not_confirm(tmp_path):
    """Refused case: the page heading stands on every answer, so the controls do not decide it."""
    ctx = _inj_ctx(tmp_path, _page_target([]))
    script = Script([_sql_plan("Product search"), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict != "confirmed"


def _negative(history):
    steps = [n for feedback in _experiments(history) for n in feedback.get("steps", [])]
    return {"verdict": {"verdict": "not-reproducible", "rationale": "the controls answer alike",
                        "proof_steps": steps}}


def test_a_parameterised_page_supports_a_negative_verdict_on_a_result_text(tmp_path):
    """VER-055, VER-013: the result text stands in every baseline answer and in no control answer, in two
    declared contexts, so the controls answer alike as a non-matching value."""
    ctx = _inj_ctx(tmp_path, _page_target([], parameterised=True))
    script = Script([_sql_plan("Item number 2"), _sql_plan("Item number 2", "pear AND {{predicate}}"), _negative])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "not-reproducible" and result.proof["checked"] is True
    assert len(result.proof["contexts"]) == 2 and result.proof["observation_text"] == "Item number 2"


def test_a_negative_verdict_on_a_text_every_answer_shows_is_downgraded(tmp_path):
    """Refused case: a constant page text answers alike whether or not the input is injectable."""
    ctx = _inj_ctx(tmp_path, _page_target([], parameterised=True))
    script = Script([_sql_plan("Product search"), _sql_plan("Product search", "pear AND {{predicate}}"),
                     _negative])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "inconclusive" and "page rather than a result" in result.rationale


def _expression_plan(**extra):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The name is rendered through the template engine and evaluated",
        "path": "/hello", "input_location": "params", "input_name": "name", "baseline": "bob",
        "expression_template": "{{ {{expression}} }}", **extra}}


def test_a_page_answer_confirms_template_injection_through_each_computed_result(tmp_path):
    """VER-055: each control's own fresh product or sum stands in its page as a whole number."""
    sent = []
    ctx = _inj_ctx(tmp_path, _template_target(sent), cwe="CWE-1336", path="/hello")
    script = Script([_expression_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert result.proof["observation_pointer"] is None and "observation_text" not in result.proof


def test_a_page_that_shows_the_expression_as_text_does_not_confirm(tmp_path):
    """Refused case: the template is reflected, never evaluated, so no computed result stands in the page."""
    ctx = _inj_ctx(tmp_path, _template_target([], evaluates=False), cwe="CWE-1336", path="/hello")
    script = Script([_expression_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict != "confirmed"
    assert "were not returned" in _experiments(script.history)[0]["reason"]


def _arithmetic(bodies):
    """An accepted page-answer arithmetic experiment whose recorded answers are `bodies` by control name."""
    plan = {"kind": "boolean", "path": "/hello", "method": "GET", "input_location": "params", "input_name": "name",
            "baseline": "bob", "expression_template": "{{ {{expression}} }}",
            "positive": "{{ 1234*5678 }}", "negative": "{{ 1234+5678 }}",
            "positive_other": "{{ 1234*5679 }}", "negative_other": "{{ 1234+5679 }}",
            "expected_values": {"positive": 7006652, "negative": 6912, "positive_other": 7007886,
                                "negative_other": 6913}}
    history = [{"tool": "plan_test", "args": plan, "result": {"accepted": True, "experiment": plan}}]
    responses = {}
    for name in ("baseline", "positive", "negative", "positive_other", "negative_other"):
        for _ in range(2):
            history.append({"tool": "http_request", "args": {"path": "/hello", "params": {"name": plan[name]}},
                            "result": {"status": 200}})
            responses[len(history)] = {"complete": True, "body": bodies[name]}
    return SimpleNamespace(responses=responses), history, list(range(2, len(history) + 1))


@pytest.mark.parametrize(("baseline", "positive", "reason"), [
    ("<p>Hello bob</p>", "<p>Hello 7006652</p>", None),
    ("<p>Hello bob, order 6912</p>", "<p>Hello 7006652</p>", "also appears in the baseline"),   # result elsewhere
    ("<p>Hello bob</p>", "<p>Hello 70066520</p>", "were not returned"),                       # inside a longer one
])
def test_each_computed_result_stands_as_a_whole_number_in_its_own_answer_only(baseline, positive, reason):
    ctx, history, cited = _arithmetic({"baseline": baseline, "positive": positive, "negative": "<p>Hello 6912</p>",
                                       "positive_other": "<p>Hello 7007886</p>",
                                       "negative_other": "<p>Hello 6913</p>"})
    problem = injection_check(ctx, history, cited)
    assert problem is None if reason is None else reason in problem


@pytest.mark.parametrize(("extra", "message"), [
    ({}, "declare the observation"),
    ({"pointer": "/items", "text": "Item number 2"}, "not both"),
    ({"text": "Item number 2", "auth_artifact": True}, "needs pointer"),
])
def test_a_boolean_experiment_declares_exactly_one_observation(tmp_path, extra, message):
    ctx = _inj_ctx(tmp_path, _page_target([]))
    args = {k: v for k, v in _sql_plan("x")["args"].items() if k != "text"}
    with pytest.raises(ToolError, match=message):
        AgentTools(ctx).plan_test(**args, **extra)
