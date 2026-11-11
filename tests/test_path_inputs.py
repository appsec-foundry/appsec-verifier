"""Path controls change only the declared segment and retain proof and scope checks (VER-044)."""

from __future__ import annotations

import copy
import json
import sqlite3
from dataclasses import replace
from urllib.parse import quote, unquote, urlsplit

import pytest
from test_agent_tools import Resp, _ctx
from test_experiments import boolean_history, plan

from appsec_verifier.agent import AgentTools, ToolError
from appsec_verifier.agent.experiments import experiment_groups
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.endpoints import Endpoint


def tools_for(tmp_path, transport):
    ctx = _ctx(tmp_path, transport)
    ctx.plan.cls, ctx.plan.cwe = "injection", "CWE-89"
    ctx.scope = {**ctx.scope, "injection_inputs": [{"finding_id": "T-1", "path": "/items/:id",
                 "input_location": "path", "input_name": "id", "semantics": "literal"}]}
    tools = AgentTools(ctx)
    tools.plan_test(**plan(path="/items/:id", input_location="path", input_name="id")["args"])
    return tools


def test_path_control_is_encoded_and_the_guard_sees_the_final_destination(tmp_path):
    sent = []
    tools = tools_for(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp())
    value = "10' AND '1'='1"
    tools.http_request(path="/items/:id", path_inputs={"id": value})
    assert sent == ["https://app.example.com/items/" + quote(value, safe="")]
    with pytest.raises(ToolError, match="ambiguous"):
        tools.http_request(path="/items/:id", path_inputs={"id": "../admin"})
    assert len(sent) == 1


@pytest.mark.parametrize("path, values", [
    ("/items/:other", {"id": "1"}), ("/items/:id", {"other": "1"}),
    ("/items/:id", {"id": "1", "other": "2"}), ("/else/:id", {"id": "1"}),
])
def test_unmatched_path_inputs_send_nothing(tmp_path, path, values):
    sent = []
    tools = tools_for(tmp_path, lambda *a, **k: sent.append(a) or Resp())
    with pytest.raises(ToolError):
        tools.http_request(path=path, path_inputs=values)
    assert sent == []


def test_path_inputs_outside_an_injection_experiment_name_the_way_out(tmp_path):
    """An access-control plan on a placeholder route takes the identifier in its path; the refusal says so, and
    nothing is sent."""
    sent = []
    ctx = _ctx(tmp_path, lambda *a, **k: sent.append(a) or Resp())
    ctx.plan.cls = "access-control"
    with pytest.raises(ToolError, match=r"write the value into path itself, e\.g\. /items/3"):
        AgentTools(ctx).http_request(path="/items/:id", path_inputs={"id": "3"})
    assert sent == []


def test_a_mismatched_path_input_names_the_declared_template_and_input(tmp_path):
    tools = tools_for(tmp_path, lambda *a, **k: Resp())
    with pytest.raises(ToolError, match="keep path /items/:id and give only id"):
        tools.http_request(path="/items/:id", path_inputs={"other": "1"})


def test_mismatched_operator_contract_refuses_path_input(tmp_path):
    tools = tools_for(tmp_path, lambda *a, **k: Resp())
    tools.ctx.scope["injection_inputs"][0]["path"] = "/other/:id"
    with pytest.raises(ToolError, match="operator-declared"):
        tools.http_request(path="/items/:id", path_inputs={"id": "1"})


def test_path_observations_only_change_one_declared_input():
    history = boolean_history()
    history[0]["args"].update(path="/items/:id", input_location="path", input_name="id")
    for row in history[1:]:
        row["args"]["path"] = "/items/:id"
        row["args"]["path_inputs"] = {"id": row["args"].pop("params")["q"]}
    assert experiment_groups(history, list(range(2, len(history) + 1)))[2] is None
    changed = copy.deepcopy(history)
    changed[-1]["args"]["role"] = "other"
    assert "stay fixed" in experiment_groups(changed, list(range(2, len(changed) + 1)))[2]


@pytest.mark.parametrize("path", ["/items/:id/:other", "/items/prefix:id", "https://other/:id", "/items/:id?q=1"])
def test_ambiguous_path_binding_is_rejected_at_declaration(tmp_path, path):
    tools = tools_for(tmp_path, lambda *a, **k: Resp())
    with pytest.raises(ToolError, match="whole-segment"):
        tools.plan_test(**plan(path=path, input_location="path", input_name="id")["args"])


@pytest.mark.parametrize("parameterized", [False, True])
def test_path_sql_controls_exercise_real_query_behavior(tmp_path, parameterized):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    db.execute("INSERT INTO items VALUES (7, 'pear')")
    seen = []

    def target(method, url, headers, **kwargs):
        value = unquote(urlsplit(url).path.removeprefix("/items/"))
        seen.append(value)
        rows = (db.execute("SELECT id FROM items WHERE name = ?", (value,)) if parameterized else
                db.execute("SELECT id FROM items WHERE name = '" + value + "'")).fetchall()
        return Resp(200, json.dumps({"ids": [r[0] for r in rows]}))

    tools = tools_for(tmp_path, target)
    ctx = tools.ctx
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("GET", "/items/:id", None),))
    declaration = plan(path="/items/:id", input_location="path", input_name="id", baseline="pear",
                       sql_template="pear' AND {{predicate}} -- ", pointer="/ids")["args"]
    actions = [{"tool": "plan_test", "args": declaration},
               {"verdict": {"verdict": "confirmed", "rationale": "Repeated complementary path controls",
                            "proof_steps": list(range(2, 12))}}]

    histories = []

    class Planner:
        def next_step(self, context, history):
            histories.append(copy.deepcopy(history))
            return actions.pop(0) if actions else {"verdict": {"verdict": "inconclusive", "rationale": "No proof"}}

    try:
        result = AgentProbe("injection", Planner).run(ctx)
        assert len(seen) == 10, [h.get("result") for h in histories[-1] if h.get("result", {}).get("error")]
        assert result.verdict == ("inconclusive" if parameterized else "confirmed")
    finally:
        db.close()
