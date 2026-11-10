"""Loop-level scenarios of the second cost round: write controls on request (VER-011), template candidates
(VER-011), the auth-artifact form (VER-049), proof steps chosen by code and proof feedback (VER-043), each with
the refused case. Offline: SQLite stands in for the target's query, a fake planner for the model."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

import pytest
from test_agent_tools import Resp, _ctx

from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.endpoints import Endpoint

MARK = "vrfaa"   # the finding's marker part; a write must carry it (VER-014)
EMAIL = f"{MARK}@nobody.test"


class Script:
    """A planner that replays steps; a callable step is given the history so far."""

    def __init__(self, steps):
        self.steps, self.calls, self.history = list(steps), 0, []

    def next_step(self, ctx, history):
        self.calls += 1
        self.history = history
        step = self.steps.pop(0) if self.steps else {"verdict": {"verdict": "inconclusive",
                                                                  "rationale": "script ended"}}
        return step(history) if callable(step) else step


def _holding_steps(history):
    feedback = [h["result"] for h in history if h.get("tool") == "experiment" and h["result"].get("proof") == "holds"]
    return feedback[-1]["steps"] if feedback else []


def _confirm(history):
    return {"verdict": {"verdict": "confirmed", "rationale": "the controls decide the result",
                        "proof_steps": _holding_steps(history)}}


def _login_target(sent):
    """A login whose email is concatenated into SQL: a true predicate signs in, anything else is 401."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users(email TEXT, password TEXT)")
    db.execute("INSERT INTO users VALUES ('admin@shop.test', 'secret')")

    def target(m, u, h, **kw):
        body = kw.get("json") or {}
        sent.append((m, body.get("email")))
        try:
            rows = db.execute("SELECT email FROM users WHERE email = '" + str(body.get("email")) + "' AND password = '"
                              + str(body.get("password", "")) + "'").fetchall()
        except sqlite3.Error as exc:
            return Resp(500, json.dumps({"error": str(exc)}))
        if rows:
            return Resp(200, json.dumps({"authentication": {"token": "eyJ.secret.token", "umail": rows[0][0]}}))
        return Resp(401, "Invalid email or password.")

    return target


def _login_ctx(tmp_path, sent, *, safe=False, read_only=False):
    ctx = _ctx(tmp_path, _login_target(sent), safe=safe, read_only=read_only)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", instance="routes/login.ts:34",
                       endpoints=(Endpoint("POST", "/rest/user/login", None),))
    ctx.marker = (MARK, "bb")
    return ctx


def _login_plan(template=None, **extra):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The email is concatenated into the login query",
        "path": "/rest/user/login", "method": "POST", "input_location": "json", "input_name": "email",
        "baseline": EMAIL, "pointer": "/authentication/token", "auth_artifact": True,
        "sql_template": template or f"{EMAIL}' OR {{{{predicate}}}} -- ", **extra}}


def test_login_bypass_confirms_with_send_controls_in_few_model_calls(tmp_path):
    """T-011: the auth-artifact plan on a write, its controls sent in one action on request, confirmed."""
    sent = []
    ctx = _login_ctx(tmp_path, sent)
    script = Script([_login_plan(), {"tool": "send_controls", "args": {}}, _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert script.calls == 3                                   # plan, send_controls, verdict
    assert len(sent) == 5                                      # five controls, each once: no repetition needed
    statuses = [h["result"]["status"] for h in script.history if h.get("experiment")]
    assert sorted(statuses) == [200, 200, 401, 401, 401]       # the 401-to-200 flip is the proof (VER-049)


def test_a_write_plan_sends_nothing_on_acceptance(tmp_path):
    """Refused case: accepting a write plan never sends a control by itself."""
    sent = []
    ctx = _login_ctx(tmp_path, sent)
    script = Script([_login_plan()])
    AgentProbe("injection", lambda: script).run(ctx)
    assert sent == []


@pytest.mark.parametrize("safe, read_only", [(True, True), (False, True)])
def test_send_controls_is_refused_without_intrusive_mode_or_state_change(tmp_path, safe, read_only):
    """Refused case: safe mode, or a scope with allow_state_change false, sends no write control."""
    sent = []
    ctx = _login_ctx(tmp_path, sent, safe=safe, read_only=read_only)
    script = Script([_login_plan(), {"tool": "send_controls", "args": {}}])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert sent == [] and result.verdict != "confirmed"


def test_send_controls_needs_an_accepted_plan_and_runs_once_per_plan(tmp_path):
    """Refused case: no plan, nothing sent; a second call for the same plan sends nothing more."""
    sent = []
    ctx = _login_ctx(tmp_path, sent)
    script = Script([{"tool": "send_controls", "args": {}}])
    AgentProbe("injection", lambda: script).run(ctx)
    assert sent == []
    errors = [h["result"]["error"] for h in script.history if h.get("tool") == "send_controls"]
    assert errors and "not a challenge" in errors[0]

    sent2 = []
    ctx2 = _login_ctx(tmp_path, sent2)
    script2 = Script([_login_plan(), {"tool": "send_controls", "args": {}}, {"tool": "send_controls", "args": {}}])
    AgentProbe("injection", lambda: script2).run(ctx2)
    assert len(sent2) == 5
    errors = [h["result"]["error"] for h in script2.history if h.get("tool") == "send_controls"]
    assert errors and "already sent" in errors[-1]


def _search_target(sent):
    """A product search whose term sits inside two parentheses: only a template that closes both works."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE products(id INTEGER, name TEXT)")
    db.executemany("INSERT INTO products VALUES (?, ?)", [(1, "apple"), (2, "pear")])

    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "")
        sent.append(q)
        try:
            rows = db.execute("SELECT id FROM products WHERE ((name LIKE '%" + q + "%'))").fetchall()
        except sqlite3.Error as exc:
            return Resp(500, json.dumps({"error": str(exc)}))
        return Resp(200, json.dumps({"data": [r[0] for r in rows]}))

    return target


def _search_ctx(tmp_path, sent):
    ctx = _ctx(tmp_path, _search_target(sent))
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", instance="routes/search.ts:23",
                       endpoints=(Endpoint("GET", "/rest/products/search", None),))
    return ctx


def _search_plan(templates):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The search term is concatenated into the query",
        "path": "/rest/products/search", "input_location": "params", "input_name": "q",
        "baseline": "zzz", "pointer": "/data", "sql_template": templates}}


def test_template_candidates_find_the_working_one_in_one_plan(tmp_path):
    """T-004: two candidates fail with a server error, the third confirms, all in one model decision."""
    sent = []
    ctx = _search_ctx(tmp_path, sent)
    templates = ["zzz' OR {{predicate}} -- ", "zzz%' OR ({{predicate}} -- ", "zzz%' OR {{predicate}})) -- "]
    script = Script([_search_plan(templates), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert script.calls == 2                                   # plan and verdict: no revision call
    plans = [h for h in script.history if h.get("tool") == "plan_test"]
    assert len(plans) == 3 and plans[-1]["args"]["sql_template"] == templates[2]


def test_a_failed_control_is_named_in_the_experiment_feedback(tmp_path):
    """WP2: the feedback gives the failed control's step, status and an excerpt of its error."""
    sent = []
    ctx = _search_ctx(tmp_path, sent)
    script = Script([_search_plan("zzz' OR {{predicate}} -- ")])
    AgentProbe("injection", lambda: script).run(ctx)
    feedback = next(h["result"] for h in script.history if h.get("tool") == "experiment")
    assert feedback["proof"] == "missing"
    failed = feedback["failed_control"]
    assert failed["status"] == 500 and "SQLITE" in failed["excerpt"].upper() or "error" in failed["excerpt"]
    assert "so far" in feedback["reason"]                       # names how many of each control are recorded


def test_proof_steps_are_chosen_by_code_after_a_holding_experiment(tmp_path):
    """A confirmed verdict that cites nothing stands on the experiment's own steps, re-checked in code."""
    sent = []
    ctx = _search_ctx(tmp_path, sent)
    script = Script([_search_plan("zzz%' OR {{predicate}})) -- "),
                     {"verdict": {"verdict": "confirmed", "rationale": "the result set follows the predicate",
                                  "proof_steps": []}}])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert result.proof["steps"] == _holding_steps(script.history)


def test_code_chosen_steps_never_confirm_an_experiment_that_did_not_hold(tmp_path):
    """Refused case: without a holding experiment, a verdict citing nothing stays unconfirmed."""
    sent = []
    ctx = _search_ctx(tmp_path, sent)
    script = Script([_search_plan("zzz' OR {{predicate}} -- "),
                     {"verdict": {"verdict": "confirmed", "rationale": "claim", "proof_steps": []}},
                     {"verdict": {"verdict": "confirmed", "rationale": "claim", "proof_steps": []}},
                     {"verdict": {"verdict": "confirmed", "rationale": "claim", "proof_steps": []}}])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "inconclusive"


def test_a_login_status_flip_without_the_auth_form_points_to_it(tmp_path):
    """WP2: a response-field plan whose controls flip 401 to 200 is told to use auth_artifact."""
    from appsec_verifier.agent.experiments import injection_check

    plan = {"kind": "boolean", "path": "/rest/user/login", "method": "POST", "input_location": "json",
            "input_name": "email", "baseline": "b", "positive": "p", "negative": "n", "positive_other": "po",
            "negative_other": "no", "pointer": "/authentication/token", "sql_template": "x {{predicate}}"}
    history = [{"tool": "plan_test", "args": plan, "result": {"accepted": True, "experiment": plan}}]
    for value, status in (("b", 401), ("p", 200), ("n", 401), ("po", 200), ("no", 401)) * 2:
        history.append({"tool": "http_request", "args": {"method": "POST", "path": "/rest/user/login",
                                                          "json": {"email": value}},
                        "result": {"status": status}})
    reason = injection_check(None, history, list(range(2, len(history) + 1)))
    assert "auth_artifact" in reason


# ── values for the request's other inputs (VER-011) ───────────────────────────

LOGIN_VARIANT = {"id": "variant-001", "hypothesis": "The email is concatenated into the login query",
                 "request": {"method": "POST", "path": "/rest/user/login",
                             "inputs": [{"location": "json", "name": "email"},
                                        {"location": "json", "name": "password"}]}}


def _pin(ctx, variant):
    ctx.plan = replace(ctx.plan, verification_context={"version": 1, "variants": [variant]}, variant_id=variant["id"])
    return ctx


def test_a_login_variant_with_two_inputs_confirms_with_a_fixed_password(tmp_path):
    """The run's T-011: the variant declares email and password, so the generated controls carry a fixed password
    and only the email differs."""
    sent = []
    ctx = _pin(_login_ctx(tmp_path, sent), LOGIN_VARIANT)
    plan = _login_plan(variant="variant-001", fixed={"json": {"password": "not-a-secret"}})
    script = Script([plan, {"tool": "send_controls", "args": {}}, _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and script.calls == 3, result.rationale
    controls = [h["args"]["json"] for h in script.history if h.get("experiment")]
    assert len(controls) == 5 and {c["password"] for c in controls} == {"not-a-secret"}
    assert len({c["email"] for c in controls}) == 5


def test_a_login_variant_without_the_password_is_refused_before_any_request(tmp_path):
    """Refused case: the controls would lack a declared input, so the plan names it and nothing is sent."""
    sent = []
    ctx = _pin(_login_ctx(tmp_path, sent), LOGIN_VARIANT)
    script = Script([_login_plan(variant="variant-001"), {"tool": "send_controls", "args": {}}])
    AgentProbe("injection", lambda: script).run(ctx)
    assert sent == []
    error = script.history[0]["result"]["error"]
    assert "json:password" in error and '"json": {"password"' in error


@pytest.mark.parametrize("extra, reason", [
    ({"fixed": {"json": {"email": "x"}}}, "must not set the injected input"),
    ({"fixed": {"headers": {"X-A": "1"}}}, "invalid experiment declaration"),
    ({"fixed": {"json": {}}}, "invalid experiment declaration"),
    ({"fixed": {"json": {"password": {"$ne": 1}}}}, "invalid experiment declaration"),   # values are scalars
    ({"fixed": {"json": {"password": "x"}}, "sql_template": None, "positive": "a", "negative": "b"},
     "plan has none"),
])
def test_fixed_values_are_refused_where_they_do_not_fit(tmp_path, extra, reason):
    from appsec_verifier.agent.tools import AgentTools, ToolError

    ctx = _login_ctx(tmp_path, [])
    args = {k: v for k, v in {**_login_plan()["args"], "auth_artifact": None, **extra}.items() if v is not None}
    with pytest.raises(ToolError, match=reason):
        AgentTools(ctx).plan_test(**args)


def test_command_injection_probes_carry_no_fixed_values(tmp_path):
    """Refused case: command probes send only the harmless arithmetic controls, so no other value rides along."""
    from appsec_verifier.agent.tools import AgentTools, ToolError

    ctx = _search_ctx(tmp_path, [])
    ctx.plan = replace(ctx.plan, cwe="CWE-78")
    baseline = "plain"
    args = {k: v for k, v in _search_plan(["x' AND {{predicate}} -- "])["args"].items() if k != "sql_template"}
    with pytest.raises(ToolError, match="fixed is not available"):
        AgentTools(ctx).plan_test(**{**args, "baseline": baseline, "fixed": {"params": {"sort": "name"}},
                                     "expression_template": baseline + "; printf '%s' \"$(({{expression}}))\""})


def test_a_query_key_in_fixed_means_params(tmp_path):
    from appsec_verifier.agent.tools import AgentTools

    ctx = _search_ctx(tmp_path, [])
    tools = AgentTools(ctx)
    result = tools.plan_test(**{**_search_plan(["x' AND {{predicate}} -- "])["args"],
                                "fixed": {"query": {"sort": "name"}}})
    assert result["accepted"] is True
    assert all(r["params"]["sort"] == "name" for r in tools.experiment_requests())


def test_controls_refused_before_sending_leave_the_plan_unsent(tmp_path):
    """A write control the controller refuses never reaches the target, so a second send_controls repeats the
    refusal instead of claiming the controls ran."""
    sent = []
    ctx = _login_ctx(tmp_path, sent)
    ctx.marker = ("vrfzz", "bb")       # the controls carry another marker, so every write is refused (VER-014)
    script = Script([_login_plan(), {"tool": "send_controls", "args": {}}, {"tool": "send_controls", "args": {}}])
    AgentProbe("injection", lambda: script).run(ctx)
    assert sent == []
    errors = [h["result"].get("error", "") for h in script.history if h.get("experiment")]
    assert len(errors) == 2 and all("must carry vrfzz" in e for e in errors)
    assert not any("already sent" in h["result"].get("error", "") for h in script.history)


def _contract_case(name):
    """A two-input variant per form whose controls the Verifier generates, with the plan that fixes the other."""
    q = {"location": "query", "name": "q"}
    cases = {
        "sql-read": ("CWE-89", "GET", "/search", [q, {"location": "query", "name": "sort"}],
                     {"input_location": "params", "input_name": "q", "baseline": "plain", "pointer": "/result",
                      "sql_template": "plain' AND {{predicate}} -- "}, {"params": {"sort": "name"}}),
        "sql-login": ("CWE-89", "POST", "/rest/user/login", LOGIN_VARIANT["request"]["inputs"],
                      {"input_location": "json", "input_name": "email", "baseline": EMAIL,
                       "pointer": "/authentication/token", "auth_artifact": True,
                       "sql_template": f"{EMAIL}' OR {{{{predicate}}}} -- "}, {"json": {"password": "x"}}),
        "nosql-operator": ("CWE-943", "GET", "/search", [{"location": "json", "name": "q"},
                                                         {"location": "json", "name": "limit"}],
                           {"input_location": "json", "input_name": "q", "baseline": "apple", "pointer": "/result",
                            "operator_challenge": "nosql"}, {"json": {"limit": 5}}),
        "expression": ("CWE-1336", "GET", "/search", [q, {"location": "query", "name": "lang"}],
                       {"input_location": "params", "input_name": "q", "baseline": "plain", "pointer": "/result",
                        "expression_template": "{{ {{expression}} }}"}, {"params": {"lang": "en"}}),
    }
    return cases[name]


@pytest.mark.parametrize("name", ["sql-read", "sql-login", "nosql-operator", "expression"])
def test_every_generated_control_passes_the_verifiers_own_checks(tmp_path, name):
    """Contract: what the Verifier generates itself must satisfy what its controller demands of any request. Without
    the other input in fixed the plan is refused, so no control is generated that the controller would refuse."""
    from appsec_verifier.agent.controller import Controller
    from appsec_verifier.agent.tools import AgentTools, ToolError

    cwe, method, path, inputs, declaration, fixed = _contract_case(name)
    ctx = _pin(_ctx(tmp_path, lambda *a, **k: Resp(), safe=False, read_only=False),
               {"id": "v", "hypothesis": "The input reaches the query",
                "request": {"method": method, "path": path, "inputs": inputs}})
    ctx.plan = replace(ctx.plan, cls="injection", cwe=cwe)
    ctx.marker = (MARK, "bb")
    plan = {"kind": "boolean", "hypothesis": "The input reaches the query unescaped", "variant": "v",
            "path": path, "method": method, **declaration}
    with pytest.raises(ToolError, match="a value in fixed"):
        AgentTools(ctx).plan_test(**plan)
    tools = AgentTools(ctx)
    accepted = tools.plan_test(**plan, fixed=fixed)
    controller = Controller(ctx)
    controller.plan = accepted.get("experiment") or plan
    requests = tools.experiment_requests(write=method != "GET")
    assert requests
    for request in requests:
        controller.before("http_request", request, experiment=True)
