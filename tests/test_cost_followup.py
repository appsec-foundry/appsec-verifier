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


def test_an_empty_fixed_is_accepted_and_adds_no_value(tmp_path):
    """The run's T-004 sent `fixed: {}`; it is a plan with no fixed values, not a declaration error."""
    import json

    from appsec_verifier.agent.steps import parse_step
    from appsec_verifier.agent.tools import AgentTools

    args = {**_search_plan(["x' AND {{predicate}} -- "])["args"], "fixed": {}}
    assert parse_step({"action": "plan_test", "args_json": json.dumps(args)})["tool"] == "plan_test"
    tools = AgentTools(_search_ctx(tmp_path, []))
    assert tools.plan_test(**args)["accepted"] is True
    without = AgentTools(_search_ctx(tmp_path, []))
    without.plan_test(**{k: v for k, v in args.items() if k != "fixed"})
    keys = [sorted(r["params"]) for r in tools.experiment_requests()]
    assert keys and keys == [sorted(r["params"]) for r in without.experiment_requests()]


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


# ── a read plan's own controls (VER-011) ──────────────────────────────────────

def _reviews_target(sent, *, vulnerable):
    """GET /rest/products/:id/reviews: product 1 has a review. Converted with Number(), an injected id matches
    nothing; evaluated as JavaScript, a true predicate matches every review and a false one none."""
    from urllib.parse import unquote, urlsplit

    def target(m, u, h, **kw):
        value = unquote(urlsplit(u).path.split("/")[3])
        sent.append((m, value))
        if value.isdigit():
            hit = value == "1"
        elif vulnerable:
            hit = "|| true" in value
        else:
            hit = False
        return Resp(200, json.dumps({"status": "success", "data": [{"product": 1, "message": "ok"}] if hit else []}))

    return target


def _reviews_ctx(tmp_path, sent, *, vulnerable=False, method="GET"):
    ctx = _ctx(tmp_path, _reviews_target(sent, vulnerable=vulnerable), safe=method == "GET",
               read_only=method == "GET")
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-943", instance="routes/showProductReviews.ts:36",
                       endpoints=(Endpoint(method, "/rest/products/:id/reviews", None),))
    ctx.marker = (MARK, "bb")
    return ctx


def _reviews_plan(**extra):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The id is concatenated into a $where predicate",
        "path": "/rest/products/:id/reviews", "method": "GET", "input_location": "path", "input_name": "id",
        "baseline": "1", "positive": "1 || true", "negative": "1 && false", "pointer": "/data", **extra}}


def _feedback(history):
    return [h["result"] for h in history if h.get("tool") == "experiment"]


def test_own_read_controls_run_at_once_and_say_they_support_only_a_negative_verdict(tmp_path):
    """The run's T-033: the agent's own controls are sent on acceptance, each twice, without a model call per
    request, and the feedback says no declaration confirms a NoSQL injection through a path input."""
    sent = []
    script = Script([_reviews_plan(), {"verdict": {"verdict": "inconclusive", "rationale": "Number() conversion"}}])
    result = AgentProbe("injection", lambda: script).run(_reviews_ctx(tmp_path, sent))
    assert result.verdict == "inconclusive" and script.calls == 2
    assert sorted(v for _, v in sent) == ["1", "1", "1 && false", "1 && false", "1 || true", "1 || true"]
    feedback = _feedback(script.history)
    assert feedback and feedback[0]["proof"] == "negative-only"
    assert "no declaration can confirm" in feedback[0]["next"] and len(feedback[0]["steps"]) == 6


def test_own_read_controls_name_the_form_that_could_confirm(tmp_path):
    sent = []
    ctx = _reviews_ctx(tmp_path, sent)
    ctx.plan = replace(ctx.plan, cwe="CWE-89")
    script = Script([_reviews_plan()])
    AgentProbe("injection", lambda: script).run(ctx)
    assert "declare a plan with sql_template" in _feedback(script.history)[0]["next"]


def test_own_controls_never_confirm_even_when_they_flip(tmp_path):
    """Refused case: values the agent chose that flip the answer are still no proof (VER-011)."""
    sent = []
    script = Script([_reviews_plan(), lambda history: {"verdict": {
        "verdict": "confirmed", "rationale": "the predicate flips the result",
        "proof_steps": _feedback(history)[0]["steps"]}}])
    result = AgentProbe("injection", lambda: script).run(_reviews_ctx(tmp_path, sent, vulnerable=True))
    assert len(sent) == 6 and result.verdict != "confirmed"


def test_own_controls_on_a_write_are_never_sent_by_the_verifier(tmp_path):
    """Refused case: a write plan with the agent's own controls sends nothing on acceptance, and send_controls
    refuses it; only generated controls are sent on request."""
    sent = []
    ctx = _reviews_ctx(tmp_path, sent, method="PATCH")
    script = Script([_reviews_plan(method="PATCH", input_location="json", path="/rest/products/:id/reviews",
                                   baseline=f"{MARK}1", positive=f"{MARK}1 || true", negative=f"{MARK}1 && false"),
                     {"tool": "send_controls", "args": {}}])
    AgentProbe("injection", lambda: script).run(ctx)
    assert script.history[0]["result"].get("accepted") is True
    assert sent == []
    errors = [h["result"].get("error", "") for h in script.history if h.get("tool") == "send_controls"]
    assert errors and "not a challenge" in errors[0]


# ── VER-053: returned marker and engine-error forms ───────────────────────────


def _inj_ctx(tmp_path, target, *, cwe="CWE-89", method="GET", path="/rest/products/search",
             safe=True, read_only=True):
    ctx = _ctx(tmp_path, target, safe=safe, read_only=read_only)
    ctx.plan = replace(ctx.plan, cls="injection", cwe=cwe, instance="routes/search.ts:23",
                       endpoints=(Endpoint(method, path, None),))
    return ctx


def _marker_plan(**extra):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The term sits in two parentheses; a UNION returns a chosen value",
        "path": "/rest/products/search", "input_location": "params", "input_name": "q",
        "sql_marker": {"prefix": "'))", "columns": 1, "column": 0, "comment": "-- "}, **extra}}


def _error_plan(**extra):
    return {"tool": "plan_test", "args": {
        "kind": "boolean", "hypothesis": "The term is concatenated; a stray quote breaks the query",
        "path": "/rest/products/search", "input_location": "params", "input_name": "q",
        "baseline": "zzz", "error_probe": True, **extra}}


def test_returned_marker_confirms_through_the_query_channel(tmp_path):
    """VER-053: a UNION the Verifier builds returns its own constant, proving a read primitive. The marker is a
    concatenation the database computes, so an echo of the payload could not reproduce it."""
    sent = []
    ctx = _inj_ctx(tmp_path, _search_target(sent))
    script = Script([_marker_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert any("UNION SELECT" in q for q in sent) and not any("FROM" in q.upper() for q in sent)


def _echo_target(sent):
    """Reflects the query term verbatim but runs no SQL, so the joined marker never appears."""
    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "")
        sent.append(q)
        return Resp(200, json.dumps({"query": q, "data": []}))

    return target


def test_an_echo_without_execution_does_not_confirm_the_marker_form(tmp_path):
    """Refused case: the payload is reflected, but the concatenated marker is never computed, so no confirmation."""
    sent = []
    ctx = _inj_ctx(tmp_path, _echo_target(sent))
    script = Script([_marker_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict != "confirmed"


def test_engine_error_confirms_sql_injection(tmp_path):
    """VER-053: a stray quote raises a database engine error that the balanced control does not."""
    sent = []
    ctx = _inj_ctx(tmp_path, _search_target(sent))
    script = Script([_error_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert "zzz'" in sent and "zzz''" in sent                 # the break and the balanced control


def test_engine_error_text_is_withheld_from_the_model(tmp_path):
    """VER-053/VER-016: the model sees only the engine-error class, never the error text."""
    sent = []
    ctx = _inj_ctx(tmp_path, _search_target(sent))
    script = Script([_error_plan(), _confirm])
    AgentProbe("injection", lambda: script).run(ctx)
    controls = [h["result"] for h in script.history if h.get("experiment")]
    assert any(c.get("engine_error") is True for c in controls)
    assert all("body withheld" in c.get("body_excerpt", "") for c in controls)
    assert not any("unrecognized token" in c.get("body_excerpt", "") for c in controls)


def _generic_500_target(sent):
    """A plain 500 with no engine detail, as a WAF or a generic error handler returns."""
    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "")
        sent.append(q)
        if q.count("'") % 2 == 1:
            return Resp(500, "Internal Server Error")
        return Resp(200, json.dumps({"data": []}))

    return target


def test_a_generic_failure_does_not_confirm_the_engine_error_form(tmp_path):
    """Refused case: a 500 without an engine-error signature is not proof; input validation or a WAF look like it."""
    sent = []
    ctx = _inj_ctx(tmp_path, _generic_500_target(sent))
    script = Script([_error_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict != "confirmed"


def _nosql_target(sent):
    """A Mongo-style endpoint: an invalid $regex (an unclosed group) raises an engine error, a valid one does not."""
    def target(m, u, h, **kw):
        val = (kw.get("json") or {}).get("q")
        sent.append(val)
        if isinstance(val, dict) and str(val.get("$regex", "")).startswith("("):
            return Resp(500, json.dumps({"errmsg": "Regular expression is invalid: missing )", "code": 51091}))
        return Resp(200, json.dumps({"data": []}))

    return target


def test_engine_error_confirms_nosql_injection(tmp_path):
    """VER-053: the engine-error form is not SQL-only; a NoSQL operator injection confirms the same way. On a POST
    write the controls carry the finding marker, so they stay attributable (VER-014)."""
    sent = []
    ctx = _inj_ctx(tmp_path, _nosql_target(sent), cwe="CWE-943", method="POST", path="/rest/user/find",
                   safe=False, read_only=False)
    ctx.marker = (MARK, "bb")                                  # a POST write must carry the finding marker
    plan = {"tool": "plan_test", "args": {"kind": "boolean", "hypothesis": "q is a Mongo operator field",
            "path": "/rest/user/find", "method": "POST", "input_location": "json", "input_name": "q",
            "error_probe": True}}
    script = Script([plan, {"tool": "send_controls", "args": {}}, _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert all(isinstance(v, dict) and MARK in v.get("$regex", "") for v in sent)   # every write is attributable


def _xpath_target(sent):
    """An XPath endpoint: an unbalanced quote raises a parser error, a balanced one does not."""
    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "")
        sent.append(q)
        if q.count("'") % 2 == 1:
            return Resp(500, "net.sf.saxon.trans.XPathException: Invalid XPath expression")
        return Resp(200, json.dumps({"data": []}))

    return target


def test_engine_error_confirms_xpath_injection(tmp_path):
    """VER-053: an XPath injection confirms through the same engine-error form."""
    sent = []
    ctx = _inj_ctx(tmp_path, _xpath_target(sent), cwe="CWE-643")
    script = Script([_error_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True


def _double_quoted_target(sent):
    """The term sits in a double-quoted SQL string and the application strips single quotes, so only the double
    quote of the metacharacter set breaks the query."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE products(id INTEGER, name TEXT)")

    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "").replace("'", "")
        sent.append(q)
        try:
            db.execute('SELECT id FROM products WHERE name = "' + q + '"').fetchall()
        except sqlite3.Error as exc:
            return Resp(500, json.dumps({"error": str(exc)}))
        return Resp(200, json.dumps({"data": []}))

    return target


def test_the_metacharacter_set_finds_a_break_the_single_quote_misses(tmp_path):
    """VER-053: the sweep sends more than the single quote; here only the double quote reaches the parser, and
    one breaking metacharacter whose counterpart stays quiet confirms."""
    sent = []
    ctx = _inj_ctx(tmp_path, _double_quoted_target(sent))
    script = Script([_error_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert {'zzz"', 'zzz""', "zzz`", "zzz``"} <= set(sent)   # the whole set was sent, not only the quote


def _template_target(sent):
    """A Jinja-style template sink: an unclosed {{ raises a template syntax error, a single { is inert text."""
    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "")
        sent.append(q)
        if q.count("{{") > q.count("}}"):
            return Resp(500, "jinja2.exceptions.TemplateSyntaxError: unexpected end of template")
        return Resp(200, json.dumps({"data": []}))

    return target


def test_engine_error_confirms_template_injection(tmp_path):
    """VER-053: template injection confirms through its delimiter set; nothing is evaluated."""
    sent = []
    ctx = _inj_ctx(tmp_path, _template_target(sent), cwe="CWE-1336")
    script = Script([_error_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert "zzz{{" in sent and "zzz{" in sent


def _always_failing_target(sent):
    """Every input with a metacharacter raises the same engine error, balanced or not."""
    def target(m, u, h, **kw):
        q = (kw.get("params") or {}).get("q", "")
        sent.append(q)
        if q != "zzz":
            return Resp(500, 'unrecognized token: "x"')
        return Resp(200, json.dumps({"data": []}))

    return target


def test_a_break_whose_counterpart_also_fails_does_not_confirm(tmp_path):
    """Refused case: when the balanced counterpart raises the engine error too, the break is not what caused it."""
    sent = []
    ctx = _inj_ctx(tmp_path, _always_failing_target(sent))
    script = Script([_error_plan(), _confirm])
    result = AgentProbe("injection", lambda: script).run(ctx)
    assert result.verdict != "confirmed"
    feedback = next(h["result"] for h in script.history if h.get("tool") == "experiment")
    assert feedback["proof"] == "missing" and "counterpart did too" in feedback["reason"]
