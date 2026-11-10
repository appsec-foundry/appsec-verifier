"""Finding-bound derivation and adaptive proof against fake targets (VER-005, VER-008, VER-043)."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

import pytest
from test_agent_probe import ScriptedPlanner
from test_agent_tools import Resp, _ctx
from test_experiments import STRATEGY

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.derivation import MAX_DERIVED
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.steps import parse_step
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.cli import _blocker
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.scope import ScopeGuard


def context(tmp_path, transport=lambda *a, **k: Resp(), *, safe=True):
    ctx = _ctx(tmp_path, transport, safe=safe, read_only=safe)
    ctx.plan = replace(ctx.plan, cls="open-redirect", cwe="CWE-601",
                       endpoints=(Endpoint("GET", "/go", None),))
    ctx.marker = ("harmless", "marker")
    return ctx


def response(ctx, body, *, path="/go", complete=True):
    ctx.agent_history = [{"tool": "http_request", "args": {"path": path}, "result": {"status": 200}}]
    ctx.responses = {1: {"body": body, "complete": complete}}


def derive(ctx, path="/go/next", method="GET", inputs=None, evidence_step=1):
    return AgentTools(ctx).derive_request(evidence_step=evidence_step, method=method, path=path,
                                         inputs=inputs or [], reason="Follow the form for the affected resource")


def test_missing_exploit_recipe_is_completed_from_a_form_and_proved(tmp_path):
    sent = []

    def target(method, url, headers, **kwargs):
        sent.append((method, url))
        if url.endswith("/go"):
            return Resp(200, '<form action="/go/next"><input name="destination"></form>')
        assert kwargs["params"] == {"destination": "https://harmlessmarker.invalid"}
        reply = Resp(302)
        reply.headers = {"Location": kwargs["params"]["destination"]}
        return reply

    ctx = context(tmp_path, target)
    actions = [
        {"tool": "http_request", "args": {"path": "/go"}},
        {"tool": "derive_request", "args": {"evidence_step": 1, "method": "GET", "path": "/go/next",
         "inputs": [{"location": "query", "name": "destination"}], "reason": "The form supplies the redirect input"}},
        {"tool": "http_request", "args": {"path": "/go/next",
                                          "params": {"destination": "https://harmlessmarker.invalid"}}},
        {"verdict": {"verdict": "confirmed", "rationale": "The redirect uses the harmless marker", "proof_steps": [3]}},
    ]
    result = AgentProbe("open-redirect", lambda: ScriptedPlanner(actions)).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"]
    assert sent == [("GET", ctx.target_base + "/go"), ("GET", ctx.target_base + "/go/next")]
    assert result.poc and any("supported by recorded step 1" in o for o in result.observations)


@pytest.mark.parametrize("path", ["/other", "/go/next/further", "https://evil.example/go/next",
                                 "https://api.example.com/go/next", "/go/../admin", "/go/%2e%2e/admin"])
def test_an_observed_link_cannot_authorize_unrelated_or_out_of_scope_requests(tmp_path, path):
    ctx = context(tmp_path)
    response(ctx, f'<a href="{path}">open</a>')
    with pytest.raises(ToolError):
        derive(ctx, path)
    assert not ctx.derived_requests


@pytest.mark.parametrize("prefix", ["/", "/api", "/v1", "/rest"])
def test_generic_root_does_not_authorize_an_application_crawl(tmp_path, prefix):
    ctx = context(tmp_path)
    ctx.plan.endpoints = (Endpoint("GET", prefix, None),)
    response(ctx, f'<a href="{prefix.rstrip("/")}/admin">open</a>', path=prefix)
    with pytest.raises(ToolError):
        derive(ctx, prefix.rstrip("/") + "/admin")


def test_new_routes_do_not_become_discovery_roots(tmp_path):
    ctx = context(tmp_path)
    response(ctx, '<a href="/go/next">next</a>')
    derive(ctx)
    response(ctx, '<a href="/go/next/admin">next</a>', path="/go/next")
    with pytest.raises(ToolError):
        derive(ctx, "/go/next/admin")


@pytest.mark.parametrize("step,complete", [(0, True), (2, True), (1, False)])
def test_missing_or_truncated_evidence_is_not_accepted(tmp_path, step, complete):
    ctx = context(tmp_path)
    response(ctx, '<a href="/go/next">next</a>', complete=complete)
    with pytest.raises(ToolError):
        derive(ctx, evidence_step=step)


def test_an_unseen_input_or_a_failed_response_cannot_supply_a_request(tmp_path):
    ctx = context(tmp_path)
    response(ctx, '<form action="/go/next"><input name="q"></form>')
    with pytest.raises(ToolError):
        derive(ctx, inputs=[{"location": "query", "name": "admin"}])
    ctx.agent_history[0]["result"] = {"status": 500}
    with pytest.raises(ToolError):
        derive(ctx)


def test_scope_path_restriction_also_applies_to_recorded_forms(tmp_path):
    ctx = context(tmp_path)
    ctx.scope = {**ctx.scope, "path_prefixes": ["/go/allowed"]}
    ctx.guard = ScopeGuard(ctx.scope)
    response(ctx, '<form action="/go/next"></form>')
    with pytest.raises(ToolError, match="authorised"):
        derive(ctx)


@pytest.mark.parametrize("safe,forbid", [(True, False), (False, True)])
def test_observed_write_never_overrides_mode_or_scope(tmp_path, safe, forbid):
    ctx = context(tmp_path, safe=safe)
    ctx.scope = {**ctx.scope, "allow_state_change": not forbid}
    response(ctx, '<form method="POST" action="/go/next"><input name="q"></form>')
    with pytest.raises(ToolError, match="permission"):
        derive(ctx, method="POST", inputs=[{"location": "form", "name": "q"}])


def test_a_derived_write_still_requires_the_finding_marker(tmp_path):
    ctx = context(tmp_path, safe=False)
    response(ctx, '<form method="POST" action="/go/next"><input name="q"></form>')
    derive(ctx, method="POST", inputs=[{"location": "form", "name": "q"}])
    with pytest.raises(ToolError, match="carry"):
        Controller(ctx).before("http_request", {"method": "POST", "path": "/go/next", "form": {"q": "plain"}})


def source(ctx, text, path="routes/basket.ts"):
    ctx.agent_history = [{"tool": "read_source", "args": {"path": path},
                          "result": {"text": text, "start_line": 1}}]


def test_evidenced_input_can_extend_a_variant_but_an_operator_pin_still_wins(tmp_path):
    ctx = context(tmp_path)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", verification_context={"variants": [{
        "id": "old", "request": {"method": "GET", "path": "/go", "inputs": [{"location": "query", "name": "q"}]}}]})
    source(ctx, "app.get('/go', req => query(req.query.filter))")
    derive(ctx, "/go", inputs=[{"location": "query", "name": "filter"}])
    args = {"kind": "boolean", "hypothesis": "The filter changes the SQL predicate", "strategy": STRATEGY,
            "variant": "old", "path": "/go", "input_location": "params", "input_name": "filter",
            "baseline": "pear", "sql_template": "pear' AND {{predicate}} -- ", "pointer": "/items"}
    controller, tools = Controller(ctx), AgentTools(ctx)
    controller.before("plan_test", args)
    assert tools.plan_test(**args)["accepted"]
    ctx.scope = {**ctx.scope, "injection_inputs": [{"finding_id": ctx.plan.id, "path": "/go",
                  "input_location": "params", "input_name": "q", "semantics": "literal"}]}
    with pytest.raises(ToolError, match="declared injection_inputs"):
        tools.plan_test(**args)


def test_derived_input_drives_fresh_sql_controls_against_an_isolated_database(tmp_path):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    db.execute("INSERT INTO items VALUES (7, 'pear')")
    requests = []

    def target(method, url, headers, **kwargs):
        value = kwargs["params"]["filter"]
        requests.append(value)
        rows = db.execute("SELECT id FROM items WHERE name = '" + value + "'").fetchall()
        return Resp(200, json.dumps({"items": [r[0] for r in rows]}))

    ctx = context(tmp_path, target)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", verification_context={"variants": [{
        "id": "hint", "request": {"method": "GET", "path": "/go", "inputs": [{"location": "query", "name": "q"}]}}]})
    (tmp_path / "routes" / "basket.ts").write_text("app.get('/go', req => query(req.query.filter))")
    declaration = {"kind": "boolean", "hypothesis": "The filter changes the SQL predicate", "strategy": STRATEGY,
                   "variant": "hint", "path": "/go", "input_location": "params", "input_name": "filter",
                   "baseline": "pear", "sql_template": "pear' AND {{predicate}} -- ", "pointer": "/items"}
    actions = [{"tool": "read_source", "args": {"path": "routes/basket.ts"}},
               {"tool": "derive_request", "args": {"evidence_step": 1, "method": "GET", "path": "/go",
                "inputs": [{"location": "query", "name": "filter"}], "reason": "The handler reads the filter input"}},
               {"tool": "plan_test", "args": declaration},
               {"verdict": {"verdict": "confirmed", "rationale": "Fresh controls change the selected result",
                            "proof_steps": list(range(4, 14))}}]
    try:
        result = AgentProbe("injection", lambda: ScriptedPlanner(actions)).run(ctx)
        assert result.verdict == "confirmed" and result.proof["checked"] and len(requests) == 10
        assert result.proof["variant"] == "hint" and result.proof["observation_pointer"] == "/items"
    finally:
        db.close()


def test_unrelated_source_does_not_authorize_requests_even_with_matching_text(tmp_path):
    ctx = context(tmp_path)
    source(ctx, "app.get('/go/next', req => req.query.q)", path="unrelated.ts")
    with pytest.raises(ToolError, match="source"):
        derive(ctx)


def test_local_import_supplies_a_related_route_but_not_an_unrelated_one(tmp_path):
    ctx = context(tmp_path)
    source(ctx, "import './redirect'")
    ctx.agent_history.append({"tool": "read_source", "args": {"path": "routes/redirect.ts"}, "result": {
        "text": "router.get('/go/next', handler)\nrouter.get('/admin', admin)", "start_line": 1}})
    assert derive(ctx, evidence_step=2)["accepted"]
    with pytest.raises(ToolError):
        derive(ctx, path="/admin", evidence_step=2)


def test_source_can_supply_a_missing_route_without_guessing(tmp_path):
    ctx = context(tmp_path)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", endpoints=())
    source(ctx, "app.get('/go', req => query(req.query.q))")
    assert _blocker(ctx.plan, identities=[], browser=None, listener=None, scope=ctx.scope,
                    safe=True, source=True) is None
    assert derive(ctx, "/go", inputs=[{"location": "query", "name": "q"}])["accepted"]
    with pytest.raises(ToolError):
        derive(ctx, "/invented")


def test_sibling_source_import_is_related_but_repository_escape_is_not(tmp_path):
    ctx = context(tmp_path)
    source(ctx, "import '../handlers/redirect'\nimport '../../outside'")
    for path in ("handlers/redirect.ts", "../outside.ts"):
        ctx.agent_history.append({"tool": "read_source", "args": {"path": path},
                                  "result": {"text": "router.get('/go/next', handler)", "start_line": 1}})
    assert derive(ctx, evidence_step=2)["accepted"]
    with pytest.raises(ToolError, match="local import"):
        derive(ctx, evidence_step=3)


def test_import_depth_cannot_grow_with_history_order(tmp_path):
    ctx = context(tmp_path)
    source(ctx, "import './one'")
    for name, child in (("one", "two"), ("two", "three"), ("three", "four"), ("four", "five")):
        ctx.agent_history.append({"tool": "read_source", "args": {"path": f"routes/{name}.ts"}, "result": {
            "text": f"import './{child}'\nrouter.get('/go/next', handler)", "start_line": 1}})
    assert derive(ctx, evidence_step=4)["accepted"]
    with pytest.raises(ToolError, match="local import"):
        derive(ctx, evidence_step=5)


def test_derivation_is_bounded_and_its_action_schema_is_strict(tmp_path):
    ctx = context(tmp_path)
    response(ctx, '<a href="/go/next">next</a>')
    for _ in range(MAX_DERIVED):
        derive(ctx)
    with pytest.raises(ToolError, match="allowance"):
        derive(ctx)
    out = parse_step({"action": "derive_request", "args_json": json.dumps({"evidence_step": 1, "method": "DELETE",
                     "path": "/go", "inputs": [], "reason": "delete everything"}), "note": "try"})
    assert out.get("refused") == "derive_request"


def _registration_repo(tmp_path, import_path="./routes/payment"):
    (tmp_path / "routes" / "payment.ts").write_text(
        "export function getPaymentMethodById () {\n"
        "  return async (req, res) => res.json(await CardModel.findOne({ where: { id: req.params.id } }))\n"
        "}\n")
    (tmp_path / "server.ts").write_text(
        f"import * as payment from '{import_path}'\n"
        "app.get('/api/Cards/:id', security.appendUserId(), utils.asyncHandler(payment.getPaymentMethodById()))\n")


def _registration_ctx(tmp_path, sent):
    def target(method, url, headers, **kwargs):
        sent.append((method, url))
        return Resp(200, '{"id": 2}')

    ctx = _ctx(tmp_path, target)
    ctx.plan = replace(ctx.plan, instance="routes/payment.ts:2", endpoints=())
    return ctx


def _registration_steps():
    return [
        {"tool": "read_source", "args": {"path": "routes/payment.ts", "around_line": 2}},
        {"tool": "search_source", "args": {"text": "getPaymentMethodById"}},
        {"tool": "read_source", "args": {"path": "server.ts", "around_line": 2}},
        {"tool": "derive_request", "args": {"evidence_step": 3, "method": "GET", "path": "/api/Cards/2",
                                            "inputs": [], "reason": "server.ts registers the finding's handler"}},
        {"tool": "http_request", "args": {"path": "/api/Cards/2", "role": "customer-a"}},
    ]


def test_a_route_another_file_registers_for_the_findings_handler_supplies_its_request(tmp_path):
    """VER-008: a finding without an assessed route (T-010) gets its request from the file that registers its
    handler, found by a content search; the request is sent and its provenance is recorded."""
    sent = []
    ctx = _registration_ctx(tmp_path, sent)
    _registration_repo(tmp_path)
    AgentProbe("access-control", lambda: ScriptedPlanner(_registration_steps())).run(ctx)
    assert sent == [("GET", "https://app.example.com/api/Cards/2")]
    derived = ctx.derived_requests[0]
    assert derived["source_file"] == "server.ts" and derived["source_line"] == 2


def test_a_registration_of_another_files_handler_supplies_no_request(tmp_path):
    """Refused case: the registering file imports another module, so its route is not the finding's."""
    sent = []
    ctx = _registration_ctx(tmp_path, sent)
    _registration_repo(tmp_path, import_path="./routes/other")
    AgentProbe("access-control", lambda: ScriptedPlanner(_registration_steps())).run(ctx)
    assert sent == [] and not ctx.derived_requests


# ── routes resolved from the source before the agent starts (VER-008) ─────────

PAYMENT = ("export function getPaymentMethods () { return async (req, res) => res.json([]) }\n"
           "export function getPaymentMethodById () { return async (req, res) => res.json({}) }\n"
           "export function delPaymentMethodById () { return async (req, res) => res.json({}) }\n")
FILLER = "".join(f"// line {n}\n" for n in range(450))   # import and registration far apart, as in server.ts


def _far_repo(tmp_path, import_line="import * as payment from './routes/payment'\n", server="server.ts"):
    (tmp_path / "routes" / "payment.ts").write_text(PAYMENT)
    (tmp_path / server).write_text(
        import_line + FILLER
        + "app.post('/api/Cards', security.appendUserId())\n"
        "app.get('/api/Cards', security.appendUserId(), utils.asyncHandler(payment.getPaymentMethods()))\n"
        "app.put('/api/Cards/:id', security.denyAll())\n"
        "app.delete('/api/Cards/:id', security.appendUserId(), utils.asyncHandler(payment.delPaymentMethodById()))\n"
        "app.get('/api/Cards/:id', security.appendUserId(), utils.asyncHandler(payment.getPaymentMethodById()))\n")


def _resolved(ctx):
    from appsec_verifier.agent.derivation import source_registrations

    return [(r["method"], r["path"], r["source_file"], r["source_line"]) for r in source_registrations(ctx)]


def test_the_verifier_resolves_a_registration_far_below_its_import(tmp_path):
    """T-010: the import is at the top of server.ts and the registrations hundreds of lines below. A PUT whose own
    handler list names none of the finding's handlers is not credited with the next line's DELETE handler, and
    DELETE and a POST without the finding's handler are never resolved."""
    ctx = _registration_ctx(tmp_path, [])
    _far_repo(tmp_path)
    assert _resolved(ctx) == [("GET", "/api/Cards", "server.ts", 453), ("GET", "/api/Cards/:id", "server.ts", 456)]


def test_a_named_import_binds_the_handler_but_not_a_word_of_the_route(tmp_path):
    ctx = _ctx(tmp_path, lambda *a, **k: Resp())
    ctx.plan = replace(ctx.plan, instance="routes/search.ts:1", endpoints=())
    (tmp_path / "routes" / "search.ts").write_text("export function search () { return (req, res) => res.json([]) }\n")
    (tmp_path / "server.ts").write_text(
        "import { search as find } from './routes/search'\n" + FILLER
        + "app.get('/api/search', utils.asyncHandler(other()))\n"      # a word of the path, not the handler
        "app.get('/rest/products/search', utils.asyncHandler(find()))\n")
    assert _resolved(ctx) == [("GET", "/rest/products/search", "server.ts", 453)]


@pytest.mark.parametrize("change", ["other-module", "named-route", "secret-file", "no-source"])
def test_no_route_is_resolved_without_a_literal_tie_to_the_findings_file(tmp_path, change):
    """Refused cases: an import of another module with the same name, a finding whose assessment names a route,
    a registering file that holds credentials (never read), and a run without a source checkout."""
    ctx = _registration_ctx(tmp_path, [])
    if change == "other-module":
        (tmp_path / "other").mkdir()
        _far_repo(tmp_path, import_line="import * as payment from './other/payment'\n")
    elif change == "named-route":
        _far_repo(tmp_path)
        ctx.plan = replace(ctx.plan, endpoints=(Endpoint("GET", "/api/Users", None),))
    elif change == "secret-file":
        _far_repo(tmp_path, server=".env.ts")
    else:
        _far_repo(tmp_path)
        ctx.source = None
    assert _resolved(ctx) == []


def test_a_resolved_route_is_testable_from_the_first_step_and_nothing_else_is(tmp_path):
    """The agent sends the resolved request without reading or deriving anything; another route stays refused, and
    the report names where the route came from."""
    from appsec_verifier.agent.prompts import _seed

    sent = []
    ctx = _registration_ctx(tmp_path, sent)
    _far_repo(tmp_path)
    steps = [{"tool": "http_request", "args": {"path": "/api/Users/2", "role": "customer-a"}},
             {"tool": "http_request", "args": {"path": "/api/Cards/2", "role": "customer-a"}}]
    result = AgentProbe("access-control", lambda: ScriptedPlanner(steps)).run(ctx)
    assert sent == [("GET", "https://app.example.com/api/Cards/2")]
    assert "GET /api/Cards/:id (server.ts:456)" in _seed(ctx)
    assert any("resolved from the source before the test" in o and "server.ts:456" in o
               for o in result.observations)
