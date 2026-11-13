"""Browser request derivation remains evidence-bound and never sends traffic (VER-008, VER-043)."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_agent_probe import ScriptedPlanner
from test_agent_tools import Resp
from test_request_derivation import context, derive

from appsec_verifier.agent.client_routes import declarations
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.tools import ToolError


def client(ctx, text, *, page="/workspace/", body='<script src="/assets/profile.js"></script>', complete=True):
    ctx.plan = replace(ctx.plan, endpoints=(), instance="public/assets/profile.js:8")
    ctx.agent_history = [
        {"tool": "http_request", "args": {"path": page}, "result": {"status": 200}},
        {"tool": "read_source", "args": {"path": "public/assets/profile.js"},
         "result": {"text": text, "start_line": 1}},
    ]
    ctx.responses = {1: {"body": body, "complete": complete}}


@pytest.mark.parametrize("text", [
    "fetch('profiles?q=test')",
    "const req = new XMLHttpRequest(); req.open('GET', 'profiles?q=test', true);",
])
def test_relative_client_requests_use_the_recorded_document_not_the_script_directory(tmp_path, text):
    ctx = context(tmp_path, lambda *a, **k: pytest.fail("derivation must not send requests"))
    client(ctx, text)
    assert derive(ctx, "/workspace/profiles", evidence_step=2,
                  inputs=[{"location": "query", "name": "q"}])["accepted"]
    with pytest.raises(ToolError):
        derive(ctx, "/assets/profiles", evidence_step=2)
    with pytest.raises(ToolError):
        derive(ctx, "/workspace/profiles", evidence_step=2, inputs=[{"location": "json", "name": "q"}])
    assert ctx.budget.requests == 0


def test_literal_json_request_retains_write_permission_and_input_checks(tmp_path):
    ctx = context(tmp_path)
    client(ctx, "fetch('/profiles', {method: 'POST', body: JSON.stringify({name: value})})")
    with pytest.raises(ToolError, match="intrusive"):
        derive(ctx, "/profiles", method="POST", evidence_step=2)
    ctx.safe = ctx.read_only = False
    assert derive(ctx, "/profiles", method="POST", evidence_step=2,
                  inputs=[{"location": "json", "name": "name"}])["accepted"]
    with pytest.raises(ToolError):
        derive(ctx, "/profiles", method="POST", evidence_step=2,
               inputs=[{"location": "json", "name": "admin"}])


@pytest.mark.parametrize("body,complete", [
    ('<script src="/assets/unrelated.js"></script>', True),
    ('<script src="https://elsewhere.test/assets/profile.js"></script>', True),
    ('<base href="https://elsewhere.test/"><script src="/assets/profile.js"></script>', True),
    ('<script src="/assets/profile.js"></script>', False),
])
def test_relative_requests_need_complete_related_document_evidence(tmp_path, body, complete):
    ctx = context(tmp_path)
    client(ctx, "fetch('profiles')", body=body, complete=complete)
    with pytest.raises(ToolError):
        derive(ctx, "/workspace/profiles", evidence_step=2)


def test_a_document_base_is_respected_and_conflicting_documents_stay_unresolved(tmp_path):
    ctx = context(tmp_path)
    client(ctx, "fetch('profiles')",
           body='<base href="/api/"><script src="/assets/profile.js"></script>')
    assert derive(ctx, "/api/profiles", evidence_step=2)["accepted"]
    ctx.derived_requests = []
    ctx.inferred_route_roots = []
    ctx.agent_history.append({"tool": "http_request", "args": {"path": "/other/"}, "result": {"status": 200}})
    ctx.responses[3] = {"body": '<script src="/assets/profile.js"></script>', "complete": True}
    with pytest.raises(ToolError):
        derive(ctx, "/api/profiles", evidence_step=2)


@pytest.mark.parametrize("text", [
    "// fetch('/profiles')", "/* fetch('/profiles') */", "const example = `fetch('/profiles')`",
    'const example = "fetch(\'/profiles\')"', "fetch(prefix + '/profiles')",
    "fetch('/profiles', options)", "fetch('/profiles', {...options})",
    "fetch('/profiles', {method: selectedMethod})", "fetch('/profiles', {method: 'POST', ...options})",
    "fetch('/profiles', {method: 'GET', method: 'POST'})", "object.open('GET', '/profiles')",
    "fetch('/profiles', {__proto__: {method: 'POST'}})",
    "service.fetch('/profiles')", "fetch('/profiles', {method: 'DELETE'})",
])
def test_dynamic_or_non_request_text_supplies_no_candidate(text):
    assert declarations(text) == []


@pytest.mark.parametrize("literal", [
    "https://elsewhere.test/profiles", "//elsewhere.test/profiles", "/blocked/profiles",
])
def test_client_requests_do_not_expand_the_operator_scope(tmp_path, literal):
    ctx = context(tmp_path)
    ctx.guard.scope["deny_paths"] = ["/blocked"]
    client(ctx, f"fetch('{literal}')")
    with pytest.raises(ToolError):
        derive(ctx, literal, evidence_step=2)
    assert not ctx.derived_requests


def test_another_source_file_or_route_family_supplies_no_authority(tmp_path):
    ctx = context(tmp_path)
    client(ctx, "fetch('/profiles')")
    ctx.agent_history[1]["args"]["path"] = "public/assets/unrelated.js"
    with pytest.raises(ToolError, match="source"):
        derive(ctx, "/profiles", evidence_step=2)
    ctx.agent_history[1]["args"]["path"] = "public/assets/profile.js"
    ctx.plan = replace(ctx.plan, endpoints=context(tmp_path).plan.endpoints)
    with pytest.raises(ToolError):
        derive(ctx, "/profiles", evidence_step=2)


def test_browser_source_can_supply_a_missing_request_and_reach_a_checked_proof(tmp_path):
    sent = []

    def target(method, url, headers, **kwargs):
        sent.append(url)
        if url.endswith("/workspace/"):
            return Resp(200, '<script src="/assets/profile.js"></script>')
        assert url.endswith("/workspace/continue")
        response = Resp(302, "")
        response.headers = {"Location": kwargs["params"]["destination"]}
        return response

    ctx = context(tmp_path, target)
    ctx.plan = replace(ctx.plan, endpoints=(), instance="public/assets/profile.js:2")
    script = tmp_path / "public/assets/profile.js"
    script.parent.mkdir(parents=True)
    script.write_text("fetch('continue?destination=local');\n")
    actions = [
        {"tool": "http_request", "args": {"path": "/workspace/", "prerequisite": True}},
        {"tool": "read_source", "args": {"path": "public/assets/profile.js"}},
        {"tool": "derive_request", "args": {"evidence_step": 2, "method": "GET", "path": "/workspace/continue",
         "inputs": [{"location": "query", "name": "destination"}], "reason": "The recorded script calls this route"}},
        {"tool": "http_request", "args": {"path": "/workspace/continue",
         "params": {"destination": "https://harmlessmarker.invalid/"}}},
        {"verdict": {"verdict": "confirmed", "rationale": "The target redirects to the generated marker host",
                     "proof_steps": [4]}},
    ]
    result = AgentProbe("open-redirect", lambda: ScriptedPlanner(actions), max_steps=6).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert len(sent) == 2 and all(url.startswith(ctx.target_base) for url in sent)


@pytest.mark.parametrize("text", [
    "const base = '/profiles/'; fetch(base + id);",
    "fetch(`/profiles/${id}`);",
])
def test_dynamic_record_segment_keeps_a_fixed_resource_prefix(tmp_path, text):
    ctx = context(tmp_path)
    client(ctx, text)
    assert derive(ctx, "/profiles/17", evidence_step=2, inputs=[{"location": "path", "name": "id"}])["accepted"]
    with pytest.raises(ToolError):
        derive(ctx, "/other/17", evidence_step=2)
    with pytest.raises(ToolError):
        derive(ctx, "/profiles/17/admin", evidence_step=2)


@pytest.mark.parametrize("text", [
    "fetch(`${host}/profiles`)", "fetch(`/profiles/${id + 1}`)",
    "fetch(`/profiles/name-${id}`)", "fetch(`/profiles?id=${id}`)",
    "const base = '/profiles/'; const base = '/other/'; fetch(base + id)",
])
def test_unknown_or_ambiguous_dynamic_resource_stays_unresolved(text):
    assert declarations(text) == []


def test_requests_in_the_evidenced_function_can_form_a_workflow_but_other_functions_cannot(tmp_path):
    ctx = context(tmp_path)
    text = """function profile() {
    fetch('/profile/save', {method: 'POST', body: JSON.stringify({name: value})});
    fetch('/profile/read');
    output.innerHTML = value;
}
function unrelated() {
    fetch('/admin/remove');
}
"""
    client(ctx, text)
    ctx.plan = replace(ctx.plan, instance="public/assets/profile.js:4")
    ctx.safe = ctx.read_only = False
    assert derive(ctx, "/profile/save", method="POST", evidence_step=2)["accepted"]
    assert derive(ctx, "/profile/read", evidence_step=2)["accepted"]
    with pytest.raises(ToolError):
        derive(ctx, "/admin/remove", evidence_step=2)


def test_literal_include_uses_recorded_parent_form_not_the_fragment_url(tmp_path):
    ctx = context(tmp_path)
    ctx.plan = replace(ctx.plan, endpoints=(), instance="public/fragments/profile.php:2")
    ctx.agent_history = [
        {"tool": "read_source", "args": {"path": "public/fragments/profile.php"},
         "result": {"text": "<?php echo $_GET['name'];", "start_line": 1}},
        {"tool": "read_source", "args": {"path": "public/profile.php"},
         "result": {"text": "<?php\nrequire __DIR__ . '/fragments/profile.php';", "start_line": 1}},
        {"tool": "http_request", "args": {"path": "/profile.php"}, "result": {"status": 200}},
    ]
    ctx.responses = {3: {"complete": True, "body": '<form><input name="name"></form>'}}
    assert derive(ctx, "/profile.php", evidence_step=2, inputs=[{"location": "query", "name": "name"}])["accepted"]
    ctx.agent_history[1]["result"]["text"] = "<?php\nrequire __DIR__ . '/unrelated.php';"
    with pytest.raises(ToolError):
        derive(ctx, "/profile.php", evidence_step=2)


@pytest.mark.parametrize("executes", [True, False])
def test_stored_workflow_uses_derived_creation_then_read_and_browser_proof(tmp_path, executes):
    from types import SimpleNamespace
    from urllib.parse import urlsplit

    from appsec_verifier.endpoints import Endpoint

    stored, sent = {}, []

    def target(method, url, headers, **kwargs):
        path = urlsplit(url).path
        sent.append((method, path))
        if method == "POST":
            assert path == "/profile/save"
            stored.update(kwargs["json"])
            return Resp(201, '{"id":17}')
        assert path == "/profile/view"
        return Resp(200, stored.get("name", ""))

    ctx = context(tmp_path, target, safe=False)
    ctx.plan = replace(ctx.plan, cls="xss", cwe="CWE-79", instance="public/profile.js:4",
                       endpoints=(Endpoint("GET", "/profile/view", None),))
    script = tmp_path / "public/profile.js"
    script.parent.mkdir()
    script.write_text("function profile() {\n"
                      "    fetch('/profile/save', {method: 'POST', body: JSON.stringify({name: value})});\n"
                      "    fetch('/profile/view');\n    output.innerHTML = value;\n}\n")

    def browser(url, **kwargs):
        # Stand in for Chrome's execution observation, after a real guarded read of the stateful fake target.
        reply = ctx.http.request("GET", url)
        assert "harmless" in reply.text and stored
        return {"status": 200, "executed": executes, "context_verified": True}

    ctx.browser = SimpleNamespace(check=browser)
    actions = [
        {"tool": "read_source", "args": {"path": "public/profile.js"}},
        {"tool": "derive_request", "args": {"evidence_step": 1, "method": "POST", "path": "/profile/save",
         "inputs": [{"location": "json", "name": "name"}], "reason": "The sink function saves then reads the profile"}},
        {"tool": "http_request", "args": {"method": "POST", "path": "/profile/save",
         "json": {"name": "<script>alert('harmless'.concat('marker'))</script>"}}},
        {"tool": "http_request", "args": {"path": "/profile/view"}},
        {"tool": "browser_check", "args": {"path": "/profile/view"}},
        {"verdict": {"verdict": "confirmed", "rationale": "The stored marker executes", "proof_steps": [5]}},
    ]
    result = AgentProbe("xss", lambda: ScriptedPlanner(actions), max_steps=7).run(ctx)
    assert result.verdict == ("confirmed" if executes else "inconclusive"), result.rationale
    assert sent == [("POST", "/profile/save"), ("GET", "/profile/view"), ("GET", "/profile/view")]
