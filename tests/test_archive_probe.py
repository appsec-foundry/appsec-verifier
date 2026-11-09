"""Archive traversal requires a fresh escaped marker and bounded, authorized writes (VER-045)."""

from __future__ import annotations

import copy
import io
import zipfile

import httpx
import pytest
from test_agent_tools import _ctx

from appsec_verifier.agent import AgentTools, ToolError
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.proof import check_proof
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.limits import LimitExceeded
from appsec_verifier.verify import poc
from appsec_verifier.verify.probes import ProbeResult

CHECK = {"id": "zip-test", "finding_id": "T-1", "upload_path": "/upload", "field": "file",
         "extraction_directory": "/test-area/extract", "read_path": "/test-area/{marker}.txt",
         "cleanup_path": "/cleanup/{marker}"}


def setup(tmp_path, *, vulnerable=True, cleanup=True, extension="txt"):
    seen, files = [], {}

    def transport(method, url, headers, **kwargs):
        seen.append((method, url, kwargs))
        request = httpx.Request(method, url, **{k: v for k, v in kwargs.items() if k in ("files", "json")})
        if method == "POST" and url.endswith("/upload"):
            name, data, kind = kwargs["files"]["file"]
            assert name.endswith(".zip") and kind == "application/zip" and len(data) < 1024
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                assert len(archive.infolist()) == 1
                entry = archive.infolist()[0]
                assert entry.filename == "../vrftest." + extension and entry.file_size < 100
                if vulnerable:
                    files["marker"] = archive.read(entry).decode()
            return httpx.Response(201, request=request)
        if method == "POST":
            files.clear()
            return httpx.Response(200, request=request)
        return httpx.Response(200 if files else 404, text=files.get("marker", "missing"), request=request)

    ctx = _ctx(tmp_path, transport, safe=False, read_only=False)
    ctx.http._budget = ctx.budget
    ctx.plan.cls, ctx.plan.cwe = "path-traversal", "CWE-22"
    ctx.plan.endpoints = (Endpoint("POST", "/upload", None),)
    ctx.marker = ("vrf", "test")
    contract = copy.deepcopy(CHECK)
    contract["read_path"] = "/test-area/{marker}." + extension
    if not cleanup:
        contract.pop("cleanup_path")
    ctx.scope = {**ctx.scope, "archive_checks": [contract]}
    return AgentTools(ctx), seen


def test_archive_escape_has_recorded_cleanup_and_code_checked_proof(tmp_path):
    tools, seen = setup(tmp_path)
    result = tools.archive_probe(check_id="zip-test")
    assert result["escaped_marker"] is True and result["cleanup"] == "removed"
    assert result["archive_entry"] == "../vrftest.txt" and result["content"].startswith("archive-proof-")
    assert len(result["archive_sha256"]) == 64
    assert [method for method, _, _ in seen] == ["GET", "POST", "GET", "POST", "GET"]
    history = [{"tool": "archive_probe", "args": {"check_id": "zip-test"}, "result": result}]
    verdict = check_proof(tools.ctx, history, ProbeResult("confirmed", "high", "claim"), [1])
    assert verdict.verdict == "confirmed" and verdict.proof["archive"]["cleanup"] == "removed"
    assert len(tools.take_exchanges()) == 5
    with pytest.raises(ToolError, match="reconcile"):
        tools.archive_probe(check_id="zip-test")
    assert len(seen) == 5


def test_successful_upload_without_escape_is_not_proof(tmp_path):
    tools, _ = setup(tmp_path, vulnerable=False)
    result = tools.archive_probe(check_id="zip-test")
    history = [{"tool": "archive_probe", "args": {}, "result": result}]
    assert not result["escaped_marker"]
    verdict = check_proof(tools.ctx, history, ProbeResult("confirmed", "high", "claim"), [1])
    assert verdict.verdict == "inconclusive"


@pytest.mark.parametrize("fault", ["safe", "read-only", "scope-writes", "no-check", "foreign-finding",
                                   "wrong-route", "foreign-read", "privileged"])
def test_archive_probe_refuses_without_authority_before_any_request(tmp_path, fault):
    tools, seen = setup(tmp_path)
    ctx = tools.ctx
    role = None
    if fault == "safe":
        ctx.safe = True
    elif fault == "read-only":
        ctx.read_only = True
    elif fault == "scope-writes":
        ctx.scope["allow_state_change"] = False
    elif fault == "no-check":
        ctx.scope["archive_checks"] = []
    elif fault == "foreign-finding":
        ctx.scope["archive_checks"][0]["finding_id"] = "T-other"
    elif fault == "wrong-route":
        ctx.plan.endpoints = ()
    elif fault == "foreign-read":
        ctx.scope["archive_checks"][0]["read_path"] = "https://other.invalid/{marker}.txt"
    else:
        ctx.identities[0]["privileged"] = True
        role = ctx.identities[0]["role"]
    with pytest.raises(ToolError):
        tools.archive_probe(check_id="zip-test", role=role)
    assert seen == []


def test_missing_cleanup_is_visible_in_final_result(tmp_path):
    tools, _ = setup(tmp_path, cleanup=False)
    result = tools.archive_probe(check_id="zip-test")
    assert result["cleanup"] == "manual-required"
    verdict = poc.attach(tools.ctx, [], [], ProbeResult("inconclusive", "low", "stop"), [])
    assert verdict.proof["archive_attempt"]["cleanup"] == "manual-required"
    assert any("cleanup: manual-required" in note for note in verdict.observations)


def test_budget_stops_probe_and_never_repeats_an_unknown_upload(tmp_path):
    tools, seen = setup(tmp_path, cleanup=False)
    tools.ctx.budget.limits.max_requests = 1
    with pytest.raises(LimitExceeded):
        tools.archive_probe(check_id="zip-test")
    assert len(seen) == 1
    with pytest.raises(ToolError, match="reconcile"):
        tools.archive_probe(check_id="zip-test")


def test_unknown_upload_is_not_retried_even_with_a_fresh_tool_instance(tmp_path):
    tools, _ = setup(tmp_path, cleanup=False)
    send = tools.ctx.http._transport
    writes = []

    def timeout(method, url, headers, **kwargs):
        if method == "POST":
            writes.append(url)
            raise httpx.ReadTimeout("unknown write outcome")
        return send(method, url, headers, **kwargs)

    tools.ctx.http._transport = timeout
    with pytest.raises(ToolError, match="ReadTimeout"):
        tools.archive_probe(check_id="zip-test")
    assert tools.ctx.archive_attempt["cleanup"] == "manual-required"
    with pytest.raises(ToolError, match="reconcile"):
        AgentTools(tools.ctx).archive_probe(check_id="zip-test")
    assert len(writes) == 1


def test_agent_archive_result_keeps_requests_and_cleanup(tmp_path):
    tools, seen = setup(tmp_path)
    actions = [{"tool": "archive_probe", "args": {"check_id": "zip-test"}},
               {"verdict": {"verdict": "confirmed", "rationale": "Fresh marker escaped the extraction directory",
                            "proof_steps": [1]}}]

    class Planner:
        def next_step(self, ctx, history):
            return actions.pop(0)

    result = AgentProbe("path-traversal", Planner).run(tools.ctx)
    assert result.verdict == "confirmed"
    assert len(seen) == 5 and result.proof["archive_attempt"]["cleanup"] == "removed"
    assert result.poc and result.poc["steps"]


def test_existing_marker_location_prevents_upload(tmp_path):
    tools, seen = setup(tmp_path)
    tools.ctx.http._transport = lambda method, url, headers, **kwargs: (
        seen.append((method, url, kwargs)) or httpx.Response(200, text="existing",
                                                          request=httpx.Request(method, url))
    )
    with pytest.raises(ToolError, match="absent"):
        tools.archive_probe(check_id="zip-test")
    assert len(seen) == 1 and seen[0][0] == "GET"


def test_fabricated_archive_result_cannot_confirm(tmp_path):
    tools, _ = setup(tmp_path)
    history = [{"tool": "archive_probe", "args": {},
                "result": {"escaped_marker": True, "cleanup": "removed"}}]
    result = check_proof(tools.ctx, history, ProbeResult("confirmed", "high", "claim"), [1])
    assert result.verdict == "inconclusive"


def test_failed_cleanup_remains_visible_even_when_marker_escape_was_observed(tmp_path):
    tools, _ = setup(tmp_path)
    original = tools.ctx.http._transport

    def fail_cleanup(method, url, headers, **kwargs):
        if "/cleanup/" in url:
            return httpx.Response(403, request=httpx.Request(method, url))
        return original(method, url, headers, **kwargs)

    tools.ctx.http._transport = fail_cleanup
    result = tools.archive_probe(check_id="zip-test")
    assert result["escaped_marker"] and result["cleanup"] == "manual-required"


@pytest.mark.parametrize("fault", [None, "unknown-field", "missing-location", "invalid-field", "missing-marker"])
def test_archive_scope_declaration_is_strict(fault):
    from appsec_verifier.cli import _validate_scope

    check = copy.deepcopy(CHECK)
    if fault == "unknown-field":
        check["content"] = "arbitrary contents are not permitted"
    elif fault == "missing-location":
        check.pop("extraction_directory")
    elif fault == "invalid-field":
        check["field"] = "file\r\nOther: value"
    elif fault == "missing-marker":
        check["read_path"] = "/existing-file.txt"
    scope = {"schema_version": 1, "base_url": "https://app.example.com",
             "owner": {"name": "Fixture operator", "contact": "fixture@example.invalid"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-01-01T00:00:00Z"},
             "archive_checks": [check]}
    assert bool(_validate_scope(scope)) == (fault is not None)


@pytest.mark.parametrize("fault", ["other-variant", "other-field"])
def test_archive_probe_keeps_the_selected_variant_and_its_declared_field(tmp_path, fault):
    tools, seen = setup(tmp_path)
    request = {"method": "POST", "path": "/upload", "inputs": [{"location": "form", "name": "file"}]}
    if fault == "other-variant":
        request["path"] = "/other-upload"
    else:
        request["inputs"][0]["name"] = "other"
    tools.ctx.plan.verification_context = {"version": 1, "variants": [{"id": "selected", "request": request}]}
    tools.ctx.plan.variant_id = "selected"
    with pytest.raises(ToolError):
        tools.archive_probe(check_id="zip-test")
    assert seen == []


def test_markdown_marker_supports_download_routes_that_refuse_txt(tmp_path):
    tools, seen = setup(tmp_path, extension="md")
    result = tools.archive_probe(check_id="zip-test")
    assert result["escaped_marker"] and result["archive_entry"] == "../vrftest.md"
    assert seen[0][1].endswith("/vrftest.md")
