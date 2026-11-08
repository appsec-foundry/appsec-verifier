"""Confirmed UI observations keep identity, proof and request boundaries (VER-035)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from test_poc import Resp, _ctx

from appsec_verifier.agent.tools import AgentTools
from appsec_verifier.verify.browser_evidence import capture_application
from appsec_verifier.verify.poc import capture, entry
from appsec_verifier.verify.probes import ProbeResult


def setup_capture(tmp_path, *, verdict="confirmed", value="bob@shop.test", step=1):
    calls = []
    raw = capture(Resp(), method="GET", url="https://shop.example.com/rest/basket/2")
    recorded = entry(raw, role="customer-a")

    def check(url, **kw):
        calls.append((url, kw))
        return {"status": 200, "_exchanges": [raw], "evidence": [
            {"kind": "screenshot", "path": "evidence/app.png", "presentation": "application"}]}

    browser = SimpleNamespace(screenshots={"access-control"}, check=check)
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), browser=browser)
    tools = AgentTools(ctx)
    history = [{"tool": "http_request", "args": {"path": "/rest/basket/2", "role": "customer-a"},
                "result": {"status": 200}}]
    sent = [{"step": 1, "tool": "http_request", "entries": [recorded]}]
    result = ProbeResult(verdict, proof={"checked": True})
    capture_application(ctx, tools, history, sent, result,
                        {"path": "/#/basket", "step": step, "value": value}, [1])
    return ctx, calls, history, sent, result


def test_application_capture_uses_cited_identity_read_only_and_records_requests(tmp_path):
    ctx, calls, history, sent, result = setup_capture(tmp_path)
    assert len(calls) == 1
    assert calls[0][1]["safe"] is True and calls[0][1]["role"] == "customer-a"
    assert calls[0][1]["identity_headers"] == ctx.sessions.headers_for("customer-a")
    assert calls[0][1]["observation"]["resource_url"].endswith("/rest/basket/2")
    assert len(history) == len(sent) == 2
    assert sent[-1]["entries"][0]["_role"] == "customer-a"
    assert result.verdict == "confirmed" and result.proof == {"checked": True}


@pytest.mark.parametrize("kwargs", [{"verdict": "inconclusive"}, {"value": "invented-effect"}, {"step": 99}])
def test_invalid_proof_or_unconfirmed_result_never_starts_browser(tmp_path, kwargs):
    _, calls, history, sent, result = setup_capture(tmp_path, **kwargs)
    assert calls == [] and not result.evidence
    assert len(history) == len(sent) == 1


@pytest.mark.parametrize("proposal", [
    {"path": "/ui", "step": 1, "value": "known", "script": "fetch('/write')"},
    {"path": "/ui", "step": 1, "value": "known", "role": "admin"},
    {"path": "/ui", "step": True, "value": "known"},
    {"path": "/ui", "step": 1, "value": "x" * 201},
])
def test_browser_evidence_schema_refuses_executable_or_identity_overrides(proposal):
    from appsec_verifier.agent.steps import check_action

    parsed = check_action({"verdict": {"verdict": "confirmed", "rationale": "effect observed",
                                       "browser_evidence": proposal}})
    assert parsed["verdict"]["verdict"] == "inconclusive"
    assert "browser_evidence" not in parsed["verdict"]
