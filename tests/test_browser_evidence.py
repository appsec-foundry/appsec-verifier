"""Confirmed UI observations keep identity, proof and request boundaries (VER-035)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from test_poc import Resp, _ctx

from appsec_verifier.agent.tools import AgentTools
from appsec_verifier.verify.browser_evidence import attach_explanation, capture_application
from appsec_verifier.verify.poc import capture, entry
from appsec_verifier.verify.probes import ProbeResult
from appsec_verifier.verify.report import to_markdown


def setup_capture(tmp_path, *, verdict="confirmed", values=("bob@shop.test",), step=1, role=None,
                  cls="access-control"):
    calls = []
    raw = capture(Resp(), method="GET", url="https://shop.example.com/rest/basket/2")
    recorded = entry(raw, role="customer-a")

    def check(url, **kw):
        calls.append((url, kw))
        return {"status": 200, "_exchanges": [raw], "evidence": [
            {"kind": "screenshot", "path": "evidence/app.png", "presentation": "application"}]}

    browser = SimpleNamespace(screenshots={"access-control", "injection"}, check=check)
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), cls=cls, browser=browser)
    tools = AgentTools(ctx)
    history = [{"tool": "http_request", "args": {"path": "/rest/basket/2", "role": "customer-a"},
                "result": {"status": 200}}]
    sent = [{"step": 1, "tool": "http_request", "entries": [recorded]}]
    result = ProbeResult(verdict, proof={"checked": True})
    proposal = {"path": "/#/basket", "step": step, "values": list(values), **({"role": role} if role else {})}
    capture_application(ctx, tools, history, sent, result, proposal, [1])
    return ctx, calls, history, sent, result


def test_application_capture_uses_cited_identity_read_only_and_records_requests(tmp_path):
    ctx, calls, history, sent, result = setup_capture(tmp_path)
    assert len(calls) == 1
    assert calls[0][1]["safe"] is True and calls[0][1]["role"] == "customer-a"
    assert calls[0][1]["identity_headers"] == ctx.sessions.headers_for("customer-a")
    assert calls[0][1]["observation"]["resource_url"].endswith("/rest/basket/2")
    assert calls[0][1]["observation"]["values"] == ["bob@shop.test"]
    assert len(history) == len(sent) == 2
    assert sent[-1]["entries"][0]["_role"] == "customer-a"
    assert result.verdict == "confirmed" and result.proof == {"checked": True}


def test_the_agent_may_pick_another_identity_of_the_run_and_an_injection_page(tmp_path):
    """VER-035: the agent picks page, identity and up to three values; injection effects can be shown too."""
    ctx, calls, _, _, result = setup_capture(tmp_path, role="customer-b", values=("bob@shop.test", '"UserId":2'),
                                             cls="injection")
    assert calls[0][1]["role"] == "customer-b"
    assert calls[0][1]["identity_headers"] == ctx.sessions.headers_for("customer-b")
    assert calls[0][1]["observation"]["values"] == ["bob@shop.test", '"UserId":2']
    assert [e["path"] for e in result.evidence] == ["evidence/app.png"]


@pytest.mark.parametrize("kwargs", [{"verdict": "inconclusive"}, {"values": ("invented-effect",)},
                                    {"values": ("bob@shop.test", "invented-effect")}, {"step": 99},
                                    {"role": "admin"}])
def test_invalid_proof_identity_or_unconfirmed_result_never_starts_browser(tmp_path, kwargs):
    _, calls, history, sent, result = setup_capture(tmp_path, **kwargs)
    assert calls == [] and not result.evidence
    assert len(history) == len(sent) == 1


@pytest.mark.parametrize("cls", ["xss", "path-traversal", "session", "ssrf", "open-redirect"])
def test_classes_without_a_page_effect_never_open_one(tmp_path, cls):
    _, calls, _, _, result = setup_capture(tmp_path, cls=cls)
    assert calls == [] and any("existing proof capture" in o for o in result.observations)


@pytest.mark.parametrize("proposal", [
    {"path": "/ui", "step": 1, "values": ["known"], "script": "fetch('/write')"},
    {"path": "/ui", "step": True, "values": ["known"]},
    {"path": "/ui", "step": 1, "values": ["x" * 201]},
    {"path": "/ui", "step": 1, "values": ["a1a", "b2b", "c3c", "d4d"]},
    {"path": "/ui", "step": 1, "values": []},
    {"path": "/ui", "step": 1, "value": "known"},
])
def test_browser_evidence_schema_refuses_executable_or_unbounded_proposals(proposal):
    from appsec_verifier.agent.steps import check_action

    parsed = check_action({"verdict": {"verdict": "confirmed", "rationale": "effect observed",
                                       "browser_evidence": proposal}})
    assert parsed["verdict"]["verdict"] == "inconclusive"
    assert "browser_evidence" not in parsed["verdict"]


def test_the_explanation_leads_the_report_labelled_as_the_agents_and_stays_text(tmp_path):
    ctx = _ctx(tmp_path, lambda *a, **k: Resp())
    result = ProbeResult("confirmed", evidence=[
        {"kind": "exchange", "path": "evidence/x.json"},
        {"kind": "screenshot", "path": "evidence/T-001-xss-1.png", "presentation": "application"},
        {"kind": "screenshot", "path": "evidence/T-001-application-1.png", "presentation": "application"}])
    attach_explanation(ctx, result, "The search page runs the injected img onerror handler.\n```\n# heading")
    first, second = result.evidence[1], result.evidence[2]
    assert first["explanation"].startswith("The search page runs") and "explanation" not in second
    markdown = to_markdown({"meta": {}, "results": [{"result_id": "VF-001", "verdict": "confirmed",
                                                     "evidence": result.evidence}]})
    assert "Test agent's explanation: The search page runs the injected img onerror handler." in markdown
    assert "\n# heading" not in markdown           # fenced and on one line: no heading, no closed fence


def test_another_page_replaces_only_the_live_screenshot_and_joins_the_har(tmp_path):
    """VER-042: one more read-only observation under the same checks; recorded HTML and HTTP images stay."""
    from appsec_verifier.verify.browser_evidence import recapture

    ctx, calls, history, sent, result = setup_capture(tmp_path)
    old = {"kind": "screenshot", "path": "evidence/old.png", "presentation": "application", "source": "live-browser"}
    kept = {"kind": "screenshot", "path": "evidence/T-001-access-control-1.png", "presentation": "application",
            "source": "recorded-html"}
    result.evidence[:] = [old, kept, {"kind": "har", "path": "evidence/stale.har"}]
    assert recapture(ctx, AgentTools(ctx), history, sent, result, [1],
                     {"path": "/#/profile", "step": 1, "values": ["bob@shop.test"]}) is True
    assert calls[-1][0].endswith("/#/profile") and calls[-1][1]["safe"] is True
    paths = [e["path"] for e in result.evidence]
    assert paths[0] == "evidence/app.png" and "evidence/old.png" not in paths and kept["path"] in paths
    assert [e["path"] for e in result.evidence if e["kind"] == "har"] == ["evidence/T-001-poc.har"]
    assert (tmp_path / "evidence" / "T-001-poc.har").is_file()
    assert recapture(ctx, AgentTools(ctx), history, sent, result, [1],
                     {"path": "/#/x", "step": 1, "values": ["invented"]}) is False   # checks hold: no browser


@pytest.mark.parametrize("verdict, evidence, text", [
    ("inconclusive", [{"kind": "screenshot", "path": "evidence/a.png", "presentation": "application"}], "x" * 20),
    ("confirmed", [{"kind": "screenshot", "path": "evidence/T-001-exchange-1.png"}], "x" * 20),
    ("confirmed", [{"kind": "screenshot", "path": "evidence/a.png", "presentation": "application"}], "   "),
])
def test_no_explanation_without_a_confirmed_application_screenshot(tmp_path, verdict, evidence, text):
    result = ProbeResult(verdict, evidence=evidence)
    attach_explanation(_ctx(tmp_path, lambda *a, **k: Resp()), result, text)
    assert all("explanation" not in e for e in result.evidence)
