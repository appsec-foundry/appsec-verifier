"""Mask or omit credentials before capture; preserve technical proof (VER-016/022/035)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_verifier.tools.browser import ProofBrowser
from appsec_verifier.tools.browser_mask import mask_credentials
from appsec_verifier.verify import poc
from appsec_verifier.verify.probes import ProbeResult
from appsec_verifier.verify.report import _poc_markdown

SECRET = "fixture-token-1234"
URL = "https://app.example.test/page"
MARKER = ("vrf1234", "5678")


def redact(value):
    return json.loads(json.dumps(value).replace(SECRET, "[redacted]"))


@pytest.fixture
def capture(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(Error=RuntimeError))
    browser = ProofBrowser(None, tmp_path / "evidence")
    browser.redact = redact
    browser.private_text = lambda text: SECRET in text or "marker-file-value" in text
    marked = {"marks": 1, "hidden": [], "crop": None, "carrier": "<img>", "text": "ordinary page"}
    monkeypatch.setattr(browser, "_mark", lambda *a, **k: marked)
    # DOM masking is exercised against Chrome in test_browser_live; these cases check the persistence gate.
    monkeypatch.setattr("appsec_verifier.tools.browser.mask_credentials", lambda *a, **k: (False, None))
    calls = []

    def screenshot(**kwargs):
        calls.append(kwargs)
        if "path" in kwargs:
            Path(kwargs["path"]).write_bytes(b"fake-png")
        return b"fake-png"

    page = SimpleNamespace(screenshot=screenshot)
    monkeypatch.setattr("appsec_verifier.tools.browser.capture_masked",
                        lambda page, *a, **k: (screenshot(), marked["text"]))

    def framed(**kwargs):
        kwargs["path"].write_bytes(b"framed-fake-png")
        return kwargs["path"], None

    monkeypatch.setattr(browser, "_shoot_recorded", framed)
    return browser, marked, page, calls


def save(browser, page, url=URL):
    return browser._save(page, "T-1", url, 200, [("alert", "".join(MARKER))], MARKER, None)


@pytest.mark.parametrize("location", ["page", "missing-text", "no-check", "failed-check"])
def test_xss_keeps_execution_record_but_never_captures_unsafe_image(capture, location):
    browser, marked, page, calls = capture
    url = URL
    if location == "page":
        marked["text"] += SECRET
    elif location == "missing-text":
        marked["text"] = None
    elif location == "no-check":
        browser.redact = None
    else:
        browser.redact = lambda value: 1 / 0
    entries = save(browser, page, url)
    assert calls == [] and list(browser._dir.glob("*.png")) == []
    assert [e["kind"] for e in entries] == ["browser-event"]
    assert entries[0]["screenshot_omitted"]
    record = next(browser._dir.glob("*.json")).read_text()
    assert SECRET not in record
    assert json.loads(record)["executed_via"] == ["alert"]


def test_captions_are_masked_before_rendering_and_marked_in_evidence(capture, monkeypatch):
    browser, marked, page, calls = capture
    marked["carrier"] = '<img title="' + SECRET + '">'
    frames = []

    def framed(**kwargs):
        frames.append(kwargs["body"])
        kwargs["path"].write_bytes(b"fake-png")
        return kwargs["path"], None

    monkeypatch.setattr(browser, "_shoot_recorded", framed)
    entries = save(browser, page, URL + "?token=" + SECRET)
    assert calls and len(frames) == 1
    assert SECRET not in frames[0] and "[redacted]" in frames[0]
    assert "Known credentials masked" in frames[0]
    image = next(e for e in entries if e["kind"] == "screenshot")
    assert image["credential_masked"] and image["redacted"] and image["reviewable"]


def test_failed_framing_does_not_save_an_unlabelled_fallback(capture, monkeypatch):
    browser, _, page, _ = capture
    monkeypatch.setattr(browser, "_shoot_recorded", lambda **k: (None, None))
    [event] = save(browser, page)
    assert "labelled" in event["screenshot_omitted"]
    assert not list(browser._dir.glob("*.png"))


@pytest.mark.parametrize("case", ["missing-redactor", "freeze-failed", "protected-value"])
def test_masking_failures_never_allow_capture(case):
    page = SimpleNamespace()  # cannot freeze; no screenshot is attempted
    masked, error = mask_credentials(page, None if case == "missing-redactor" else redact,
                                     protected=[SECRET] if case == "protected-value" else [])
    assert not masked and error and SECRET not in error
    if case == "protected-value":
        assert "decisive observation" in error


@pytest.mark.parametrize("text, reviewable", [("ordinary page", True), ("marker-file-value", False)])
def test_normal_screenshot_and_local_marker_evidence_remain(capture, text, reviewable):
    browser, marked, page, calls = capture
    marked["text"] = text
    entries = save(browser, page)
    assert len(calls) == 1
    image = next(e for e in entries if e["kind"] == "screenshot")
    assert image["reviewable"] is reviewable
    assert next(browser._dir.glob("*.png")).read_bytes() == b"framed-fake-png"


@pytest.mark.parametrize("secret", [False, True])
def test_live_application_observation_checks_before_writing(capture, monkeypatch, secret):
    browser, marked, page, calls = capture
    marked["text"] = SECRET if secret else "visible proof"
    context = SimpleNamespace(route_web_socket=lambda *a: None, expose_binding=lambda *a: None,
                              add_init_script=lambda *a: None, close=lambda: None, new_page=lambda: page)
    context.route = lambda pattern, handler: setattr(context, "handler", handler)
    page.url = URL
    page.on = lambda *a: None
    page.wait_for_timeout = lambda *a: None

    def goto(url, **kwargs):
        request = SimpleNamespace(method="GET", url=url, headers={}, post_data_buffer=None,
                                  resource_type="document", is_navigation_request=lambda: True,
                                  frame=SimpleNamespace(parent_frame=None))
        route = SimpleNamespace(fulfill=lambda **kw: None, abort=lambda *a: pytest.fail("unexpected abort"))
        context.handler(route, request)
        return SimpleNamespace(status=200)

    page.goto = goto
    browser._http = SimpleNamespace(request=lambda *a, **kw: SimpleNamespace(
        status_code=200, headers={"content-type": "text/html"}, content=b"<p>visible proof</p>"))
    monkeypatch.setattr(browser, "_ensure", lambda: SimpleNamespace(new_context=lambda **kw: context))
    result = browser.check(URL, identity_headers={}, target_base=URL, marker=MARKER, finding_id="T-1",
                           wait_ms=0, safe=True, observation={"resource_url": URL, "step": 1,
                                                             "values": ["visible proof"]})
    assert bool(result["evidence"]) is not secret
    assert bool(calls) is not secret
    assert bool(list(browser._dir.glob("*.png"))) is not secret
    assert result["_exchanges"]  # omitting the image does not discard its HTTP evidence
    if secret:
        assert "credential" in result["error"] and SECRET not in result["error"]


def test_omission_reason_is_kept_without_changing_the_verdict():
    reason = "a credential was detected in the screenshot text"
    result = ProbeResult("confirmed", proof={"executed": True})
    history = [{"tool": "browser_check", "result": {"executed": True, "screenshot_error": reason}}]
    poc._attach(SimpleNamespace(sessions=None), history, [], result, [1])
    assert result.verdict == "confirmed" and result.proof == {"executed": True}
    assert result.observations == ["Application screenshot unavailable: " + reason + "."]


def test_report_labels_source_identity_steps_and_masking():
    image = {"kind": "screenshot", "presentation": "application", "path": "evidence/proof.png",
             "source": "live-browser", "role": "owner", "credential_masked": True, "executed_via": ["alert"]}
    result = ProbeResult("confirmed", evidence=[image])
    history = [{"tool": "browser_check", "result": {"executed": True, "evidence": [dict(image)]}}]
    poc._attach(SimpleNamespace(sessions=None), history, [], result, [1])
    text = "\n".join(_poc_markdown({"evidence": result.evidence}))
    assert "Application browser capture" in text and "View as owner" in text
    assert "recorded step 1" in text and "Dialog drawn from the recorded execution event" in text
    assert "Known credentials masked; each placeholder names its account and kind." in text
    assert result.verdict == "confirmed"
    image.update(source="recorded-html", executed_via=[])
    text = "\n".join(_poc_markdown({"evidence": [image]}))
    assert "Rendered from a recorded response" in text and "Dialog drawn" not in text
