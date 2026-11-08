"""XSS proof browser against real Google Chrome (VER-009, VER-018, VER-022).

Opt-in: needs `appsec-verifier[browser]`, Google Chrome, and
APPSEC_VERIFIER_BROWSER_TESTS=1. No network is used: the target is a fake
transport behind the GuardedHttpClient, and every request Chrome makes must go
through it."""

from __future__ import annotations

import html
import os
import signal
import socket
import stat
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlparse

import httpx
import pytest

pytest.importorskip("playwright.sync_api")
if os.environ.get("APPSEC_VERIFIER_BROWSER_TESTS") != "1":
    pytest.skip("set APPSEC_VERIFIER_BROWSER_TESTS=1 to start Google Chrome", allow_module_level=True)

from appsec_verifier.limits import Limits, RunBudget  # noqa: E402
from appsec_verifier.scope import ScopeGuard  # noqa: E402
from appsec_verifier.tools import GuardedHttpClient  # noqa: E402
from appsec_verifier.tools.browser import SCREENSHOT_NOTE, ProofBrowser, marker_expression  # noqa: E402

SCOPE = {"base_url": "https://shop.example.com", "hosts": ["shop.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}
BASE = SCOPE["base_url"]
MARKER = ("vrf1a2b3c4d", "5e6f7a8b")


class Target:
    """A tiny vulnerable app: /reflect echoes q unencoded, /safe encodes it,
    /echo passes q to alert() as text, /ext loads an out-of-scope script,
    /webrtc sends STUN over UDP to 127.0.0.1:<port>."""

    def __init__(self):
        self.seen = []

    def __call__(self, method, url, headers, **kw):
        self.seen.append(url)
        parsed = urlparse(url)
        if parsed.path == "/hold":                   # a long poll: the server holds the answer for 25 s
            time.sleep(min(25, kw.get("timeout") or 25))
            raise httpx.ReadTimeout("held")
        q = parse_qs(parsed.query).get("q", [""])[0]
        pages = {
            "/reflect": f"<html><body><p>Results for {q}</p></body></html>",
            "/safe": f"<html><body><p>Results for {html.escape(q)}</p></body></html>",
            "/echo": "<html><body><script>alert(new URLSearchParams(location.search).get('q'))</script></body></html>",
            "/ext": '<html><body><script src="https://evil.example.net/x.js"></script></body></html>',
            "/live": "<html><body><script>new WebSocket('wss://shop.example.com/socket')</script>"
                     f"<p>Results for {q}</p></body></html>",
            "/poll": "<html><body><script>fetch('/hold'); addEventListener('load', () => fetch('/hold'))</script>"
                     f"<p>Results for {q}</p></body></html>",
            "/spin": f"<html><body><p>Results for {q}</p><script>while (true) {{}}</script></body></html>",
            "/dialog": f"<html><body><p>Results for {q}</p><div id=welcome style='position:fixed;inset:0;"
                       "z-index:10;background:#333;color:#fff'>Welcome!</div></body></html>",
            "/webrtc": "<html><body><script>const port = new URLSearchParams(location.search).get('port');"
                       "const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:127.0.0.1:' + port}]});"
                       "pc.createDataChannel('x'); pc.createOffer().then(o => pc.setLocalDescription(o));"
                       "</script></body></html>",
        }
        body = pages.get(parsed.path, "not found")
        return SimpleNamespace(status_code=200 if parsed.path in pages else 404,
                               headers={"content-type": "text/html"}, content=body.encode())


@pytest.fixture
def browser(tmp_path):
    target = Target()
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), target)
    b = ProofBrowser(http, tmp_path / "evidence")
    yield b, target, tmp_path
    b.close()


def _check(b, path, finding="T-1"):
    return b.check(BASE + path, identity_headers={}, target_base=BASE, marker=MARKER, finding_id=finding,
                   wait_ms=300, safe=True)


def test_executed_marker_is_proven_with_owner_only_evidence(browser):
    b, _, tmp = browser
    payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>"
    result = _check(b, "/reflect?q=" + quote(payload, safe=""))
    assert result["executed"] is True
    kinds = {e["kind"]: e for e in result["evidence"]}
    shot = tmp / kinds["screenshot"]["path"]
    assert shot.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert stat.S_IMODE(shot.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp / "evidence").stat().st_mode) == 0o700


def test_encoded_reflection_is_not_execution(browser):
    b, _, _ = browser
    result = _check(b, "/safe?q=" + quote(f"<script>alert({marker_expression(MARKER)})</script>", safe=""))
    assert result["executed"] is False and "evidence" not in result


def test_echoed_payload_text_is_not_execution(browser):
    b, _, _ = browser
    result = _check(b, "/echo?q=" + quote(marker_expression(MARKER), safe=""))
    assert result["executed"] is False and result["dialogs"] == [{"kind": "alert", "is_marker": False}]


def test_out_of_scope_subresource_is_blocked_before_contact(browser):
    b, target, _ = browser
    result = _check(b, "/ext")
    assert any("evil.example.net" in x["url"] for x in result["blocked"])
    assert all("evil.example.net" not in url for url in target.seen)


def test_out_of_scope_navigation_is_blocked(browser):
    b, target, _ = browser
    result = b.check("https://evil.example.net/", identity_headers={}, target_base=BASE, marker=MARKER,
                     finding_id="T-1", wait_ms=0, safe=True)
    assert result["executed"] is False and result.get("error") and target.seen == []


def test_a_page_that_opens_a_websocket_is_checked_without_hanging(browser):
    """A WebSocket handler that calls Playwright synchronously spins forever on its event loop;
    the check must come back in seconds, with the proof intact."""
    b, _, _ = browser
    fired = []

    def hung(signum, frame):
        fired.append(signum)
        raise TimeoutError("browser check hangs")

    previous = signal.signal(signal.SIGALRM, hung)
    signal.alarm(20)
    try:
        payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>"
        result = _check(b, "/live?q=" + quote(payload, safe=""))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert not fired and result["executed"] is True


def test_requests_the_server_holds_open_do_not_hold_up_the_check(browser):
    """A long poll before load is cut after a few seconds; one sent during the wait ends with the wait."""
    b, _, _ = browser
    payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>"
    started = time.monotonic()
    result = _check(b, "/poll?q=" + quote(payload, safe=""))
    assert time.monotonic() - started < 9
    assert result["executed"] is True
    assert any(x["url"].endswith("/hold") and "ReadTimeout" in x["reason"] for x in result["blocked"])


def test_a_page_script_that_never_returns_ends_the_check_with_the_proof_kept(browser, monkeypatch):
    """The page never reaches load and does not answer the marking or the screenshot; each has a timeout
    (shortened here), and the event record of the executed marker is kept."""
    from appsec_verifier.tools import browser as browser_module

    monkeypatch.setattr(browser_module, "NAVIGATION_TIMEOUT_MS", 2000)
    monkeypatch.setattr(browser_module, "EVIDENCE_TIMEOUT_MS", 1000)
    b, _, _ = browser
    payload = f"<script>alert({marker_expression(MARKER)})</script>"
    started = time.monotonic()
    result = _check(b, "/spin?q=" + quote(payload, safe=""))
    assert time.monotonic() - started < 10
    assert result["executed"] is True and [e["kind"] for e in result["evidence"]] == ["browser-event"]


def test_udp_from_the_page_never_leaves_chrome(browser):
    """WebRTC/STUN is UDP, which the request interception never sees; only the
    network namespace keeps it in (VER-018). Without it this listener gets packets."""
    b, _, _ = browser
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    received = 0
    try:
        result = b.check(BASE + f"/webrtc?port={sock.getsockname()[1]}", identity_headers={}, target_base=BASE,
                         marker=MARKER, finding_id="T-1", wait_ms=3000, safe=True)
        assert result["status"] == 200
        while True:
            try:
                sock.recvfrom(2048)
                received += 1
            except OSError:          # timeout: nothing (more) arrived
                break
    finally:
        sock.close()
    assert received == 0


def test_screenshot_marks_the_payload_and_names_the_proof(browser):
    """VER-035: a caption and an outline on the element that carries the payload."""
    import json

    b, _, tmp = browser
    payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>"
    result = b.check(BASE + "/reflect?q=" + quote(payload, safe=""), identity_headers={}, target_base=BASE,
                     marker=MARKER, finding_id="T-1", wait_ms=300, safe=True, role="customer-a")
    kinds = {e["kind"]: e for e in result["evidence"]}
    event = json.loads((tmp / kinds["browser-event"]["path"]).read_text())
    assert event["marked_elements"] == 1
    pages = [x for x in result["_exchanges"] if x["navigation"]]
    assert len(pages) == 1 and pages[0]["status"] == 200 and b"Results for" in pages[0]["content"]


def test_a_dialog_over_the_payload_is_hidden_for_the_screenshot_and_named(browser):
    """VER-035: the payload runs under the page's own dialog; the screenshot shows the payload element,
    says what it hid, and the event record lists it."""
    import json

    b, _, tmp = browser
    payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>"
    result = _check(b, "/dialog?q=" + quote(payload, safe=""))
    assert result["executed"] is True
    kinds = {e["kind"]: e for e in result["evidence"]}
    event = json.loads((tmp / kinds["browser-event"]["path"]).read_text())
    assert event["marked_elements"] == 1 and event["hidden_for_screenshot"] == ["div#welcome"]


def test_screenshots_can_be_turned_off_without_losing_the_proof(tmp_path):
    target = Target()
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), target)
    b = ProofBrowser(http, tmp_path / "evidence", screenshots=())
    try:
        payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>"
        result = _check(b, "/reflect?q=" + quote(payload, safe=""))
    finally:
        b.close()
    assert result["executed"] is True
    assert [e["kind"] for e in result["evidence"]] == ["browser-event"]
    assert not list((tmp_path / "evidence").glob("*.png"))


def test_render_draws_a_recorded_page_without_contacting_the_target(browser):
    """VER-035: an access-control screenshot comes from the record; its images and scripts are never fetched."""
    b, target, tmp = browser
    html = ('<html><body><h1>Basket of bob@shop.test</h1><img src="/logo.png">'
            '<script src="https://shop.example.com/app.js"></script></body></html>')
    [shot] = b.render(url=BASE + "/basket/2", status=200, content_type="text/html", html=html, finding_id="T-2",
                      caption=["AppSec Verifier · T-2 · access control"], highlight=["bob@shop.test"])
    assert target.seen == []
    assert shot["marked"] == 1 and shot["note"] == SCREENSHOT_NOTE
    path = tmp / shot["path"]
    assert path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" and stat.S_IMODE(path.stat().st_mode) == 0o600


def test_render_exchanges_draws_the_recorded_exchanges_without_contacting_the_target(browser):
    """VER-035: the image of a finding's exchanges, with what decides marked, from the record only."""
    from appsec_verifier.verify import poc

    b, target, tmp = browser

    def exchange(query, body):
        return poc.entry({"method": "GET", "url": BASE + "/search?q=" + query, "body": None, "status": 200,
                          "headers": [("Accept", "application/json")], "elapsed_ms": 40,
                          "response_headers": [("Content-Type", "application/json")], "content": body.encode(),
                          "time": "2026-11-07T12:00:00Z"})

    shown = [(1, exchange("x%27%20OR%201%3D1--", '{"items":[1,2,3]}')),
             (2, exchange("x%27%20OR%201%3D2--", '{"items":[]}'))]
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-3", cls="injection"), marker=("vrfa", "b"), scope={})
    page, marked = poc.exchange_document(ctx, [{}, {}], shown, "confirmed", "evidence/T-3-poc.har")
    [shot] = b.render_exchanges(html=page, finding_id="T-3", marked=marked)
    assert target.seen == [] and shot["marked"] == marked == 4 and shot["note"] == SCREENSHOT_NOTE
    path = tmp / shot["path"]
    assert path.name == "T-3-exchange-1.png" and path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert int.from_bytes(path.read_bytes()[20:24], "big") < 720       # as tall as the content, not the window
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
