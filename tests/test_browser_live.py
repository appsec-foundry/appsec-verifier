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
import struct
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
            "/busy": "<html><body style='margin:0'><header style='position:fixed;top:0;left:0;right:0;height:56px;"
                     "background:#263238;color:#fff'>Shop</header><div style='height:900px'></div>"
                     f"<main style='padding:80px 20px'><h1>Search</h1><p>Results for {q}</p></main>"
                     "<div id=toast style='position:fixed;right:20px;bottom:20px;width:300px;height:60px;"
                     "background:#4caf50'>You solved a challenge</div><canvas style='position:fixed;inset:0;"
                     "width:100%;height:100%;pointer-events:none'></canvas><div style='height:900px'></div>"
                     "</body></html>",
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
    b.redact = lambda value: value  # this fake target has no credentials unless a test supplies one
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


def test_the_marker_expression_survives_a_query_that_reads_plus_as_a_space(browser):
    """Servers and client-side routers often decode + in a query string as a space, as /reflect does."""
    b, _, _ = browser
    joined_with_plus = f"<img src=x onerror=alert('{MARKER[0]}'+'{MARKER[1]}')>"
    assert _check(b, "/reflect?q=" + joined_with_plus)["executed"] is False
    assert _check(b, f"/reflect?q=<img src=x onerror=alert({marker_expression(MARKER)})>")["executed"] is True


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
    width, height = struct.unpack(">II", (tmp / kinds["screenshot"]["path"]).read_bytes()[16:24])
    # Address bar, drawn dialog, the page section with application context and the caption, in a compact panel.
    assert width == 1280 and 500 <= height <= 1200
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


@pytest.mark.parametrize("extra, reviewable", [("", True), (" s3cret-token", False)])
def test_a_screenshot_is_saved_only_without_a_secret_in_its_page_text(browser, extra, reviewable):
    """VER-016/022/042: credentials exclude the image from disk as well as the model."""
    import json

    b, _, tmp = browser
    b.redact = lambda value: json.loads(json.dumps(value).replace("s3cret-token", "[redacted]"))
    b.private_text = lambda text: "s3cret-token" in text
    payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>{extra}"
    result = _check(b, "/reflect?q=" + quote(payload, safe=""))
    shots = [e for e in result["evidence"] if e["kind"] == "screenshot"]
    assert bool(shots) is reviewable
    assert bool(list((tmp / "evidence").glob("*.png"))) is reviewable
    assert result["executed"] is True
    if shots:
        assert shots[0]["reviewable"] is True
    else:
        assert "credential" in result["screenshot_error"]
        assert all("s3cret-token" not in p.read_text() for p in (tmp / "evidence").glob("*.json"))


def test_floating_layers_are_hidden_for_the_screenshot_while_the_header_stays(browser):
    """VER-035: notifications and confetti that do not hold the payload leave the image; the app's header bar
    stays as context, and the event record names what was hidden."""
    import json

    b, _, tmp = browser
    payload = f"<img src=x onerror=alert({marker_expression(MARKER)})>"
    result = _check(b, "/busy?q=" + quote(payload, safe=""))
    kinds = {e["kind"]: e for e in result["evidence"]}
    event = json.loads((tmp / kinds["browser-event"]["path"]).read_text())
    assert event["marked_elements"] == 1
    assert event["hidden_for_screenshot"] == ["div#toast", "canvas"]


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
    [shot] = b.render(url=BASE + "/basket/2", status=200, content_type="text/html", html=html, name="T-2",
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
    [shot] = b.render_exchanges(html=page, name="T-3-sql-injection", marked=marked)
    assert target.seen == [] and shot["marked"] == marked == 4 and shot["note"] == SCREENSHOT_NOTE
    path = tmp / shot["path"]
    assert path.name == "T-3-sql-injection-http-1.png" and path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert int.from_bytes(path.read_bytes()[20:24], "big") < 720       # as tall as the content, not the window
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_evidence_revision_panel_is_compact_and_sends_no_requests(browser):
    from appsec_verifier.verify.evidence_review import presentation_document

    b, target, tmp = browser
    revision = {"explanation": "The second account received the same test marker as the owner. "
                "The original proof remains in the HAR. <img src=/must-not-load>",
                "quotes": [{"step": 2, "part": "response", "text": 'HTTP/1.1 200 OK\n{"marker":"vrf-demo"}'},
                           {"step": 3, "part": "response", "text": 'HTTP/1.1 200 OK\n{"marker":"vrf-demo"}'}]}
    page = presentation_document("T-2", "confirmed", revision)
    [shot] = b.render_exchanges(html=page, name="T-2", marked=0, kind="explanation")
    assert target.seen == []
    width, height = struct.unpack(">II", (tmp / shot["path"]).read_bytes()[16:24])
    assert width <= 1280 and 0 < height <= 1200


@pytest.mark.parametrize("case, captured", [("visible", True), ("hidden", False), ("unrelated", False),
                                          ("api-only", False), ("blocked", False)])
def test_application_capture_requires_visible_effect_and_matching_resource(tmp_path, case, captured):
    calls = []

    def target(method, url, headers, **kw):
        calls.append((method, url))
        if url.endswith("/api/proof"):
            body, mime = '{"effect":"verifier-test-effect"}', "application/json"
        else:
            load = "fetch('/api/proof')" if case != "unrelated" else "Promise.resolve()"
            style = ' style="display:none"' if case == "hidden" else ""
            body = (f'<html><body><h1>Application</h1><div id=result{style}></div><script>'
                    f'{load}.then(() => document.querySelector("#result").textContent="verifier-test-effect");'
                    "fetch('/write', {method:'POST', body:'must not send'});"
                    "fetch('https://outside.example/private');</script></body></html>")
            mime = "text/html"
        return SimpleNamespace(status_code=200, headers={"content-type": mime}, content=body.encode())

    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), target)
    b = ProofBrowser(http, tmp_path / "evidence")
    path = "/api/proof" if case == "api-only" else "/ui"
    url = "https://outside.example/ui" if case == "blocked" else BASE + path
    try:
        result = b.check(url, identity_headers={}, target_base=BASE, marker=MARKER,
                         finding_id="T-UI", wait_ms=200, safe=True, role="customer-a",
                         observation={"resource_url": BASE + "/api/proof", "step": 2,
                                      "values": ["verifier-test-effect", "not-on-the-page"]})
    finally:
        b.close()
    assert bool(result["evidence"]) is captured
    assert all(method == "GET" and url.startswith(BASE + "/") for method, url in calls)
    if captured:
        shot = result["evidence"][0]
        assert shot["presentation"] == "application" and shot["proof_step"] == 2
        assert (tmp_path / shot["path"]).is_file()
    else:
        assert "error" in result


@pytest.mark.parametrize("value, path, captured", [
    (MARKER[0] + "e99d52fe", "/ui", True),                              # a list shows the marked record
    ("verifier-test-effect", "/ui", False),                             # no marker: only the cited resource counts
    (MARKER[0] + "e99d52fe", "/ui?q=" + MARKER[0] + "e99d52fe", False),  # the route itself carries the value
])
def test_application_capture_accepts_another_request_that_shows_the_marked_record(tmp_path, value, path, captured):
    def target(method, url, headers, **kw):
        if "/api/list" in url:
            body, mime = '{"data":[{"description":"' + value + '"}]}', "application/json"
        else:
            body = ("<html><body><h1>Products</h1><div id=list></div><script>"
                    "fetch('/api/list').then(r => r.json()).then(j => "
                    "document.querySelector('#list').textContent = j.data[0].description);"
                    "</script></body></html>")
            mime = "text/html"
        return SimpleNamespace(status_code=200, headers={"content-type": mime}, content=body.encode())

    b = ProofBrowser(GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), target), tmp_path / "evidence")
    try:
        result = b.check(BASE + path, identity_headers={}, target_base=BASE, marker=MARKER, finding_id="T-UI",
                         name="T-UI-product-update", wait_ms=300, safe=True, role="customer-a",
                         observation={"resource_url": BASE + "/api/Products/51", "step": 6, "values": [value]})
    finally:
        b.close()
    assert bool(result["evidence"]) is captured
    if captured:
        assert result["evidence"][0]["path"] == "evidence/T-UI-product-update.png"
        assert (tmp_path / result["evidence"][0]["path"]).is_file()
