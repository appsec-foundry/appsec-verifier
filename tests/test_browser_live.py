"""XSS proof browser against real Google Chrome (VER-009, VER-018, VER-022).

Opt-in: needs `appsec-verifier[browser]`, Google Chrome, and
APPSEC_VERIFIER_BROWSER_TESTS=1. No network is used: the target is a fake
transport behind the GuardedHttpClient, and every request Chrome makes must go
through it."""

from __future__ import annotations

import html
import os
import socket
import stat
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlparse

import pytest

pytest.importorskip("playwright.sync_api")
if os.environ.get("APPSEC_VERIFIER_BROWSER_TESTS") != "1":
    pytest.skip("set APPSEC_VERIFIER_BROWSER_TESTS=1 to start Google Chrome", allow_module_level=True)

from appsec_verifier.limits import Limits, RunBudget  # noqa: E402
from appsec_verifier.scope import ScopeGuard  # noqa: E402
from appsec_verifier.tools import GuardedHttpClient  # noqa: E402
from appsec_verifier.tools.browser import ProofBrowser, marker_expression  # noqa: E402

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
        q = parse_qs(parsed.query).get("q", [""])[0]
        pages = {
            "/reflect": f"<html><body><p>Results for {q}</p></body></html>",
            "/safe": f"<html><body><p>Results for {html.escape(q)}</p></body></html>",
            "/echo": "<html><body><script>alert(new URLSearchParams(location.search).get('q'))</script></body></html>",
            "/ext": '<html><body><script src="https://evil.example.net/x.js"></script></body></html>',
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
