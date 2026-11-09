"""The SSRF callback listener binds only to loopback, keeps only marker hits and
bounded metadata, and is never a target of the Verifier itself (VER-012, VER-018)."""

from __future__ import annotations

import http.client
import socket

import pytest

from appsec_verifier.cli import _callback_listener
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import callback as callback_module
from appsec_verifier.tools.callback import CallbackListener, CallbackUnavailable

MARKER = "vrf0a1b2c3d4e5f6a7b"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.parametrize("callback, reason", [
    (None, "needs host, port and base_url"),
    ({"host": "127.0.0.1", "port": 4444}, "needs host, port and base_url"),
    ({"host": "0.0.0.0", "port": 4444, "base_url": "https://cb.example.com"}, "only to loopback"),
    ({"host": "10.0.0.5", "port": 4444, "base_url": "https://cb.example.com"}, "only to loopback"),
    ({"host": "127.0.0.1", "port": 4444, "base_url": "http://cb.example.com"}, "must be https"),
    ({"host": "127.0.0.1", "port": 4444, "base_url": "http://172.17.0.1:4444"}, "must be https"),
    ({"host": "127.0.0.1", "port": 4444, "base_url": "ftp://localhost"}, "http(s) URL"),
])
def test_unsafe_or_incomplete_callback_is_refused(callback, reason):
    with pytest.raises(CallbackUnavailable, match=reason.replace("(", r"\(").replace(")", r"\)")):
        CallbackListener(callback)


@pytest.mark.parametrize("callback", [
    {"host": "127.0.0.1", "port": 4444, "base_url": "http://localhost:4444"},
    {"host": "localhost", "port": 4444, "base_url": "http://127.0.0.1:4444/"},
    {"host": "::1", "port": 4444, "base_url": "https://cb.example.com/in"},
])
def test_loopback_callback_is_accepted(callback):
    listener = CallbackListener(callback)
    assert listener.url_for(MARKER) == callback["base_url"].rstrip("/") + "/" + MARKER


def test_listener_records_only_marker_requests_without_their_content():
    port = _free_port()
    listener = CallbackListener({"host": "127.0.0.1", "port": port, "base_url": f"http://127.0.0.1:{port}"})
    listener.start()
    try:
        for method, target in (("GET", f"/{MARKER}?secret=s3cr3t"), ("POST", "/no-marker"), ("PUT", f"/x/{MARKER}")):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request(method, target, body=b"payload" if method != "GET" else None,
                         headers={"Authorization": "Bearer internal-token"})
            resp = conn.getresponse()
            assert resp.status == 204 and resp.read() == b""
            conn.close()
        hits = listener.hits(MARKER)
        assert [h["method"] for h in hits] == ["GET", "PUT"] and hits[0]["source"] == "127.0.0.1"
        assert set(hits[0]) == {"at", "method", "source"}                 # no path, headers or body kept
        assert listener.wait_for(MARKER, 0) and not listener.wait_for("vrf" + "0" * 16, 0.01)
    finally:
        listener.close()


def test_listener_bounds_what_it_keeps(monkeypatch):
    monkeypatch.setattr(callback_module, "_MAX_MARKERS", 2)
    monkeypatch.setattr(callback_module, "_MAX_HITS", 3)
    listener = CallbackListener({"host": "127.0.0.1", "port": 4444, "base_url": "http://127.0.0.1:4444"})
    for i in range(5):
        listener._record(f"/{MARKER}", "GET", "127.0.0.1")
        listener._record(f"/vrf{i:016x}", "GET", "127.0.0.1")
    assert len(listener.hits(MARKER)) == 3
    assert len(listener._hits) == 2


# ── the listener is never a target ────────────────────────────────────────────

SCOPE = {"base_url": "http://localhost:3000", "hosts": ["localhost", "127.0.0.1"], "ports": [3000, 4444],
         "schemes": ["http"], "callback": {"host": "127.0.0.1", "port": 4444, "base_url": "http://localhost:4444"}}


@pytest.mark.parametrize("url", ["http://127.0.0.1:4444/vrf", "http://localhost:4444/", "http://[::1]:4444/x"])
def test_guard_never_lets_the_verifier_reach_the_listener(url):
    scope = dict(SCOPE, hosts=SCOPE["hosts"] + ["::1"])
    decision = ScopeGuard(scope).authorize(url, "target")
    assert not decision.allowed and "callback listener" in decision.reason


def test_guard_refuses_the_listener_by_its_base_url_too():
    scope = dict(SCOPE, hosts=["app.example.com", "cb.example.com"], ports=[443], schemes=["https"],
                 callback={"host": "127.0.0.1", "port": 4444, "base_url": "https://cb.example.com"})
    assert not ScopeGuard(scope).authorize("https://cb.example.com/vrf", "target").allowed
    assert ScopeGuard(scope).authorize("https://app.example.com/", "target").allowed


def test_guard_still_allows_the_target_beside_the_listener():
    assert ScopeGuard(SCOPE).authorize("http://localhost:3000/rest", "target").allowed


# ── end to end through verify ─────────────────────────────────────────────────

def test_verify_confirms_ssrf_when_the_target_calls_the_listener(tmp_path, monkeypatch):
    """The CLI starts the listener, the agent steers the (fake) target to it, the hit confirms the
    finding, and the listener is closed afterwards. Nothing leaves loopback."""
    from urllib.parse import urlsplit

    import yaml

    from appsec_verifier import cli
    from appsec_verifier.tools import httpx_transport

    port = _free_port()
    scope = {"schema_version": 1, "base_url": "http://localhost:3000", "schemes": ["http"],
             "owner": {"name": "tester"}, "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
             "callback": {"expect_rejected": True, "host": "127.0.0.1", "port": port, "base_url": f"http://127.0.0.1:{port}"}}
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(scope))
    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": "T-9", "cwe": "CWE-918", "severity": "high", "title": "ssrf", "scenario": "GET /fetch",
         "evidence": {"file": "routes/fetch.ts", "line": 1}}]}))
    seen = {}

    class Planner:
        def next_step(self, ctx, history):
            if not history:
                seen["listener"] = ctx.listener
                return {"tool": "http_request",
                        "args": {"path": "/fetch", "params": {"url": ctx.listener.url_for("".join(ctx.marker))}}}
            return {"verdict": {"verdict": "confirmed", "rationale": "the listener was called"}}

    class Resp:
        status_code, text, headers = 200, "fetched", {}

    def vulnerable_target(method, url, headers, params=None, **kwargs):      # the target fetches what it is given
        if params is None:                                                   # the pre-flight GET (VER-032)
            return Resp()
        u = urlsplit(params["url"])
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)    # direct, never through a proxy
        conn.request("GET", u.path)
        conn.getresponse().read()
        conn.close()
        return Resp()

    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: vulnerable_target)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope",
                   str(tmp_path / "scope.yaml"), "--output", str(tmp_path / "out"), "--yes", "--rate", "0"])
    result = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())["results"][0]
    assert rc == 0 and result["verdict"] == "confirmed", result["rationale"]
    assert result["evidence"][0]["kind"] == "callback"
    assert seen["listener"]._server is None                                   # closed after the run


# ── pre-flight ────────────────────────────────────────────────────────────────

def _plan(cls):
    return FindingPlan(id="T-1", cwe="CWE-918", severity="High", title="t", match_key="k", instance="a.ts:1",
                       status="dynamic", cls=cls, reason="r")


def test_listener_is_prepared_only_for_ssrf_findings():
    assert _callback_listener(SCOPE, [_plan("xss")]) == (None, None)
    listener, note = _callback_listener(SCOPE, [_plan("ssrf")])
    assert listener is not None and "127.0.0.1:4444" in note
    listener, note = _callback_listener({"callback": {"host": "0.0.0.0", "port": 1, "base_url": "https://x"}},
                                        [_plan("ssrf")])
    assert listener is None and "SSRF findings cannot be confirmed" in note


# ── automatic listener for a local target (VER-012) ───────────────────────────

def test_a_local_target_without_a_callback_gets_one_on_a_free_loopback_port():
    from appsec_verifier.cli import _auto_callback

    for target, bind, shown in (("http://localhost:3000", "127.0.0.1", "127.0.0.1"),
                                ("http://127.0.0.1:3000/app", "127.0.0.1", "127.0.0.1"),
                                ("http://[::1]:3000", "::1", "[::1]")):
        scope = {"base_url": target}
        assert _auto_callback(scope, target, [_plan("ssrf")]) is True
        cb = scope["callback"]
        assert cb["host"] == bind and cb["expect_rejected"] is True
        assert cb["base_url"] == f"http://{shown}:{cb['port']}" and 0 < cb["port"] < 65536
        assert CallbackListener(cb).base_url == cb["base_url"]
        wide = dict(scope, hosts=["localhost", "127.0.0.1", "::1"], ports=[3000, cb["port"]], schemes=["http"])
        assert not ScopeGuard(wide).authorize(cb["base_url"] + "/vrf", "target").allowed    # never a target


@pytest.mark.parametrize("target, cls, scope", [
    ("https://app.example.com", "ssrf", {}),                                  # not loopback
    ("http://10.0.0.5:3000", "ssrf", {}),
    ("http://localhost:3000", "xss", {}),                                     # no SSRF finding selected
    ("http://localhost:3000", "ssrf", {"callback": SCOPE["callback"]}),       # the scope declares one
])
def test_no_automatic_callback_otherwise(target, cls, scope):
    from appsec_verifier.cli import _auto_callback

    before = dict(scope)
    assert _auto_callback(scope, target, [_plan(cls)]) is False and scope == before


def test_verify_confirms_ssrf_through_the_automatic_listener_without_a_scope_file(tmp_path, monkeypatch, capsys):
    """--url on localhost, no callback declared: the run listens on a free loopback port, says so, and a hit
    confirms the finding because the target fetched an internal address."""
    from urllib.parse import urlsplit

    import yaml

    from appsec_verifier import cli
    from appsec_verifier.tools import httpx_transport

    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": "T-9", "cwe": "CWE-918", "severity": "high", "title": "ssrf", "scenario": "GET /fetch",
         "evidence": {"file": "routes/fetch.ts", "line": 1}}]}))

    class Planner:
        def next_step(self, ctx, history):
            if not history:
                return {"tool": "http_request",
                        "args": {"path": "/fetch", "params": {"url": ctx.listener.url_for("".join(ctx.marker))}}}
            return {"verdict": {"verdict": "confirmed", "rationale": "the listener was called"}}

    class Resp:
        status_code, text, headers = 200, "fetched", {}

    def vulnerable_target(method, url, headers, params=None, **kwargs):
        if params is None:
            return Resp()
        u = urlsplit(params["url"])
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
        conn.request("GET", u.path)
        conn.getresponse().read()
        conn.close()
        return Resp()

    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: vulnerable_target)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--url", "http://localhost:3000",
                   "--output", str(tmp_path / "out"), "--yes", "--rate", "0"])
    result = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())["results"][0]
    assert rc == 0 and result["verdict"] == "confirmed", result["rationale"]
    assert "(the target must reach this machine's loopback, not via docker -p)" in capsys.readouterr().out
