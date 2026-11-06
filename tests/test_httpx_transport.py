"""httpx transport does not follow redirects (the guard does), passes body/
headers, and integrates with GuardedHttpClient scope enforcement (VER-018/029)."""

from __future__ import annotations

import httpx
import pytest

from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, ScopeViolation
from appsec_verifier.tools.httpx_transport import HttpxTransport, _proxy_url

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}


def _mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_transport_passes_method_headers_body_and_returns_response():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content
        return httpx.Response(200, json={"ok": True})

    t = HttpxTransport(client=_mock_client(handler))
    resp = t(" POST".strip(), "https://app.example.com/x", {"Authorization": "Bearer t"}, json={"a": 1})
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    assert seen["method"] == "POST" and seen["auth"] == "Bearer t" and b'"a"' in seen["body"]


def test_transport_does_not_follow_redirects():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example/"})

    t = HttpxTransport(client=_mock_client(handler))
    resp = t("GET", "https://app.example.com/go", {})
    assert resp.status_code == 302  # returned, not followed


def test_guarded_client_with_real_transport_refuses_out_of_scope():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200)

    client = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), HttpxTransport(client=_mock_client(handler)))
    with pytest.raises(ScopeViolation):
        client.request("GET", "https://evil.example/x")
    assert calls == []  # transport never reached
    client.request("GET", "https://app.example.com/ok")
    assert calls == ["https://app.example.com/ok"]


def test_proxy_url_injects_credentials_from_env():
    scope = {"proxy": {"url": "http://proxy.corp:8080",
                       "username_env": "PX_USER", "password_env": "PX_PASS"}}
    url = _proxy_url(scope, env={"PX_USER": "u", "PX_PASS": "p@ss"})
    assert url == "http://u:p%40ss@proxy.corp:8080"


def test_proxy_url_none_when_unconfigured():
    assert _proxy_url({}, env={}) is None
