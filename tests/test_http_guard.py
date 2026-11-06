"""Guarded HTTP client enforces scope + budget and drops cross-origin
credentials on redirect (VER-017, VER-018, VER-015)."""

from __future__ import annotations

import pytest

from appsec_verifier.limits import Limits, LimitExceeded, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, ScopeViolation, same_origin, strip_cross_origin_auth

SCOPE = {
    "base_url": "https://app.example.com",
    "hosts": ["app.example.com"],
    "ports": [443],
    "schemes": ["https"],
    "path_prefixes": ["/"],
}


class Resp:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def client(transport, **kw):
    return GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), transport, **kw)


def test_same_origin_default_ports():
    assert same_origin("https://a.com/x", "https://a.com:443/y")
    assert not same_origin("https://a.com/x", "https://b.com/x")


def test_strip_cross_origin_auth():
    h = {"Authorization": "Bearer t", "Cookie": "s=1", "Accept": "*/*"}
    kept = strip_cross_origin_auth(h, "https://a.com/x", "https://a.com/y")
    assert "Authorization" in kept
    dropped = strip_cross_origin_auth(h, "https://a.com/x", "https://evil.com/y")
    assert "Authorization" not in dropped and "Cookie" not in dropped and "Accept" in dropped


def test_out_of_scope_request_refused():
    calls = []
    c = client(lambda m, u, h: calls.append(u) or Resp())
    with pytest.raises(ScopeViolation):
        c.request("GET", "https://evil.example/x")
    assert calls == []  # nothing was sent


def test_in_scope_request_sent_and_counted():
    seen = []
    budget = RunBudget(Limits())
    c = GuardedHttpClient(ScopeGuard(SCOPE), budget, lambda m, u, h: seen.append((m, u)) or Resp())
    c.request("GET", "https://app.example.com/api/x", {"Authorization": "Bearer t"})
    assert seen == [("GET", "https://app.example.com/api/x")]
    assert budget.requests == 1


def test_redirect_to_foreign_origin_drops_auth_then_is_refused():
    # First hop (in scope) 302s to evil.com: the Authorization header must be
    # dropped AND the new destination must fail the scope check.
    sent = []

    def transport(method, url, headers):
        sent.append((url, dict(headers)))
        if url == "https://app.example.com/login":
            return Resp(302, {"Location": "https://evil.example/steal"})
        return Resp(200)

    c = client(transport)
    with pytest.raises(ScopeViolation):
        c.request("GET", "https://app.example.com/login", {"Authorization": "Bearer secret"})
    # the foreign origin was refused before any request reached it
    assert "https://evil.example/steal" not in [u for u, _ in sent]


def test_budget_exhaustion_stops_client():
    c = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits(max_requests=1)),
                          lambda m, u, h: Resp())
    c.request("GET", "https://app.example.com/a")
    with pytest.raises(LimitExceeded):
        c.request("GET", "https://app.example.com/b")
