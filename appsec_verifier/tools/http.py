"""Scope- and budget-confined HTTP client (VER-017, VER-018, VER-015).

Every request is authorised by the ScopeGuard before it is sent and counted
against the RunBudget. Credentials (Authorization, Cookie, proxy auth) are
dropped, never forwarded, when a redirect leads to a different origin. The
actual transport is injected: `transport(method, url, headers) -> Response`,
so the enforcement is unit-testable without a network and without binding a
particular HTTP library yet.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

_SENSITIVE = ("authorization", "cookie", "proxy-authorization")

Transport = Callable[[str, str, dict], Any]


class ScopeViolation(Exception):
    """Raised when a request's destination is not authorised by the scope."""


def same_origin(a: str, b: str) -> bool:
    ua, ub = urlparse(a), urlparse(b)
    pa = ua.port or {"https": 443, "http": 80}.get((ua.scheme or "").lower())
    pb = ub.port or {"https": 443, "http": 80}.get((ub.scheme or "").lower())
    return (ua.scheme.lower(), (ua.hostname or "").lower(), pa) == (ub.scheme.lower(), (ub.hostname or "").lower(), pb)


def strip_cross_origin_auth(headers: dict, from_url: str, to_url: str) -> dict:
    """Return headers safe to send to `to_url`: when it is a different origin
    than `from_url`, sensitive credential headers are removed (VER-018)."""
    if same_origin(from_url, to_url):
        return dict(headers)
    return {k: v for k, v in headers.items() if k.lower() not in _SENSITIVE}


class GuardedHttpClient:
    def __init__(self, guard, budget, transport: Transport, *, default_purpose: str = "target",
                 max_redirects: int = 5):
        self._guard = guard
        self._budget = budget
        self._transport = transport
        self._default_purpose = default_purpose
        self._max_redirects = max_redirects

    def request(self, method: str, url: str, headers: dict | None = None, *, purpose: str | None = None):
        purpose = purpose or self._default_purpose
        headers = dict(headers or {})
        hops = 0
        while True:
            decision = self._guard.authorize(url, purpose)
            if not decision.allowed:
                raise ScopeViolation(decision.reason)
            self._budget.check_time()
            self._budget.note_request()
            resp = self._transport(method, url, headers)

            status = getattr(resp, "status_code", None)
            resp_headers = getattr(resp, "headers", {}) or {}
            location = resp_headers.get("Location") or resp_headers.get("location")
            if status and 300 <= status < 400 and location and hops < self._max_redirects:
                target = urljoin(url, location)
                headers = strip_cross_origin_auth(headers, url, target)  # VER-018
                url = target
                hops += 1
                continue
            return resp
