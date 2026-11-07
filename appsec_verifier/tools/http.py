"""Scope- and budget-confined HTTP client (VER-017, VER-018, VER-015).

Every request is authorised by the ScopeGuard before it is sent and counted
against the RunBudget. Credentials (Authorization, Cookie, proxy auth) are
dropped, never forwarded, when a redirect leads to a different origin. Only
the methods in ALLOWED_METHODS are ever sent, whoever asks; DELETE and every
other method are refused here (VER-014). Safe mode narrows this further to
SAFE_METHODS at the callers. The actual transport is injected:
`transport(method, url, headers) -> Response`, so the enforcement is
unit-testable without a network and without binding a particular HTTP library.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

_SENSITIVE = ("authorization", "cookie", "proxy-authorization")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
ALLOWED_METHODS = SAFE_METHODS + ("POST", "PUT", "PATCH")

Transport = Callable[..., Any]   # transport(method, url, headers, **kwargs) -> Response


class ScopeViolation(Exception):
    """Raised when a request's destination is not authorised by the scope."""


def _origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        u = urlparse(url)
        scheme = (u.scheme or "").lower()
        port = u.port or {"https": 443, "http": 80}.get(scheme)
    except (TypeError, ValueError, AttributeError):
        return None
    return (scheme, (u.hostname or "").lower(), port) if u.hostname else None


def same_origin(a: str, b: str) -> bool:
    """True only for two parseable URLs with the same scheme, host and port; an
    unparseable URL is never the same origin, so credentials are dropped."""
    oa, ob = _origin(a), _origin(b)
    return oa is not None and oa == ob


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

    def request(self, method: str, url: str, headers: dict | None = None, *,
                purpose: str | None = None, follow_redirects: bool = True, **kwargs):
        """Send one request through the injected transport, authorised and
        budgeted. `kwargs` (e.g. data=, json=, params=) are forwarded to the
        transport; on a redirect the request body is dropped and sensitive
        headers are stripped when the origin changes (VER-018). With
        `follow_redirects=False` a redirect is returned as is, for a caller (the
        proof browser) that sends each hop through this client again."""
        purpose = purpose or self._default_purpose
        if not isinstance(method, str) or method.upper() not in ALLOWED_METHODS:
            raise ScopeViolation(f"method {str(method)[:20]!r} is never sent (VER-014)")
        headers = dict(headers or {})
        req_kwargs = dict(kwargs)
        hops = 0
        while True:
            decision = self._guard.authorize(url, purpose)
            if not decision.allowed:
                raise ScopeViolation(decision.reason)
            self._budget.check_time()
            self._budget.note_request()
            resp = self._transport(method, url, headers, **req_kwargs)

            status = getattr(resp, "status_code", None)
            resp_headers = getattr(resp, "headers", {}) or {}
            location = resp_headers.get("Location") or resp_headers.get("location")
            if follow_redirects and status and 300 <= status < 400 and location and hops < self._max_redirects:
                try:
                    target = urljoin(url, location)
                except ValueError as exc:
                    raise ScopeViolation("unparseable redirect target") from exc
                headers = strip_cross_origin_auth(headers, url, target)  # VER-018
                url = target
                req_kwargs = {}            # never resend the body across a redirect
                hops += 1
                continue
            return resp
