"""The exact, narrow tool surface the verification agent is confined to
(VER-017). The agent never gets a shell or raw network: it can issue an HTTP
request to the target as one of the configured identities (scope-guarded),
read the evidenced source (repository-confined), and, for XSS findings, load a
page in the proof browser whose requests go through the same guard (VER-009,
VER-018). Nothing else.

An identity's credentials go only to the origin it is bound to (its
`target_origin`, by default the target base URL), never to another host in the
scope (VER-018, VER-028). Only GET, HEAD and OPTIONS are sent in safe mode, and
POST, PUT and PATCH only in intrusive mode; DELETE and every other method are
never sent (VER-014). A failing identity or transport ends the call as a tool
error for the agent, never as an exception past the loop. A response body is
redacted of every credential value before it is cut to the excerpt (VER-016).
"""

from __future__ import annotations

import hashlib
from urllib.parse import urljoin

import httpx

from ..auth.sessions import AuthError
from ..tools.http import ALLOWED_METHODS, SAFE_METHODS, ScopeViolation, same_origin
from .source_reader import SourceAccessError

_BODY_EXCERPT = 600


class ToolError(Exception):
    """A tool call was rejected or malformed. Surfaced to the agent as an error
    result, never raised past the loop."""


def _body_text(resp) -> str:
    text = getattr(resp, "text", None)
    if text is None:
        content = getattr(resp, "content", b"") or b""
        text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
    return text


class AgentTools:
    """Dispatches the agent's tool calls against a ProbeContext."""

    def __init__(self, ctx):
        self.ctx = ctx

    def call(self, name: str, args: dict) -> dict:
        if name == "http_request":
            return self.http_request(**args)
        if name == "read_source":
            return self.read_source(**args)
        if name == "browser_check":
            return self.browser_check(**args)
        raise ToolError(f"unknown tool {name!r}; available: http_request, read_source, browser_check")

    def browser_check(self, *, path: str, role: str | None = None, wait_ms: int = 1500) -> dict:
        from ..tools.browser import BrowserError

        if self.ctx.plan.cls != "xss":
            raise ToolError("the proof browser is only available for XSS findings")
        if self.ctx.browser is None:
            raise ToolError("no proof browser in this run; install appsec-verifier[browser] and Google Chrome")
        headers, origin = {}, self.ctx.target_base
        if role:
            origin = self._bound_origin(role)
            headers = self._session_headers(role)
        url = urljoin(self.ctx.target_base.rstrip("/") + "/", str(path).lstrip("/"))
        if not isinstance(wait_ms, int) or isinstance(wait_ms, bool):
            raise ToolError("wait_ms must be an integer number of milliseconds")
        try:
            # The browser attaches the identity headers only to requests for `origin` (VER-018).
            return self.ctx.browser.check(url, identity_headers=headers, target_base=origin,
                                          marker=self.ctx.marker, finding_id=self.ctx.plan.id, wait_ms=wait_ms,
                                          safe=self.ctx.safe or self.ctx.read_only)
        except BrowserError as exc:
            raise ToolError(str(exc)) from exc

    def _bound_origin(self, role: str) -> str:
        """The origin `role`'s credentials may be sent to (VER-018, VER-028)."""
        if self.ctx.sessions is None:
            raise ToolError("no identities are configured for this run")
        return self.ctx.sessions.origin_for(role) or self.ctx.target_base

    def _session_headers(self, role: str) -> dict:
        try:
            return self.ctx.sessions.headers_for(role)
        except (AuthError, ScopeViolation) as exc:
            raise ToolError(f"identity {role!r} is unavailable: {exc}") from exc

    def http_request(self, *, role: str | None = None, method: str = "GET", path: str = "/",
                     params: dict | None = None, json: dict | None = None) -> dict:
        m = (method or "GET").upper()
        if m not in ALLOWED_METHODS:
            raise ToolError(f"{m} is never sent; allowed methods are {', '.join(ALLOWED_METHODS)} (VER-014)")
        if m not in SAFE_METHODS and (self.ctx.safe or self.ctx.read_only):
            raise ToolError(f"{m} is disabled in safe/read-only mode (VER-014/030); use --allow-intrusive")
        if self.ctx.http is None or not self.ctx.target_base:
            raise ToolError("no HTTP transport is wired for this run")
        url = urljoin(self.ctx.target_base.rstrip("/") + "/", str(path).lstrip("/"))
        headers = {}
        if role:
            origin = self._bound_origin(role)
            if not same_origin(url, origin):
                raise ToolError(f"identity {role!r} is bound to {origin}; its credentials are not sent to "
                                f"another origin (VER-018). Send this request without a role.")
            headers = self._session_headers(role)
        try:
            resp = self._send(m, url, headers, params, json)
            # VER-028: re-obtain the session once when the target rejects it as unauthenticated (401).
            # A 403 is an authorisation answer, often the very result under test; a new login cannot change it.
            if getattr(resp, "status_code", None) == 401 and role and self.ctx.sessions is not None:
                self.ctx.sessions.invalidate(role)
                headers = self._session_headers(role)
                resp = self._send(m, url, headers, params, json)
        except ScopeViolation as exc:
            raise ToolError(f"request refused — out of scope: {exc}") from exc
        except (httpx.HTTPError, httpx.InvalidURL, OSError) as exc:
            raise ToolError(f"request failed: {type(exc).__name__}") from exc
        text = _body_text(resp)
        redacted = self.ctx.sessions.redact(text) if self.ctx.sessions is not None else text
        return {
            "role": role,
            "status": getattr(resp, "status_code", None),
            "length": len(text),                         # of the whole body, not of the excerpt
            # of the redacted body, so no hash of a credential exists; lets the proof check compare answers
            "body_sha256": hashlib.sha256(redacted.encode("utf-8", "replace")).hexdigest(),
            "body_excerpt": redacted[:_BODY_EXCERPT],    # redacted before the cut: no partial token (VER-016)
        }

    def _send(self, method, url, headers, params, json):
        kwargs = {}
        if params:
            kwargs["params"] = params
        if json is not None:
            kwargs["json"] = json
        return self.ctx.http.request(method, url, headers, purpose="target", **kwargs)

    def read_source(self, *, path: str, around_line: int | None = None) -> dict:
        if self.ctx.source is None:
            raise ToolError("no source checkout is available for this run")
        try:
            return self.ctx.source.read_window(path, around_line=around_line)
        except SourceAccessError as exc:
            raise ToolError(str(exc)) from exc
