"""The exact, narrow tool surface the verification agent is confined to
(VER-017). The agent never gets a shell or raw network: it can issue an HTTP
request to the target as one of the configured identities (scope-guarded),
read the evidenced source (repository-confined), and, for XSS findings, load a
page in the proof browser whose requests go through the same guard (VER-009,
VER-018). Nothing else.
"""

from __future__ import annotations

from urllib.parse import urljoin

from .source_reader import SourceAccessError

_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
_BODY_EXCERPT = 600


class ToolError(Exception):
    """A tool call was rejected or malformed. Surfaced to the agent as an error
    result, never raised past the loop."""


def _body_excerpt(resp) -> str:
    text = getattr(resp, "text", None)
    if text is None:
        content = getattr(resp, "content", b"") or b""
        text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
    return text[:_BODY_EXCERPT]


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
        headers = {}
        if role:
            if self.ctx.sessions is None:
                raise ToolError("no identities are configured for this run")
            headers = self.ctx.sessions.headers_for(role)
        url = urljoin(self.ctx.target_base.rstrip("/") + "/", str(path).lstrip("/"))
        if not isinstance(wait_ms, int) or isinstance(wait_ms, bool):
            raise ToolError("wait_ms must be an integer number of milliseconds")
        try:
            return self.ctx.browser.check(url, identity_headers=headers, target_base=self.ctx.target_base,
                                          marker=self.ctx.marker, finding_id=self.ctx.plan.id, wait_ms=wait_ms,
                                          safe=self.ctx.safe or self.ctx.read_only)
        except BrowserError as exc:
            raise ToolError(str(exc)) from exc

    def http_request(self, *, role: str | None = None, method: str = "GET", path: str = "/",
                     params: dict | None = None, json: dict | None = None) -> dict:
        from ..tools import ScopeViolation

        m = (method or "GET").upper()
        if m not in _SAFE_METHODS and (self.ctx.safe or self.ctx.read_only):
            raise ToolError(f"{m} is disabled in safe/read-only mode (VER-014/030); use --allow-intrusive")
        if self.ctx.http is None or not self.ctx.target_base:
            raise ToolError("no HTTP transport is wired for this run")
        url = urljoin(self.ctx.target_base.rstrip("/") + "/", str(path).lstrip("/"))
        headers = {}
        if role:
            if self.ctx.sessions is None:
                raise ToolError("no identities are configured for this run")
            headers = self.ctx.sessions.headers_for(role)
        try:
            resp = self._send(m, url, headers, params, json)
            if getattr(resp, "status_code", None) in (401, 403) and role and self.ctx.sessions is not None:
                self.ctx.sessions.invalidate(role)                # VER-028: refresh once on auth failure
                headers = self.ctx.sessions.headers_for(role)
                resp = self._send(m, url, headers, params, json)
        except ScopeViolation as exc:
            raise ToolError(f"request refused — out of scope: {exc}") from exc
        return {
            "role": role,
            "status": getattr(resp, "status_code", None),
            "length": len(_body_excerpt(resp)),
            "body_excerpt": _body_excerpt(resp),
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
