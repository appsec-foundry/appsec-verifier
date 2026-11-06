"""The exact, narrow tool surface the verification agent is confined to
(VER-017). The agent never gets a shell or raw network: it can issue an HTTP
request to the target as one of the configured identities (scope-guarded), and
read the evidenced source (repository-confined). Nothing else.
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
        raise ToolError(f"unknown tool {name!r}; available: http_request, read_source")

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
