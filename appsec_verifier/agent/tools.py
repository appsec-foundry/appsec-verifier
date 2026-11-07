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
The agent's path is appended to the target base URL as written, without
resolving dot segments, so the guard decides on the path the agent chose and
refuses an ambiguous one (VER-018). http_request does not follow redirects: a
3xx answer is returned with its `location`, which is what an open-redirect
proof observes (VER-012); any further hop is a request of its own.

Path traversal and SSRF are steered to harmless markers (VER-012). In a
path-traversal probe a parameter or body value that names a file (`..`, an
absolute path, a NUL) must name the scope's marker file; in an SSRF probe a
value that holds a URL must point at the callback listener. Values are
percent-decoded up to three times before the check. This is a floor, not a
parser of every encoding; the prompt states the same rule. The marker file's
content never reaches the model: it is replaced by "[marker-file]" in every
tool result, and http_request reports `marker_read` instead. An SSRF probe's
http_request reports `callback_hit` once the listener has seen the finding's
marker. Every http_request reports `elapsed_ms`, the time httpx measured for
the exchange, for a timing proof of injection (VER-011).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

import httpx

from ..auth.sessions import AuthError
from ..tools.http import ALLOWED_METHODS, SAFE_METHODS, ScopeViolation, same_origin
from .source_reader import SourceAccessError

_BODY_EXCERPT = 600
_LOCATION_CAP = 2000
_HIDDEN = "[marker-file]"
_CALLBACK_WAIT_S = 1.0
_DRIVE = re.compile(r"^[A-Za-z]:")


class ToolError(Exception):
    """A tool call was rejected or malformed. Surfaced to the agent as an error
    result, never raised past the loop."""


def _body_text(resp) -> str:
    text = getattr(resp, "text", None)
    if text is None:
        content = getattr(resp, "content", b"") or b""
        text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
    return text


def _elapsed_ms(resp) -> int | None:
    """How long the answer took, from sending the request to reading the body, as httpx measures it."""
    try:
        elapsed = getattr(resp, "elapsed", None)
        return round(elapsed.total_seconds() * 1000) if elapsed is not None else None
    except (AttributeError, RuntimeError):      # httpx raises RuntimeError before the body is read
        return None


def _strings(value):
    """Every string value inside params or a JSON body; keys are not values."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


def _decoded(value: str) -> str:
    for _ in range(3):
        plain = unquote(value)
        if plain == value:
            break
        value = plain
    return value


def _file_path(value: str) -> str | None:
    """The file path a value names, up to a NUL, or None when it does not look like one."""
    d = _decoded(value)
    if ".." in d or "\x00" in d or d.startswith(("/", "\\", "~")) or _DRIVE.match(d):
        return d.split("\x00", 1)[0].replace("\\", "/")
    return None


def _hide(value, secret: str | None):
    """`value` with every occurrence of the marker file's content replaced."""
    if not secret:
        return value
    if isinstance(value, str):
        return value.replace(secret, _HIDDEN)
    if isinstance(value, dict):
        return {k: _hide(v, secret) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_hide(v, secret) for v in value]
    return value


class AgentTools:
    """Dispatches the agent's tool calls against a ProbeContext."""

    def __init__(self, ctx):
        self.ctx = ctx
        marker_file = (getattr(ctx, "scope", None) or {}).get("marker_file") or {}
        self._marker_content = marker_file.get("content") or None
        path = str(marker_file.get("path") or "").replace("\\", "/")
        self._marker_name = PurePosixPath(path).name or None

    def call(self, name: str, args: dict) -> dict:
        tool = {"http_request": self.http_request, "read_source": self.read_source,
                "browser_check": self.browser_check}.get(name)
        if tool is None:
            raise ToolError(f"unknown tool {name!r}; available: http_request, read_source, browser_check")
        return _hide(tool(**args), self._marker_content)     # the model never sees the marker file's content

    def _check_steering(self, params, body) -> None:
        """Path-traversal and SSRF probes aim only at the marker file and the callback listener (VER-012)."""
        cls, values = self.ctx.plan.cls, [*_strings(params), *_strings(body)]
        if cls == "path-traversal":
            name = self._marker_name
            for value in values:
                path = _file_path(value)
                if path is not None and not (name and (path == name or path.endswith("/" + name))):
                    raise ToolError("a path-traversal probe may name only the scope's marker file"
                                    + (f" ({name})" if name else "; this scope names none") + " (VER-012)")
        elif cls == "ssrf":
            base = self.ctx.listener.base_url if self.ctx.listener is not None else None
            for value in values:
                d = _decoded(value)
                if d.startswith("//") and base:
                    d = urlsplit(base).scheme + ":" + d
                if ("://" in d or d.startswith("//")) and not (base and same_origin(d, base)):
                    raise ToolError("an SSRF probe may point the target only at the callback listener"
                                    + (f" ({base}/…)" if base else "; this run has none") + " (VER-012)")

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
        url = self._url(path)
        if not isinstance(wait_ms, int) or isinstance(wait_ms, bool):
            raise ToolError("wait_ms must be an integer number of milliseconds")
        try:
            # The browser attaches the identity headers only to requests for `origin` (VER-018).
            return self.ctx.browser.check(url, identity_headers=headers, target_base=origin,
                                          marker=self.ctx.marker, finding_id=self.ctx.plan.id, wait_ms=wait_ms,
                                          safe=self.ctx.safe or self.ctx.read_only)
        except BrowserError as exc:
            raise ToolError(str(exc)) from exc

    def _url(self, path) -> str:
        """An absolute http(s) URL as given, anything else appended below the target base URL.
        Unlike urljoin, this keeps `..` in the URL, where the guard refuses it (VER-018)."""
        path = str(path)
        try:
            scheme = urlsplit(path).scheme
        except ValueError as exc:
            raise ToolError("the path is not a parseable URL path") from exc
        if scheme in ("http", "https"):
            return path
        return self.ctx.target_base.rstrip("/") + "/" + path.lstrip("/")

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
        self._check_steering(params, json)
        url = self._url(path)
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
        redacted = _hide(redacted, self._marker_content)  # before the cut, so no part of the marker remains
        status = getattr(resp, "status_code", None)
        out = {
            "role": role,
            "status": status,
            "length": len(text),                         # of the whole body, not of the excerpt
            # of the redacted body, so no hash of a credential exists; lets the proof check compare answers
            "body_sha256": hashlib.sha256(redacted.encode("utf-8", "replace")).hexdigest(),
            "body_excerpt": redacted[:_BODY_EXCERPT],    # redacted before the cut: no partial token (VER-016)
        }
        resp_headers = getattr(resp, "headers", None) or {}
        location = resp_headers.get("Location") or resp_headers.get("location")
        if isinstance(status, int) and 300 <= status < 400 and location:
            location = str(location)
            location = self.ctx.sessions.redact(location) if self.ctx.sessions is not None else location
            out["location"] = _hide(location, self._marker_content)[:_LOCATION_CAP]
        elapsed = _elapsed_ms(resp)
        if elapsed is not None:
            out["elapsed_ms"] = elapsed                  # transport time, without the rate limit's wait (VER-011)
        if self.ctx.plan.cls == "path-traversal" and self._marker_content:
            out["marker_read"] = self._marker_content in text           # the raw body, checked in code
        if self.ctx.plan.cls == "ssrf" and self.ctx.listener is not None:
            out["callback_hit"] = self.ctx.listener.wait_for("".join(self.ctx.marker), _CALLBACK_WAIT_S)
        return out

    def _send(self, method, url, headers, params, json):
        kwargs = {}
        if params:
            kwargs["params"] = params
        if json is not None:
            kwargs["json"] = json
        # Not followed: the agent sees the redirect itself (VER-012) and sends any next hop as its own request.
        return self.ctx.http.request(method, url, headers, purpose="target", follow_redirects=False, **kwargs)

    def read_source(self, *, path: str, around_line: int | None = None) -> dict:
        if self.ctx.source is None:
            raise ToolError("no source checkout is available for this run")
        try:
            return self.ctx.source.read_window(path, around_line=around_line)
        except SourceAccessError as exc:
            raise ToolError(str(exc)) from exc
