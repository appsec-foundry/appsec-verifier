"""A single marked ZIP traversal experiment in an operator-designated test area (VER-045)."""

from __future__ import annotations

import hashlib
import io
import re
import secrets
import zipfile

import httpx

from ..tools.http import ScopeViolation, same_origin
from ..verification_context import route_matches


def run(tools, check_id, role=None):
    from .tools import ToolError, _body_text

    ctx = tools.ctx
    checks = [r for r in ctx.scope.get("archive_checks", [])
              if r["finding_id"] == ctx.plan.id and r["id"] == check_id]
    if ctx.plan.cls != "path-traversal" or len(checks) != 1:
        raise ToolError("archive probe needs this finding's operator-declared archive check")
    if ctx.safe or ctx.read_only or ctx.scope.get("allow_state_change") is False:
        raise ToolError("archive probe needs state-change authorization and intrusive mode")
    if role and tools._privileged(role):
        raise ToolError("a privileged identity only reads")
    if (getattr(ctx, "archive_attempt", None) or {}).get("upload_attempted"):
        raise ToolError("an archive upload was attempted; reconcile its marker before any further run")
    check = checks[0]
    variants = ctx.plan.verification_context.get("variants", [])
    if ctx.plan.variant_id:
        variants = [v for v in variants if v["id"] == ctx.plan.variant_id]
    routes = ([v["request"] for v in variants] if variants or ctx.plan.variant_id else
              [{"method": e.method, "path": e.path} for e in ctx.plan.endpoints])
    matching = [r for r in routes if r["method"] in ("POST", "ALL")
                and route_matches(r["path"], check["upload_path"])]
    if not matching:
        raise ToolError("the finding must evidence the archive upload route")
    if all(r.get("inputs") and not any(i["location"] == "form" and i["name"] == check["field"]
                                      for i in r["inputs"]) for r in matching):
        raise ToolError("archive field does not match the evidenced finding input")
    marker = "".join(ctx.marker)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", marker):
        raise ToolError("archive probe needs a bounded filename marker")
    extension = check["read_path"].rsplit(".", 1)[-1]
    if extension not in ("txt", "md"):
        raise ToolError("archive markers must use harmless .txt or .md text files")
    filename = marker + "." + extension
    content = "archive-proof-" + secrets.token_hex(16)
    paths = {"upload": check["upload_path"], "read": check["read_path"].replace("{marker}", marker)}
    if check.get("cleanup_path"):
        paths["cleanup"] = check["cleanup_path"].replace("{marker}", marker)
    headers = {}
    # Validate every destination before even the baseline read; the guarded client checks again per request.
    for path in paths.values():
        url = tools._url(path)
        if not same_origin(url, ctx.target_base):
            raise ToolError("archive requests must stay on the target origin")
        decision = ctx.guard.authorize(url, "target")
        if not decision.allowed:
            raise ToolError("archive request is outside scope")
        if role and not same_origin(url, tools._bound_origin(role)):
            raise ToolError("archive identity is bound to another origin")
    if role:
        headers = tools._session_headers(role)
    state = {"check_id": check_id, "marker": filename, "cleanup": "not-attempted", "escaped_marker": False}
    ctx.archive_attempt = state

    def send(method, key, **kwargs):
        if ctx.http is None:
            raise ToolError("no HTTP transport is wired for this run")
        try:
            response = ctx.http.request(method, tools._url(paths[key]), headers, purpose="target",
                                        follow_redirects=False, **kwargs)
        except ScopeViolation as exc:
            raise ToolError("archive request refused by scope") from exc
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise ToolError("archive request failed: " + type(exc).__name__) from exc
        tools._record(tools._sent(response, method, tools._url(paths[key]), headers, None, None), role, headers)
        return response

    baseline = send("GET", "read")
    if baseline.status_code not in (404, 410):
        raise ToolError("archive marker location must be absent before upload (404 or 410)")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zipped:
        zipped.writestr("../" + filename, content)
    state.update(archive_entry="../" + filename, content=content,
                 archive_sha256=hashlib.sha256(archive.getvalue()).hexdigest(),
                 upload_path=check["upload_path"], field=check["field"])
    state["upload_attempted"] = True  # Before the write: a timeout is never grounds for repeating it.
    state["cleanup"] = "manual-required"
    try:
        uploaded = send("POST", "upload", files={check["field"]: (marker + ".zip", archive.getvalue(),
                                                                  "application/zip")})
        observed = send("GET", "read")
        state["escaped_marker"] = (200 <= uploaded.status_code < 300 and observed.status_code == 200
                                    and _body_text(observed) == content)
    finally:
        if "cleanup" in paths:
            # Only this marker, at the operator-declared endpoint. No DELETE and no retries.
            state["cleanup"] = "unknown"
            cleaned = send("POST", "cleanup", json={"marker": filename})
            absent = send("GET", "read")
            state["cleanup"] = ("removed" if 200 <= cleaned.status_code < 300
                                and absent.status_code in (404, 410) else "manual-required")
    result = {**state, "extraction_directory": check["extraction_directory"], "read_path": paths["read"]}
    ctx.archive_proof = result.copy()
    return result
