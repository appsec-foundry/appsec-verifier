"""Evidence-backed request derivation inside a finding (VER-005, VER-008, VER-043).

Source declarations and recorded links/forms supply candidates, never authority. A
candidate must stay on the target origin and the original resource's route family;
derived routes cannot become anchors for exploring another resource. Unknown
framework syntax or relationships stay unresolved. No request is sent here.
"""

from __future__ import annotations

import posixpath
import re
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..tools.http import SAFE_METHODS, same_origin
from ..verification_context import planned_route

MAX_DERIVED = 8
_PLACEHOLDER = re.compile(r":\w+|\{\w+\}|<\w+>|\d+|[0-9a-fA-F-]{36}")
_ROUTE = re.compile(
    r"(?im)^\s*@?(?:(?:app|router|blueprint)\.)?(get|post|put|patch|head|options)"
    r"\(\s*['\"](/[^'\"\s]{0,500})['\"]"
)
_MAPPING = re.compile(r"@(Get|Post|Put|Patch)Mapping\(\s*(?:value\s*=\s*)?['\"](/[^'\"\s]{0,500})['\"]")
_IMPORT = re.compile(r"(?:from\s*|require\(\s*|import\s*)['\"](\.[^'\"\s]{1,200})['\"]")
_INPUT = re.compile(r"(?:req|request)\.(query|body|params)(?:\.([A-Za-z_]\w*)|\[['\"]([^'\"]+)['\"]\])")


def resolve(ctx, path):
    return path if urlsplit(path).scheme else ctx.target_base.rstrip("/") + "/" + path.lstrip("/")


def original_routes(ctx):
    """Only assessment/operator roots, never routes suggested by target content."""
    routes = [{"method": e.method, "path": e.path} for e in ctx.plan.endpoints]
    routes += [v["request"] for v in ctx.plan.verification_context.get("variants", [])]
    routes += [{"method": e.method, "path": e.path} for e in getattr(ctx.plan, "preparation", ())]
    for key in ("test_resources", "injection_inputs", "session_checks"):
        routes += [r for r in ctx.scope.get(key, []) if r["finding_id"] == ctx.plan.id]
    routes += getattr(ctx, "inferred_route_roots", [])
    return routes


def _parts(path):
    parsed = urlsplit(path)
    # Hash routes identify a different application view even when the HTTP path is identical.
    return tuple(p for p in (urlsplit(parsed.fragment).path if parsed.fragment else parsed.path).split("/") if p)


def related(anchor, candidate):
    """One resource: the same route or its immediate collection, record or view.

    A bare origin, API/version prefix, or placeholder cannot anchor discovery.
    The fixed prefix is never shortened beyond a record's last segment.
    """
    a, b = _parts(anchor), _parts(candidate)
    if a == b:
        return bool(a)
    if a and _PLACEHOLDER.fullmatch(a[-1]):
        a = a[:-1]
    if not a or a[-1].lower() in ("api", "rest", "graphql") or re.fullmatch(r"v\d+", a[-1], re.I):
        return False
    if any(_PLACEHOLDER.fullmatch(p) for p in a):
        return False
    return b[:len(a)] == a and len(a) <= len(b) <= len(a) + 1


class _Forms(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.routes, self.form = base, [], None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            method = (attrs.get("method") or "GET").upper()
            self.form = {"method": method, "path": urljoin(self.base, attrs.get("action") or self.base), "inputs": []}
            self.routes.append(self.form)
        elif tag in ("input", "textarea", "select") and self.form is not None and attrs.get("name"):
            location = "query" if self.form["method"] == "GET" else "form"
            self.form["inputs"].append({"location": location, "name": attrs["name"]})
        elif tag == "a" and attrs.get("href"):
            path = urljoin(self.base, attrs["href"])
            self.routes.append({"method": "GET", "path": path, "inputs": [
                {"location": "query", "name": k} for k, _ in parse_qsl(urlsplit(path).query)]})

    def handle_endtag(self, tag):
        if tag == "form":
            self.form = None


def _source_roots(ctx, history):
    root = (ctx.plan.instance or "").rsplit(":", 1)[0]
    paths = {root}
    # Follow literal local imports only from already related source, with a finite depth.
    for _ in range(3):
        known = set(paths)
        for h in history:
            if h.get("tool") != "read_source" or h.get("args", {}).get("path") not in known:
                continue
            text = h.get("result", {}).get("text", "")
            parent = PurePosixPath(h["args"]["path"]).parent
            for match in list(_IMPORT.finditer(text))[:12]:
                path = posixpath.normpath(str(parent / match[1]))
                # A sibling import may use ..; repository escapes cannot supply evidence.
                if path == ".." or path.startswith(("../", "/")):
                    continue
                paths.update([path, *(path + ext for ext in (".ts", ".js", ".py", "/index.ts", "/index.js"))])
    return paths


def _source_candidates(ctx, history, h):
    path = h.get("args", {}).get("path")
    if path not in _source_roots(ctx, history):
        raise ValueError("the source is not the finding's evidence or a recorded local import from it")
    result = h.get("result", {})
    text = result.get("text", "")
    candidates = []
    for pattern in (_ROUTE, _MAPPING):
        for m in list(pattern.finditer(text))[:32]:
            line = result.get("start_line", 1) + text[:m.start()].count("\n")
            # Input declarations belong to this handler, not to an unrelated later route.
            following = pattern.search(text, m.end())
            body = text[m.start():following.start() if following else len(text)]
            inputs = []
            for match in _INPUT.finditer(body):
                location = {"query": "query", "body": "json", "params": "path"}[match[1]]
                inputs.append({"location": location, "name": match[2] or match[3]})
                if location == "json":
                    inputs.append({"location": "form", "name": match[2] or match[3]})
            candidates.append({"method": m[1].upper(), "path": m[2], "inputs": inputs,
                               "source_file": path, "source_line": line})
    return candidates


def derive(ctx, *, evidence_step, method, path, inputs, reason):
    """Validate a proposal against recorded evidence, not model-provided quotes."""
    history = getattr(ctx, "agent_history", [])
    if type(evidence_step) is not int or not 1 <= evidence_step <= len(history):
        raise ValueError("cite a recorded source or HTTP step of this finding")
    if len(getattr(ctx, "derived_requests", [])) >= MAX_DERIVED:
        raise ValueError("the finding's derived-request allowance is exhausted")
    url = resolve(ctx, path)
    if not same_origin(url, ctx.target_base) or not ctx.guard.authorize(url, "target").allowed:
        raise ValueError("derived request is outside the authorised target")
    if method not in SAFE_METHODS and (ctx.safe or ctx.read_only or ctx.scope.get("allow_state_change") is False):
        raise ValueError("derived writes need intrusive mode and state-change permission")
    h = history[evidence_step - 1]
    if h.get("result", {}).get("error"):
        raise ValueError("a failed action supplies no request evidence")
    source = h.get("tool") == "read_source"
    if source:
        candidates = _source_candidates(ctx, history, h)
    elif h.get("tool") == "http_request":
        response = ctx.responses.get(evidence_step, {})
        if not response.get("complete") or not 200 <= h.get("result", {}).get("status", 0) < 300:
            raise ValueError("request derivation needs a complete successful recorded response")
        parser = _Forms(resolve(ctx, h["args"].get("path", "/")))
        parser.feed(response.get("body", ""))
        candidates = parser.routes
    else:
        raise ValueError("only recorded source declarations and application links or forms supply requests")
    roots = original_routes(ctx)
    # Bootstrap only at the evidenced source location when the assessment has no route.
    if not roots and source:
        file, _, line = (ctx.plan.instance or "").rpartition(":")
        near = [r for r in candidates if r.get("source_file") == file and line.isdigit()
                and 0 <= int(line) - r["source_line"] <= 80]
        roots = near[-1:]
    matching = [r for r in candidates if r["method"] == method
                and planned_route(resolve(ctx, r["path"]), url)
                and all(i in r.get("inputs", []) for i in inputs)]
    if not matching or not any(related(resolve(ctx, r["path"]), url) for r in roots):
        raise ValueError("request or inputs lack recorded evidence for the finding's original resource")
    if source:
        # Source paths are relative to the operator's base URL; browser links are already absolute.
        origin = {k: v for k, v in matching[0].items() if k.startswith("source_")}
    else:
        origin = {"response_step": evidence_step}
    request = {"method": method, "path": path, "inputs": inputs, "evidence_step": evidence_step,
               "reason": reason, **origin}
    if not hasattr(ctx, "derived_requests"):
        ctx.derived_requests = []
    if not original_routes(ctx):
        ctx.inferred_route_roots = [{"method": r["method"], "path": r["path"]} for r in roots]
    ctx.derived_requests.append(request)
    return {"accepted": True, "request": request}


def covers(ctx, plan):
    """Whether independently checked derivation covers this plan's route and input."""
    location = {"params": "query"}.get(plan.get("input_location"), plan.get("input_location"))
    return any(r["method"] == plan.get("method", "GET")
               and planned_route(resolve(ctx, r["path"]), resolve(ctx, plan["path"]))
               and (not location or {"location": location, "name": plan.get("input_name")} in r["inputs"])
               for r in getattr(ctx, "derived_requests", []))
