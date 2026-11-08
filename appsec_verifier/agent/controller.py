"""Deterministic action authority and finite repetition allowances (VER-008, VER-010, VER-014, VER-015, VER-036).

ScopeGuard remains the connection authority. Assessment routes only narrow
that scope; neither model plans nor target responses can add routes here.
An accepted plan narrows requests to its route and method; under an
own-resource access-control plan its owner may also write to the finding's
routes, to create the resource it then reads back. Every write carries the
finding's marker and names no existing record in its path (VER-014).
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from ..limits import LimitExceeded, execution_deadline
from ..tools.http import SAFE_METHODS, same_origin
from ..verification_context import record_segment, route_matches
from .experiments import token
from .tools import ToolError, _strings


class Controller:
    def __init__(self, ctx):
        self.ctx = ctx
        self.repetitions = Counter()
        self.failures = 0
        self.plan = None
        self.source_routes = []
        self._counted = None  # the repetition key the last before() call charged

    def check(self):
        self.ctx.guard.check_window()
        self.ctx.budget.check_time()
        if self.failures >= 3:
            raise LimitExceeded("stagnation", "three consecutive actions failed without a usable observation")

    def before_model(self):
        self.check()
        budget = self.ctx.budget
        if budget.requests >= budget.limits.max_requests:
            raise LimitExceeded("requests", "request cap reached")

    def run(self, operation):
        self.check()
        seconds = self.ctx.budget.remaining_time()
        window = self.ctx.guard.remaining_time()
        kind = "window" if window is not None and window <= seconds else "time"
        with execution_deadline(min(seconds, window) if window is not None else seconds, kind=kind):
            result = operation()
        self.check()
        return result

    def _routes(self):
        p = self.ctx.plan
        variants = p.verification_context.get("variants", [])
        if p.variant_id:
            variants = [v for v in variants if v["id"] == p.variant_id]
        if variants or p.variant_id:
            return [v["request"] for v in variants]
        routes = [{"method": e.method, "path": e.path} for e in p.endpoints]
        for key in ("test_resources", "injection_inputs", "session_checks"):
            routes.extend({"method": r.get("method", "GET"), "path": r["path"]}
                          for r in self.ctx.scope.get(key, []) if r["finding_id"] == p.id)
        return routes + self.source_routes

    def _matches(self, template, path):
        def resolved(value):
            return value if urlsplit(value).scheme else self.ctx.target_base.rstrip("/") + "/" + value.lstrip("/")

        if not route_matches(resolved(template), resolved(path)):
            return False
        expected, actual = urlsplit(template).fragment, urlsplit(path).fragment
        return not expected or route_matches(expected, actual)

    def _target(self, name, args):
        path = args.get("path", "/")
        method = args.get("method", "GET").upper()
        try:
            parsed = urlsplit(path)
        except ValueError as exc:
            raise ToolError("the path is not a parseable URL path") from exc
        url = path if parsed.scheme else self.ctx.target_base.rstrip("/") + "/" + path.lstrip("/")
        decision = self.ctx.guard.authorize(url, "target")
        if not decision.allowed:
            raise ToolError(f"request refused — out of scope: {decision.reason}")
        if not same_origin(url, self.ctx.target_base):
            raise ToolError("the finding's requests must use its target origin")
        route_path = path
        matching = [r for r in self._routes() if (r["method"] in (method, "ALL")
                    or r["method"] == "PAGE" and method == "GET")
                    and self._matches(r["path"], route_path)]
        if not matching:
            raise ToolError("request has no matching route in this finding or its operator-declared resources")
        if name == "http_request" and method not in SAFE_METHODS and not any(
                r["finding_id"] == self.ctx.plan.id and r["path"] == path and r.get("method", "GET") == method
                for r in self.ctx.scope.get("test_resources", [])):
            self._write_allowed(path, args, matching)
        # Under an own-resource plan the owner, and only the owner, may also write to the finding's routes (VER-010).
        owner_write = (name == "http_request" and self.plan and self.plan.get("owner") and method not in SAFE_METHODS
                       and args.get("role") == self.plan["owner"])
        if name != "plan_test" and self.plan and not owner_write and (
            not self._matches(self.plan["path"], route_path) or method != self.plan.get("method", "GET")
        ):
            raise ToolError("request does not match the accepted test plan")
        if name == "http_request" and self.plan:
            plan = self.plan
            if plan.get("kind") in ("boolean", "timing"):
                supplied = {k: dict(args.get(k) or {}) for k in ("params", "json", "form")}
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                names = [k for k, _ in pairs] + list(supplied["params"])
                if len(names) != len(set(names)):
                    raise ToolError("experiment requests cannot contain duplicate query inputs")
                supplied["params"].update(pairs)
                selected = supplied.pop(plan["input_location"], {})
                controls = [plan[k] for k in ("baseline", "positive", "negative", "positive_other", "negative_other")
                            if k in plan]
                if (set(selected) != {plan["input_name"]} or any(supplied.values())
                        or token(selected.get(plan["input_name"])) not in {token(v) for v in controls}):
                    raise ToolError("request must use the accepted experiment's input and control values")
            if plan.get("kind") == "access-control" and plan.get("resource"):
                resource = next((r for r in self.ctx.scope.get("test_resources", [])
                                 if r["finding_id"] == self.ctx.plan.id and r["id"] == plan.get("resource")), None)
                if (parsed.query != urlsplit(plan["path"]).query or resource is None
                        or any((args.get(k) or {}) != (resource.get(k) or {})
                                           for k in ("params", "json", "form"))):
                    raise ToolError("request must use the accepted access-control resource inputs")
                if (args.get("role") or "anonymous") not in resource["allowed_roles"] + resource["denied_roles"]:
                    raise ToolError("request role is not declared for the accepted resource")
        # Variant input declarations constrain query/body names, not payload values.
        for r in matching:
            if "inputs" not in r:
                return
            names = {"query": set(), "json": set(), "form": set()}
            for i in r["inputs"]:
                if i["location"] in names:
                    names[i["location"]].add(i["name"])
            query = {k for k, _ in parse_qsl(urlsplit(path).query)} | set(args.get("params") or {})
            if name == "browser_check":
                query |= {k for k, _ in parse_qsl(urlsplit(urlsplit(path).fragment).query)}
            if query <= names["query"] and all(set(args.get(k) or {}) <= names[k] for k in ("json", "form")):
                return
        raise ToolError("request inputs do not match the finding variant")

    def _write_allowed(self, path, args, matching):
        """VER-014: a write carries the finding's marker, so what it changes can be found and attributed, and
        names no existing record by its identifier in the URL path, since that record may belong to someone
        else. An operator-declared test resource is exempt. Identifiers in a body are not recognised."""
        part = (getattr(self.ctx, "marker", None) or ("",))[0]
        if not part:
            raise ToolError("this finding has no marker, so it sends no write (VER-014)")
        sent = [path, *(v for k in ("params", "json", "form") for v in _strings(args.get(k)))]
        if not any(part in v for v in sent if isinstance(v, str)):
            raise ToolError(f"a write must carry {part} in its path or a value, so the change can be found "
                            "(VER-014)")
        segment = next(filter(None, (record_segment(r["path"], path) for r in matching)), None)
        if segment is not None:
            raise ToolError(f"a write must not name an existing record in its path ({segment[:80]!r}): it may "
                            "create, never change what may belong to someone else (VER-014)")

    def _key(self, name, args):
        args = dict(args)
        if name == "plan_test":
            args = {k: v for k, v in args.items() if k not in ("strategy", "hypothesis")}
        if name in ("http_request", "browser_check"):
            args["method"] = args.get("method", "GET").upper()
            args["role"] = args.get("role") or None
            for field in ("params", "json", "form"):
                if not args.get(field):
                    args.pop(field, None)
            # Equivalent query ordering and spelling of URL encoding cannot buy extra attempts.
            path = args.get("path", "/")
            parsed = urlsplit(path if urlsplit(path).scheme else
                              self.ctx.target_base.rstrip("/") + "/" + path.lstrip("/"))
            query = parse_qsl(parsed.query, keep_blank_values=True)
            query.extend((k, str(v)) for k, v in (args.pop("params", {}) or {}).items())
            args["path"] = parsed._replace(query="").geturl()
            args["query"] = sorted(query)
        return token([name, args])

    def before(self, name, args):
        self._counted = None
        self.check()
        if name in ("http_request", "browser_check", "plan_test"):
            self._target(name, args)
        key = self._key(name, args)
        allowance = 1 if name == "http_request" and args.get("method", "GET").upper() not in SAFE_METHODS else 2
        if self.repetitions[key] >= allowance:
            raise LimitExceeded("stagnation", "action repetition allowance exhausted; no further execution")
        self.repetitions[key] += 1
        self._counted = key

    def refuse(self):
        """A tool call the step contract refused (steps.py): nothing ran, and it counts as a failed action."""
        self._counted = None
        self.failures += 1

    def observe(self, name, args, result):
        failed = bool(result.get("error")) or (type(result.get("status")) is int and result["status"] >= 500)
        if failed:
            self.failures += 1
            if name == "plan_test" and self._counted is not None:
                # A rejected plan executed nothing, and its key leaves out the strategy it was rejected for:
                # the corrected plan keeps the allowance. Repeated rejections still stop after three failures.
                self.repetitions[self._counted] -= 1
        elif name == "plan_test":
            if result.get("accepted"):
                self.plan = result.get("experiment") or args
        else:
            self.failures = 0
            # Only the nearest preceding literal route at the evidenced source location.
            # Source text narrows the operator's scope; model prose never supplies a route.
            if name == "read_source" and args.get("path") == (self.ctx.plan.instance or "").rsplit(":", 1)[0]:
                pattern = (r'(?m)^\s*(?:(?:app|router)\.)?(get|post|put|patch|head|options)'
                           r'''\(\s*['"](/[^'"\s]{0,500})['"]''')
                location = (self.ctx.plan.instance or "").rsplit(":", 1)[-1]
                text = result.get("text", "")
                candidates = [m for m in re.finditer(pattern, text, re.IGNORECASE)
                              if location.isdigit() and 0 <= int(location)
                              - (result.get("start_line", 1) + text[:m.start()].count("\n")) <= 40]
                for match in candidates[-1:]:
                    route = {"method": match[1].upper(), "path": match[2]}
                    if route not in self.source_routes and len(self.source_routes) < 4:
                        self.source_routes.append(route)
