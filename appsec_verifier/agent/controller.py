"""Deterministic action authority and finite repetition allowances (VER-008, VER-010, VER-014, VER-015, VER-036,
VER-043).

ScopeGuard remains the connection authority. Assessment routes and independently
checked request derivations narrow that scope; model plans alone add nothing.
An injection experiment narrows requests to its route and method; under an
own-resource access-control plan its owner may also write to the finding's
routes, and to the POST collection route the assessment names for one of its
record routes, to create the resource it then reads back; the latter is
recorded as a deviation (VER-008, VER-043). Every write carries the
finding's marker and names no existing record in its path (VER-014). The one
exception is a write proof (VER-010): under a plan with a change, another
normal account may send that change to the record the owner's write created
and its read showed with the marker (ctx.owned), and a GET on the change's path
may read what the creating answer returned (ctx.created) when the finding names
no read. Both come from the target's answers (agent/tools.py), never from the
model.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlsplit

from ..limits import LimitExceeded, execution_deadline
from ..tools.http import SAFE_METHODS, same_origin
from ..verification_context import planned_route, record_segment, record_segments
from .experiments import normal_roles, token
from .tools import ToolError, _strings


def _route_list(routes) -> str:
    """Compact rendering of the routes the controller will accept, for a tool error that the model reads."""
    seen, out = set(), []
    for r in routes:
        key = (r.get("method", "GET"), r.get("path", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f"{key[0]} {key[1]}")
        if len(out) == 8:
            break
    return ", ".join(out) if out else "no route in this finding"


class Controller:
    def __init__(self, ctx):
        self.ctx = ctx
        self.repetitions = Counter()
        self.failures = 0
        self.plan = None
        self.source_routes = []
        self.deviations = []  # preparation routes the owner used outside the finding's own (VER-008, VER-043)
        self._counted = None  # the repetition key the last before() call charged
        self._preparing = None  # the preparation route of the action before() last allowed
        # Non-sink inputs pinned on the first probe of an accepted boolean/timing experiment, so
        # later probes carry the same accompanying fields and only the sink value differs. Reset on
        # every freshly accepted plan.
        self._experiment_shape = None

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

    def _routes(self, change=None):
        """The finding's routes; with `change`, a write of the finding that changes a record (VER-010), also a GET
        on its path, marked derived: it may read only what the owner created, to observe the change."""
        p = self.ctx.plan
        variants = p.verification_context.get("variants", [])
        if p.variant_id:
            variants = [v for v in variants if v["id"] == p.variant_id]
        if variants or p.variant_id:
            routes = [v["request"] for v in variants]
            routes += [{"method": e.method, "path": e.path} for e in p.endpoints
                       if not any(r["method"] == e.method and self._matches(r["path"], e.path) for r in routes)]
        else:
            routes = [{"method": e.method, "path": e.path} for e in p.endpoints]
        for key in ("test_resources", "injection_inputs", "session_checks"):
            routes.extend({"method": r.get("method", "GET"), "path": r["path"]}
                          for r in self.ctx.scope.get(key, []) if r["finding_id"] == p.id)
        routes += [r for r in self.source_routes if not any(
            v["method"] == r["method"] and self._matches(v["path"], r["path"]) for v in routes)]
        routes += getattr(self.ctx, "derived_requests", [])
        if (self.plan or {}).get("kind") == "access-control" and self.plan.get("owner"):
            routes += [{"method": e.method, "path": e.path, "preparation": True}
                       for e in getattr(p, "preparation", ())]
        if change and self._names_change(routes, change):
            routes = [*routes, {"method": "GET", "path": change["path"], "derived": True}]
        return routes

    def _names_change(self, routes, change) -> bool:
        return isinstance(change, dict) and any(
            r["method"] in (change.get("method"), "ALL") and self._matches(r["path"], change.get("path", ""))
            for r in routes)

    def _matches(self, template, path):
        def resolved(value):
            return value if urlsplit(value).scheme else self.ctx.target_base.rstrip("/") + "/" + value.lstrip("/")

        return planned_route(resolved(template), resolved(path))

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
        change = args.get("change") if name == "plan_test" else (self.plan or {}).get("change")
        if name == "plan_test" and change and not self._names_change(self._routes(), change):
            writes = [r for r in self._routes() if r.get("method") not in SAFE_METHODS]
            raise ToolError("change must be a write request this finding names"
                            + (f"; writes it names: {_route_list(writes)}" if writes else ""))
        matching = [r for r in self._routes(change) if (r["method"] in (method, "ALL")
                    or r["method"] == "PAGE" and method == "GET")
                    and self._matches(r["path"], route_path)]
        if matching and all(r.get("preparation") for r in matching):
            if name != "http_request" or args.get("role") != (self.plan or {}).get("owner"):
                raise ToolError("preparation is only for the accepted test resource owner")
            self._preparing = f"{method} {matching[0]['path']}"   # a deviation once it is answered (observe)
        if not matching:
            raise ToolError("request has no matching route in this finding or its operator-declared resources; "
                            f"allowed: {_route_list(self._routes(change))}")
        if name != "plan_test" and all(r.get("derived") for r in matching) and not self._created(change, path):
            raise ToolError("a GET the finding does not name may read only the record the owner created (VER-010)")
        # Under a change plan another normal account writes the second marker to what the owner created (VER-010).
        plan = self.plan or {}
        change_write = bool(name == "http_request" and change and method == change["method"]
                            and args.get("role") in normal_roles(self.ctx.identities)
                            and args.get("role") != plan.get("owner") and self._matches(change["path"], route_path))
        if name == "http_request" and method not in SAFE_METHODS and not any(
                r["finding_id"] == self.ctx.plan.id and r["path"] == path and r.get("method", "GET") == method
                for r in self.ctx.scope.get("test_resources", [])):
            self._write_allowed(path, args, matching, created=change_write and self._created(change, path, "owned"))
        # Under an own-resource plan the owner, and only the owner, may also write to the finding's routes (VER-010).
        owner_write = (name == "http_request" and self.plan and self.plan.get("owner") and method not in SAFE_METHODS
                       and args.get("role") == self.plan["owner"])
        if (name != "plan_test" and self.plan
                and (self.plan.get("kind") in ("boolean", "timing", "access-control") or self.plan.get("resource"))
                and not owner_write and not change_write and (
            not self._matches(self.plan["path"], route_path) or method != self.plan.get("method", "GET")
        )):
            raise ToolError("request does not match the accepted test plan")
        if name == "http_request" and self.plan:
            plan = self.plan
            if plan.get("kind") in ("boolean", "timing"):
                supplied = {k: dict(args.get(k) or {}) for k in ("params", "json", "form", "path_inputs")}
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                query_names = [k for k, _ in pairs] + list(supplied["params"])
                if len(query_names) != len(set(query_names)):
                    raise ToolError("experiment requests cannot contain duplicate query inputs")
                supplied["params"].update(pairs)
                location = "path_inputs" if plan["input_location"] == "path" else plan["input_location"]
                selected = supplied[location]
                controls = [plan[k] for k in ("baseline", "positive", "negative", "positive_other", "negative_other")
                            if k in plan]
                sink = selected.get(plan["input_name"])
                if plan["input_name"] not in selected or token(sink) not in {token(v) for v in controls}:
                    values = ", ".join(repr(str(v)[:60]) for v in controls)
                    raise ToolError(
                        "request must carry the accepted experiment's sink value; "
                        f"send {plan['input_name']!r} in {plan['input_location']} with one of {values}"
                    )
                # Everything except the sink is the request's "shape"; pin it on the first probe and
                # require every subsequent probe to match. This lets the agent fulfil an endpoint's
                # other required fields (a rating next to the vulnerable comment) without opening the
                # door to varying them between baseline, positive and negative — which would make the
                # proof compare answers that differ for the wrong reason (VER-011).
                shape = {k: tuple(sorted((kk, str(vv)) for kk, vv in v.items())) for k, v in supplied.items()
                         if k != location}
                shape[location] = tuple(sorted((kk, str(vv)) for kk, vv in selected.items()
                                                if kk != plan["input_name"]))
                if self._experiment_shape is None:
                    self._experiment_shape = shape
                elif shape != self._experiment_shape:
                    expected = {k: dict(v) for k, v in self._experiment_shape.items() if v}
                    raise ToolError(
                        "experiment requests must keep the non-sink fields identical across all probes "
                        f"so the comparison rests on the sink alone; first probe used {expected}"
                    )
            if plan.get("kind") == "access-control" and plan.get("resource"):
                resource = next((r for r in self.ctx.scope.get("test_resources", [])
                                 if r["finding_id"] == self.ctx.plan.id and r["id"] == plan.get("resource")), None)
                if (parsed.query != urlsplit(plan["path"]).query or resource is None
                        or any((args.get(k) or {}) != (resource.get(k) or {})
                                           for k in ("params", "json", "form"))):
                    raise ToolError("request must use the accepted access-control resource inputs")
                if (args.get("role") or "anonymous") not in resource["allowed_roles"] + resource["denied_roles"]:
                    raise ToolError("request role is not declared for the accepted resource")
        # Variant inputs are the sinks the finding claims.
        # - plan_test only declares intent (its query lives in a fragment the tool does not send), so it may
        #   not name inputs outside the declared sinks, but need not carry them: supplied ⊆ declared.
        # - an actual request (http_request, browser_check) must exercise every declared sink; fulfilling an
        #   endpoint's unrelated required fields (a rating next to the vulnerable comment, a CSRF token next
        #   to the vulnerable url) is normal and allowed: declared ⊆ supplied, extras permitted.
        declared: list[str] = []
        for r in matching:
            if "inputs" not in r:
                return
            names = {"query": set(), "json": set(), "form": set(), "path": set()}
            for i in r["inputs"]:
                if i["location"] in names:
                    names[i["location"]].add(i["name"])
                    declared.append(f"{i['location']}:{i['name']}")
            query = {k for k, _ in parse_qsl(urlsplit(path).query)} | set(args.get("params") or {})
            if name == "browser_check":
                query |= {k for k, _ in parse_qsl(urlsplit(urlsplit(path).fragment).query)}
            supplied = {"query": query, "json": set(args.get("json") or {}), "form": set(args.get("form") or {}),
                        "path": set(args.get("path_inputs") or {})}
            if name == "plan_test":
                if all(supplied[k] <= names[k] for k in ("query", "json", "form", "path")):
                    return
            elif all(names[k] <= supplied[k] for k in ("query", "json", "form", "path")):
                return
        seen = []
        for d in declared:
            if d not in seen:
                seen.append(d)
        allowed = ", ".join(seen[:8]) if seen else "no inputs declared"
        verb = "may only use" if name == "plan_test" else "must carry"
        raise ToolError(f"request {verb} the finding's declared variant inputs: {allowed}")

    def _created(self, change, path, which="created") -> bool:
        """Whether every record `path` names is one the owner's write created in this finding (VER-010):
        `created`, returned by its creating answer, or `owned`, which the owner's read then showed with its
        marker."""
        segments = record_segments(change["path"], path) if isinstance(change, dict) else []
        ids = getattr(self.ctx, which, None) or set()
        return bool(segments) and all(unquote(s) in ids for s in segments)

    def _write_allowed(self, path, args, matching, *, created=False):
        """VER-014: a write carries the finding's marker, so what it changes can be found and attributed, and
        names no existing record by its identifier in the URL path, since that record may belong to someone
        else. An operator-declared test resource is exempt, and `created`: the change of a record the owner's
        write created in this finding (VER-010). Identifiers in a body are not recognised."""
        part = (getattr(self.ctx, "marker", None) or ("",))[0]
        if not part:
            raise ToolError("this finding has no marker, so it sends no write (VER-014)")
        sent = [path, *(v for k in ("params", "json", "form") for v in _strings(args.get(k)))]
        if not any(part in v for v in sent if isinstance(v, str)):
            raise ToolError(f"a write must carry {part} in its path or a value, so the change can be found "
                            "(VER-014)")
        segment = next(filter(None, (record_segment(r["path"], path) for r in matching)), None)
        if segment is not None and not created:
            raise ToolError(f"a write must not name an existing record in its path ({segment[:80]!r}): it may "
                            "create, never change what may belong to someone else; only a change plan's other "
                            "account may change the record its owner created (VER-010, VER-014)")

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
        self._counted = self._preparing = None
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
        if self._preparing and type(result.get("status")) is int and self._preparing not in self.deviations:
            self.deviations.append(self._preparing)
        self._preparing = None
        status = result.get("status")
        server_error = type(status) is int and status >= 500
        # An injection experiment's http_request is a hypothesis check: a 5xx can be the whole observation
        # (stable server-side error contrasting with a working baseline, an SQL/driver error that evidences
        # the sink). The verdict logic in proof.py still gates what a 5xx can actually prove; the controller
        # must not retire the experiment before the agent can run those comparisons. Outside an accepted
        # boolean/timing experiment, 5xx keeps counting as a failed action because a probe that crashes the
        # server without plan context is usually not informative.
        experiment_probe = (name == "http_request" and self.plan
                            and self.plan.get("kind") in ("boolean", "timing"))
        failed = bool(result.get("error")) or (server_error and not experiment_probe)
        if failed:
            self.failures += 1
            if name == "plan_test" and self._counted is not None:
                # A rejected plan executed nothing, and its key leaves out the strategy it was rejected for:
                # the corrected plan keeps the allowance. Repeated rejections still stop after three failures.
                self.repetitions[self._counted] -= 1
        elif name == "plan_test":
            if result.get("accepted"):
                self.plan = result.get("experiment") or args
                self._experiment_shape = None   # a fresh plan pins its own shape on the next probe
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
