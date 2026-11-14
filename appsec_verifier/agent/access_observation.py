"""Operator-selected harmless observations for access comparisons (VER-010/057/061)."""

from __future__ import annotations

import json
from urllib.parse import unquote_plus

from .experiments import pointer_value


def selected_observation(ctx, path, method="GET"):
    policies = [p for p in getattr(ctx, "scope", {}).get("access_policies", [])
                if p["finding_id"] == ctx.plan.id and p["path"] == path
                and p.get("method", "GET") == method and p.get("observation")]
    return policies[0]["observation"] if len(policies) == 1 else None


def matches(body, observation, sent=None):
    """Exact selected field or non-reflected text; malformed JSON never establishes a match."""
    if not observation:
        return False
    value = observation["value"]
    if sent is not None:
        encoded = json.dumps(sent, ensure_ascii=False, sort_keys=True)
        needle = value if isinstance(value, str) else json.dumps(value)
        for _ in range(4):
            if needle in encoded:
                return False
            encoded = unquote_plus(encoded)
    try:
        if observation["pointer"]:
            actual = pointer_value(body, observation["pointer"])
            return type(actual) is type(value) and actual == value
        return isinstance(value, str) and value in body
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        return False


def exposure_check(ctx, history, cited, plan, *, negative=False):
    if negative:
        return "declared exposure supports no negative verdict"
    resource = next((r for r in ctx.scope.get("test_resources", [])
                     if r["finding_id"] == ctx.plan.id and r["id"] == plan.get("resource")
                     and r.get("anonymous_only")), None)
    if not resource or not resource.get("restriction") or not resource.get("source"):
        return "exposure needs an operator-declared restriction and harmless marker"
    reads, controls = [], []
    for n in set(cited or []):
        h = history[n - 1] if type(n) is int and 0 < n <= len(history) else {}
        args, result = h.get("args", {}), h.get("result", {})
        if (h.get("tool") != "http_request" or args.get("comparison") is not True
                or args.get("role") or args.get("method", "GET") != "GET"
                or args.get("params", {}) != resource.get("params", {})):
            return "cite only the generated anonymous exposure comparison"
        response = getattr(ctx, "responses", {}).get(n, {})
        if not response.get("complete") or type(result.get("status")) is not int:
            return "exposure comparison is incomplete"
        match = response.get("exposure_match")
        if args.get("path") == resource["path"]:
            reads.append(200 <= result["status"] < 300 and match is True)
        elif args.get("path") == plan.get("control_path"):
            controls.append(match is False and result["status"] < 500)
        else:
            return "exposure comparison cites another resource"
    if len(reads) != 2 or not all(reads) or len(controls) != 1 or not all(controls):
        return "exposure needs two matching anonymous reads and a marker-free neighbouring control"
    return None
