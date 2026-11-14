"""Separate observed access from operator-established restrictions (VER-010, VER-046, VER-057).

Policies describe intended access only. They grant no route, identity, write permission or proof.
Finding claims and model interpretations never create policy entries.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..verification_context import route_matches
from .experiments import latest_plan, normal_roles


def restriction(ctx, history, cited):
    """Return the applicable declared restriction, only for a successful denied-identity read/write."""
    _, plan = latest_plan(history)
    scope = getattr(ctx, "scope", None) or {}
    resources = scope.get("test_resources", [])
    resource = next((r for r in resources if r.get("finding_id") == ctx.plan.id
                     and r.get("id") == plan.get("resource")), None)
    if resource is not None:
        return {"source": resource.get("source", "scope.test_resources:" + resource["id"]),
                "restriction": resource.get("restriction", "Operator-declared test resource access"),
                "allowed_roles": resource["allowed_roles"], "denied_roles": resource["denied_roles"],
                "path": resource["path"], "method": resource.get("method", "GET")}
    operation = plan.get("change") or plan
    allowed_role = plan.get("signed_in") or plan.get("reference") or plan.get("owner")
    tested_denied = ({"anonymous"} if plan.get("signed_in") else
                     set(normal_roles(getattr(ctx, "identities", []))) - {allowed_role})
    for policy in scope.get("access_policies", []):
        if (policy.get("finding_id") != ctx.plan.id
                or policy.get("method", "GET") != operation.get("method", "GET")
                or not route_matches(urlsplit(operation.get("path", "")).path, policy["path"])):
            continue
        allowed, denied = set(policy["allowed_roles"]), set(policy["denied_roles"])
        if allowed & denied or allowed_role not in allowed:
            continue
        seen = set()
        for n in cited or []:
            if type(n) is not int or not 1 <= n <= len(history):
                continue
            h = history[n - 1]
            args, result = h.get("args", {}), h.get("result", {})
            # Policy paths are exact and apply across inputs. No wildcard or prefix widens policy.
            actual = urlsplit(args.get("path", ""))
            path = actual.path
            if (h.get("tool") == "http_request" and not actual.fragment
                    and path == policy["path"] and args.get("method", "GET").upper() == policy.get("method", "GET")
                    and type(result.get("status")) is int and 200 <= result["status"] < 300):
                seen.add(args.get("role") or "anonymous")
        if seen & denied & tested_denied:
            return {"method": policy.get("method", "GET"),
                    **{k: policy[k] for k in ("source", "restriction", "path", "allowed_roles", "denied_roles")},
                    **({"observation": policy["observation"]} if policy.get("observation") else {})}
    return None


def require_restriction(ctx, history, cited, result):
    """Retain the checked comparison as an observation when its authorization meaning is unestablished."""
    if result.verdict != "confirmed" or getattr(ctx.plan, "cls", None) != "access-control":
        return result
    policy = restriction(ctx, history, cited)
    if policy is not None:
        result.proof["access_restriction"] = policy
        return result
    result.verdict, result.confidence = "inconclusive", "low"
    result.proof.update(checked=False, observed_access=True,
                        missing=["observed access has no independently established access restriction"])
    result.observations = [*result.observations, "The recorded comparison established access; whether it violates "
                           "the application's intended access policy remains unproven."]
    result.rationale = "Access observed, authorization violation unproven: declare the expected restriction and " \
                       "its source in scope.access_policies or use an operator-declared test resource."
    return result


def apply_intent_review(result, review):
    """A QA objection can invalidate a confirmation, never establish a missing restriction."""
    if result.verdict == "confirmed" and review.get("issues"):
        result.verdict, result.confidence = "inconclusive", "low"
        result.proof = {**(result.proof or {}), "checked": False, "observed_access": True,
                        "missing": ["unresolved technical objection to the intended access restriction"]}
        result.rationale = "Access observed; technical QA left the expected restriction unresolved."
    return result
