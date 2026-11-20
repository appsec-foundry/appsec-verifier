"""Separate observed access from operator-established restrictions (VER-010, VER-046, VER-057).

Policies describe intended access only. They grant no route, identity, write permission or proof.
Model interpretations never create policy entries. Where the operator declares nothing for a request, the
Verifier assumes the restriction the checked comparison implies, unless the run is limited to declared access
(--declared-access-only); the result marks that restriction as assumed. An operator's access rule says who may use
a request; it takes precedence over the assumption.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..verification_context import record_segment, route_matches
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


# The restriction the Verifier assumes for each comparison form of a finding where the operator declares none.
FINDING_RESTRICTIONS = {
    "signed_in": "The request requires a signed-in account.",
    "reference": "Only a privileged account may use the function.",
    "owner": "Only the account that owns the record may read or change it.",
}


def _compared(ctx, plan, form):
    """The request and identities of the checked comparison `form`: the identity it reads or changes as, and the
    identities whose access it observed."""
    operation = plan.get("change") or plan
    denied = (["anonymous"] if form == "signed_in" else
              sorted(set(normal_roles(getattr(ctx, "identities", []))) - {plan[form]}))
    return {"path": urlsplit(operation.get("path", "")).path, "method": operation.get("method", "GET"),
            "allowed_roles": [plan[form]], "denied_roles": denied}


def finding_restriction(ctx, history):
    """The restriction the Verifier assumes for the comparison form that was checked, unless the run is limited to
    declared access (VER-010). The text comes from the form, never from a model."""
    if getattr(ctx, "assume_restrictions", False) is not True:
        return None
    _, plan = latest_plan(history)
    form = next((f for f in FINDING_RESTRICTIONS if plan.get(f)), None)
    if form is None:
        return None
    return {"source": f"assumed by the Verifier for finding {ctx.plan.id}; no rule was declared for the request",
            "restriction": FINDING_RESTRICTIONS[form], "assumed": True, **_compared(ctx, plan, form)}


# Who may use a request by the operator's access rule (VER-010), and which rules the access each comparison form
# observes breaks: a request without credentials every rule but anyone, another normal account's read or change of
# the owner's record owner and admin, a normal account's answer identical to the privileged one admin.
ACCESS_RULES = {
    "owner": "Only the account that owns the record may read or change it.",
    "signed-in": "The request requires a signed-in account.",
    "admin": "Only an admin may use the request.",
    "anyone": "Anyone may use the request, also without signing in.",
}
BROKEN_BY = {"signed_in": {"owner", "signed-in", "admin"}, "owner": {"owner", "admin"}, "reference": {"admin"}}


def access_rule(scope, method: str, path: str):
    """The operator's access rule for a request, matched by method and route, or None."""
    for rule in (scope or {}).get("access_rules", []):
        rule_method, _, rule_path = rule["request"].partition(" ")
        if rule_method == method and route_matches(rule_path, urlsplit(path).path):
            return rule
    return None


def rule_requests(plan, *, writes: bool) -> list[tuple[str, str]]:
    """The requests of `plan` an access comparison reads or, with `writes`, changes, whose rule decides it: the GET
    requests the finding names, also for a route it names for every method (`ALL`), which a comparison reads with a
    GET, and the writes that change a record by its identifier."""
    variants = (getattr(plan, "verification_context", None) or {}).get("variants", [])
    named = [(v["request"].get("method", "GET"), v["request"].get("path", "")) for v in variants] or [
        (e.method, e.path) for e in getattr(plan, "endpoints", ())]
    requests = []
    for method, path in named:
        method, path = "GET" if method == "ALL" else method, urlsplit(path).path
        if re.fullmatch(r"/[^?#\s]{0,2000}", path) and (method == "GET" or (
                writes and method in ("PUT", "PATCH") and record_segment(path) is not None)):
            if (method, path) not in requests:
                requests.append((method, path))
    return requests


def operator_restriction(ctx, history):
    """(rule, restriction): the operator's access rule for the checked comparison's request, and the restriction
    it establishes when the observed access breaks it, else None (VER-010)."""
    _, plan = latest_plan(history)
    form = next((f for f in FINDING_RESTRICTIONS if plan.get(f)), None)
    operation = plan.get("change") or plan
    rule = access_rule(getattr(ctx, "scope", None), operation.get("method", "GET"), operation.get("path", ""))
    if rule is None or form is None or rule["may"] not in BROKEN_BY[form]:
        return rule, None
    return rule, {"source": f"the operator's access rule for {rule['request']} ({rule.get('source') or 'scope'})",
                  "restriction": ACCESS_RULES[rule["may"]], **_compared(ctx, plan, form)}


def established_restriction(ctx, history, cited):
    """(rule, restriction): what a checked comparison is judged by (VER-010), for the final check and for the
    feedback the agent gets after the comparison alike. A declared policy or resource decides first, then the
    operator's access rule for the request, and only without such a rule the restriction the Verifier assumes. The
    rule is returned whenever one exists, so a caller can say that it allows the observed access."""
    rule, policy = None, restriction(ctx, history, cited)
    if policy is None:
        rule, policy = operator_restriction(ctx, history)
    if policy is None and rule is None:
        policy = finding_restriction(ctx, history)
    return rule, policy


def require_restriction(ctx, history, cited, result):
    """Retain the checked comparison as an observation when its authorization meaning is unestablished. An
    operator's access rule for the request decides before the assumed restriction."""
    if result.verdict != "confirmed" or getattr(ctx.plan, "cls", None) != "access-control":
        return result
    rule, policy = established_restriction(ctx, history, cited)
    if policy is not None:
        result.proof["access_restriction"] = policy
        return result
    result.verdict, result.confidence = "inconclusive", "low"
    if rule is not None:
        result.proof.update(checked=False, observed_access=True,
                            missing=["the observed access does not break the operator's access rule"])
        result.observations = [*result.observations, "The recorded comparison established access that the "
                               f"operator's access rule for {rule['request']} allows."]
        result.rationale = (f"Access observed, but the operator's access rule allows it: {ACCESS_RULES[rule['may']]} "
                            "Only a comparison whose access breaks the rule can confirm.")
        return result
    result.proof.update(checked=False, observed_access=True,
                        missing=["observed access has no independently established access restriction"])
    result.observations = [*result.observations, "The recorded comparison established access; whether it violates "
                           "the application's intended access policy remains unproven."]
    result.rationale = "Access observed, authorization violation unproven: say who may use the request in " \
                       "scope.access_rules, declare the expected restriction and its source in " \
                       "scope.access_policies, or use an operator-declared test resource."
    return result


def apply_intent_review(result, review):
    """A QA objection can invalidate a confirmation, never establish a missing restriction."""
    if result.verdict == "confirmed" and review.get("issues"):
        result.verdict, result.confidence = "inconclusive", "low"
        result.proof = {**(result.proof or {}), "checked": False, "observed_access": True,
                        "missing": ["unresolved technical objection to the intended access restriction"]}
        result.rationale = "Access observed; technical QA left the expected restriction unresolved."
    return result
