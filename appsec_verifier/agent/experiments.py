"""Declared experiments and observations over recorded answers (VER-008, VER-010, VER-011, VER-013)."""

from __future__ import annotations

import json
import secrets

from ..planning import STRATEGY_SCHEMA

SCALAR = {"type": ["string", "number", "boolean"], "maxLength": 4000}
PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind", "hypothesis", "path", "strategy"],
    "properties": {
        "kind": {"enum": ["boolean", "timing", "access-control", "control", "execution", "session"]},
        "hypothesis": {"type": "string", "minLength": 10, "maxLength": 1000},
        "variant": {"type": "string", "maxLength": 80},
        "path": {"type": "string", "minLength": 1, "maxLength": 2000},
        "method": {"enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"]},
        "input_location": {"enum": ["params", "json", "form"]},
        "input_name": {"type": "string", "minLength": 1, "maxLength": 128},
        "baseline": SCALAR,
        "positive": SCALAR,
        "negative": SCALAR,
        "pointer": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^/"},
        "resource": {"type": "string", "maxLength": 80},
        "strategy": STRATEGY_SCHEMA,
        "expression_template": {"type": "string", "minLength": 5, "maxLength": 3000},
        "operator_challenge": {"enum": ["nosql"]},
        "predicate_template": {"type": "string", "minLength": 15, "maxLength": 3000},
        "predicate_attribute": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9-]{0,63}$"},
        "sql_template": {"type": "string", "minLength": 15, "maxLength": 3000},
    },
    "allOf": [
        {
            "if": {"properties": {"kind": {"const": "boolean"}}},
            "then": {"required": ["input_location", "input_name", "baseline", "pointer"]},
        },
        {
            "if": {"properties": {"kind": {"const": "timing"}}},
            "then": {"required": ["input_location", "input_name", "baseline", "positive"]},
        },
        {"if": {"properties": {"kind": {"const": "access-control"}}}, "then": {"required": ["resource"]}},
    ],
}


def sql_controls(plan):
    """Fresh complementary equality/inequality challenges; the model cannot choose their answers."""
    template = plan.get("sql_template", "")
    if template.count("{{predicate}}") != 1:
        raise ValueError("SQL proof needs a template containing exactly one {{predicate}} placeholder")
    a = 100000 + secrets.randbelow(800000)
    b = a + 1 + secrets.randbelow(9999)
    predicates = {
        "positive": f"({a}={a})",
        "negative": f"({a}={b})",
        "positive_other": f"({b}<>{a})",
        "negative_other": f"({b}<>{b})",
    }
    return {**plan, **{k: template.replace("{{predicate}}", v) for k, v in predicates.items()}}


def operator_controls(plan):
    baseline = plan["baseline"]
    absent = "vrf" + secrets.token_hex(16)
    return {
        **plan,
        "positive": {"$eq": baseline},
        "negative": {"$eq": absent},
        "positive_other": {"$in": [baseline]},
        "negative_other": {"$in": [absent]},
    }


def ldap_controls(plan):
    attribute = plan.get("predicate_attribute", "")
    template = plan["predicate_template"]
    if not attribute or template.count("{{predicate}}") != 1:
        raise ValueError("LDAP proof needs an evidenced attribute and exactly one {{predicate}}")
    a, b = secrets.token_hex(12), secrets.token_hex(12)
    predicates = {
        "positive": f"(|({attribute}={a})(!({attribute}={a})))",
        "negative": f"(&({attribute}={a})(!({attribute}={a})))",
        "positive_other": f"(|({attribute}={b})(!({attribute}={b})))",
        "negative_other": f"(&({attribute}={b})(!({attribute}={b})))",
    }
    return {
        **plan,
        "sql_template": template,
        **{k: template.replace("{{predicate}}", v) for k, v in predicates.items()},
    }


def expression_controls(plan):
    template = plan.get("expression_template", "")
    if template.count("{{expression}}") != 1:
        raise ValueError("expression proof needs exactly one {{expression}} placeholder")
    a, b = 1000 + secrets.randbelow(8000), 1000 + secrets.randbelow(8000)
    expressions = {
        "positive": (f"{a}*{b}", a * b),
        "negative": (f"{a}+{b}", a + b),
        "positive_other": (f"{a}*{b + 1}", a * (b + 1)),
        "negative_other": (f"{a}+{b + 1}", a + b + 1),
    }
    return {
        **plan,
        **{k: template.replace("{{expression}}", v[0]) for k, v in expressions.items()},
        "expected_values": {k: v[1] for k, v in expressions.items()},
    }


def pointer_value(body: str, pointer: str):
    """RFC 6901 selection only: no expressions, wildcard queries or executable selectors."""
    value = json.loads(body)
    for part in pointer.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not part.isdecimal() or (len(part) > 1 and part[0] == "0"):
                raise ValueError("invalid array index")
            value = value[int(part)]
        elif isinstance(value, dict):
            value = value[part]
        else:
            raise ValueError("pointer does not select a value")
    return value


def token(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def latest_plan(history: list[dict]):
    for n in range(len(history), 0, -1):
        h = history[n - 1]
        if h.get("tool") == "plan_test" and h.get("result", {}).get("accepted") is True:
            return n, h.get("result", {}).get("experiment") or h["args"]
    return 0, {}


def observation(ctx, step, pointer):
    response = getattr(ctx, "responses", {}).get(step)
    if not response or not response.get("complete"):
        raise ValueError("recorded response unavailable or truncated")
    return pointer_value(response["body"], pointer)


def experiment_groups(history, cited):
    start, plan = latest_plan(history)
    if not start:
        return {}, {}, "declare a plan_test before collecting proof"
    groups = {k: [] for k in ("baseline", "positive", "negative", "positive_other", "negative_other") if k in plan}
    signatures = set()
    for n in cited:
        if n <= start:
            return plan, {}, "proof must be collected after the declared plan"
        h = history[n - 1]
        args, result = h.get("args", {}), h.get("result", {})
        if h.get("tool") != "http_request" or not isinstance(result.get("status"), int):
            return plan, {}, "proof needs answered target requests"
        if args.get("path") != plan["path"] or (args.get("method") or "GET").upper() != plan.get("method", "GET"):
            return plan, {}, "proof requests do not match the declared target"
        values = dict(args.get(plan.get("input_location")) or {})
        value = values.pop(plan.get("input_name"), None)
        fixed = {k: args.get(k) or {} for k in ("params", "json", "form", "headers")}
        fixed[plan.get("input_location", "params")] = values
        signatures.add(token([args.get("role"), fixed]))
        bucket = next((k for k in groups if token(value) == token(plan[k])), None)
        if bucket is None:
            return plan, {}, "a cited request did not use a declared control value"
        groups[bucket].append((n, result))
    if len(signatures) != 1:
        return plan, {}, "only the declared input may change; identity and other inputs must stay fixed"
    return plan, groups, None


def injection_check(ctx, history, cited):
    plan, groups, error = experiment_groups(history, cited)
    if error:
        return error
    if plan.get("kind") not in ("boolean", "timing"):
        return "declare a boolean or timing experiment for injection"
    if any(len(group) < 2 for group in groups.values()):
        return "repeat every declared input at least twice using distinct requests"
    statuses = {r["status"] for group in groups.values() for _, r in group}
    if len(statuses) != 1 or not all(200 <= s < 300 for s in statuses):
        return "error/status changes alone do not prove injection; obtain comparable successful responses"
    if plan["kind"] == "timing":
        fast, slow = groups["baseline"], groups["positive"]
        order = ["baseline" if n in {s for s, _ in fast} else "positive" for n in sorted(cited)]
        if any(a == b for a, b in zip(order, order[1:], strict=False)):
            return "alternate timing controls and delayed requests"
        times = [r.get("elapsed_ms") for group in (fast, slow) for _, r in group]
        if any(type(t) is not int or t < 0 for t in times):
            return "every timing observation needs a measured duration"
        gap = min(r["elapsed_ms"] for _, r in slow) - max(r["elapsed_ms"] for _, r in fast)
        largest_gap = max(r["elapsed_ms"] for _, r in slow) - min(r["elapsed_ms"] for _, r in fast)
        if gap < 2000 or largest_gap > 5000:
            return "the repeated timing separation must be between 2 and 5 seconds"
        # Timing proof cannot rely on different result types or an ordinary expensive result set.
        if len({(r.get("body_sha256"), r["status"]) for g in groups.values() for _, r in g}) != 1:
            return "timing controls must return the same response"
        return "timing separation alone cannot distinguish injection from ordinary computation; use SQL challenges"
    if plan.get("expression_template"):
        try:
            expected = plan["expected_values"]
            if any(str(value) in plan[name] for name, value in expected.items()):
                return "computed answers must not appear in the supplied expression"
            for name, group in groups.items():
                if name == "baseline":
                    continue
                if any(str(observation(ctx, n, plan["pointer"])) != str(expected[name]) for n, _ in group):
                    return "fresh arithmetic expressions were not evaluated to the expected distinct answers"
            if len({str(observation(ctx, n, plan["pointer"])) for n, _ in groups["baseline"]}) != 1:
                return "the baseline observation is unstable"
        except (ValueError, KeyError, IndexError, TypeError):
            return "the expression observation is unavailable"
        return None
    if (
        not (plan.get("sql_template") or plan.get("operator_challenge"))
        or not {"positive_other", "negative_other"} <= groups.keys()
    ):
        return "ordinary input-dependent results are not proof; use fresh complementary SQL predicate challenges"
    observed = {}
    try:
        for name, group in groups.items():
            values = [observation(ctx, n, plan["pointer"]) for n, _ in group]
            encoded = {token(v) for v in values}
            if len(encoded) != 1:
                return "the selected observation is unstable across repetitions"
            if any(str(plan[k]) in token(v) for k in groups if k != "baseline" for v in values):
                return "the selected observation reflects the test input"
            observed[name] = values[0]
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        return "the declared JSON observation is missing or incomplete"
    if observed["baseline"] in (None, "", [], {}) or token(observed["baseline"]) != token(observed["positive"]):
        return "the true condition must reproduce the nonempty baseline observation"
    if token(observed["negative"]) == token(observed["positive"]):
        return "the false condition did not change the selected observation"
    if token(observed["positive_other"]) != token(observed["baseline"]) or token(observed["negative_other"]) != token(
        observed["negative"]
    ):
        return "complementary SQL predicates did not reproduce the same true and false observations"
    return None


def access_observations(ctx, history, cited):
    start, plan = latest_plan(history)
    resources = (getattr(ctx, "scope", {}) or {}).get("test_resources", [])
    resource = next((r for r in resources if r["id"] == plan.get("resource") and r["finding_id"] == ctx.plan.id), None)
    if plan.get("kind") != "access-control" or resource is None:
        return [], None, "declare an access-control plan using an operator-supplied test resource"
    if any(n <= start for n in cited):
        return [], None, "proof must be collected after the declared plan"
    matched = []
    for n in cited:
        h = history[n - 1]
        args, res = h.get("args", {}), h.get("result", {})
        if (
            h.get("tool") != "http_request"
            or type(res.get("status")) is not int
            or args.get("path") != resource["path"]
            or (args.get("method") or "GET").upper() != resource.get("method", "GET")
            or any((args.get(k) or {}) != resource.get(k, {}) for k in ("params", "json", "form", "headers"))
        ):
            return [], resource, "every citation must request the declared resource with the same inputs"
        response = getattr(ctx, "responses", {}).get(n, {})
        if not response.get("complete"):
            return [], resource, "the resource observation is missing or incomplete"
        try:
            if resource["pointer"]:
                present = token(observation(ctx, n, resource["pointer"])) == token(resource["value"])
            else:
                present = (
                    isinstance(resource["value"], str)
                    and resource["value"] in response.get("body", "")
                    and resource["value"] not in token(args)
                )
        except (ValueError, KeyError, IndexError, TypeError, RecursionError):
            # An absent field in a valid JSON object differs from unreadable/truncated data.
            try:
                json.loads(response["body"])
            except (ValueError, KeyError, TypeError, RecursionError):
                return [], resource, "the resource response cannot be inspected"
            present = False
        matched.append(
            (
                args.get("role") or "anonymous",
                response.get("identity"),
                res["status"],
                bool(present and res.get("length")),
            )
        )
    return matched, resource, None


def access_check(ctx, history, cited, *, negative=False, blocked=False):
    matched, resource, error = access_observations(ctx, history, cited)
    if error:
        return error
    allowed = [
        (r, i)
        for r, i, status, present in matched
        if r in resource["allowed_roles"] and present and 200 <= status < 300
    ]
    if negative:
        if any(present for r, _, _, present in matched if r in resource["denied_roles"]):
            return "the protected resource is present for a denied identity"
        denied = [
            (r, i)
            for r, i, status, present in matched
            if r in resource["denied_roles"]
            and not present
            and (status in (403, 404) if blocked else 200 <= status < 300)
        ]
    else:
        denied = [
            (r, i)
            for r, i, status, present in matched
            if r in resource["denied_roles"] and present and 200 <= status < 300
        ]
    if any(a != b and ia is not None and ib is not None and ia != ib for a, ia in allowed for b, ib in denied):
        return None
    return "the resource lacks a valid contrast between an allowed and an independent denied identity"
