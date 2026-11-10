"""Declared experiments and observations over recorded answers (VER-008, VER-010, VER-011, VER-013, VER-041)."""

from __future__ import annotations

import json
import secrets
from urllib.parse import parse_qsl, unquote

from ..planning import STRATEGY_SCHEMA
from ..verification_context import planned_route, record_segments, route_matches

SCALAR = {"type": ["string", "number", "boolean"], "maxLength": 4000}


def _candidates(template: dict) -> dict:
    return {"anyOf": [template, {"type": "array", "minItems": 1, "maxItems": 3, "uniqueItems": True,
                                 "items": template}]}


PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind", "hypothesis", "path"],
    "properties": {
        "kind": {"enum": ["boolean", "timing", "access-control", "control", "execution", "session"]},
        "hypothesis": {"type": "string", "minLength": 10, "maxLength": 1000},
        "variant": {"type": "string", "maxLength": 80},
        # Optional free-text rationale (e.g. for a revised template); ignored by every check, it lets a
        # resubmitted plan carry its reason without tripping additionalProperties.
        "note": {"type": "string", "maxLength": 2000},
        "path": {"type": "string", "minLength": 1, "maxLength": 2000},
        "method": {"enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"]},
        "input_location": {"enum": ["params", "query", "json", "form", "path"]},
        "input_name": {"type": "string", "minLength": 1, "maxLength": 128},
        # The identity the Verifier sends the generated read-only controls as; omit or null for unauthenticated.
        "role": {"type": ["string", "null"], "maxLength": 80},
        "baseline": SCALAR,
        "positive": SCALAR,
        "negative": SCALAR,
        "pointer": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^/"},
        "resource": {"type": "string", "maxLength": 80},
        "owner": {"type": "string", "minLength": 1, "maxLength": 80},
        # The finding's request that changes a record, for a write proof on the owner's resource (VER-010).
        "change": {
            "type": "object",
            "additionalProperties": False,
            "required": ["method", "path"],
            "properties": {"method": {"enum": ["POST", "PUT", "PATCH"]},
                           "path": {"type": "string", "minLength": 1, "maxLength": 2000}},
        },
        "reference": {"type": "string", "minLength": 1, "maxLength": 80},
        "strategy": STRATEGY_SCHEMA,
        # One template, or up to three candidates the Verifier tries in turn on a server error (VER-011).
        "expression_template": _candidates({"type": "string", "minLength": 5, "maxLength": 3000}),
        "operator_challenge": {"enum": ["nosql"]},
        "predicate_template": {"type": "string", "minLength": 15, "maxLength": 3000},
        "predicate_attribute": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9-]{0,63}$"},
        "sql_template": _candidates({"type": "string", "minLength": 15, "maxLength": 3000}),
        # VER-048: a blind-injection out-of-band proof carries the callback URL instead of observing a field.
        "oob_template": {"type": "string", "minLength": 5, "maxLength": 3000},
        # VER-049: the observation is the presence of an authenticated artifact at `pointer`, not a field's value.
        "auth_artifact": {"type": "boolean"},
        # VER-011: values for the request's other inputs, such as the password next to a login's user name, that
        # every generated control carries unchanged.
        "fixed": {
            "type": "object",
            "additionalProperties": False,
            "minProperties": 1,
            "properties": {
                location: {"type": "object", "minProperties": 1, "maxProperties": 8,
                           "propertyNames": {"minLength": 1, "maxLength": 128},
                           "additionalProperties": {"type": ["string", "number", "boolean"], "maxLength": 1000}}
                for location in ("params", "json", "form")
            },
        },
    },
    "allOf": [
        {
            "if": {"properties": {"kind": {"const": "boolean"}}, "not": {"required": ["oob_template"]}},
            "then": {"required": ["input_location", "input_name", "baseline", "pointer"]},
        },
        {
            "if": {"required": ["oob_template"]},
            "then": {"required": ["input_location", "input_name"]},
        },
        {
            "if": {"properties": {"kind": {"const": "timing"}}},
            "then": {"required": ["input_location", "input_name", "baseline", "positive"]},
        },
        {
            "if": {"properties": {"kind": {"const": "access-control"}}},
            "then": {"oneOf": [{"required": ["resource"]}, {"required": ["owner"]}, {"required": ["reference"]}]},
        },
        {"if": {"required": ["change"]}, "then": {"required": ["owner"]}},
    ],
}

def generates_controls(plan) -> bool:
    """Whether the Verifier generates this accepted plan's controls itself (VER-011)."""
    return plan.get("kind") == "boolean" and bool(
        plan.get("sql_template") or plan.get("expression_template") or plan.get("operator_challenge"))


# Exposure and missing authentication are proven only with an operator-declared resource (verifiable-cwes.yaml).
_RESOURCE_ONLY_CWES = ("CWE-200", "CWE-306")


def normal_roles(identities) -> list[str]:
    return [i["role"] for i in identities or [] if i.get("role") and not i.get("privileged")]


def privileged_roles(identities) -> list[str]:
    return [i["role"] for i in identities or [] if i.get("role") and i.get("privileged")]


def access_methods(finding_id, cwe, scope, identities, *, writes: bool) -> list[str]:
    """How this run can prove an access-control finding (VER-010): `resource`, the operator's test resource,
    which takes precedence; else `owner`, a resource a normal account creates (two normal accounts and writes),
    and `reference`, a comparison with a privileged account (VER-041)."""
    if any(r["finding_id"] == finding_id for r in (scope or {}).get("test_resources", [])):
        return ["resource"]
    if cwe in _RESOURCE_ONLY_CWES:
        return []
    normal = normal_roles(identities)
    return [m for m, ok in (("owner", writes and len(normal) >= 2),
                            ("reference", bool(normal and privileged_roles(identities)))) if ok]


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


def callback_controls(plan, listener, marker):
    """VER-048: an out-of-band proof for injection that surfaces no response difference. The positive control
    carries the listener URL inside the declared injection template, so a reachable sink makes the target fetch
    it; the negative carries the same URL as bare data, which an ordinary URL-fetching feature would retrieve
    too, so a callback there refutes the proof. Both carry the finding marker; http_request swaps it for a fresh
    per-attempt nonce (agent/tools.py), and the listener correlates the hit. No application data is read."""
    template = plan.get("oob_template", "")
    if template.count("{{callback}}") != 1:
        raise ValueError("an out-of-band proof needs a template containing exactly one {{callback}} placeholder")
    url = listener.url_for("".join(marker or ()))
    if "{{callback}}" in url:
        raise ValueError("the callback URL is unavailable")
    return {
        **plan,
        "positive": template.replace("{{callback}}", url),
        "negative": url,
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
            return plan, {}, (f"proof must be collected after the declared plan (VER-011): step {n} precedes the "
                              f"plan in step {start} and must be repeated")
        h = history[n - 1]
        args, result = h.get("args", {}), h.get("result", {})
        if h.get("tool") != "http_request" or not isinstance(result.get("status"), int):
            return plan, {}, f"proof needs answered target requests; step {n} is none"
        if not planned_route(plan["path"], args.get("path") or "") or (
            (args.get("method") or "GET").upper() != plan.get("method", "GET")
        ):
            return plan, {}, (f"proof requests do not match the declared target: step {n} does not send "
                              f"{plan.get('method', 'GET')} {plan['path']}")
        # A query in the path counts as params, as the controller sends it; the rest of the path stays fixed.
        path, _, query = (args.get("path") or "").partition("?")
        sent = {k: dict(args.get(k) or {}) for k in ("params", "json", "form", "headers", "path_inputs")}
        sent["params"].update(parse_qsl(query, keep_blank_values=True))
        if plan.get("input_location") == "path":
            if path != plan["path"]:
                return plan, {}, "path input requests must retain the exact declared template (VER-044)"
            value = sent["path_inputs"].pop(plan.get("input_name"), None)
            signatures.add(token([args.get("role"), path, sent]))
        else:
            values = sent[plan.get("input_location", "params")]
            value = values.pop(plan.get("input_name"), None)
            signatures.add(token([args.get("role"), path, sent]))
        bucket = next((k for k in groups if token(value) == token(plan[k])), None)
        if bucket is None:
            return plan, {}, f"a cited request did not use a declared control value: step {n}"
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
    short = [f"{name} {len(group)} of 2" for name, group in groups.items() if len(group) < 2]
    if short:
        return ("repeat every declared control at least twice using distinct requests; so far " + ", ".join(short))
    statuses = {r["status"] for group in groups.values() for _, r in group}
    if len(statuses) != 1 or not all(200 <= s < 300 for s in statuses):
        # A login-bypass injection flips 401 to 200; that is proven with the auth-artifact form, not here.
        if plan.get("sql_template") and {s for s in statuses if s in (401, 403)} and any(
                200 <= s < 300 for s in statuses):
            return ("the controls flip the response status (e.g. 401 to 200); that is a login-bypass proof: "
                    "declare the plan with auth_artifact true and pointer at the token field, not a response field")
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
    if observed["positive"] in (None, "", [], {}):
        return "the true predicates produced an empty observation; choose a signal present when the condition holds"
    if token(observed["positive"]) != token(observed["positive_other"]):
        return "the complementary true predicates did not produce the same observation"
    if token(observed["negative"]) != token(observed["negative_other"]):
        return "the complementary false predicates did not produce the same observation"
    if token(observed["positive"]) == token(observed["negative"]):
        return "the true and false predicates did not separate the observation into two classes"
    return None


def injection_proof(ctx, history, cited):
    """The injection check that fits the latest accepted plan: the auth-artifact form (VER-049) for a declared
    login bypass, otherwise the response-field or timing form (VER-011). The out-of-band form (VER-048) is checked
    in proof.py, since it needs the listener's record."""
    _, plan = latest_plan(history)
    if plan.get("auth_artifact"):
        return auth_artifact_check(ctx, history, cited)
    return injection_check(ctx, history, cited)


def injection_ready(ctx, history, steps):
    """Whether the controls the Verifier just ran already meet the injection proof (VER-011), reported to the
    agent so its next step is the verdict. Pure: it sets no verdict and writes no evidence; proof.py still
    re-checks the cited steps before a confirmed verdict stands. When a control met a server error the feedback
    names it, so the agent can see the template is wrong without reading the step itself."""
    problem = injection_proof(ctx, history, steps)
    if problem is None:
        return {"proof": "holds", "steps": sorted(steps),
                "next": "submit_verdict confirmed and cite these steps in proof_steps"}
    feedback = {"proof": "missing", "reason": problem, "steps": sorted(steps),
                "next": "revise the plan with a corrected template, or submit the verdict the evidence supports"}
    failed = next((n for n in reversed(steps) if (history[n - 1].get("result") or {}).get("status", 0) >= 500
                   or (history[n - 1].get("result") or {}).get("error")), None)
    if failed is not None:
        result = history[failed - 1].get("result") or {}
        excerpt = (result.get("error") or result.get("body_excerpt") or "")[:300]
        feedback["failed_control"] = {"step": failed, "status": result.get("status"), "excerpt": excerpt}
    return feedback


def callback_injection_check(ctx, history, cited):
    """VER-048: a blind injection is confirmed when the injecting control reaches the loopback listener and the
    inert-URL control does not. The listener, not the model, observed each hit; the controls buy nothing beyond
    the callback correlation, and no application data is read."""
    plan, groups, error = experiment_groups(history, cited)
    if error:
        return error
    if not plan.get("oob_template"):
        return "declare an out-of-band template for a callback injection proof"
    positive, negative = groups.get("positive", []), groups.get("negative", [])
    if len(positive) < 2:
        return "repeat the injecting control at least twice so each attempt carries its own callback nonce"
    if not negative:
        return "cite the inert-URL control, whose missing callback rules out an ordinary URL fetch"
    if not all(r.get("callback_hit") is True for _, r in positive):
        return "every injecting request must produce a correlated callback hit"
    if any(r.get("callback_hit") for _, r in negative):
        return "the inert-URL control reached the listener, so a callback does not prove injection here"
    return None


def auth_artifact_check(ctx, history, cited):
    """VER-049: a login-bypass injection is confirmed when the true-predicate controls yield an authenticated
    artifact and the false-predicate controls and the baseline do not. The artifact's presence (not its value,
    which is withheld in code, agent/tools.py) is computed by the code, so the uniform-status rule does not apply:
    a 401-to-200 auth flip is the point. The complementary true/false pair rules out a coincidence, so no
    repetition is needed."""
    plan, groups, error = experiment_groups(history, cited)
    if error:
        return error
    if not plan.get("auth_artifact"):
        return "declare an auth-artifact experiment for a login-bypass proof"
    present_groups = [k for k in ("positive", "positive_other") if k in groups]
    absent_groups = [k for k in ("baseline", "negative", "negative_other") if k in groups]
    if not present_groups or "negative" not in absent_groups:
        return "cite the generated true and false predicate controls so the auth flip can be compared"
    if any(not group or not all(r.get("auth_artifact") is True for _, r in group)
           for group in (groups[k] for k in present_groups)):
        return "every true-predicate control must yield the authenticated artifact"
    if any(r.get("auth_artifact") for k in absent_groups for _, r in groups[k]):
        return "a false-predicate control or the baseline also authenticated, so the injection is not shown"
    return None


def access_observations(ctx, history, cited):
    _, plan = latest_plan(history)
    resources = (getattr(ctx, "scope", {}) or {}).get("test_resources", [])
    resource = next((r for r in resources if r["id"] == plan.get("resource") and r["finding_id"] == ctx.plan.id), None)
    if plan.get("kind") != "access-control" or resource is None:
        return [], None, "declare an access-control plan using an operator-supplied test resource"
    matched = []
    for n in cited:
        h = history[n - 1]
        args, res = h.get("args", {}), h.get("result", {})
        if (
            h.get("tool") != "http_request"
            or type(res.get("status")) is not int
            or args.get("path") != resource["path"]
            or (args.get("method") or "GET").upper() != resource.get("method", "GET")
            or any((args.get(k) or {}) != resource.get(k, {})
                   for k in ("params", "json", "form", "headers", "path_inputs"))
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


def _sent(args) -> str:
    return token({k: args.get(k) for k in ("path", "params", "json", "form")})


def _access_steps(ctx, history, cited, plan):
    """The cited steps of a self-made access proof, split into writes and reads. Every read is an answered GET
    to one path that matches the plan's, with the same inputs: (step, role, response, result). The steps may
    precede the latest plan (VER-043); a negative verdict is held to its plan in proof._negative."""
    writes, reads, shapes = [], [], set()
    for n in cited:
        h = history[n - 1]
        args, res = h.get("args", {}), h.get("result", {})
        method = (args.get("method") or "GET").upper()
        if h.get("tool") != "http_request" or type(res.get("status")) is not int:
            return [], [], f"proof needs answered target requests; step {n} is none"
        if method in ("POST", "PUT", "PATCH"):
            writes.append((n, args.get("role") or None, res))
            continue
        if method != plan.get("method", "GET") or not route_matches(plan["path"], args.get("path", "")):
            return [], [], (f"every read must request the planned path with the planned method: step {n} does not "
                            f"send {plan.get('method', 'GET')} {plan['path']}")
        shapes.add(token([args.get("path"), *((args.get(k) or {}) for k in ("params", "json", "form"))]))
        response = getattr(ctx, "responses", {}).get(n)
        if not response:
            return [], [], "the resource observation is missing"
        reads.append((n, args.get("role") or None, response, res))
    if len(shapes) > 1:
        return [], [], "every read must request the same resource with the same inputs"
    return writes, reads, None


def owned_check(ctx, history, cited, *, negative=False, blocked=False):
    """A resource the owner created with the finding's marker (VER-010, VER-014): the owner reads the marker back,
    a read without a role does not show it, and another normal account's read decides."""
    _, plan = latest_plan(history)
    owner, marker = plan["owner"], "".join(getattr(ctx, "marker", None) or ())
    if not marker:
        return "this run has no marker for the finding"
    if any(h.get("tool") == "http_request" and type(h.get("result", {}).get("status")) is int
           and marker in _sent(h.get("args", {})) and (h.get("args", {}).get("role") or None) != owner
           for h in history):
        return "an identity other than the owner sent the marker"
    writes, reads, error = _access_steps(ctx, history, cited, plan)
    if error:
        return error
    if not writes or any(role != owner or not 200 <= res["status"] < 300 for _, role, res in writes):
        return "cite the owner's answered write that carries the marker"
    if not any(marker in _sent(history[n - 1]["args"]) for n, _, _ in writes):
        return "no cited write of the owner carries the marker"
    if any(n < min(w for w, _, _ in writes) for n, *_ in reads):
        return "the reads must follow the owner's write"
    if any(marker in _sent(history[n - 1]["args"]) for n, *_ in reads):
        return "a read that sends the marker itself does not count"
    seen = []
    for _, role, response, res in reads:
        present = marker in response.get("body", "")
        if not present and not response.get("complete"):
            return "a response is incomplete, so the marker's absence is not established"
        seen.append((role, response.get("identity"), res["status"], present and 200 <= res["status"] < 300))
    owners = {i for role, i, _, present in seen if role == owner and present}
    if not owners:
        return "the owner's read does not show the marker"
    anonymous = [present for role, *_, present in seen if role is None]
    if not anonymous:
        return "cite a read without a role"
    if any(anonymous):
        return "the marker is visible without a login, so the resource is public"
    normal = normal_roles(getattr(ctx, "identities", None))
    others = [(i, status, present) for role, i, status, present in seen
              if role in normal and role != owner and i is not None and i not in owners]
    if negative:
        if any(present for _, _, present in others):
            return "the marker is present for the other account"
        if any(status in (403, 404) if blocked else 200 <= status < 300 for _, status, _ in others):
            return None
    elif any(present for _, _, present in others):
        return None
    return "the resource lacks a valid contrast between its owner and an independent other normal account"


def changed_check(ctx, history, cited, *, negative=False, blocked=False):
    """A write on a resource the owner created (VER-010, VER-014): the owner writes the marker and reads it back,
    another normal account writes the second marker to that record by the identifier its creation returned and
    the owner's read confirmed (ctx.owned), and the owner's next read decides: the second marker confirms, the
    first alone after a 403 or 404 gives blocked-by-control."""
    _, plan = latest_plan(history)
    owner, change = plan["owner"], plan["change"]
    first, second = "".join(getattr(ctx, "marker", None) or ()), plan.get("second_marker") or ""
    if not first or not second:
        return "this run has no markers for the finding"
    for h in history:
        args = h.get("args") or {}
        if h.get("tool") != "http_request" or type(h.get("result", {}).get("status")) is not int:
            continue
        if first in _sent(args) and (args.get("role") or None) != owner:
            return "an identity other than the owner sent the marker"
        if second in _sent(args) and (args.get("role") or None) == owner:
            return "the owner sent the second marker itself"
    writes, reads, error = _access_steps(ctx, history, cited, plan)
    if error:
        return error
    responses, created = getattr(ctx, "responses", {}), getattr(ctx, "owned", None) or set()
    creates = [n for n, role, res in writes
               if role == owner and 200 <= res["status"] < 300 and first in _sent(history[n - 1]["args"])]
    if not creates:
        return "cite the owner's answered write that carries the marker"
    owner_ids = {responses.get(n, {}).get("identity") for n in creates}
    normal, changes = normal_roles(getattr(ctx, "identities", None)), []
    for n, role, res in writes:
        args = history[n - 1]["args"]
        if n in creates:
            continue
        if not (role in normal and role != owner and second in _sent(args)
                and (args.get("method") or "GET").upper() == change["method"]
                and route_matches(change["path"], args.get("path", ""))):
            return "a cited write is neither the owner's creation nor the other account's change"
        segments = record_segments(change["path"], args.get("path", ""))
        if not segments or any(unquote(s) not in created for s in segments):
            return "the change must name the record the owner's write created"
        if responses.get(n, {}).get("identity") in owner_ids:
            return "the change came from the owner's own session"
        changes.append((n, res))
    if not changes:
        return "cite the other account's write of the second marker to the created record"
    step, answer = min(changes, key=lambda c: c[0])
    if any(n > step for n in creates):
        return "the owner's write must come before the change"
    if any(first in _sent(history[n - 1]["args"]) or second in _sent(history[n - 1]["args"]) for n, *_ in reads):
        return "a read that sends a marker itself does not count"
    owner_reads = sorted((n, response, res) for n, role, response, res in reads if role == owner)
    if not any(min(creates) < n < step and first in response.get("body", "") and 200 <= res["status"] < 300
               for n, response, res in owner_reads):
        return "the owner's read does not show the marker before the change"
    after = [(response, res) for n, response, res in owner_reads if n > step]
    if not after:
        return "cite the owner's read after the change"
    response, res = after[0]                                    # the owner's next read decides
    ok = 200 <= res["status"] < 300
    shows_second, shows_first = ok and second in response.get("body", ""), ok and first in response.get("body", "")
    if not shows_second and not response.get("complete"):
        return "the owner's read after the change is incomplete, so the second marker's absence is not established"
    if not negative:
        return None if shows_second else "the owner's next read after the change does not show the second marker"
    if shows_second:
        return "the owner's read shows the second marker, so the change went through"
    if not blocked:
        return "a change without effect shows no protection; only a 403 or 404 gives blocked-by-control"
    if answer["status"] in (403, 404) and shows_first:
        return None
    return "the change was not refused with 403 or 404, or the owner's read no longer shows the marker"


def privileged_check(ctx, history, cited, *, negative=False, blocked=False):
    """A privileged function (VER-010, VER-041): the privileged account gets 2xx, a request without a role 401 or
    403, and a normal account the identical answer (confirmed) or 403/404 (blocked-by-control). Identical means the
    same unredacted bytes (the recorded response's digest): an answer that names its own user is never identical,
    a list that names every user can be."""
    if negative and not blocked:
        return "a different answer for the normal account does not show that the function is protected"
    _, plan = latest_plan(history)
    writes, reads, error = _access_steps(ctx, history, cited, plan)
    if error or writes:
        return error or "a privileged comparison only reads"
    reference = [(response.get("identity"), response["digest"]) for _, role, response, res in reads
                 if role == plan["reference"] and 200 <= res["status"] < 300 and res.get("length")
                 and response.get("digest")]
    if not reference:
        return "the privileged account's request was not answered with content"
    statuses = [res["status"] for _, role, _, res in reads if role is None]
    if not blocked and (not statuses or any(s not in (401, 403) for s in statuses)):
        return "a request without a role must be refused with 401 or 403"
    ids, roles = {i for i, _ in reference}, normal_roles(getattr(ctx, "identities", None))
    normal = [(response.get("identity"), res["status"], response.get("digest")) for _, role, response, res in reads
              if role in roles and response.get("identity") not in ids]
    same = [i for i, status, digest in normal
            if 200 <= status < 300 and digest and digest in {d for _, d in reference}]
    if blocked:
        if same:
            return "a normal account received the privileged answer"
        if any(status in (403, 404) for _, status, _ in normal):
            return None
    elif same:
        return None
    return "no independent normal account received the identical answer"


def access_check(ctx, history, cited, *, negative=False, blocked=False):
    _, plan = latest_plan(history)
    if plan.get("kind") == "access-control" and (plan.get("owner") or plan.get("reference")):
        if any(r["finding_id"] == ctx.plan.id for r in (getattr(ctx, "scope", None) or {}).get("test_resources", [])):
            return "the operator-declared test resource takes precedence"
        check = changed_check if plan.get("change") else owned_check if plan.get("owner") else privileged_check
        return check(ctx, history, cited, negative=negative, blocked=blocked)
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
