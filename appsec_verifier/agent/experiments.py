"""Declared experiments and observations over recorded answers (VER-008, VER-010, VER-011, VER-013, VER-041,
VER-049, VER-053, VER-055, VER-057, VER-061)."""

from __future__ import annotations

import json
import re
import secrets
from urllib.parse import parse_qsl, unquote

from ..planning import STRATEGY_SCHEMA
from ..verification_context import planned_route, record_segments, route_matches

SCALAR = {"type": ["string", "number", "boolean"], "maxLength": 4000}

# VER-053: tokens that mark a database, NoSQL or XPath engine error, as opposed to a generic server failure or a
# validation message. Only membership of this class, never the error text, decides the engine-error proof.
_ENGINE_ERROR = re.compile(
    r"SQLITE_ERROR|unrecognized token|near \"[^\"]*\": syntax error|incomplete input|"
    r"you have an error in your SQL syntax|SQL syntax|syntax error at or near|"
    r"unterminated quoted string|quoted string not properly terminated|ORA-\d{5}|SQLSTATE\[|"
    r"PG::|psycopg|sqlalchemy|SQLException|MySQL|MariaDB|PostgreSQL|"
    # Microsoft SQL Server, H2 and Db2 name a syntax error in words of their own.
    r"Unclosed quotation mark|Incorrect syntax near|Syntax error in SQL statement|DB2 SQL error|SQLCODE=-?\d+|"
    r"XPathException|Invalid XPath|xmlXPathEval|XPST\d{4}|XPTY\d{4}|Saxon|"
    r"MongoError|BSONError|E11000|\$regex|Regular expression is invalid|"
    r"unknown (?:top level )?operator \$|"
    # VER-053: template-engine and code-evaluation parse errors, for the engine-error form of template and
    # code-evaluation injection. Broad tokens (SyntaxError, Unexpected token) are safe here: engine_error_signature
    # runs only for an error-probe control, and a balanced counterpart that also raises one fails the proof closed.
    # Library-specific tokens only: a bare engine name (Twig, Velocity, Handlebars, Mako) is an ordinary word in
    # page text such as a product name.
    r"TemplateSyntaxError|jinja2|Twig\\Error|Twig_Error|freemarker\.core|FreeMarker template error|"
    r"org\.apache\.velocity|ParseErrorException|org\.thymeleaf|TemplateProcessingException|"
    r"SpelParseException|SpelEvaluationException|SmartyCompilerException|Smarty error|"
    r"Liquid::SyntaxError|Liquid syntax error|Parse error on line|mako\.exceptions|"
    r"unexpected end of template|unexpected '%\}'|unexpected '\}\}'|"
    r"SyntaxError|invalid syntax|unexpected EOF|Unexpected token|Unexpected end of input",
    re.IGNORECASE,
)


def engine_error_signature(text: str) -> bool:
    """VER-053: whether a response body carries a database, NoSQL or XPath engine error. Only this, not the error
    text, decides the engine-error proof; the text stays owner-only evidence (agent/tools.py, VER-016)."""
    return bool(text) and _ENGINE_ERROR.search(text) is not None


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
        # VER-055: for a page or text answer, a literal text whose presence the experiment observes.
        "text": {"type": "string", "minLength": 3, "maxLength": 200},
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
        # VER-057: the account whose answer a request without credentials must receive; the Verifier sends both and
        # a random path next to the finding's, and compares the answers in code.
        "signed_in": {"type": "string", "minLength": 1, "maxLength": 80},
        "strategy": STRATEGY_SCHEMA,
        # One template, or up to three candidates the Verifier tries in turn on a server error (VER-011).
        "expression_template": _candidates({"type": "string", "minLength": 5, "maxLength": 3000}),
        "operator_challenge": {"enum": ["nosql"]},
        "predicate_template": {"type": "string", "minLength": 15, "maxLength": 3000},
        # VER-011: a NoSQL input spliced into a server-side JavaScript predicate such as $where (CWE-943).
        "js_predicate_template": {"type": "string", "minLength": 10, "maxLength": 3000},
        "predicate_attribute": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9-]{0,63}$"},
        "sql_template": _candidates({"type": "string", "minLength": 15, "maxLength": 3000}),
        # VER-048: a blind-injection out-of-band proof carries the callback URL instead of observing a field.
        "oob_template": {"type": "string", "minLength": 5, "maxLength": 3000},
        # VER-049: the observation is the presence of an authenticated artifact at `pointer`, not a field's value.
        "auth_artifact": {"type": "boolean"},
        # VER-053: a Verifier-built UNION that returns a marker constant of the Verifier's own. The prefix only
        # closes the current literal and parentheses (punctuation and whitespace); the Verifier owns the SELECT
        # list, so no real column or row can be named.
        "sql_marker": {
            "type": "object",
            "additionalProperties": False,
            "required": ["prefix", "columns", "column"],
            "properties": {
                "prefix": {"type": "string", "maxLength": 16, "pattern": "^[\\s'\")(]*$"},
                "columns": {"type": "integer", "minimum": 1, "maximum": 20},
                "column": {"type": "integer", "minimum": 0, "maximum": 19},
                "comment": {"enum": ["-- ", "-- -", "#"]},
                "concat": {"enum": ["||", "concat"]},
            },
        },
        # VER-053: the engine-error form; the Verifier sends a syntax-breaking and a balanced control and observes
        # whether a backend engine error results. True when present.
        "error_probe": {"const": True},
        # VER-011: values for the request's other inputs, such as the password next to a login's user name, that
        # every generated control carries unchanged. An empty object gives none, like an absent one.
        "fixed": {
            "type": "object",
            "additionalProperties": False,
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
            "if": {"properties": {"kind": {"const": "boolean"}},
                   "not": {"anyOf": [{"required": ["oob_template"]}, {"required": ["sql_marker"]},
                                     {"required": ["error_probe"]}]}},
            # The observation, a pointer or a text (VER-055), is checked in AgentTools.plan_test.
            "then": {"required": ["input_location", "input_name", "baseline"]},
        },
        {
            "if": {"required": ["oob_template"]},
            "then": {"required": ["input_location", "input_name"]},
        },
        # VER-053: the returned-marker and engine-error forms name the input but need no field pointer; the marker
        # form needs no baseline (the generated UNION replaces the input value).
        {"if": {"required": ["sql_marker"]}, "then": {"required": ["input_location", "input_name"]}},
        {"if": {"required": ["error_probe"]}, "then": {"required": ["input_location", "input_name"]}},
        {
            "if": {"properties": {"kind": {"const": "timing"}}},
            "then": {"required": ["input_location", "input_name", "baseline", "positive"]},
        },
        {
            "if": {"properties": {"kind": {"const": "access-control"}}},
            "then": {"oneOf": [{"required": ["resource"]}, {"required": ["owner"]}, {"required": ["reference"]},
                               {"required": ["signed_in"]}]},
        },
        {"if": {"required": ["change"]}, "then": {"required": ["owner"]}},
    ],
}

OBSERVATION_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["plan_step"],
    "properties": {
        "plan_step": {"type": "integer", "minimum": 1},
        "pointer": PLAN_SCHEMA["properties"]["pointer"],
        "text": PLAN_SCHEMA["properties"]["text"],
    },
    "oneOf": [{"required": ["pointer"]}, {"required": ["text"]}],
}


def revisable_observation(plan) -> bool:
    """VER-055: only response-field/text experiments, never withheld or mechanism-owned observations."""
    return plan.get("kind") == "boolean" and not any(
        plan.get(k) for k in ("auth_artifact", "error_probe", "sql_marker", "oob_template"))


def observation_problem(plan) -> str | None:
    """What a boolean plan's observation lacks (VER-011, VER-055): one observation, a JSON field or a text of a page
    answer. Arithmetic may read its results from the answer itself, a login bypass observes its artifact's field, and
    the engine-error, returned-marker and out-of-band forms observe in code."""
    if plan.get("kind") != "boolean" or any(plan.get(k) for k in ("oob_template", "sql_marker", "error_probe")):
        return None
    if plan.get("pointer") and plan.get("text"):
        return "observe either a JSON field (pointer) or a text of the answer (text), not both"
    if plan.get("auth_artifact") and not plan.get("pointer"):
        return "an auth-artifact proof needs pointer at the token or session field"
    if not (plan.get("pointer") or plan.get("text") or plan.get("expression_template")):
        return ("declare the observation: pointer for a JSON field, or text for a literal text a recorded page or "
                "text answer shows")
    return None


def generates_controls(plan) -> bool:
    """Whether the Verifier generates this accepted plan's controls itself (VER-011, VER-053)."""
    return plan.get("kind") == "boolean" and bool(
        plan.get("sql_template") or plan.get("expression_template") or plan.get("operator_challenge")
        or plan.get("js_predicate_template") or plan.get("sql_marker") or plan.get("error_probe"))


def agent_controls(plan) -> bool:
    """Whether an injection plan's controls are values the agent chose itself, which can support a negative
    result but never a confirmation (VER-011)."""
    return plan.get("kind") in ("boolean", "timing") and not any(
        plan.get(k) for k in ("sql_template", "expression_template", "operator_challenge", "predicate_template",
                              "js_predicate_template", "oob_template", "sql_marker", "error_probe"))


def confirming_form(cwe, location) -> str | None:
    """The declaration whose generated controls can confirm an injection of this CWE through this input, as
    AgentTools.plan_test accepts it, or None."""
    if cwe == "CWE-89":
        return "sql_template"
    if cwe == "CWE-943":
        return {"json": "operator_challenge", "params": "operator_challenge or js_predicate_template",
                "query": "operator_challenge or js_predicate_template"}.get(location, "js_predicate_template")
    if cwe in ("CWE-78", "CWE-94", "CWE-95", "CWE-1336", "CWE-643"):
        return "expression_template"
    return "predicate_template" if cwe == "CWE-90" else None


def fixed_forms(cwe, location) -> list[str]:
    """The declarations whose generated controls carry `fixed`, the request's other inputs, for an injection of this
    CWE through this input: the engine-error probe first, as the prompt orders them, then the template form that
    can confirm (VER-011, VER-053). Command injection probes carry nothing else, so none."""
    if cwe == "CWE-78":
        return []
    forms = ["error_probe"] if cwe in ENGINE_ERROR_CWES and (cwe != "CWE-943" or location == "json") else []
    return forms + [form for form in (confirming_form(cwe, location) or "").split(" or ")
                    if form and generates_controls({"kind": "boolean", form: True})]


# Missing authentication and exposure: proven with an operator-declared resource, or the comparison without
# credentials, compared in code, of which the model sees only the answer without credentials (VER-057,
# verifiable-cwes.yaml); the agent's own requests reach only a declared resource (agent/tools.py).
EXPOSURE_CWES = ("CWE-200", "CWE-306", "CWE-497", "CWE-530", "CWE-538", "CWE-548", "CWE-552")
# An IDOR concerns another account's record, never a privileged function, so the privileged comparison cannot
# prove it (VER-010): without a declared resource only a record an account creates can.
RECORD_CWES = ("CWE-639",)


def normal_roles(identities) -> list[str]:
    return [i["role"] for i in identities or [] if i.get("role") and not i.get("privileged")]


def privileged_roles(identities) -> list[str]:
    return [i["role"] for i in identities or [] if i.get("role") and i.get("privileged")]


def access_methods(finding_id, cwe, scope, identities, *, writes: bool) -> list[str]:
    """How this run can prove an access-control finding (VER-010): `resource`, the operator's test resource,
    which takes precedence; else `owner`, a resource a normal account creates (two normal accounts and writes),
    and, except for an IDOR, `reference`, a comparison with a privileged account for a privileged function
    (VER-041), and `signed_in`, a request without credentials that gets an account's answer (VER-057); missing
    authentication and exposure only the last. The test plan, plan_test, the prompt and technical QA all read
    this, so a finding no method fits is not tested (VER-008)."""
    if any(r["finding_id"] == finding_id for r in (scope or {}).get("test_resources", [])):
        return ["resource"]
    signed_in = bool(normal_roles(identities) or privileged_roles(identities)) and cwe not in RECORD_CWES
    if cwe in EXPOSURE_CWES:
        return ["signed_in"] if signed_in else []
    normal = normal_roles(identities)
    reference = bool(normal and privileged_roles(identities)) and cwe not in RECORD_CWES
    return [m for m, ok in (("owner", writes and len(normal) >= 2), ("reference", reference),
                            ("signed_in", signed_in)) if ok]


def comparison_path(path: str, segment: str) -> str:
    """The random path next to `path` a comparison without credentials also requests (VER-057): `segment` in place
    of its last segment, keeping a trailing slash, so a target that answers every path alike is seen."""
    trailing = path.endswith("/") and path != "/"
    parent = path.rstrip("/").rsplit("/", 1)[0]
    return f"{parent}/{segment}" + ("/" if trailing else "")


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


def marker_controls(plan):
    """VER-053: a Verifier-built UNION that returns a constant marker the Verifier chose, so a returned marker
    proves a read primitive without reading any real column or row. The prefix (punctuation and whitespace only,
    enforced by the schema) closes the current literal and parentheses; the Verifier owns the SELECT list, which
    is NULLs and one concatenated marker, so no FROM or real column can be added. Each marker is two halves the
    database concatenates, so an echo of the sent payload cannot reproduce the joined value."""
    m = plan["sql_marker"]
    prefix, columns, column = m["prefix"], m["columns"], m["column"]
    if column >= columns:
        raise ValueError("the marker column is outside the declared column count")
    comment, concat = m.get("comment", "-- "), m.get("concat", "||")

    def payload(h1, h2):
        cell = f"'{h1}'||'{h2}'" if concat == "||" else f"CONCAT('{h1}','{h2}')"
        cols = [cell if i == column else "NULL" for i in range(columns)]
        return f"{prefix} UNION SELECT " + ",".join(cols) + f" {comment}"

    a, b = (secrets.token_hex(6), secrets.token_hex(6)), (secrets.token_hex(6), secrets.token_hex(6))
    return {
        **plan,
        "positive": payload(*a),
        "negative": payload(*b),
        "markers": {"positive": "".join(a), "negative": "".join(b)},
    }


# VER-053: the per-class set of syntax-breaking metacharacters the engine-error form sends, each paired with a
# balanced counterpart. The Verifier owns this set; the agent only asks for the form (error_probe). A string
# context appends the break to the finding's baseline and the counterpart doubles or closes it, so only the break
# leaves the literal or expression open; NoSQL breaks the operator structure instead. LDAP and command execution
# have no engine-error form.
_STRING_BREAKS = {
    "CWE-89": [("'", "''"), ('"', '""'), ("`", "``")],   # SQL: string quote and the MySQL identifier quote
    "CWE-643": [("'", "''"), ('"', '""')],               # XPath: string quotes
}
_TEMPLATE_BREAKS = [("${", "$"), ("{{", "{"), ("<%", "<"), ("#{", "#")]   # template delimiters, no evaluation
_TEMPLATE_CWES = ("CWE-94", "CWE-95", "CWE-1336")
# VER-053: the CWEs the engine-error form covers; VER-054 gates every other confirming form behind its probe.
ENGINE_ERROR_CWES = ("CWE-89", "CWE-643", "CWE-943", *_TEMPLATE_CWES)

_GROUP_NAMES = ("baseline", "positive", "negative", "positive_other", "negative_other")


def control_values(plan) -> dict:
    """The control name -> sink value map the proof buckets cited requests by (VER-011). The response-field,
    marker, arithmetic and auth forms use the five fixed groups; the engine-error form (VER-053) uses one
    break and one balance per metacharacter of its generated set, so it is not bounded to five."""
    error_set = plan.get("error_set")
    if error_set:
        values = {}
        for entry in error_set:
            values[f"break:{entry['name']}"] = entry["break"]
            values[f"balance:{entry['name']}"] = entry["balance"]
        return values
    return {k: plan[k] for k in _GROUP_NAMES if k in plan}


def error_controls(plan, cwe, marker=""):
    """VER-053: the engine-error form's break/balance set for the class. A syntax-breaking metacharacter (an
    unclosed string quote, template delimiter, or NoSQL operator group) should raise a backend engine error that
    its balanced counterpart does not. The error class, classified in code (engine_error_signature), is the
    signal; the error text never reaches the model (VER-016). On a write the controls carry the finding marker,
    so the request stays attributable (VER-014); the NoSQL break stays an unclosed group either way."""
    if cwe in _STRING_BREAKS or cwe in _TEMPLATE_CWES:
        base = str(plan.get("baseline", ""))
        pairs = _STRING_BREAKS.get(cwe, _TEMPLATE_BREAKS)
        return {**plan, "error_set": [{"name": b, "break": base + b, "balance": base + g} for b, g in pairs]}
    if cwe == "CWE-943":
        tag = marker or "x"
        return {**plan, "error_set": [{"name": "$regex", "break": {"$regex": "(" + tag},
                                       "balance": {"$regex": tag}}]}
    raise ValueError("the engine-error form covers SQL, XPath, NoSQL, template and code-evaluation injection")


def operator_controls(plan):
    """VER-011: fresh equality and membership operators against the literal baseline lookup. In a query parameter
    they travel in bracket notation (bracket_params), whose values arrive as text, so they are text there too."""
    baseline = plan["baseline"]
    if plan.get("input_location") in ("params", "query"):
        baseline = str(baseline)
    absent = "vrf" + secrets.token_hex(16)
    return {
        **plan,
        "positive": {"$eq": baseline},
        "negative": {"$eq": absent},
        "positive_other": {"$in": [baseline]},
        "negative_other": {"$in": [absent]},
    }


_BRACKET = re.compile(r"\[(\$[a-z]{2,10})\](\[\])?")


def brackets(plan) -> bool:
    """Whether the plan's controls travel as bracket notation in a query parameter (VER-011)."""
    return bool(plan.get("operator_challenge")) and plan.get("input_location") in ("params", "query")


def bracket_params(name: str, value) -> dict:
    """An operator control as query parameters the way Express 4 (qs) and PHP build an object from them (VER-011):
    {"$eq": "1"} as q[$eq]=1, {"$in": ["1"]} as q[$in][]=1. Any other value stays name=value."""
    if not isinstance(value, dict):
        return {name: value}
    out = {}
    for operator, v in value.items():
        if isinstance(v, list):
            if len(v) != 1:
                raise ValueError("a bracket-notation membership control carries exactly one value")
            out[f"{name}[{operator}][]"] = v[0]
        else:
            out[f"{name}[{operator}]"] = v
    return out


def take_sink(values: dict, name: str, bracketed: bool):
    """Removes the declared input from a request's inputs and returns it, or None when it is absent. With
    `bracketed` an operator object is rebuilt from name[$op] and name[$op][] keys, as the target would build it;
    a key it cannot read stays in `values`, so the request's shape differs from its controls'."""
    if name in values or not bracketed:
        return values.pop(name, None)
    found = {}
    for key in [k for k in values if k.startswith(name + "[")]:
        match = _BRACKET.fullmatch(key[len(name):])
        if match:
            found[match.group(1)] = [values.pop(key)] if match.group(2) else values.pop(key)
    return found or None


def js_controls(plan):
    """VER-011: fresh complementary JavaScript predicates for a NoSQL input spliced into a server-side JavaScript
    predicate such as $where (CWE-943). The template is the baseline that finds a record, joined with && to its one
    {{predicate}} placeholder, so the true predicates repeat the baseline and the false ones suppress it. It holds
    no ||, so no control can widen the answer beyond the baseline's record (no exfiltration, VER-011)."""
    template, baseline = plan["js_predicate_template"], str(plan.get("baseline", ""))
    if template.count("{{predicate}}") != 1:
        raise ValueError("a JavaScript predicate proof needs a template with exactly one {{predicate}} placeholder")
    if "||" in template or not baseline or not template.startswith(baseline):
        raise ValueError("the template starts with the baseline that finds a record and contains no ||; for a "
                         "negative verdict's second context, declare your own positive and negative values "
                         "without a template")
    before, after = (part.strip() for part in template.split("{{predicate}}"))
    if not (before.endswith("&&") or after.startswith("&&")):
        raise ValueError("join {{predicate}} to the baseline with &&, for example 1 && {{predicate}}")
    a = 100000 + secrets.randbelow(800000)
    b = a + 1 + secrets.randbelow(9999)
    predicates = {
        "positive": f"({a}==={a})",
        "negative": f"({a}==={b})",
        "positive_other": f"({b}!=={a})",
        "negative_other": f"({b}!=={b})",
    }
    return {**plan, **{k: template.replace("{{predicate}}", v) for k, v in predicates.items()}}


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
            plan = h.get("result", {}).get("experiment") or h["args"]
            # Append-only corrections change the observation, never the request plan or its position. A view
            # selecting an earlier experiment still sees only corrections bound to that experiment (VER-055).
            for revision in history[n:]:
                result = revision.get("result") or {}
                if (revision.get("tool") == "revise_observation" and result.get("accepted") is True
                        and result.get("plan_step") == n and revisable_observation(plan)):
                    plan = {k: v for k, v in plan.items() if k not in ("pointer", "text")}
                    plan.update({k: v for k, v in result["observation"].items() if k in ("pointer", "text")})
            return n, plan
    return 0, {}


def experiment_steps(history: list[dict], plan_step: int) -> list[int]:
    """Every automatic control of one completed experiment, including failed controls (VER-011, VER-055)."""
    active, steps = 0, []
    completed = False
    for n, h in enumerate(history, 1):
        if h.get("tool") == "plan_test" and (h.get("result") or {}).get("accepted") is True:
            active = n
        if active == plan_step:
            if h.get("tool") == "http_request" and h.get("experiment") is True:
                steps.append(n)
            elif h.get("tool") == "experiment" and (h.get("result") or {}).get("steps") == steps:
                completed = True
    return steps if completed else []


def complete_experiment_citations(history: list[dict], cited):
    """Expand an automatic experiment's citations to its whole control set; manual proof rules stay intact."""
    if not isinstance(cited, list) or any(type(n) is not int or not 1 <= n <= len(history) for n in cited):
        return cited
    if len(set(cited)) != len(cited):
        return cited
    if not cited:
        for n in range(len(history), 0, -1):
            steps = experiment_steps(history, n) if history[n - 1].get("tool") == "plan_test" else []
            if steps:
                return steps
        return cited
    selected = set()
    for n in cited:
        h = history[n - 1]
        if h.get("tool") != "http_request" or h.get("experiment") is not True:
            return cited
        start, _ = latest_plan(history[:n - 1])
        steps = experiment_steps(history, start)
        if not steps:
            return cited
        selected.update(steps)
    return sorted(selected)


def plan_view(history: list[dict], cited) -> list[dict]:
    """The history as the cited steps saw it (VER-011, VER-043): when a plan was accepted before the last cited
    step, a plan accepted after it does not govern them, so an experiment stays checkable against its own plan
    when a later plan follows it, for example one a technical QA question led to. Steps sent before any plan
    still count under the plan that follows them (VER-043). Step numbers are unchanged, and every check still
    applies to the governing plan. Without valid citations the history is returned as it is."""
    steps = [n for n in cited if type(n) is int and 1 <= n <= len(history)] if isinstance(cited, list) else []
    if not steps or not latest_plan(history[:max(steps)])[0]:
        return history
    last = max(steps)
    return [{**h, "result": {"superseded": f"accepted after step {last}"}}
            if n > last and h.get("tool") == "plan_test" and (h.get("result") or {}).get("accepted") is True
            else h for n, h in enumerate(history, 1)]


class ObservationError(ValueError):
    """A safe, actionable distinction between a bad observation and unavailable evidence (VER-055)."""


def observation(ctx, step, pointer):
    response = getattr(ctx, "responses", {}).get(step)
    if not response or not response.get("complete"):
        raise ObservationError(f"recorded response of step {step} is unavailable or incomplete; "
                               "an observation correction cannot recover missing evidence")
    try:
        return pointer_value(response["body"], pointer)
    except json.JSONDecodeError as exc:
        raise ObservationError(f"the answer of step {step} is not valid JSON; for an HTML or text answer, "
                               "use revise_observation with text instead of pointer") from exc
    except (ValueError, TypeError, RecursionError) as exc:
        raise ObservationError(f"the JSON pointer cannot select a value in step {step}; "
                               "inspect read_response and correct it with revise_observation") from exc


def body_of(ctx, step) -> str:
    """The whole recorded response body of a step, for the returned-marker membership check (VER-053)."""
    response = getattr(ctx, "responses", {}).get(step)
    if not response or not response.get("complete"):
        raise ObservationError(f"recorded response of step {step} is unavailable or incomplete; "
                               "an observation correction cannot recover missing evidence")
    return response["body"]


def observe(ctx, step, plan):
    """What the plan observes in a step's recorded answer: the JSON value at its pointer (VER-011), or whether its
    text occurs in the answer (VER-055). ValueError when the answer cannot show it."""
    if plan.get("pointer"):
        return observation(ctx, step, plan["pointer"])
    if plan.get("text"):
        return plan["text"] in body_of(ctx, step)
    raise ValueError("the plan declares no observation")


def sent_texts(plan) -> list[str]:
    """Every value an experiment sends for its inputs, as text: the controls, the baseline and the fixed values."""
    values = [*control_values(plan).values()]
    values += [v for inputs in (plan.get("fixed") or {}).values() for v in (inputs or {}).values()]
    return [v if isinstance(v, str) else json.dumps(v) for v in values]


def shows_number(body: str, value) -> bool:
    """VER-055: whether a computed result stands in an answer as a whole number, not inside a longer one."""
    return re.search(rf"(?<!\d){re.escape(str(value))}(?!\d)", body) is not None


def experiment_groups(history, cited, accepted=None):
    """The cited requests by control group of the plan that governs them (VER-011). A step's recorded result holds
    the plan redacted for the planner (VER-016), while each request is recorded as sent; a control value that
    contains a credential, such as a user name as baseline, would match its own request only in one of them. So
    requests are compared with the plan as accepted, from `accepted` (step -> plan, kept by the loop outside the
    history), and messages and the returned plan stay redacted."""
    start, shown = latest_plan(history)
    if not start:
        return {}, {}, "declare a plan_test before collecting proof"
    plan = (accepted or {}).get(start) or shown
    control_map = control_values(plan)
    groups = {k: [] for k in control_map}
    signatures = set()
    for n in cited:
        if n <= start:
            return shown, {}, (f"proof must be collected after the declared plan (VER-011): step {n} precedes the "
                               f"plan in step {start} and must be repeated")
        h = history[n - 1]
        args, result = h.get("args", {}), h.get("result", {})
        if h.get("tool") != "http_request" or not isinstance(result.get("status"), int):
            return shown, {}, f"proof needs answered target requests; step {n} is none"
        if not planned_route(plan["path"], args.get("path") or "") or (
            (args.get("method") or "GET").upper() != plan.get("method", "GET")
        ):
            return shown, {}, (f"proof requests do not match the declared target: step {n} does not send "
                               f"{shown.get('method', 'GET')} {shown['path']}")
        # A query in the path counts as params, as the controller sends it; the rest of the path stays fixed.
        path, _, query = (args.get("path") or "").partition("?")
        sent = {k: dict(args.get(k) or {}) for k in ("params", "json", "form", "headers", "path_inputs")}
        sent["params"].update(parse_qsl(query, keep_blank_values=True))
        if plan.get("input_location") == "path":
            if path != plan["path"]:
                return shown, {}, "path input requests must retain the exact declared template (VER-044)"
            value = sent["path_inputs"].pop(plan.get("input_name"), None)
            signatures.add(token([args.get("role"), path, sent]))
        else:
            values = sent["params" if plan.get("input_location") == "query" else plan.get("input_location", "params")]
            value = take_sink(values, plan.get("input_name"), brackets(plan))
            signatures.add(token([args.get("role"), path, sent]))
        bucket = next((k for k, v in control_map.items() if token(value) == token(v)), None)
        if bucket is None:
            return shown, {}, f"a cited request did not use a declared control value: step {n}"
        groups[bucket].append((n, result))
    if len(signatures) != 1:
        return shown, {}, "only the declared input may change; identity and other inputs must stay fixed"
    return shown, groups, None


def _error_probe_check(groups, plan) -> str | None:
    """VER-053: the engine-error sweep confirms when at least one metacharacter breaks the backend and its
    balanced counterpart does not, each repeated. Other metacharacters of the set that did not break are part of
    the sweep and do not refute it."""
    any_break = False
    for entry in plan.get("error_set", []):
        breaks = groups.get(f"break:{entry['name']}", [])
        balances = groups.get(f"balance:{entry['name']}", [])
        if any(r.get("engine_error") for _, r in breaks):
            any_break = True
        if (len(breaks) >= 2 and all(r.get("engine_error") is True for _, r in breaks)
                and len(balances) >= 2 and not any(r.get("engine_error") for _, r in balances)):
            return None
    if any_break:
        return ("a syntax-breaking metacharacter raised an engine error but its balanced counterpart did too, so "
                "the break is not what caused it")
    return ("no syntax-breaking metacharacter raised a backend engine error; a generic failure or a validation "
            "message is not proof")


def injection_check(ctx, history, cited):
    plan, groups, error = experiment_groups(history, cited, getattr(ctx, "accepted_plans", None))
    if error:
        return error
    if plan.get("kind") not in ("boolean", "timing"):
        return "declare a boolean or timing experiment for injection"
    if plan.get("error_probe"):
        # VER-053: the engine-error form expects a break to fail, so it precedes the uniform-status and repeat
        # rules. At least one metacharacter of the generated set must raise a backend engine error (classified in
        # code) on every one of its break requests that its balanced counterpart raises on none, each repeated.
        return _error_probe_check(groups, plan)
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
    if plan.get("sql_marker"):
        # VER-053: each control's own generated marker (the concatenation the database computes, which an echo of
        # the sent payload cannot reproduce) returns in its response and not in the complementary one.
        markers = plan.get("markers", {})
        mp, mn = markers.get("positive", ""), markers.get("negative", "")
        if not mp or not mn:
            return "the generated markers are missing from the plan"
        try:
            pos_bodies = [body_of(ctx, n) for n, _ in groups.get("positive", [])]
            neg_bodies = [body_of(ctx, n) for n, _ in groups.get("negative", [])]
        except ValueError:
            return "the returned-marker observation is missing or incomplete"
        if not pos_bodies or not neg_bodies:
            return "cite the marker-returning control and its complementary control"
        if not all(mp in b for b in pos_bodies):
            return "the generated marker did not return through the query channel for its control"
        if any(mp in b for b in neg_bodies) or any(mn in b for b in pos_bodies):
            return "a marker returned for the complementary control too, so it is not driven by the injection"
        if not all(mn in b for b in neg_bodies):
            return "the complementary marker did not return for its control"
        return None
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
            if not plan.get("pointer"):
                # VER-055: in a page or text answer, each control's own result stands as a whole number, and no
                # other control's result, nor any in the baseline's answer.
                for name, group in groups.items():
                    for n, _ in group:
                        body = body_of(ctx, n)
                        if name in expected and not shows_number(body, expected[name]):
                            return "fresh arithmetic results were not returned in the controls' answers"
                        if any(shows_number(body, v) for k, v in expected.items() if k != name):
                            return ("a computed result also appears in the baseline's or another control's answer, "
                                    "so the answer does not show the evaluation")
                return None
            for name, group in groups.items():
                if name == "baseline":
                    continue
                if any(str(observation(ctx, n, plan["pointer"])) != str(expected[name]) for n, _ in group):
                    return "fresh arithmetic expressions were not evaluated to the expected distinct answers"
            if len({str(observation(ctx, n, plan["pointer"])) for n, _ in groups["baseline"]}) != 1:
                return "the baseline observation is unstable"
        except ObservationError as exc:
            return str(exc)
        except (ValueError, KeyError, IndexError, TypeError):
            return "the expression observation is unavailable"
        return None
    if not complementary(plan) or not {"positive_other", "negative_other"} <= groups.keys():
        return "ordinary input-dependent results are not proof; use fresh complementary SQL predicate challenges"
    if plan.get("text") and any(plan["text"] in sent for sent in sent_texts(plan)):
        return "the selected text is part of a sent value, so its presence may be an echo"      # VER-055
    try:
        values = {name: [_observe_or_absent(ctx, n, plan) for n, _ in group] for name, group in groups.items()}
    except ObservationError as exc:
        return str(exc)
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        return "the declared observation is missing or incomplete"
    if plan.get("pointer") and all(v is None for group in values.values() for v in group):
        return ("the selected JSON field is absent or null in every recorded answer; inspect read_response "
                "and select the result field with revise_observation")
    return boolean_classes(plan, values)


def _observe_or_absent(ctx, step, plan):
    """`observe`, with a field a complete JSON answer lacks read as no value (None) rather than a failure (VER-011):
    the presence of a result is an observation, as a text that does not occur is (VER-055). Every control already
    answered with the same successful status, and the true class must still show a value (boolean_classes)."""
    try:
        return observe(ctx, step, plan)
    except (KeyError, IndexError):
        if plan.get("pointer"):
            return None
        raise


def complementary(plan) -> bool:
    """Whether the Verifier generates the experiment's true and false controls in two complementary forms each,
    which a boolean injection proof needs (VER-011)."""
    return bool(plan.get("sql_template") or plan.get("operator_challenge") or plan.get("js_predicate_template"))


def boolean_classes(plan, values: dict[str, list]) -> str | None:
    """Why a boolean experiment's observations, per control group, do not split into the classes its proof needs,
    or None when they do (VER-011): each group answers alike every time and never with a sent value, the two true
    forms alike, the two false forms alike, true unlike false, and with a JavaScript predicate the true class
    repeating the baseline. The proof check and the evidence image (VER-035) read this one comparison."""
    observed = {}
    for name, group in values.items():
        if len({token(v) for v in group}) != 1:
            return "the selected observation is unstable across repetitions"
        if any(str(plan[k]) in token(v) for k in values if k != "baseline" for v in group):
            return "the selected observation reflects the test input"
        observed[name] = group[0]
    # A text is present for one class and absent for the other, either way round (VER-055).
    if not plan.get("text") and observed["positive"] in (None, "", [], {}):
        return "the true predicates produced an empty observation; choose a signal present when the condition holds"
    if token(observed["positive"]) != token(observed["positive_other"]):
        return "the complementary true predicates did not produce the same observation"
    if token(observed["negative"]) != token(observed["negative_other"]):
        return "the complementary false predicates did not produce the same observation"
    if token(observed["positive"]) == token(observed["negative"]):
        return "the true and false predicates did not separate the observation into two classes"
    if plan.get("js_predicate_template") and token(observed["positive"]) != token(observed.get("baseline")):
        # VER-011: joined with && to the baseline's record, a true predicate repeats it and nothing beyond it.
        return "the true JavaScript predicates did not repeat the baseline's answer"
    return None


def injection_proof(ctx, history, cited):
    """The injection check that fits the latest accepted plan: the auth-artifact form (VER-049) for a declared
    login bypass, otherwise the response-field or timing form (VER-011). The out-of-band form (VER-048) is checked
    in proof.py, since it needs the listener's record."""
    _, plan = latest_plan(history)
    if plan.get("auth_artifact"):
        return auth_artifact_check(ctx, history, cited)
    return injection_check(ctx, history, cited)


NEGATIVE_CONTEXTS = ("A negative verdict needs true and false controls that answer alike in at least two declared "
                     "contexts on the same input, such as a numeric and a quoted one: declare another plan for the "
                     "second and cite both experiments.")


def injection_ready(ctx, history, steps):
    """Whether the controls the Verifier just ran already meet the injection proof (VER-011), reported to the
    agent so its next step is the verdict. Pure: it sets no verdict and writes no evidence; proof.py still
    re-checks the cited steps before a confirmed verdict stands. When a control met a server error the feedback
    names it, so the agent can see the template is wrong without reading the step itself."""
    plan_step, plan = latest_plan(history)
    if agent_controls(plan):
        # Controls the agent chose itself ran as an experiment: they can carry a negative verdict, never a
        # confirmation; name the declaration that could confirm, or that none can (VER-011).
        form = confirming_form(getattr(ctx.plan, "cwe", None), plan.get("input_location"))
        feedback = {"proof": "negative-only", "steps": sorted(steps),
                    "reason": "controls you chose can support a negative verdict, never a confirmation",
                    "next": (f"to confirm, declare a plan with {form}; " if form else
                             "no declaration can confirm this finding's CWE through this input; ")
                    + "otherwise submit the verdict these steps support, citing them. " + NEGATIVE_CONTEXTS}
    else:
        problem = injection_proof(ctx, history, steps)
        if problem is None:
            return {"proof": "holds", "steps": sorted(steps),
                    "next": "submit_verdict confirmed and cite these steps in proof_steps"}
        feedback = {"proof": "missing", "reason": problem, "steps": sorted(steps),
                    "next": "revise the plan with a corrected template, or submit the verdict the evidence supports"
                    + ("" if plan.get("error_probe") or plan.get("kind") != "boolean" else ". " + NEGATIVE_CONTEXTS)}
    if revisable_observation(plan):
        feedback["plan_step"] = plan_step
        feedback["next"] = (f"If only the observation is wrong, call revise_observation with plan_step {plan_step} "
                            "and exactly one of text or pointer; it rechecks all recorded controls without requests. "
                            "Missing or incomplete evidence still needs new tests. Otherwise: " + feedback["next"])
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
    plan, groups, error = experiment_groups(history, cited, getattr(ctx, "accepted_plans", None))
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
    """VER-049: positive artifacts must access the declared protected resource; every baseline and negative
    control must fail that read. Presence alone is not authenticated access. Values remain withheld."""
    plan, groups, error = experiment_groups(history, cited, getattr(ctx, "accepted_plans", None))
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
    from .auth_followup import declaration

    check = declaration(ctx, plan["path"])
    if not check:
        return "login-bypass proof needs the declared protected follow-up resource"
    for kind, group in groups.items():
        for _, result in group:
            observed = result.get("auth_access") or {}
            if observed.get("path") != check["path"] or type(observed.get("status")) is not int:
                return "every control needs its recorded protected-resource follow-up"
            if not 200 <= observed["status"] < 500:
                return "a failed follow-up cannot establish the protected-resource contrast"
            if observed.get("pointer") != check["pointer"] or observed.get("value") != check["value"]:
                return "follow-up observations must match the operator's declared resource"
            if kind in present_groups:
                if (observed.get("matched") is not True or observed.get("artifact_supplied") is not True
                        or not 200 <= observed["status"] < 300):
                    return "positive artifacts must access the declared protected resource"
            elif observed.get("matched") is not False:
                return "baseline or negative control also reached the protected resource"
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


REFERENCE_ANONYMOUS = ("a request without a role got a 2xx answer, so the privileged-function comparison cannot "
                       "confirm this finding; missing authentication is proven by the comparison without "
                       "credentials (signed_in) or a configured test_resource")


def reference_unavailable(ctx, history: list[dict]) -> dict | None:
    """Told to the agent as soon as an accepted privileged-function plan can no longer confirm (VER-010, VER-036):
    its request without a role was answered 2xx with content. The finding may still name another path, so the
    agent decides; nothing stops here, and the proof check refuses that plan with the same reason."""
    if getattr(ctx.plan, "cls", None) != "access-control" or not history:
        return None
    _, plan = latest_plan(history)
    if plan.get("kind") != "access-control" or not plan.get("reference") or plan.get("owner"):
        return None
    h = history[-1]
    args, res = h.get("args") or {}, h.get("result") or {}
    if (h.get("tool") == "http_request" and not args.get("role") and not args.get("prerequisite")
            and isinstance(res.get("status"), int) and 200 <= res["status"] < 300 and res.get("length")
            and planned_route(plan.get("path") or "", args.get("path") or "")):
        return {"reason": REFERENCE_ANONYMOUS,
                "next": "plan_test with signed_in set to an account of this run and the same path, or plan another "
                        "path of this finding where a request without a role is refused"}
    return None


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
        if any(200 <= s < 300 for s in statuses):
            return REFERENCE_ANONYMOUS
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


def signed_in_check(ctx, history, cited, *, negative=False, blocked=False):
    """A request without credentials that gets an account's answer (VER-057), from the comparison the Verifier sent
    itself: the account's GET answered 2xx with content, the same GET without credentials answered 2xx with the
    identical bytes (the recorded digest) from another session, and the random path next to it, also without
    credentials, not answered 2xx with those bytes, so a target that answers every path alike confirms nothing.
    The comparison only confirms: a refusal without credentials shows no control the finding is about."""
    if negative:
        return ("the comparison without credentials only confirms; a different or refused answer does not show "
                "that the function is protected")
    _, plan = latest_plan(history)
    account, path, control = plan.get("signed_in"), plan.get("path"), plan.get("control_path")
    if not control:
        return "the plan has no random path of the Verifier to compare with"
    reads = []
    for n in cited if isinstance(cited, list) else []:
        h = history[n - 1] if type(n) is int and 1 <= n <= len(history) else {}
        args, res = h.get("args") or {}, h.get("result") or {}
        if (h.get("tool") != "http_request" or args.get("comparison") is not True
                or (args.get("method") or "GET").upper() != "GET" or type(res.get("status")) is not int):
            return f"cite only the comparison the Verifier sent for the plan; step {n} is not part of it"
        response = getattr(ctx, "responses", {}).get(n) or {}
        reads.append((args.get("role") or None, args.get("path"), res["status"], res.get("length"),
                      response.get("identity"), response.get("digest")))
    signed = [(i, d) for role, p, status, length, i, d in reads
              if role == account and p == path and 200 <= status < 300 and length and d]
    if not signed:
        return f"the request as {account} was not answered with content"
    ids, digests = {i for i, _ in signed}, {d for _, d in signed}
    anonymous = [(status, i, d) for role, p, status, _, i, d in reads if role is None and p == path]
    if not anonymous:
        return "cite the request without credentials"
    if not any(200 <= status < 300 and d in digests and i not in ids for status, i, d in anonymous):
        return (f"the request without credentials did not receive the identical answer {account} received; an "
                "answer that changes between requests or names the signed-in user is never identical")
    controls = [(status, d) for role, p, status, _, _, d in reads if role is None and p == control]
    if not controls:
        return "cite the request to the random path next to the finding's"
    if any(200 <= status < 300 and d in digests for status, d in controls):
        return ("the random path next to the finding's received the same answer, so the target answers every path "
                "alike")
    return None


def comparison_ready(ctx, history, steps):
    """Whether the comparison the Verifier just sent meets VER-057, reported to the agent so its next step is the
    verdict. Pure: proof.py re-checks the cited steps."""
    _, current = latest_plan(history)
    if current.get("exposure"):
        from .access_observation import exposure_check

        problem = exposure_check(ctx, history, steps, current)
    else:
        problem = signed_in_check(ctx, history, steps)
    if problem is None:
        from .access_policy import restriction

        if restriction(ctx, history, steps) is None:
            return {"proof": "missing", "access_observed": True, "steps": sorted(steps),
                    "reason": "access observed, but no independent access restriction is established",
                    "next": "submit_verdict inconclusive; report observed access separately from the "
                            "unproven restriction. A model claim cannot supply that restriction"}
        path = latest_plan(history)[1].get("path")
        exposed = next((n for n in sorted(steps) if 1 <= n <= len(history)
                        and not (history[n - 1].get("args") or {}).get("role")
                        and (history[n - 1].get("args") or {}).get("path") == path), None)
        shown = (f"; step {exposed}, the answer without credentials, is shown to you: present what it lets anyone "
                 "read (VER-059)") if exposed else ""
        return {"proof": "holds", "steps": sorted(steps),
                "next": "submit_verdict confirmed and cite these steps in proof_steps" + shown}
    return {"proof": "missing", "reason": problem, "steps": sorted(steps),
            "next": "plan another read of this finding, or submit_verdict inconclusive with this reason; the "
                    "comparison supports no negative verdict"}


def access_check(ctx, history, cited, *, negative=False, blocked=False):
    _, plan = latest_plan(history)
    if plan.get("exposure"):
        from .access_observation import exposure_check

        return exposure_check(ctx, history, cited, plan, negative=negative)
    if plan.get("kind") == "access-control" and plan.get("signed_in"):
        if any(r["finding_id"] == ctx.plan.id for r in (getattr(ctx, "scope", None) or {}).get("test_resources", [])):
            return "the operator-declared test resource takes precedence"
        return signed_in_check(ctx, history, cited, negative=negative, blocked=blocked)
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
