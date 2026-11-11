"""The exact, narrow tool surface the verification agent is confined to
(VER-017). The agent never gets a shell or raw network: it can issue an HTTP
request to the target as one of the configured identities (scope-guarded),
read the evidenced source (repository-confined), and, for XSS findings, load a
page in the proof browser whose requests go through the same guard (VER-009,
VER-018). Request derivation checks recorded evidence without contacting the
target (VER-008, VER-043). A read the finding's own request needs but the
assessment never names is sent as a bounded GET prerequisite (VER-047).

An identity's credentials go only to the origin it is bound to (its
`target_origin`, by default the target base URL), never to another host in the
scope (VER-018, VER-028). Only GET, HEAD and OPTIONS are sent in safe mode, and
POST, PUT and PATCH only in intrusive mode, with the finding's marker and
without naming an existing record in the path (agent/controller.py). In safe
mode, where the operator can be asked, a write that passes every other check,
or a plan that needs writes, is put to the operator first, and a yes turns the
finding intrusive (VER-052, write_prompt.py); DELETE and
every other method are never sent (VER-014). A privileged account (--admin-account) only reads, in any
mode (VER-041). An access-control plan without an operator test resource is
accepted only when the run allows its proof: a resource a normal account
creates (two normal accounts, intrusive mode), for which plan_test returns the
finding's marker, or a comparison with a privileged account (VER-010). A
failing identity or transport ends the call as a tool
error for the agent, never as an exception past the loop. A response body is
redacted of every credential value before it is cut to the excerpt (VER-016).
The agent's path is appended to the target base URL as written, without
resolving dot segments, so the guard decides on the path the agent chose and
refuses an ambiguous one (VER-018). http_request does not follow redirects: a
3xx answer is returned with its `location`, which is what an open-redirect
proof observes (VER-012); any further hop is a request of its own.

Path traversal and SSRF are steered to harmless markers (VER-012). In a
path-traversal probe a parameter or body value that names a file (`..`, an
absolute path, a NUL) must name the scope's marker file; in an SSRF probe a
value that holds a URL must point at the callback listener. Values are
percent-decoded up to three times before the check. This is a floor, not a
parser of every encoding; the prompt states the same rule. The marker file's
content never reaches the model: it is replaced by "[marker-file]" in every
tool result, and http_request reports `marker_read` instead. An SSRF probe's
http_request reports `callback_hit` once the listener has seen the finding's
marker. Every http_request reports `elapsed_ms`, the time httpx measured for
the exchange, for a timing proof of injection (VER-011).
"""

from __future__ import annotations

import hashlib
import hmac
import json as jsonlib
import re
import secrets
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

import httpx
from jsonschema import Draft202012Validator

from ..auth.sessions import AuthError
from ..planning import evidence_name
from ..tools.http import ALLOWED_METHODS, SAFE_METHODS, ScopeViolation, same_origin
from ..verification_context import missing_capabilities, path_values, record_segments, route_matches
from ..verify import poc
from .experiments import (
    PLAN_SCHEMA,
    access_methods,
    agent_controls,
    generates_controls,
    normal_roles,
    pointer_value,
    privileged_roles,
    token,
)
from .source_reader import SourceAccessError

_BODY_EXCERPT = 600
_LOCATION_CAP = 2000
_HIDDEN = "[marker-file]"
# VER-049: an auth-artifact probe's body may hold a fresh session token; only its presence (computed in code) is
# kept, and this stands in for the body everywhere the model or the log could read it.
_AUTH_ARTIFACT_NOTICE = "[auth-artifact probe: body withheld; the token value never reaches the model or logs]"
_CALLBACK_WAIT_S = 1.0
_DRIVE = re.compile(r"^[A-Za-z]:")


def _variant_line(v: dict) -> str:
    """Compact single-line rendering of a variant for a tool error, so the model can pick the right one.
    Keeps the variant's id, method, path and declared inputs; omits the hypothesis and larger context."""
    req = v.get("request") or {}
    parts = [f"{v.get('id', '?')}", f"{req.get('method', 'GET')} {req.get('path', '')}".strip()]
    inputs = req.get("inputs") or []
    if inputs:
        parts.append("inputs " + ", ".join(f"{i.get('location', '?')}:{i.get('name', '?')}" for i in inputs[:6]))
    return " · ".join(p for p in parts if p)


def _variant_catalog(variants: list[dict], cap: int = 6) -> str:
    """At most `cap` variants, joined with '; ': enough for the model to recognise the one it means."""
    seen = []
    for v in variants:
        line = _variant_line(v)
        if line not in seen:
            seen.append(line)
        if len(seen) == cap:
            break
    return "; ".join(seen)


def _resolve_variant(variants: list[dict], supplied: str) -> tuple[dict | None, str]:
    """Match `supplied` to a declared variant id, forgivingly.

    Exact id wins. Otherwise accept the one declared id that is a token-boundary prefix of `supplied`
    (declared followed by '-' or '_') — this is the case a model that pads a known id with extra
    descriptive words: 'variant-002' is accepted when the model sent 'variant-002-related-search'.
    Must be unique across variants; an ambiguous or missing match returns (None, '').
    The other direction (declared longer than supplied) stays a rejection because it is not uniquely
    recoverable: the model might have meant either of several specific variants.
    """
    for v in variants:
        if v.get("id") == supplied:
            return v, ""
    candidates = []
    for v in variants:
        did = v.get("id") or ""
        if did and (supplied.startswith(did + "-") or supplied.startswith(did + "_")):
            candidates.append(v)
    if len(candidates) == 1:
        return candidates[0], f"variant {supplied!r} accepted as {candidates[0]['id']!r}"
    return None, ""


class ToolError(Exception):
    """A tool call was rejected or malformed. Surfaced to the agent as an error
    result, never raised past the loop."""


def _body_text(resp) -> str:
    text = getattr(resp, "text", None)
    if text is None:
        content = getattr(resp, "content", b"") or b""
        text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
    return text


def _auth_artifact_present(body: str, pointer: str | None) -> bool:
    """VER-049: whether an authenticated artifact (a token, a non-empty identity) sits at `pointer` in the body.
    Only this boolean is kept; the value is read here and discarded, never surfaced."""
    if not pointer:
        return False
    from .experiments import pointer_value
    try:
        value = pointer_value(body, pointer)
    except (ValueError, KeyError, IndexError, TypeError):
        return False
    return value not in (None, "", [], {}, False, 0)


def _elapsed_ms(resp) -> int | None:
    """How long the answer took, from sending the request to reading the body, as httpx measures it."""
    try:
        elapsed = getattr(resp, "elapsed", None)
        return round(elapsed.total_seconds() * 1000) if elapsed is not None else None
    except (AttributeError, RuntimeError):  # httpx raises RuntimeError before the body is read
        return None


def _strings(value):
    """Every string value inside params or a JSON body; keys are not values."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


def _decoded(value: str) -> str:
    for _ in range(3):
        plain = unquote(value)
        if plain == value:
            break
        value = plain
    return value


def _file_path(value: str) -> str | None:
    """The file path a value names, up to a NUL, or None when it does not look like one."""
    d = _decoded(value)
    if ".." in d or "\x00" in d or d.startswith(("/", "\\", "~")) or _DRIVE.match(d):
        return d.split("\x00", 1)[0].replace("\\", "/")
    return None


def _hide(value, secret: str | None):
    """`value` with every occurrence of the marker file's content replaced."""
    if not secret:
        return value
    if isinstance(value, str):
        return value.replace(secret, _HIDDEN)
    if isinstance(value, dict):
        return {k: _hide(v, secret) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_hide(v, secret) for v in value]
    return value


_WRAPPERS = ("data", "result", "item", "record", "resource", "object")


def _created_ids(body: str, location) -> set[str]:
    """The identifiers a creating answer returns (VER-010): the id field of the answer or of its data wrapper, and
    the last path segment of a Location header. An id of a nested record, such as its owner, is not the created
    record's."""
    found: set[str] = set()
    try:
        answer = jsonlib.loads(body)
    except (ValueError, RecursionError):
        answer = None
    if isinstance(answer, dict):
        for record in (answer, *(answer.get(k) for k in _WRAPPERS)):
            for key, v in (record.items() if isinstance(record, dict) else ()):
                if (isinstance(key, str) and key.lower() == "id" and isinstance(v, int | str)
                        and not isinstance(v, bool) and 0 < len(str(v)) <= 128 and "/" not in str(v)):
                    found.add(str(v))
    if location:
        try:
            segment = unquote(urlsplit(str(location)).path.rstrip("/").rsplit("/", 1)[-1])
        except ValueError:
            segment = ""
        if 0 < len(segment) <= 128:
            found.add(segment)
    return found


class AgentTools:
    """Dispatches the agent's tool calls against a ProbeContext."""

    def __init__(self, ctx):
        self.ctx = ctx
        marker_file = (getattr(ctx, "scope", None) or {}).get("marker_file") or {}
        self._marker_content = marker_file.get("content") or None
        path = str(marker_file.get("path") or "").replace("\\", "/")
        self._marker_name = PurePosixPath(path).name or None
        self._exchanges: list[dict] = []
        self._kept = 0  # body characters this finding's proof of concept holds so far
        self._last_response = None
        self._identities = {}
        self._response_chars = 0
        self._digest_key = secrets.token_bytes(32)

    def take_response(self):
        response, self._last_response = self._last_response, None
        return response

    def derive_request(self, **args):
        """Record a supported request derived from this finding's evidence (VER-008, VER-043)."""
        from .derivation import derive

        try:
            return derive(self.ctx, **args)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

    def plan_test(self, **plan) -> dict:
        # The variant schema (verification-context) and the derivation code both say "query" for a URL query
        # parameter; the plan schema (and the scope's injection_inputs) say "params". Accept the model's "query"
        # at this boundary and normalise to "params" so the one vocabulary mismatch between schemas does not
        # kill a run.
        if plan.get("input_location") == "query":
            plan = {**plan, "input_location": "params"}
        if isinstance(plan.get("fixed"), dict) and "query" in plan["fixed"] and "params" not in plan["fixed"]:
            plan = {**plan, "fixed": {("params" if k == "query" else k): v for k, v in plan["fixed"].items()}}
        if not Draft202012Validator(PLAN_SCHEMA).is_valid(plan):
            raise ToolError("invalid experiment declaration")
        # VER-011: up to three candidate templates; the first is checked and run now, the others only when its
        # controls meet a server error (next_candidate). A write runs only the first: no write is ever sent for
        # a template the agent has not looked at in the result of its own controls.
        candidates = []
        for key in ("sql_template", "expression_template"):
            if isinstance(plan.get(key), list):
                candidates += [(key, template) for template in plan[key][1:]]
                plan = {**plan, key: plan[key][0]}
        declared = plan
        # A strategy is optional (VER-043). When one is given, an observed prerequisite needs recorded responses
        # of this finding; one without them counts as assumed, which grants nothing (only a missing one matters,
        # proof.py), so the plan need not be declared again.
        responses = getattr(self.ctx, "responses", {})
        assumed = []
        if plan.get("strategy"):
            prerequisites = []
            for i, prerequisite in enumerate(plan["strategy"]["prerequisites"], 1):
                steps = prerequisite.get("steps", [])
                if prerequisite["status"] == "observed" and (not steps or any(n not in responses for n in steps)):
                    prerequisite = {**prerequisite, "status": "assumed"}
                    assumed.append(str(i))
                prerequisites.append(prerequisite)
            plan = {**plan, "strategy": {**plan["strategy"], "prerequisites": prerequisites}}
        # VER-052: when the operator can be asked, the plan is checked as in intrusive mode; what only intrusive
        # mode allows is collected, and the operator is asked once every other check has passed.
        asking = (self.ctx.safe or self.ctx.read_only) and self._ask_writes() is not None
        safe_mode = (self.ctx.safe or self.ctx.read_only) and not asking
        needs_writes: list[str] = []
        # Name every declaration problem at once, so one revision can fix them all.
        problems = []
        variants = getattr(self.ctx.plan, "verification_context", {}).get("variants", [])
        if variants and not plan.get("variant"):
            problems.append("select an evidenced finding variant for this plan; variants: "
                            + _variant_catalog(variants))
        if plan.get("variant") and not variants:
            problems.append("this finding has no variants; omit variant")
        if plan["kind"] in ("boolean", "timing"):
            is_write = plan.get("method", "GET") not in SAFE_METHODS
            if is_write and safe_mode:
                # VER-011 + VER-030: writes repeat only in intrusive mode; the agent sends each control itself.
                problems.append("an experiment sends every control twice; a write needs --allow-intrusive")
            elif is_write and asking:
                needs_writes.append(f"{plan.get('method')} {plan.get('path')}, each control twice")
        if problems:
            raise ToolError("; ".join(problems))
        from .experiments import callback_controls, expression_controls, ldap_controls, operator_controls, sql_controls

        if any(
            plan.get(k) for k in ("expression_template", "sql_template", "predicate_template", "operator_challenge")
        ):
            # VER-011: an operator-declared injection_inputs entry pins the input for this finding; without one,
            # the agent chooses it from an assessed or independently derived request.
            pinned = [r for r in self.ctx.scope.get("injection_inputs", [])
                      if r["finding_id"] == self.ctx.plan.id]
            if pinned and not any(
                r["path"] == plan["path"]
                and r["input_location"] == plan.get("input_location")
                and r["input_name"] == plan.get("input_name")
                and r["semantics"] == "literal"
                for r in pinned
            ):
                raise ToolError("the plan's input does not match a declared injection_inputs entry for this finding")
        if plan.get("operator_challenge"):
            if self.ctx.plan.cwe != "CWE-943" or plan.get("input_location") != "json" or plan["kind"] != "boolean":
                raise ToolError("NoSQL operator challenges need a JSON boolean experiment for CWE-943")
            plan = operator_controls(plan)
        if plan.get("predicate_template"):
            if self.ctx.plan.cwe != "CWE-90" or plan["kind"] != "boolean":
                raise ToolError("LDAP predicate controls need a boolean experiment for CWE-90")
            try:
                plan = ldap_controls(plan)
            except ValueError as exc:
                raise ToolError(str(exc)) from exc
        if plan.get("expression_template"):
            if self.ctx.plan.cwe == "CWE-78":
                baseline = plan.get("baseline")
                if (
                    not isinstance(baseline, str)
                    or not re.fullmatch(r"[A-Za-z0-9_. -]{1,100}", baseline)
                    or plan["expression_template"] != baseline + "; printf '%s' \"$(({{expression}}))\""
                ):
                    raise ToolError("command proof uses only a plain baseline followed by harmless printf arithmetic")
            if (self.ctx.plan.cwe not in ("CWE-78", "CWE-94", "CWE-95", "CWE-1336", "CWE-643")
                    or plan["kind"] != "boolean"):
                raise ToolError("expression challenges need a command, code-evaluation, template or XPath "
                                f"injection finding declared as kind \"boolean\"; this finding is "
                                f"{getattr(self.ctx.plan, 'cwe', None) or '(no CWE)'} and the plan's kind is "
                                f"{plan.get('kind')!r}")
            try:
                plan = expression_controls(plan)
            except ValueError as exc:
                raise ToolError(str(exc)) from exc
        if plan.get("sql_template") and not plan.get("predicate_template"):
            if plan["kind"] != "boolean" or getattr(self.ctx.plan, "cwe", "") != "CWE-89":
                raise ToolError("SQL challenges apply only to boolean SQL injection experiments")
            try:
                plan = sql_controls(plan)
            except ValueError as exc:
                raise ToolError(str(exc)) from exc
        if plan.get("oob_template"):
            # VER-048: an out-of-band proof is the standard-run form only for blind code-evaluation and template
            # injection, where no response-side proof exists. SQL, NoSQL and XPath keep their cheaper response-side
            # forms, and command execution as the carrier stays out of scope, so none of those are accepted here.
            if getattr(self.ctx.plan, "cwe", "") not in ("CWE-94", "CWE-95", "CWE-1336") or plan["kind"] != "boolean":
                raise ToolError("out-of-band proofs need a code-evaluation or template injection finding "
                                "declared as kind \"boolean\"")
            if self.ctx.listener is None:
                raise ToolError("this run has no callback listener for an out-of-band proof")
            if plan.get("method", "GET") not in SAFE_METHODS and safe_mode:
                raise ToolError("an out-of-band proof on a write needs --allow-intrusive")
            if plan.get("method", "GET") not in SAFE_METHODS and asking:
                needs_writes.append(f"{plan.get('method')} {plan.get('path')}, an out-of-band proof")
            try:
                plan = callback_controls(plan, self.ctx.listener, self.ctx.marker)
            except ValueError as exc:
                raise ToolError(str(exc)) from exc
        if plan.get("auth_artifact") and not (plan.get("sql_template") or plan.get("operator_challenge")):
            # VER-049: a login-bypass proof rides on the generated SQL/NoSQL controls but observes the presence
            # of an authenticated artifact at the (schema-required) pointer instead of a response field.
            raise ToolError("an auth-artifact proof needs a boolean SQL or NoSQL challenge "
                            "(sql_template for CWE-89 or operator_challenge for CWE-943)")
        if plan.get("fixed"):
            if not generates_controls(plan):
                raise ToolError("fixed gives values to the controls the Verifier generates; this plan has none")
            if plan["input_name"] in (plan["fixed"].get(plan.get("input_location")) or {}):
                raise ToolError("fixed must not set the injected input; the generated controls supply it")
            if getattr(self.ctx.plan, "cwe", "") == "CWE-78":
                # Command probes send nothing but the harmless arithmetic controls (_check_steering).
                raise ToolError("command injection probes carry no other values, so fixed is not available")
        groups = [plan[k] for k in ("baseline", "positive", "negative") if k in plan]
        if plan["kind"] == "boolean" and not all(k in plan for k in ("positive", "negative")):
            raise ToolError("boolean experiments need sql_template or explicit positive and negative controls")
        if len({token(v) for v in groups}) != len(groups):
            raise ToolError("control values must be distinct")
        if plan["kind"] == "timing" and "negative" in plan:
            raise ToolError("timing uses baseline and positive only")
        if plan.get("input_location") == "form" and plan.get("method", "GET") in SAFE_METHODS:
            raise ToolError("form experiments need a body-capable write method and intrusive authorization")
        if plan.get("input_location") == "path":
            from .path_inputs import validate_path_input

            validate_path_input(plan["path"], plan.get("input_name") or "")
        variant_note = ""
        if plan.get("variant"):
            from .derivation import covers

            variant, variant_note = _resolve_variant(variants, plan["variant"])
            if variant is None:
                # Second chance: the plan's method and path already carry the intent. If exactly one declared
                # variant uses the same request, take it — the id was only an advisory label.
                pm, pp = plan.get("method", "GET"), plan.get("path", "")
                by_route = [v for v in variants
                            if ((v.get("request") or {}).get("method") == pm
                                and route_matches((v.get("request") or {}).get("path") or "", pp))]
                if len(by_route) == 1:
                    variant = by_route[0]
                    variant_note = (f"variant {plan['variant']!r} accepted as {variant['id']!r} "
                                     "by matching method and path")
                else:
                    raise ToolError(f"unknown finding variant {plan['variant']!r}; variants: "
                                    + _variant_catalog(variants))
            # The canonical id goes into the stored experiment, so later checks and the next_action
            # context use it unambiguously.
            plan = {**plan, "variant": variant["id"]}
            derived = covers(self.ctx, plan)
            vreq = variant["request"]
            # VER-010: an access-control write proof reads with GET and sends the variant's write as its change, so
            # a variant that names the write is met by the change. The schema allows only POST, PUT and PATCH there,
            # and the controller still checks it is a write this finding names and who may send it.
            change = plan.get("change") if plan["kind"] == "access-control" else None
            as_change = bool(change) and vreq["method"] == change["method"] and route_matches(vreq["path"],
                                                                                              change["path"])
            hint = ("; for an access-control write proof read with GET and name this request as change"
                    if plan["kind"] == "access-control" and vreq["method"] not in SAFE_METHODS else "")
            if not derived and not as_change and vreq["method"] != plan.get("method", "GET"):
                raise ToolError(f"the method does not match the finding variant; variant {variant['id']!r} uses "
                                f"{vreq['method']} {vreq.get('path', '')}{hint}")
            if not derived and not as_change and not route_matches(vreq["path"], plan["path"]):
                raise ToolError(f"the path does not match the finding variant; variant {variant['id']!r} uses "
                                f"{vreq['method']} {vreq.get('path', '')}{hint}")
            inputs = vreq.get("inputs", [])
            location = {"params": "query"}.get(plan.get("input_location"), plan.get("input_location"))
            if (
                plan.get("kind") in ("boolean", "timing")
                and not derived
                and inputs
                and not any(i["location"] == location and i["name"] == plan["input_name"] for i in inputs)
            ):
                raise ToolError(f"the input does not match the finding variant; variant {variant['id']!r} declares "
                                + ", ".join(f"{i['location']}:{i['name']}" for i in inputs[:6]))
            missing = missing_capabilities(
                variant, safe=safe_mode, browser=self.ctx.browser is not None,
                identities=bool(getattr(self.ctx, "identities", None)),
            )
            if missing and not derived:
                raise ToolError("this variant needs unavailable capabilities: " + ", ".join(missing))
            if asking and not derived and "state-change" in missing_capabilities(
                    variant, safe=True, browser=True, identities=True):
                needs_writes.append(f"{vreq['method']} {vreq.get('path', '')}, the variant's state change")
            # VER-011: the generated controls are sent as they are, so they must carry every input the variant
            # declares; the request's other inputs come from fixed, a path input from the plan's path.
            if generates_controls(plan) and not derived and inputs:
                given = {("query" if loc == "params" else loc, name)
                         for loc, values in (plan.get("fixed") or {}).items() for name in values}
                given.add((location, plan["input_name"]))
                given |= {("path", name) for name in path_values(vreq["path"], plan["path"])}
                absent = [i for i in inputs if (i["location"], i["name"]) not in given]
                if absent:
                    first = absent[0]
                    example = jsonlib.dumps({"params" if first["location"] == "query" else first["location"]:
                                             {first["name"]: "..."}})
                    raise ToolError("every generated control must carry the inputs the variant declares; give "
                                    + ", ".join(f"{i['location']}:{i['name']}" for i in absent)
                                    + f" a value in fixed, e.g. fixed: {example}")
        marker = None
        if plan["kind"] == "access-control" and not plan.get("resource"):
            methods = access_methods(self.ctx.plan.id, getattr(self.ctx.plan, "cwe", None), self.ctx.scope,
                                     self.ctx.identities, writes=not safe_mode)
            if "resource" in methods:
                raise ToolError("the operator-declared test resource takes precedence; plan with its resource id")
            if plan.get("method", "GET") != "GET":
                raise ToolError("the resource or function is read with GET; a write the finding names goes into "
                                "change, sent by another account to what the owner created")
            if plan.get("owner"):
                if "owner" not in methods:
                    raise ToolError("creating a resource needs two normal accounts and --allow-intrusive (VER-010)")
                if plan["owner"] not in normal_roles(self.ctx.identities):
                    raise ToolError("the owner must be a normal account; a privileged account only reads (VER-041)")
                marker = "".join(self.ctx.marker)
                if asking:      # the owner's write creates the record the comparison reads (VER-010)
                    needs_writes.append(f"a write by {plan['owner']} that creates its test record with the marker")
                if plan.get("change"):
                    if not record_segments(plan["change"]["path"]):
                        raise ToolError("change is the finding's write that changes a record by its identifier in "
                                        "the path, such as PUT /items/:id")
                    # The Verifier's, like the first; its marker part keeps the change attributable (VER-014).
                    second = marker
                    while second == marker:
                        second = self.ctx.marker[0] + secrets.token_hex(4)
                    plan = {**plan, "second_marker": second}
                    if asking:
                        needs_writes.append(f"{plan['change']['method']} {plan['change']['path']} by another "
                                            "account, to that record")
            else:
                if "reference" not in methods:
                    raise ToolError("a privileged comparison needs a privileged and a normal account (VER-041)")
                if plan["reference"] not in privileged_roles(self.ctx.identities):
                    raise ToolError("the reference must be a privileged account")
        elif plan["kind"] == "access-control":
            resource = next(
                (
                    r
                    for r in self.ctx.scope.get("test_resources", [])
                    if r["id"] == plan.get("resource") and r["finding_id"] == self.ctx.plan.id
                ),
                None,
            )
            if (
                resource is None
                or resource["path"] != plan["path"]
                or resource.get("method", "GET") != plan.get("method", "GET")
            ):
                raise ToolError("the plan needs a matching operator-supplied test resource")
        if needs_writes and not self._may_write(needs_writes, plan.get("owner") or plan.get("role") or ""):
            raise ToolError("this plan needs write requests, which safe mode does not send, and the operator did not "
                            "allow them for this finding (VER-030, VER-052): " + "; ".join(needs_writes))
        self._experiment = plan
        notes = []
        if candidates and plan.get("method", "GET") not in SAFE_METHODS:
            notes.append("send_controls uses the first template; revise the plan to try another")
            candidates = []
        self._candidates = [(key, template, declared) for key, template in candidates]
        if assumed:
            notes.append(f"prerequisite {', '.join(assumed)} counts as assumed: observed needs http_request steps "
                         "of this finding with a recorded response")
        if variant_note:
            notes.append(variant_note)
        if needs_writes:
            notes.append("the operator allowed write requests for this finding (VER-052); every write carries the "
                         "finding's marker and creates, never changes what may belong to someone else (VER-014)")
        return {
            "accepted": True,
            "kind": plan["kind"],
            "experiment": plan,
            **({"marker": marker} if marker else {}),
            **({"second_marker": plan["second_marker"]} if plan.get("second_marker") else {}),
            **({"note": "; ".join(notes)} if notes else {}),
        }

    def next_candidate(self):
        """The next candidate template of the accepted plan, declared and checked like the first (VER-011), as
        (the declaration, the plan_test result); None when there is none left. A candidate the checks refuse is
        skipped."""
        while getattr(self, "_candidates", None):
            key, template, declared = self._candidates.pop(0)
            remaining = self._candidates
            args = {**declared, key: template}
            try:
                result = self.plan_test(**args)
            except ToolError:
                self._candidates = remaining
                continue
            self._candidates = remaining
            return args, result
        return None

    def experiment_requests(self, *, role=None, write=False):
        """The accepted challenge's generated controls as requests, or a read plan's own controls (VER-011). A read
        plan's controls run when the
        plan is accepted (`write` False); a write plan's only when the agent asks with send_controls in intrusive
        mode (`write` True), and only once per plan. Each control is sent twice, an auth-artifact control once,
        because that proof needs no repetition (VER-049)."""
        plan = getattr(self, "_experiment", {})
        # A read plan's own controls, values the agent chose, run the same way; never a write's (VER-011).
        if not generates_controls(plan) and (write or not agent_controls(plan)):
            raise ToolError("the accepted plan is not a challenge whose controls the Verifier generates and sends")
        is_write = plan.get("method", "GET") not in SAFE_METHODS
        if is_write and not write:
            raise ToolError("a write plan's controls are sent only when you call send_controls")
        if write and not is_write:
            raise ToolError("a read plan's controls already ran when the plan was accepted")
        if write and (self.ctx.safe or self.ctx.read_only):
            raise ToolError("controls on a write need --allow-intrusive and a scope that permits state change "
                            "(VER-030)")
        if not hasattr(self, "_controls_sent"):
            self._controls_sent = set()
        if write and token(plan) in self._controls_sent:
            raise ToolError("this plan's controls were already sent; revise the plan for another experiment")
        location = "path_inputs" if plan.get("input_location") == "path" else plan["input_location"]
        fixed = plan.get("fixed") or {}
        # Every control carries the same fixed values for the request's other inputs; only the declared input
        # differs (VER-011).
        requests = [
            {
                "path": plan["path"],
                "method": plan.get("method", "GET"),
                **({"role": role} if role else {}),
                **{k: dict(v) for k, v in fixed.items()},
                location: {**fixed.get(location, {}),
                           plan["input_name"]: str(plan[group]) if location == "path_inputs" else plan[group]},
            }
            for _ in range(1 if plan.get("auth_artifact") else 2)
            for group in ("baseline", "positive", "negative", "positive_other", "negative_other")
            if group in plan
        ]
        if write:
            self._controls_sent.add(token(plan))
        return requests

    def release_controls(self):
        """A write plan none of whose controls reached the target, all refused before sending, counts as not sent,
        so a second send_controls names the refusal instead of claiming the controls ran."""
        getattr(self, "_controls_sent", set()).discard(token(getattr(self, "_experiment", {})))

    def read_context(self, *, variant: str | None = None, field: str | None = None) -> dict:
        variants = getattr(self.ctx.plan, "verification_context", {}).get("variants", [])
        note = ""
        if variant:
            value, note = _resolve_variant(variants, variant)
            if value is None:
                raise ToolError(f"unknown finding variant {variant!r}; variants: "
                                + (_variant_catalog(variants) or "none declared"))
        else:
            value = {**getattr(self.ctx.plan, "context", {}), "prior_results": getattr(self.ctx, "prior_results", [])}
        if field:
            if field not in value:
                available = ", ".join(sorted(value.keys())) or "no fields in this context"
                raise ToolError(f"that context field is unavailable; available: {available}")
            value = {field: value[field]}
        out = {"context": value, "trust": "analysis data; assumptions need runtime checks"}
        if note:
            out["note"] = note
        return out

    def read_response(self, *, steps: list[int], pointer: str | None = None, offset: int = 0) -> dict:
        out = []
        for n in steps:
            response = getattr(self.ctx, "responses", {}).get(n)
            if response is None:
                raise ToolError("no recorded response for that step in this finding")
            body = response["body"]
            if pointer is not None:
                try:
                    if not response["complete"]:
                        raise ValueError("incomplete")
                    body = token(pointer_value(body, pointer))
                except (ValueError, TypeError, KeyError, IndexError, RecursionError) as exc:
                    raise ToolError("the JSON pointer cannot be read from this response") from exc
            out.append(
                {
                    "step": n,
                    "text": body[offset : offset + 1500],
                    "length": len(body),
                    "complete": response["complete"],
                    "more": len(body) > offset + 1500,
                }
            )
        return {
            "responses": out,
            "equal": len(out) == 2
            and all(r["complete"] and not r["more"] for r in out)
            and offset == 0
            and out[0]["text"] == out[1]["text"],
        }

    def take_exchanges(self) -> list[dict]:
        """The redacted exchanges the last tool call sent and received, for the proof of concept (VER-034).
        They never go into a tool result, so the model does not see them."""
        out, self._exchanges = self._exchanges, []
        return out

    def _record(
        self, raw: dict, role: str | None, identity: dict, *, keep_body: bool = True, navigation: bool = False
    ) -> None:
        omit = None if keep_body else "body not kept for this resource type"
        if omit is None and self._kept >= poc.MAX_FINDING_BODY_CHARS:
            omit = "body not kept: the finding's proof of concept reached its size limit"
        sessions = self.ctx.sessions
        e = poc.entry(
            raw,
            redact=sessions.redact if sessions is not None else None,
            identity=identity,
            role=role,
            omit_body=omit,
            navigation=navigation,
        )
        self._kept += len(e["response"]["content"].get("text") or "")
        self._exchanges.append(e)

    def call(self, name: str, args: dict) -> dict:
        tool = {
            "derive_request": self.derive_request,
            "archive_probe": self.archive_probe,
            "http_request": self.http_request,
            "read_source": self.read_source,
            "find_source": self.find_source,
            "search_source": self.search_source,
            "browser_check": self.browser_check,
            "plan_test": self.plan_test,
            "read_context": self.read_context,
            "read_response": self.read_response,
        }.get(name)
        if tool is None:
            raise ToolError(f"unknown tool {name!r}; available: http_request, read_source, browser_check")
        return _hide(tool(**args), self._marker_content)  # the model never sees the marker file's content

    def archive_probe(self, *, check_id: str, role: str | None = None) -> dict:
        from .archive_probe import run

        return run(self, check_id, role)

    def _check_steering(self, params, body) -> None:
        """Path-traversal and SSRF probes aim only at the marker file and the callback listener (VER-012)."""
        cls, values = self.ctx.plan.cls, [*_strings(params), *_strings(body)]
        if getattr(self.ctx.plan, "cwe", "") == "CWE-78":
            plan = getattr(self, "_experiment", {})
            allowed = {
                plan[k]
                for k in ("baseline", "positive", "negative", "positive_other", "negative_other")
                if k in plan and isinstance(plan[k], str)
            }
            if any(value not in allowed for value in values):
                raise ToolError("command probes use only the accepted harmless arithmetic controls")
        if cls == "path-traversal":
            name = self._marker_name
            for value in values:
                path = _file_path(value)
                if path is not None and not (name and (path == name or path.endswith("/" + name))):
                    raise ToolError(
                        "a path-traversal probe may name only the scope's marker file"
                        + (f" ({name})" if name else "; this scope names none")
                        + " (VER-012)"
                    )
        elif cls == "ssrf":
            base = self.ctx.listener.base_url if self.ctx.listener is not None else None
            for value in values:
                d = _decoded(value)
                if d.startswith("//") and base:
                    d = urlsplit(base).scheme + ":" + d
                if ("://" in d or d.startswith("//")) and not (base and same_origin(d, base)):
                    raise ToolError(
                        "an SSRF probe may point the target only at the callback listener"
                        + (f" ({base}/…)" if base else "; this run has none")
                        + " (VER-012)"
                    )
        elif cls == "injection" and getattr(self, "_experiment", {}).get("oob_template"):
            # The sink is a payload that embeds a URL, not a bare URL: check each embedded URL points at the
            # listener, so an injection proof cannot be steered at another host (VER-012, VER-048).
            base = self.ctx.listener.base_url if self.ctx.listener is not None else None
            for value in values:
                for url in re.findall(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>)\\]+", _decoded(value)):
                    if not (base and same_origin(url, base)):
                        raise ToolError(
                            "an out-of-band injection probe may carry a URL only to the callback listener"
                            + (f" ({base}/…)" if base else "; this run has none")
                            + " (VER-012)"
                        )

    def browser_check(self, *, path: str, role: str | None = None, wait_ms: int = 1500) -> dict:
        from ..tools.browser import BrowserError

        if self.ctx.plan.cls != "xss":
            raise ToolError("the proof browser is only available for XSS findings")
        if self.ctx.browser is None:
            raise ToolError("no proof browser in this run; install appsec-verifier[browser] and Google Chrome")
        headers, origin = {}, self.ctx.target_base
        if role:
            origin = self._bound_origin(role)
            headers = self._session_headers(role)
        url = self._url(path)
        if not isinstance(wait_ms, int) or isinstance(wait_ms, bool):
            raise ToolError("wait_ms must be an integer number of milliseconds")
        try:
            # The browser attaches the identity headers only to requests for `origin` (VER-018).
            result = self.ctx.browser.check(
                url,
                identity_headers=headers,
                target_base=origin,
                marker=self.ctx.marker,
                finding_id=self.ctx.plan.id,
                name=evidence_name(self.ctx.plan),
                wait_ms=wait_ms,
                safe=self.ctx.safe or self.ctx.read_only or bool(role and self._privileged(role)),
                role=role,
            )
        except BrowserError as exc:
            raise ToolError(str(exc)) from exc
        for raw in result.pop("_exchanges", None) or []:
            self._record(
                raw, role, headers, keep_body=raw.get("keep_body", True), navigation=raw.get("navigation", False)
            )
        return result

    def _url(self, path) -> str:
        """An absolute http(s) URL as given, anything else appended below the target base URL.
        Unlike urljoin, this keeps `..` in the URL, where the guard refuses it (VER-018)."""
        path = str(path)
        try:
            scheme = urlsplit(path).scheme
        except ValueError as exc:
            raise ToolError("the path is not a parseable URL path") from exc
        if scheme in ("http", "https"):
            return path
        return self.ctx.target_base.rstrip("/") + "/" + path.lstrip("/")

    def _ask_writes(self):
        """The operator's question for write requests safe mode does not send, or None (VER-052)."""
        return getattr(self.ctx, "ask_writes", None)

    def _may_write(self, requests: list[str], identity: str) -> bool:
        """Whether this finding may send write requests: in intrusive mode, or after the operator allowed them,
        which turns this finding intrusive (VER-052). The agent's step note is shown as its reason."""
        if not (self.ctx.safe or self.ctx.read_only):
            return True
        ask = self._ask_writes()
        if ask is None or not ask(requests, getattr(self, "note", None), identity):
            return False
        self.ctx.safe = self.ctx.read_only = False
        return True

    def _privileged(self, role: str) -> bool:
        """Whether `role` is a privileged account, which only reads (VER-041)."""
        return any(i.get("role") == role and i.get("privileged") for i in (self.ctx.identities or []))

    def _bound_origin(self, role: str) -> str:
        """The origin `role`'s credentials may be sent to (VER-018, VER-028)."""
        if self.ctx.sessions is None:
            raise ToolError("no identities are configured for this run")
        return self.ctx.sessions.origin_for(role) or self.ctx.target_base

    def _session_headers(self, role: str) -> dict:
        try:
            return self.ctx.sessions.headers_for(role)
        except (AuthError, ScopeViolation) as exc:
            raise ToolError(f"identity {role!r} is unavailable: {exc}") from exc
        except (httpx.HTTPError, httpx.InvalidURL, OSError) as exc:  # the message can carry a proxy URL
            raise ToolError(f"identity {role!r} is unavailable: its login failed ({type(exc).__name__})") from exc

    def http_request(
        self,
        *,
        role: str | None = None,
        method: str = "GET",
        path: str = "/",
        params: dict | None = None,
        json: dict | None = None,
        form: dict | None = None,
        path_inputs: dict | None = None,
        prerequisite: bool = False,
    ) -> dict:
        # `prerequisite` (VER-047) is read by the controller to authorise a harmless read the finding's own
        # request needs but the assessment never names; the request itself is sent and recorded normally.
        m = (method or "GET").upper()
        original_path = path
        if path_inputs is not None:
            self._check_steering(None, path_inputs)
            from .path_inputs import bind_path_input

            path = bind_path_input(self.ctx, getattr(self, "_experiment", {}), path, path_inputs)
        if getattr(self.ctx.plan, "cwe", "") == "CWE-78":
            experiment = getattr(self, "_experiment", {})
            supplied = {"params": params, "json": json, "form": form, "path": path_inputs}
            selected = supplied.get(experiment.get("input_location")) or {}
            if (
                original_path != experiment.get("path")
                or urlsplit(path).query
                or urlsplit(path).fragment
                or m != experiment.get("method", "GET")
                or set(selected) != {experiment.get("input_name")}
                or any(v for k, v in supplied.items() if k != experiment.get("input_location"))
            ):
                raise ToolError("command proof requests must match the declared arithmetic input exactly")
        if self.ctx.plan.cls == "session" and not any(
            r["finding_id"] == self.ctx.plan.id
            and r["path"] == path
            and m == "GET"
            and r.get("role") == role
            and not any((params, json, form))
            for r in self.ctx.scope.get("session_checks", [])
        ):
            raise ToolError("session checks use only the operator-declared read-only cookie observation")
        if getattr(self.ctx.plan, "cwe", "") in ("CWE-200", "CWE-306"):
            resources = self.ctx.scope.get("test_resources", [])
            if not any(
                r["finding_id"] == self.ctx.plan.id
                and r["path"] == path
                and r.get("method", "GET") == m
                and m in SAFE_METHODS
                and all((r.get(k) or {}) == (v or {}) for k, v in (("params", params), ("json", json), ("form", form)))
                for r in resources
            ):
                raise ToolError("exposure checks use only the operator-declared harmless read-only resource")
        if m not in ALLOWED_METHODS:
            raise ToolError(f"{m} is never sent; allowed methods are {', '.join(ALLOWED_METHODS)} (VER-014)")
        if m not in SAFE_METHODS and (self.ctx.safe or self.ctx.read_only) and self._ask_writes() is None:
            raise ToolError(f"{m} is disabled in safe/read-only mode (VER-014/030); use --allow-intrusive")
        if m not in SAFE_METHODS and role and self._privileged(role):
            raise ToolError(f"{role} is a privileged account and only reads (VER-041); write as a normal account")
        if self.ctx.http is None or not self.ctx.target_base:
            raise ToolError("no HTTP transport is wired for this run")
        if json is not None and form is not None:
            raise ToolError("choose one body format: json or form")
        if form is not None and m in SAFE_METHODS:
            raise ToolError("form bodies require POST, PUT or PATCH")
        self._url(path)  # reject malformed URLs as tool errors before parsing their query
        query = parse_qsl(urlsplit(path).query, keep_blank_values=True)
        self._check_steering(dict(query), None)
        # Check every duplicate too; converting to a dict alone could hide a forbidden value.
        self._check_steering(None, [v for _, v in query])
        self._check_steering(params, json)
        self._check_steering(None, form)
        attempt_marker = None
        callback_cls = self.ctx.plan.cls == "ssrf" or (
            self.ctx.plan.cls == "injection" and (getattr(self, "_experiment", None) or {}).get("oob_template"))
        if callback_cls and self.ctx.listener is not None:
            from ..tools.browser import new_marker

            marker = "".join(self.ctx.marker)
            values = [*_strings(params), *_strings(json), *_strings(form), *(v for _, v in query)]
            if marker and any(marker in v for v in values):
                attempt_marker = "".join(new_marker())

                def replace_marker(value):
                    if isinstance(value, str):
                        return value.replace(marker, attempt_marker)
                    if isinstance(value, dict):
                        return {k: replace_marker(v) for k, v in value.items()}
                    if isinstance(value, list):
                        return [replace_marker(v) for v in value]
                    return value

                params, json, form = (replace_marker(v) for v in (params, json, form))
                path = urlsplit(path)._replace(query=urlencode([(k, replace_marker(v)) for k, v in query])).geturl()
        url = self._url(path)
        headers = {}
        if role:
            origin = self._bound_origin(role)
            if not same_origin(url, origin):
                raise ToolError(
                    f"identity {role!r} is bound to {origin}; its credentials are not sent to "
                    f"another origin (VER-018). Send this request without a role."
                )
        # VER-052: every other check has passed, so the operator is asked only for a write the run would send in
        # intrusive mode; before the session headers, which may sign in.
        if m not in SAFE_METHODS and not self._may_write([f"{m} {urlsplit(url).path or '/'}"], role or ""):
            raise ToolError(f"{m} is disabled in safe/read-only mode (VER-014/030); the operator did not allow "
                            "write requests for this finding (VER-052)")
        if role:
            headers = self._session_headers(role)
        try:
            resp = self._send(m, url, headers, params, json, form)
            from .session_proof import cookie_observations

            session_cookies = cookie_observations(resp, self.ctx.sessions) if self.ctx.plan.cls == "session" else []
            self._record(self._sent(resp, m, url, headers, params, json, form), role, headers)
            sessions = self.ctx.sessions if role else None
            if sessions is not None:
                sessions.answered(role, getattr(resp, "status_code", None))
            # VER-028: re-obtain the session once when the target rejects it as unauthenticated (401), unless a
            # new session already met a 401 (sessions.renew). A 403 is an authorisation answer, often the very
            # result under test; a new login cannot change it.
            if m in SAFE_METHODS and sessions is not None and getattr(resp, "status_code", None) == 401 \
                    and sessions.renew(role):
                headers = self._session_headers(role)
                resp = self._send(m, url, headers, params, json, form)
                session_cookies = cookie_observations(resp, self.ctx.sessions) if self.ctx.plan.cls == "session" else []
                self._record(self._sent(resp, m, url, headers, params, json, form), role, headers)
                sessions.answered(role, getattr(resp, "status_code", None))
        except ScopeViolation as exc:
            raise ToolError(f"request refused — out of scope: {exc}") from exc
        except (httpx.HTTPError, httpx.InvalidURL, OSError) as exc:
            raise ToolError(f"request failed: {type(exc).__name__}") from exc
        text = _body_text(resp)
        redacted = self.ctx.sessions.redact(text) if self.ctx.sessions is not None else text
        redacted = _hide(redacted, self._marker_content)  # before the cut, so no part of the marker remains
        experiment = getattr(self, "_experiment", None) or {}
        auth_artifact_probe = self.ctx.plan.cls == "injection" and experiment.get("auth_artifact")
        auth_present = _auth_artifact_present(text, experiment.get("pointer")) if auth_artifact_probe else None
        if auth_artifact_probe:
            # The presence is kept; the body itself stands down everywhere it could be read: the recorded body
            # (read_response), the excerpt the model sees, and the hash (VER-049, VER-016).
            text = redacted = _AUTH_ARTIFACT_NOTICE
        identity_key = tuple(sorted(headers.items()))
        identity = self._identities.setdefault(identity_key, len(self._identities))
        cap = min(64000, max(0, 256000 - self._response_chars))
        # Whether two answers are the same, also where redaction made them look alike (each naming its own user):
        # keyed with this finding's random key, held in memory only, so it is no hash of a credential.
        digest = hmac.new(self._digest_key, text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()
        self._last_response = {"body": redacted[:cap], "complete": len(redacted) <= cap, "identity": identity,
                               "digest": digest}
        self._response_chars += min(len(redacted), cap)
        status = getattr(resp, "status_code", None)
        out = {
            "role": role,
            "status": status,
            "length": len(text),  # of the whole body, not of the excerpt
            # of the redacted body, so no hash of a credential exists; lets the proof check compare answers
            "body_sha256": hashlib.sha256(redacted.encode("utf-8", "replace")).hexdigest(),
            "body_excerpt": redacted[:_BODY_EXCERPT],  # redacted before the cut: no partial token (VER-016)
        }
        resp_headers = getattr(resp, "headers", None) or {}
        location = resp_headers.get("Location") or resp_headers.get("location")
        if isinstance(status, int) and 300 <= status < 400 and location:
            location = str(location)
            location = self.ctx.sessions.redact(location) if self.ctx.sessions is not None else location
            out["location"] = _hide(location, self._marker_content)[:_LOCATION_CAP]
        if self.ctx.plan.cls == "session":
            out["session_cookies"] = session_cookies
        if auth_artifact_probe:
            out["auth_artifact"] = bool(auth_present)   # the code's observation; the token value is withheld
        plan = getattr(self, "_experiment", None) or {}
        if plan.get("change") and role == plan.get("owner") and isinstance(status, int) and 200 <= status < 300:
            # A change may name only a record the owner's write created (its answer's id) and the owner's read
            # then showed with the marker, so it is that record (VER-010, agent/controller.py).
            for name in ("created", "owned"):
                if getattr(self.ctx, name, None) is None:
                    setattr(self.ctx, name, set())
            if m in ("POST", "PUT", "PATCH"):
                self.ctx.created.update(_created_ids(text, location))
            elif m == "GET" and all(self.ctx.marker) and "".join(self.ctx.marker) in text:
                segments = [unquote(s) for s in record_segments(plan["path"], path)]
                if segments and all(s in self.ctx.created for s in segments):
                    self.ctx.owned.update(segments)
        elapsed = _elapsed_ms(resp)
        if elapsed is not None:
            out["elapsed_ms"] = elapsed  # transport time, without the rate limit's wait (VER-011)
        if self.ctx.plan.cls == "path-traversal" and self._marker_content:
            out["marker_read"] = self._marker_content in text  # the raw body, checked in code
        if callback_cls and self.ctx.listener is not None:
            out["callback_hit"] = bool(attempt_marker and self.ctx.listener.wait_for(attempt_marker, _CALLBACK_WAIT_S))
            if attempt_marker:
                out["callback_attempt"] = attempt_marker
                records = getattr(self.ctx, "callback_records", {})
                records[attempt_marker] = self.ctx.listener.hits(attempt_marker) if out["callback_hit"] else []
                self.ctx.callback_records = records
        return out

    @staticmethod
    def _sent(resp, method, url, headers, params, body, form=None) -> dict:
        """The exchange as sent: the transport's own record when it keeps one, else what this tool passed on."""
        sent_headers = dict(headers)
        if body is not None:
            sent_headers.setdefault("content-type", "application/json")
        if form is not None:
            sent_headers.setdefault("content-type", "application/x-www-form-urlencoded")
        try:
            full = str(httpx.URL(url, params=params)) if params else url
        except (TypeError, ValueError, httpx.InvalidURL):
            full = url
        return poc.capture(
            resp,
            method=method,
            url=full,
            headers=sent_headers,
            body=urlencode(form) if form is not None else None if body is None else jsonlib.dumps(body),
        )

    def _send(self, method, url, headers, params, json, form=None):
        kwargs = {}
        if params:
            kwargs["params"] = params
        if json is not None:
            kwargs["json"] = json
        if form is not None:
            kwargs["data"] = form
        # Not followed: the agent sees the redirect itself (VER-012) and sends any next hop as its own request.
        return self.ctx.http.request(method, url, headers, purpose="target", follow_redirects=False, **kwargs)

    def read_source(self, *, path: str, around_line: int | None = None) -> dict:
        if self.ctx.source is None:
            raise ToolError("no source checkout is available for this run")
        try:
            return self.ctx.source.read_window(path, around_line=around_line)
        except SourceAccessError as exc:
            raise ToolError(str(exc)) from exc

    def find_source(self, *, query: str) -> dict:
        if self.ctx.source is None:
            raise ToolError("no source checkout is available for this run")
        try:
            out = self.ctx.source.find(query)
        except SourceAccessError as exc:
            raise ToolError(str(exc)) from exc
        if not out.get("matches"):
            # A symbol or route string never matches a file name; say so instead of an empty answer (VER-050).
            out["note"] = ("find_source matches file names and paths only, not file contents; use search_source to "
                           "find a symbol, route or string inside files")
        return out

    def search_source(self, *, text: str) -> dict:
        """VER-050: literal content search inside the source checkout, under the same confinement as read_source."""
        if self.ctx.source is None:
            raise ToolError("no source checkout is available for this run")
        try:
            return self.ctx.source.search(text)
        except SourceAccessError as exc:
            raise ToolError(str(exc)) from exc
