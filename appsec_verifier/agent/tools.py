"""The exact, narrow tool surface the verification agent is confined to
(VER-017). The agent never gets a shell or raw network: it can issue an HTTP
request to the target as one of the configured identities (scope-guarded),
read the evidenced source (repository-confined), and, for XSS findings, load a
page in the proof browser whose requests go through the same guard (VER-009,
VER-018). Request derivation checks recorded evidence without contacting the
target (VER-008, VER-043).

An identity's credentials go only to the origin it is bound to (its
`target_origin`, by default the target base URL), never to another host in the
scope (VER-018, VER-028). Only GET, HEAD and OPTIONS are sent in safe mode, and
POST, PUT and PATCH only in intrusive mode, with the finding's marker and
without naming an existing record in the path (agent/controller.py); DELETE and
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
from ..verification_context import missing_capabilities, record_segments, route_matches
from ..verify import poc
from .experiments import PLAN_SCHEMA, access_methods, normal_roles, pointer_value, privileged_roles, token
from .source_reader import SourceAccessError

_BODY_EXCERPT = 600
_LOCATION_CAP = 2000
_HIDDEN = "[marker-file]"
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


class ToolError(Exception):
    """A tool call was rejected or malformed. Surfaced to the agent as an error
    result, never raised past the loop."""


def _body_text(resp) -> str:
    text = getattr(resp, "text", None)
    if text is None:
        content = getattr(resp, "content", b"") or b""
        text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
    return text


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
        if not Draft202012Validator(PLAN_SCHEMA).is_valid(plan):
            raise ToolError("invalid experiment declaration")
        # An observed prerequisite needs recorded responses of this finding; one without them counts as assumed,
        # which grants nothing (only a missing one matters, proof.py), so the plan need not be declared again.
        responses = getattr(self.ctx, "responses", {})
        prerequisites, assumed = [], []
        for i, prerequisite in enumerate(plan["strategy"]["prerequisites"], 1):
            steps = prerequisite.get("steps", [])
            if prerequisite["status"] == "observed" and (not steps or any(n not in responses for n in steps)):
                prerequisite = {**prerequisite, "status": "assumed"}
                assumed.append(str(i))
            prerequisites.append(prerequisite)
        plan = {**plan, "strategy": {**plan["strategy"], "prerequisites": prerequisites}}
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
            intrusive = not (self.ctx.safe or self.ctx.read_only)
            if is_write and not intrusive:
                # VER-011 + VER-030: writes repeat only in intrusive mode; the agent sends each control itself.
                problems.append("an experiment sends every control twice; a write needs --allow-intrusive")
        if problems:
            raise ToolError("; ".join(problems))
        from .experiments import expression_controls, ldap_controls, operator_controls, sql_controls

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
        if plan.get("variant"):
            from .derivation import covers

            variant = next((v for v in variants if v["id"] == plan["variant"]), None)
            if variant is None:
                raise ToolError(f"unknown finding variant {plan['variant']!r}; variants: "
                                + _variant_catalog(variants))
            derived = covers(self.ctx, plan)
            vreq = variant["request"]
            if not derived and vreq["method"] != plan.get("method", "GET"):
                raise ToolError(f"the method does not match the finding variant; variant {variant['id']!r} uses "
                                f"{vreq['method']} {vreq.get('path', '')}")
            if not derived and not route_matches(vreq["path"], plan["path"]):
                raise ToolError(f"the path does not match the finding variant; variant {variant['id']!r} uses "
                                f"{vreq['method']} {vreq.get('path', '')}")
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
                variant, safe=self.ctx.safe or self.ctx.read_only, browser=self.ctx.browser is not None
            )
            if missing and not derived:
                raise ToolError("this variant needs unavailable capabilities: " + ", ".join(missing))
        marker = None
        if plan["kind"] == "access-control" and not plan.get("resource"):
            methods = access_methods(self.ctx.plan.id, getattr(self.ctx.plan, "cwe", None), self.ctx.scope,
                                     self.ctx.identities, writes=not (self.ctx.safe or self.ctx.read_only))
            if "resource" in methods:
                raise ToolError("the operator-declared test resource takes precedence; plan with its resource id")
            if plan.get("method", "GET") != "GET":
                raise ToolError("the resource or function is read with GET")
            if plan.get("owner"):
                if "owner" not in methods:
                    raise ToolError("creating a resource needs two normal accounts and --allow-intrusive (VER-010)")
                if plan["owner"] not in normal_roles(self.ctx.identities):
                    raise ToolError("the owner must be a normal account; a privileged account only reads (VER-041)")
                marker = "".join(self.ctx.marker)
                if plan.get("change"):
                    if not record_segments(plan["change"]["path"]):
                        raise ToolError("change is the finding's write that changes a record by its identifier in "
                                        "the path, such as PUT /items/:id")
                    # The Verifier's, like the first; its marker part keeps the change attributable (VER-014).
                    second = marker
                    while second == marker:
                        second = self.ctx.marker[0] + secrets.token_hex(4)
                    plan = {**plan, "second_marker": second}
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
        if getattr(self, "_experiment", None) and not plan["strategy"].get("revision_reason"):
            raise ToolError("a revised plan must explain the new observation and the next change")
        self._experiment = plan
        return {
            "accepted": True,
            "kind": plan["kind"],
            "experiment": plan,
            **({"marker": marker} if marker else {}),
            **({"second_marker": plan["second_marker"]} if plan.get("second_marker") else {}),
            **({"note": f"prerequisite {', '.join(assumed)} counts as assumed: observed needs http_request steps "
                        "of this finding with a recorded response"} if assumed else {}),
            "next": "collect observations; run_experiment repeats read-only injection controls within the budget",
        }

    def experiment_requests(self, *, role=None):
        plan = getattr(self, "_experiment", {})
        if plan.get("kind") != "boolean" or not (
            plan.get("sql_template") or plan.get("expression_template") or plan.get("operator_challenge")
        ):
            raise ToolError("run_experiment needs an accepted SQL challenge plan")
        if plan.get("method", "GET") not in SAFE_METHODS:
            raise ToolError("automatic repetitions are read-only; writes are never automatically repeated. "
                            "Send each control value as its own http_request step, twice per control.")

        location = "path_inputs" if plan.get("input_location") == "path" else plan["input_location"]
        return [
            {
                "path": plan["path"],
                "method": plan.get("method", "GET"),
                **({"role": role} if role else {}),
                location: {plan["input_name"]: str(plan[group]) if location == "path_inputs" else plan[group]},
            }
            for _ in range(2)
            for group in ("baseline", "positive", "negative", "positive_other", "negative_other")
            if group in plan
        ]

    def read_context(self, *, variant: str | None = None, field: str | None = None) -> dict:
        variants = getattr(self.ctx.plan, "verification_context", {}).get("variants", [])
        if variant:
            value = next((v for v in variants if v["id"] == variant), None)
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
        return {"context": value, "trust": "analysis data; assumptions need runtime checks"}

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
    ) -> dict:
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
        if m not in SAFE_METHODS and (self.ctx.safe or self.ctx.read_only):
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
        if self.ctx.plan.cls == "ssrf" and self.ctx.listener is not None:
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
        if self.ctx.plan.cls == "ssrf" and self.ctx.listener is not None:
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
