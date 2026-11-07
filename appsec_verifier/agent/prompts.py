"""The action schemas and prompts every model host shares (VER-017, VER-019).

`_tool_defs()` lists the only actions a planner may propose — the confined
tools (http_request, read_source, browser_check) plus submit_verdict — and
steps.py builds the strict step contract from them. `_system()` and `_seed()`
describe the task and the run mode; no credential and no target content is
part of them.
"""

from __future__ import annotations

_RESULT_CAP = 4000  # bound tool-result text fed back to the model (tokens/cost)

_VERDICT_ENUM = ["confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted"]


def _tool_defs() -> list[dict]:
    return [
        {
            "name": "http_request",
            "description": "Send one HTTP request to the target as a test identity. "
                           "Path is relative to the target base URL. Safe mode allows only GET/HEAD/OPTIONS; "
                           "POST/PUT/PATCH need intrusive mode; other methods are never sent. A role's "
                           "credentials go only to its own origin.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "role": {"type": "string", "description": "identity role label, or omit for unauthenticated"},
                    "method": {"type": "string", "default": "GET"},
                    "path": {"type": "string"},
                    "params": {"type": "object",
                               "additionalProperties": {"type": ["string", "integer", "number", "boolean"]}},
                    "json": {"type": "object"},
                },
                "required": ["path"],
            },
        },
        {
            "name": "read_source",
            "description": "Read a window of the target's source to locate the route/parameter for the finding.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "around_line": {"type": "integer"}},
                "required": ["path"],
            },
        },
        {
            "name": "browser_check",
            "description": "XSS findings only: load one target page (GET, path relative to the target base URL, "
                           "payload in the path or query) in the headless proof browser, optionally as an "
                           "identity, and report whether your marker expression executed. Requests the page "
                           "makes stay within the scope and run mode.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "role": {"type": "string", "description": "identity role label, or omit for unauthenticated"},
                    "wait_ms": {"type": "integer", "minimum": 0, "maximum": 5000},
                },
                "required": ["path"],
            },
        },
        {
            "name": "submit_verdict",
            "description": "Submit the final verdict for this finding and end the probe.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": _VERDICT_ENUM},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "rationale": {"type": "string"},
                    "identities_used": {"type": "array", "items": {"type": "string"}},
                    "proof": {"type": "object"},
                    "evidence": {"type": "array", "items": {"type": "object"}},
                    "deviation": {"type": "string"},
                    "observations": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["verdict", "rationale"],
            },
        },
    ]


def _system(ctx) -> str:
    roles = ", ".join(i.get("role") for i in (ctx.identities or []) if i.get("role")) or "none configured"
    mode = "SAFE (read-only; GET/HEAD/OPTIONS only; one benign payload; no noisy probing)" if ctx.safe else "intrusive"
    return (
        "You verify ONE static security finding against the running target, and only that finding. "
        "Use only the provided tools; never attempt anything outside them. "
        f"Run mode: {mode}. Available identity roles: {roles}.\n"
        "For access-control/IDOR: fetch the same resource as two different identities and compare what each "
        "receives; it is confirmed only if one identity reaches or alters another's resource. "
        "For XSS: a verdict of confirmed requires evidence the payload executes, not just that it is reflected. "
        "For injection: rely on an observable response/timing difference, never on exfiltrated data. "
        "Do not pursue other weaknesses; note anything incidental as an observation. "
        "When you have enough evidence — or cannot get it — call submit_verdict. "
        "If you cannot reproduce it, say not-reproducible or inconclusive; do not guess confirmed."
        + _xss_marker_hint(ctx)
    )


def _xss_marker_hint(ctx) -> str:
    plan, marker = getattr(ctx, "plan", None), getattr(ctx, "marker", ("", ""))
    if getattr(plan, "cls", None) != "xss" or not all(marker):
        return ""
    return (
        f"\nXSS proof: your payload must call alert('{marker[0]}'+'{marker[1]}') — the two parts joined at "
        "runtime (quotes may change to fit the context). Only that evaluated value counts as execution, and only "
        "browser_check observes it; confirmed without an executed marker is downgraded."
    )


def _seed(ctx) -> str:
    p = ctx.plan
    return (
        f"Finding {p.id} ({p.cwe}, class {p.cls}): {p.title}\n"
        f"Evidence location: {p.instance}\n"
        f"Scenario/notes: {getattr(p, 'reason', '')}\n"
        f"Target base URL: {ctx.target_base}\n"
        "Plan and execute the verification, then submit_verdict."
    )
