"""Anthropic-backed planner: the model that drives an AgentProbe (VER-028).

Implements the Planner protocol over the Anthropic Messages API tool-use loop.
The Anthropic client is injected, so the message threading, tool-schema, and
response parsing are unit-tested with a fake client; a real client is built
lazily (requires the optional `anthropic` dependency). The agent is offered only
the confined tools (http_request, read_source) plus submit_verdict; `tool_choice`
is auto (forced tool use is rejected on current models).
"""

from __future__ import annotations

import json

DEFAULT_MODEL = "claude-opus-5-5"
_MAX_TOKENS = 8000
_RESULT_CAP = 4000  # bound tool-result text fed back to the model (tokens/cost)

_VERDICT_ENUM = ["confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted"]


def _tool_defs() -> list[dict]:
    return [
        {
            "name": "http_request",
            "description": "Send one HTTP request to the target as a test identity. "
                           "Path is relative to the target base URL. Safe mode allows only GET/HEAD/OPTIONS.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "role": {"type": "string", "description": "identity role label, or omit for unauthenticated"},
                    "method": {"type": "string", "default": "GET"},
                    "path": {"type": "string"},
                    "params": {"type": "object"},
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


class AnthropicPlanner:
    def __init__(self, *, model: str = DEFAULT_MODEL, client=None, api_key: str | None = None,
                 max_tokens: int = _MAX_TOKENS):
        self._model = model
        self._max_tokens = max_tokens
        self._client = client if client is not None else _default_client(api_key)
        self._messages: list[dict] = []
        self._started = False
        self._pending_assistant = None   # assistant content blocks holding the last tool_use
        self._pending_tool_id = None

    def next_step(self, ctx, history: list[dict]) -> dict:
        if not self._started:
            self._messages = [{"role": "user", "content": _seed(ctx)}]
            self._started = True
        elif history and self._pending_tool_id is not None:
            result = history[-1].get("result")
            self._messages.append({"role": "assistant", "content": self._pending_assistant})
            self._messages.append({"role": "user", "content": [{
                "type": "tool_result",
                "tool_use_id": self._pending_tool_id,
                "content": json.dumps(result, default=str)[:_RESULT_CAP],
            }]})

        resp = self._client.messages.create(
            model=self._model, max_tokens=self._max_tokens, system=_system(ctx),
            tools=_tool_defs(), tool_choice={"type": "auto"}, messages=self._messages,
        )
        tool_use = next((b for b in resp.content if getattr(b, "type", None) == "tool_use"), None)
        if tool_use is None:
            return {"verdict": {"verdict": "inconclusive",
                                "rationale": "agent ended without calling submit_verdict"}}
        self._pending_assistant = resp.content
        self._pending_tool_id = tool_use.id
        args = dict(tool_use.input or {})
        if tool_use.name == "submit_verdict":
            return {"verdict": args}
        return {"tool": tool_use.name, "args": args}


def _default_client(api_key: str | None):
    try:
        import anthropic
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without the optional dep
        raise RuntimeError(
            "the 'anthropic' package is required for the live agent; install appsec-verifier[agent]"
        ) from exc
    return anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
