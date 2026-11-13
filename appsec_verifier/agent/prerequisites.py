"""Check runtime prerequisites against recorded answers, without requests (VER-008, VER-043, VER-047)."""

from __future__ import annotations

SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["condition", "steps", "text"],
    "properties": {
        "condition": {"type": "string", "minLength": 10, "maxLength": 600},
        "steps": {"type": "array", "minItems": 1, "maxItems": 4, "uniqueItems": True,
                  "items": {"type": "integer", "minimum": 1}},
        "text": {"type": "string", "minLength": 3, "maxLength": 200},
    },
}


def check(ctx, *, condition, steps, text):
    """An observation is a literal in complete successful runtime responses, never a source-code claim."""
    from .tools import ToolError

    history = getattr(ctx, "agent_history", [])
    checks = getattr(ctx, "prerequisite_checks", [])
    if len(checks) >= 8:
        raise ToolError("the eight runtime prerequisite checks have been used", kind="capability")
    present = []
    for n in steps:
        if not 1 <= n <= len(history) or history[n - 1].get("tool") not in ("http_request", "browser_check"):
            raise ToolError("a runtime prerequisite cites answered target requests, never source reads", kind="schema")
        response = getattr(ctx, "responses", {}).get(n, {})
        result = history[n - 1].get("result", {})
        if not response.get("complete") or result.get("body_withheld") or result.get("error"):
            raise ToolError("the recorded runtime response is incomplete or withheld", kind="capability")
        status = result.get("status")
        present.append(type(status) is int and 200 <= status < 300 and text in response.get("body", ""))
    item = {"condition": condition, "steps": steps, "status": "observed" if all(present) else "not-observed",
            "observation": text, "authority": "recorded text only; no route, permission or vulnerability proof"}
    ctx.prerequisite_checks = [*checks, item]
    return item
