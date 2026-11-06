"""The agent loop that drives a probe (VER-008, VER-015, VER-017).

A ``Planner`` (the model, injected) is asked for the next step given the finding
and what the tools have returned so far; it either calls a tool or submits a
verdict. The loop executes tool calls through the confined AgentTools, enforces
a step limit and the run budget, and never lets a bad tool call escape — errors
go back to the planner as data. A planner that never submits ends inconclusive,
not refuted (VER-024).
"""

from __future__ import annotations

from typing import Protocol

from ..limits import LimitExceeded
from ..verify.probes import ProbeContext, ProbeResult
from .tools import AgentTools, ToolError

_VERDICTS = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")


class Planner(Protocol):
    def next_step(self, ctx: ProbeContext, history: list[dict]) -> dict:
        """Return {"tool": name, "args": {...}} or {"verdict": {...}}."""
        ...


def _result_from_verdict(v: dict) -> ProbeResult:
    verdict = v.get("verdict")
    if verdict not in _VERDICTS:
        return ProbeResult(verdict="inconclusive",
                           rationale=f"agent returned an invalid verdict {verdict!r}")
    return ProbeResult(
        verdict=verdict,
        confidence=v.get("confidence"),
        rationale=v.get("rationale"),
        proof=v.get("proof"),
        identities_used=v.get("identities_used", []),
        state_changes=v.get("state_changes", []),
        deviation=v.get("deviation"),
        observations=v.get("observations", []),
        evidence=v.get("evidence", []),
    )


class AgentProbe:
    """A generic agent-driven probe. `cls` is the verification class it is
    registered for (e.g. "access-control" for IDOR); the planner is seeded with
    class-specific guidance."""

    def __init__(self, cls: str, planner: Planner, *, max_steps: int = 12):
        self.cls = cls
        self._planner = planner
        self._max_steps = max_steps

    def run(self, ctx: ProbeContext) -> ProbeResult:
        tools = AgentTools(ctx)
        history: list[dict] = []
        for _ in range(self._max_steps):
            try:
                ctx.budget.check_time()
            except LimitExceeded as exc:
                return ProbeResult(verdict="inconclusive", rationale=f"stopped by limit: {exc}", limits_hit=exc.kind)
            action = self._planner.next_step(ctx, history)
            if "verdict" in action:
                return _result_from_verdict(action["verdict"])
            name, args = action.get("tool"), action.get("args", {})
            try:
                result = tools.call(name, args)
            except ToolError as exc:
                result = {"error": str(exc)}
            except LimitExceeded as exc:
                return ProbeResult(verdict="inconclusive", rationale=f"stopped by limit: {exc}", limits_hit=exc.kind)
            history.append({"tool": name, "args": args, "result": result})
        return ProbeResult(verdict="inconclusive",
                           rationale="step budget exhausted without a verdict", limits_hit="attempts")
