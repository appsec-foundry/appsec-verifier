"""The agent loop that drives a probe (VER-001, VER-008, VER-015, VER-017, VER-019).

A ``Planner`` (the model, injected) is asked for the next step given the finding
and what the tools have returned so far; it either calls a tool or submits a
verdict. Every action is validated against the strict tool schemas here,
whichever planner produced it; an invalid one ends the finding inconclusive and
nothing runs. The loop executes tool calls through the confined AgentTools,
enforces a step limit, the run budget and the authorisation window (checked
before every planner call), and never lets a bad tool call escape
— errors go back to the planner as data. Every tool result is redacted of
credential values before the planner sees it (VER-016). A planner that never
submits ends inconclusive, not refuted (VER-024).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ..limits import LimitExceeded
from ..verify.probes import ProbeContext, ProbeResult
from .steps import check_action
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


def _xss_proof(ctx, history: list[dict], result: ProbeResult) -> ProbeResult:
    """VER-009: an XSS finding is confirmed only when the proof browser saw the
    marker execute; the model's word is not enough. The browser's evidence, not
    the model's, then backs the verdict."""
    if getattr(ctx.plan, "cls", None) != "xss" or result.verdict != "confirmed":
        return result
    proofs = [h["result"] for h in history if h.get("tool") == "browser_check"
              and isinstance(h.get("result"), dict) and h["result"].get("executed") is True]
    if not proofs:
        return ProbeResult(
            verdict="inconclusive", confidence=result.confidence, identities_used=result.identities_used,
            observations=result.observations,
            rationale="indicative, not executed: no browser_check saw the marker execute (VER-009). "
                      f"Agent's claim: {result.rationale or ''}".strip(),
        )
    result.evidence = [e for p in proofs for e in p.get("evidence") or []]
    return result


class AgentProbe:
    """A generic agent-driven probe. `cls` is the verification class it is
    registered for (e.g. "access-control" for IDOR). `planner_factory` returns a
    FRESH planner per run, because a planner carries per-run conversation state."""

    def __init__(self, cls: str, planner_factory: Callable[[], Planner], *, max_steps: int = 12):
        self.cls = cls
        self._planner_factory = planner_factory
        self._max_steps = max_steps

    def run(self, ctx: ProbeContext) -> ProbeResult:
        planner = self._planner_factory()
        tools = AgentTools(ctx)
        history: list[dict] = []
        for _ in range(self._max_steps):
            try:
                ctx.budget.check_time()
                ctx.guard.check_window()       # no model call once the authorisation window has closed
            except LimitExceeded as exc:
                return ProbeResult(verdict="inconclusive", rationale=f"stopped by limit: {exc}", limits_hit=exc.kind)
            action = check_action(planner.next_step(ctx, history))   # VER-019: no unchecked arguments
            if "verdict" in action:
                return _xss_proof(ctx, history, _result_from_verdict(action["verdict"]))
            name, args = action.get("tool"), action.get("args", {})
            try:
                result = tools.call(name, args)
            except ToolError as exc:
                result = {"error": str(exc)}
            except LimitExceeded as exc:
                return ProbeResult(verdict="inconclusive", rationale=f"stopped by limit: {exc}", limits_hit=exc.kind)
            if ctx.sessions is not None:
                result = ctx.sessions.redact(result)       # VER-016: no credential value reaches the planner
            history.append({"tool": name, "args": args, "result": result})
        return ProbeResult(verdict="inconclusive",
                           rationale="step budget exhausted without a verdict", limits_hit="attempts")
