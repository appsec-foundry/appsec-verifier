"""The agent loop that drives a probe (VER-001, VER-008, VER-013, VER-015, VER-017, VER-019).

A ``Planner`` (the model, injected) is asked for the next step given the finding
and what the tools have returned so far; it either calls a tool or submits a
verdict. Every action is validated against the strict tool schemas here,
whichever planner produced it; an invalid one ends the finding inconclusive and
nothing runs. The loop executes tool calls through the confined AgentTools,
enforces a step limit, the run budget and the authorisation window (checked
before every planner call), and never lets a bad tool call escape
— errors go back to the planner as data. Every tool result is redacted of
credential values before the planner sees it (VER-016). A planner that never
submits ends inconclusive, not refuted (VER-024). A confirmed verdict stands
only if the code finds the proof its class requires (proof.py). Every step —
tool call and outcome, refused proposal, stopping limit, verdict — goes to
`ctx.log`, the run's action log (VER-017).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Protocol

from ..limits import LimitExceeded
from ..verify.probes import ProbeContext, ProbeResult
from .proof import check_proof
from .steps import check_action
from .tools import AgentTools, ToolError

_VERDICTS = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")
# What the action log keeps of a tool result: outcome and refusal reasons, never body or source text.
_LOGGED_RESULT = ("status", "length", "executed", "blocked", "error", "path", "start_line", "marker_read",
                  "callback_hit")
_PROPOSAL_CAP = 500


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


def _log(ctx, step: int, **record) -> None:
    if ctx.log is not None:
        ctx.log({"finding": ctx.plan.id, "step": step, **record})


def _stopped(ctx, step: int, exc: LimitExceeded, **record) -> ProbeResult:
    _log(ctx, step, **record, stopped=exc.kind, reason=str(exc))
    return ProbeResult(verdict="inconclusive", rationale=f"stopped by limit: {exc}", limits_hit=exc.kind)


def _finish(ctx, step: int, result: ProbeResult) -> ProbeResult:
    _log(ctx, step, verdict=result.verdict, rationale=result.rationale, limits_hit=result.limits_hit)
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
        for step in range(1, self._max_steps + 1):
            try:
                ctx.budget.check_time()
                ctx.guard.check_window()       # no model call once the authorisation window has closed
                proposal = planner.next_step(ctx, history)
            except LimitExceeded as exc:
                return _stopped(ctx, step, exc)
            action = check_action(proposal)   # VER-019: no unchecked arguments
            if "verdict" in action:
                if action != proposal:        # the step contract refused what the planner proposed (VER-017)
                    _log(ctx, step, refused=action["verdict"]["rationale"],
                         proposal=json.dumps(proposal, default=str)[:_PROPOSAL_CAP])
                verdict = action["verdict"]
                return _finish(ctx, step, check_proof(ctx, history, _result_from_verdict(verdict),
                                                      verdict.get("proof_steps")))
            name, args = action["tool"], action["args"]
            try:
                result = tools.call(name, args)
            except ToolError as exc:
                result = {"error": str(exc)}
            except LimitExceeded as exc:
                return _stopped(ctx, step, exc, tool=name, args=args)
            if ctx.sessions is not None:
                result = ctx.sessions.redact(result)       # VER-016: no credential value reaches the planner
            _log(ctx, step, tool=name, args=args, result={k: result[k] for k in _LOGGED_RESULT if k in result})
            history.append({"tool": name, "args": args, "result": result})
        return _finish(ctx, self._max_steps, ProbeResult(
            verdict="inconclusive", rationale="step budget exhausted without a verdict", limits_hit="attempts"))
