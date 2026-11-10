"""The agent loop that drives a probe (VER-001, VER-008, VER-013, VER-015, VER-017, VER-019, VER-036, VER-046).

A ``Planner`` (the model, injected) is asked for the next step given the finding
and what the tools have returned so far; it either calls a tool or submits a
verdict. Every action is validated against the strict tool schemas here,
whichever planner produced it, and nothing invalid runs: a tool call with invalid
arguments goes back to the planner as an error and counts as a failed action, any
other invalid action ends the finding inconclusive. The loop executes tool calls through the confined AgentTools,
enforces a step limit, the run budget and the authorisation window (checked
before every planner call), and never lets a bad tool call escape
— errors go back to the planner as data. Every tool result is redacted of
credential values before the planner sees it (VER-016). A planner that never
submits ends inconclusive, not refuted (VER-024). A confirmed verdict stands
only if the code finds the proof its class requires (proof.py). Every step —
tool call with the planner's note and outcome, refused proposal, stopping limit, verdict — goes to
`ctx.log`, the run's action log (VER-017), and to `ctx.progress`, the console.
What each step sent to the target and got back is kept apart from the history
the planner sees and becomes the finding's proof of concept, whatever the
verdict and also when a limit stops it (verify/poc.py, VER-034).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from functools import partial
from typing import Protocol

from ..limits import LimitExceeded
from ..verify import poc
from ..verify.probes import ProbeContext, ProbeResult
from .controller import Controller
from .proof import check_proof
from .steps import check_action
from .tools import AgentTools, ToolError

_VERDICTS = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")
# What the action log keeps of a tool result: outcome and refusal reasons, never body or source text.
_LOGGED_RESULT = ("status", "length", "executed", "blocked", "error", "path", "start_line", "marker_read",
                  "callback_hit", "accepted", "elapsed_ms")
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
        confidence="low",
        rationale=v.get("rationale"),
        proof=None,  # only the checker may create the evidence contract
        identities_used=v.get("identities_used", []),
        state_changes=v.get("state_changes", []),
        deviation=v.get("deviation"),
        observations=v.get("observations", []),
        # The model's own account of evidence is not taken over: the code records it (VER-034).
    )


def _log(ctx, step: int | None, **record) -> None:
    if ctx.log is not None:
        ctx.log({"finding": ctx.plan.id, "step": step, **record})
    if ctx.progress is not None:
        ctx.progress.step({"step": step, **record})


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
        controller = Controller(ctx)
        result = self._run(ctx, controller)
        result.technical_review = getattr(ctx, "technical_review_result", None)
        if result.technical_review and result.technical_review["status"] != "not-reviewed":
            _log(ctx, None, tool="technical_review", note="Technical QA: " + result.technical_review["status"],
                 result=result.technical_review)
        # Every preparation route the owner used outside the finding's own is a recorded deviation (VER-008).
        result.observations = [*result.observations, *(
            f"Deviation: the owner created its own test resource with {route}, a route the assessment names for "
            "this resource outside this finding (VER-043)." for route in controller.deviations)]
        for request in ctx.derived_requests:
            result.observations.append(
                f"Derived request: {request['method']} {request['path']}, supported by recorded step "
                f"{request['evidence_step']}. Reason: {request['reason']}"
            )
        return result

    def _run(self, ctx: ProbeContext, controller: Controller) -> ProbeResult:
        from .technical_review import TechnicalReview

        planner = self._planner_factory()
        qa = TechnicalReview(ctx, self._planner_factory, planner)
        ctx.technical_review_result = qa.state
        ctx.evidence_test_planner = planner
        ctx.evidence_reviewer_factory = self._planner_factory
        tools = AgentTools(ctx)
        history: list[dict] = []
        ctx.agent_history = history
        sent: list[dict] = []  # per step what went to the target and came back, never shown to the planner
        ctx.responses = {}
        ctx.created, ctx.owned = set(), set()
        last_rejected = None
        last_cited = None
        repairs = 0
        qa_candidate = None

        def attach_stopped(stopped):
            # A follow-up cannot erase an already checked observation when its budget ends.
            cited = None
            if qa_candidate is not None:
                prior, cited = qa_candidate
                stopped = replace(prior, limits_hit=stopped.limits_hit, observations=[
                    *prior.observations, "Technical QA follow-up stopped before a revised conclusion."])
                qa.state["reason"] = "Technical objections remain; the follow-up stopped within the existing limits."
            return poc.attach(ctx, history, sent, stopped, cited)

        def keep(step: int, name: str) -> None:
            response = tools.take_response()
            if response is not None:
                ctx.responses[step] = response
            entries = tools.take_exchanges()
            if entries:
                sent.append({"step": step, "tool": name, "entries": entries})

        for decision in range(1, self._max_steps + 1):
            step = len(history) + 1
            ctx.controller_state = {
                "remaining_decisions": self._max_steps - decision + 1,
                "remaining_request_actions": self._max_steps - sum(
                    h.get("tool") in ("http_request", "browser_check") for h in history
                ),
                "remaining_run_requests": ctx.budget.limits.max_requests - ctx.budget.requests,
            }
            try:
                ctx.budget.check_time()
                ctx.guard.check_window()  # no model call once the authorisation window has closed
                if ctx.progress is not None:
                    ctx.progress.activity(decision, self._max_steps)
                controller.before_model()
                proposal = controller.run(lambda: planner.next_step(ctx, history))
            except LimitExceeded as exc:
                return attach_stopped(_stopped(ctx, step, exc))
            action = check_action(proposal)  # VER-019: no unchecked arguments
            if "refused" in action:
                # VER-017: refused and logged, nothing runs; counted like a failed action (VER-036)
                controller.refuse()
                args = action["args"] if isinstance(action["args"], dict) else {}   # None: not one JSON object
                call = {"tool": action["refused"], "args": args,
                        **({"note": action["note"]} if action.get("note") else {})}
                result = {"error": action["error"]}
                _log(ctx, step, **call, result=result)
                history.append({"tool": action["refused"], "args": args, "result": result})
                continue
            if "verdict" in action:
                if action != proposal:  # the step contract refused what the planner proposed (VER-017)
                    _log(
                        ctx,
                        step,
                        refused=action["verdict"]["rationale"],
                        proposal=json.dumps(proposal, default=str)[:_PROPOSAL_CAP],
                    )
                verdict = action["verdict"]
                result = check_proof(ctx, history, _result_from_verdict(verdict), verdict.get("proof_steps"))
                if (result.proof or {}).get("checked") is False and repairs < 2 and decision < self._max_steps:
                    repairs += 1
                    last_rejected = result
                    last_cited = verdict.get("proof_steps")
                    feedback = {
                        "status": "insufficient",
                        "missing": result.proof["missing"],
                        "remaining_steps": self._max_steps - decision,
                    }
                    _log(ctx, step, tool="proof_feedback", result=feedback)
                    history.append({"tool": "proof_feedback", "args": {}, "result": feedback})
                    continue
                if last_rejected is not None and verdict.get("verdict") == "inconclusive":
                    result = last_rejected
                    verdict = {**verdict, "proof_steps": last_cited}
                feedback = qa.consider(history, result, tools, controller, self._max_steps - decision)
                if feedback is not None:
                    if (result.proof or {}).get("checked") is True:
                        qa_candidate = (result, verdict.get("proof_steps"))
                    _log(ctx, step, tool="qa_feedback", note="Technical QA requests a follow-up", result=feedback)
                    history.append({"tool": "qa_feedback", "args": {}, "result": feedback})
                    continue
                from ..verify.browser_evidence import attach_explanation, capture_application, recapture

                if result.limits_hit is None:
                    capture_application(ctx, tools, history, sent, result, verdict.get("browser_evidence"),
                                        verdict.get("proof_steps"))
                result = poc.attach(ctx, history, sent, result, verdict.get("proof_steps"), verdict.get("highlight"))
                attach_explanation(ctx, result, verdict.get("image_explanation"))
                # An evidence review may ask for another page for an unclear screenshot (VER-042).
                ctx.recapture = partial(recapture, ctx, tools, history, sent, result, verdict.get("proof_steps"))
                return _finish(ctx, step, result)
            name, args = action["tool"], action["args"]
            if name == "run_experiment":
                try:
                    requests = controller.run(lambda args=args: tools.experiment_requests(**args))
                except LimitExceeded as exc:
                    return attach_stopped(_stopped(ctx, step, exc))
                except ToolError as exc:
                    result = {"error": str(exc)}
                    controller.observe(name, args, result)
                    history.append({"tool": name, "args": args, "result": result})
                    _log(ctx, step, tool=name, args=args, result=result)
                    continue
                for request in requests:
                    step = len(history) + 1
                    try:
                        ctx.budget.check_time()
                        ctx.guard.check_window()
                        if sum(h.get("tool") in ("http_request", "browser_check") for h in history) >= self._max_steps:
                            raise LimitExceeded("attempts", "per-finding request attempt limit reached")
                        controller.before("http_request", request)
                        result = controller.run(lambda request=request: tools.http_request(**request))
                    except ToolError as exc:
                        result = {"error": str(exc)}
                    except LimitExceeded as exc:
                        keep(step, "http_request")
                        return attach_stopped(_stopped(ctx, step, exc))
                    keep(step, "http_request")
                    controller.observe("http_request", request, result)
                    if ctx.sessions is not None:
                        result = ctx.sessions.redact(result)
                    history.append({"tool": "http_request", "args": request, "result": result})
                    _log(
                        ctx,
                        step,
                        tool="http_request",
                        args=request,
                        result={k: result[k] for k in _LOGGED_RESULT if k in result},
                    )
                    if result.get("error") or not 200 <= result.get("status", 0) < 300:
                        break
                continue
            call = {"tool": name, "args": args, **({"note": action["note"]} if action.get("note") else {})}
            if ctx.progress is not None:
                ctx.progress.activity(decision, self._max_steps, name, args)
            try:
                if name in ("http_request", "browser_check") and sum(
                        h.get("tool") in ("http_request", "browser_check") for h in history) >= self._max_steps:
                    raise LimitExceeded("attempts", "per-finding request attempt limit reached")
                controller.before(name, args)
                result = controller.run(lambda name=name, args=args: tools.call(name, args))
            except ToolError as exc:
                result = {"error": str(exc)}
            except LimitExceeded as exc:
                keep(step, name)
                return attach_stopped(_stopped(ctx, step, exc, **call))
            keep(step, name)
            controller.observe(name, args, result)
            if ctx.sessions is not None:
                result = ctx.sessions.redact(result)  # VER-016: no credential value reaches the planner
            _log(ctx, step, **call, result={k: result[k] for k in _LOGGED_RESULT if k in result})
            history.append({"tool": name, "args": args, "result": result})
        return _finish(
            ctx,
            self._max_steps,
            attach_stopped(
                ProbeResult(
                    verdict="inconclusive", rationale="step budget exhausted without a verdict", limits_hit="attempts"
                ),
            ),
        )
