"""The agent loop that drives a probe (VER-001, VER-008, VER-011, VER-013, VER-015, VER-017, VER-019, VER-024, VER-036,
VER-043, VER-046, VER-047, VER-052, VER-053, VER-055, VER-057, VER-059).

An accepted read injection plan runs its generated controls at once, trying the plan's next template candidate
when a control meets a server error; a write plan's controls run only when the agent asks with send_controls. An
accepted comparison without credentials sends its three reads at once the same way (VER-057).
Each model call's cost and token counts go on the next action-log record.

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
from .proof import check_proof, retain_login_observations
from .steps import check_action
from .tools import AgentTools, ToolError

_VERDICTS = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")
# What the action log keeps of a tool result: outcome and refusal reasons, never body or source text.
_LOGGED_RESULT = ("status", "length", "executed", "markup_break", "blocked", "error", "path", "start_line",
                  "marker_read", "callback_hit", "accepted", "elapsed_ms", "engine_error", "body_withheld",
                  "plan_step", "observation", "steps", "error_kind", "recovery")
_PROPOSAL_CAP = 500


def _control_failed(tools, result: dict) -> bool:
    """Whether a generated control's answer stops the experiment (VER-011): a transport error or a server error
    always; for the response-field form any non-2xx answer, since its proof needs comparable successful
    responses. An auth-artifact control (VER-049) expects 401 or 403 from its false controls, so only an error
    or a 5xx stops it. An engine-error sweep (VER-053) sends several metacharacters at once and any status is a
    valid observation for one of them, so only a transport error stops it; the proof decides on the engine-error
    class."""
    status = result.get("status", 0)
    experiment = getattr(tools, "_experiment", None) or {}
    if experiment.get("error_probe") or experiment.get("signed_in") or experiment.get("exposure"):
        # A comparison without credentials (VER-057) expects a refusal or a 404 for some of its requests.
        return bool(result.get("error"))
    if result.get("error") or not isinstance(status, int) or status >= 500:
        return True
    if experiment.get("auth_artifact"):
        return False
    return not 200 <= status < 300


def _request_attempts(history: list[dict]) -> int:
    """Requests that count against the per-finding attempt cap (an experiment's tagged controls are excluded)."""
    return sum(h.get("tool") in ("http_request", "browser_check") and not h.get("experiment") for h in history)


class Planner(Protocol):
    def next_step(self, ctx: ProbeContext, history: list[dict]) -> dict:
        """Return {"tool": name, "args": {...}} or {"verdict": {...}}."""
        ...


MODEL_CALL_FAILED = "Model call failed: "      # an observation the code adds; the report's reason line reads it
EXPERIMENT_NO_PROOF = "Experiment without proof: "   # likewise, an experiment whose controls gave no proof
# Observations only the code adds, which the reason line reads (verify/report.py, why_not_confirmed); a model's
# observation that starts like one is dropped, so the model cannot supply the reason (VER-024).
_CODE_OBSERVATIONS = (MODEL_CALL_FAILED, EXPERIMENT_NO_PROOF, "Runtime prerequisite ")


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
        # An observation with the code's own prefix is the code's alone (VER-024).
        observations=[o for o in v.get("observations", []) if not str(o).startswith(_CODE_OBSERVATIONS)],
        # The model's own account of evidence is not taken over: the code records it (VER-034).
    )


def untested_write(ctx, result: ProbeResult) -> ProbeResult:
    """VER-052: a finding whose test ends without a checked result after this run refused a write it would send
    with --allow-intrusive is not tested in this mode, whichever of not-attempted and inconclusive the agent
    chose, like a finding whose named requests all write: the report names the refused writes and how to allow
    them, and the console lists it under intrusive mode (limits_hit safe-mode). A result the proof check
    accepted, one a limit stopped, and one without a refused write are returned as they are."""
    refused = getattr(ctx, "refused_writes", None)
    if (result.verdict not in ("not-attempted", "inconclusive") or (result.proof or {}).get("checked") is True
            or result.limits_hit or not isinstance(refused, list) or not refused):
        return result
    writes = ", ".join(refused[:3]) + (f" and {len(refused) - 3} more" if len(refused) > 3 else "")
    # The unmet proof of an inconclusive verdict goes with it: the reason is the mode, not a missing citation.
    return replace(result, verdict="not-attempted", proof=None, limits_hit="safe-mode",
                   rationale=f"not tested: safe mode; the finding needs {writes}, which this run does not send; "
                             "run with --allow-intrusive to test it")


def take_model_calls(ctx) -> list[dict]:
    """The model calls made since the last action-log record (agent/hosts.py), cleared: what each cost and, where
    the host reports them, its token counts. Numbers only, never content (VER-017)."""
    calls = getattr(ctx, "model_calls", None)
    if not isinstance(calls, list) or not calls:
        return []
    ctx.model_calls = []
    return calls


def _log(ctx, step: int | None, **record) -> None:
    if ctx.log is not None:
        calls = take_model_calls(ctx)
        ctx.log({"finding": ctx.plan.id, "step": step, **record, **({"model": calls} if calls else {})})
    if ctx.progress is not None:
        ctx.progress.step({"step": step, **record})


def _stopped(ctx, step: int, exc: LimitExceeded, **record) -> ProbeResult:
    _log(ctx, step, **record, stopped=exc.kind, reason=str(exc))
    return ProbeResult(verdict="inconclusive", rationale=exc.rationale(), limits_hit=exc.kind)


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
        if self.cls == "session":
            retain_login_observations(ctx, getattr(ctx, "agent_history", []), result)
        # A model may correctly report inconclusive immediately after the comparison feedback. Still retain
        # the code-checked observed access separately from the missing restriction (VER-010/057).
        if self.cls == "access-control" and result.verdict == "inconclusive" and not result.proof:
            history = getattr(ctx, "agent_history", [])
            observed = next((h.get("result", {}).get("steps") for h in reversed(history)
                             if h.get("tool") == "experiment" and h.get("result", {}).get("access_observed")), None)
            if observed:
                checked = check_proof(ctx, history, replace(result, verdict="confirmed"), observed)
                if (checked.proof or {}).get("observed_access"):
                    result.proof, result.evidence = checked.proof, checked.evidence
                    result.observations = checked.observations
        # VER-024: a failed model call that ended the test is the reason the report gives, in the code's own words.
        failed = getattr(ctx, "model_call_failed", None)
        if failed and result.verdict == "inconclusive" and not result.limits_hit and result.rationale == failed:
            result.observations = [*result.observations, MODEL_CALL_FAILED + failed]
        result.technical_review = getattr(ctx, "technical_review_result", None)
        if result.technical_review and result.technical_review["status"] != "not-reviewed":
            _log(ctx, None, tool="technical_review", note="Technical QA: " + result.technical_review["status"],
                 result=result.technical_review)
        # Every preparation route the owner used outside the finding's own is a recorded deviation (VER-008).
        result.observations = [*result.observations, *(
            f"Deviation: the owner created its own test resource with {route}, a route the assessment names for "
            "this resource outside this finding (VER-043)." for route in controller.deviations)]
        # A harmless read the finding's own request needed but the assessment never named (VER-047).
        result.observations = [*result.observations, *(
            f"Prerequisite read: {route}, a request this finding's test needed but the assessment does not name "
            "(VER-047)." for route in controller.prerequisites)]
        for item in getattr(ctx, "prerequisite_checks", []):
            result.observations.append(f"Runtime prerequisite {item['condition']}: {item['status']} "
                                       f"(recorded steps {item['steps']}).")
        # VER-024: why the controls of an unconfirmed finding's experiments gave no proof, in the check's words.
        if result.verdict != "confirmed":
            reasons = [h["result"]["reason"] for h in getattr(ctx, "agent_history", [])
                       if h.get("tool") == "experiment" and isinstance(h.get("result"), dict)
                       and h["result"].get("proof") == "missing" and h["result"].get("reason")]
            result.observations.extend(EXPERIMENT_NO_PROOF + str(reason) for reason in dict.fromkeys(reasons))
        for request in ctx.derived_requests:
            origin = (f"supported by recorded step {request['evidence_step']}" if request.get("evidence_step")
                      else "resolved from the source before the test")
            result.observations.append(
                f"Derived request: {request['method']} {request['path']}, {origin}. Reason: {request['reason']}"
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
        ctx.accepted_plans = {}   # the steps of this history
        sent: list[dict] = []  # per step what went to the target and came back, never shown to the planner
        ctx.responses = {}
        ctx.created, ctx.owned = set(), set()
        # VER-008: when the assessment names no route, routes the source registers for the finding's handlers are
        # resolved in code before the first model call, and anchor the agent's derivations as derive() would.
        from .derivation import source_registrations

        registered = source_registrations(ctx)
        if registered:
            ctx.derived_requests = [*ctx.derived_requests, *registered]
            ctx.inferred_route_roots = [{"method": r["method"], "path": r["path"]} for r in registered]
        last_rejected = None
        last_cited = None
        repairs = 0
        # VER-059: after a verdict that cites steps the agent composes its presentation from the recorded steps, and
        # may correct it once before the Verifier leaves anything out. `presented` holds the result and verdict whose
        # presentation is awaited; they stand, and the answer adds only its presentation.
        presentation_requested = presentation_repaired = False
        presented = None
        qa_candidate = None

        def conclude(step: int, result, verdict, *, live: bool = True):
            """Record the verdict's evidence and end the finding (VER-034, VER-035, VER-059). Without `live`, a limit
            ended the wait for the agent, so no application page is opened."""
            from ..verify.browser_evidence import attach_explanation, capture_application, recapture
            from ..verify.presentation import present

            if self.cls == "access-control":
                from .access_policy import apply_intent_review

                result = apply_intent_review(result, qa.state)
            result = untested_write(ctx, result)
            cited = (result.proof or {}).get("steps") or verdict.get("proof_steps")
            if live and result.limits_hit is None:
                capture_application(ctx, tools, history, sent, result, verdict.get("browser_evidence"),
                                    cited)
            result = poc.attach(ctx, history, sent, result, cited, verdict.get("highlight"),
                                verdict.get("presentation"))
            attach_explanation(ctx, result, verdict.get("image_explanation"))
            # An evidence review may ask for another page for an unclear screenshot, or present the proof of
            # concept again (VER-042, VER-059).
            ctx.recapture = partial(recapture, ctx, tools, history, sent, result, cited)
            ctx.represent = partial(present, ctx, history, sent, result, cited)
            return _finish(ctx, step, result)

        def ask_presentation(step: int, tool: str, result, verdict, message: dict) -> None:
            """Send the agent the redacted record of the steps its verdict rests on with `message` (VER-059). The
            excerpts are model context, not action-log content."""
            from ..verify.presentation import repair_context

            evidence = repair_context(ctx, history, sent, result, verdict.get("proof_steps"))
            _log(ctx, step, tool=tool, result={**message, "required_steps": evidence["required_steps"]})
            history.append({"tool": tool, "args": {}, "result": {**message, **evidence}})

        def attach_stopped(stopped):
            # A follow-up cannot erase an already checked observation when its budget ends.
            cited = None
            if qa_candidate is not None:
                prior, cited = qa_candidate
                stopped = replace(prior, limits_hit=stopped.limits_hit, observations=[
                    *prior.observations, "Technical QA follow-up stopped before a revised conclusion."])
                qa.state["reason"] = "Technical objections remain; the follow-up stopped within the existing limits."
                if self.cls == "access-control":
                    from .access_policy import apply_intent_review

                    stopped = apply_intent_review(stopped, qa.state)
            from ..verify.presentation import present

            result = poc.attach(ctx, history, sent, stopped, cited)
            ctx.represent = partial(present, ctx, history, sent, result, cited)    # an evidence review may (VER-059)
            return result

        def keep(step: int, name: str) -> None:
            response = tools.take_response()
            if response is not None:
                ctx.responses[step] = response
            entries = tools.take_exchanges()
            if entries:
                sent.append({"step": step, "tool": name, "entries": entries})

        def send_experiment_controls(role, *, write=False):
            """Send the accepted plan's bounded controls as their own numbered steps, in one action and without
            a model call (VER-011). `write` sends a write plan's controls, which the agent asks for explicitly;
            otherwise a read plan's, which run on acceptance. Returns (the steps it sent, a ProbeResult to end
            the probe on a limit, or None). When experiment_requests refuses the plan nothing is sent."""
            sent_steps: list[int] = []
            try:
                requests = controller.run(lambda: tools.experiment_requests(role=role, write=write))
            except LimitExceeded as exc:
                return sent_steps, attach_stopped(_stopped(ctx, len(history) + 1, exc))
            except ToolError as exc:
                if write:   # the agent asked; tell it why nothing was sent
                    result = {"error": str(exc), "error_kind": exc.kind}
                    step_n = len(history) + 1
                    _log(ctx, step_n, tool="send_controls", result=result)
                    history.append({"tool": "send_controls", "args": {}, "result": result})
                return sent_steps, None
            labels = tools.control_labels()
            for position, request in enumerate(requests):
                step_n = len(history) + 1
                try:
                    ctx.budget.check_time()
                    ctx.guard.check_window()
                    if _request_attempts(history) >= self._max_steps:
                        raise LimitExceeded("attempts", "per-finding request attempt limit reached")
                    controller.before("http_request", request, experiment=True)
                    result = controller.run(lambda request=request: tools.http_request(**request))
                except ToolError as exc:
                    result = {"error": str(exc), "error_kind": exc.kind}
                except LimitExceeded as exc:
                    keep(step_n, "http_request")
                    return sent_steps, attach_stopped(_stopped(ctx, step_n, exc))
                keep(step_n, "http_request")
                controller.observe("http_request", request, result)
                if ctx.sessions is not None:
                    result = ctx.sessions.redact(result)
                # Which control of the series this is: the requests differ only in a value the console cuts off.
                label = {"control": labels[position]} if position < len(labels) else {}
                history.append({"tool": "http_request", "args": request, "result": result, "experiment": True,
                                **label})
                _log(ctx, step_n, tool="http_request", args=request,
                     result={k: result[k] for k in _LOGGED_RESULT if k in result}, **label)
                sent_steps.append(step_n)
                if _control_failed(tools, result):
                    break
            if write and not any(type(history[n - 1]["result"].get("status")) is int for n in sent_steps):
                tools.release_controls()
            return sent_steps, None

        def report_experiment(sent_steps):
            """Append the experiment's own feedback step and return it (VER-011, VER-043, VER-057)."""
            from .experiments import comparison_ready, injection_ready, latest_plan, plan_view

            view = plan_view(history, sent_steps)
            start, plan = latest_plan(view)
            comparison = plan.get("signed_in") or plan.get("exposure")
            feedback = (comparison_ready if comparison else injection_ready)(ctx, view, sent_steps)
            feedback["plan_step"] = start
            _log(ctx, len(history) + 1, tool="experiment", result=feedback)
            history.append({"tool": "experiment", "args": {}, "result": feedback})
            return feedback

        def run_read_experiment(role):
            """Run an accepted read plan's controls, and, if a control met a server error, the plan's next
            template candidate in turn, until the proof holds or the candidates run out (VER-011)."""
            sent_steps, stop = send_experiment_controls(role)
            if stop is not None or not sent_steps:
                return stop
            feedback = report_experiment(sent_steps)
            while feedback.get("proof") != "holds" and history[-2]["result"].get("status", 0) >= 500:
                candidate = tools.next_candidate()
                if candidate is None:
                    break
                args, result = candidate
                controller.observe("plan_test", args, result)
                ctx.accepted_plans[len(history) + 1] = result["experiment"]
                if ctx.sessions is not None:
                    result = ctx.sessions.redact(result)   # VER-016, as for the agent's own plan_test
                _log(ctx, len(history) + 1, tool="plan_test", args=args,
                     result={k: result[k] for k in _LOGGED_RESULT if k in result})
                history.append({"tool": "plan_test", "args": args, "result": result})
                sent_steps, stop = send_experiment_controls(role)
                if stop is not None:
                    return stop
                if not sent_steps:
                    break
                feedback = report_experiment(sent_steps)
            return None

        for decision in range(1, self._max_steps + 1):
            step = len(history) + 1
            ctx.controller_state = {
                "remaining_decisions": self._max_steps - decision + 1,
                "remaining_request_actions": self._max_steps - _request_attempts(history),
                "remaining_run_requests": ctx.budget.limits.max_requests - ctx.budget.requests,
            }
            try:
                ctx.budget.check_time()
                ctx.budget.check_finding_cost()  # VER-051: stop this finding, not the run, at its spend cap
                ctx.guard.check_window()  # no model call once the authorisation window has closed
                if ctx.progress is not None:
                    ctx.progress.activity(decision, self._max_steps)
                controller.before_model()
                proposal = controller.run(lambda: planner.next_step(ctx, history))
            except LimitExceeded as exc:
                if presented is not None:      # the verdict was complete; only its presentation was awaited
                    return conclude(step, *presented, live=False)
                return attach_stopped(_stopped(ctx, step, exc))
            action = check_action(proposal)  # VER-019: no unchecked arguments
            if presented is not None and "verdict" not in action:
                return conclude(step, *presented)   # VER-059: only a verdict answers a presentation feedback
            if "refused" in action:
                # VER-017: refused and logged, nothing runs; counted like a failed action (VER-036)
                controller.refuse(action["refused"], action["error"])
                args = action["args"] if isinstance(action["args"], dict) else {}   # None: not one JSON object
                call = {"tool": action["refused"], "args": args,
                        **({"note": action["note"]} if action.get("note") else {})}
                result = {"error": action["error"], "error_kind": "schema"}
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
                from ..verify.presentation import assess

                if presented is not None:
                    # VER-059: the answer to a presentation request or correction adds its presentation only; the
                    # result and verdict stand, whatever else the answer says. An answer without one, such as a host
                    # error, keeps the earlier one. Before the Verifier leaves anything out of one, the agent may
                    # correct it once, while a step is left; an answer without any is not asked for again.
                    (result, kept), presented = presented, None
                    again = verdict.get("presentation")
                    verdict = {**kept, **({"presentation": again} if again is not None else {})}
                    checked = assess(ctx, history, sent, result, verdict.get("proof_steps"),
                                     verdict.get("presentation"))
                    problems = [*([f"it would leave out {'; '.join(checked.left_out)}"] if checked.left_out else []),
                                *([checked.why] if checked.why else [])]
                    if problems and verdict.get("presentation") is not None and not presentation_repaired \
                            and decision < self._max_steps:
                        presentation_repaired, presented = True, (result, verdict)
                        ask_presentation(step, "presentation_feedback", result, verdict, {
                            "status": "presentation needs a correction", "reason": "; ".join(problems),
                            "next": "submit the same verdict again with a corrected presentation; only the "
                                    "presentation of that answer is used"})
                        continue
                    return conclude(step, result, verdict)
                result = check_proof(ctx, history, _result_from_verdict(verdict), verdict.get("proof_steps"))
                if ((result.proof or {}).get("checked") is False and not (result.proof or {}).get("observed_access")
                        and repairs < 2 and decision < self._max_steps):
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
                    # A corrected conclusion may explain an unavailable prerequisite more accurately than
                    # the earlier rejected confirmation. Retain the code's failure and classification, but
                    # replace the rejected model claim and its citations with the corrected conclusion.
                    result.proof = last_rejected.proof
                    missing = "; ".join((result.proof or {}).get("missing", ["insufficient proof"]))
                    previous = "Earlier proof attempt was not accepted: " + missing
                    label = (last_rejected.rationale or "indicative, not proven").partition(":")[0]
                    corrected = (result.rationale or "No further proof collected").rstrip(". ")
                    result.rationale = f"{label}: {corrected}. {previous}"
                    if "proof_steps" not in verdict:
                        verdict = {**verdict, "proof_steps": last_cited}
                # VER-046: intent objections invalidate access-control confirmations at the final gate.
                feedback = None
                confirmed_checked = result.verdict == "confirmed" and (result.proof or {}).get("checked") is True
                intent_only = confirmed_checked and self.cls == "access-control"
                if confirmed_checked and not intent_only and not qa.shared.get("reviews", 0):
                    qa.state["reason"] = "A confirmed verdict whose proof check passed is not reviewed (VER-046)."
                else:
                    feedback = qa.consider(history, result, tools, controller, self._max_steps - decision,
                                           intent=intent_only)
                if feedback is not None:
                    if (result.proof or {}).get("checked") is True:
                        qa_candidate = (result, verdict.get("proof_steps"))
                    _log(ctx, step, tool="qa_feedback", note="Technical QA requests a follow-up", result=feedback)
                    history.append({"tool": "qa_feedback", "args": {}, "result": feedback})
                    continue
                # VER-059: after a verdict that cites steps, while a step is left, the agent receives the redacted
                # record of the steps it rests on and composes its presentation from it; the verdict and its checked
                # proof stay as they are. Without a step left, the verdict's own presentation counts.
                cites = assess(ctx, history, sent, result, verdict.get("proof_steps"), None).why \
                    != "the verdict cites no step"
                if cites and not presentation_requested and decision < self._max_steps:
                    presentation_requested, presented = True, (result, verdict)
                    ask_presentation(step, "presentation_request", result, verdict, {
                        "status": "verdict recorded; compose its presentation",
                        "next": "submit the same verdict again with presentation, quoting only recorded_evidence; "
                                "only the presentation of that answer is used"})
                    continue
                return conclude(step, result, verdict)
            name, args = action["tool"], action["args"]
            if name == "send_controls":
                # The agent asks the Verifier to send an accepted write plan's controls, in one action and
                # without a model call per request (VER-011). A read plan's controls already ran on acceptance.
                sent_steps, stop = send_experiment_controls(args.get("role"), write=True)
                if stop is not None:
                    return _finish(ctx, len(history), stop)
                if sent_steps:
                    report_experiment(sent_steps)
                continue
            call = {"tool": name, "args": args, **({"note": action["note"]} if action.get("note") else {})}
            if ctx.progress is not None:
                ctx.progress.activity(decision, self._max_steps, name, args)
            try:
                if name in ("http_request", "browser_check") and _request_attempts(history) >= self._max_steps:
                    raise LimitExceeded("attempts", "per-finding request attempt limit reached")
                controller.before(name, args)
                tools.note = action.get("note")     # shown as the agent's reason if it asks for writes (VER-052)
                result = controller.run(lambda name=name, args=args: tools.call(name, args))
            except ToolError as exc:
                result = {"error": str(exc), "error_kind": exc.kind}
            except LimitExceeded as exc:
                keep(step, name)
                return attach_stopped(_stopped(ctx, step, exc, **call))
            keep(step, name)
            controller.observe(name, args, result)
            if name == "plan_test" and result.get("accepted"):
                ctx.accepted_plans[len(history) + 1] = result["experiment"]
            if ctx.sessions is not None:
                result = ctx.sessions.redact(result)  # VER-016: no credential value reaches the planner
            _log(ctx, step, **call, result={k: result[k] for k in _LOGGED_RESULT if k in result})
            history.append({"tool": name, "args": args, "result": result})
            if name == "revise_observation" and result.get("accepted"):
                report_experiment(result["steps"])
            # When the steps so far already meet the class proof by a signal the code sets itself (an executed
            # XSS marker, an SSRF callback hit, a path-traversal marker read), tell the agent so its next step
            # is the verdict (VER-043). The code still re-checks the cited steps before a confirmed verdict.
            if name in ("http_request", "browser_check") and isinstance(result, dict):
                from .proof import proof_ready

                ready = proof_ready(ctx, history)
                if ready:
                    result["proof_ready"] = {"steps": ready,
                                             "next": "submit_verdict confirmed and cite these steps in proof_steps"}
                # The opposite signal: the accepted privileged-function plan can no longer confirm (VER-010).
                from .experiments import reference_unavailable

                unavailable = reference_unavailable(ctx, history)
                if unavailable:
                    result["proof_unavailable"] = unavailable
            # An accepted read injection plan runs its generated controls, or the agent's own, at once and reports
            # whether the proof already holds, or that own controls support only a negative verdict, so the agent
            # submits the verdict instead of a separate step (VER-011, VER-043). A write plan sends nothing here;
            # the agent calls send_controls for generated controls. An out-of-band or other flow is the agent's own.
            if name == "plan_test" and result.get("accepted"):
                stop = run_read_experiment(args.get("role"))
                if stop is not None:
                    return _finish(ctx, len(history), stop)
        return _finish(
            ctx,
            self._max_steps,
            attach_stopped(
                ProbeResult(
                    verdict="inconclusive", rationale="step budget exhausted without a verdict", limits_hit="attempts"
                ),
            ),
        )
