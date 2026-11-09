"""Application screenshots tied to an already checked proof (VER-035).

Where a page of the application can show the exploit or its effect (access
control, injection), the test agent picks that page, the test identity, up to
three values to mark and one sentence that explains the image. Only one
read-only observation is allowed. The values must come from a decisive
successful GET response of the proof, and the browser must read that same
resource and show one of them. The agent never supplies a script or a new
proof. XSS keeps the page where its marker executed; the explanation is
attached to whichever application screenshot leads the report.
"""

from __future__ import annotations

from ..agent.tools import ToolError
from ..limits import LimitExceeded, execution_deadline
from ..planning import evidence_id
from ..tools.browser import BrowserError
from .poc import decisive_steps

PAGE_CLASSES = ("access-control", "injection")


def capture_application(ctx, tools, history, sent, result, proposal, cited):
    if result.verdict != "confirmed" or not proposal:
        return
    if ctx.plan.cls not in PAGE_CLASSES:
        if not any(e.get("presentation") == "application" for e in result.evidence or []):   # e.g. XSS has one
            result.observations.append("Application screenshot unavailable: this class uses its existing proof "
                                       "capture.")
        return
    if ctx.browser is None or ctx.plan.cls not in getattr(ctx.browser, "screenshots", ()):
        return
    try:
        step = proposal["step"]
        if step not in decisive_steps(ctx, history, result.verdict, cited):
            raise ToolError("the selected response is not a decisive proof step")
        entries = next((s["entries"] for s in sent if s["step"] == step), [])
        entry = next((e for e in entries if e["request"]["method"] == "GET"
                      and 200 <= e["response"]["status"] < 300), None)
        values = list(proposal["values"])
        text = entry["response"]["content"].get("text", "") if entry is not None else ""
        if entry is None or any(v not in text or "[redacted]" in v for v in values):
            raise ToolError("the selected visible values are not in a successful recorded GET response")
        role = proposal.get("role") or entry.get("_role")
        if role is not None and role not in {i.get("role") for i in ctx.identities or []}:
            raise ToolError("the selected identity is not one of this run's identities")
        headers = tools._session_headers(role) if role else {}
        origin = tools._bound_origin(role) if role else ctx.target_base
        url = tools._url(proposal["path"])
        ctx.guard.check_window()
        ctx.budget.check_time()
        remaining, window = ctx.budget.remaining_time(), ctx.guard.remaining_time()
        seconds = min(remaining, window) if window is not None else remaining
        kind = "window" if window is not None and window <= remaining else "time"
        with execution_deadline(seconds, kind=kind):
            observation = ctx.browser.check(
                url, identity_headers=headers, target_base=origin, marker=ctx.marker,
                finding_id=evidence_id(ctx.plan), wait_ms=1500, safe=True, role=role,
                observation={"step": step, "values": values, "resource_url": entry["request"]["url"]},
            )
        for raw in observation.pop("_exchanges", []) or []:
            tools._record(raw, role, headers, keep_body=raw.get("keep_body", True),
                          navigation=raw.get("navigation", False))
        entries = tools.take_exchanges()
        # Append the supplementary observation after proof selection; it can never establish a verdict.
        history.append({"tool": "application_observation", "args": {"path": proposal["path"], "role": role},
                        "result": {"status": observation.get("status")}})
        if entries:
            sent.append({"step": len(history), "tool": "application_observation", "entries": entries})
        result.evidence.extend(observation.get("evidence", []))
        if observation.get("error"):
            result.observations.append("Application screenshot unavailable: " + observation["error"])
        if ctx.log:
            ctx.log({"finding": ctx.plan.id, "tool": "application_observation",
                     "result": {"captured": bool(observation.get("evidence")), "proof_step": step}})
    except LimitExceeded as exc:
        result.limits_hit = result.limits_hit or exc.kind
        result.observations.append(f"Application screenshot unavailable: {exc.kind} limit reached.")
    except (ToolError, BrowserError):
        result.observations.append("Application screenshot unavailable: invalid proof reference, identity or browser.")


def recapture(ctx, tools, history, sent, result, cited, proposal) -> bool:
    """Another page for an unclear application screenshot, chosen by the test agent after an evidence review
    issue (VER-042): one more read-only observation with every check of capture_application. Only a new
    screenshot replaces the earlier live one; its requests join the finding's HAR either way."""
    from .poc import _write_har
    from .probes import ProbeResult

    if result.verdict != "confirmed" or ctx.plan.cls not in PAGE_CLASSES:
        return False
    trial = ProbeResult("confirmed")
    before = len(sent)
    capture_application(ctx, tools, history, sent, trial, proposal, cited)
    result.observations.extend(o for o in trial.observations if o not in result.observations)
    if len(sent) > before:
        for step in sent:
            step.setdefault("decisive", False)
        har = _write_har(ctx, sent)
        result.evidence[:] = [*(e for e in result.evidence if e.get("kind") != "har"), *har]
    shots = [e for e in trial.evidence if e.get("kind") == "screenshot"]
    if not shots:
        return False
    def live(e):
        return (e.get("kind") == "screenshot" and e.get("source") == "live-browser"
                and e.get("presentation") == "application")

    result.evidence[:] = [*shots, *(e for e in result.evidence if not live(e))]
    return True


def attach_explanation(ctx, result, explanation):
    """The agent's sentence on the application screenshot that leads the report, labelled as its explanation
    there (VER-035); redacted like every model text, and dropped when no such screenshot exists."""
    if result.verdict != "confirmed" or not isinstance(explanation, str) or not explanation.strip():
        return
    shot = next((e for e in result.evidence if e.get("kind") == "screenshot"
                 and e.get("presentation") == "application"), None)
    if shot is None:
        return
    text = " ".join(explanation.split())[:300]
    shot["explanation"] = ctx.sessions.redact(text) if ctx.sessions is not None else text
