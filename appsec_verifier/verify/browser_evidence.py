"""Application screenshots tied to an already checked access-control proof (VER-035).

Only one read-only observation is allowed, under the decisive GET's identity.
The model selects a UI route and an existing response value, never an executable
script or a new proof. The browser must read that resource and show the value.
"""

from __future__ import annotations

from ..agent.tools import ToolError
from ..limits import LimitExceeded, execution_deadline
from ..planning import evidence_id
from ..tools.browser import BrowserError
from .poc import decisive_steps


def capture_application(ctx, tools, history, sent, result, proposal, cited):
    if result.verdict != "confirmed" or not proposal:
        return
    if ctx.plan.cls != "access-control":
        result.observations.append("Application screenshot unavailable: this class uses its existing proof capture.")
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
        value = proposal["value"]
        if entry is None or value not in entry["response"]["content"].get("text", "") or "[redacted]" in value:
            raise ToolError("the selected visible value is not in a successful recorded GET response")
        role = entry.get("_role")
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
                observation={"step": step, "value": value, "resource_url": entry["request"]["url"]},
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
