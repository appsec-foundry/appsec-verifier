"""The evidence the code requires before a finding counts as confirmed
(VER-009 to VER-013, VER-022, VER-043, VER-053).

The model's verdict alone never confirms a finding. A confirmed verdict cites
its proof in `proof_steps`: step numbers of the loop's history, counted from 1
as the prompt and the action log number them. The code checks those steps
against what the tools actually returned. The latest test plan names the route,
variant and identities the proof must match; for a confirmation its steps may
also precede that plan, except in an injection experiment (VER-011), and an
assumption the plan still lists as missing blocks nothing (VER-043). A negative
verdict still needs attempts after its plan:

- xss (VER-009): a browser_check in which the marker executed. The browser's
  screenshot and event record become the evidence; no proof_steps are needed.
  If any request of the probe carried the marker already joined (also
  percent-encoded), the dialog could be a page echoing a parameter through
  alert(), so it does not count.
- access-control (VER-010): a declared operator-owned resource is present for
  an allowed identity and an independently authenticated denied identity.
  Without one, at medium confidence: a resource a normal account created with
  the finding's marker, which its owner reads back, a request without a role
  does not see, and another normal account sees; or a privileged function
  whose answer a normal account receives identically to a privileged account
  while a request without a role is refused (VER-041).
- injection (VER-011): a declared experiment repeats baseline and true/false
  conditions twice, holding every other input and identity fixed. A selected
  JSON value reproduces the nonempty baseline only for the true condition.
  Timing needs alternating controls and two 2–5 s separations with identical
  response bodies. Error codes, body hashes and reflections alone are no proof
  for this form. Two further declared forms exist (VER-053): a Verifier-built
  UNION whose own marker constant returns through the query channel, and a
  syntax-breaking versus balanced pair whose break alone raises a backend
  engine error (its class, not the error text, decides). All are checked in
  experiments.injection_check.
- open-redirect (VER-012): a cited http_request answered 301, 302, 303, 307 or
  308 whose `location` leads to the finding's redirect host,
  `<marker>.invalid`. The marker is random per finding, so only a target that
  took the destination from the request can name it; `.invalid` never
  resolves (RFC 6761), so nothing is contacted, and the redirect is not
  followed.
- path-traversal (VER-012): a cited http_request whose response body held the
  content of the marker file the operator placed (scope `marker_file`), seen
  in code (`marker_read`). The model never sees that content, and a request
  that carried it does not count, so an echo cannot stand in for a read.
- ssrf (VER-012): a request with the finding's marker arrived at the
  Verifier's callback listener (tools/callback.py). The listener's record is
  the evidence; no proof_steps are needed. The guard never lets the Verifier
  itself contact the listener, so only the target can have sent it.
- any other class: never confirmed, there is no check for it.

A confirmed verdict that fails its check becomes inconclusive with the reason;
the model's claim stays in the rationale. A passing check replaces the model's
evidence with the code's: for xss the browser's files, for ssrf the listener's
hits (time, method, source address), otherwise a record of the cited exchanges
(method, path, params, body, identity, status, length, body hash, for a
redirect the host it leads to, for a traversal whether the marker was read; no
response body, no headers), redacted of credential values and written
owner-only under evidence/.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ..planning import evidence_id
from ..verification_context import planned_route
from ..verify.probes import ProbeResult
from .experiments import (
    access_check,
    callback_injection_check,
    experiment_groups,
    injection_proof,
    latest_plan,
    observation,
    token,
)
from .tools import _decoded

_REDIRECTS = (301, 302, 303, 307, 308)


def redirect_host(marker) -> str | None:
    """The host an open-redirect proof must lead to, or None without a marker."""
    return "".join(marker) + ".invalid" if marker and all(marker) else None


def _holding_experiment_steps(history: list[dict]):
    """The steps of the latest experiment the Verifier ran that reported the injection proof holds (VER-011), or
    None. Those are read controls the code generated and sent itself, so the verdict can rest on them even when
    the model cited nothing or the wrong steps."""
    for h in reversed(history):
        if h.get("tool") == "experiment" and isinstance(h.get("result"), dict):
            result = h["result"]
            if result.get("proof") == "holds" and isinstance(result.get("steps"), list):
                return [n for n in result["steps"] if isinstance(n, int)]
    return None


def _xss_routes(ctx, history: list[dict]) -> list[str]:
    """The routes an XSS browser_check must sit on to count: the finding's variant routes and any request the
    code derived for it, narrowed to a declared plan path when the agent gave one (VER-043)."""
    variants = getattr(ctx.plan, "verification_context", {}).get("variants", [])
    routes = [v["request"]["path"] for v in variants if (v.get("request") or {}).get("path")]
    routes += [r["path"] for r in getattr(ctx, "derived_requests", [])]
    _, plan = latest_plan(history)
    if plan.get("path"):
        routes = [plan["path"]]
    return routes


def _xss_steps(ctx, history: list[dict]) -> list[int]:
    """The browser_check steps that executed the marker in a verified context, on one of the finding's routes,
    whose own request did not already carry the joined marker (the echo guard). The same selection the _xss
    proof check applies, so proof_ready never points at a step the check would then reject."""
    routes = _xss_routes(ctx, history)
    joined = "".join(getattr(ctx, "marker", None) or ())
    steps = []
    for n, h in enumerate(history, 1):
        result = h.get("result")
        if (h.get("tool") == "browser_check" and isinstance(result, dict)
                and result.get("executed") is True and result.get("context_verified") is True
                and (not routes or any(planned_route(rp, h.get("args", {}).get("path") or "") for rp in routes))
                and not (joined and joined in _decoded(h.get("args", {}).get("path") or ""))):
            steps.append(n)
    return steps


def proof_ready(ctx, history: list[dict]):
    """The recorded steps that already meet this finding's class proof through a signal the code sets itself —
    an executed XSS marker on the finding's route, an SSRF callback hit, an open redirect to the marker host, a
    path-traversal marker read — for the agent's next step, or None. Pure: it selects nothing the model merely
    asserts, and proof.py re-checks every cited step before a confirmed verdict stands (VER-009 to VER-013).
    Injection readiness is reported by the experiment feedback."""
    cls = getattr(ctx.plan, "cls", None)
    if cls == "xss":
        steps = _xss_steps(ctx, history)
    elif cls == "ssrf":
        steps = [n for n, h in enumerate(history, 1)
                 if h.get("tool") == "http_request" and (h.get("result") or {}).get("callback_hit") is True]
    elif cls == "open-redirect":
        host = redirect_host(getattr(ctx, "marker", None))
        steps = [n for n, h in enumerate(history, 1)
                 if h.get("tool") == "http_request" and (h.get("result") or {}).get("status") in _REDIRECTS
                 and host is not None and _location_host(ctx, (h.get("result") or {}).get("location")) == host]
    elif cls == "path-traversal" and not any(
            r["finding_id"] == ctx.plan.id for r in (getattr(ctx, "scope", None) or {}).get("archive_checks", [])):
        steps = [n for n, h in enumerate(history, 1)
                 if h.get("tool") == "http_request" and (h.get("result") or {}).get("marker_read") is True]
    else:
        return None
    return sorted(steps) or None


def check_proof(ctx, history: list[dict], result: ProbeResult, cited) -> ProbeResult:
    """`result` if it is not confirmed or its proof holds, else an inconclusive result with the reason."""
    if result.verdict not in ("confirmed", "not-reproducible", "blocked-by-control"):
        return result
    if result.verdict != "confirmed":
        return _negative(ctx, history, result, cited)
    # The plan guides the agent; an assumption it still lists as missing blocks nothing once the class's proof
    # below holds, and steps sent before the latest plan count when they meet it (VER-043).
    cls = getattr(ctx.plan, "cls", None)
    if cls == "session":
        from .session_proof import session_check

        error = session_check(ctx, history, cited)
        return _downgrade(result, error) if error else _checked(result, history, cited)

    if cls == "xss":
        executed = [
            n
            for n, h in enumerate(history, 1)
            if h.get("tool") == "browser_check" and h.get("result", {}).get("executed") is True
        ]
        return _checked(_xss(ctx, history, result), history, executed)
    if cls == "ssrf":
        hits = [
            n
            for n, h in enumerate(history, 1)
            if h.get("tool") == "http_request" and h.get("result", {}).get("callback_hit") is True
        ]
        return _checked(_ssrf(ctx, result, history), history, hits)
    if cls == "path-traversal" and any(
        r["finding_id"] == ctx.plan.id for r in (getattr(ctx, "scope", None) or {}).get("archive_checks", [])
    ):
        proof = getattr(ctx, "archive_proof", None)
        selected = [n for n in cited or [] if type(n) is int and 1 <= n <= len(history)
                    and history[n - 1].get("tool") == "archive_probe"
                    and history[n - 1].get("result") == proof]
        if not proof or not proof.get("escaped_marker") or not selected:
            return _downgrade(result, "archive traversal needs a fresh escaped-marker readback after its upload")
        result = _checked(result, history, selected, ctx)
        result.proof["archive"] = proof
        return result
    if cls == "injection" and latest_plan(history)[1].get("oob_template"):
        exchanges, problem = _cited_exchanges(ctx, history, cited, 2)
        if problem is None:
            problem = callback_injection_check(ctx, history, cited)
        if problem is not None:
            return _downgrade(result, problem)
        result.evidence = _write_record(ctx, "exchanges", exchanges)
        return _checked(result, history, cited, ctx)
    if cls == "injection":
        # The auth-artifact form for a login bypass (VER-049), otherwise the response-field or timing form
        # (VER-011). Steps chosen by code (VER-043): when the cited steps do not carry the proof but the latest
        # experiment the Verifier ran reported it holds, check and record those steps instead. XSS and SSRF
        # already work this way; the code never confirms on steps it has not re-checked here.
        effective = cited if isinstance(cited, list) else []
        if injection_proof(ctx, history, effective):
            holding = _holding_experiment_steps(history)
            if holding and injection_proof(ctx, history, holding) is None:
                effective = holding
        exchanges, problem = _cited_exchanges(ctx, history, effective, 2)
        if problem is None:
            problem = injection_proof(ctx, history, effective)
        if problem is not None:
            return _downgrade(result, problem)
        result.evidence = _write_record(ctx, "exchanges", exchanges)
        return _checked(result, history, effective, ctx)
    check, minimum = {
        "access-control": (None, 2),
        "open-redirect": (_redirect, 1),
        "path-traversal": (_traversal, 1),
    }.get(cls, (None, 0))
    if check is None and cls != "access-control":
        return _downgrade(result, f"there is no proof check for class {cls!r}")
    exchanges, problem = _cited_exchanges(ctx, history, cited, minimum)
    if problem is None:
        if cls == "access-control":
            problem = access_check(ctx, history, cited)
        else:
            problem = check(ctx, exchanges)
    if problem is not None:
        return _downgrade(result, problem)
    result.evidence = _write_record(ctx, "exchanges", exchanges)
    return _checked(result, history, cited, ctx)


def _checked(result, history, cited, ctx=None):
    if result.verdict not in ("confirmed", "not-reproducible", "blocked-by-control"):
        return result
    _, plan = latest_plan(history)
    own = plan.get("kind") == "access-control" and (plan.get("owner") or plan.get("reference"))
    result.confidence = (
        "high" if result.verdict == "confirmed" and plan.get("kind") not in ("boolean", "timing") and not own
        else "medium"
    )
    events = {k: v for k, v in (result.proof or {}).items() if k in ("executed", "callback_hit")}
    scope = "cited requests only"
    if plan.get("change"):
        scope = (f"cited requests only, on a resource {plan['owner']} created and another account wrote to; the "
                 "record with the markers stays on the target")
        events["marker"] = "".join(getattr(ctx, "marker", None) or ())
        events["second_marker"] = plan.get("second_marker")
    elif plan.get("owner"):
        scope = (f"cited requests only, on a resource {plan['owner']} created; the record with the marker stays "
                 "on the target")
        events["marker"] = "".join(getattr(ctx, "marker", None) or ())
    elif plan.get("reference"):
        scope = (f"cited requests only; the same answer as for {plan['reference']} does not show that the "
                 "function is meant for privileged accounts only; that restriction is taken from the finding")
    result.proof = {
        **events,
        "checked": True,
        "contract": 3,
        "steps": cited or [],
        "kind": plan.get("kind", "marker"),
        "tested_path": plan.get("path"),
        "variant": plan.get("variant"),
        "hypothesis": plan.get("hypothesis"),
        "observation_pointer": plan.get("pointer"),
        "scope": scope,
    }
    result.identities_used = sorted(
        {
            h.get("args", {}).get("role") or "anonymous"
            for h in history
            if h.get("tool") in ("http_request", "browser_check", "archive_probe")
        }
    )
    return result


def _negative(ctx, history, result, cited):
    answered = [
        h
        for h in history
        if h.get("tool") in ("http_request", "browser_check", "archive_probe")
        and type(h.get("result", {}).get("status")) is int
    ]
    if not answered:
        return ProbeResult(
            verdict="not-attempted",
            confidence="low",
            rationale="no answered target request supports the proposed verdict",
        )
    if (
        not isinstance(cited, list)
        or not cited
        or any(type(n) is not int or not 1 <= n <= len(history) for n in cited)
        or len(cited) != len(set(cited))
    ):
        return _downgrade(result, "cite distinct executed attempts for a negative verdict")
    selected = [history[n - 1] for n in cited]
    if ctx.plan.cls == "session":
        from .session_proof import session_check

        error = session_check(ctx, history, cited, negative=True)
        return _downgrade(result, error) if error else _checked(result, history, cited)
    if ctx.plan.cls == "xss" and result.verdict == "not-reproducible":
        marker = getattr(ctx, "marker", None) or ()
        if all(
            h.get("tool") == "browser_check"
            and h.get("result", {}).get("executed") is False
            and type(h["result"].get("status")) is int
            and 200 <= h["result"]["status"] < 300
            and marker
            and all(part in _decoded(h.get("args", {}).get("path", "")) for part in marker)
            and not h["result"].get("error")
            and not h["result"].get("blocked")
            for h in selected
        ):
            return _checked(result, history, cited)
        return _downgrade(result, "the browser did not complete an unblocked execution attempt")
    start, plan = latest_plan(history)
    if not start or len(cited) < 2 or any(n <= start for n in cited):
        return _downgrade(result, "declare a hypothesis and cite a reference plus a fresh test attempt")
    # An own-resource proof also cites the owner's write, and its plan path may hold a placeholder: access_check
    # matches those paths itself.
    own = ctx.plan.cls == "access-control" and (plan.get("owner") or plan.get("reference"))
    if any(
        h.get("tool") != "http_request"
        or (not own and not planned_route(plan.get("path") or "", h.get("args", {}).get("path") or ""))
        or type(h.get("result", {}).get("status")) is not int
        for h in selected
    ):
        return _downgrade(result, "negative proof must contain answered requests to the planned target")
    if ctx.plan.cls == "access-control":
        problem = access_check(ctx, history, cited, negative=True, blocked=result.verdict == "blocked-by-control")
        if problem:
            return _downgrade(result, problem)
    elif ctx.plan.cls == "injection":
        plan, groups, error = experiment_groups(history, cited)
        if error or plan.get("kind") not in ("boolean", "timing") or any(len(g) < 2 for g in groups.values()):
            return _downgrade(result, error or "repeat each planned input before drawing a negative conclusion")
        statuses = [h["result"]["status"] for h in selected]
        if result.verdict == "blocked-by-control":
            baseline = [r["status"] for _, r in groups["baseline"]]
            tests = [r["status"] for k, g in groups.items() if k != "baseline" for _, r in g]
            if not (
                len(set(baseline)) == 1
                and all(200 <= s < 300 for s in baseline)
                and tests
                and len(set(tests)) == 1
                and all(s in (400, 403, 406, 422) for s in tests)
            ):
                return _downgrade(result, "no repeatable target rejection contrasts with a working reference")
        elif plan["kind"] == "timing":
            times = [h["result"].get("elapsed_ms") for h in selected]
            if (
                any(type(t) is not int or t < 0 for t in times)
                or max(times) - min(times) > 500
                or len({h["result"].get("body_sha256") for h in selected}) != 1
                or any(not h["result"].get("length") for h in selected)
                or len(set(statuses)) != 1
                or not all(200 <= s < 300 for s in statuses)
            ):
                return _downgrade(result, "the timing observations do not establish a stable undelayed result")
        else:
            try:
                values = [observation(ctx, n, plan["pointer"]) for n in cited]
            except (ValueError, KeyError, TypeError, IndexError, RecursionError):
                return _downgrade(result, "the planned response observation cannot be compared")
            if (
                len({token(v) for v in values}) != 1
                or values[0] in (None, "", [], {})
                or any(str(plan[k]) in token(v) for k in ("positive", "negative") for v in values)
                or len(set(statuses)) != 1
                or not all(200 <= s < 300 for s in statuses)
            ):
                return _downgrade(result, "the observations do not establish a stable negative result")
    else:
        return _downgrade(
            result, "this class has no checked negative experiment; report the observations as inconclusive"
        )
    exchanges, error = _cited_exchanges(ctx, history, cited, 2)
    if error:
        return _downgrade(result, error)
    result.evidence = _write_record(ctx, "exchanges", exchanges)
    return _checked(result, history, cited, ctx)


def _downgrade(result: ProbeResult, reason: str, label: str = "indicative, not proven") -> ProbeResult:
    return ProbeResult(
        verdict="inconclusive",
        confidence="low",
        identities_used=result.identities_used,
        proof={"checked": False, "contract": 3, "missing": [reason]},
        observations=result.observations,
        rationale=f"{label}: {reason}. Agent's claim: {result.rationale or ''}".strip(),
    )


def _xss(ctx, history: list[dict], result: ProbeResult) -> ProbeResult:
    # No execution plan is required (VER-043). The probe is pinned to one variant (planning.expand_variants);
    # that variant's request route, and any request the code derived for this finding, decide which
    # browser_check counts, so the per-variant discipline the old plan provided is kept without the plan. If
    # the agent did declare a plan with a path, it narrows to that path (_xss_routes, shared with proof_ready).
    routes = _xss_routes(ctx, history)
    proof_steps = [
        h
        for h in history
        if h.get("tool") == "browser_check"
        and (not routes or any(planned_route(rp, h.get("args", {}).get("path") or "") for rp in routes))
        and isinstance(h.get("result"), dict)
        and h["result"].get("executed") is True
        and h["result"].get("context_verified") is True
    ]
    if not proof_steps:
        where = f" on the finding's route {routes[0]}" if routes else ""
        return _downgrade(result, "no browser_check saw the marker execute" + where, "indicative, not executed")
    joined = "".join(getattr(ctx, "marker", None) or ())
    # The echo guard applies to the proof step's own request: a browser_check whose URL already carries the
    # joined marker could be reading back what it just sent. Earlier unrelated history (plan hypotheses,
    # read_source, stored writes elsewhere) does not bear on whether this dialog was a runtime execution.
    if joined and any(joined in _decoded(h.get("args", {}).get("path") or "") for h in proof_steps):
        return _downgrade(
            result,
            "a request carried the already joined marker, so the dialog may be an echo, not executed script",
            "indicative, not executed",
        )
    result.evidence = [e for p in (h["result"] for h in proof_steps) for e in p.get("evidence") or []]
    result.proof = {"executed": True}
    return result


def _location_host(ctx, location) -> str | None:
    """The host a redirect's Location leads to, resolved against the target as a browser would."""
    if not isinstance(location, str):
        return None
    try:
        host = urlsplit(urljoin(getattr(ctx, "target_base", None) or "", location)).hostname
    except ValueError:
        return None
    return host.rstrip(".") if host else None


def _cited_exchanges(ctx, history: list[dict], cited, minimum: int) -> tuple[list[dict], str | None]:
    if not isinstance(cited, list) or len(cited) < minimum:
        steps = "two steps" if minimum == 2 else "one step"
        return [], f"a confirmed verdict must cite at least {steps} in proof_steps"
    if any(type(n) is not int for n in cited) or len(cited) != len(set(cited)):
        return [], "proof steps must be distinct integer request ids"
    exchanges = []
    for n in cited:
        if type(n) is not int or not 1 <= n <= len(history):
            return [], f"proof step {n!r} does not exist"
        step = history[n - 1]
        res, args = step.get("result") or {}, step.get("args") or {}
        if step.get("tool") != "http_request" or not isinstance(res.get("status"), int):
            return [], f"proof step {n} is not an answered http_request"
        exchange = {
            "step": n, "method": str(args.get("method") or "GET").upper(), "path": args.get("path"),
            "params": args.get("params") or {}, "json": args.get("json"), "form": args.get("form"),
            "role": args.get("role"),
            "status": res["status"], "length": res.get("length"), "body_sha256": res.get("body_sha256"),
        }
        if "location" in res:
            exchange["location_host"] = _location_host(ctx, res["location"])
        if "marker_read" in res:
            exchange["marker_read"] = res["marker_read"] is True
        if isinstance(res.get("elapsed_ms"), int) and not isinstance(res["elapsed_ms"], bool):
            exchange["elapsed_ms"] = res["elapsed_ms"]
        exchanges.append(exchange)
    return exchanges, None


def _redirect(ctx, exchanges: list[dict]) -> str | None:
    host = redirect_host(getattr(ctx, "marker", None))
    if host is None:
        return "this run has no redirect marker for the finding"
    if any(e["status"] in _REDIRECTS and e.get("location_host") == host for e in exchanges):
        return None
    return f"no cited step was answered with a redirect (301, 302, 303, 307, 308) to {host}"


def _traversal(ctx, exchanges: list[dict]) -> str | None:
    content = ((getattr(ctx, "scope", None) or {}).get("marker_file") or {}).get("content")
    if not content:
        return "the scope names no marker file to read"
    for e in exchanges:
        sent = json.dumps([e["path"], e["params"], e["json"], e.get("form")], default=str)
        if e.get("marker_read") and content not in sent:     # an echo of the content is not a read
            return None
    return "no cited step returned the content of the scope's marker file"


def _ssrf(ctx, result: ProbeResult, history=None) -> ProbeResult:
    listener, marker = getattr(ctx, "listener", None), "".join(getattr(ctx, "marker", None) or ())
    if listener is None or not marker:
        return _downgrade(result, "this run has no callback listener for the finding")
    attempts = {
        h.get("result", {}).get("callback_attempt")
        for h in history or []
        if h.get("tool") == "http_request" and h.get("result", {}).get("callback_hit") is True
    }
    hits = [hit for attempt in attempts for hit in getattr(ctx, "callback_records", {}).get(attempt, [])]
    if not hits:
        return _downgrade(result, "no callback was recorded within the observation window of a cited attempt")
    if not (getattr(ctx, "scope", {}) or {}).get("callback", {}).get("expect_rejected"):
        return _downgrade(result, "callback retrieval was observed; the operator has not declared it forbidden")
    result.evidence = _write_record(ctx, "callback_hits", hits, kind="callback")
    result.proof = {"callback_hit": True}
    result.observations.append(
        "Only the controlled callback retrieval was observed; other internal reachability is unproven."
    )
    return result


def _write_record(ctx, key: str, items: list[dict], kind: str = "exchange") -> list[dict]:
    """`items` as an owner-only evidence file; [] when the run has no evidence directory."""
    directory = getattr(ctx, "evidence_dir", None)
    if directory is None:
        return []
    record = {
        "finding_id": ctx.plan.id,
        "class": ctx.plan.cls,
        key: items,
        "captured": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if ctx.sessions is not None:
        record = ctx.sessions.redact(record)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', evidence_id(ctx.plan))}-{key.replace('_', '-')}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(record, indent=2, default=str))
    path.chmod(0o600)  # also when an earlier run left the file with wider rights
    return [
        {
            "kind": kind,
            "path": f"evidence/{path.name}",
            "redacted": True,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    ]
