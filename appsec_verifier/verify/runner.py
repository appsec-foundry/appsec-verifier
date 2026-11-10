"""Orchestrate a verification run over already-selected findings (VER-008,
VER-020, VER-037, VER-046). Pure, injectable logic: the probe registry, HTTP client, budget, and
clock are all passed in, so the whole flow is tested offline. An optional
`progress` (progress.RunProgress) shows each finding with a probe, its
steps, its proof and, once its last variant is done, a changed rating
(VER-039) on the console. Returns the
verification document as a dict shaped for schemas/verification.schema.yaml,
its results redacted of every credential value the sessions know (VER-016).

A probe that fails ends its finding inconclusive; the action log gets the
exception type and the place in this package where it passed, never its
message. Once a run-wide limit (requests, cost, time, model calls, window) has
stopped a finding, the remaining findings are not tested and say so (VER-015,
VER-024). Ctrl-C ends the run the same way: the finding under test ends
inconclusive, the rest are not tested, and the document is still returned with
`meta.interrupted` set, so the results gathered so far reach the report.
A finding the run cannot confirm (cli._blocker) is not tested and says why.
"""

from __future__ import annotations

import hashlib
import traceback
from datetime import datetime, timezone
from pathlib import Path

from ..limits import LimitExceeded, Limits, RunBudget
from ..loader import FindingPlan
from .probes import ProbeContext, ProbeRegistry, ProbeResult
from .report import RUN_LIMITS as _RUN_LIMITS  # once reached, they stay reached for the run

_VERDICTS = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")
_PACKAGE = Path(__file__).resolve().parents[1]


def _failure_site(exc: BaseException) -> str | None:
    """`path/in/package.py:line` of the last frame in this package the exception passed through."""
    site = None
    for frame in traceback.extract_tb(exc.__traceback__):
        try:
            site = f"{Path(frame.filename).resolve().relative_to(_PACKAGE).as_posix()}:{frame.lineno}"
        except ValueError:
            continue
    return site


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _private_text(sessions, scope):
    """Whether a text holds a credential value or the marker file's content: such a screenshot never reaches a
    model (VER-012, VER-016, VER-042)."""
    marker = (scope.get("marker_file") or {}).get("content")

    def check(text: str) -> bool:
        return bool(marker and marker in text) or (sessions is not None and sessions.redact(text) != text)

    return check


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _result_entry(idx: int, plan: FindingPlan, res: ProbeResult) -> dict:
    return {
        "result_id": f"VF-{idx:03d}",
        "finding_ref": {
            "id": plan.id,
            "match_key": plan.match_key or "",
            "instance": plan.instance,
            "title": plan.title or None,
            "cwe": plan.cwe or None,
            "variant": plan.variant_id,
            "variant_digest": plan.variant_digest,
        },
        "class": plan.cls,
        "eligibility": {"status": plan.status, "reason": plan.reason},
        "verdict": res.verdict,
        "confidence": res.confidence,
        "rationale": res.rationale,
        "proof": res.proof,
        "identities_used": res.identities_used,
        "state_changes": res.state_changes,
        "deviation": res.deviation,
        "observations": res.observations,
        "limits_hit": res.limits_hit,
        "evidence": res.evidence,
        "poc": res.poc,
        "planning": res.planning,
        "evidence_review": res.evidence_review,
        "technical_review": res.technical_review,
        "selection_reason": plan.selection_reason,
        "target_location": res.target_location
        or ({"source_file": plan.instance.rsplit(":", 1)[0], "source_line": None} if plan.instance else None),
    }


def _verify_one(plan: FindingPlan, registry: ProbeRegistry, ctx_factory, log=None) -> ProbeResult:
    """Decide one finding's outcome. Non-dynamic findings, and dynamic ones with
    no registered probe, are `not-attempted` with a reason — never refuted. A
    probe that fails ends that finding inconclusive; the run and the results
    already gathered go on to the report."""
    if plan.status != "dynamic":
        return ProbeResult(verdict="not-attempted", rationale=plan.reason)
    probe = registry.get(plan.cls)
    if probe is None:
        return ProbeResult(verdict="not-attempted", rationale=f"no probe implemented for class '{plan.cls}' yet")
    try:
        res = probe.run(ctx_factory(plan))
    except LimitExceeded as exc:
        return ProbeResult(verdict="inconclusive", rationale=f"stopped by limit: {exc}", limits_hit=exc.kind)
    except Exception as exc:  # noqa: BLE001 - one failed probe must not lose the run; only the type is reported
        if log is not None:     # the message can carry target data or credentials; type and place cannot
            log({"finding": plan.id, "step": None, "probe_failed": type(exc).__name__, "at": _failure_site(exc)})
        return ProbeResult(verdict="inconclusive", rationale=f"probe failed: {type(exc).__name__}")
    if res.verdict not in _VERDICTS:
        raise ValueError(f"probe for {plan.cls} returned invalid verdict {res.verdict!r}")
    return res


def run_verification(
    *,
    assessment_path: Path,
    scope: dict,
    scope_path: Path | None,
    plans: list[FindingPlan],
    limits: Limits,
    identities: list[dict],
    registry: ProbeRegistry,
    verifier_version: str,
    target_base: str,
    authorization: dict,
    http=None,
    sessions=None,
    source=None,
    environment: str | None = None,
    safe: bool = True,
    read_only: bool = True,
    contacted: bool = False,
    target_status: dict | None = None,
    now: datetime | None = None,
    budget: RunBudget | None = None,
    agent: dict | None = None,
    browser=None,
    listener=None,
    log=None,
    evidence_dir: Path | None = None,
    progress=None,
    skipped: dict[str, str] | None = None,
) -> dict:
    """`skipped` maps a finding id to why this run cannot confirm it; such a
    finding is not tested and reports that reason (not-attempted)."""
    now = now or datetime.now(timezone.utc)
    from ..planning import evidence_id

    skipped = skipped or {}
    budget = budget or RunBudget(limits)
    from ..scope import ScopeGuard
    from ..tools.browser import new_marker

    guard = ScopeGuard(scope)
    if browser is not None:
        browser.private_text = _private_text(sessions, scope)
        browser.redact = sessions.redact if sessions is not None else lambda value: value

    contexts = {}
    technical_review_budgets = {}

    def ctx_factory(plan: FindingPlan) -> ProbeContext:
        related = set(plan.context.get("dependencies", []))
        ctx = ProbeContext(
            plan=plan,
            scope=scope,
            guard=guard,
            budget=budget,
            http=http,
            identities=identities,
            callback=scope.get("callback") or {},
            safe=safe,
            read_only=read_only,
            sessions=sessions,
            source=source,
            target_base=target_base,
            browser=browser,
            marker=new_marker(),
            listener=listener,
            log=log,
            evidence_dir=evidence_dir,
            progress=progress,
            technical_review_budget=technical_review_budgets.setdefault(plan.id, {}),
            prior_results=[
                {
                    "finding": r["finding_ref"]["id"],
                    "verdict": r["verdict"],
                    "tested_scope": r.get("proof"),
                    "transition": "unverified; this result does not establish the next prerequisite",
                }
                for r in results
                if r["finding_ref"]["id"] in related
            ][-12:],
        )

        contexts[evidence_id(plan)] = ctx
        return ctx

    probed = [
        p.status == "dynamic" and registry.get(p.cls) is not None and evidence_id(p) not in skipped for p in plans
    ]
    if progress is not None:
        progress.begin([plan for plan, shown in zip(plans, probed, strict=True) if shown])
    results = []
    groups = {}
    last_variant = {p.id: i for i, p in enumerate(plans, start=1)}
    confirmed_ids: set[str] = set()  # VER-039: one confirmed variant retires the finding's other variants
    stopped: str | None = None  # the run-wide limit that stopped an earlier finding
    interrupted = False
    for i, (plan, shown) in enumerate(zip(plans, probed, strict=True), start=1):
        started = _iso(datetime.now(timezone.utc))
        if evidence_id(plan) in skipped:
            res = ProbeResult(verdict="not-attempted", rationale=f"not tested: {skipped[evidence_id(plan)]}")
        elif shown and plan.id in confirmed_ids:
            res = ProbeResult(
                verdict="not-attempted",
                rationale="not tested: another variant of this finding already confirmed it",
            )
            if progress is not None:
                progress.finding(plan, agent=False)
        elif shown and interrupted:
            res = ProbeResult(verdict="not-attempted", rationale="not tested: the run was interrupted")
        elif shown and stopped:
            res = ProbeResult(
                verdict="not-attempted",
                limits_hit=stopped,
                rationale=f"not tested: the run's {stopped} limit was reached by an earlier finding",
            )
            if progress is not None:
                progress.finding(plan, agent=False)  # no agent starts for it
        else:
            if shown and progress is not None:
                progress.finding(plan)
            try:
                res = _verify_one(plan, registry, ctx_factory, log)
            except KeyboardInterrupt:
                interrupted = True
                if log is not None:
                    log({"finding": plan.id, "step": None, "interrupted": True})
                res = ProbeResult(
                    verdict="inconclusive", rationale="the run was interrupted while this finding was tested"
                )
            if shown and progress is not None and not interrupted:
                progress.agent_finished(plan, res)
            if res.limits_hit in _RUN_LIMITS:
                stopped = res.limits_hit
            if res.verdict == "confirmed":
                confirmed_ids.add(plan.id)
        results.append(_result_entry(i, plan, res))
        if res.verdict != "not-attempted":
            results[-1]["timing"] = {"started": started, "finished": _iso(datetime.now(timezone.utc))}
        ctx = contexts.get(evidence_id(plan))
        if ctx is not None and res.verdict != "not-attempted":
            groups.setdefault(plan.id, []).append((i - 1, plan, ctx, res))
        if last_variant[plan.id] == i and plan.id in groups:
            from .evidence_review import review_finding

            group = groups.pop(plan.id)
            review_stop = review_finding([(c, r) for _, _, c, r in group],
                                         stop="interrupted" if interrupted else stopped)
            if review_stop == "interrupted":
                interrupted = True
            elif review_stop in _RUN_LIMITS:
                stopped = review_stop
            for idx, reviewed_plan, _, reviewed_result in group:
                timing = results[idx].get("timing")
                results[idx] = _result_entry(idx + 1, reviewed_plan, reviewed_result)
                if timing is not None:
                    results[idx]["timing"] = timing
                contexts.pop(evidence_id(reviewed_plan), None)
        if shown and progress is not None and not interrupted:
            rating = None
            if last_variant[plan.id] == i:      # the rating rests on all variants of the finding (VER-039)
                from .report import rating_after_verification

                rating = rating_after_verification(plan.rating, [r for r in results
                                                                 if r["finding_ref"]["id"] == plan.id])
            progress.finished(plan, res, rating=rating)
    if sessions is not None:
        results = sessions.redact(results)  # VER-016: model text never carries a credential into the report

    tally = {"confirmed": 0, "not_reproducible": 0, "blocked": 0, "inconclusive": 0, "not_attempted": 0}
    _key = {
        "confirmed": "confirmed",
        "not-reproducible": "not_reproducible",
        "blocked-by-control": "blocked",
        "inconclusive": "inconclusive",
        "not-attempted": "not_attempted",
    }
    for r in results:
        tally[_key[r["verdict"]]] += 1
    tally["total"] = len(results)

    window = scope.get("window") or {}
    meta = {
        "schema_version": 1,
        "generated": _iso(now),
        "verifier_version": verifier_version,
        "model": (agent or {}).get("model"),
        "profile": (agent or {}).get("profile"),
        "source_assessment": str(assessment_path),
        "source_assessment_sha256": _sha256(assessment_path),
        "target": {
            "base_url": target_base,
            "environment": environment or scope.get("environment"),
            "reachable": (target_status or {}).get("reachable"),
            "detected_build": (target_status or {}).get("detected_build"),
            "build_match": (target_status or {}).get("build_match", "unknown"),
        },
        "scope": {
            "file": str(scope_path) if scope_path else None,  # None: the target URL alone (VER-001)
            "sha256": _sha256(scope_path) if scope_path else None,
            "owner": (scope.get("owner") or {}).get("name"),
            "window_from": window.get("from"),
            "window_until": window.get("until"),
        },
        "authorization": {
            "confirmed": bool(authorization.get("confirmed")),
            "mode": authorization.get("mode", "interactive"),
            "at": authorization.get("at"),
        },
        "limits": {
            "max_requests": limits.max_requests,
            "max_attempts": limits.max_attempts,
            "max_calls": limits.max_calls,
            "max_duration_s": limits.max_duration_s,
            "rate_rps": limits.rate_rps,
            "cost_limit_usd": limits.cost_limit_usd,
        },
        "identities": [
            {"role": i.get("role"), "authenticated": (i.get("method") not in (None, "none"))} for i in identities
        ],
        "summary": tally,
        "safety": {
            "mode": "safe" if safe else "intrusive",
            "read_only": bool(read_only),
            "destructive_actions": "forbidden",
            # Nothing is cleaned up: marked records a write created stay on the target (VER-010, VER-014).
            "state_changes_cleaned": None if read_only else False,
        },
        "contacted_target": bool(contacted),
        "interrupted": interrupted,
    }
    return {"meta": meta, "results": results}
