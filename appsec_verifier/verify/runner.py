"""Orchestrate a verification run over already-selected findings (VER-008,
VER-020). Pure, injectable logic: the probe registry, HTTP client, budget, and
clock are all passed in, so the whole flow is tested offline. Returns the
verification document as a dict shaped for schemas/verification.schema.yaml.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..limits import LimitExceeded, Limits, RunBudget
from ..loader import FindingPlan
from .probes import ProbeContext, ProbeRegistry, ProbeResult

_VERDICTS = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


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
        "target_location": res.target_location or (
            {"source_file": plan.instance.rsplit(":", 1)[0], "source_line": None} if plan.instance else None
        ),
    }


def _verify_one(plan: FindingPlan, registry: ProbeRegistry, ctx_factory) -> ProbeResult:
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
        return ProbeResult(verdict="inconclusive", rationale=f"probe failed: {type(exc).__name__}")
    if res.verdict not in _VERDICTS:
        raise ValueError(f"probe for {plan.cls} returned invalid verdict {res.verdict!r}")
    return res


def run_verification(
    *,
    assessment_path: Path,
    scope: dict,
    scope_path: Path,
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
) -> dict:
    now = now or datetime.now(timezone.utc)
    budget = budget or RunBudget(limits)
    from ..scope import ScopeGuard
    from ..tools.browser import new_marker
    guard = ScopeGuard(scope)

    def ctx_factory(plan: FindingPlan) -> ProbeContext:
        return ProbeContext(
            plan=plan, scope=scope, guard=guard, budget=budget, http=http,
            identities=identities, callback=scope.get("callback") or {},
            safe=safe, read_only=read_only, sessions=sessions, source=source,
            target_base=target_base, browser=browser, marker=new_marker(),
        )

    results = [_result_entry(i, p, _verify_one(p, registry, ctx_factory)) for i, p in enumerate(plans, start=1)]

    tally = {"confirmed": 0, "not_reproducible": 0, "blocked": 0, "inconclusive": 0, "not_attempted": 0}
    _key = {
        "confirmed": "confirmed", "not-reproducible": "not_reproducible",
        "blocked-by-control": "blocked", "inconclusive": "inconclusive", "not-attempted": "not_attempted",
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
            "file": str(scope_path),
            "sha256": _sha256(scope_path),
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
            {"role": i.get("role"), "authenticated": (i.get("method") not in (None, "none"))}
            for i in identities
        ],
        "summary": tally,
        "safety": {
            "mode": "safe" if safe else "intrusive",
            "read_only": bool(read_only),
            "destructive_actions": "forbidden",
            "state_changes_cleaned": None if read_only else True,
        },
        "contacted_target": bool(contacted),
    }
    return {"meta": meta, "results": results}
