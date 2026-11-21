"""Orchestrate a verification run over already-selected findings (VER-008,
VER-020, VER-037, VER-046, VER-051, VER-065). Pure, injectable logic: the probe registry, HTTP client, budget, and
clock are all passed in, so the whole flow is tested offline. An optional
`progress` (progress.RunProgress) shows each finding with a probe, its
steps, its proof and, once its last variant is done, a changed rating
(VER-039) on the console. Returns the
verification document as a dict shaped for schemas/verification.schema.yaml,
its results redacted of every credential value the sessions know (VER-016).

A probe that fails ends its finding inconclusive; the action log gets the
exception type and the place in this package where it passed, never its
message. An optional `failures` (failure_debug.FailureDebug) keeps each finding
whose verification failed, with its error and model calls (VER-063). Once a
run-wide limit (requests, cost, time, model calls, window) has stopped a
finding, the remaining findings are not tested and say so (VER-015, VER-024).
Ctrl-C ends the run the same way: the finding under test ends inconclusive,
the rest are not tested, and the document is still returned with
`meta.interrupted` set, so the results gathered so far reach the report.
A finding the run cannot confirm (cli._blocker) is not tested and says why,
also one that only safe mode keeps from being tested. In a terminal the test
agent can ask for a write while it tests: a yes runs that finding in intrusive
mode; each answer is kept on its result (VER-052).

With `parallel` above 1 that many worker threads test findings at the same time
(VER-065), in the same order: each takes the next entry whose finding is not
under test and whose dependencies are done, so the variants of one finding stay
in their order on one thread. The budget, the request rate and the sessions are
the run's. An entry that may send write requests is tested alone; one the
operator allows writes for while it is tested waits until the others under test
have ended. The main thread serves the workers' browser calls (parallel.py) and
takes Ctrl-C, which cancels the budget and stops the model calls in progress.
The results are numbered in test order once the run is over.
"""

from __future__ import annotations

import hashlib
import json
import threading
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
    from ..auth.model_data import model_data

    marker = (scope.get("marker_file") or {}).get("content")

    def check(text: str) -> bool:
        return bool(marker and marker in text) or model_data(text, sessions) != text

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


def _verify_one(plan: FindingPlan, registry: ProbeRegistry, ctx_factory, log=None, failures=None) -> ProbeResult:
    """Decide one finding's outcome. Non-dynamic findings, and dynamic ones with
    no registered probe, are `not-attempted` with a reason — never refuted. A
    probe that fails ends that finding inconclusive; the run and the results
    already gathered go on to the report. `failures` keeps the finding when its
    verification failed (VER-063)."""
    if plan.status != "dynamic":
        return ProbeResult(verdict="not-attempted", rationale=plan.reason)
    probe = registry.get(plan.cls)
    if probe is None:
        return ProbeResult(verdict="not-attempted", rationale=f"no probe implemented for class '{plan.cls}' yet")
    ctx = error = None
    try:
        ctx = ctx_factory(plan)
        res = probe.run(ctx)
    except LimitExceeded as exc:
        res = ProbeResult(verdict="inconclusive", rationale=exc.rationale(), limits_hit=exc.kind)
    except Exception as exc:  # noqa: BLE001 - one failed probe must not lose the run; only the type is reported
        if log is not None:     # the message can carry target data or credentials; type and place cannot
            log({"finding": plan.id, "step": None, "probe_failed": type(exc).__name__, "at": _failure_site(exc)})
        error, res = exc, ProbeResult(verdict="inconclusive", rationale=f"probe failed: {type(exc).__name__}")
    else:
        if res.verdict not in _VERDICTS:
            raise ValueError(f"probe for {plan.cls} returned invalid verdict {res.verdict!r}")
    if failures is not None:
        failures.record(plan, ctx, res, error)
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
    assume_restrictions: bool = False,
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
    ask_writes=None,
    failures=None,
    parallel: int = 1,
) -> dict:
    """`skipped` maps a finding id to why this run cannot confirm it; such a
    finding is not tested and reports that reason (not-attempted).

    `failures` (failure_debug.FailureDebug) keeps each finding whose verification failed (VER-063).

    `ask_writes` (write_prompt.WritePrompt), in an interactive run that may ask, decides write requests safe
    mode does not send (VER-052): the test agent of a finding can ask while it tests. A finding the operator
    allows writes for runs in intrusive mode.
    `parallel` is how many findings are tested at the same time (VER-065); 1 tests them one after another."""
    now = now or datetime.now(timezone.utc)
    from ..auth.model_data import model_data
    from ..planning import evidence_id

    skipped = skipped or {}
    budget = budget or RunBudget(limits)
    from ..scope import ScopeGuard
    from ..tools.browser import new_marker

    guard = ScopeGuard(scope)
    if browser is not None:
        browser.private_text = _private_text(sessions, scope)
        browser.redact = lambda value: model_data(value, sessions)

    probed = [
        p.status == "dynamic" and registry.get(p.cls) is not None and evidence_id(p) not in skipped for p in plans
    ]
    # No more threads than findings to test, so a run that tests one finding looks as it always has (VER-065).
    parallel = max(1, min(int(parallel), len({plan.id for plan, shown in zip(plans, probed, strict=True) if shown})))
    asking = getattr(budget, "lock", None) or threading.RLock()
    together = parallel > 1 and progress is not None
    if parallel > 1:
        from .parallel import MainThread, MainThreadBrowser

        main = MainThread()
        if browser is not None:
            browser = MainThreadBrowser(browser, main)
        if progress is not None:
            from ..progress import ParallelProgress

            progress = ParallelProgress(progress, parallel)
    contexts = {}
    technical_review_budgets = {}

    def ctx_factory(plan: FindingPlan) -> ProbeContext:
        related = set(plan.context.get("dependencies", []))
        key = evidence_id(plan)
        writes = ask_writes is not None and ask_writes.covered(key)    # the operator allowed them (VER-052)

        current = planned[id(plan)]

        def ask(requests, reason, identity):
            with asking:        # one question to the operator at a time (VER-065)
                allowed = ask_writes(budget, key=key, finding=f"{plan.id} · {plan.title or plan.cwe or ''}",
                                     requests=requests, reason=reason, identity=identity, asked="by the test agent")
            if allowed:
                alone(current)
            return allowed

        with lock:
            # The finding's variants in test order: the tested ones, the one under test, then those to come.
            variants = [(m, entry_results.get(m)) for m in (
                *sorted((m for m in order if entries[m][0].id == plan.id), key=order.__getitem__),
                *sorted(m for m in pending if entries[m][0].id == plan.id))]
            earlier = [r for r in tested() if r["finding_ref"]["id"] in related][-12:]

        ctx = ProbeContext(
            plan=plan,
            scope=scope,
            guard=guard,
            budget=budget,
            http=http,
            identities=identities,
            callback=scope.get("callback") or {},
            safe=safe and not writes,
            read_only=read_only and not writes,
            ask_writes=ask if ask_writes is not None and not writes else None,
            assume_restrictions=assume_restrictions is True,
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
            variant_status=[
                {"variant": p.variant_id or evidence_id(p), "active": m == current,
                 "request": [v["request"] for v in p.verification_context.get("variants", [])],
                 "hypothesis": [v.get("hypothesis", "") for v in p.verification_context.get("variants", [])],
                 "prerequisites": [v.get("prerequisites", []) for v in p.verification_context.get("variants", [])],
                 "identities_used": r.get("identities_used", []) if r else [],
                 "reason": r.get("rationale") if r else None,
                 "status": r["verdict"] if r else "active" if m == current else "pending",
                 "proof_checked": bool((r.get("proof") or {}).get("checked")) if r else False}
                for m, r in variants for p in (entries[m][0],)
            ][:32],
            prior_results=[
                {
                    "finding": r["finding_ref"]["id"],
                    "verdict": r["verdict"],
                    "tested_scope": r.get("proof"),
                    "transition": "unverified; this result does not establish the next prerequisite",
                }
                for r in earlier
            ],
        )

        contexts[evidence_id(plan)] = ctx
        return ctx

    if progress is not None:
        progress.begin([plan for plan, shown in zip(plans, probed, strict=True) if shown])
    def _variant_signature(plan):
        """Only fully described equivalent variants share a result (VER-039).

        Missing hypothesis/identity/proof context is not evidence of equivalence.
        Keep all variant fields except its label; unknown future fields narrow reuse.
        """
        variants = getattr(plan, "verification_context", {}).get("variants", [])
        if len(variants) != 1:
            return None
        variant = {k: v for k, v in variants[0].items() if k != "id"}
        required = ("request", "hypothesis", "prerequisites", "expected_observations", "negative_controls")
        if not all(variant.get(k) for k in required):
            return None
        return json.dumps(variant, sort_keys=True, separators=(",", ":"))

    entries = list(zip(plans, probed, strict=True))   # in the planned order; an entry is named by its position
    planned = {id(p): n for n, p in enumerate(plans)}
    lock = threading.Condition()            # guards the run's state below when findings are tested together
    pending = set(range(len(entries)))
    running: dict[int, str] = {}            # the entries under test and their findings
    order: dict[int, tuple] = {}            # a started entry's place in the test order
    entry_results: dict[int, dict] = {}
    groups = {}
    deferred: set[str] = set()  # VER-026: confirmed findings, whose remaining variants wait behind the others
    confirmed_ids: set[str] = set()  # Findings eligible for evidence review.
    confirmed_by: dict[str, str] = {}  # VER-026: the variant that confirmed each finding
    tested_signatures: dict[str, set] = {}  # VER-039: a request already tested is not tested again
    # stopped: the run-wide limit that stopped an earlier finding. writer: the entry that may send write requests,
    # tested alone; waiting: entries under test that wait to become it (VER-065). failed: an error that ends the run.
    state = {"stopped": None, "interrupted": False, "failed": None, "writer": None, "waiting": 0}

    def tested() -> list[dict]:
        """The results so far in test order: the planned order, a confirmed finding's further variants last."""
        with lock:
            return [entry_results[n] for n in sorted(entry_results, key=order.__getitem__)]

    def take() -> int | None:
        """The next entry to test, started: the first in test order whose finding is not under test and whose
        earlier dependencies are done. An entry that may send write requests starts only when nothing else is
        tested, and nothing starts beside it (VER-065). The caller holds the lock."""
        if state["failed"] is not None or state["writer"] is not None or state["waiting"]:
            return None
        busy = set(running.values())
        for n in sorted(pending, key=lambda n: (entries[n][0].id in deferred, n)):
            plan, shown = entries[n]
            if plan.id in busy:
                continue
            needs = set(plan.context.get("dependencies", []))
            if needs and any(m < n and entries[m][0].id in needs and entries[m][0].id not in deferred
                             for m in (*pending, *running)):
                continue
            writes = shown and (not (safe or read_only) or getattr(ask_writes, "whole_run", False))
            if writes and running:
                return None
            pending.discard(n)
            running[n] = plan.id
            order[n] = (plan.id in deferred, n)
            if writes:
                state["writer"] = n
            return n
        return None

    def alone(n: int) -> None:
        """Wait until entry `n`, which the operator allowed writes for, is the only one tested (VER-065)."""
        with lock:
            if state["writer"] == n:
                return
            state["waiting"] += 1
            lock.notify_all()
            lock.wait_for(lambda: state["writer"] is None and len(running) <= state["waiting"])
            state["waiting"] -= 1
            state["writer"] = n

    def interrupt() -> None:
        with lock:
            state["interrupted"] = True
        if parallel > 1:        # the other findings under test cannot be interrupted: end their calls and requests
            from ..agent.hosts import stop_running

            budget.cancel()
            stop_running()

    def test(n: int) -> None:
        plan, shown = entries[n]
        key = evidence_id(plan)
        started = _iso(datetime.now(timezone.utc))
        budget.begin_finding(plan.id)
        finding_exhausted = False
        try:
            budget.check_finding_cost()
        except LimitExceeded:
            finding_exhausted = True
        with lock:
            repeated = shown and _variant_signature(plan) in tested_signatures.get(plan.id, set())
            confirmed_via = confirmed_by.get(plan.id) if shown else None
            interrupted, stopped = state["interrupted"], state["stopped"]
        if key in skipped:
            res = ProbeResult(verdict="not-attempted", rationale=f"not tested: {skipped[key]}")
        elif repeated:
            res = ProbeResult(
                verdict="not-attempted",
                rationale="not tested: another variant of this finding already completed an equivalent test",
            )
            if progress is not None:
                progress.finding(plan, agent=False)
        elif confirmed_via:
            # VER-026: one confirmed variant establishes the weakness; another vector to it changes no verdict.
            res = ProbeResult(verdict="not-attempted",
                              rationale=f"not tested: the finding was already confirmed through {confirmed_via}")
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
        elif shown and finding_exhausted:
            res = ProbeResult(verdict="not-attempted", limits_hit="finding-cost",
                              rationale="not tested: the finding's cost limit was reached by an earlier variant")
            if progress is not None:
                progress.finding(plan, agent=False)
        else:
            if shown and progress is not None:
                progress.finding(plan)
            cut = False
            try:
                res = _verify_one(plan, registry, ctx_factory, log, failures)
            except KeyboardInterrupt:
                interrupt()
                cut = True
            else:
                # Ctrl-C reaches the main thread; a finding another thread was testing ended at its cancelled
                # calls and is reported like the one the main thread was testing.
                cut = parallel > 1 and state["interrupted"] and res.verdict == "inconclusive"
            if cut:
                if log is not None:
                    log({"finding": plan.id, "step": None, "interrupted": True})
                res = ProbeResult(
                    verdict="inconclusive", rationale="the run was interrupted while this finding was tested"
                )
            if shown and progress is not None and not state["interrupted"]:
                progress.agent_finished(plan, res)
            with lock:
                if res.limits_hit in _RUN_LIMITS:
                    state["stopped"] = res.limits_hit
                if res.verdict == "confirmed":
                    confirmed_ids.add(plan.id)
                    confirmed_by.setdefault(plan.id, plan.variant_id or evidence_id(plan))
                    # VER-026: the finding is confirmed, so its remaining variants are not tested: they wait until
                    # every other selected finding has been tested and are then recorded as not tested.
                    deferred.add(plan.id)
                signature = _variant_signature(plan)
                if shown and signature is not None and (res.proof or {}).get("checked") is True:
                    tested_signatures.setdefault(plan.id, set()).add(signature)
        group = review_reason = None
        with lock:
            entry_results[n] = _result_entry(0, plan, res)      # numbered once the run is over
            if ask_writes is not None and key in ask_writes.records:   # each answer, for its finding
                entry_results[n]["write_permission"] = dict(ask_writes.records[key])
            if res.verdict != "not-attempted":
                entry_results[n]["timing"] = {"started": started, "finished": _iso(datetime.now(timezone.utc))}
            ctx = contexts.get(key)
            if ctx is not None and res.verdict != "not-attempted":
                groups.setdefault(plan.id, []).append((n, plan, ctx, res))
            # A finding is reviewed and rated once, after its last variant; deferral (above) keeps a confirmed
            # finding's later variants together, so this is still a single group of all its tested variants.
            last_variant = all(entries[m][0].id != plan.id for m in pending)
            if last_variant and plan.id in groups:
                group = groups.pop(plan.id)
                # VER-042: the evidence presentation is reviewed only for a finding with a confirmed variant; an
                # unconfirmed finding records a not-reviewed state without a model call. A run interruption or
                # limit takes precedence as the reason.
                if state["interrupted"]:
                    review_reason = "interrupted"
                elif state["stopped"]:
                    review_reason = state["stopped"]
                elif plan.id not in confirmed_ids:
                    review_reason = "no confirmed variant to present"
        if group is not None:
            from .evidence_review import review_finding

            review_stop = review_finding([(c, r) for _, _, c, r in group], stop=review_reason)
            if review_stop == "interrupted":
                interrupt()
            with lock:
                if review_stop in _RUN_LIMITS:
                    state["stopped"] = review_stop
                for idx, reviewed_plan, _, reviewed_result in group:
                    timing = entry_results[idx].get("timing")
                    entry_results[idx] = _result_entry(0, reviewed_plan, reviewed_result)
                    if timing is not None:
                        entry_results[idx]["timing"] = timing
                    contexts.pop(evidence_id(reviewed_plan), None)
        if shown and progress is not None and not state["interrupted"]:
            rating = None
            if last_variant:      # the rating rests on all variants of the finding (VER-039)
                from .report import rating_after_verification

                rating = rating_after_verification(plan.rating, [r for r in tested()
                                                                 if r["finding_ref"]["id"] == plan.id])
            progress.finished(plan, res, rating=rating)

    def work() -> None:
        """Test entries until none is left: the whole run in a run that tests one finding at a time, one of
        its worker threads otherwise. Ending an entry and starting the next is one step, so a finding's next
        variant follows on the same thread and in the same place of the console."""
        done = shown_finding = None
        try:
            while True:
                with lock:
                    if done is not None:
                        running.pop(done, None)
                        if state["writer"] == done:
                            state["writer"] = None
                        done = None
                        lock.notify_all()
                    while (n := take()) is None and pending and state["failed"] is None:
                        lock.wait(1.0)
                    if n is None:
                        return
                    if together and entries[n][0].id != shown_finding:
                        progress.end_unit()
                        progress.start_unit()
                        shown_finding = entries[n][0].id
                done = n
                test(n)
        except BaseException as exc:
            with lock:
                state["failed"] = state["failed"] or exc
            raise
        finally:
            with lock:
                if done is not None:
                    running.pop(done, None)
                    if state["writer"] == done:
                        state["writer"] = None
                lock.notify_all()
            if together:
                progress.end_unit()

    if parallel > 1:
        from ..limits import worker_thread

        def worker() -> None:
            with worker_thread():
                try:
                    work()
                except BaseException:  # noqa: BLE001 - kept in state["failed"]; the main thread raises it
                    pass

        threads = [threading.Thread(target=worker, name=f"appsec-verifier-finding-{k + 1}", daemon=True)
                   for k in range(parallel)]
        for thread in threads:
            thread.start()
        while any(thread.is_alive() for thread in threads):
            try:
                main.serve(lambda: not any(thread.is_alive() for thread in threads))
            except KeyboardInterrupt:
                interrupt()
        if state["failed"] is not None:
            raise state["failed"]
    else:
        work()
    results = tested()
    for number, entry in enumerate(results, 1):
        entry["result_id"] = f"VF-{number:03d}"
    interrupted = state["interrupted"]
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
            # VER-015: raises the operator typed when the run reached its cost ceiling.
            **({"cost_limit_raises": list(budget.ceiling_raises)} if budget.ceiling_raises else {}),
        },
        "identities": [
            {"role": i.get("role"), "authenticated": (i.get("method") not in (None, "none"))} for i in identities
        ],
        "summary": tally,
        "safety": {
            "mode": "safe" if safe else "intrusive",
            "read_only": bool(read_only),
            # VER-010: where no rule is declared, the restriction a comparison implies counts.
            **({"access_restrictions_assumed": True} if assume_restrictions is True else {}),
            # VER-052: the findings the operator allowed write requests for in a safe run.
            **({"writes_allowed_for": allowed} if (allowed := sorted({
                r["finding_ref"]["id"] for r in results if (r.get("write_permission") or {}).get("allowed")
            })) else {}),
            "destructive_actions": "forbidden",
            # Nothing is cleaned up: marked records a write created stay on the target (VER-010, VER-014).
            "state_changes_cleaned": None if read_only and not allowed else False,
        },
        "contacted_target": bool(contacted),
        "interrupted": interrupted,
    }
    for row in results:
        row["tested_build"] = {k: meta["target"][k] for k in ("detected_build", "build_match")}
        row["retained"] = False
    return {"meta": meta, "results": results}
