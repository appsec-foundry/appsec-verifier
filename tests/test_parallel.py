"""Testing several findings at the same time (VER-065): the same results in the planned order, the run's limits
kept across the threads, write requests only by a finding tested alone, and a cancellable run. Offline."""

from __future__ import annotations

import io
import re
import threading
import time
from pathlib import Path

import pytest

from appsec_verifier.limits import LimitExceeded, Limits, RunBudget, deadline_left, execution_deadline, worker_thread
from appsec_verifier.loader import FindingPlan
from appsec_verifier.progress import RunProgress
from appsec_verifier.verify import run_verification
from appsec_verifier.verify.parallel import MainThread
from appsec_verifier.verify.probes import ProbeContext, ProbeRegistry, ProbeResult

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
         "schemes": ["https"], "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
         "owner": {"name": "tester"}, "allow_state_change": True}


def _plan(id, variant=None, **extra):
    return FindingPlan(id=id, cwe="CWE-79", severity="High", title=f"finding {id}", match_key=f"{id}.ts|CWE-79",
                       instance=f"{id}.ts:10", status="dynamic", cls="xss", reason="r", variant_id=variant, **extra)


class Probe:
    """Records which findings were under test together; `work(ctx)` is the test itself."""
    cls = "xss"

    def __init__(self, work=None, verdicts=None, pause=0.05):
        self.work, self.verdicts, self.pause = work, verdicts or {}, pause
        self.lock = threading.Lock()
        self.active: list[str] = []
        self.together: list[tuple] = []     # the findings under test, each time one started
        self.order: list[tuple] = []        # (event, finding, variant)

    def run(self, ctx: ProbeContext) -> ProbeResult:
        plan = ctx.plan
        with self.lock:
            self.active.append(plan.id)
            self.together.append(tuple(self.active))
            self.order.append(("start", plan.id, plan.variant_id))
        try:
            time.sleep(self.pause)
            if self.work is not None:
                self.work(ctx)
        finally:
            with self.lock:
                self.active.remove(plan.id)
                self.order.append(("end", plan.id, plan.variant_id))
        verdict = self.verdicts.get((plan.id, plan.variant_id), self.verdicts.get(plan.id, "inconclusive"))
        return ProbeResult(verdict=verdict, rationale="tested", proof={"checked": False})


def _run(plans, probe, parallel, **kwargs):
    registry = ProbeRegistry()
    registry.register(probe)
    kwargs.setdefault("limits", Limits())
    return run_verification(
        assessment_path=Path("security-assessment.yaml"), scope=SCOPE, scope_path=Path("scope.yaml"),
        plans=plans, identities=[{"role": "a", "method": "form"}], registry=registry, verifier_version="test",
        target_base="https://app.example.com", authorization={"confirmed": False, "mode": "interactive", "at": None},
        contacted=False, parallel=parallel, **kwargs)


def _summary(doc):
    return [(r["result_id"], r["finding_ref"]["id"], r["finding_ref"]["variant"], r["verdict"])
            for r in doc["results"]]


def test_findings_are_tested_together_and_reported_in_the_planned_order():
    plans = [_plan(f"T-{n}") for n in range(1, 7)]
    verdicts = {"T-2": "confirmed", "T-5": "not-reproducible"}
    together = Probe(verdicts=verdicts)
    doc = _run(plans, together, 3)
    alone = Probe(verdicts=verdicts, pause=0)
    assert _summary(doc) == _summary(_run(plans, alone, 1))
    assert [r["result_id"] for r in doc["results"]] == [f"VF-{n:03d}" for n in range(1, 7)]
    assert max(map(len, together.together)) == 3        # never more than asked for
    assert max(map(len, alone.together)) == 1


def test_the_variants_of_one_finding_keep_their_order_and_never_run_together():
    plans = [_plan("T-1", "variant-001"), _plan("T-1", "variant-002"), _plan("T-1", "variant-003"),
             _plan("T-2"), _plan("T-3")]
    probe = Probe()
    doc = _run(plans, probe, 4)
    assert all(len(set(active)) == len(active) for active in probe.together)
    t1 = [(event, variant) for event, finding, variant in probe.order if finding == "T-1"]
    assert t1 == [(e, v) for v in ("variant-001", "variant-002", "variant-003") for e in ("start", "end")]
    assert [(r["finding_ref"]["id"], r["finding_ref"]["variant"]) for r in doc["results"]][:3] == [
        ("T-1", "variant-001"), ("T-1", "variant-002"), ("T-1", "variant-003")]


def test_a_confirmed_findings_further_variants_come_after_the_other_findings():
    """VER-026 holds as in a run that tests one finding at a time."""
    plans = [_plan("T-1", "variant-001"), _plan("T-1", "variant-002"), _plan("T-2"), _plan("T-3")]
    verdicts = {("T-1", "variant-001"): "confirmed"}
    doc = _run(plans, Probe(verdicts=verdicts), 2)
    assert _summary(doc) == _summary(_run(plans, Probe(verdicts=verdicts, pause=0), 1))
    assert [r["finding_ref"]["id"] for r in doc["results"]] == ["T-1", "T-2", "T-3", "T-1"]


def test_a_finding_is_tested_after_the_finding_it_depends_on():
    seen = {}

    def work(ctx):
        seen[ctx.plan.id] = [r["finding"] for r in ctx.prior_results]

    plans = [_plan("T-1"), _plan("T-2", context={"dependencies": ["T-1"]}), _plan("T-3")]
    probe = Probe(work=work)
    _run(plans, probe, 3)
    assert seen["T-2"] == ["T-1"]
    assert probe.order.index(("end", "T-1", None)) < probe.order.index(("start", "T-2", None))


def test_the_request_limit_holds_across_the_findings_tested_together():
    budget = RunBudget(Limits(max_requests=15, rate_rps=0))

    def work(ctx):
        for _ in range(10):
            ctx.budget.note_request()

    plans = [_plan(f"T-{n}") for n in range(1, 7)]
    doc = _run(plans, Probe(work=work, pause=0.01), 4, budget=budget, limits=budget.limits)
    assert budget.requests == 15
    stopped = [r for r in doc["results"] if r["limits_hit"] == "requests"]
    assert stopped and all(r["verdict"] in ("inconclusive", "not-attempted") for r in stopped)
    # Once the run's limit is reached, the findings not yet started are not tested and say so (VER-015).
    assert any(r["verdict"] == "not-attempted" for r in stopped)


def test_an_intrusive_run_tests_one_finding_at_a_time():
    probe = Probe()
    _run([_plan(f"T-{n}") for n in range(1, 5)], probe, 4, safe=False, read_only=False)
    assert max(map(len, probe.together)) == 1


class _Yes:
    """An operator who allows the writes of the finding that asks (write_prompt.WritePrompt's interface)."""

    def __init__(self):
        self.records, self.asked_together = {}, 0
        self._lock = threading.Lock()
        self._asking = 0

    def covered(self, key):
        return False

    def __call__(self, budget, *, key, **_):
        with self._lock:
            self._asking += 1
            self.asked_together = max(self.asked_together, self._asking)
        time.sleep(0.02)
        with self._lock:
            self._asking -= 1
        self.records[key] = {"allowed": True}
        return True


def test_a_finding_the_operator_allows_writes_for_is_tested_alone_from_then_on():
    writing: list[tuple] = []
    probe = Probe()

    def work(ctx):
        if ctx.plan.id in ("T-1", "T-2"):
            assert ctx.ask_writes(["POST /x"], "needs a write", "a") is True
            with probe.lock:
                writing.append(tuple(probe.active))     # who is under test while this one may write
            time.sleep(0.05)
            with probe.lock:
                writing.append(tuple(probe.active))
        else:
            time.sleep(0.05)

    probe.work = work
    ask = _Yes()
    doc = _run([_plan(f"T-{n}") for n in range(1, 7)], probe, 3, ask_writes=ask)
    # The other finding that asked waits its turn; no finding that only reads is under test beside a writer.
    assert writing and all(set(active) <= {"T-1", "T-2"} for active in writing)
    assert ask.asked_together == 1          # one question at a time
    assert len(doc["results"]) == 6 and max(map(len, probe.together)) == 3


def test_ctrl_c_ends_the_findings_under_test_and_leaves_the_rest_untested():
    class Browser:
        screenshots = ()

        def check(self, url, **kwargs):
            raise KeyboardInterrupt

    budget = RunBudget(Limits(rate_rps=0))

    def work(ctx):
        if ctx.plan.id == "T-1":
            ctx.browser.check("https://app.example.com/")
        for _ in range(200):                # the others stop at their next request
            time.sleep(0.01)
            ctx.budget.note_request()

    plans = [_plan(f"T-{n}") for n in range(1, 7)]
    doc = _run(plans, Probe(work=work, pause=0.01), 2, budget=budget, limits=budget.limits, browser=Browser())
    assert doc["meta"]["interrupted"] is True and budget.cancelled
    verdicts = {r["finding_ref"]["id"]: (r["verdict"], r["rationale"]) for r in doc["results"]}
    assert verdicts["T-1"] == ("inconclusive", "the run was interrupted while this finding was tested")
    assert verdicts["T-2"] == ("inconclusive", "the run was interrupted while this finding was tested")
    assert all(verdicts[f"T-{n}"] == ("not-attempted", "not tested: the run was interrupted") for n in range(3, 7))
    with pytest.raises(LimitExceeded):
        budget.note_request()               # nothing is sent after the run was cancelled
    with pytest.raises(LimitExceeded):
        budget.note_call()


def test_the_proof_browser_is_used_on_the_main_thread_only():
    threads = []

    class Browser:
        screenshots = ("xss",)

        def check(self, url, **kwargs):
            threads.append(threading.current_thread())
            return {"executed": False}

    seen = []

    def work(ctx):
        seen.append((threading.current_thread(), ctx.browser.check("https://app.example.com/"),
                     ctx.browser.screenshots))

    _run([_plan(f"T-{n}") for n in range(1, 4)], Probe(work=work), 3, browser=Browser())
    assert len(threads) == 3 and all(thread is threading.main_thread() for thread in threads)
    assert all(thread is not threading.main_thread() and result == {"executed": False} and shots == ("xss",)
               for thread, result, shots in seen)


def test_a_main_thread_call_is_bound_by_the_workers_deadline():
    main, outcome = MainThread(), []

    def worker():
        with worker_thread():
            try:
                with execution_deadline(0.05):
                    main.call(lambda: time.sleep(5))
            except LimitExceeded as exc:
                outcome.append(exc.kind)

    thread = threading.Thread(target=worker)
    thread.start()
    began = time.monotonic()
    main.serve(lambda: not thread.is_alive())
    assert outcome == ["time"] and time.monotonic() - began < 2


def test_an_error_in_a_probe_ends_the_run_as_in_a_run_that_tests_one_finding_at_a_time():
    class Broken:
        cls = "xss"

        def run(self, ctx):
            return ProbeResult(verdict="surely")

    with pytest.raises(ValueError, match="invalid verdict"):
        _run([_plan(f"T-{n}") for n in range(1, 5)], Broken(), 3)


def test_a_deadline_off_the_main_thread_needs_a_marked_worker():
    outcome = {}

    def unmarked():
        try:
            with execution_deadline(5):
                outcome["unmarked"] = "ran"
        except LimitExceeded as exc:
            outcome["unmarked"] = str(exc)

    def marked():
        with worker_thread():
            with execution_deadline(5):
                with execution_deadline(60):            # an inner deadline never extends the outer one
                    outcome["left"] = deadline_left()
            try:
                with execution_deadline(0.01):
                    time.sleep(0.05)                     # the work's own timeout ended it late
            except LimitExceeded as exc:
                outcome["late"] = exc.kind
            try:
                with execution_deadline(0):
                    outcome["zero"] = "ran"
            except LimitExceeded:
                outcome["zero"] = "refused"
        try:
            with execution_deadline(5):                  # the mark ends with the worker's work
                outcome["after"] = "ran"
        except LimitExceeded:
            outcome["after"] = "refused"

    for target in (unmarked, marked):
        thread = threading.Thread(target=target)
        thread.start()
        thread.join()
    assert outcome["unmarked"] == "execution deadlines require a POSIX main thread"
    assert 0 < outcome["left"] <= 5 and outcome["late"] == "time"
    assert outcome["zero"] == "refused" and outcome["after"] == "refused"
    assert deadline_left() is None


def test_each_thread_charges_its_own_finding_and_the_cap_stops_only_that_finding():
    budget = RunBudget(Limits(cost_limit_usd=4.0, finding_cost_fraction=0.25, min_finding_cost_usd=0.5))
    stopped = {}

    def spend(finding, usd):
        budget.begin_finding(finding)
        budget.note_cost(usd)
        try:
            budget.note_call()
            stopped[finding] = False
        except LimitExceeded as exc:
            stopped[finding] = exc.kind

    threads = [threading.Thread(target=spend, args=args) for args in (("T-1", 1.2), ("T-2", 0.3))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert stopped == {"T-1": "finding-cost", "T-2": False}
    assert budget.cost == pytest.approx(1.5) and budget.calls == 1


def test_the_request_rate_is_the_runs_not_each_findings():
    budget = RunBudget(Limits(rate_rps=50))
    sent = []

    def send():
        for _ in range(5):
            budget.pace()
            sent.append(time.monotonic())

    threads = [threading.Thread(target=send) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    sent.sort()
    assert len(sent) == 20 and sent[-1] - sent[0] >= 19 / 50 * 0.9


def test_the_cost_ceiling_question_is_asked_once_for_findings_that_reach_it_together():
    budget = RunBudget(Limits(cost_limit_usd=1.0))
    asked = []

    def ask(b):
        asked.append(b.cost)
        time.sleep(0.02)
        return None

    budget.ask_ceiling = ask
    ended = []

    def spend():
        try:
            budget.note_cost(0.6)
            ended.append("spent")
        except LimitExceeded as exc:
            ended.append(exc.kind)

    threads = [threading.Thread(target=spend) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(ended) == ["cost", "spent"] and len(asked) == 1


def _console(plans, probe, parallel):
    stream = io.StringIO()
    progress = RunProgress(stream, live=False, env={})
    try:
        _run(plans, probe, parallel, progress=progress)
    finally:
        progress.close()
    return [line for line in stream.getvalue().splitlines() if line.strip()]


def test_the_console_shows_each_finding_as_a_block_in_the_planned_order():
    plans = [_plan(f"T-{n}") for n in range(1, 5)]

    def work(ctx):
        time.sleep({"T-1": 0.2, "T-2": 0.0, "T-3": 0.1, "T-4": 0.0}[ctx.plan.id])    # T-2 and T-4 finish first

    lines = _console(plans, Probe(work=work, pause=0), 4)
    events = [(line.split()[2], line.split()[3]) for line in lines if " T-" in line and "/4 T-" in line]
    blocks = [finding for finding, event in events if event == "start"]
    assert blocks == ["T-1", "T-2", "T-3", "T-4"]
    # Every entry of a finding stands between its start and the next finding's start.
    assert [finding for finding, _ in events] == sorted((finding for finding, _ in events))
    assert sum(event == "done" for _, event in events) == 4
    # The grid reads as in a run that tests one finding at a time.
    alone = _console(plans, Probe(pause=0), 1)
    assert [line.split()[2:4] for line in alone if "/4 T-" in line] == [list(event) for event in events]


def test_the_status_line_names_each_finding_under_test(monkeypatch):
    from appsec_verifier.progress import ParallelProgress

    monkeypatch.setenv("COLUMNS", "140")
    stream = io.StringIO()
    inner = RunProgress(stream, live=True, env={"TERM": "xterm"}, model="claude-sonnet-4-5")
    inner.TICK_SECONDS = 3600           # the test draws the status itself
    progress = ParallelProgress(inner)
    plans = [_plan("T-1"), _plan("T-2")]
    progress.begin(plans)
    try:
        ready = threading.Barrier(3)

        def test(plan):
            progress.start_unit()
            progress.finding(plan)
            progress.activity(3, 12)
            ready.wait(5)
            ready.wait(5)
            progress.end_unit()

        threads = [threading.Thread(target=test, args=(plan,)) for plan in plans]
        for thread in threads:
            thread.start()
        ready.wait(5)
        stream.seek(0)
        stream.truncate()
        inner.tick()
        status = stream.getvalue()
        ready.wait(5)
        for thread in threads:
            thread.join()
    finally:
        inner.close()
    rows = status.split("\n")
    assert len(rows) == 3       # a row for each finding under test, then the status line
    assert "T-1 finding T-1" in rows[0] and "step 3/12 · Sonnet 4.5 plans" in rows[0]
    assert "T-2 finding T-2" in rows[1]
    # The status line counts them and names no single finding.
    assert "2 running · 0 of 2 done" in rows[2] and "T-1" not in rows[2]
    # As in AppSec Analyzer each finding's row starts in the DETAIL column, where the status line's bar starts.
    plain = [re.sub(r"\033\[[0-9;?]*[A-Za-z]|\r", "", row) for row in rows]
    assert [len(row) - len(row.lstrip()) for row in plain[:2]] == [plain[2].index("─")] * 2


def test_verify_parallel_runs_the_agent_loop_and_its_requests_in_worker_threads(tmp_path, monkeypatch, capsys):
    """The whole path of `verify --parallel`: the agent loop, its bounded actions and the guarded requests work
    off the main thread, under the run's request limit."""
    from types import SimpleNamespace

    import yaml

    from appsec_verifier import cli
    from appsec_verifier.tools import httpx_transport

    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    threats = [{"id": f"T-{n}", "cwe": "CWE-89", "severity": "high", "title": f"sqli {n}",
                "scenario": f"GET /rest/search{n}?q=' breaks the query.",
                "evidence": {"file": f"routes/search{n}.ts", "line": 3}} for n in range(1, 6)]
    asked, sent, lock = [], [], threading.Lock()

    class Planner:
        def next_step(self, ctx, history):
            with lock:
                asked.append((ctx.plan.id, threading.current_thread() is threading.main_thread()))
            if not history:
                return {"tool": "http_request", "args": {"path": f"/rest/search{ctx.plan.id[2:]}?q=1"}}
            return {"verdict": {"verdict": "not-reproducible", "rationale": "checked"}}

    def transport(method, url, headers, **kw):
        time.sleep(0.02)
        with lock:
            sent.append((url, threading.current_thread() is threading.main_thread()))
        return SimpleNamespace(status_code=200, headers={}, text="ok", content=b"ok", url=url)

    for name, doc in (("a.yaml", {"threats": threats}), ("s.yaml", scope)):
        (tmp_path / name).write_text(yaml.safe_dump(doc))
    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: transport)
    cli.main(["verify", "--assessment", str(tmp_path / "a.yaml"), "--scope", str(tmp_path / "s.yaml"),
              "--output", str(tmp_path / "out"), "--yes", "--rate", "0", "--screenshots", "none",
              "--parallel", "3", "--max-requests", "4"])
    out = capsys.readouterr()
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert "3 findings at the same time" in out.out
    assert [r["finding_ref"]["id"] for r in report["results"]] == [f"T-{n}" for n in range(1, 6)]
    assert asked and not any(main for _, main in asked)
    assert any(not main for url, main in sent if "/rest/search" in url)
    # The run's request limit holds across the findings: no fifth request leaves, and the run says so.
    assert len(sent) <= 4
    assert any(r["limits_hit"] == "requests" for r in report["results"])


@pytest.mark.parametrize(("profile", "options", "findings", "shown"), [
    ("anthropic-api", [], 5, "4 findings at the same time"),
    ("codex-cli", [], 5, "2 findings at the same time"),
    ("copilot-cli", [], 5, "2 findings at the same time"),
    ("anthropic-api", ["--parallel", "3"], 5, "3 findings at the same time"),
    ("codex-cli", ["--parallel", "4"], 5, "4 findings at the same time"),
    ("anthropic-api", [], 3, "3 findings at the same time"),
    ("anthropic-api", [], 1, None),
    ("anthropic-api", ["--parallel", "1"], 5, None),
    ("anthropic-api", ["--allow-intrusive"], 5, "one finding at a time: this run may send write requests"),
])
def test_without_parallel_a_run_tests_as_many_findings_at_once_as_appsec_analyzer(tmp_path, monkeypatch, capsys,
                                                                                  profile, options, findings, shown):
    """Four, two on the codex-cli and copilot-cli subscriptions, never more than there are findings to test; a
    value the operator sets applies as given, and an intrusive run still tests one finding at a time."""
    import yaml

    from appsec_verifier import cli

    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    threats = [{"id": f"T-{n}", "cwe": "CWE-89", "severity": "high", "title": f"sqli {n}",
                "scenario": f"GET /rest/search{n}?q=' breaks the query.",
                "evidence": {"file": f"routes/search{n}.ts", "line": 3}} for n in range(1, findings + 1)]
    for name, doc in (("a.yaml", {"threats": threats}), ("s.yaml", scope)):
        (tmp_path / name).write_text(yaml.safe_dump(doc))
    info = {"profile": profile, "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (object, info))
    cli.main(["verify", "--assessment", str(tmp_path / "a.yaml"), "--scope", str(tmp_path / "s.yaml"),
              "--output", str(tmp_path / "out"), "--dry-run", "--yes", "--screenshots", "none", *options])
    rows = [line.split(":", 1)[1].strip() for line in capsys.readouterr().out.splitlines()
            if line.strip().startswith("Parallel ")]
    assert rows == ([shown] if shown else [])
