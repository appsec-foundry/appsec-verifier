"""The run's progress on the console in the look of AppSec Analyzer: one grid line per finding bound,
step, refused step and stopping limit; a live status line only on a terminal and a heartbeat off it;
no escape sequence from the assessment or the model and no credential value on the console
(VER-005, VER-016, VER-017)."""

from __future__ import annotations

import io
import re
import sys
from types import SimpleNamespace

import pytest
import yaml

from appsec_verifier import cli
from appsec_verifier.agent import AgentProbe
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.progress import RunProgress, _StatusGuard, duration
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.verify.probes import ProbeContext, ProbeRegistry, ProbeResult
from appsec_verifier.verify.runner import run_verification

HOSTILE = "\x1b]0;pwned\x07\x1b[2J"
SGR = re.compile(r"\x1b\[[0-9;]*m")


class Tty(io.StringIO):
    def isatty(self):
        return True


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def slow_ticker(monkeypatch):
    """The tests call `tick` themselves; the background ticker must not draw in between."""
    monkeypatch.setattr(RunProgress, "TICK_SECONDS", 3600)
    monkeypatch.setattr(RunProgress, "HEARTBEAT_SECONDS", 120)


def _plan(id="T-1", cls="access-control", title="Basket of another user readable", status="dynamic"):
    return FindingPlan(id=id, cwe="CWE-639", severity="high", title=title, match_key="a.ts|CWE-639",
                       instance="a.ts:1", status=status, cls=cls, reason="r")


def _rows(stream) -> list[str]:
    return stream.getvalue().splitlines()


def test_durations_read_like_the_analyzer():
    assert [duration(s) for s in (0, 45, 185, 3725)] == ["0s", "45s", "3m05s", "1h02m"]


def test_off_a_terminal_each_event_is_one_plain_grid_line():
    out, clock = io.StringIO(), Clock()
    progress = RunProgress(out, model="claude-sonnet-5-5", remaining_time=lambda: 1740, clock=clock, env={})
    progress.begin([_plan(), _plan("T-2")])
    progress.finding(_plan())
    clock.now += 20
    progress.step({"step": 1, "tool": "http_request", "args": {"method": "GET", "path": "/rest/basket/2",
                                                                "role": "alice"},
                   "result": {"status": 200, "length": 512}})
    clock.now += 40
    progress.step({"step": 2, "verdict": "confirmed"})
    progress.finished(_plan(), ProbeResult(verdict="confirmed", confidence="high", rationale="a read b"))
    progress.close()
    header, start, step, done = _rows(out)[1:]
    assert header.split() == ["TIME", "FINDING", "EVENT", "PROGRESS", "ELAPSED", "LEFT", "DETAIL"]
    assert start.split()[1:7] == ["1/2", "T-1", "start", "0%", "0s", "≤29m"]
    assert start.endswith("access-control · Basket of another user readable")
    assert step.endswith("step 1 · GET /rest/basket/2 as alice → 200 · 512 B")
    assert done.split()[1:7] == ["1/2", "T-1", "done", "50%", "1m00s", "~1m"]
    assert done.endswith("confirmed (high) · proof checked · 2 steps · 1m00s · a read b")
    assert "\x1b" not in out.getvalue()


def test_the_start_line_names_the_requests_and_the_verdict_colour_is_seen_from_the_finding(monkeypatch):
    from appsec_verifier.endpoints import Endpoint

    monkeypatch.setenv("COLUMNS", "400")
    out = Tty()
    progress = RunProgress(out, clock=Clock(), env={"FORCE_COLOR": "1"}, live=False)
    st = progress.st
    plan = _plan()
    plan.endpoints = (Endpoint("GET", "/rest/basket/:id", True), Endpoint("PUT", "/a", None),
                      Endpoint("GET", "/b", None))
    progress.begin([plan])
    progress.finding(plan)
    start = SGR.sub("", _rows(out)[-1])
    assert start.endswith("access-control · GET /rest/basket/:id (login), PUT /a · Basket of another user readable")
    assert st("1/1 T-1", "bold") in _rows(out)[-1] and st("1/1 T-1", "accent", "bold") not in out.getvalue()
    for verdict, label, role in (("confirmed", "confirmed", "ok"), ("not-reproducible", "not reproducible", "critical"),
                                 ("blocked-by-control", "blocked by control", "critical"),
                                 ("inconclusive", "inconclusive", "warn")):
        progress.finished(plan, ProbeResult(verdict=verdict))
        assert st(label, role) in _rows(out)[-1], verdict


def test_a_step_line_shows_the_agent_note_the_payload_and_the_model_time(monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    out, clock = io.StringIO(), Clock()
    progress = RunProgress(out, model="m", clock=clock, env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.activity(1, 12)
    clock.now += 14
    args = {"method": "POST", "path": "/rest/user/login", "params": {"q": "x'--"}, "json": {"email": "a'--"}}
    progress.activity(1, 12, "http_request", args)
    progress.step({"step": 1, "tool": "http_request", "args": args, "note": "login bypass with a quote",
                   "result": {"status": 500, "length": 90}})
    assert _rows(out)[-1].endswith("step 1 · login bypass with a quote · POST /rest/user/login?q=x'-- "
                                   '{"email":"a\'--"} → 500 · 90 B · model 14s')



def test_each_screenshot_of_a_finding_is_named_with_its_path_under_the_done_line():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={}, out_dir="verification")
    progress.begin([_plan()])
    progress.finding(_plan())
    evidence = [{"kind": "browser-event", "path": "evidence/T-1-xss-1.json"},
                {"kind": "screenshot", "path": "evidence/T-1-xss-1.png"},
                {"kind": "har", "path": "evidence/T-1-poc.har"},
                {"kind": "screenshot", "path": "evidence/T-1-exchange-1.png"}]
    progress.finished(_plan(), ProbeResult(verdict="confirmed", evidence=evidence))
    rows = _rows(out)[-3:]
    assert rows[0].split()[3] == "done"
    assert [r.split()[3] for r in rows[1:]] == ["img", "img"]
    assert rows[1].endswith("screenshot verification/evidence/T-1-xss-1.png")
    assert rows[2].endswith("screenshot verification/evidence/T-1-exchange-1.png")


def test_refused_steps_and_limits_need_attention_and_are_not_repeated_on_the_done_line():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.step({"step": 1, "refused": "unknown action 'fetch_url'", "proposal": "{}"})
    progress.step({"step": 2, "tool": "http_request", "args": {"path": "/a"}, "stopped": "requests",
                   "reason": "request cap 1 exceeded"})
    progress.finished(_plan(), ProbeResult(verdict="inconclusive", rationale="stopped by limit: request cap"))
    rows = _rows(out)[3:]
    assert rows[0].split()[3] == "↻" and rows[0].endswith("step 1 · refused: unknown action 'fetch_url'")
    assert rows[1].split()[3] == "⚠"
    assert rows[1].endswith("step 2 · GET /a · stopped by limit: request cap 1 exceeded")
    assert rows[2].endswith("inconclusive · 2 steps · 0s")


def test_an_inconclusive_finding_says_why_when_nothing_above_did():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.finished(_plan(), ProbeResult(verdict="inconclusive", rationale="claude call failed: no answer"))
    assert _rows(out)[-1].endswith("inconclusive · 0s · claude call failed: no answer")


@pytest.mark.parametrize("api_prices, spend", [(False, "run $1.62 of $10.00"),
                                               (True, "run $1.62 of $10.00 at API prices")])
def test_with_costs_shown_the_done_line_gives_the_finding_cost_and_the_run_spend(api_prices, spend):
    out, spent = io.StringIO(), [1.20]
    progress = RunProgress(out, clock=Clock(), env={}, spent=lambda: spent[0], cost_limit=10.0,
                           api_prices=api_prices)
    progress.begin([_plan()])
    progress.finding(_plan())
    spent[0] = 1.62
    progress.finished(_plan(), ProbeResult(verdict="inconclusive", rationale="no answer"))
    assert _rows(out)[-1].endswith(f"inconclusive · 0s · $0.42 · {spend} · no answer")


def test_text_from_the_assessment_model_and_target_carries_no_escape_sequence_or_secret():
    out = Tty()
    redact = lambda v: yaml.safe_load(yaml.safe_dump(v).replace("s3cret", "[redacted]"))  # noqa: E731
    progress = RunProgress(out, redact=redact, clock=Clock(), env={"FORCE_COLOR": "1"}, live=False)
    progress.begin([_plan()])
    progress.finding(_plan(id=f"T-1{HOSTILE}", title=f"title {HOSTILE}"))
    progress.activity(1, 12, "http_request", {"path": f"/x?t=s3cret{HOSTILE}", "role": f"a{HOSTILE}"})
    progress.step({"step": 1, "tool": "http_request", "args": {"path": f"/x?t=s3cret{HOSTILE}"},
                   "result": {"error": f"refused s3cret {HOSTILE}"}})
    progress.finished(_plan(), ProbeResult(verdict="inconclusive", confidence=HOSTILE, rationale=f"s3cret{HOSTILE}"))
    text = out.getvalue()
    assert "s3cret" not in text and "[redacted]" in text
    assert "\x1b" not in SGR.sub("", text) and "\x07" not in text       # only the Verifier's own colour codes
    assert "s3cret" not in progress._activity and "\x1b" not in progress._activity


def test_on_a_terminal_the_status_line_shows_the_running_step_and_is_cleared_before_each_line(monkeypatch):
    monkeypatch.setenv("COLUMNS", "160")
    out, clock = Tty(), Clock()
    progress = RunProgress(out, model="m", remaining_time=lambda: 600, clock=clock, env={})
    assert progress.live
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.activity(3, 12)
    clock.now += 7
    progress.tick()
    frame = out.getvalue().rsplit("\n", 1)[1]
    assert frame.startswith("\x1b[?2026h\x1b[?25l\r") and frame.endswith("\r\x1b[?25h\x1b[?2026l")
    assert "step 3/12 · asking m · 7s" in frame and "─" * RunProgress.BAR_WIDTH in frame
    before = out.getvalue()
    progress.step({"step": 3, "tool": "read_source", "args": {"path": "a.ts", "around_line": 4}, "result": {}})
    added = out.getvalue()[len(before):]
    assert added.startswith("\r\x1b[K") and added.endswith("step 3 · source a.ts:4 → done\n")   # cleared first
    progress.tick()
    progress.close()
    assert out.getvalue().endswith("\r\x1b[K")                              # no status line left behind


def test_lines_printed_by_others_clear_the_status_line_first(capsys):
    out = Tty()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    assert isinstance(sys.stderr, _StatusGuard)
    progress.tick()
    print("a warning", file=sys.stderr)
    assert out.getvalue().endswith("\r\x1b[K")
    progress.close()
    assert not isinstance(sys.stderr, _StatusGuard)
    assert "a warning" in capsys.readouterr().err


def test_off_a_terminal_a_quiet_stretch_gets_a_heartbeat_line():
    out, clock = io.StringIO(), Clock()
    progress = RunProgress(out, model="m", clock=clock, env={})
    assert not progress.live
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.activity(2, 12)
    clock.now += 119
    progress.tick()
    assert len(_rows(out)) == 3
    clock.now += 1
    progress.tick()
    assert _rows(out)[-1].endswith("step 2/12 · asking m · 2m00s")
    assert "\x1b" not in out.getvalue()
    progress.close()


def test_no_finding_with_a_probe_shows_no_grid():
    out = io.StringIO()
    progress = RunProgress(out, env={})
    progress.begin([])
    progress.close()
    assert out.getvalue() == ""


class Recorder:
    def __init__(self):
        self.events = []

    def begin(self, plans):
        self.events.append(("begin", [plan.id for plan in plans]))

    def finding(self, plan):
        self.events.append(("finding", plan.id))

    def activity(self, step, of, tool=None, args=None):
        self.events.append(("activity", step, of, tool))

    def step(self, record):
        self.events.append(("step", record.get("step"), record.get("tool") or record.get("verdict")))

    def finished(self, plan, result):
        self.events.append(("finished", plan.id, result.verdict))


def test_the_runner_shows_only_findings_with_a_probe():
    class Probe:
        cls = "access-control"

        def run(self, ctx):
            return ProbeResult(verdict="not-reproducible")

    recorder = Recorder()
    plans = [_plan("T-1"), _plan("T-2", status="static-only"), _plan("T-3", cls="xss")]
    scope = {"base_url": "https://app.example.com", "hosts": ["app.example.com"]}
    run_verification(assessment_path="a.yaml", scope=scope, scope_path="s.yaml", plans=plans, limits=Limits(),
                     identities=[], registry=ProbeRegistry({"access-control": Probe()}), verifier_version="t",
                     target_base=scope["base_url"], authorization={}, progress=recorder)
    assert recorder.events == [("begin", ["T-1"]), ("finding", "T-1"), ("finished", "T-1", "not-reproducible")]


def test_the_agent_loop_announces_each_call_before_it_runs_and_reports_each_step():
    steps = iter([{"tool": "read_source", "args": {"path": "a.ts"}},
                  {"verdict": {"verdict": "not-reproducible", "rationale": "checked"}}])

    class Planner:
        def next_step(self, ctx, history):
            return next(steps)

    recorder = Recorder()
    scope = {"base_url": "https://app.example.com", "hosts": ["app.example.com"]}
    ctx = ProbeContext(plan=_plan(), scope=scope, guard=ScopeGuard(scope), budget=RunBudget(Limits()), http=None,
                       identities=[], callback={}, progress=recorder)
    AgentProbe("access-control", Planner, max_steps=5).run(ctx)
    assert recorder.events == [("activity", 1, 5, None), ("activity", 1, 5, "read_source"),
                               ("step", 1, "read_source"), ("activity", 2, 5, None),
                               ("step", 2, "not-reproducible")]


def test_the_agent_loop_logs_and_shows_the_planner_note_and_ignores_it_for_a_verdict():
    out, clock = io.StringIO(), Clock()
    steps = iter([{"tool": "read_source", "args": {"path": "a.ts"}, "note": f"find the route{HOSTILE}"},
                  {"verdict": {"verdict": "not-reproducible", "rationale": "checked"}}])

    class Planner:
        def next_step(self, ctx, history):
            clock.now += 9
            return next(steps)

    log = []
    progress = RunProgress(out, clock=clock, env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    scope = {"base_url": "https://app.example.com", "hosts": ["app.example.com"]}
    ctx = ProbeContext(plan=_plan(), scope=scope, guard=ScopeGuard(scope), budget=RunBudget(Limits()), http=None,
                       identities=[], callback={}, progress=progress, log=log.append)
    AgentProbe("access-control", Planner, max_steps=5).run(ctx)
    progress.close()
    assert log[0]["note"] == f"find the route{HOSTILE}"      # JSON-encoded when written, see test_actionlog
    assert "note" not in log[1]
    assert " · find the route]0;pwned[2J · source a.ts → error: " in out.getvalue()
    assert "model 9s" in out.getvalue() and "\x1b" not in out.getvalue()


def _verify_run(tmp_path, monkeypatch, capsys, info, *extra, usd=0.0):
    """One `verify` run over a fake planner whose every step costs `usd`; returns (stderr rows, stdout)."""
    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(scope))
    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor",
         "evidence": {"file": "routes/basket.ts", "line": 1}}]}))

    class Planner:
        def next_step(self, ctx, history):
            ctx.budget.note_cost(usd)
            if not history:
                return {"tool": "http_request", "args": {"path": "/rest/basket/2"}}
            return {"verdict": {"verdict": "not-reproducible", "rationale": "owner checked"}}

    def transport(method, url, headers, **k):
        return SimpleNamespace(status_code=200 if url.endswith(".com") else 403, headers={}, text="no",
                               content=b"no", url=url)

    from appsec_verifier.tools import httpx_transport

    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: transport)
    assert cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope",
                     str(tmp_path / "scope.yaml"), "--output", str(tmp_path / "out"), "--yes", "--test-all",
                     *extra]) == 0
    captured = capsys.readouterr()
    return captured.err.splitlines(), captured.out


def test_verify_shows_the_grid_on_stderr_and_the_run_usage_in_the_summary(tmp_path, monkeypatch, capsys):
    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none", "api_billing": True}
    rows, out = _verify_run(tmp_path, monkeypatch, capsys, info, usd=0.25)
    assert any(row.startswith("TIME") and "FINDING" in row for row in rows)
    assert any("step 1 · GET /rest/basket/2 → 403" in row for row in rows)
    assert rows[-1].split()[3:5] == ["done", "100%"] and "not reproducible" in rows[-1]
    assert " · $0.50 · run $0.50 of $10.00 · " in rows[-1]                 # API billing: costs shown
    assert "Run        : " in out and "2 requests · $0.50 of $10.00" in out


@pytest.mark.parametrize("profile, show, done, run", [
    ("claude", False, None, "2 requests\n"),
    ("claude", True, " · $0.50 · run $0.50 of $10.00 at API prices · ", "2 requests · $0.50 of $10.00 at API prices"),
    ("codex-cli", False, None, "2 requests\n"),
    ("codex-cli", True, None, "2 requests · cost not reported (subscription)"),
])
def test_a_subscription_run_shows_costs_only_with_show_costs(tmp_path, monkeypatch, capsys, profile, show, done, run):
    """As in AppSec Analyzer: without API billing the console names no amount unless --show-costs asks for it;
    a profile that reports no cost says so. The cost limit still applies (VER-015)."""
    info = {"profile": profile, "model": "m", "runtime": "fake", "auth": "login", "api_billing": False}
    rows, out = _verify_run(tmp_path, monkeypatch, capsys, info, *(["--show-costs"] if show else []),
                            usd=0.25 if profile == "claude" else 0.0)
    if done:
        assert done in rows[-1]
    else:
        assert "$" not in "\n".join(rows)
    assert run in out
