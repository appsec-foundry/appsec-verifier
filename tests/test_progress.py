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
from appsec_verifier.progress import RunProgress, _StatusGuard, duration, short_model
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
    result = ProbeResult(verdict="confirmed", confidence="high", rationale="a read b",
                         proof={"checked": True, "steps": [1, 2]})
    progress.agent_finished(_plan(), result)
    progress.finished(_plan(), result)
    progress.close()
    header, start, agent, step, finished, proof, done = _rows(out)[1:]
    assert header.split() == ["TIME", "FINDING", "EVENT", "PROGRESS", "ELAPSED", "LEFT", "DETAIL"]
    assert start.split()[1:7] == ["1/2", "T-1", "start", "0%", "0s", "≤29m"]
    assert start.endswith("Basket of another user readable · high · access-control")
    assert agent.split()[3] == "agent" and agent.endswith("▶ test agent started · Sonnet 5.5 · no identities")
    assert step.endswith("step 1 · GET /rest/basket/2 as alice → 200 · 512 B")
    assert finished.split()[3] == "agent" and finished.endswith("■ test agent finished · 2 steps · 1m00s")
    assert proof.split()[3] == "proof"
    assert proof.endswith("✓ proof checked: access differs between identities · steps 1, 2")
    assert done.split()[1:7] == ["1/2", "T-1", "done", "50%", "1m00s", "~1m"]
    assert done.endswith("✔ confirmed (high) · 1m00s · a read b")
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
    title, facts, agent = _rows(out)[-3:]
    assert SGR.sub("", title).endswith("  Basket of another user readable") and st(plan.title, "bold") in title
    assert SGR.sub("", facts).strip() == "high · access-control · GET /rest/basket/:id (login), PUT /a"
    plain = SGR.sub("", agent)
    assert plain.split()[3] == "agent" and plain.endswith("▶ test agent started · no identities")
    assert st("▶ test agent started", "agent", "bold") in agent
    assert facts.startswith(" " * len(SGR.sub("", title).split("Basket")[0])) and st("high", "high") in facts
    assert st("1/1 T-1", "bold") in title and st("1/1 T-1", "accent", "bold") not in out.getvalue()
    for verdict, label, role in (("confirmed", "✔ confirmed", "ok"),
                                 ("not-reproducible", "✘ not reproducible", "critical"),
                                 ("blocked-by-control", "✘ blocked by control", "critical"),
                                 ("inconclusive", "? inconclusive", "warn")):
        progress.finished(plan, ProbeResult(verdict=verdict))
        assert st(label, role, "bold") in _rows(out)[-1], verdict


@pytest.mark.parametrize("model, short", [("claude-sonnet-5-5", "Sonnet 5.5"), ("claude-opus-4-1-20250805", "Opus 4.1"),
                                          ("haiku", "Haiku"), ("claude-fable-5-1", "Fable 5.1"),
                                          ("gpt-5.1-codex", "gpt-5.1-codex")])
def test_models_are_named_in_the_short_form_of_the_analyzer(model, short):
    assert short_model(model) == short


def test_the_start_entry_names_the_agent_its_step_budget_and_what_it_may_use(monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    out, clock = Tty(), Clock()
    progress = RunProgress(out, model="claude-sonnet-4-5-20250929", runtime="Claude CLI", max_steps=12,
                           roles=["alice", "bob"], source=True, clock=clock, env={}, live=False)
    progress.begin([_plan(), _plan("T-2")])
    progress.finding(_plan())
    row = SGR.sub("", _rows(out)[-1])
    assert row.split()[3] == "agent" and row.endswith("▶ test agent started · Sonnet 4.5 via Claude CLI · ≤12 steps · "
                                                      "identities alice, bob · source code")
    progress.activity(1, 12)
    assert progress._activity == "step 1/12 · Sonnet 4.5 plans"         # what the status line shows
    progress.finding(_plan("T-2"), agent=False)     # stopped by an earlier run-wide limit: no agent starts
    assert SGR.sub("", _rows(out)[-1]).strip() == "high · access-control"


def test_a_finding_an_earlier_run_wide_limit_stopped_is_shown_without_an_agent():
    class Probe:
        cls = "access-control"

        def run(self, ctx):
            return ProbeResult(verdict="inconclusive", limits_hit="requests")

    recorder = Recorder()
    scope = {"base_url": "https://app.example.com", "hosts": ["app.example.com"]}
    run_verification(assessment_path="a.yaml", scope=scope, scope_path="s.yaml", plans=[_plan("T-1"), _plan("T-2")],
                     limits=Limits(), identities=[], registry=ProbeRegistry({"access-control": Probe()}),
                     verifier_version="t", target_base=scope["base_url"], authorization={}, progress=recorder)
    assert [event[:3] for event in recorder.events] == [
                               ("begin", ["T-1", "T-2"]), ("finding", "T-1"), ("agent finished", "T-1", "inconclusive"),
                               ("finished", "T-1", "inconclusive"),
                               ("finding", "T-2", "no agent"), ("finished", "T-2", "not-attempted")]


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
    progress.finished(_plan(), ProbeResult(verdict="confirmed", evidence=evidence, proof={"checked": True}))
    rows = _rows(out)[-3:]
    assert rows[0].split()[3] == "done"
    assert [r.split()[3] for r in rows[1:]] == ["proof", "proof"]
    assert rows[1].endswith("screenshot verification/evidence/T-1-xss-1.png")
    assert rows[2].endswith("screenshot verification/evidence/T-1-exchange-1.png")


@pytest.mark.parametrize("verdict, proof", [
    ("inconclusive", {"checked": False, "missing": ["the browser did not complete an execution attempt"]}),
    ("inconclusive", None),
])
def test_a_screenshot_without_a_checked_proof_is_no_proof_line(verdict, proof):
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={}, out_dir="verification")
    progress.begin([_plan()])
    progress.finding(_plan())
    evidence = [{"kind": "screenshot", "path": "evidence/T-1-exchange-1.png"}]
    progress.finished(_plan(), ProbeResult(verdict=verdict, evidence=evidence, proof=proof))
    assert _rows(out)[-1].split()[3] == "img"


def test_refused_steps_and_limits_need_attention_and_are_not_repeated_on_the_done_line():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.step({"step": 1, "refused": "unknown action 'fetch_url'", "proposal": "{}"})
    progress.step({"step": 2, "tool": "http_request", "args": {"path": "/a"}, "stopped": "requests",
                   "reason": "request cap 1 exceeded"})
    result = ProbeResult(verdict="inconclusive", rationale="stopped by limit: request cap", limits_hit="requests")
    progress.agent_finished(_plan(), result)
    progress.finished(_plan(), result)
    rows = _rows(out)[4:]
    assert rows[0].split()[3] == "↻" and rows[0].endswith("step 1 · refused: unknown action 'fetch_url'")
    assert rows[1].split()[3] == "⚠"
    assert rows[1].endswith("step 2 · GET /a · stopped by limit: request cap 1 exceeded")
    assert rows[2].endswith("■ test agent finished · 2 steps · 0s")
    assert rows[3].split()[3] == "proof" and rows[3].endswith("✗ no proof: stopped by the requests limit")
    assert rows[4].endswith("? inconclusive · 0s")


def test_an_inconclusive_finding_says_why_when_nothing_above_did():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.finished(_plan(), ProbeResult(verdict="inconclusive", rationale="claude call failed: no answer"))
    assert _rows(out)[-1].endswith("? inconclusive · 0s · claude call failed: no answer")


@pytest.mark.parametrize("result, why", [
    # A claimed confirmation the proof check refused: what it missed, not the agent's claim.
    (ProbeResult(verdict="inconclusive",
                 rationale="indicative, not proven: no executed browser_check. Agent's claim: x",
                 proof={"checked": False, "contract": 3, "missing": ["no executed browser_check"]}),
     "no executed browser_check"),
    (ProbeResult(verdict="not-reproducible", rationale="bob got 403 for every basket",
                 proof={"checked": True, "steps": [2, 3]}), "bob got 403 for every basket"),
    (ProbeResult(verdict="inconclusive", rationale="probe failed: KeyError"), "probe failed: KeyError"),
    (ProbeResult(verdict="inconclusive"), "no verdict"),
])
def test_without_a_checked_proof_the_proof_entry_says_why_and_the_done_line_does_not_repeat_it(monkeypatch, result,
                                                                                                why):
    monkeypatch.setenv("COLUMNS", "400")
    out = Tty()
    progress = RunProgress(out, clock=Clock(), env={}, live=False)
    st = progress.st
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.agent_finished(_plan(), result)
    proof = _rows(out)[-1]
    assert SGR.sub("", proof).split()[3] == "proof" and SGR.sub("", proof).endswith(f"✗ no proof: {why}")
    assert st("✗ no proof", "warn", "bold") in proof and st(f": {why}", "warn") in proof
    assert st("proof  ", "warn") in proof                     # the event in the warning colour, not green
    progress.finished(_plan(), result)
    assert why not in _rows(out)[-1] and SGR.sub("", _rows(out)[-1]).endswith(" · 0s")


@pytest.mark.parametrize("cls, shown", [("xss", "script executed in the browser"),
                                        ("path-traversal", "marker file read"),
                                        ("ssrf", "the target called the Verifier's listener")])
def test_a_checked_proof_stands_out_with_what_it_showed(monkeypatch, cls, shown):
    monkeypatch.setenv("COLUMNS", "400")
    out = Tty()
    progress = RunProgress(out, clock=Clock(), env={}, live=False)
    st = progress.st
    plan = _plan(cls=cls)
    progress.begin([plan])
    progress.finding(plan)
    result = ProbeResult(verdict="confirmed", confidence="high", rationale="why", proof={"checked": True, "steps": [4]})
    progress.agent_finished(plan, result)
    proof = _rows(out)[-1]
    assert SGR.sub("", proof).endswith(f"✓ proof checked: {shown} · step 4")
    assert st("✓ proof checked", "ok", "bold") in proof and st("proof  ", "ok") in proof
    progress.finished(plan, result)
    assert st("✔ confirmed (high)", "ok", "bold") in _rows(out)[-2] and _rows(out)[-1].strip() == "why"


def test_a_proof_the_check_sent_back_to_the_agent_says_why(monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    out, spent = Tty(), [0.10]
    redact = lambda v: yaml.safe_load(yaml.safe_dump(v).replace("s3cret", "[redacted]"))  # noqa: E731
    progress = RunProgress(out, clock=Clock(), env={}, live=False, redact=redact, spent=lambda: spent[0],
                           cost_limit=10.0)
    st = progress.st
    progress.begin([_plan()])
    progress.finding(_plan())
    spent[0] = 0.13
    progress.step({"step": 3, "tool": "proof_feedback",
                   "result": {"status": "insufficient", "remaining_steps": 4,
                              "missing": [f"step 1 precedes the plan in step 2 and must be repeated s3cret{HOSTILE}"]}})
    row = _rows(out)[-1]
    assert SGR.sub("", row).split()[3] == "proof"
    assert SGR.sub("", row).endswith("step 3 · ✗ proof not accepted: step 1 precedes the plan in step 2 and must be "
                                     "repeated [redacted]]0;pwned[2J · back to the agent · $0.03")
    assert st("✗ proof not accepted", "warn", "bold") in row and "s3cret" not in row
    assert "\x1b" not in SGR.sub("", row) and "\x07" not in row


def test_a_result_a_proof_needs_is_highlighted_in_its_step(monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    out = Tty()
    progress = RunProgress(out, clock=Clock(), env={}, live=False)
    st = progress.st
    progress.begin([_plan(cls="xss")])
    progress.finding(_plan(cls="xss"))
    progress.step({"step": 1, "tool": "browser_check", "args": {"path": "/#/search?q=x"}, "result": {"executed": True}})
    assert st("script executed", "ok", "bold") in _rows(out)[-1]
    progress.step({"step": 2, "tool": "http_request", "args": {"path": "/f"},
                   "result": {"status": 200, "marker_read": True, "callback_hit": True}})
    assert st("marker file read", "ok", "bold") in _rows(out)[-1] and st("callback hit", "ok", "bold") in _rows(out)[-1]
    progress.step({"step": 3, "tool": "browser_check", "args": {"path": "/#/search?q=y"},
                   "result": {"executed": False}})
    assert SGR.sub("", _rows(out)[-1]).endswith("→ no script executed")
    assert st("no script executed", "ok", "bold") not in _rows(out)[-1]


def test_the_evidence_reviewer_has_agent_entries_for_its_start_and_end():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.evidence_review("T-1", "review", 0, "Checking evidence text, layout and 1 screenshot.")
    progress.evidence_review("T-1", "revise", 1, "Original test agent: unclear quote")
    progress.evidence_review("T-1", "review", 1, "Checking evidence text, layout and 1 screenshot.")
    progress.evidence_review("T-1", "quality", 1, "clear: Evidence text and layout checks passed.")
    progress.evidence_review("T-1", "quality", 0, "not-reviewed: Review not started: interrupted.")
    rows = _rows(out)[-5:]
    assert [row.split()[3] for row in rows] == ["agent", "revise", "review", "agent", "quality"]
    assert rows[0].endswith("▶ evidence reviewer started · Checking evidence text, layout and 1 screenshot.")
    assert rows[1].endswith("correction 1/2 · Original test agent: unclear quote")
    assert rows[3].endswith("■ evidence reviewer finished · clear: Evidence text and layout checks passed.")
    assert rows[4].endswith("correction 0/2 · not-reviewed: Review not started: interrupted.")


def test_a_changed_rating_follows_the_verdict_and_an_unchanged_one_is_not_shown(monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    out = Tty()
    progress = RunProgress(out, clock=Clock(), env={}, live=False)
    st = progress.st
    progress.begin([_plan()])
    progress.finding(_plan())
    rating = {"analyzer": {"likelihood": "Low", "impact": "High", "severity": "Medium"},
              "after_verification": {"likelihood": "High", "impact": "High", "severity": "High"}, "changed": True,
              "reason": "confirmed with a checked proof: likelihood Low → High, severity Medium → High"}
    progress.finished(_plan(), ProbeResult(verdict="confirmed"), rating=rating)
    row = _rows(out)[-1]
    assert SGR.sub("", row).split()[3] == "rating"
    assert SGR.sub("", row).endswith("severity Medium → High · likelihood Low → High · confirmed with a checked proof")
    assert st("severity Medium → High", "bold") in row
    unchanged = {"analyzer": {}, "after_verification": {}, "changed": False, "reason": "no checked proof"}
    progress.finished(_plan(), ProbeResult(verdict="inconclusive"), rating=unchanged)
    assert SGR.sub("", _rows(out)[-1]).split()[3] == "done"


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


def test_with_costs_shown_each_step_gives_its_cost_and_the_status_line_the_run_spend(monkeypatch):
    """As in AppSec Analyzer the cost runs along with the run, not only at a finding's end."""
    monkeypatch.setenv("COLUMNS", "200")
    out, clock, spent = io.StringIO(), Clock(), [1.20]
    progress = RunProgress(out, model="m", clock=clock, env={}, spent=lambda: spent[0], cost_limit=10.0)
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.activity(1, 12)
    spent[0] = 1.25
    progress.activity(1, 12, "http_request", {"path": "/a"})
    progress.step({"step": 1, "tool": "http_request", "args": {"path": "/a"}, "result": {"status": 200}})
    assert _rows(out)[-1].endswith("step 1 · GET /a → 200 · model 0s · $0.05")
    spent[0] = 1.27
    progress.step({"step": 2, "refused": "unknown action 'x'"})
    assert _rows(out)[-1].endswith("step 2 · refused: unknown action 'x' · $0.02")
    progress.step({"step": 3, "tool": "read_source", "args": {"path": "a.ts"}, "result": {}})
    assert _rows(out)[-1].endswith("step 3 · source a.ts → done")        # nothing spent, no amount
    progress.activity(4, 12)
    clock.now += 120
    progress.tick()
    assert _rows(out)[-1].endswith("$1.27 of $10.00 · step 4/12 · m plans · 2m00s")

    live = Tty()
    progress = RunProgress(live, model="m", clock=clock, env={}, spent=lambda: spent[0], cost_limit=10.0,
                           api_prices=True)
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.activity(1, 12)
    progress.tick()
    frame = live.getvalue().rsplit("\n", 1)[1]
    assert progress.st("$1.27", "accent") + " of $10.00 · step 1/12 · m plans" in frame
    spent[0] = 1.62
    progress.finished(_plan(), ProbeResult(verdict="inconclusive"))
    done = _rows(live)[-1]
    assert progress.st("$0.35", "accent") in done and progress.st("$1.62", "accent") in done
    assert SGR.sub("", done).endswith("inconclusive · 0s · $0.35 · run $1.62 of $10.00 at API prices")
    progress.close()


def test_on_a_terminal_findings_are_set_apart_and_the_tested_request_stands_out(monkeypatch):
    monkeypatch.setenv("COLUMNS", "120")
    out, spent = Tty(), [0.0]
    progress = RunProgress(out, clock=Clock(), env={}, spent=lambda: spent[0], cost_limit=10.0)
    st = progress.st
    progress.begin([_plan(), _plan("T-2")])
    progress.finding(_plan())
    long = "/rest/products/search?q=" + "x')) OR 1=1-- " * 8
    spent[0] = 0.04
    progress.step({"step": 1, "tool": "http_request", "args": {"path": long}, "note": "boolean injection",
                   "result": {"status": 500, "length": 942}})
    progress.finished(_plan(), ProbeResult(verdict="confirmed", confidence="high", rationale="the rows flipped"))
    progress.finding(_plan("T-2"))
    progress.close()
    rows = [SGR.sub("", row) for row in _rows(out)]
    column = rows[2].index("Basket")                        # where the detail column starts
    note = next(i for i, row in enumerate(rows) if row.endswith("step 1 · boolean injection"))
    hang = column + len("step 1 · ")
    done = next(i for i, row in enumerate(rows) if " done " in row)
    tested = rows[note + 1:done]
    assert len(tested) == 2                                                 # the long request wraps
    assert all(row.startswith(" " * hang) and not row[hang].isspace() for row in tested)   # under the note
    assert tested[0][hang:].startswith("GET /rest/products/search?q=x'))")
    assert all(len(row) <= 119 for row in rows)
    assert tested[-1].endswith("→ 500 · 942 B · $0.04")
    assert _rows(out)[note + 1].strip() == st(tested[0].strip(), "agent")   # each piece of the request coloured
    assert st(tested[1][hang:].split(" → ")[0], "agent") in _rows(out)[note + 2]
    assert st("$0.04", "accent") in out.getvalue()
    blank = rows.index("", done)                                            # a blank line before the next finding
    assert " 2/2 T-2  start " in rows[blank + 1]
    entry = [row[column:] for row in rows[done:blank]]
    assert all(row[:column].isspace() for row in rows[done + 1:blank]) and entry[-1] == "the rows flipped"
    assert " ".join(entry[:-1]) == "✔ confirmed (high) · 0s · $0.04 · run $0.04 of $10.00"
    assert entry[-2].endswith("run $0.04 of $10.00")                        # the spend stays whole


def test_off_a_terminal_a_blank_line_sets_each_finding_apart():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan(), _plan("T-2")])
    progress.finding(_plan())
    progress.step({"step": 1, "tool": "http_request", "args": {"path": "/a"}, "note": "n", "result": {"status": 200}})
    progress.finished(_plan(), ProbeResult(verdict="confirmed", rationale="why"))
    progress.finding(_plan("T-2"))
    rows = _rows(out)[2:]
    assert [row.split()[3] if row else "" for row in rows] == ["start", "agent", "·", "done", "", "start", "agent"]
    assert rows[2].endswith("step 1 · n · GET /a → 200") and rows[3].endswith(" · why")


def test_text_from_the_assessment_model_and_target_carries_no_escape_sequence_or_secret(monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    out = Tty()
    redact = lambda v: yaml.safe_load(yaml.safe_dump(v).replace("s3cret", "[redacted]"))  # noqa: E731
    progress = RunProgress(out, model=f"m{HOSTILE}", runtime=f"Claude CLI {HOSTILE}", roles=[f"alice s3cret{HOSTILE}"],
                           redact=redact, clock=Clock(), env={"FORCE_COLOR": "1"}, live=False)
    progress.begin([_plan()])
    progress.finding(_plan(id=f"T-1{HOSTILE}", title=f"title {HOSTILE}"))
    assert "test agent started · m" in SGR.sub("", out.getvalue()) and "identities alice [redacted]" in out.getvalue()
    progress.activity(1, 12, "http_request", {"path": f"/x?t=s3cret{HOSTILE}", "role": f"a{HOSTILE}"})
    progress.step({"step": 1, "tool": "http_request", "args": {"path": f"/x?t=s3cret{HOSTILE}"},
                   "result": {"error": f"refused s3cret {HOSTILE}"}})
    result = ProbeResult(verdict="inconclusive", confidence=HOSTILE, rationale=f"s3cret{HOSTILE}")
    progress.agent_finished(_plan(), result)
    assert SGR.sub("", _rows(out)[-1]).endswith("✗ no proof: [redacted]]0;pwned[2J")
    progress.finished(_plan(), result)
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
    assert "step 3/12 · m plans · 7s" in frame and "─" * RunProgress.BAR_WIDTH in frame
    before = out.getvalue()
    progress.step({"step": 3, "tool": "read_source", "args": {"path": "a.ts", "around_line": 4}, "result": {}})
    added = out.getvalue()[len(before):]
    assert added.startswith("\r\x1b[K") and SGR.sub("", added).endswith("step 3 · source a.ts:4 → done\n")  # cleared
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
    assert len(_rows(out)) == 4
    clock.now += 1
    progress.tick()
    assert _rows(out)[-1].endswith("step 2/12 · m plans · 2m00s")
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

    def finding(self, plan, agent=True):
        self.events.append(("finding", plan.id) if agent else ("finding", plan.id, "no agent"))

    def activity(self, step, of, tool=None, args=None):
        self.events.append(("activity", step, of, tool))

    def step(self, record):
        self.events.append(("step", record.get("step"), record.get("tool") or record.get("verdict")))

    def agent_finished(self, plan, result):
        self.events.append(("agent finished", plan.id, result.verdict))

    def finished(self, plan, result, rating=None):
        self.events.append(("finished", plan.id, result.verdict, *([rating] if rating else [])))


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
    assert recorder.events[:3] == [("begin", ["T-1"]), ("finding", "T-1"),
                                   ("agent finished", "T-1", "not-reproducible")]
    assert recorder.events[3][:3] == ("finished", "T-1", "not-reproducible") and len(recorder.events) == 4


def test_the_runner_gives_the_rating_after_the_last_variant_of_a_finding_from_all_its_variants():
    """One confirmed variant raises the rating (VER-039); it is shown once, after the finding's last variant."""
    from dataclasses import replace

    class Probe:
        cls = "access-control"

        def run(self, ctx):
            if ctx.plan.variant_id == "v1":
                return ProbeResult(verdict="confirmed", proof={"checked": True, "variant": "v1", "steps": [1, 2]})
            return ProbeResult(verdict="inconclusive", rationale="no second identity")

    rating = {"likelihood": "Low", "impact": "High", "effective_severity": "Medium", "risk": None,
              "verification_context": {"variants": [{"id": "v1"}, {"id": "v2"}]}}
    plan = replace(_plan("T-1"), rating=rating)
    plans = [replace(plan, variant_id=v, variant_digest=v * 8) for v in ("v1", "v2")] + [_plan("T-2")]
    recorder = Recorder()
    scope = {"base_url": "https://app.example.com", "hosts": ["app.example.com"]}
    run_verification(assessment_path="a.yaml", scope=scope, scope_path="s.yaml", plans=plans, limits=Limits(),
                     identities=[], registry=ProbeRegistry({"access-control": Probe()}), verifier_version="t",
                     target_base=scope["base_url"], authorization={}, progress=recorder)
    finished = [event for event in recorder.events if event[0] == "finished"]
    assert [len(event) for event in finished] == [3, 4, 4]          # no rating after the first variant
    changed, unrated = finished[1][3], finished[2][3]
    assert changed["changed"] and changed["after_verification"] == {"likelihood": "High", "impact": "High",
                                                                    "severity": "High"}
    assert not unrated["changed"]                                    # T-2 names no rating


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
                               ("step", 2, "not-attempted")]


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
        {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor", "scenario": "GET /rest/basket/2",
         "evidence": {"file": "routes/basket.ts", "line": 1}}]}))

    class Planner:
        def next_step(self, ctx, history):
            ctx.budget.note_cost(usd)
            if not history:
                return {"tool": "http_request", "args": {"path": "/rest/basket/2"}}
            return {"verdict": {"verdict": "inconclusive", "rationale": "rejection alone is insufficient"}}

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
    info = {"profile": "anthropic-api", "model": "m", "runtime": "Fake API 1.0", "runtime_name": "Fake API",
            "auth": "none", "api_billing": True}
    rows, out = _verify_run(tmp_path, monkeypatch, capsys, info, usd=0.25)
    assert any(row.startswith("TIME") and "FINDING" in row for row in rows)
    assert any(row.endswith("▶ test agent started · m via Fake API · ≤12 steps · no identities") for row in rows)
    assert any(row.endswith("✗ no proof: rejection alone is insufficient") for row in rows)
    assert any("step 1 · GET /rest/basket/2 → 403" in row for row in rows)
    done = next(row for row in rows if row.split()[3:4] == ["done"])
    assert done.split()[3:5] == ["done", "100%"] and "inconclusive" in done
    assert done.endswith(" · $0.50 · run $0.50 of $10.00")                # API billing: costs shown
    # The verdict cites no step: the image of its requests follows, named img, not proof (VER-035).
    assert rows[-1].split()[3] == "img" and "screenshot" in rows[-1]
    assert "Run        : " in out and "2 requests · $0.50 of $10.00" in out


@pytest.mark.parametrize("profile, show, done, run", [
    ("claude", False, None, "2 requests\n"),
    ("claude", True, " · $0.50 · run $0.50 of $10.00 at API prices", "2 requests · $0.50 of $10.00 at API prices"),
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
        assert next(row for row in rows if row.split()[3:4] == ["done"]).endswith(done)
    else:
        assert "$" not in "\n".join(rows)
    assert run in out
