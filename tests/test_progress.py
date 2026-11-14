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


def test_the_proof_line_names_the_form_and_a_qa_objection_has_its_own_line():
    """T-058 (run 133): the comparison without credentials is not "access differs between identities", and the
    technical QA's record, which has no step number, shows its first objection instead of "step None"."""
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.step({"step": None, "tool": "technical_review", "note": "Technical QA: needs-attention",
                   "result": {"status": "needs-attention", "issues": [
                       {"code": "interpretation", "detail": "jwt.pub is a public key.", "question": "?"}]}})
    result = ProbeResult(verdict="confirmed", confidence="medium", rationale="served",
                         proof={"checked": True, "steps": [4, 5, 6], "form": "comparison-without-credentials"})
    progress.agent_finished(_plan(), result)
    progress.close()
    text = "\n".join(_rows(out))
    assert "step None" not in text
    assert "Technical QA: needs-attention · jwt.pub is a public key." in text
    assert "✓ proof checked: same answer without credentials, unlike a random path · steps 4, 5, 6" in text


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
        done = next(row for row in reversed(_rows(out)) if SGR.sub("", row).split()[3:4] == ["done"])
        assert st(label, role, "bold") in done, verdict


def test_a_variant_line_names_its_own_key_and_request_so_siblings_differ():
    from dataclasses import replace

    from appsec_verifier.endpoints import Endpoint
    out = Tty()
    progress = RunProgress(out, clock=Clock(), live=False)
    finding = _plan(cls="xss", title="Sanitizer bypass")
    finding.endpoints = (Endpoint("GET", "/api/Feedbacks", None),)
    plans = [replace(finding, variant_id=f"variant-00{i}",
                     verification_context={"variants": [{"id": f"variant-00{i}", "request": {"method": m, "path": p}}]})
             for i, (m, p) in enumerate((("GET", "/api/Feedbacks"), ("POST", "/api/Feedbacks")), start=1)]
    progress.begin(plans)
    for plan in plans:
        progress.finding(plan)
    facts = [SGR.sub("", r).rstrip() for r in _rows(out) if "variant-00" in r]
    assert facts[0].endswith("variant-001 · GET /api/Feedbacks")
    assert facts[1].endswith("variant-002 · POST /api/Feedbacks")      # a sibling reads differently


@pytest.mark.parametrize("model, short", [("claude-sonnet-5-5", "Sonnet 5.5"), ("claude-opus-4-1-20250805", "Opus 4.1"),
                                          ("haiku", "Haiku"), ("claude-fable-5-1", "Fable 5.1"),
                                          ("gpt-5.1-codex", "gpt-5.1-codex")])
def test_models_are_named_in_the_short_form_of_the_analyzer(model, short):
    assert short_model(model) == short


def test_the_start_entry_names_the_agent_its_step_budget_and_what_it_may_use(monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setattr(RunProgress, "MAX_COLUMNS", 400)
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
    progress.step({"step": 2, "tool": "http_request", "args": args,
                   "result": {"status": 500, "length": None, "body_withheld": True}})
    assert "→ 500 · body withheld" in _rows(out)[-1]          # no size of the notice that stands in for it



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


def test_refused_steps_and_limits_need_attention_and_the_done_line_names_the_limit_to_raise():
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
    assert rows[4].endswith("? inconclusive · 0s · Limit reached: the run's requests to the target; raise them with "
                            "--max-requests.")


def test_a_test_agent_that_made_no_progress_is_shown_as_stopped_with_its_last_failure():
    """A stop after failed actions is no budget: the ⚠ row says stopped and names the last failure, the proof
    row says the agent made no progress (VER-036)."""
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    reason = "three actions in a row failed without a usable observation; the last: plan_test: no placeholder"
    progress.step({"step": 8, "stopped": "stagnation", "reason": reason})
    result = ProbeResult(verdict="inconclusive", rationale="stopped: " + reason, limits_hit="stagnation")
    progress.agent_finished(_plan(), result)
    progress.finished(_plan(), result)
    rows = [" ".join(row.split()) for row in _rows(out)[4:]]
    assert rows[0].endswith("step 8 · stopped: " + reason) and "by limit" not in rows[0]
    assert rows[2].endswith("✗ no proof: the test agent made no progress and was stopped")
    assert rows[3].endswith("? inconclusive · 0s · Agent stuck: the Verifier refused its steps repeatedly, the last a "
                            "test plan the Verifier refused. A new run may get further.")


def test_an_inconclusive_finding_says_why_when_nothing_above_did():
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.finished(_plan(), ProbeResult(verdict="inconclusive", rationale="claude call failed: no answer"))
    assert _rows(out)[-1].endswith("? inconclusive · 0s · Agent's assessment: claude call failed: no answer.")


@pytest.mark.parametrize("result, why, done", [
    # A claimed confirmation the proof check refused: what it missed, not the agent's claim.
    (ProbeResult(verdict="inconclusive",
                 rationale="indicative, not proven: no executed browser_check. Agent's claim: x",
                 proof={"checked": False, "contract": 3, "missing": ["no executed browser_check"]}),
     "no executed browser_check", "No proof: the agent's confirmation failed the proof check: no executed "
                                  "browser_check."),
    # A negative verdict is no missing proof: its done line does not repeat the reason.
    (ProbeResult(verdict="not-reproducible", rationale="bob got 403 for every basket",
                 proof={"checked": True, "steps": [2, 3]}), "bob got 403 for every basket", None),
    (ProbeResult(verdict="inconclusive", rationale="probe failed: KeyError"), "probe failed: KeyError",
     "Verifier error: the test stopped on an internal error (KeyError); failed-findings.json in the run directory "
     "has the details."),
    (ProbeResult(verdict="inconclusive"), "no verdict",
     "No proof: the test agent ended without a proof the Verifier could check."),
])
def test_without_a_checked_proof_the_proof_entry_says_why_and_the_done_line_says_it_by_kind(monkeypatch, result, why,
                                                                                            done):
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
    rows = [SGR.sub("", row) for row in _rows(out)]
    at = max(n for n, row in enumerate(rows) if row.split()[3:4] == ["done"])
    assert rows[at].endswith(" · 0s")
    if done:            # on a terminal under the done line, continued under its column
        assert " ".join(" ".join(rows[at + 1:]).split()) == done
    else:
        assert at == len(rows) - 1 and why not in rows[at]


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
    monkeypatch.setattr(RunProgress, "MAX_COLUMNS", 400)
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
                                     "repeated [redacted]]0;pwned[2J · back to the agent · run $0.13")
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


_BOOLEAN_PLAN = {"kind": "boolean", "path": "/brute/", "method": "GET", "input_location": "query",
                 "input_name": "username", "baseline": "admin", "sql_template": "admin' AND {{predicate}} -- -"}
_BOOLEAN_CONTROLS = (("baseline", "admin", 4399), ("true", "admin' AND (1=1) -- -", 4463),
                     ("false", "admin' AND (1=2) -- -", 4399), ("true, second pair", "admin' AND (2<>1) -- -", 4463),
                     ("false, second pair", "admin' AND (2<>2) -- -", 4399))


def _experiment(progress, plan, controls, *, first=5, role="account-2", feedback=None):
    """The records agent/loop.py logs for an accepted plan: the plan, its controls, then the check's feedback."""
    progress.step({"step": first - 1, "tool": "plan_test", "args": plan, "result": {"accepted": True}})
    step = first
    for label, value, result in controls:
        args = {"path": plan["path"], "method": "GET", **({"role": role} if role else {}),
                "params": {"password": "x", plan["input_name"]: value}}
        if not isinstance(result, dict):
            result = {"status": 200, "length": result}
        progress.step({"step": step, "tool": "http_request", "args": args, "control": label, "result": result})
        step += 1
    if feedback is not None:
        progress.step({"step": step, "tool": "experiment", "args": {}, "result": feedback})


def _shown(out) -> str:
    """The grid without colour, a wrapped entry read as one text."""
    return " ".join(SGR.sub("", "\n".join(_rows(out))).split())


def _started(monkeypatch, cls="injection", **kwargs):
    monkeypatch.setenv("COLUMNS", "400")
    out = Tty()
    progress = RunProgress(out, clock=Clock(), env={}, live=False, **kwargs)
    progress.begin([_plan(cls=cls)])
    progress.finding(_plan(cls=cls))
    return out, progress


def test_an_experiments_controls_stand_as_a_block_that_says_what_is_tested(monkeypatch):
    """As in a DVWA run: ten controls showed a cut-off URL each and ended in `experiment → done`. The block says
    what the experiment tests and asks, each control what it is and the value it sends, a second round with the
    first round's answers is one entry, and the check's outcome closes the block."""
    out, progress = _started(monkeypatch)
    controls = [(f"{name} #{n}", value, length) for n in (1, 2) for name, value, length in _BOOLEAN_CONTROLS]
    _experiment(progress, _BOOLEAN_PLAN, controls, feedback={"proof": "holds", "steps": list(range(5, 15))})
    shown = _shown(out)
    assert "boolean test of username (query) as account-2, each control twice:" in shown
    assert "do the true and false conditions answer differently" in shown
    assert "step 5 · normal · admin → 200 · 4399 B" in shown
    assert "step 6 · true · admin' AND (1=1) -- - → 200 · 4463 B" in shown
    assert "step 9 · false · admin' AND (2<>2) -- - → 200 · 4399 B" in shown
    assert "steps 10–14 · round 2: same answers as round 1" in shown
    assert "step 15 · ✓ the controls give the proof" in shown
    assert "step 10 ·" not in shown and "#1" not in shown and "/brute/?" not in shown
    assert "experiment" not in shown


def test_a_second_round_with_other_answers_shows_each_of_its_controls(monkeypatch):
    out, progress = _started(monkeypatch)
    controls = [(f"{name} #1", value, length) for name, value, length in _BOOLEAN_CONTROLS]
    controls += [("baseline #2", "admin", 4399), ("true #2", "admin' AND (1=1) -- -", 4399)]
    _experiment(progress, _BOOLEAN_PLAN, controls, feedback={"proof": "missing",
                                                             "reason": "the selected observation is unstable"})
    shown = _shown(out)
    assert "round 2" not in shown
    assert "step 10 · normal · admin → 200 · 4399 B" in shown
    assert "step 11 · true · admin' AND (1=1) -- - → 200 · 4399 B" in shown
    assert "step 12 · ✗ the controls give no proof: the selected observation is unstable" in shown


def test_a_block_cut_short_by_a_limit_shows_its_held_controls_before_the_stop(monkeypatch):
    out, progress = _started(monkeypatch)
    controls = [(f"{name} #1", value, length) for name, value, length in _BOOLEAN_CONTROLS] + [
        ("baseline #2", "admin", 4399)]
    _experiment(progress, _BOOLEAN_PLAN, controls)
    progress.step({"step": 11, "stopped": "time", "reason": "run time limit reached"})
    shown = _shown(out)
    assert 0 <= shown.index("step 10 · round 2: same answers as round 1") < shown.index("run time limit reached")


def test_the_comparison_names_who_reads_which_path(monkeypatch):
    """VER-057: the account's GET, the same GET without credentials and a random path; the identity belongs to a
    control, not to the block, and nothing is folded into a round."""
    out, progress = _started(monkeypatch, cls="access-control")
    plan = {"kind": "access-control", "path": "/api/v1/user/", "method": "GET", "signed_in": "account-1"}
    progress.step({"step": 1, "tool": "plan_test", "args": plan, "result": {"accepted": True}})
    for step, label, path, role, status in ((2, "as the account", "/api/v1/user/", "account-1", 200),
                                            (3, "without credentials", "/api/v1/user/", None, 200),
                                            (4, "random path", "/api/v1/vrf39/", None, 404)):
        progress.step({"step": step, "tool": "http_request", "control": label, "result": {"status": status},
                       "args": {"method": "GET", "comparison": True, "path": path, **({"role": role} if role else {})}})
    progress.step({"step": 5, "tool": "experiment", "args": {}, "result": {
        "proof": "missing", "reason": "access observed, but no independent access restriction is established"}})
    shown = _shown(out)
    assert "comparison of /api/v1/user/ signed in and without credentials:" in shown
    assert "does the request without credentials get the account's answer, unlike a random path?" in shown
    assert "step 2 · signed in as account-1 · /api/v1/user/ → 200" in shown
    assert "step 3 · without credentials · /api/v1/user/ → 200" in shown
    assert "step 4 · random path · /api/v1/vrf39/ → 404" in shown
    assert "✗ the controls give no proof: access observed" in shown


def test_the_engine_error_sweep_names_breaks_and_their_balanced_counterparts(monkeypatch):
    """VER-053: a break and a balance per metacharacter; the labels carry the metacharacter, the value shows it."""
    out, progress = _started(monkeypatch)
    plan = {**_BOOLEAN_PLAN, "error_probe": True}
    plan.pop("sql_template")
    controls = [("break ' #1", "admin'", {"status": 500, "body_withheld": True}),
                ("balance ' #1", "admin''", 4399)]
    _experiment(progress, plan, controls, feedback={"proof": "negative-only"})
    shown = _shown(out)
    assert "engine-error test of username (query) as account-2, each control twice:" in shown
    assert "does a syntax-breaking character raise an engine error that its balanced counterpart does not?" in shown
    assert "step 5 · break · admin' → 500 · body withheld" in shown
    assert "step 6 · balanced · admin'' → 200 · 4399 B" in shown
    assert "step 7 · the controls can support a negative verdict only: the agent chose their values" in shown


def test_a_control_shows_no_credential_value(monkeypatch):
    """VER-016: the value a control sends and the plan's fields pass the run's redaction like any other step."""
    secret = "Zq8-cred-71x"
    out, progress = _started(monkeypatch, redact=lambda value: _redact_all(value, secret))
    plan = {**_BOOLEAN_PLAN, "baseline": secret}
    _experiment(progress, plan, [("baseline #1", secret, 4399), ("true #1", secret + "' AND (1=1) -- -", 4463)],
                feedback={"proof": "missing", "reason": f"the baseline {secret} answered differently"})
    shown = _shown(out)
    assert secret not in shown
    assert "step 5 · normal · [account-1 password] → 200" in shown
    assert "step 6 · true · [account-1 password]' AND (1=1) -- -" in shown


def _redact_all(value, secret):
    if isinstance(value, str):
        return value.replace(secret, "[account-1 password]")
    if isinstance(value, dict):
        return {_redact_all(k, secret): _redact_all(v, secret) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_all(v, secret) for v in value]
    return value


def test_a_request_of_the_agent_after_a_block_shows_its_url_again(monkeypatch):
    out, progress = _started(monkeypatch)
    _experiment(progress, _BOOLEAN_PLAN, [("baseline #1", "admin", 4399)])
    progress.step({"step": 6, "tool": "http_request", "result": {"status": 200, "length": 4399},
                   "args": {"path": "/brute/", "params": {"username": "admin"}, "role": "account-2"}})
    assert "step 6 · GET /brute/?username=admin as account-2 → 200 · 4399 B" in _shown(out)


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
    # The reviewer's own row carries its time, which the finding's done line then leaves out.
    assert rows[3].endswith("■ evidence reviewer finished · clear: Evidence text and layout checks passed. · 0s")
    assert rows[4].endswith("correction 0/2 · not-reviewed: Review not started: interrupted.")


def test_reviewer_corrections_issues_and_the_rationale_show_their_first_sentence():
    """The report keeps the reviewer's issues by variant; the console gives each one's first sentence only."""
    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.evidence_review("T-1", "review", 0, "Checking evidence text and layout metadata.")
    progress.evidence_review("T-1", "revise", 1, "Original test agent: Step 5 returned a 500. The rationale skips it.")
    progress.evidence_review("T-1", "quality", 1, "needs-attention: Two correction rounds reached; unresolved issues "
                                                  "remain.")
    progress.evidence_review("T-1", "issue", 1, "T-1-930a49d43872218b: The comparison line lists only steps 8-17. "
                                                "It never says which responses are empty.")
    progress.finished(_plan(), ProbeResult(verdict="confirmed", rationale="q at routes/search.ts:23 is concatenated "
                                                                          "into the SQL query. Steps 9 and 11 flip."))
    revise, _, issue, done = _rows(out)[-4:]
    assert revise.endswith("correction 1/2 · Original test agent: Step 5 returned a 500.")
    assert issue.split()[3] == "issue"
    assert issue.endswith("  The comparison line lists only steps 8-17.")     # no variant key, no round
    assert done.endswith(" · q at routes/search.ts:23 is concatenated into the SQL query.")


def test_on_a_wide_terminal_rows_wrap_at_the_analyzers_line_width(monkeypatch):
    """A terminal wider than AppSec Analyzer's 140 columns still wraps there; the status line is cut there."""
    monkeypatch.setenv("COLUMNS", "400")
    out, clock = Tty(), Clock()
    progress = RunProgress(out, clock=clock, env={})
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.step({"step": 1, "tool": "http_request", "args": {"path": "/a"}, "note": "word " * 60,
                   "result": {"status": 200}})
    rows = [SGR.sub("", row) for row in _rows(out)]
    note = [row for row in rows if "word" in row]
    assert len(note) > 1 and all(len(row) <= RunProgress.MAX_COLUMNS - 1 for row in rows)
    progress.activity(2, 12, "http_request", {"path": "/" + "x" * 300})
    progress.tick()
    frame = SGR.sub("", out.getvalue().rsplit("\n", 1)[1])
    status = re.sub(r"\x1b\[[?0-9;]*[a-zA-Z]|\r", "", frame)
    assert status.endswith("…") and len(status) == RunProgress.MAX_COLUMNS - 1
    progress.close()


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
    assert SGR.sub("", _rows(out)[-2]).split()[3] == "done" and "rating" not in SGR.sub("", _rows(out)[-1])


@pytest.mark.parametrize("api_prices, spend", [(False, "run $1.62 of $10.00"),
                                               (True, "run $1.62 of $10.00 at API prices")])
def test_with_costs_shown_the_done_line_gives_the_run_spend_and_not_the_finding_cost(api_prices, spend):
    out, spent = io.StringIO(), [1.20]
    progress = RunProgress(out, clock=Clock(), env={}, spent=lambda: spent[0], cost_limit=10.0,
                           api_prices=api_prices)
    progress.begin([_plan()])
    progress.finding(_plan())
    spent[0] = 1.62
    progress.finished(_plan(), ProbeResult(verdict="inconclusive", rationale="no answer"))
    assert _rows(out)[-1].endswith(f"inconclusive · 0s · {spend} · Agent's assessment: no answer.")
    assert "$0.42" not in _rows(out)[-1]


def test_the_evidence_review_shows_its_own_time_and_the_run_spend_off_the_variants_done_line():
    """WP4: the review of a finding runs before its last variant's done line; its time goes on the
    reviewer's own row, which also gives the run's spend so far."""
    out, spent, clock = io.StringIO(), [1.00], Clock()
    progress = RunProgress(out, clock=clock, env={}, spent=lambda: spent[0], cost_limit=10.0)
    progress.begin([_plan()])
    progress.finding(_plan(), agent=False)                    # a variant retired by a confirmed sibling
    progress.evidence_review("T-1", "review", 0, "Checking evidence text and layout metadata.")
    spent[0], clock.now = 1.63, clock.now + 126
    progress.evidence_review("T-1", "quality", 0, "clear: Evidence text and layout checks passed.")
    finished = _rows(out)[-1]
    assert finished.endswith("■ evidence reviewer finished · clear: Evidence text and layout checks passed. · "
                             "2m06s · run $1.63")
    progress.finished(_plan(), ProbeResult(verdict="not-attempted", rationale="another variant confirmed it"))
    assert _rows(out)[-1].endswith(" · 0s · run $1.63 of $10.00 · Not needed: another variant confirmed it.")


def test_with_costs_shown_entries_give_the_running_total_and_the_status_line_the_run_spend(monkeypatch):
    """The cost runs along with the run, not only at a finding's end; each amount is the run's total so far,
    not what one step cost."""
    monkeypatch.setenv("COLUMNS", "200")
    out, clock, spent = io.StringIO(), Clock(), [1.20]
    progress = RunProgress(out, model="m", clock=clock, env={}, spent=lambda: spent[0], cost_limit=10.0)
    progress.begin([_plan()])
    progress.finding(_plan())
    progress.activity(1, 12)
    spent[0] = 1.25
    progress.activity(1, 12, "http_request", {"path": "/a"})
    progress.step({"step": 1, "tool": "http_request", "args": {"path": "/a"}, "result": {"status": 200}})
    assert _rows(out)[-1].endswith("step 1 · GET /a → 200 · model 0s · run $1.25")
    spent[0] = 1.27
    progress.step({"step": 2, "refused": "unknown action 'x'"})
    assert _rows(out)[-1].endswith("step 2 · refused: unknown action 'x' · run $1.27")
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
    done = _rows(live)[-2]
    assert progress.st("$1.62", "accent") in done
    assert SGR.sub("", done).endswith("inconclusive · 0s · run $1.62 of $10.00 at API prices")
    said = "No proof: the test agent ended without a proof the Verifier could check."
    assert SGR.sub("", _rows(live)[-1]).strip() == said
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
    assert tested[-1].endswith("→ 500 · 942 B · run $0.04")
    assert _rows(out)[note + 1].strip() == st(tested[0].strip(), "agent")   # each piece of the request coloured
    assert st(tested[1][hang:].split(" → ")[0], "agent") in _rows(out)[note + 2]
    assert st("$0.04", "accent") in out.getvalue()
    blank = rows.index("", done)                                            # a blank line before the next finding
    assert " 2/2 T-2  start " in rows[blank + 1]
    entry = [row[column:] for row in rows[done:blank]]
    assert all(row[:column].isspace() for row in rows[done + 1:blank]) and entry[-1] == "the rows flipped"
    assert " ".join(entry[:-1]) == "✔ confirmed (high) · 0s · run $0.04 of $10.00"
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
    from test_poc import RenderBrowser

    browser = RenderBrowser()
    browser.close = lambda: None
    monkeypatch.setattr(cli, "_proof_browser", lambda *args: (browser, "fake proof browser", None))
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
    assert done.endswith(" · run $0.50 of $10.00 · Agent's assessment: rejection alone is insufficient.")
    assert "$0.50 · run" not in done                                      # the running total only
    # The verdict cites no step: the image of its requests follows, named img, not proof (VER-035).
    assert rows[-1].split()[3] == "img" and "screenshot" in rows[-1]
    assert "Run        : " in out and "2 requests · $0.50 of $10.00" in out


@pytest.mark.parametrize("profile, show, done, run", [
    ("claude", False, None, "2 requests\n"),
    ("claude", True, "s · run $0.50 of $10.00 at API prices", "2 requests · $0.50 of $10.00 at API prices"),
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
        assert done + " · " in next(row for row in rows if row.split()[3:4] == ["done"])
    else:
        assert "$" not in "\n".join(rows)
    assert run in out


def test_the_grid_counts_findings_and_the_variants_of_one_share_its_number():
    """The grid shows the findings this run verifies: a finding's variants share its number, and it counts as
    done once its last variant is."""
    from dataclasses import replace

    out = io.StringIO()
    progress = RunProgress(out, clock=Clock(), env={})
    first = replace(_plan("T-1"), variant_id="v1")
    second = replace(_plan("T-1"), variant_id="v2")
    other = _plan("T-2")
    progress.begin([first, second, other])
    assert progress.total == 2
    progress.finding(first)
    progress.finished(first, ProbeResult(verdict="inconclusive", rationale="no proof"))
    assert progress.done == 0                                   # its other variant is still to come
    progress.finding(second, agent=False)
    progress.finished(second, ProbeResult(verdict="not-attempted", rationale="same request"))
    progress.finding(other)
    rows = [row for row in _rows(out) if " start " in row]
    assert [row.split()[1] for row in rows] == ["1/2", "1/2", "2/2"]
    assert progress.done == 1
