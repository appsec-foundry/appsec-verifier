"""In an interactive run the Verifier asks for a higher cost ceiling when the run reaches it; only an amount the
operator types raises it, every other answer keeps it, and no other limit is raised this way (VER-015)."""

from __future__ import annotations

import io
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from appsec_verifier import budget_prompt, cli
from appsec_verifier.budget_prompt import MAX_RAISES, CeilingPrompt, can_prompt, read_answer
from appsec_verifier.limits import LimitExceeded, Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.progress import RunProgress
from appsec_verifier.verify import ProbeRegistry, run_verification
from appsec_verifier.verify.probes import ProbeResult
from appsec_verifier.verify.report import to_markdown


class FakeProgress:
    def __init__(self):
        self.events = []

    @contextmanager
    def paused(self):
        self.events.append("paused")
        yield
        self.events.append("resumed")

    def raise_cost_limit(self, limit):
        self.events.append(("limit", limit))


def _prompt(*answers, progress=None, **kw):
    answers, written = list(answers), []
    prompt = CeilingPrompt(progress, write=written.append, read=lambda budget: answers.pop(0), **kw)
    return prompt, written, answers


def _budget(ceiling=10.0, prompt=None):
    budget = RunBudget(Limits(cost_limit_usd=ceiling))
    budget.ask_ceiling = prompt
    return budget


# ── the budget ────────────────────────────────────────────────────────────────

def test_a_higher_ceiling_the_operator_typed_lets_the_run_go_on():
    budget = _budget(10.0, lambda b: 25.0)
    budget.note_cost(6.0)
    budget.note_cost(6.0)                           # over 10: asked, raised, no stop
    assert budget.limits.cost_limit_usd == 25.0 and budget.ceiling_raises == [{"from": 10.0, "to": 25.0}]
    assert budget.remaining_cost() == 13.0
    assert budget.finding_cost_cap() == max(budget.limits.min_finding_cost_usd,
                                            25.0 * budget.limits.finding_cost_fraction)   # VER-051 follows it


@pytest.mark.parametrize("answer", [None, 10.0, 11.0])
def test_without_a_higher_amount_than_spent_the_run_stops_at_the_ceiling(answer):
    budget = _budget(10.0, lambda b: answer)
    budget.note_cost(6.0)
    with pytest.raises(LimitExceeded) as exc:
        budget.note_cost(6.0)                       # 12 spent: 11 does not cover it
    assert exc.value.kind == "cost" and budget.limits.cost_limit_usd == 10.0 and not budget.ceiling_raises


def test_without_a_question_the_ceiling_stops_the_run_and_the_last_call_before_it_is_refused():
    budget = _budget(1.0)
    budget.note_cost(1.0)                           # exactly at the ceiling
    with pytest.raises(LimitExceeded) as exc:
        budget.check_cost()
    assert exc.value.kind == "cost" and str(exc.value) == "cost ceiling reached"
    asked = []
    budget.ask_ceiling = lambda b: asked.append(b.cost) or 2.0
    budget.check_cost()                             # asked before the next call, which then may run
    assert asked == [1.0] and budget.limits.cost_limit_usd == 2.0


def test_a_cost_that_cannot_be_bounded_is_never_a_question():
    asked = []
    budget = _budget(10.0, lambda b: asked.append(1) or 50.0)
    with pytest.raises(LimitExceeded):
        budget.note_cost(float("nan"))
    with pytest.raises(LimitExceeded):
        budget.check_cost()
    assert not asked


def test_no_other_limit_is_raised_by_the_question():
    budget = RunBudget(Limits(cost_limit_usd=10.0, max_requests=1, max_calls=1))
    budget.ask_ceiling = lambda b: 50.0
    budget.note_request()
    budget.note_call()
    with pytest.raises(LimitExceeded) as requests:
        budget.note_request()
    with pytest.raises(LimitExceeded) as calls:
        budget.note_call()
    assert (requests.value.kind, calls.value.kind) == ("requests", "calls")


# ── the question ──────────────────────────────────────────────────────────────

def test_an_amount_above_the_spend_raises_the_ceiling_with_the_status_line_paused():
    progress = FakeProgress()
    prompt, written, _ = _prompt("25\n", progress=progress, api_prices=True)
    budget = _budget(10.0)
    budget.cost = 10.4
    assert prompt(budget) == 25.0
    assert progress.events == ["paused", ("limit", 25.0), "resumed"]
    text = "".join(written)
    assert "Cost limit reached: $10.40 of $10.00 at API prices used." in text
    assert "New total cost limit in USD (more than 10.40), or Enter to stop testing: " in text
    assert "Cost limit raised from $10.00 to $25.00 at API prices." in text


@pytest.mark.parametrize("answers, why", [
    (["\n"], ""),                                   # Enter keeps the ceiling
    ([""], ": the input ended"),
    ([None], ": the run time is up"),
    (["abc\n", "5\n", "1e3\n"], ""),                # three invalid answers, a lower amount among them
    (["9" * 130], ""),                              # too long to be an amount
])
def test_every_other_answer_keeps_the_ceiling_and_the_run_does_not_ask_again(answers, why):
    prompt, written, left = _prompt(*answers)
    budget = _budget(10.0)
    budget.cost = 10.4
    assert prompt(budget) is None and not left
    assert "".join(written).endswith(f"Cost limit stays at $10.00{why}; the run stops testing and does not ask "
                                     "again.\n\n")
    asked = len(written)
    assert prompt(budget) is None and len(written) == asked    # declined: no second question


def test_a_wrong_answer_is_asked_again_and_a_valid_one_then_counts():
    prompt, written, _ = _prompt("ten\n", "30.50\n")
    assert prompt(_budget(10.0)) == 30.5
    assert "Enter an amount in USD above 10.00, for example 20, or press Enter.\n" in written


def test_a_run_asks_at_most_max_raises_times():
    prompt, written, _ = _prompt()
    budget = _budget(10.0)
    budget.ceiling_raises = [{"from": 1.0, "to": 2.0}] * MAX_RAISES
    assert prompt(budget) is None and not written


def test_keys_typed_before_the_question_are_discarded_and_the_run_time_ends_the_wait(monkeypatch):
    import select
    import termios

    calls = []
    monkeypatch.setattr(termios, "tcflush", lambda stream, queue: calls.append(("flush", queue)))
    monkeypatch.setattr(select, "select", lambda r, w, x, timeout: calls.append("select") or (r, [], []))
    monkeypatch.setattr(sys, "stdin", io.StringIO("40\n"))
    assert read_answer(SimpleNamespace(remaining_time=lambda: 60.0)) == "40\n"
    assert calls == [("flush", termios.TCIFLUSH), "select"]
    calls.clear()
    assert read_answer(SimpleNamespace(remaining_time=lambda: 0.0)) is None
    assert calls == [("flush", termios.TCIFLUSH)]                  # nothing read once the run time is up


def test_only_an_interactive_run_on_a_terminal_asks(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr(sys, "stderr", Tty())
    assert can_prompt(True) and not can_prompt(False)
    monkeypatch.setattr(sys, "stderr", io.StringIO())             # the question would not be seen
    assert not can_prompt(True)


def test_the_status_line_stays_away_while_the_question_waits_and_the_new_limit_shows(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(RunProgress, "TICK_SECONDS", 3600)
    monkeypatch.setenv("COLUMNS", "160")
    plan = FindingPlan(id="T-1", cwe="CWE-639", severity="high", title="t", match_key="a.ts|CWE-639",
                       instance="a.ts:1", status="dynamic", cls="access-control", reason="r")
    out, spent = Tty(), [10.4]
    progress = RunProgress(out, env={}, spent=lambda: spent[0], cost_limit=10.0)
    progress.begin([plan])
    progress.finding(plan)
    with progress.paused():
        before = out.getvalue()
        progress.tick()
        assert out.getvalue() == before                             # no status line over the question
        progress.raise_cost_limit(25.0)
    progress.tick()
    plain = lambda: re.sub(r"\x1b\[[0-9;]*m", "", out.getvalue())     # noqa: E731
    assert "$10.40 of $25.00" in plain()
    progress.finished(plan, ProbeResult(verdict="inconclusive"))
    assert "run $10.40 of $25.00" in plain().splitlines()[-1]
    progress.close()


# ── the report and a whole run ───────────────────────────────────────────────

def test_the_report_records_each_raise():
    limits = Limits(cost_limit_usd=30.0)
    budget = RunBudget(limits)
    budget.ceiling_raises = [{"from": 10.0, "to": 20.0}, {"from": 20.0, "to": 30.0}]
    doc = run_verification(assessment_path=Path("a.yaml"), scope={"base_url": "https://app.example.com"},
                           scope_path=None, plans=[], limits=limits, identities=[], budget=budget,
                           registry=ProbeRegistry({}),
                           verifier_version="t", target_base="https://app.example.com", authorization={})
    assert doc["meta"]["limits"]["cost_limit_raises"] == budget.ceiling_raises
    assert "- **Cost limit:** raised during the run at the operator's request, $10.00 → $20.00 → $30.00" \
        in to_markdown(doc)
    jsonschema = pytest.importorskip("jsonschema")
    schema = yaml.safe_load((Path(__file__).resolve().parent.parent / "schemas" / "verification.schema.yaml")
                            .read_text())
    jsonschema.validate(doc, schema)
    unraised = run_verification(assessment_path=Path("a.yaml"), scope={"base_url": "https://app.example.com"},
                                scope_path=None, plans=[], limits=Limits(), identities=[],
                                registry=ProbeRegistry({}), verifier_version="t",
                                target_base="https://app.example.com", authorization={})
    assert "cost_limit_raises" not in unraised["meta"]["limits"] and "Cost limit" not in to_markdown(unraised)


def _verify(tmp_path, monkeypatch, *answers):
    """One interactive `verify` run of two findings whose fake planner spends USD 0.30 per step under a USD 1
    ceiling: each finding stays under its own cap (VER-051), the second one reaches the run's ceiling."""
    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(scope))
    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": f"T-{n}", "cwe": "CWE-639", "severity": "high", "title": "idor", "scenario": f"GET /rest/basket/{n}",
         "evidence": {"file": "routes/basket.ts", "line": n}} for n in (1, 2)]}))

    class Planner:
        def next_step(self, ctx, history):
            ctx.budget.note_cost(0.30)
            if not history:
                return {"tool": "http_request", "args": {"path": "/rest/basket/2"}}
            return {"verdict": {"verdict": "inconclusive", "rationale": "rejection alone is insufficient"}}

    def transport(method, url, headers, **k):
        return SimpleNamespace(status_code=403, headers={}, text="no", content=b"no", url=url)

    from appsec_verifier.tools import httpx_transport

    info = {"profile": "anthropic-api", "model": "m", "runtime": "Fake API 1.0", "runtime_name": "Fake API",
            "auth": "none", "api_billing": True}
    answers = list(answers)
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: transport)
    monkeypatch.setattr(budget_prompt, "can_prompt", lambda interactive: True)
    monkeypatch.setattr(budget_prompt, "read_answer", lambda budget: answers.pop(0))
    code = cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope",
                     str(tmp_path / "scope.yaml"), "--output", str(tmp_path / "out"), "--yes", "--test-all",
                     "--cost-limit", "1", "--screenshots", "none"])
    return code, yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text()), answers


def test_a_run_that_reaches_its_ceiling_goes_on_after_a_raise(tmp_path, monkeypatch, capsys):
    code, doc, left = _verify(tmp_path, monkeypatch, "2\n")
    assert code == cli.EXIT_OK and not left
    assert doc["meta"]["limits"]["cost_limit_usd"] == 2.0
    assert doc["meta"]["limits"]["cost_limit_raises"] == [{"from": 1.0, "to": 2.0}]
    assert [r["verdict"] for r in doc["results"]] == ["inconclusive", "inconclusive"]
    assert not any(r.get("limits_hit") for r in doc["results"])
    assert "Cost limit raised from $1.00 to $2.00." in capsys.readouterr().err


def test_a_run_whose_ceiling_is_kept_stops_with_the_limit_exit(tmp_path, monkeypatch, capsys):
    code, doc, left = _verify(tmp_path, monkeypatch, "\n")
    assert code == cli.EXIT_LIMIT and not left
    assert [r.get("limits_hit") for r in doc["results"]] == [None, "cost"]
    assert "cost_limit_raises" not in doc["meta"]["limits"] and doc["meta"]["limits"]["cost_limit_usd"] == 1.0
    assert "Cost limit stays at $1.00; the run stops testing" in capsys.readouterr().err
