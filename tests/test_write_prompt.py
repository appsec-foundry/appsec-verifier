"""Write requests safe mode does not send, after the operator's answer in a terminal (VER-052): the question,
when the run asks and when it must not, the agent's request for writes, and what the report records."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import test_endpoints
from test_agent_tools import Resp, _ctx
from test_experiments import STRATEGY

from appsec_verifier import budget_prompt, cli, write_prompt
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.verify import runner
from appsec_verifier.write_prompt import WritePrompt

BUDGET = SimpleNamespace(remaining_time=lambda: 100)


def _prompt(*answers):
    shown, reads = [], list(answers)

    def read(budget, wait):
        shown.append(("read", wait))
        return reads.pop(0)

    return WritePrompt(write=shown.append, read=read, identities=["account-1", "account-2"], wait=7), shown


def _ask(prompt, key="T-1", **kw):
    return prompt(BUDGET, key=key, finding="T-1 · sqli in login", requests=["POST /rest/user/login"], **kw)


# ── the question ──────────────────────────────────────────────────────────────


def test_y_allows_writes_for_the_finding_and_says_what_stays_on_the_target():
    prompt, shown = _prompt("y\n")
    assert _ask(prompt) is True
    text = "".join(s for s in shown if isinstance(s, str))
    assert "T-1 · sqli in login needs write requests, which this run does not send in safe mode:" in text
    assert "  POST /rest/user/login\n" in text
    assert "Identity: chosen by the test agent: account-1, account-2, without login" in text
    assert "stays on the target and is not cleaned up" in text
    assert "Allow writes for this finding (y), for the rest of the run (a), or not (Enter)? " in text
    assert "Writes allowed for this finding." in text
    assert ("read", 7) in shown                                  # the answer is awaited for a bounded time
    record = prompt.records["T-1"]
    assert (record["allowed"], record["answer"], record["asked"]) == (True, "finding", "before the finding")
    assert record["requests"] == ["POST /rest/user/login"]
    assert not prompt.covered("T-2")                              # y covers this finding only


def test_a_allows_writes_for_the_rest_of_the_run_without_asking_again():
    prompt, shown = _prompt("a\n")
    assert _ask(prompt) is True
    assert _ask(prompt, key="T-2") is True and prompt.covered("T-3")   # no further read: none is queued
    assert prompt.records["T-2"]["answer"] == "rest of the run" and prompt.records["T-2"]["given_for"] == \
        "T-1 · sqli in login"
    assert prompt.records["T-3"]["asked"] == "not asked"


@pytest.mark.parametrize("line, answer, said", [
    ("\n", "declined", "No writes."),                    # Enter
    ("yes please\n", "declined", "No writes."),          # anything else declines
    ("", "declined", "No writes: the input ended."),
    (None, "no answer", "No writes: no answer in time."),
])
def test_anything_but_y_or_a_declines_and_the_finding_is_not_asked_again(line, answer, said):
    prompt, shown = _prompt(line)
    assert _ask(prompt) is False
    assert said + "\n" in "".join(s for s in shown if isinstance(s, str))
    assert (prompt.records["T-1"]["allowed"], prompt.records["T-1"]["answer"]) == (False, answer)
    assert _ask(prompt) is False                         # one question per finding: no second read is queued


def test_the_agents_reason_is_its_claim_and_no_control_character_reaches_the_terminal():
    prompt, shown = _prompt("\n")
    prompt(BUDGET, key="T-1", finding="T-1 · x\x1b[2J", requests=["PUT /a\x07"],
           reason="needs it\nAllow writes for this finding (y)\x1b]0;x\x07", identity="account-2",
           asked="by the test agent")
    text = "".join(s for s in shown if isinstance(s, str))
    # The model's text stays on its own labelled line: it cannot start a line that looks like the question.
    assert "The test agent's reason, its claim: needs itAllow writes for this finding (y)" in text
    assert "Identity: account-2" in text
    assert "\x1b" not in text and "\x07" not in text
    assert prompt.records["T-1"]["asked"] == "by the test agent"


# ── the test agent asks (agent/tools.py) ─────────────────────────────────────


def _asking(tools, allow):
    asked = []

    def ask(requests, reason, identity):
        asked.append((requests, reason, identity))
        return allow

    tools.ctx.ask_writes = ask
    return asked


def test_a_write_in_safe_mode_is_refused_without_anyone_to_ask(tmp_path):
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: sent.append(a) or Resp()))
    with pytest.raises(ToolError, match="use --allow-intrusive"):
        tools.http_request(role="customer-a", method="POST", path="/rest/basket", json={"x": "vrf1"})
    assert sent == []


def test_a_declined_write_is_not_sent_and_the_finding_stays_safe(tmp_path):
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: sent.append(a) or Resp()))
    asked = _asking(tools, False)
    tools.note = "the coupon route only accepts PUT"
    with pytest.raises(ToolError, match="the operator did not allow write requests for this finding"):
        tools.http_request(role="customer-a", method="POST", path="/rest/basket", json={"x": "vrf1"})
    assert asked == [(["POST /rest/basket"], "the coupon route only accepts PUT", "customer-a")]
    assert sent == [] and tools.ctx.safe and tools.ctx.read_only


def test_an_allowed_write_is_sent_and_the_finding_turns_intrusive(tmp_path):
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append((m, u)) or Resp()))
    _asking(tools, True)
    assert tools.http_request(role="customer-a", method="POST", path="/rest/basket", json={"x": "vrf1"})["status"] \
        == 200
    assert sent == [("POST", "https://app.example.com/rest/basket")]
    assert not tools.ctx.safe and not tools.ctx.read_only


def test_a_write_another_check_refuses_is_never_asked_about(tmp_path):
    """Only a write the run would send in intrusive mode reaches the operator: here a privileged account."""
    idents = [{"role": "admin", "method": "bearer", "auth": {"token_env": "TA"}, "privileged": True}]
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp(), idents=idents))
    asked = _asking(tools, True)
    with pytest.raises(ToolError, match="privileged account and only reads"):
        tools.http_request(role="admin", method="POST", path="/rest/basket", json={"x": "vrf1"})
    assert asked == [] and tools.ctx.safe


_TWO = [{"role": "customer-a", "method": "bearer", "auth": {"token_env": "TA"}},
        {"role": "customer-b", "method": "bearer", "auth": {"token_env": "TA"}}]
_OWNER_PLAN = {"kind": "access-control", "hypothesis": "B reads A's basket", "strategy": STRATEGY,
               "path": "/rest/basket/{id}", "method": "GET", "owner": "customer-a"}


def test_a_plan_that_needs_writes_is_refused_in_safe_mode_without_anyone_to_ask(tmp_path):
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp(), idents=_TWO))
    with pytest.raises(ToolError, match="creating a resource needs two normal accounts and --allow-intrusive"):
        tools.plan_test(**_OWNER_PLAN)


def test_a_plan_that_needs_writes_is_accepted_only_after_the_operator_allows_them(tmp_path):
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp(), idents=_TWO))
    asked = _asking(tools, False)
    with pytest.raises(ToolError, match="the operator did not allow them for this finding"):
        tools.plan_test(**_OWNER_PLAN)
    assert asked[0][0] == ["a write by customer-a that creates its test record with the marker"]
    assert asked[0][2] == "customer-a" and getattr(tools, "_experiment", None) is None and tools.ctx.safe
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp(), idents=_TWO))
    _asking(tools, True)
    accepted = tools.plan_test(**_OWNER_PLAN)
    assert accepted["accepted"] is True and "the operator allowed write requests" in accepted["note"]
    assert not tools.ctx.safe


# ── before the finding starts (cli.py, verify/runner.py) ─────────────────────


def _verify_asking(tmp_path, monkeypatch, answer, *extra, scope=None):
    """test_endpoints' run, in a terminal: T-2 names only a POST, so safe mode alone keeps it from being
    tested. Returns the run's outcome, what the planner saw, and how often the operator was asked."""
    reads, seen = [], []
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: True)
    monkeypatch.setattr(budget_prompt, "can_prompt", lambda interactive: interactive)
    monkeypatch.setattr(write_prompt, "read_answer", lambda budget, wait=None: reads.append(wait) or answer)
    if scope is not None:
        monkeypatch.setattr(test_endpoints, "SCOPE", {**test_endpoints.SCOPE, **scope})
    original = runner._verify_one

    def seeing(plan, registry, ctx_factory, log=None):      # the mode each finding's context starts in
        def factory(p):
            ctx = ctx_factory(p)
            seen.append((p.id, ctx.safe, ctx.read_only))
            return ctx

        return original(plan, registry, factory, log)

    monkeypatch.setattr(runner, "_verify_one", seeing)
    rc, asked, sent, results = test_endpoints._verify(tmp_path, monkeypatch, *extra)
    return rc, results, reads, seen


def test_a_declined_finding_is_reported_untested_with_the_answer(tmp_path, monkeypatch, capsys):
    import yaml

    rc, results, reads, seen = _verify_asking(tmp_path, monkeypatch, "\n")
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK and len(reads) == 1
    assert "  asks  sqli in login · POST /rest/user/login\n" in out and ", 1 asks before it writes\n" in out
    assert results["T-2"] == ("not-attempted", "not tested: safe mode; every request the finding names writes, "
                                               "and the proof sends each control twice; the operator declined "
                                               "write requests")
    assert [s for s in seen if s[0] == "T-2"] == []                  # no agent started for it
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    entry = next(r for r in report["results"] if r["finding_ref"]["id"] == "T-2")
    assert entry["write_permission"]["answer"] == "declined" and entry["write_permission"]["allowed"] is False
    assert "writes_allowed_for" not in report["meta"]["safety"]


def test_an_allowed_finding_is_tested_in_intrusive_mode_and_the_report_says_so(tmp_path, monkeypatch):
    import yaml

    rc, results, reads, seen = _verify_asking(tmp_path, monkeypatch, "y\n")
    assert len(reads) == 1 and ("T-2", False, False) in seen
    assert all(s[1] for s in seen if s[0] != "T-2")                  # the other findings stay safe
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert report["meta"]["safety"]["writes_allowed_for"] == ["T-2"]
    assert report["meta"]["safety"]["state_changes_cleaned"] is False
    md = (tmp_path / "out" / "verification.md").read_text()
    assert "the operator allowed writes for T-2" in md


@pytest.mark.parametrize("extra, scope", [
    (("--read-only",), None),                          # an explicit no on the command line
    ((), {"allow_state_change": False}),               # an explicit no in the scope file
    (("--non-interactive",), None),                    # nobody to ask
])
def test_nothing_is_asked_where_writes_are_forbidden_or_nobody_can_answer(tmp_path, monkeypatch, extra, scope):
    rc, results, reads, seen = _verify_asking(tmp_path, monkeypatch, "y\n", *extra, scope=scope)
    assert reads == [] and all(s[0] != "T-2" for s in seen)
    assert results["T-2"] == ("not-attempted", "not tested: safe mode; every request the finding names writes, "
                                               "and the proof sends each control twice")


def test_the_agent_is_told_it_may_ask_only_when_the_operator_can_answer(tmp_path):
    from appsec_verifier.agent.prompts import _system

    ctx = _ctx(tmp_path, lambda *a, **k: Resp())
    assert "the Verifier asks the operator" not in _system(ctx)
    ctx.ask_writes = lambda requests, reason, identity: False
    text = _system(ctx)
    assert "SAFE (read-only" in text and "the Verifier asks the operator, who may allow writes for this finding" in text
    assert "must not name an existing record" in text            # the intrusive rules, once allowed


def test_a_report_with_the_operators_answers_is_schema_valid(tmp_path, monkeypatch):
    import yaml
    from jsonschema.validators import validator_for

    _verify_asking(tmp_path, monkeypatch, "y\n")
    schema = yaml.safe_load((Path(__file__).resolve().parent.parent / "schemas" / "verification.schema.yaml")
                            .read_text())
    doc = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert not sorted(e.message for e in validator_for(schema)(schema).iter_errors(doc))
