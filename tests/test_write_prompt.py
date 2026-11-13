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

    return WritePrompt(write=shown.append, read=read, wait=7), shown


def _ask(prompt, key="T-1", **kw):
    return prompt(BUDGET, key=key, finding="T-1 · sqli in login", requests=["POST /rest/user/login"], **kw)


# ── the question ──────────────────────────────────────────────────────────────


def test_y_allows_writes_for_the_finding_and_says_what_stays_on_the_target():
    prompt, shown = _prompt("y\n")
    assert _ask(prompt) is True
    text = "".join(s for s in shown if isinstance(s, str))
    assert ("T-1 · sqli in login: the test agent asks for write requests, which this run does not send in safe "
            "mode:") in text
    assert "  POST /rest/user/login\n" in text
    assert "Identity: without login\n" in text                   # the request's own identity, never a list
    assert "anything it creates stays on the target and is not cleaned up" in text
    assert "Allow writes for this finding (y), for the rest of the run (a), or not (Enter)? " in text
    assert "Writes allowed for this finding." in text
    assert ("read", 7) in shown                                  # the answer is awaited for a bounded time
    record = prompt.records["T-1"]
    assert (record["allowed"], record["answer"], record["asked"]) == (True, "finding", "by the test agent")
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


@pytest.mark.parametrize("change", [None, {"method": "PUT", "path": "/rest/basket/{id}"}])
def test_the_resource_an_access_control_proof_creates_is_refused_in_safe_mode_without_asking(tmp_path, change):
    """The record an account creates for the comparison (VER-010) was known before the run: --allow-intrusive
    decides it, not a question mid-run, whether the operator could be asked or not."""
    plan = {**_OWNER_PLAN, **({"change": change} if change else {})}
    for asking in (False, True):
        tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp(), idents=_TWO))
        asked = _asking(tools, True) if asking else []
        with pytest.raises(ToolError, match="creating a resource needs two normal accounts and --allow-intrusive"):
            tools.plan_test(**plan)
        assert asked == [] and tools.ctx.safe and getattr(tools, "_experiment", None) is None
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp(), idents=_TWO, safe=False, read_only=False))
    assert tools.plan_test(**plan)["accepted"] is True


_WRITE_PLAN = {"kind": "boolean", "hypothesis": "email is spliced into the login SQL query", "strategy": STRATEGY,
               "path": "/rest/user/login", "method": "POST", "input_location": "json", "input_name": "email",
               "baseline": "nobody@x", "pointer": "/authentication/token", "sql_template": "x' OR {{predicate}} -- "}


def test_a_plan_that_needs_writes_is_accepted_only_after_the_operator_allows_them(tmp_path):
    def tools_for_injection():
        tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp()))
        tools.ctx.plan.cls, tools.ctx.plan.cwe = "injection", "CWE-89"
        return tools

    tools = tools_for_injection()
    asked = _asking(tools, False)
    with pytest.raises(ToolError, match="the operator did not allow them for this finding"):
        tools.plan_test(**_WRITE_PLAN)
    assert asked[0][0] == ["POST /rest/user/login, each control twice"]
    assert getattr(tools, "_experiment", None) is None and tools.ctx.safe
    tools = tools_for_injection()
    _asking(tools, True)
    accepted = tools.plan_test(**_WRITE_PLAN)
    assert accepted["accepted"] is True and "the operator allowed write requests" in accepted["note"]
    assert not tools.ctx.safe


def test_a_write_the_variant_declares_is_refused_without_asking(tmp_path):
    """The write a variant lists was known before the run: --allow-intrusive decides it, not a question mid-run.
    Here a read that triggers what a write stored, as for stored code evaluation."""
    from dataclasses import replace

    from appsec_verifier.agent.prompts import _seed

    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp()))
    stored = {"id": "v", "hypothesis": "A stored name is evaluated", "required_capabilities": ["state-change"],
              "request": {"method": "GET", "path": "/profile"}}
    tools.ctx.plan = replace(tools.ctx.plan, cls="injection", cwe="CWE-95",
                             verification_context={"version": 1, "variants": [stored]}, variant_id="v")
    asked = _asking(tools, True)
    assert '"unavailable": ["state-change"]' in _seed(tools.ctx)
    with pytest.raises(ToolError, match="unavailable capabilities: state-change"):
        tools.plan_test(kind="boolean", hypothesis="The stored name is evaluated", variant="v", path="/profile",
                        method="GET", input_location="params", input_name="q", baseline="a", positive="b",
                        negative="c", pointer="/data")
    assert asked == [] and tools.ctx.safe and getattr(tools, "_experiment", None) is None


_NAMED_WRITE = {"id": "variant-001", "hypothesis": "id is concatenated into the UPDATE",
                "request": {"method": "POST", "path": "/rest/basket/{id}", "inputs": [{"location": "json",
                                                                                         "name": "id"}]}}


def _naming(source):
    """The plan or scope fields by which a finding names POST /rest/basket/{id} before the run."""
    from appsec_verifier.endpoints import Endpoint

    write = (Endpoint("POST", "/rest/basket/{id}", None),)
    return {
        "variant": ({"verification_context": {"version": 1, "variants": [_NAMED_WRITE]},
                     "variant_id": "variant-001"}, {}),
        "assessment request": ({"endpoints": write}, {}),
        "assessment request for any method": ({"endpoints": (Endpoint("ALL", "/rest/basket/{id}", None),)}, {}),
        "preparation": ({"preparation": write}, {}),
        "scope injection input": ({}, {"injection_inputs": [{"finding_id": "T-1", "path": "/rest/basket/{id}",
                                                             "input_location": "json", "input_name": "id",
                                                             "semantics": "literal"}]}),
        "scope test resource": ({}, {"test_resources": [{"id": "r", "finding_id": "T-1", "path": "/rest/basket/{id}",
                                                         "method": "POST", "allowed_roles": ["customer-a"],
                                                         "denied_roles": [], "pointer": "/id", "value": "1"}]}),
    }[source]


@pytest.mark.parametrize("source", ["variant", "assessment request", "assessment request for any method",
                                    "preparation", "scope injection input", "scope test resource"])
def test_a_write_the_finding_names_before_the_run_is_refused_without_asking(tmp_path, source):
    """Refused case, as in a DVWA run: the agent sent its variant's own POST "to test operator write permission"
    and the operator was asked mid-run. The test plan showed that write, so --allow-intrusive decides it; only a
    write the agent comes upon while testing is put to the operator."""
    from dataclasses import replace

    plan_fields, scope_fields = _naming(source)
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: sent.append(a) or Resp()))
    tools.ctx.plan = replace(tools.ctx.plan, **plan_fields)
    tools.ctx.scope = {**tools.ctx.scope, **scope_fields}
    asked = _asking(tools, False)
    with pytest.raises(ToolError, match="before the run, so --allow-intrusive decides it and the operator is not "
                                        "asked"):
        tools.http_request(role="customer-a", method="POST", path="/rest/basket/7", json={"id": "vrf1"})
    assert asked == [] and sent == [] and tools.ctx.safe
    with pytest.raises(ToolError, match="the operator did not allow write requests"):
        tools.http_request(role="customer-a", method="POST", path="/rest/coupon", json={"c": "vrf1"})
    assert asked == [(["POST /rest/coupon"], None, "customer-a")] and sent == []    # an unforeseen write is asked


def test_a_write_the_finding_names_is_sent_once_the_run_allows_writes(tmp_path):
    """The rule decides only whether to ask: with --allow-intrusive, or after a yes, the named write is sent."""
    from dataclasses import replace

    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append((m, u)) or Resp(), safe=False,
                            read_only=False))
    tools.ctx.plan = replace(tools.ctx.plan, **_naming("variant")[0])
    assert tools.http_request(role="customer-a", method="POST", path="/rest/basket/7", json={"id": "vrf1"})[
        "status"] == 200
    assert sent == [("POST", "https://app.example.com/rest/basket/7")]


def test_a_plan_on_a_write_the_assessment_names_is_refused_without_asking(tmp_path):
    """Refused case: a plan whose write the finding names before the run is not put to the operator either."""
    from dataclasses import replace

    from appsec_verifier.endpoints import Endpoint

    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp()))
    tools.ctx.plan = replace(tools.ctx.plan, cls="injection", cwe="CWE-89",
                             endpoints=(Endpoint("POST", "/rest/user/login", None),))
    asked = _asking(tools, True)
    with pytest.raises(ToolError, match="a write needs --allow-intrusive"):
        tools.plan_test(**_WRITE_PLAN)
    assert asked == [] and tools.ctx.safe and getattr(tools, "_experiment", None) is None


# ── in a run (cli.py, verify/runner.py) ──────────────────────────────────────

_SAFE_MODE_ONLY = ("not-attempted", "not tested: safe mode; every request the finding names writes, and the proof "
                   "sends each control twice")


def _verify_asking(tmp_path, monkeypatch, answer, *extra, scope=None, agent_asks=None):
    """test_endpoints' run, in a terminal: T-1 names a read, T-2 only a POST, so safe mode alone keeps T-2 from
    being tested. The test agent of `agent_asks` asks for a write when its finding starts. Returns the run's
    outcome, how often the operator was asked, and per finding started its mode and whether its agent may ask."""
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
            seen.append((p.id, ctx.safe, ctx.read_only, ctx.ask_writes is not None))
            if p.id == agent_asks and ctx.ask_writes is not None:
                ctx.ask_writes(["POST /rest/products/search"], "the search also takes a POST", "")
            return ctx

        return original(plan, registry, factory, log)

    monkeypatch.setattr(runner, "_verify_one", seeing)
    rc, asked, sent, results = test_endpoints._verify(tmp_path, monkeypatch, *extra)
    return rc, results, reads, seen


def test_a_finding_whose_requests_all_write_is_not_asked_about_and_stays_untested(tmp_path, monkeypatch, capsys):
    """VER-052: only the test agent asks, during a test; --allow-intrusive tests such a finding."""
    import yaml

    rc, results, reads, seen = _verify_asking(tmp_path, monkeypatch, "y\n")
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK and reads == []
    assert "T-2 → run with --allow-intrusive" in out and "asks" not in out
    assert results["T-2"] == _SAFE_MODE_ONLY
    assert [s for s in seen if s[0] == "T-2"] == []                  # no agent started for it
    assert ("T-1", True, True, True) in seen                         # the agent of a read finding may ask
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert all("write_permission" not in r for r in report["results"])
    assert "writes_allowed_for" not in report["meta"]["safety"]


@pytest.mark.parametrize("answer, allowed", [("y\n", True), ("\n", False)])
def test_the_report_gives_the_answer_to_the_test_agent_s_question(tmp_path, monkeypatch, answer, allowed):
    import yaml

    rc, results, reads, seen = _verify_asking(tmp_path, monkeypatch, answer, agent_asks="T-1")
    assert len(reads) == 1
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    entry = next(r for r in report["results"] if r["finding_ref"]["id"] == "T-1")
    assert (entry["write_permission"]["allowed"], entry["write_permission"]["asked"]) == (allowed, "by the test agent")
    assert entry["write_permission"]["requests"] == ["POST /rest/products/search"]
    md = (tmp_path / "out" / "verification.md").read_text()
    if allowed:
        assert report["meta"]["safety"]["writes_allowed_for"] == ["T-1"]
        assert report["meta"]["safety"]["state_changes_cleaned"] is False
        assert "the operator allowed writes for T-1" in md
    else:
        assert "writes_allowed_for" not in report["meta"]["safety"]
        assert "the operator allowed writes" not in md


@pytest.mark.parametrize("extra, scope", [
    (("--read-only",), None),                          # an explicit no on the command line
    ((), {"allow_state_change": False}),               # an explicit no in the scope file
    (("--non-interactive",), None),                    # nobody to ask
])
def test_nothing_is_asked_where_writes_are_forbidden_or_nobody_can_answer(tmp_path, monkeypatch, extra, scope):
    rc, results, reads, seen = _verify_asking(tmp_path, monkeypatch, "y\n", *extra, scope=scope, agent_asks="T-1")
    assert reads == [] and all(s[0] != "T-2" for s in seen)
    assert [s for s in seen if s[0] == "T-1"] == [("T-1", True, True, False)]    # its agent cannot ask
    assert results["T-2"] == _SAFE_MODE_ONLY


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

    _verify_asking(tmp_path, monkeypatch, "y\n", agent_asks="T-1")
    schema = yaml.safe_load((Path(__file__).resolve().parent.parent / "schemas" / "verification.schema.yaml")
                            .read_text())
    doc = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert not sorted(e.message for e in validator_for(schema)(schema).iter_errors(doc))


# ── a write the run refused during the test (VER-052) ────────────────────────


def test_a_refused_write_is_kept_for_the_finding_and_the_agent_told_how_to_end_it(tmp_path):
    """Refused for the mode, with nobody to ask or after a no, a write is kept and the refusal says how to end."""
    tools = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp()))
    with pytest.raises(ToolError, match="tested only with this write, submit_verdict not-attempted"):
        tools.http_request(role="customer-a", method="POST", path="/rest/basket?x=1", json={"x": "vrf1"})
    _asking(tools, False)
    with pytest.raises(ToolError, match="did not allow write requests.*submit_verdict not-attempted"):
        tools.http_request(role="customer-a", method="PUT", path="/rest/basket/2", json={"x": "vrf1"})
    assert tools.ctx.refused_writes == ["POST /rest/basket", "PUT /rest/basket/2"]
    forbidden = AgentTools(_ctx(tmp_path, lambda *a, **k: Resp()))
    forbidden.ctx.scope = {**forbidden.ctx.scope, "allow_state_change": False}   # --allow-intrusive would not help
    with pytest.raises(ToolError):
        forbidden.http_request(role="customer-a", method="POST", path="/rest/basket", json={"x": "vrf1"})
    assert not getattr(forbidden.ctx, "refused_writes", None)


def test_a_finding_that_needs_a_refused_write_ends_not_tested_in_this_mode(tmp_path):
    """The agent's not-attempted after a refused write is the run's 'needs intrusive mode', naming the write; any
    other verdict, or one without a refused write, stays as it is."""
    from test_agent_probe import ScriptedPlanner

    from appsec_verifier.agent.loop import AgentProbe

    def run(*actions):
        ctx = _ctx(tmp_path, lambda *a, **k: Resp())
        return AgentProbe("access-control", lambda: ScriptedPlanner(list(actions))).run(ctx)

    write = {"tool": "http_request", "args": {"role": "customer-a", "method": "PUT", "path": "/rest/basket/2",
                                               "json": {"name": "vrf1"}}}
    result = run(write, {"verdict": {"verdict": "not-attempted", "rationale": "the stored name needs this PUT"}})
    assert result.verdict == "not-attempted" and result.limits_hit == "safe-mode"
    assert result.rationale == ("not tested: safe mode; the finding needs PUT /rest/basket/2, which this run does "
                                "not send; run with --allow-intrusive to test it")
    assert run(write, {"verdict": {"verdict": "inconclusive", "rationale": "partly seen"}}).limits_hit is None
    assert run({"verdict": {"verdict": "not-attempted", "rationale": "nothing to read"}}).limits_hit is None


def test_the_console_and_the_report_list_it_under_intrusive_mode():
    from appsec_verifier.verify.report import _not_tested

    rationale = ("not tested: safe mode; the finding needs PUT /rest/basket/2, which this run does not send; run "
                 "with --allow-intrusive to test it")
    assert _not_tested(rationale) == "needs --allow-intrusive: its test needs PUT /rest/basket/2"
    assert _not_tested("not tested: safe mode; every declared variant needs a state change") == (
        "needs --allow-intrusive: every request it names writes")
    plan = SimpleNamespace(id="T-1", severity="high")
    doc = {"results": [{"finding_ref": {"id": "T-1", "title": "stored xss"}, "verdict": "not-attempted",
                        "class": "xss", "rationale": rationale, "limits_hit": "safe-mode",
                        "eligibility": {"status": "dynamic"}}]}
    lines = "\n".join(cli._results(cli.Style(False), doc, [plan], {}))
    assert "needs intrusive mode" in lines and "run with --allow-intrusive" in lines


def test_an_interactive_run_derives_a_write_so_the_operator_can_be_asked(tmp_path):
    """VER-052: with someone to ask, derive_request accepts a write intrusive mode would send; sending it still
    needs the operator's yes. Without anyone to ask it is refused and kept for the report."""
    from test_request_derivation import page_script

    def setup(asking):
        ctx = page_script(tmp_path)
        ctx.agent_history = [{"tool": "read_source", "args": {"path": "vulnerabilities/sqli/source/low.php"},
                              "result": {"text": "Route::post('/vulnerabilities/sqli/save', fn() => $_POST['id']);",
                                         "start_line": 1}}]
        ctx.ask_writes = (lambda *a, **k: False) if asking else None
        return ctx

    args = {"evidence_step": 1, "method": "POST", "path": "/vulnerabilities/sqli/save",
            "inputs": [{"location": "form", "name": "id"}], "reason": "the source declares the write"}
    refused = setup(False)
    with pytest.raises(ToolError, match="derived writes need intrusive mode.*submit_verdict not-attempted"):
        AgentTools(refused).derive_request(**args)
    assert refused.refused_writes == ["POST /vulnerabilities/sqli/save"]
    assert AgentTools(setup(True)).derive_request(**args)["accepted"] is True
