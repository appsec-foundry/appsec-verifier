"""Controller boundaries, progress and deadlines, with no live hosts (VER-036)."""

from __future__ import annotations

import signal
import time
from dataclasses import replace

import pytest
from test_agent_tools import Resp, _ctx
from test_experiments import STRATEGY

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.limits import LimitExceeded, Limits, RunBudget, execution_deadline
from appsec_verifier.tools import GuardedHttpClient


def context(tmp_path, transport=lambda *a, **k: Resp()):
    ctx = _ctx(tmp_path, transport)
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("GET", "/search", None),))
    return ctx


def test_repeat_errors_stop_before_third_execution(tmp_path):
    ctx = context(tmp_path)
    calls = []

    class Planner:
        def next_step(self, ctx, history):
            calls.append(1)
            return {"tool": "read_source", "args": {"path": "missing.py"}}

    logs = []
    ctx.log = logs.append
    result = AgentProbe(ctx.plan.cls, Planner).run(ctx)
    assert result.verdict == "inconclusive" and result.limits_hit == "stagnation"
    assert len(calls) == 3
    assert sum(bool(r.get("result", {}).get("error")) for r in logs) == 2


def test_three_distinct_failures_stop_before_next_model_call(tmp_path):
    ctx = context(tmp_path)
    calls = []

    class Planner:
        def next_step(self, ctx, history):
            calls.append(1)
            return {"tool": "read_source", "args": {"path": f"missing{len(calls)}.py"}}

    result = AgentProbe(ctx.plan.cls, Planner).run(ctx)
    assert result.limits_hit == "stagnation" and len(calls) == 3


def test_plan_cannot_authorize_other_route(tmp_path):
    c = Controller(context(tmp_path))
    with pytest.raises(ToolError, match="no matching route"):
        c.before("plan_test", {"path": "/unrelated"})
    c.before("http_request", {"path": "/search"})  # bounded diagnostics before a plan
    c.plan = {"path": "/search"}
    with pytest.raises(ToolError):
        c.before("http_request", {"path": "/unrelated"})


def test_missing_route_never_guessed(tmp_path):
    ctx = context(tmp_path)
    ctx.plan.endpoints = ()
    with pytest.raises(ToolError, match="no matching route"):
        Controller(ctx).before("http_request", {"path": "/search"})


def test_control_repetitions_allowed_but_rewording_does_not_reset(tmp_path):
    c = Controller(context(tmp_path))
    for _ in range(2):
        c.before("http_request", {"path": "/search"})
        c.observe("http_request", {}, {"status": 200})
    c.observe("plan_test", {}, {"accepted": True, "experiment": {"path": "/search"}})
    with pytest.raises(LimitExceeded, match="repetition"):
        c.before("http_request", {"path": "/search", "method": "GET"})


def test_declared_variant_restricts_input_names(tmp_path):
    ctx = context(tmp_path)
    ctx.plan.verification_context = {"variants": [{"id": "v", "request": {
        "method": "GET", "path": "/search", "inputs": [{"location": "query", "name": "q"}]}}]}
    c = Controller(ctx)
    c.before("http_request", {"path": "/search?q=benign"})
    with pytest.raises(ToolError, match="inputs"):
        c.before("http_request", {"path": "/search?other=value"})


def test_revised_plan_text_alone_is_not_progress(tmp_path):
    c = Controller(context(tmp_path))
    for i in range(2):
        c.before("plan_test", {"path": "/search", "hypothesis": str(i), "strategy": STRATEGY})
    with pytest.raises(LimitExceeded):
        c.before("plan_test", {"path": "/search", "hypothesis": "new words", "strategy": {}})


def test_late_model_response_cannot_read_source(tmp_path):
    ctx = context(tmp_path)
    clock = [0.0]
    ctx.budget = RunBudget(Limits(max_duration_s=1), clock=lambda: clock[0])
    reads = []

    class Source:
        def read_window(self, *a, **k):
            reads.append(1)
            return {}

    class Planner:
        def next_step(self, ctx, history):
            clock[0] = 2
            return {"tool": "read_source", "args": {"path": "any.py"}}

    ctx.source = Source()
    result = AgentProbe(ctx.plan.cls, Planner).run(ctx)
    assert result.limits_hit == "time" and not reads


def test_http_receives_remaining_time_and_rejects_late_answer(tmp_path):
    ctx = context(tmp_path)
    clock = [0.0]
    budget = RunBudget(Limits(max_duration_s=1), clock=lambda: clock[0])
    seen = []

    def transport(*a, **kw):
        seen.append(kw["timeout"])
        clock[0] = 2
        return Resp()

    with pytest.raises(LimitExceeded):
        GuardedHttpClient(ctx.guard, budget, transport).request("GET", ctx.target_base)
    assert seen == [1.0]


def test_deadline_interrupts_operation_and_restores_signal():
    previous = signal.getsignal(signal.SIGALRM)
    completed = []
    with pytest.raises(LimitExceeded):
        with execution_deadline(0.02):
            try:
                time.sleep(0.5)
                completed.append(1)
            except Exception:
                pytest.fail("ordinary tool exception handler swallowed deadline")
    assert not completed and signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_nested_deadline_preserves_window_reason():
    with pytest.raises(LimitExceeded) as exc:
        with execution_deadline(0.02, kind="window"), execution_deadline(1):
            time.sleep(0.5)
    assert exc.value.kind == "window"


@pytest.mark.parametrize("cls,query", [
    ("ssrf", "url=http%3A%2F%2F169.254.169.254%2F"),
    ("path-traversal", "file=..%2F..%2Fetc%2Fpasswd"),
    ("ssrf", "url=http%3A%2F%2Fevil.invalid&url=benign"),
])
def test_query_markers_cannot_bypass_steering(tmp_path, cls, query):
    sent = []
    ctx = context(tmp_path, lambda *a, **k: sent.append(1) or Resp())
    ctx.plan.cls = cls
    with pytest.raises(ToolError):
        AgentTools(ctx).http_request(path="/search?" + query)
    assert not sent


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_write_is_not_retried_after_401(tmp_path, method):
    sent = []
    ctx = _ctx(tmp_path, lambda *a, **k: sent.append(1) or Resp(401), safe=False, read_only=False)
    result = AgentTools(ctx).http_request(path="/search", method=method, role="customer-a")
    assert result["status"] == 401 and len(sent) == 1


def test_source_read_cap_applies_before_decoding(tmp_path):
    from appsec_verifier.agent.source_reader import MAX_SOURCE_BYTES, SourceAccessError, SourceReader

    (tmp_path / "large.py").write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
    with pytest.raises(SourceAccessError, match="read limit"):
        SourceReader(tmp_path).read_window("large.py")


def test_reading_evidenced_literal_route_permits_targeted_diagnostic(tmp_path):
    ctx = context(tmp_path)
    ctx.plan.endpoints = ()
    c = Controller(ctx)
    c.observe("read_source", {"path": "unrelated.py"}, {"text": "get('/other', handler)"})
    with pytest.raises(ToolError):
        c.before("http_request", {"path": "/other"})
    c.observe("read_source", {"path": "routes/basket.ts"}, {"text": "get('/search', handler)"})
    c.before("http_request", {"path": "/search"})


def test_plan_binding_refuses_other_known_route_and_input(tmp_path):
    ctx = context(tmp_path)
    ctx.plan.endpoints += (Endpoint("GET", "/other", None),)
    c = Controller(ctx)
    c.plan = {"path": "/search", "kind": "boolean", "input_location": "params", "input_name": "q",
              "baseline": "plain", "positive": "true", "negative": "false"}
    c.before("http_request", {"path": "/search", "params": {"q": "plain"}})
    for args in ({"path": "/other"}, {"path": "/search", "params": {"unrelated": "plain"}},
                 {"path": "/search", "params": {"q": "undeclared"}}):
        with pytest.raises(ToolError):
            c.before("http_request", args)
    with pytest.raises(ToolError, match="duplicate"):
        c.before("http_request", {"path": "/search?q=undeclared&q=plain"})


def test_query_encoding_or_empty_defaults_do_not_buy_more_repetitions(tmp_path):
    c = Controller(context(tmp_path))
    c.before("http_request", {"path": "/search?q=a"})
    c.before("http_request", {"path": "/search?q=%61", "json": {}})
    with pytest.raises(LimitExceeded):
        c.before("http_request", {"path": "https://app.example.com/search", "params": {"q": "a"}})


def test_browser_fragment_route_cannot_be_changed(tmp_path):
    ctx = context(tmp_path)
    ctx.plan.endpoints = (Endpoint("PAGE", "/#/search", None),)
    c = Controller(ctx)
    c.before("browser_check", {"path": "/#/search?q=marker"})
    with pytest.raises(ToolError):
        c.before("browser_check", {"path": "/#/admin"})
    with pytest.raises(ToolError):
        c.before("http_request", {"path": "/#/search", "method": "POST"})


def test_absolute_path_cannot_escape_finding_base_prefix(tmp_path):
    ctx = context(tmp_path)
    ctx.target_base += "/shop"
    c = Controller(ctx)
    c.before("http_request", {"path": "/search"})
    c.before("http_request", {"path": "https://app.example.com/shop/search"})
    with pytest.raises(ToolError):
        c.before("http_request", {"path": "https://app.example.com/search"})


def test_ssrf_query_marker_is_replaced_and_observed(tmp_path):
    from test_agent_tools import FakeListener

    sent = []
    ctx = context(tmp_path, lambda m, u, h, **kw: sent.append(u) or Resp())
    ctx.plan.cls = "ssrf"
    ctx.marker = ("vrfa", "bc")
    ctx.listener = FakeListener(hit=True)
    result = AgentTools(ctx).http_request(path="/search?url=http%3A%2F%2Flocalhost%3A4444%2Fvrfabc")
    assert result["callback_hit"] and "vrfabc" not in sent[0]
    assert ctx.listener.waited == [result["callback_attempt"]]


def test_rate_wait_does_not_outlive_budget():
    clock = [0.0]

    def sleep(seconds):
        clock[0] += seconds

    budget = RunBudget(Limits(max_duration_s=1, rate_rps=0.001), clock=lambda: clock[0], sleep=sleep)
    budget.pace()
    with pytest.raises(LimitExceeded):
        budget.pace()
    assert clock[0] == 1


def test_cli_pipe_cap_is_enforced_while_reading(monkeypatch):
    """Use real local pipes, but no process or agent CLI is started."""
    import os
    import subprocess
    from types import SimpleNamespace

    from appsec_verifier.agent import hosts

    child_in, parent_in = os.pipe()
    parent_out, child_out = os.pipe()
    parent_err, child_err = os.pipe()
    proc = SimpleNamespace(stdin=os.fdopen(parent_in, "wb"), stdout=os.fdopen(parent_out, "rb"),
                           stderr=os.fdopen(parent_err, "rb"), args=["fake"], wait=lambda **kw: 0)
    try:
        os.write(child_out, b"x" * 101)
        monkeypatch.setattr(hosts, "MAX_OUTPUT_BYTES", 100)
        with pytest.raises(subprocess.SubprocessError, match="size limit"):
            hosts._communicate_bounded(proc, b"", 1)
    finally:
        for fd in (child_in, child_out, child_err):
            os.close(fd)


def test_deadline_and_error_cleanup_kill_the_cli_group(monkeypatch):
    from types import SimpleNamespace

    from appsec_verifier.agent import hosts

    proc = SimpleNamespace()
    killed = []
    monkeypatch.setattr(hosts.subprocess, "Popen", lambda *a, **kw: proc)
    monkeypatch.setattr(hosts, "_stop_group", lambda p: killed.append(p))

    def blocked(*args):
        time.sleep(0.5)

    monkeypatch.setattr(hosts, "_communicate_bounded", blocked)
    with pytest.raises(LimitExceeded), execution_deadline(0.02):
        hosts.run_process(["fake"], input="", cwd="/tmp", env={}, timeout=1)
    assert killed == [proc]


def test_model_call_deadline_counts_as_host_failure(tmp_path, monkeypatch):
    from appsec_verifier.agent import hosts

    class Host:
        label = "fake"
        broken = None

        def call(self, *args):
            time.sleep(0.5)

    monkeypatch.setattr(hosts, "CALL_TIMEOUT_S", 0.02)
    host = Host()
    for _ in range(3):
        result = hosts.HostPlanner(host).next_step(context(tmp_path), [])
        assert result["verdict"]["verdict"] == "inconclusive"
    assert host.failed_calls == 3 and host.broken


def test_batch_repetitions_keep_evidence_and_stop_before_extra_requests(tmp_path):
    sent = []
    ctx = context(tmp_path, lambda *a, **kw: sent.append(kw["params"]) or Resp())
    ctx.plan.cls, ctx.plan.cwe = "injection", "CWE-89"
    ctx.scope = {**ctx.scope, "injection_inputs": [{"finding_id": ctx.plan.id, "path": "/search",
                 "input_location": "params", "input_name": "q", "semantics": "literal"}]}
    actions = iter([
        {"tool": "plan_test", "args": {"kind": "boolean", "hypothesis": "Test the declared SQL predicate",
         "path": "/search", "strategy": STRATEGY, "input_location": "params", "input_name": "q",
         "baseline": "plain", "pointer": "/result", "sql_template": "plain' AND {{predicate}} -- "}},
        {"tool": "run_experiment", "args": {}},
        {"tool": "run_experiment", "args": {}},
    ])

    class Planner:
        def next_step(self, ctx, history):
            return next(actions)

    result = AgentProbe("injection", Planner).run(ctx)
    assert result.verdict == "inconclusive" and result.limits_hit == "stagnation"
    assert len(sent) == 10 and len(result.poc["steps"]) == 10


SEARCH_VARIANT = {"id": "v-search", "hypothesis": "q is rendered as HTML in the heading", "request": {
    "method": "GET", "path": "/#/search", "inputs": [{"location": "query", "name": "q"}]}}


class ExecutingBrowser:
    def check(self, url, **kw):
        return {"executed": True, "context_verified": True, "evidence": []}


class Script:
    def __init__(self, steps):
        self.steps, self.calls = iter(steps), 0

    def next_step(self, ctx, history):
        self.calls += 1
        return next(self.steps, {"verdict": {"verdict": "inconclusive", "rationale": "script ended"}})


def xss_context(tmp_path):
    ctx = context(tmp_path)
    ctx.plan = replace(ctx.plan, cls="xss", cwe="CWE-79", endpoints=(),
                       verification_context={"variants": [SEARCH_VARIANT]})
    ctx.browser, ctx.marker = ExecutingBrowser(), ("m1", "m2")
    return ctx


def xss_plan(*prerequisites, variant="v-search"):
    args = {"kind": "execution", "hypothesis": "q reaches an innerHTML sink unsanitized", "path": "/#/search",
            "method": "GET", "strategy": {**STRATEGY, "prerequisites": list(prerequisites)}}
    if variant:
        args["variant"] = variant
    return {"tool": "plan_test", "args": args}


def page_loads(status, *steps):
    return {"condition": "The search page loads", "status": status, **({"steps": list(steps)} if steps else {})}


def test_rejected_plans_leave_the_allowance_to_the_corrected_plan(tmp_path):
    """Two plans rejected for their strategy must not use up the corrected one, whose key is the same."""
    ctx = xss_context(tmp_path)
    logs = []
    ctx.log = logs.append
    script = Script([
        {"tool": "read_context", "args": {"variant": "v-search"}},
        xss_plan(page_loads("observed", 1)),  # a context step is no observation
        xss_plan(page_loads("observed", 1)),
        xss_plan(page_loads("assumed")),  # differs only in its strategy, so its repetition key is the same
        {"tool": "browser_check", "args": {"path": "/#/search?q=<svg/onload=alert('m1'+'m2')>"}},
        {"verdict": {"verdict": "confirmed", "rationale": "the marker executed", "proof_steps": [5]}},
    ])
    result = AgentProbe("xss", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.limits_hit is None
    errors = [r["result"]["error"] for r in logs if (r.get("result") or {}).get("error")]
    assert len(errors) == 2
    assert all("prerequisite 1 is observed but cites step 1 without a recorded response" in e for e in errors)


def test_identical_rejected_plans_still_stop_after_three_failures(tmp_path):
    ctx = xss_context(tmp_path)
    logs = []
    ctx.log = logs.append
    script = Script([xss_plan(variant=None) for _ in range(4)])
    result = AgentProbe("xss", lambda: script).run(ctx)
    assert result.verdict == "inconclusive" and result.limits_hit == "stagnation"
    assert script.calls == 3
    assert sum(bool((r.get("result") or {}).get("error")) for r in logs) == 3


def test_accepted_plans_keep_using_the_allowance_and_a_refused_route_refunds_nothing(tmp_path):
    c = Controller(xss_context(tmp_path))
    args = xss_plan()["args"]
    for _ in range(2):
        c.before("plan_test", args)
        c.observe("plan_test", args, {"accepted": True, "experiment": args})
    elsewhere = {**args, "path": "/elsewhere"}
    with pytest.raises(ToolError, match="no matching route"):
        c.before("plan_test", elsewhere)
    c.observe("plan_test", elsewhere, {"error": "request has no matching route"})
    with pytest.raises(LimitExceeded, match="repetition"):
        c.before("plan_test", {**args, "hypothesis": "the same plan in other words"})


def test_plan_names_every_problem_and_accepts_a_recorded_response(tmp_path):
    ctx = xss_context(tmp_path)
    ctx.responses = {2: {"body": "", "complete": True}}
    tools = AgentTools(ctx)
    with pytest.raises(ToolError) as rejected:
        tools.plan_test(**xss_plan(page_loads("observed", 1, 2), page_loads("observed"), variant=None)["args"])
    message = str(rejected.value)
    assert "prerequisite 1 is observed but cites step 1 without a recorded response" in message
    assert "prerequisite 2 is observed but cites no step" in message
    assert "select an evidenced finding variant" in message
    assert tools.plan_test(**xss_plan(page_loads("observed", 2))["args"])["accepted"] is True


def test_an_experiment_on_a_write_is_refused_before_anything_is_sent(tmp_path):
    """Every control is sent twice and a write never repeats, so the plan could only fail (VER-036)."""
    sent = []
    ctx = context(tmp_path, lambda *a, **kw: sent.append(a) or Resp())
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", endpoints=(Endpoint("POST", "/login", None),))
    ctx.scope = {**ctx.scope, "injection_inputs": [{"finding_id": ctx.plan.id, "path": "/login",
                 "input_location": "json", "input_name": "email", "semantics": "literal"}]}
    tools = AgentTools(ctx)
    plan = {"kind": "boolean", "hypothesis": "The email is part of the SQL text", "path": "/login",
            "method": "POST", "strategy": STRATEGY, "input_location": "json", "input_name": "email",
            "baseline": "plain", "pointer": "/result", "sql_template": "plain' AND {{predicate}} -- "}
    timing = {k: v for k, v in plan.items() if k != "sql_template"}
    form = {**plan, "method": "GET", "input_location": "form"}                 # a form field needs a write
    for refused in (plan, {**timing, "kind": "timing", "method": "PATCH", "positive": "slow"}, form):
        with pytest.raises(ToolError, match="an experiment sends every control twice and a write is never repeated"):
            tools.plan_test(**refused)
    assert sent == []
    assert tools.plan_test(**{**plan, "method": "GET"})["accepted"] is True               # the same plan as a read
