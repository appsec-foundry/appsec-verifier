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


def test_prerequisite_read_allows_an_unnamed_get(tmp_path):
    """VER-047: a GET the finding does not name is allowed when marked as a prerequisite, and recorded."""
    c = Controller(context(tmp_path))
    c.before("http_request", {"method": "GET", "path": "/api/captcha", "prerequisite": True})
    assert c.prerequisites == ["GET /api/captcha"]


def test_unmarked_unnamed_get_is_still_refused(tmp_path):
    c = Controller(context(tmp_path))
    with pytest.raises(ToolError, match="no matching route"):
        c.before("http_request", {"method": "GET", "path": "/api/captcha"})


def test_prerequisite_read_is_get_only(tmp_path):
    c = Controller(context(tmp_path))
    with pytest.raises(ToolError, match="GET only"):
        c.before("http_request", {"method": "POST", "path": "/api/captcha", "prerequisite": True})


def test_prerequisite_read_stays_in_scope(tmp_path):
    """The prerequisite flag never bypasses the scope guard (VER-001, VER-018)."""
    c = Controller(context(tmp_path))
    with pytest.raises(ToolError, match="out of scope|target origin"):
        c.before("http_request", {"method": "GET", "path": "https://evil.example/x", "prerequisite": True})


def test_prerequisite_read_allowance_is_bounded(tmp_path):
    c = Controller(context(tmp_path))
    for i in range(3):
        c.before("http_request", {"method": "GET", "path": f"/api/p{i}", "prerequisite": True})
    with pytest.raises(ToolError, match="allowance"):
        c.before("http_request", {"method": "GET", "path": "/api/p9", "prerequisite": True})


def test_run_experiment_controls_keep_a_budget_apart_from_hand_probes(tmp_path):
    # A diagnostic hand-probe of a value must not use up the proof's budget for the same value, while a second
    # full run_experiment is still bounded because it re-sends the same controls into this namespace.
    c = Controller(context(tmp_path))
    req = {"method": "GET", "path": "/search", "params": {"q": "x"}}
    c.before("http_request", req)                       # a hand-probe, counted in the model namespace
    c.before("http_request", req, experiment=True)      # run_experiment sends this control, 1 of 2
    c.before("http_request", req, experiment=True)      # and 2 of 2 — the proof needs each control twice
    with pytest.raises(LimitExceeded, match="allowance"):
        c.before("http_request", req, experiment=True)  # a second run_experiment re-sends: still stopped
    c.before("http_request", {"path": "/search"})  # bounded diagnostics before a plan
    c.plan = {"path": "/search"}
    with pytest.raises(ToolError):
        c.before("http_request", {"path": "/unrelated"})


def test_a_revised_plan_gets_a_fresh_experiment_budget(tmp_path):
    # An experiment that aborts on a bad template spends one send of a control; the corrected plan must be able
    # to send that same control the two times its proof needs, because each accepted plan has its own namespace.
    c = Controller(context(tmp_path))
    req = {"method": "GET", "path": "/search", "params": {"q": "x"}}
    c.plan = {"path": "/search", "positive": "a"}
    c.before("http_request", req, experiment=True)      # aborted first experiment, baseline sent once
    c.plan = {"path": "/search", "positive": "b"}        # revised plan: fresh predicates, new token
    c.before("http_request", req, experiment=True)      # 1 of 2 under the revised plan
    c.before("http_request", req, experiment=True)      # 2 of 2
    with pytest.raises(LimitExceeded, match="allowance"):
        c.before("http_request", req, experiment=True)  # re-sending the revised plan's control still stops


def test_the_per_finding_experiment_count_is_bounded(tmp_path):
    c = Controller(context(tmp_path))
    req = {"method": "GET", "path": "/search", "params": {"q": "x"}}
    for n in range(3):
        c.plan = {"path": "/search", "positive": n}
        c.before("http_request", req, experiment=True)  # three distinct experiments run their controls
    c.plan = {"path": "/search", "positive": 99}
    with pytest.raises(LimitExceeded, match="experiment allowance is exhausted"):
        c.before("http_request", req, experiment=True)  # a fourth experiment is refused


def test_missing_route_never_guessed(tmp_path):
    ctx = context(tmp_path)
    ctx.plan.endpoints = ()
    with pytest.raises(ToolError, match="no matching route"):
        Controller(ctx).before("http_request", {"path": "/search"})


def test_route_rejection_names_the_allowed_routes(tmp_path):
    ctx = context(tmp_path)
    ctx.plan = replace(
        ctx.plan,
        endpoints=(Endpoint("GET", "/api/Feedbacks", None), Endpoint("POST", "/api/Feedbacks", None)),
    )
    with pytest.raises(ToolError, match=r"allowed: GET /api/Feedbacks, POST /api/Feedbacks"):
        Controller(ctx).before("plan_test", {"path": "/#/search"})


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
    with pytest.raises(ToolError, match="inputs"):     # declared sink q missing, only a foreign input
        c.before("http_request", {"path": "/search?other=value"})


def test_a_request_may_add_endpoint_required_fields_beyond_the_declared_sink(tmp_path):
    """Fix B: deklarierte Inputs sind die Sinks, die der Request treffen muss. Zusaetzliche vom Endpoint
    verlangte Pflichtfelder (rating neben dem verwundbaren comment) sind erlaubt, solange der Sink da ist."""
    ctx = context(tmp_path)
    ctx.marker = ("vrf0",)
    ctx.plan.verification_context = {"variants": [{"id": "v", "request": {
        "method": "POST", "path": "/api/Feedbacks", "inputs": [{"location": "json", "name": "comment"}]}}]}
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("POST", "/api/Feedbacks", None),))
    c = Controller(ctx)
    c.before("http_request", {"method": "POST", "path": "/api/Feedbacks",
                              "json": {"comment": "<img src=x>vrf0", "rating": 5}})   # extra rating allowed
    with pytest.raises(ToolError, match="declared variant inputs"):                   # sink comment missing
        c.before("http_request", {"method": "POST", "path": "/api/Feedbacks",
                                  "json": {"other": "vrf0val", "rating": 5}})


def test_accepted_experiment_pins_non_sink_fields_across_probes(tmp_path):
    """Fix B, zweite Haelfte: nach einem akzeptierten boolean-Experiment darf der Request die vom Endpoint
    verlangten Begleitfelder tragen, aber sie muessen ueber alle Proben stabil bleiben, sonst vergleicht der
    Proof auf dem falschen Unterschied (VER-011)."""
    ctx = context(tmp_path)
    ctx.marker = ("vrf0",)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89",
                       endpoints=(Endpoint("POST", "/login", None),))
    c = Controller(ctx)
    plan = {"kind": "boolean", "path": "/login", "method": "POST", "input_location": "json",
            "input_name": "email", "baseline": "vrf0@x", "positive": "vrf0@x' OR '1'='1",
            "negative": "vrf0@x' OR '1'='2"}
    c.observe("plan_test", plan, {"accepted": True, "experiment": plan})
    # First probe fixes the accompanying fields (a stable password).
    c.before("http_request", {"method": "POST", "path": "/login",
                              "json": {"email": "vrf0@x", "password": "p"}})
    # Same accompanying fields, different sink value: allowed.
    c.before("http_request", {"method": "POST", "path": "/login",
                              "json": {"email": "vrf0@x' OR '1'='1", "password": "p"}})
    # Changed accompanying field: rejected, because the comparison would no longer rest on the sink.
    with pytest.raises(ToolError, match="non-sink fields identical"):
        c.before("http_request", {"method": "POST", "path": "/login",
                                  "json": {"email": "vrf0@x' OR '1'='2", "password": "different"}})
    # A non-control sink value is still rejected (marker kept so the write rule is not what fires).
    with pytest.raises(ToolError, match="sink value"):
        c.before("http_request", {"method": "POST", "path": "/login",
                                  "json": {"email": "vrf0-unrelated", "password": "p"}})


def test_accepted_write_experiment_may_send_each_control_twice(tmp_path):
    """VER-011 + VER-030: ein akzeptiertes boolean/timing-Experiment auf einem Write muss jede deklarierte
    Kontrolle zweimal senden koennen, weil experiments.injection_check >= 2 pro Gruppe verlangt. Der dritte
    identische Send bleibt beschraenkt."""
    ctx = context(tmp_path)
    ctx.marker = ("vrf0",)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89",
                       endpoints=(Endpoint("POST", "/login", None),))
    c = Controller(ctx)
    plan = {"kind": "boolean", "path": "/login", "method": "POST", "input_location": "json",
            "input_name": "email", "baseline": "vrf0@x", "positive": "vrf0@x' OR '1'='1",
            "negative": "vrf0@x' OR '1'='2"}
    c.observe("plan_test", plan, {"accepted": True, "experiment": plan})
    probe = {"method": "POST", "path": "/login", "json": {"email": "vrf0@x", "password": "p"}}
    c.before("http_request", probe)   # first send of the baseline control
    c.before("http_request", probe)   # the proof needs the same control value twice
    with pytest.raises(LimitExceeded, match="allowance"):
        c.before("http_request", probe)   # a third identical send stays bounded


def test_write_outside_an_experiment_keeps_the_single_send_cap(tmp_path):
    """VER-014: ohne akzeptiertes boolean/timing-Experiment bleibt ein Write bei genau einem Send, damit er
    keine Zustandsaenderung wiederholt."""
    ctx = context(tmp_path)
    ctx.marker = ("vrf0",)
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("POST", "/api/Feedbacks", None),))
    c = Controller(ctx)
    write = {"method": "POST", "path": "/api/Feedbacks", "json": {"comment": "vrf0"}}
    c.before("http_request", write)
    with pytest.raises(LimitExceeded, match="allowance"):
        c.before("http_request", write)


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


def test_operator_pinned_resource_stays_bound_when_other_routes_are_known(tmp_path):
    ctx = context(tmp_path)
    ctx.plan.endpoints += (Endpoint("GET", "/other", None),)
    ctx.scope = {**ctx.scope, "test_resources": [{"finding_id": ctx.plan.id, "id": "owned",
                 "path": "/search", "allowed_roles": ["customer-a"], "denied_roles": ["customer-b"]}]}
    c = Controller(ctx)
    c.plan = {"kind": "access-control", "resource": "owned", "path": "/search"}
    c.before("http_request", {"path": "/search", "role": "customer-b"})
    with pytest.raises(ToolError, match="accepted test plan"):
        c.before("http_request", {"path": "/other", "role": "customer-b"})


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


def test_an_accepted_plan_runs_its_controls_once_automatically(tmp_path):
    # An accepted read-only SQL challenge runs its ten controls on acceptance, in one action and without a
    # run_experiment step. The empty fake target gives no contrast, so the proof does not hold.
    sent = []
    ctx = context(tmp_path, lambda *a, **kw: sent.append(kw["params"]) or Resp())
    ctx.plan.cls, ctx.plan.cwe = "injection", "CWE-89"
    ctx.scope = {**ctx.scope, "injection_inputs": [{"finding_id": ctx.plan.id, "path": "/search",
                 "input_location": "params", "input_name": "q", "semantics": "literal"}]}
    actions = iter([
        {"tool": "plan_test", "args": {"kind": "boolean", "hypothesis": "Test the declared SQL predicate",
         "path": "/search", "input_location": "params", "input_name": "q",
         "baseline": "plain", "pointer": "/result", "sql_template": "plain' AND {{predicate}} -- "}},
        {"verdict": {"verdict": "confirmed", "rationale": "controls", "proof_steps": list(range(2, 12))}},
    ])

    class Planner:
        def next_step(self, ctx, history):
            try:
                return next(actions)
            except StopIteration:
                return {"verdict": {"verdict": "inconclusive", "rationale": "no contrast"}}

    result = AgentProbe("injection", Planner).run(ctx)
    assert len(sent) == 10 and result.verdict == "inconclusive"


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


def test_a_re_declared_plan_need_not_explain_itself(tmp_path):
    """Dropping the revision-reason rule (VER-043): re-declaring a plan is accepted without a reason, and an
    executed marker on the finding's route still confirms."""
    ctx = xss_context(tmp_path)
    script = Script([
        xss_plan(page_loads("assumed")),
        xss_plan(page_loads("assumed")),  # re-declared, no reason required
        {"tool": "browser_check", "args": {"path": "/#/search?q=<svg/onload=alert('m1'.concat('m2'))>"}},
        {"verdict": {"verdict": "confirmed", "rationale": "the marker executed", "proof_steps": [3]}},
    ])
    result = AgentProbe("xss", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.limits_hit is None


PROFILE_VARIANT = {"id": "v-profile", "hypothesis": "name is rendered as HTML in the profile", "request": {
    "method": "GET", "path": "/#/profile", "inputs": [{"location": "query", "name": "name"}]}}


def _pinned_xss(tmp_path):
    from appsec_verifier.planning import expand_variants

    ctx = xss_context(tmp_path)
    ctx.plan = expand_variants([replace(ctx.plan, verification_context={
        "variants": [SEARCH_VARIANT, PROFILE_VARIANT]})])[0]       # this probe tests v-search only
    return ctx


def test_xss_confirms_without_a_plan_on_the_pinned_variant(tmp_path):
    """VER-043: no plan_test; the executed marker on the pinned variant's route confirms, and proof_ready said so."""
    ctx = _pinned_xss(tmp_path)
    script = Script([
        {"tool": "browser_check", "args": {"path": "/#/search?q=<svg/onload=alert('m1'.concat('m2'))>"}},
        {"verdict": {"verdict": "confirmed", "rationale": "the marker executed", "proof_steps": [1]}},
    ])
    result = AgentProbe("xss", lambda: script).run(ctx)
    assert result.verdict == "confirmed" and result.proof["checked"] is True
    assert script.calls == 2


def test_xss_on_another_variants_route_is_neither_ready_nor_confirmed(tmp_path):
    """Refused case: an execution on the other variant's route gets no proof_ready and is downgraded."""
    ctx = _pinned_xss(tmp_path)
    logs = []
    ctx.log = logs.append
    script = Script([
        {"tool": "browser_check", "args": {"path": "/#/profile?name=<svg/onload=alert('m1'.concat('m2'))>"}},
        {"verdict": {"verdict": "confirmed", "rationale": "the marker executed", "proof_steps": [1]}},
    ])
    result = AgentProbe("xss", lambda: script).run(ctx)
    assert result.verdict == "inconclusive"
    assert not any("proof_ready" in (h.get("result") or {}) for h in ctx.agent_history)


@pytest.mark.parametrize("plan_path", ["/#/search", "/#/search?q=<test>", "/#/search?q=<test>&lang=en"])
def test_xss_proof_takes_the_planned_route_with_or_without_a_query_template(tmp_path, plan_path):
    """The controller and the proof check compare the planned route alike; a query is not part of it (VER-009)."""
    plan = xss_plan(page_loads("assumed"))
    plan["args"]["path"] = plan_path
    script = Script([
        plan,
        {"tool": "browser_check", "args": {"path": "/#/search?q=<svg/onload=alert('m1'.concat('m2'))>"}},
        {"verdict": {"verdict": "confirmed", "rationale": "the marker executed", "proof_steps": [2]}},
    ])
    assert AgentProbe("xss", lambda: script).run(xss_context(tmp_path)).verdict == "confirmed"


def test_identical_rejected_plans_still_stop_after_three_failures(tmp_path):
    ctx = _two_variants(tmp_path)           # no variant named among two: each plan is rejected
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


def test_an_observed_prerequisite_without_a_recorded_response_counts_as_assumed(tmp_path):
    """Observed only with recorded responses of this finding; the plan is accepted rather than declared again."""
    ctx = xss_context(tmp_path)
    ctx.responses = {2: {"body": "", "complete": True}}
    tools = AgentTools(ctx)
    args = xss_plan(page_loads("observed", 1, 2), page_loads("observed"), page_loads("observed", 2))["args"]
    accepted = tools.plan_test(**args)
    statuses = [p["status"] for p in accepted["experiment"]["strategy"]["prerequisites"]]
    assert statuses == ["assumed", "assumed", "observed"]
    assert accepted["note"].startswith("prerequisite 1, 2 counts as assumed")
    assert args["strategy"]["prerequisites"][0]["status"] == "observed"  # the proposal itself stays as sent
    assert "note" not in AgentTools(ctx).plan_test(**xss_plan(page_loads("observed", 2))["args"])


def _two_variants(tmp_path):
    ctx = xss_context(tmp_path)
    ctx.plan = replace(ctx.plan, verification_context={"variants": [SEARCH_VARIANT, PROFILE_VARIANT]})
    return ctx


def test_a_plan_names_its_variant_problem(tmp_path):
    with pytest.raises(ToolError, match="select an evidenced finding variant"):
        AgentTools(_two_variants(tmp_path)).plan_test(**xss_plan(variant=None)["args"])
    ctx = xss_context(tmp_path)
    ctx.plan = replace(ctx.plan, verification_context={})
    with pytest.raises(ToolError, match="this finding has no variants; omit variant"):
        AgentTools(ctx).plan_test(**xss_plan()["args"])


def test_a_plan_without_a_variant_is_held_to_the_probes_only_one(tmp_path):
    """A probe tests one variant (expand_variants): a plan that names none takes it and passes the same checks as
    if it had named it, so a request outside that variant is still refused."""
    accepted = AgentTools(_pinned_xss(tmp_path)).plan_test(**xss_plan(variant=None)["args"])
    assert accepted["experiment"]["variant"] == "v-search"
    with pytest.raises(ToolError, match="the path does not match the finding variant; variant 'v-search'"):
        AgentTools(_pinned_xss(tmp_path)).plan_test(**{**xss_plan(variant=None)["args"], "path": "/profile"})


def test_a_plan_on_another_hash_route_is_refused_and_proves_nothing(tmp_path):
    """Refused case: the probe tests the variant on /#/search, and the finding also names /#/profile, so the
    controller allows both routes. A plan naming /#/profile fails the variant check like any other path, so a
    marker executed there cannot confirm the /#/search variant."""
    def pinned():
        ctx = _pinned_xss(tmp_path)
        ctx.plan = replace(ctx.plan, endpoints=(Endpoint("GET", "/#/search", None),
                                                Endpoint("GET", "/#/profile", None)))
        return ctx

    with pytest.raises(ToolError, match="the path does not match the finding variant; variant 'v-search'"):
        AgentTools(pinned()).plan_test(**{**xss_plan()["args"], "path": "/#/profile"})
    script = Script([
        {"tool": "plan_test", "args": {**xss_plan()["args"], "path": "/#/profile"}},
        {"tool": "browser_check", "args": {"path": "/#/profile?name=<svg/onload=alert('m1'.concat('m2'))>"}},
        {"verdict": {"verdict": "confirmed", "rationale": "the marker executed", "proof_steps": [2]}},
    ])
    result = AgentProbe("xss", lambda: script).run(pinned())
    assert result.verdict != "confirmed"
    # The `#` route also tells two variants apart when an unknown id is resolved by method and path.
    accepted = AgentTools(_two_variants(tmp_path)).plan_test(
        **{**xss_plan(variant="v-unknown")["args"], "path": "/#/profile"})
    assert accepted["experiment"]["variant"] == "v-profile"


def test_variant_mismatch_errors_name_the_valid_variants(tmp_path):
    """Fehlertexte, die Varianten betreffen, listen die zulassigen Optionen, damit der Agent in einem Step
    korrigieren kann statt in die Stagnation zu laufen."""
    ctx = xss_context(tmp_path)
    tools = AgentTools(ctx)
    # select-variant lists the catalog
    with pytest.raises(ToolError) as exc:
        AgentTools(_two_variants(tmp_path)).plan_test(**xss_plan(variant=None)["args"])
    assert "v-search" in str(exc.value) and "GET /#/search" in str(exc.value) and "v-profile" in str(exc.value)
    # unknown variant names what the user sent and the available ids when method/path also do not
    # identify a declared variant uniquely.
    with pytest.raises(ToolError, match=r"unknown finding variant 'v-missing'.*v-search"):
        tools.plan_test(**{**xss_plan(variant="v-missing")["args"], "method": "POST", "path": "/#/elsewhere"})
    # unknown variant in read_context too
    with pytest.raises(ToolError, match=r"unknown finding variant 'v-missing'.*v-search"):
        tools.read_context(variant="v-missing")
    # unavailable context field names the fields that exist
    ctx.plan = replace(ctx.plan, context={"affected_parameter": "q", "evidence_summary": "s"})
    with pytest.raises(ToolError, match=r"unavailable.*affected_parameter"):
        tools.read_context(field="variants")


def test_a_variant_id_padded_with_extra_descriptors_resolves_to_the_declared_one(tmp_path):
    """Modelle hangen gern 'erklaerende' Suffixe an deklarierte Varianten-IDs an. Solange genau eine
    deklarierte ID ein Praefix (bis zum Trenner `-` oder `_`) der genannten ist, nimmt plan_test die
    und vermerkt die Korrektur im note; andernfalls bleibt die Zurueckweisung bestehen."""
    accepted = AgentTools(xss_context(tmp_path)).plan_test(**xss_plan(variant="v-search-extra-description")["args"])
    assert accepted["experiment"]["variant"] == "v-search"
    assert "accepted as 'v-search'" in accepted["note"]
    # Exact still wins over fuzzy.
    accepted2 = AgentTools(xss_context(tmp_path)).plan_test(**xss_plan(variant="v-search")["args"])
    assert accepted2["experiment"]["variant"] == "v-search" and "note" not in accepted2
    # Mehrdeutig: deklariert sind sowohl "v" als auch "v-a"; "v-a-extra" trifft beide als Prefix.
    ctx = xss_context(tmp_path)
    ctx.plan = replace(ctx.plan, verification_context={"variants": [
        {"id": "v", "request": {"method": "GET", "path": "/#/search", "inputs": SEARCH_VARIANT["request"]["inputs"]}},
        {"id": "v-a", "request": {"method": "GET", "path": "/#/search",
                                   "inputs": SEARCH_VARIANT["request"]["inputs"]}},
    ]})
    with pytest.raises(ToolError, match=r"unknown finding variant 'v-a-extra'"):
        AgentTools(ctx).plan_test(**xss_plan(variant="v-a-extra")["args"])
    # read_context profitiert vom gleichen Mapping.
    ctx2 = xss_context(tmp_path)
    out = AgentTools(ctx2).read_context(variant="v-search-with-extra")
    assert out["context"]["id"] == "v-search" and "accepted as 'v-search'" in out["note"]


def test_an_invented_variant_id_resolves_by_matching_method_and_path(tmp_path):
    """Fix A+: nennt das Modell eine ID, die es sich ausgedacht hat, aber Methode und Pfad treffen genau
    eine deklarierte Variante, dann ist das die gemeinte; die ID war nur ein Label."""
    accepted = AgentTools(xss_context(tmp_path)).plan_test(**xss_plan(variant="variant-search-q")["args"])
    assert accepted["experiment"]["variant"] == "v-search"
    assert "by matching method and path" in accepted["note"]
    # Zwei Varianten auf derselben Methode+Pfad: nicht mehr eindeutig, also Zurueckweisung.
    ctx = xss_context(tmp_path)
    ctx.plan = replace(ctx.plan, verification_context={"variants": [
        {"id": "a", "request": {"method": "GET", "path": "/#/search",
                                 "inputs": SEARCH_VARIANT["request"]["inputs"]}},
        {"id": "b", "request": {"method": "GET", "path": "/#/search",
                                 "inputs": SEARCH_VARIANT["request"]["inputs"]}},
    ]})
    with pytest.raises(ToolError, match=r"unknown finding variant 'made-up'"):
        AgentTools(ctx).plan_test(**xss_plan(variant="made-up")["args"])


def test_method_and_path_mismatches_name_the_expected_request(tmp_path):
    ctx = xss_context(tmp_path)
    tools = AgentTools(ctx)
    bad_method = {**xss_plan()["args"], "method": "POST"}
    with pytest.raises(ToolError, match=r"method does not match.*v-search.*GET /#/search"):
        tools.plan_test(**bad_method)
    bad_path = {**xss_plan()["args"], "path": "/api/other"}
    with pytest.raises(ToolError, match=r"(path does not match|no matching route).*v-search.*GET /#/search"):
        tools.plan_test(**bad_path)


def test_5xx_during_an_accepted_injection_experiment_is_an_observation_not_a_failure(tmp_path):
    """Ein 500 auf eine Injection-Probe (z. B. SQLite-Fehler bei unbalancierter Klammer) ist das
    eigentliche Observationssignal; die Stagnationsschranke darf das Experiment nicht abschiessen,
    bevor der Agent es werten kann. proof.py entscheidet weiter, was ein 5xx tatsaechlich beweist.
    Ausserhalb eines akzeptierten Experiments zaehlt 5xx weiter als Fehlschlag."""
    c = Controller(context(tmp_path))
    c.plan = {"kind": "boolean", "path": "/search", "method": "GET", "input_location": "params",
              "input_name": "q", "baseline": "a", "positive": "b", "negative": "c"}
    for _ in range(3):
        c.observe("http_request", {"method": "GET", "path": "/search"}, {"status": 500, "length": 10})
    c.check()                                        # no stagnation on three 500s under the experiment
    assert c.failures == 0
    # A new context without an accepted experiment: 5xx keeps counting.
    c2 = Controller(context(tmp_path))
    for _ in range(3):
        c2.observe("http_request", {"method": "GET", "path": "/search"}, {"status": 500, "length": 10})
    with pytest.raises(LimitExceeded, match="three actions in a row failed") as exc:
        c2.check()
    assert exc.value.kind == "stagnation"
    assert str(exc.value).endswith("; the last: http_request: HTTP 500")


def test_a_stop_after_failed_actions_names_the_last_one_and_is_not_called_a_limit(tmp_path):
    """VER-036: three failed actions in a row stop the finding; the stop names the last failure, so the operator
    sees why, and it reads as a stop, not as a budget the run reached."""
    c = Controller(context(tmp_path))
    c.observe("read_source", {"path": "a.ts"}, {"lines": 3})
    c.refuse("fetch_url", "unknown action 'fetch_url'")
    c.observe("plan_test", {"kind": "boolean"}, {"error": "path input needs exactly one placeholder"})
    c.observe("plan_test", {"kind": "boolean"}, {"error": "path input needs exactly one\nplaceholder " + "x" * 300})
    with pytest.raises(LimitExceeded) as exc:
        c.check()
    detail = str(exc.value)
    assert detail.startswith("three actions in a row failed without a usable observation; the last: plan_test: "
                             "path input needs exactly one placeholder xx")
    assert detail.endswith("…") and "\n" not in detail and len(detail) < 300
    assert exc.value.rationale() == "stopped: " + detail
    assert LimitExceeded("requests", "request cap reached").rationale() == "stopped by limit: request cap reached"
    c.observe("http_request", {"path": "/a"}, {"status": 200})          # a usable observation resets it
    c.refuse("fetch_url", "unknown action 'fetch_url'")
    assert c.failures == 1 and c.last_failure == "fetch_url refused: unknown action 'fetch_url'"


def test_plan_test_accepts_the_query_alias_for_params(tmp_path):
    """Die Variante nennt den URL-Query als `query`, das Plan-Schema als `params`. Beides wird akzeptiert
    und auf `params` normalisiert, damit der eine Vokabular-Delta nicht ganze Varianten-Tests kippt."""
    ctx = context(tmp_path)
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89",
                       endpoints=(Endpoint("GET", "/search", None),),
                       verification_context={"variants": [{"id": "v-q",
                           "request": {"method": "GET", "path": "/search",
                                       "inputs": [{"location": "query", "name": "q"}]}}]})
    args = {"kind": "boolean", "hypothesis": "q is spliced into SQL", "path": "/search", "method": "GET",
            "strategy": STRATEGY, "variant": "v-q", "input_location": "query", "input_name": "q",
            "baseline": "a", "pointer": "/result", "sql_template": "a' AND {{predicate}} -- "}
    accepted = AgentTools(ctx).plan_test(**args)
    assert accepted["experiment"]["input_location"] == "params"


def test_an_experiment_on_a_write_needs_intrusive_mode(tmp_path):
    """VER-011 + VER-030: writes repeat only in --allow-intrusive; the agent sends each control itself."""
    from test_agent_tools import _ctx

    from appsec_verifier.agent.tools import AgentTools, ToolError

    def mk(safe):
        ctx = _ctx(tmp_path, lambda *a, **kw: Resp(), safe=safe, read_only=safe)
        ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89", endpoints=(Endpoint("POST", "/login", None),))
        return AgentTools(ctx)

    plan_write = {"kind": "boolean", "hypothesis": "The email is part of the SQL text", "path": "/login",
                  "method": "POST", "strategy": STRATEGY, "input_location": "json", "input_name": "email",
                  "baseline": "plain", "pointer": "/result", "sql_template": "plain' AND {{predicate}} -- "}
    timing_write = {k: v for k, v in plan_write.items() if k != "sql_template"}
    form_safe_method = {**plan_write, "method": "GET", "input_location": "form"}      # form implies write
    for refused in (plan_write, {**timing_write, "kind": "timing", "method": "PATCH", "positive": "slow"},
                    form_safe_method):
        with pytest.raises(ToolError, match="a write needs --allow-intrusive|form experiments need a body-capable"):
            mk(safe=True).plan_test(**refused)
    # Intrusive mode accepts the same write-based plan.
    assert mk(safe=False).plan_test(**plan_write)["accepted"] is True
    assert mk(safe=True).plan_test(**{**plan_write, "method": "GET"})["accepted"] is True    # read is OK in safe
