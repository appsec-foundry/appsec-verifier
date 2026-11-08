"""How the Verifier behaves when something fails during a run (VER-015, VER-016,
VER-017, VER-020, VER-024, VER-028): an interrupted run still writes its report,
a run-wide limit or a failing model host ends the run instead of costing a call
per finding, a slow or oversized answer ends its request, tool failures reach
the agent as tool errors, a dead proof browser is started again, logins are not
repeated without need, unreadable input files block with exit 2, and files are
replaced atomically. Offline: fakes, and a server on loopback for the transport."""

from __future__ import annotations

import errno
import gzip
import json
import math
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml

from appsec_verifier import cli
from appsec_verifier.agent import AgentTools, ToolError
from appsec_verifier.agent.host_claude import ClaudeHost
from appsec_verifier.agent.hosts import MAX_FAILED_CALLS, HostPlanner, HostReply
from appsec_verifier.agent.registry import agent_registry
from appsec_verifier.agent.source_reader import SourceReader
from appsec_verifier.auth import SessionManager
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.limits import LimitExceeded, Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, httpx_transport
from appsec_verifier.tools.browser import BrowserError, ProofBrowser
from appsec_verifier.tools.httpx_transport import HttpxTransport, ResponseTooLarge
from appsec_verifier.verify import report
from appsec_verifier.verify.probes import ProbeRegistry
from appsec_verifier.verify.runner import run_verification

BASE = "https://app.example.com"
SCOPE = {"schema_version": 1, "base_url": BASE, "owner": {"name": "tester"},
         "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
THREATS = [{"id": f"T-{n}", "cwe": "CWE-639", "severity": "high", "title": "idor",
            "evidence": {"file": "a.ts", "line": n}} for n in range(1, 5)]
LOGIN = f"{BASE}/rest/user/login"
FORM = {"role": "alice", "method": "form", "auth": {"login_url": LOGIN, "username_env": "AU", "password_env": "AP"}}
SECRET = "s3cr3t-pa55"
ENV = {"AU": "alice@example.com", "AP": SECRET}
INFO = {"profile": "anthropic-api", "model": "m", "runtime": "Anthropic API", "auth": "API key",
        "check": "model metadata accessible"}


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self.headers, self._body, self.text = status, {}, body, "ok"

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class Target:
    """Fake transport: answers by (method, url), records every call; an exception is raised."""

    def __init__(self, answers=None, default=None):
        self.answers, self.default, self.calls = dict(answers or {}), default, []

    def __call__(self, method, url, headers, **kw):
        self.calls.append((method, url))
        out = self.answers.get((method, url), self.default)
        if out is None:
            raise AssertionError(f"unexpected request {method} {url}")
        if isinstance(out, Exception):
            raise out
        return out


def _plans(n=5):
    return [FindingPlan(id=f"F{i}", cwe="CWE-639", severity="high", title="t", match_key="k", instance="a.ts:1",
                        status="dynamic", cls="access-control", reason="",
                        endpoints=(Endpoint("GET", "/rest/basket/:id", None), Endpoint("GET", "/a", None)))
            for i in range(n)]


def _run(registry, *, plans=None, limits=None, target=None, identities=(), sessions=None, log=None):
    budget = RunBudget(limits or Limits(rate_rps=0))
    http = GuardedHttpClient(ScopeGuard(SCOPE), budget, target or Target(default=Resp()))
    if identities and sessions is None:
        sessions = SessionManager(list(identities), http, env=ENV)
    doc = run_verification(assessment_path=Path("a"), scope=SCOPE, scope_path=Path("s"), plans=plans or _plans(),
                           limits=budget.limits, identities=list(identities), registry=registry, verifier_version="t",
                           target_base=BASE, authorization={}, http=http, sessions=sessions, budget=budget, log=log)
    return doc, budget


def _write(path, doc):
    path.write_text(yaml.safe_dump(doc))
    return path


def _verify(tmp_path, monkeypatch, planner, *extra, target=None, threats=None):
    target = target or Target(default=Resp())
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (planner, dict(INFO)))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: target)
    argv = ["verify", "--assessment", str(_write(tmp_path / "a.yaml", {"threats": threats or THREATS})),
            "--scope", str(_write(tmp_path / "s.yaml", SCOPE)), "--yes", "--test-all",
            "--output", str(tmp_path / "out"),
            "--rate", "0", "--screenshots", "none", *extra]
    return cli.main(argv), target


class Checked:
    """A planner that tests nothing and says so; records which findings it was asked about."""

    asked: list = []

    def next_step(self, ctx, history):
        Checked.asked.append(ctx.plan.id)
        return {"verdict": {"verdict": "not-attempted", "rationale": "checked"}}


# ── Ctrl-C still writes the report (VER-015, VER-020, VER-024) ─────────────────

def test_an_interrupted_run_writes_what_it_found_and_exits_130(tmp_path, monkeypatch, capsys):
    class Interrupted:
        def next_step(self, ctx, history):
            if ctx.plan.id == "T-3":
                raise KeyboardInterrupt
            return {"verdict": {"verdict": "not-attempted", "rationale": "checked"}}

    rc, _ = _verify(tmp_path, monkeypatch, Interrupted)
    assert rc == cli.EXIT_INTERRUPTED and "interrupted" in capsys.readouterr().err
    doc = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert doc["meta"]["interrupted"] is True
    assert [r["verdict"] for r in doc["results"]] == ["not-attempted", "not-attempted", "inconclusive",
                                                      "not-attempted"]
    assert "interrupted" in doc["results"][2]["rationale"] and "interrupted" in doc["results"][3]["rationale"]
    log = [json.loads(line) for line in (tmp_path / "out" / "agent-log.jsonl").read_text().splitlines()]
    assert {"finding": "T-3", "interrupted": True}.items() <= log[-1].items()


def test_ctrl_c_outside_a_run_ends_with_130_without_a_traceback(monkeypatch, capsys):
    monkeypatch.setattr(cli, "cmd_scope", lambda args: (_ for _ in ()).throw(KeyboardInterrupt))
    assert cli.main(["scope", "--scope", "s.yaml"]) == cli.EXIT_INTERRUPTED
    assert "interrupted." in capsys.readouterr().err


# ── --resume continues a run that did not finish ─────────────────────────────

class InterruptedAtT3:
    def next_step(self, ctx, history):
        if ctx.plan.id == "T-3":
            raise KeyboardInterrupt
        return {"verdict": {"verdict": "not-reproducible", "rationale": "first run"}}


@pytest.mark.parametrize("existing", [
    "results: [\n",
    yaml.safe_dump({"meta": {}, "results": [{"finding_ref": {"id": "X"}, "verdict": "refuted"}]}),
    yaml.safe_dump(["not", "a", "report"]),
])
def test_resume_of_an_unusable_report_is_refused_before_any_contact(tmp_path, monkeypatch, capsys, existing):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "verification.yaml").write_text(existing)
    Checked.asked = []
    rc, target = _verify(tmp_path, monkeypatch, Checked, "--resume")
    assert rc == cli.EXIT_BLOCKED and Checked.asked == [] and target.calls == []
    err = capsys.readouterr().err
    assert "cannot be continued with --resume" in err and "Nothing was contacted." in err
    assert (tmp_path / "out" / "verification.yaml").read_text() == existing


def _saved_checked_results(tmp_path, count):
    """Resume fixtures model already checked results, independently of the planner stub."""
    path = tmp_path / "out" / "verification.yaml"
    doc = yaml.safe_load(path.read_text())
    for row in doc["results"][:count]:
        row.update(verdict="blocked-by-control", rationale="first run", proof={"checked": True, "contract": 3})
    path.write_text(yaml.safe_dump(doc))


def test_resume_tests_only_the_findings_without_a_verdict_and_keeps_the_rest(tmp_path, monkeypatch, capsys):
    assert _verify(tmp_path, monkeypatch, InterruptedAtT3)[0] == cli.EXIT_INTERRUPTED
    _saved_checked_results(tmp_path, 2)
    Checked.asked = []
    assert _verify(tmp_path, monkeypatch, Checked, "--resume")[0] == cli.EXIT_OK
    assert Checked.asked == ["T-3", "T-4"]
    assert "remaining variants are tested separately" in capsys.readouterr().out
    doc = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert [(r["finding_ref"]["id"], r["rationale"]) for r in doc["results"]] == [
        ("T-1", "first run"), ("T-2", "first run"), ("T-3", "checked"), ("T-4", "checked")]
    assert doc["meta"]["interrupted"] is False and doc["meta"]["previous_generated"]
    log = [json.loads(line) for line in (tmp_path / "out" / "agent-log.jsonl").read_text().splitlines()]
    assert log[0]["finding"] == "T-1" and log[-1]["finding"] == "T-4"           # both runs in one log


def test_resume_with_nothing_left_contacts_nothing(tmp_path, monkeypatch, capsys):
    assert _verify(tmp_path, monkeypatch, Checked)[0] == cli.EXIT_OK
    _saved_checked_results(tmp_path, 4)
    Checked.asked = []
    rc, target = _verify(tmp_path, monkeypatch, Checked, "--resume")
    assert rc == cli.EXIT_OK and Checked.asked == [] and target.calls == []
    assert "nothing to resume" in capsys.readouterr().err


def test_resume_refuses_a_report_of_another_assessment_or_target(tmp_path, monkeypatch, capsys):
    assert _verify(tmp_path, monkeypatch, InterruptedAtT3)[0] == cli.EXIT_INTERRUPTED
    before = (tmp_path / "out" / "verification.yaml").read_text()
    monkeypatch.setattr(sys.modules[__name__], "THREATS", [*THREATS[:3]])     # the assessment changed
    Checked.asked = []
    rc, target = _verify(tmp_path, monkeypatch, Checked, "--resume")
    assert rc == cli.EXIT_BLOCKED and Checked.asked == [] and target.calls == []
    assert "another assessment, or the assessment has changed" in capsys.readouterr().err
    assert (tmp_path / "out" / "verification.yaml").read_text() == before
    existing = yaml.safe_load(before)
    assert report.resume_problems(existing, existing["meta"]["source_assessment_sha256"], "https://other.example") \
        == ["it was written for another target"]


def test_resume_without_a_report_runs_as_usual(tmp_path, monkeypatch):
    Checked.asked = []
    assert _verify(tmp_path, monkeypatch, Checked, "--resume")[0] == cli.EXIT_OK
    assert Checked.asked == ["T-1", "T-2", "T-3", "T-4"]


# ── unreadable input files block with exit 2 ───────────────────────────────────

def test_unreadable_scope_and_report_files_block_without_a_traceback(tmp_path, capsys):
    missing = str(tmp_path / "missing.yaml")
    assessment = str(_write(tmp_path / "a.yaml", {"threats": THREATS}))
    (tmp_path / "broken.yaml").write_text("a: [\n")
    assert cli.main(["scope", "--scope", missing]) == cli.EXIT_BLOCKED
    assert cli.main(["scope", "--scope", str(_write(tmp_path / "list.yaml", ["x"]))]) == cli.EXIT_BLOCKED
    assert cli.main(["verify", "--assessment", assessment, "--scope", missing]) == cli.EXIT_BLOCKED
    assert cli.main(["verify", "--assessment", assessment, "--scope", str(tmp_path / "broken.yaml")]) == 2
    out = str(tmp_path / "x.json")
    assert cli.main(["export", "--verification", missing, "--output", out]) == cli.EXIT_BLOCKED
    assert cli.main(["export", "--verification", str(_write(tmp_path / "v.yaml", {})), "--output", out]) == 2
    err = capsys.readouterr().err
    assert err.count("cannot read it: FileNotFoundError") == 3 and "cannot read it: " in err.replace(
        "cannot read it: FileNotFoundError", "")
    assert "it is not a mapping" in err and "file: 'meta' is a required property" in err
    assert not Path(out).exists()


# ── a single request is bounded in time and size (VER-015) ─────────────────────

def _serve(body: bytes, *, chunk: int, pause: float, headers=()):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            try:
                for i in range(0, len(body), chunk):
                    self.wfile.write(body[i:i + chunk])
                    self.wfile.flush()
                    time.sleep(pause)
            except OSError:          # the client stopped reading
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


@pytest.fixture
def serve():
    servers = []

    def start(body, **kw):
        server, url = _serve(body, **kw)
        servers.append(server)
        return url

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_an_answer_that_trickles_in_ends_after_the_timeout(serve):
    url = serve(b"x" * 8, chunk=1, pause=0.25)                     # two seconds for eight bytes
    started = time.monotonic()
    with pytest.raises(httpx.ReadTimeout):
        HttpxTransport(timeout=0.5)("GET", url, {})
    assert time.monotonic() - started < 1.5


def test_a_request_can_get_a_shorter_timeout_than_the_transport(serve):
    url = serve(b"x" * 8, chunk=1, pause=0.25)
    started = time.monotonic()
    with pytest.raises(httpx.ReadTimeout):
        HttpxTransport(timeout=30.0)("GET", url, {}, timeout=0.5)
    assert time.monotonic() - started < 1.5


def test_an_answer_within_its_bounds_is_read_whole_with_its_time(serve):
    url = serve(b"y" * 3000, chunk=1000, pause=0)
    resp = HttpxTransport(timeout=5.0)("GET", url, {})
    assert resp.status_code == 200 and resp.content == b"y" * 3000 and resp.text == "y" * 3000
    assert resp.elapsed.total_seconds() >= 0                       # the timing proof still has it (VER-011)


def test_an_oversized_answer_ends_the_request(serve):
    url = serve(b"z" * 50_000, chunk=10_000, pause=0)
    with pytest.raises(ResponseTooLarge):
        HttpxTransport(timeout=5.0, max_bytes=20_000)("GET", url, {})


def test_a_compressed_answer_is_bounded_by_its_decoded_size(serve):
    url = serve(gzip.compress(b"\0" * 2_000_000), chunk=4096, pause=0, headers=[("Content-Encoding", "gzip")])
    with pytest.raises(ResponseTooLarge):
        HttpxTransport(timeout=5.0, max_bytes=100_000)("GET", url, {})


def test_the_agent_sees_an_oversized_answer_as_a_failed_request():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"a" * 5000)))
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits(rate_rps=0)),
                             HttpxTransport(client=client, max_bytes=1000))
    with pytest.raises(ToolError, match="request failed: ResponseTooLarge"):
        AgentTools(_ctx(http=http)).call("http_request", {"path": "/big"})


# ── tool failures reach the agent as tool errors (VER-017) ─────────────────────

def _ctx(*, http=None, sessions=None, source=None):
    return SimpleNamespace(plan=SimpleNamespace(cls="access-control", id="F"), scope=SCOPE, safe=True,
                           read_only=True, http=http, target_base=BASE, sessions=sessions, listener=None,
                           source=source, browser=None, marker=("a", "b"))


def test_a_login_that_cannot_connect_is_a_tool_error_the_agent_sees():
    class Planner:
        def next_step(self, ctx, history):
            if not history:
                return {"tool": "http_request", "args": {"role": "alice", "path": "/rest/basket/1"}}
            return {"verdict": {"verdict": "inconclusive", "rationale": history[-1]["result"]["error"]}}

    log = []
    target = Target({("POST", LOGIN): httpx.ConnectError(f"proxy http://u:{SECRET}@p")}, default=Resp())
    doc, _ = _run(agent_registry(Planner), plans=_plans(1), target=target, identities=[FORM], log=log.append)
    rationale = doc["results"][0]["rationale"]
    assert "identity 'alice' is unavailable: its login failed (ConnectError)" in rationale and SECRET not in rationale
    assert [r.get("tool") for r in log if r.get("step") == 1] == ["http_request"]   # the step is in the action log


def test_a_source_path_the_file_system_cannot_use_is_a_tool_error(tmp_path):
    (tmp_path / "a.ts").write_text("x\n")
    tools = AgentTools(_ctx(source=SourceReader(tmp_path)))
    for path in ("a\x00.ts", "x" * 5000):
        with pytest.raises(ToolError):
            tools.call("read_source", {"path": path})


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file")
def test_an_unreadable_source_file_is_a_tool_error(tmp_path):
    (tmp_path / "b.ts").write_text("y")
    (tmp_path / "b.ts").chmod(0)
    with pytest.raises(ToolError, match="cannot read 'b.ts': PermissionError"):
        AgentTools(_ctx(source=SourceReader(tmp_path))).call("read_source", {"path": "b.ts"})


# ── a failed probe leaves its type and place in the action log ─────────────────

def test_a_failed_probe_logs_type_and_place_but_not_its_message():
    class Broken:
        def run(self, ctx):
            raise ValueError(f"token {SECRET}")

    log = []
    doc, _ = _run(ProbeRegistry({"access-control": Broken()}), plans=_plans(1), log=log.append)
    assert doc["results"][0]["rationale"] == "probe failed: ValueError"
    (record,) = log
    assert record["probe_failed"] == "ValueError" and record["at"].startswith("verify/runner.py:")
    assert SECRET not in json.dumps(log)


# ── a run-wide limit or a failing host ends the run (VER-015) ──────────────────

class FakeHost:
    label, model = "Fake host", "m"

    def __init__(self, *replies):
        self.replies, self.calls, self.broken = list(replies), 0, None

    def call(self, system, prompt, timeout, budget):
        self.calls += 1
        return self.replies[min(self.calls, len(self.replies)) - 1]


def test_after_the_request_cap_no_finding_asks_the_model_again():
    host = FakeHost(HostReply(step={"action": "http_request", "args_json": '{"path": "/a"}'}, usd=0.0))
    target = Target(default=Resp())
    doc, budget = _run(agent_registry(lambda: HostPlanner(host)), limits=Limits(max_requests=2, rate_rps=0),
                       target=target)
    assert len(target.calls) == 2 and budget.requests == 2 and host.calls == 2
    assert [(r["verdict"], r["limits_hit"]) for r in doc["results"]] == [("inconclusive", "requests")] + [
        ("not-attempted", "requests")] * 4
    assert "limit was reached by an earlier finding" in doc["results"][1]["rationale"]


def test_a_refused_request_is_not_counted():
    budget = RunBudget(Limits(max_requests=1, rate_rps=0))
    budget.note_request()
    with pytest.raises(LimitExceeded):
        budget.note_request()
    assert budget.requests == 1


def test_a_host_that_keeps_failing_is_not_called_for_the_rest_of_the_run():
    host = FakeHost(HostReply(error="quota_exhausted (exit 1)"))
    doc, _ = _run(agent_registry(lambda: HostPlanner(host)))
    assert host.calls == MAX_FAILED_CALLS and "calls in a row failed" in host.broken
    assert all(r["verdict"] == "inconclusive" for r in doc["results"])


def test_a_success_between_failures_keeps_the_host():
    fail = HostReply(error="rate_limit (exit 1)")
    ok = HostReply(step={"action": "submit_verdict", "args_json": '{"verdict": "inconclusive", "rationale": "x"}'})
    host = FakeHost(fail, fail, ok, fail, fail)
    _run(agent_registry(lambda: HostPlanner(host)))
    assert host.broken is None and host.calls == 5


@pytest.mark.parametrize("cost", ["NaN", "-1"])
def test_an_unusable_cost_stops_every_further_model_call(cost):
    init = {"type": "system", "subtype": "init", "tools": ["StructuredOutput"]}
    final = f'{{"type": "result", "total_cost_usd": {cost}, "structured_output": {{}}}}'
    host = ClaudeHost("claude", "v", model="m", auth="login", environ={},
                      run=lambda argv, **kw: (0, json.dumps(init) + "\n" + final + "\n", ""))
    budget = RunBudget(Limits(cost_limit_usd=1.0))
    ctx = SimpleNamespace(plan=_plans(1)[0], identities=[{"role": "alice"}], target_base=BASE, safe=True,
                          budget=budget)
    with pytest.raises(LimitExceeded, match="no usable cost"):
        HostPlanner(host).next_step(ctx, [])
    with pytest.raises(LimitExceeded):
        budget.note_cost(0.0)
    assert not math.isnan(budget.cost)


# ── a dead proof browser is started again (VER-009) ────────────────────────────

def test_a_crashed_browser_is_a_tool_error_and_starts_again(monkeypatch):
    class PlaywrightError(Exception):
        pass

    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(Error=PlaywrightError))
    launches = []

    class Dead:
        def new_context(self, **kw):
            raise PlaywrightError("Target page, context or browser has been closed")

        def close(self):
            pass

    def launcher(headless):
        launches.append(1)
        return SimpleNamespace(stop=lambda: None), Dead()

    browser = ProofBrowser(None, Path("unused"), launcher=launcher)
    kw = {"identity_headers": {}, "target_base": BASE, "marker": ("vrfa", "b"), "finding_id": "F", "wait_ms": 0,
          "safe": True}
    with pytest.raises(BrowserError, match="starts again on next use"):
        browser.check(BASE + "/", **kw)
    with pytest.raises(BrowserError):
        browser.check(BASE + "/", **kw)
    assert len(launches) == 2
    ctx = _ctx()
    ctx.plan.cls, ctx.browser = "xss", browser
    with pytest.raises(ToolError, match="the proof browser failed"):
        AgentTools(ctx).call("browser_check", {"path": "/"})


# ── logins are not repeated without need (VER-028) ─────────────────────────────

def _login_tools(target):
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits(rate_rps=0)), target)
    return AgentTools(_ctx(http=http, sessions=SessionManager([FORM], http, env=ENV)))


def test_a_401_that_a_new_login_does_not_change_logs_in_only_once():
    target = Target({("POST", LOGIN): Resp(200, {"token": "T0K3N"}), ("GET", f"{BASE}/admin"): Resp(401)})
    tools = _login_tools(target)
    for _ in range(3):
        assert tools.call("http_request", {"role": "alice", "path": "/admin"})["status"] == 401
    assert [m for m, _ in target.calls] == ["POST", "GET", "POST", "GET", "GET", "GET"]


def test_an_expired_session_is_renewed_again_after_an_accepted_request():
    pages, sent = iter([401, 401, 200, 401, 200]), []

    def transport(method, url, headers, **kw):
        sent.append(method)
        return Resp(200, {"token": "T0K3N"}) if method == "POST" else Resp(next(pages))

    tools = _login_tools(transport)
    tools.call("http_request", {"role": "alice", "path": "/x"})     # 401, new login, 401 again
    tools.call("http_request", {"role": "alice", "path": "/x"})     # 200 without a login: the session works
    tools.call("http_request", {"role": "alice", "path": "/x"})     # 401 (expired), new login, 200
    assert sent == ["POST", "GET", "POST", "GET", "GET", "GET", "POST", "GET"]


def test_a_refused_login_is_not_tried_again_in_the_run():
    target = Target({("POST", LOGIN): Resp(200, {})}, default=Resp())
    tools = _login_tools(target)
    with pytest.raises(ToolError, match="did not return a recognisable token"):
        tools.call("http_request", {"role": "alice", "path": "/x"})
    for _ in range(2):
        with pytest.raises(ToolError, match="recognisable token .*; not tried again in this run"):
            tools.call("http_request", {"role": "alice", "path": "/x"})
    assert target.calls == [("POST", LOGIN)]


# ── files are replaced atomically (VER-020, VER-027) ───────────────────────────

def test_a_failed_in_place_write_leaves_the_assessment_whole(tmp_path, monkeypatch):
    real_replace = os.replace

    def replace(src, dst):
        if Path(dst).name == "a.yaml":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_replace(src, dst)

    monkeypatch.setattr(report.os, "replace", replace)
    with pytest.raises(OSError):
        _verify(tmp_path, monkeypatch, Checked, "--annotate", "--in-place")
    assert yaml.safe_load((tmp_path / "a.yaml").read_text()) == {"threats": THREATS}
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_annotating_in_place_keeps_the_analyzers_verification_block(tmp_path, monkeypatch):
    block = {"finding_ids": ["TCF-001"], "test_case_ids": ["TC-IDOR-01"]}   # AppSec Analyzer REQ-040
    threats = [dict(t, verification=block) for t in THREATS]
    assert _verify(tmp_path, monkeypatch, Checked, "--annotate", "--in-place", threats=threats)[0] == cli.EXIT_OK
    annotated = yaml.safe_load((tmp_path / "a.yaml").read_text())
    assert [t["verification"] for t in annotated["threats"]] == [block] * len(THREATS)
    assert all(t["dynamic_verification"]["verdict"] == "not-attempted" for t in annotated["threats"])
    assert annotated["dynamic_verification"]["verification_report"] == str(tmp_path / "out" / "verification.yaml")


def test_a_replaced_file_keeps_its_permissions(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("old")
    path.chmod(0o640)
    report.write_text_atomically(path, "new")
    assert path.read_text() == "new" and (path.stat().st_mode & 0o777) == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["a.yaml"]


# ── a missing preparation is named before the run, not found in the report ─────

def _dynamic(cls):
    return FindingPlan(id="T-1", cwe="CWE-22", severity="High", title="t", match_key="k", instance="a.ts:1",
                       status="dynamic", cls=cls, reason="r")


def test_path_traversal_without_marker_file_is_named_and_the_content_never_shown():
    sel = [_dynamic("path-traversal")]
    assert cli._marker_note({}, sel).startswith("unavailable (no marker_file in the scope)")
    note = cli._marker_note({"marker_file": {"path": "/srv/m.txt", "content": "TOKEN-1234567890ab"}}, sel)
    assert note.startswith("/srv/m.txt") and "TOKEN" not in note
    assert cli._marker_note({}, [_dynamic("xss")]) is None


def test_access_control_without_a_test_identity_is_named():
    sel = [_dynamic("access-control")]
    assert cli._identities_note([], sel).startswith("unavailable (no test identity)")
    assert cli._identities_note([{"role": "alice"}, {"role": "bob"}], sel) == "alice, bob"
    assert cli._identities_note([], [_dynamic("xss")]) is None


def test_the_run_settings_name_a_missing_identity_before_anything_is_contacted(tmp_path, monkeypatch, capsys):
    rc, target = _verify(tmp_path, monkeypatch, Checked, "--dry-run")
    assert rc == cli.EXIT_OK and target.calls == []
    assert "  Identities : unavailable (no test identity); access-control findings cannot be confirmed" in (
        capsys.readouterr().out)
