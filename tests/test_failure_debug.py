"""The private debug file of failed verifications (VER-063): which findings it keeps, what it holds of each, that
credential values and the marker file's content never reach it, and that the closing message names it. Offline:
fake hosts, planners and targets."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import httpx
import yaml

from appsec_verifier import cli
from appsec_verifier.agent.hosts import MAX_FAILED_CALLS, HostPlanner, HostReply
from appsec_verifier.agent.registry import agent_registry
from appsec_verifier.auth import SessionManager
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, httpx_transport
from appsec_verifier.verify.failure_debug import FILE_NAME, FailureDebug, failure, run_identity
from appsec_verifier.verify.probes import ProbeRegistry, ProbeResult
from appsec_verifier.verify.runner import run_verification

BASE = "https://app.example.com"
SCOPE = {"schema_version": 1, "base_url": BASE, "owner": {"name": "tester"},
         "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
SECRET = "s3cr3t-pa55"
MARKER = "marker-file-content-91f3"
IDENTITY = {"role": "alice", "method": "form",
            "auth": {"login_url": f"{BASE}/login", "username_env": "AU", "password_env": "AP"}}
ENV = {"AU": "alice@example.com", "AP": SECRET}
RUN = {"verifier_version": "t", "profile": "anthropic-api", "model": "m"}


class Resp:
    status_code, headers, text = 200, {}, "ok"

    def json(self):
        raise ValueError("no json")


class Target:
    def __init__(self, error=None):
        self.error = error

    def __call__(self, method, url, headers, **kw):
        if self.error is not None:
            raise self.error
        return Resp()


class FakeHost:
    """Answers every call, a finding's steps and the technical QA's reviews alike, with the next reply."""

    label, model = "Fake host", "m"

    def __init__(self, *replies):
        self.replies, self.calls, self.broken = list(replies), 0, None

    def call(self, system, prompt, timeout, budget, *, schema=None):
        self.calls += 1
        return self.replies[min(self.calls, len(self.replies)) - 1]


def _plans(n=1):
    return [FindingPlan(id=f"F{i}", cwe="CWE-639", severity="high", title="t", match_key="k", instance="a.ts:1",
                        status="dynamic", cls="access-control", reason="",
                        endpoints=(Endpoint("GET", "/a", None),))
            for i in range(n)]


def _run(tmp_path, registry, *, plans=None, limits=None, target=None, scope=SCOPE):
    budget = RunBudget(limits or Limits(rate_rps=0))
    http = GuardedHttpClient(ScopeGuard(scope), budget, target or Target())
    sessions = SessionManager([IDENTITY], http, env=ENV)
    debug = FailureDebug(tmp_path, run=RUN, redact=sessions.redact,
                         hidden=(scope.get("marker_file") or {}).get("content"))
    doc = run_verification(assessment_path=Path("a"), scope=scope, scope_path=Path("s"), plans=plans or _plans(),
                           limits=budget.limits, identities=[{"role": "alice"}], registry=registry,
                           verifier_version="t", target_base=BASE, authorization={}, http=http, sessions=sessions,
                           budget=budget, failures=debug)
    return doc, debug


def _read(tmp_path) -> dict:
    return json.loads((tmp_path / FILE_NAME).read_text(encoding="utf-8"))


# ── what counts as a failed verification ──────────────────────────────────────

def test_an_error_a_failed_model_call_and_stagnation_are_failures():
    try:
        raise KeyError("boom")
    except KeyError as exc:
        error = exc
    assert failure(None, ProbeResult(verdict="inconclusive", rationale="probe failed: KeyError"), error)["kind"] \
        == "error"
    model = type("Ctx", (), {"model_failure": "Fake host call failed: timeout"})()
    assert failure(model, ProbeResult(verdict="inconclusive", rationale="x"))["kind"] == "model"
    stopped = ProbeResult(verdict="inconclusive", rationale="stopped: repeated tool failures", limits_hit="stagnation")
    assert failure(None, stopped) == {"kind": "stagnation", "message": "stopped: repeated tool failures"}


def test_a_limit_a_verdict_and_a_test_without_sufficient_proof_are_no_failures():
    model = type("Ctx", (), {"model_failure": "Fake host call failed: timeout"})()
    assert failure(None, ProbeResult(verdict="inconclusive", rationale="restriction not established")) is None
    assert failure(model, ProbeResult(verdict="inconclusive", rationale="x", limits_hit="requests")) is None
    assert failure(model, ProbeResult(verdict="confirmed", rationale="x")) is None   # a later answer succeeded
    assert failure(None, ProbeResult(verdict="not-reproducible", rationale="x")) is None


# ── what the file holds ───────────────────────────────────────────────────────

def test_a_failed_probe_keeps_its_message_traceback_and_code_redacted_and_private(tmp_path):
    class Broken:
        def run(self, ctx):
            raise ValueError(f"token {SECRET} and {MARKER}")

    scope = {**SCOPE, "marker_file": {"path": "/etc/marker", "content": MARKER}}
    doc, debug = _run(tmp_path, ProbeRegistry({"access-control": Broken()}), scope=scope)
    assert doc["results"][0]["rationale"] == "probe failed: ValueError"
    path = tmp_path / FILE_NAME
    assert debug.written == 1 and stat.S_IMODE(path.stat().st_mode) == 0o600
    text = path.read_text(encoding="utf-8")
    assert SECRET not in text and MARKER not in text
    data = json.loads(text)
    assert data["kind"] == "appsec-verifier failed verifications" and data["run"] == RUN
    assert data["action_log"] == "agent-log.jsonl" and "reading_guide" in data
    entry, = data["findings"]
    assert entry["finding"] == "F0" and entry["rationale"] == "probe failed: ValueError"
    why = entry["failure"]
    assert why["kind"] == "error" and why["type"] == "ValueError" and why["message"].startswith("token [")
    assert why["location"].startswith("verify/runner.py:") and why["traceback"][-1]["function"] == "run"
    assert "def _verify_one" in data["code"][why["location"]]["code"]


def test_a_failing_model_host_keeps_every_call_with_its_prompt_and_failure(tmp_path):
    host = FakeHost(HostReply(error="quota_exhausted (exit 1)"))
    doc, debug = _run(tmp_path, agent_registry(lambda: HostPlanner(host)), plans=_plans(MAX_FAILED_CALLS + 1))
    assert all(r["verdict"] == "inconclusive" for r in doc["results"])
    data = _read(tmp_path)
    assert [e["failure"]["kind"] for e in data["findings"]] == ["model"] * (MAX_FAILED_CALLS + 1)
    first, *_, last = data["findings"]
    assert first["failure"]["message"] == "Fake host call failed: quota_exhausted (exit 1)"
    call = first["calls"][0]
    assert call["call"] == "step" and call["failure"] == "quota_exhausted (exit 1)" and "answer" not in call
    assert call["prompt"] and call["instructions_sha256"] in data["instructions"]
    assert call["schema_sha256"] in data["schemas"] and isinstance(call["seconds"], float)
    # once the host is stopped for the run, a finding fails without a call
    assert "stopped for this run" in last["failure"]["message"] and last["calls"] == []


def test_an_answer_that_is_no_step_is_kept_with_the_answer(tmp_path):
    host = FakeHost(HostReply(step={"text": f"I tried {SECRET}"}, usd=0.01))
    _run(tmp_path, agent_registry(lambda: HostPlanner(host)))
    entry, = _read(tmp_path)["findings"]
    assert entry["failure"] == {"kind": "model",
                                "message": "agent reply is not a single {action, args_json, note} step"}
    answer = entry["calls"][0]["answer"]["text"]
    assert answer.startswith("I tried [") and SECRET not in json.dumps(entry)
    assert entry["calls"][0]["usd"] == 0.01


def test_a_confinement_breach_is_a_failure(tmp_path):
    step = {"action": "submit_verdict", "args_json": '{"verdict": "inconclusive", "rationale": "x"}'}
    host = FakeHost(HostReply(step=step, breach="the CLI used the tool Bash"))
    _run(tmp_path, agent_registry(lambda: HostPlanner(host)))
    entry, = _read(tmp_path)["findings"]
    assert entry["failure"]["kind"] == "model" and "confinement check failed" in entry["failure"]["message"]
    assert entry["calls"][0]["failure"] == "the CLI used the tool Bash"


def test_a_test_agent_stopped_without_progress_is_a_failure(tmp_path):
    class Retries:
        def next_step(self, ctx, history):
            return {"tool": "http_request", "args": {"path": "/a"}, "note": "read"}

    doc, _ = _run(tmp_path, agent_registry(Retries), target=Target(httpx.ConnectError("refused")))
    assert doc["results"][0]["limits_hit"] == "stagnation"
    entry, = _read(tmp_path)["findings"]
    assert entry["failure"]["kind"] == "stagnation" and entry["calls"] == []


def test_a_run_without_failures_writes_no_file_and_removes_an_earlier_one(tmp_path):
    (tmp_path / FILE_NAME).write_text("{}")
    step = {"action": "submit_verdict", "args_json": '{"verdict": "inconclusive", "rationale": "no proof"}'}
    _, debug = _run(tmp_path, agent_registry(lambda: HostPlanner(FakeHost(HostReply(step=step)))))
    assert debug.written == 0 and not (tmp_path / FILE_NAME).exists()


def test_a_limit_is_no_failure(tmp_path):
    host = FakeHost(HostReply(step={"action": "http_request", "args_json": '{"path": "/a"}'}, usd=0.0))
    doc, debug = _run(tmp_path, agent_registry(lambda: HostPlanner(host)), limits=Limits(max_requests=1, rate_rps=0))
    assert doc["results"][0]["limits_hit"] == "requests" and debug.written == 0


def test_a_file_that_cannot_be_written_never_changes_the_run(tmp_path, capsys):
    class Broken:
        def run(self, ctx):
            raise ValueError("x")

    missing = tmp_path / "gone"
    debug = FailureDebug(missing, run=RUN)
    budget = RunBudget(Limits(rate_rps=0))
    doc = run_verification(assessment_path=Path("a"), scope=SCOPE, scope_path=Path("s"), plans=_plans(2),
                           limits=budget.limits, identities=[], registry=ProbeRegistry({"access-control": Broken()}),
                           verifier_version="t", target_base=BASE, authorization={}, budget=budget, failures=debug)
    assert [r["verdict"] for r in doc["results"]] == ["inconclusive", "inconclusive"]
    assert debug.disabled and debug.written == 0
    assert capsys.readouterr().err.count("debug file not written (FileNotFoundError)") == 1


def test_the_run_identity_names_only_selected_fields(tmp_path):
    assessment = tmp_path / "a.yaml"
    assessment.write_text("threats: []\n")
    agent = {"profile": "claude", "model": "m", "runtime": "Claude CLI 2.1", "auth": "login", "check": "x"}
    run = run_identity(verifier_version="1.0", agent=agent, assessment=assessment, target=BASE, safe=True,
                       read_only=True)
    assert set(run) == {"started", "verifier_version", "profile", "model", "runtime", "mode", "read_only", "target",
                        "assessment", "assessment_sha256"}
    assert run["mode"] == "safe" and len(run["assessment_sha256"]) == 64


# ── the closing message names the file ────────────────────────────────────────

def test_verify_names_the_debug_file_only_when_a_test_failed(tmp_path, monkeypatch, capsys):
    host = FakeHost(HostReply(error="quota_exhausted (exit 1)"))

    class Checked:
        def next_step(self, ctx, history):
            return {"verdict": {"verdict": "not-attempted", "rationale": "checked"}}

    assessment = tmp_path / "a.yaml"
    assessment.write_text(yaml.safe_dump({"threats": [{"id": "T-1", "cwe": "CWE-639", "severity": "high",
                                                        "title": "idor", "evidence": {"file": "a.ts", "line": 1}}]}))
    scope = tmp_path / "s.yaml"
    scope.write_text(yaml.safe_dump(SCOPE))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: Target())
    argv = ["verify", "--assessment", str(assessment), "--scope", str(scope), "--yes", "--test-all",
            "--output", str(tmp_path / "out"), "--rate", "0", "--screenshots", "none"]
    info = {"profile": "anthropic-api", "model": "m", "runtime": "Anthropic API", "auth": "API key", "check": "x"}

    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (lambda: HostPlanner(host), dict(info)))
    cli.main(argv)
    out = capsys.readouterr().out
    path = tmp_path / "out" / FILE_NAME
    assert f"{path} (private: why the test of 1 finding failed)" in out
    data = json.loads(path.read_text())
    assert data["run"]["target"] == BASE and data["findings"][0]["failure"]["kind"] == "model"
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert report["results"][0]["rationale"] == "Fake host call failed: quota_exhausted (exit 1)"
    assert FILE_NAME not in (tmp_path / "out" / "verification.md").read_text()

    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Checked, dict(info)))
    cli.main([*argv, "--overwrite"])
    assert FILE_NAME not in capsys.readouterr().out and not path.exists()
