"""The action log records every agent step, refused ones included, owner-only,
one JSON object per line, redacted of credential values (VER-017, VER-016)."""

from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from types import SimpleNamespace

import yaml

from appsec_verifier import cli
from appsec_verifier.verify.actionlog import ActionLog

CLOCK = lambda: datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)  # noqa: E731


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_records_are_redacted_one_per_line_and_owner_only(tmp_path):
    path = tmp_path / "agent-log.jsonl"
    log = ActionLog(path, redact=lambda r: json.loads(json.dumps(r).replace("s3cret-token", "[redacted]")),
                    clock=CLOCK)
    log({"finding": "T-1", "step": 1, "tool": "http_request", "args": {"path": "/a\n{\"forged\": true}"}})
    log({"finding": "T-1", "step": 2, "refused": "bad", "proposal": "Bearer s3cret-token"})
    log.close()
    records = _lines(path)
    assert len(records) == 2                                  # a newline in a value cannot add a record
    assert records[0]["time"] == "2026-11-07T12:00:00Z" and records[0]["args"]["path"].startswith("/a\n")
    assert "s3cret-token" not in path.read_text() and records[1]["proposal"] == "Bearer [redacted]"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_append_keeps_earlier_records_and_a_new_run_starts_fresh(tmp_path):
    path = tmp_path / "agent-log.jsonl"
    path.write_text('{"old": 1}\n')
    path.chmod(0o644)
    log = ActionLog(path, append=True, clock=CLOCK)
    log({"new": 1})
    log.close()
    assert [r.get("old", r.get("new")) for r in _lines(path)] == [1, 1]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    log = ActionLog(path, clock=CLOCK)
    log({"fresh": 1})
    log.close()
    assert [list(r)[-1] for r in _lines(path)] == ["fresh"]


def test_verify_writes_the_log_with_the_refused_request(tmp_path, monkeypatch):
    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(scope))
    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor",
         "evidence": {"file": "routes/basket.ts", "line": 1}}]}))

    class Planner:      # one request the guard refuses before any connection, then a verdict
        def next_step(self, ctx, history):
            if not history:
                return {"tool": "http_request", "args": {"path": "/rest/%2e%2e/admin"}}
            return {"verdict": {"verdict": "inconclusive", "rationale": "refused"}}

    def no_network(method, url, headers, **k):    # only the pre-flight GET of the target is answered (VER-032)
        if (method, url) == ("GET", "https://app.example.com"):
            return SimpleNamespace(status_code=200, headers={})
        raise AssertionError("the test reached the transport")

    from appsec_verifier.tools import httpx_transport

    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: no_network)
    cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope", str(tmp_path / "scope.yaml"),
              "--output", str(tmp_path / "out"), "--yes", "--test-all"])
    path = tmp_path / "out" / "agent-log.jsonl"
    first, last, review = _lines(path)
    assert review["finding"] == "T-1" and review["evidence_review"] == "quality"
    assert review["detail"].startswith("not-reviewed:")
    assert first["finding"] == "T-1" and first["tool"] == "http_request"
    assert first["args"] == {"path": "/rest/%2e%2e/admin"} and "out of scope" in first["result"]["error"]
    assert last["verdict"] == "inconclusive" and last["step"] == 2
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
