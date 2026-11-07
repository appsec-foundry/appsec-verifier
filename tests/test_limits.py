"""Run budget stops on exhausted request, cost, and time bounds (VER-015)."""

from __future__ import annotations

import pytest

from appsec_verifier.limits import LimitExceeded, Limits, RunBudget


def test_request_cap_stops():
    b = RunBudget(Limits(max_requests=2))
    b.note_request()
    b.note_request()
    with pytest.raises(LimitExceeded) as e:
        b.note_request()
    assert e.value.kind == "requests"


def test_cost_ceiling_stops():
    b = RunBudget(Limits(cost_limit_usd=1.0))
    b.note_cost(0.6)
    with pytest.raises(LimitExceeded) as e:
        b.note_cost(0.6)
    assert e.value.kind == "cost"


def test_time_budget_stops():
    ticks = iter([0, 0, 100])  # start, ok-check, over-budget check
    b = RunBudget(Limits(max_duration_s=50), clock=lambda: next(ticks))
    b.check_time()  # 0 elapsed — fine
    with pytest.raises(LimitExceeded) as e:
        b.check_time()  # 100s elapsed — over 50
    assert e.value.kind == "time"


def test_defaults_load_from_data_file():
    lim = Limits.load()
    assert lim.max_requests > 0 and lim.cost_limit_usd > 0
    assert lim.max_attempts == Limits().max_attempts == 12


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(round(seconds, 6))
        self.now += seconds


def test_pace_spaces_requests_at_the_rate():
    clock = FakeClock()
    b = RunBudget(Limits(rate_rps=4), clock=clock, sleep=clock.sleep)
    for _ in range(3):
        b.pace()
    assert clock.slept == [0.25, 0.25]
    clock.now += 10          # a long pause earns no burst: the next request goes at once, the one after waits
    b.pace()
    b.pace()
    assert clock.slept == [0.25, 0.25, 0.25]


def test_pace_without_a_rate_never_waits():
    clock = FakeClock()
    b = RunBudget(Limits(rate_rps=0), clock=clock, sleep=clock.sleep)
    b.pace()
    b.pace()
    assert clock.slept == []


def test_max_attempts_bounds_the_agent_steps_per_finding(tmp_path, monkeypatch):
    """--max-attempts reaches the agent loop: no planner call beyond the cap, and the
    finding ends inconclusive with limits_hit 'attempts' (exit 3)."""
    import yaml

    from appsec_verifier import cli

    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(scope))
    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor",
         "evidence": {"file": "routes/basket.ts", "line": 1}}]}))
    asked = []

    class Planner:      # never submits; read_source without --source is a tool error, nothing is contacted
        def next_step(self, ctx, history):
            asked.append(1)
            return {"tool": "read_source", "args": {"path": "routes/basket.ts"}}

    def no_network(*a, **k):
        raise AssertionError("the test reached the transport")

    from appsec_verifier.tools import httpx_transport

    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: no_network)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope",
                   str(tmp_path / "scope.yaml"), "--output", str(tmp_path / "out"), "--yes",
                   "--max-attempts", "3"])
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert rc == 3 and len(asked) == 3
    assert report["results"][0]["limits_hit"] == "attempts"


def test_overrides_apply():
    lim = Limits.load({"cost_limit_usd": 3.0, "rate_rps": None})
    assert lim.cost_limit_usd == 3.0  # override applied
    assert lim.rate_rps > 0           # None override ignored, default kept
