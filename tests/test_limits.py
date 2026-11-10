"""Run budget stops on exhausted request, cost, and time bounds (VER-015)."""

from __future__ import annotations

from types import SimpleNamespace

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


def test_per_finding_cap_stops_the_finding_and_resets_between_findings():
    """VER-051: a single finding is bounded to its share of the run ceiling, and the next finding starts fresh."""
    b = RunBudget(Limits(cost_limit_usd=10.0))        # cap = max(0.50, 10 * 0.25) = 2.50
    assert b.finding_cost_cap() == 2.50
    b.begin_finding()
    b.note_cost(2.0)
    b.check_finding_cost()                            # under the per-finding cap: fine
    b.note_cost(0.6)                                  # 2.6 spent on this finding, over 2.50
    with pytest.raises(LimitExceeded) as e:
        b.check_finding_cost()
    assert e.value.kind == "finding-cost"
    from appsec_verifier.verify.report import RUN_LIMITS
    assert "finding-cost" not in RUN_LIMITS           # finding-local: the run continues with the next finding
    b.begin_finding()                                 # the next finding starts fresh despite the run's prior spend
    b.check_finding_cost()


def test_per_finding_floor_applies_on_a_small_run_budget():
    b = RunBudget(Limits(cost_limit_usd=1.0))         # 1 * 0.25 = 0.25, below the 0.50 floor -> cap 0.50
    assert b.finding_cost_cap() == 0.50


def test_per_finding_cap_is_off_when_the_share_is_zero():
    b = RunBudget(Limits(finding_cost_fraction=0))
    assert b.finding_cost_cap() is None
    b.begin_finding()
    b.note_cost(5.0)
    b.check_finding_cost()                            # off: never raises


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
            return {"tool": "read_source", "args": {"path": f"routes/basket-{len(asked)}.ts"}}

    def no_network(method, url, headers, **k):    # only the pre-flight GET of the target is answered (VER-032)
        if (method, url) == ("GET", "https://app.example.com"):
            return SimpleNamespace(status_code=200, headers={})
        raise AssertionError("the test reached the transport")

    from appsec_verifier.tools import httpx_transport

    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: no_network)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope",
                   str(tmp_path / "scope.yaml"), "--output", str(tmp_path / "out"), "--yes",
                   "--max-attempts", "3", "--test-all"])
    report = yaml.safe_load((tmp_path / "out" / "verification.yaml").read_text())
    assert rc == 3 and len(asked) == 3
    assert report["results"][0]["limits_hit"] == "attempts"


@pytest.mark.parametrize("field, value", [
    ("rate_rps", -1), ("max_requests", 0), ("max_requests", -5), ("max_attempts", 0), ("max_calls", 0),
    ("max_duration_s", 0), ("max_duration_s", -1.0), ("cost_limit_usd", 0), ("cost_limit_usd", float("inf")),
    ("rate_rps", float("nan")), ("max_requests", 2.5), ("max_requests", True), ("rate_rps", "5"),
    ("finding_cost_fraction", -1), ("min_finding_cost_usd", -0.5),
])
def test_invalid_limits_are_refused(field, value):
    """No bound is switched off by a sign, a zero cap or a wrong type (VER-015)."""
    with pytest.raises(ValueError, match=field):
        Limits(**{field: value})


def test_unknown_key_in_limits_file_is_refused(tmp_path, monkeypatch):
    from appsec_verifier import limits as limits_module

    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "limits.yaml").write_text("limits:\n  max_request: 10\n")    # typo: the cap would be lost
    monkeypatch.setattr(limits_module, "resource_root", lambda: tmp_path)
    with pytest.raises(ValueError, match="max_request"):
        Limits.load()


def test_shipped_limits_file_names_only_enforced_limits():
    import yaml

    from appsec_verifier.version_info import resource_root

    doc = yaml.safe_load((resource_root() / "data" / "limits.yaml").read_text())["limits"]
    assert set(doc) == set(Limits.__dataclass_fields__)


@pytest.mark.parametrize("flag, value", [("--rate", "-1"), ("--max-requests", "0"), ("--max-duration", "-5")])
def test_cli_blocks_on_an_invalid_limit_before_contact(tmp_path, monkeypatch, capsys, flag, value):
    import yaml

    from appsec_verifier import cli
    from appsec_verifier.tools import httpx_transport

    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(scope))
    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor",
         "evidence": {"file": "routes/basket.ts", "line": 1}}]}))

    def no_network(*a, **k):
        raise AssertionError("the test reached the transport")

    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: no_network)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope",
                   str(tmp_path / "scope.yaml"), "--output", str(tmp_path / "out"), "--yes", "--profile",
                   "anthropic-api", flag, value])
    assert rc == 2 and "Invalid limits" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_overrides_apply():
    lim = Limits.load({"cost_limit_usd": 3.0, "rate_rps": None})
    assert lim.cost_limit_usd == 3.0  # override applied
    assert lim.rate_rps > 0           # None override ignored, default kept
