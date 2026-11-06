"""Run budget stops on exhausted request, cost, and time bounds (VER-015)."""

from __future__ import annotations

import pytest

from appsec_verifier.limits import Limits, LimitExceeded, RunBudget


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


def test_overrides_apply():
    lim = Limits.load({"cost_limit_usd": 3.0, "rate_rps": None})
    assert lim.cost_limit_usd == 3.0  # override applied
    assert lim.rate_rps > 0           # None override ignored, default kept
