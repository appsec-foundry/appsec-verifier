"""Execution bounds enforced outside the model (VER-015): total requests, cost,
and wall-clock time. Reaching a bound raises LimitExceeded so the caller stops
the affected work rather than pressing on.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import yaml

from .version_info import resource_root


class LimitExceeded(Exception):
    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind = kind  # "requests" | "cost" | "time" | "attempts" | "calls" | "window"


@dataclass
class Limits:
    cost_limit_usd: float = 10.0
    max_requests: int = 2000
    max_attempts: int = 40
    max_calls: int = 500
    max_duration_s: float = 1800
    rate_rps: float = 5

    @classmethod
    def load(cls, overrides: dict | None = None) -> Limits:
        """Defaults from data/limits.yaml, with any provided overrides applied."""
        with open(resource_root() / "data" / "limits.yaml", encoding="utf-8") as fh:
            doc = (yaml.safe_load(fh) or {}).get("limits", {})
        base = {f: doc[f] for f in cls.__dataclass_fields__ if f in doc}
        base.update({k: v for k, v in (overrides or {}).items() if v is not None})
        return cls(**base)


class RunBudget:
    """Tracks consumption against the limits. `clock` is injectable for tests."""

    def __init__(self, limits: Limits, clock=time.monotonic):
        self.limits = limits
        self._clock = clock
        self.start = clock()
        self.requests = 0
        self.cost = 0.0
        self.calls = 0

    def note_call(self) -> None:
        """Count one model call; refuse it once the run's call cap is reached."""
        if self.limits.max_calls and self.calls >= self.limits.max_calls:
            raise LimitExceeded("calls", f"model call cap {self.limits.max_calls} reached")
        self.calls += 1

    def remaining_cost(self) -> float | None:
        """USD left under the cost ceiling, or None when it is unbounded."""
        if not self.limits.cost_limit_usd:
            return None
        return max(0.0, self.limits.cost_limit_usd - self.cost)

    def note_request(self) -> None:
        self.requests += 1
        if self.limits.max_requests and self.requests > self.limits.max_requests:
            raise LimitExceeded("requests", f"request cap {self.limits.max_requests} exceeded")

    def note_cost(self, usd: float) -> None:
        self.cost += usd
        if self.limits.cost_limit_usd and self.cost > self.limits.cost_limit_usd:
            raise LimitExceeded("cost", f"cost ceiling ${self.limits.cost_limit_usd:.2f} exceeded")

    def check_time(self) -> None:
        if self.limits.max_duration_s and (self._clock() - self.start) > self.limits.max_duration_s:
            raise LimitExceeded("time", f"run time budget {self.limits.max_duration_s}s exceeded")

    def remaining_time(self) -> float | None:
        """Seconds left in the run time budget, or None when it is unbounded."""
        if not self.limits.max_duration_s:
            return None
        return max(0.0, self.limits.max_duration_s - (self._clock() - self.start))
