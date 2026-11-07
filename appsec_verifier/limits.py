"""Execution bounds enforced outside the model (VER-015): total requests, cost,
model calls, wall-clock time and the request rate. Reaching a bound raises
LimitExceeded so the caller stops the affected work rather than pressing on;
the rate is kept by waiting, not by refusing. `max_attempts` bounds the agent
steps per finding and is applied by the agent loop (agent/loop.py).

Every bound must be a finite positive number; only `rate_rps` may be 0, which
turns the rate limit off. A negative or zero cap, or an unknown key in
data/limits.yaml, is a ValueError, so no bound is lost to a typo or a sign.
`requests` counts the requests actually sent; a refused one is not counted. A
cost that is not a finite number of at least 0 cannot be bounded, so it ends
every further model call of the run as if the ceiling were reached.
"""

from __future__ import annotations

import math
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
    max_attempts: int = 12
    max_calls: int = 500
    max_duration_s: float = 1800
    rate_rps: float = 5

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            whole = name in ("max_requests", "max_attempts", "max_calls")
            if (isinstance(value, bool) or not isinstance(value, int if whole else int | float)
                    or not math.isfinite(value)):
                raise ValueError(f"limit {name} must be a{' whole' if whole else ''} number, not {value!r}")
            if value < 0 or (value == 0 and name != "rate_rps"):
                raise ValueError(f"limit {name} must be greater than 0, not {value!r}"
                                 + (" (0 turns only the rate limit off)" if value == 0 else ""))

    @classmethod
    def load(cls, overrides: dict | None = None) -> Limits:
        """Defaults from data/limits.yaml, with any provided overrides applied."""
        with open(resource_root() / "data" / "limits.yaml", encoding="utf-8") as fh:
            doc = (yaml.safe_load(fh) or {}).get("limits", {})
        unknown = sorted(set(doc) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError(f"data/limits.yaml names limits that are not enforced: {', '.join(unknown)}")
        base = {f: doc[f] for f in cls.__dataclass_fields__ if f in doc}
        base.update({k: v for k, v in (overrides or {}).items() if v is not None})
        return cls(**base)


class RunBudget:
    """Tracks consumption against the limits. `clock` and `sleep` are injectable for tests."""

    def __init__(self, limits: Limits, clock=time.monotonic, sleep=time.sleep):
        self.limits = limits
        self._clock = clock
        self._sleep = sleep
        self.start = clock()
        self.requests = 0
        self.cost = 0.0
        self.calls = 0
        self._next_request_at: float | None = None
        self._cost_unknown = False

    def pace(self) -> None:
        """Wait until the next request may be sent under `rate_rps`: requests are
        spaced at least 1/rate_rps seconds apart, with no burst (VER-015)."""
        if not self.limits.rate_rps or self.limits.rate_rps <= 0:
            return
        now = self._clock()
        if self._next_request_at is not None and now < self._next_request_at:
            self._sleep(self._next_request_at - now)
            now = self._next_request_at
        self._next_request_at = now + 1.0 / self.limits.rate_rps

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
        if self.limits.max_requests and self.requests >= self.limits.max_requests:
            raise LimitExceeded("requests", f"request cap {self.limits.max_requests} reached")
        self.requests += 1

    def note_cost(self, usd: float) -> None:
        if self._cost_unknown or isinstance(usd, bool) or not isinstance(usd, int | float) \
                or not math.isfinite(usd) or usd < 0:
            self._cost_unknown = True
            raise LimitExceeded("cost", "a model call reported no usable cost, so the spending can no longer "
                                        "be bounded")
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
