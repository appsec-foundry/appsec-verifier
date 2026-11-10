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

In an interactive run `RunBudget.ask_ceiling` asks the operator for a higher
cost ceiling when the run reaches it (budget_prompt.py); only an amount the
operator typed raises it, and each raise is kept in `ceiling_raises`. No other
limit is raised this way.
"""

from __future__ import annotations

import math
import signal
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

import yaml

from .version_info import resource_root


class LimitExceeded(Exception):
    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind = kind  # "requests" | "cost" | "time" | "attempts" | "calls" | "window" | "finding-cost"


class _DeadlineExpired(BaseException):
    """Not swallowed by SDK/tool handlers for ordinary exceptions (VER-036)."""

    def __init__(self, kind):
        self.kind = kind


@contextmanager
def execution_deadline(seconds: float, *, kind: str = "time"):
    """Interrupt synchronous work, including blocked I/O; restore enclosing timers.

    The CLI runs on the main thread. Refuse execution where a real interrupt is
    unavailable instead of leaving a worker running after a thread timeout.
    """
    if seconds <= 0:
        raise LimitExceeded(kind, "execution deadline reached")
    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        raise LimitExceeded(kind, "execution deadlines require a POSIX main thread")
    started = time.monotonic()
    previous = signal.getsignal(signal.SIGALRM)
    old_delay, old_interval = signal.getitimer(signal.ITIMER_REAL)
    outer_first = old_delay > 0 and old_delay <= seconds
    fired = False

    def expired(signum, frame):
        nonlocal fired
        fired = True
        if outer_first and callable(previous):
            previous(signum, frame)
        raise _DeadlineExpired(kind)

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, old_delay) if old_delay > 0 else seconds)
    try:
        try:
            yield
        except _DeadlineExpired as exc:
            raise LimitExceeded(exc.kind, "execution deadline reached") from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if old_delay > 0 and not (fired and outer_first):
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, old_delay - (time.monotonic() - started)), old_interval)


_MAY_BE_ZERO = ("rate_rps", "finding_cost_fraction", "min_finding_cost_usd")


@dataclass
class Limits:
    cost_limit_usd: float = 10.0
    max_requests: int = 2000
    max_attempts: int = 12
    max_calls: int = 500
    max_duration_s: float = 1800
    rate_rps: float = 5
    # VER-051: a single finding may spend at most this share of the run's cost ceiling, never below the floor,
    # so one finding cannot drain the budget before later findings are reached. 0 turns the per-finding cap off.
    finding_cost_fraction: float = 0.25
    min_finding_cost_usd: float = 0.50

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            whole = name in ("max_requests", "max_attempts", "max_calls")
            if (isinstance(value, bool) or not isinstance(value, int if whole else int | float)
                    or not math.isfinite(value)):
                raise ValueError(f"limit {name} must be a{' whole' if whole else ''} number, not {value!r}")
            if value < 0 or (value == 0 and name not in _MAY_BE_ZERO):
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
        self._finding_start_cost = 0.0  # run cost when the finding under test began (VER-051)
        self.ask_ceiling = None         # interactive run: budget -> a higher ceiling the operator typed, or None
        self.ceiling_raises: list[dict] = []    # {"from": USD, "to": USD} per raise the operator approved

    def begin_finding(self) -> None:
        """Start a new finding's per-finding cost accounting (VER-051). Call it before each tested finding."""
        self._finding_start_cost = self.cost

    def finding_cost_cap(self) -> float | None:
        """USD a single finding may spend: a share of the run ceiling, never below the floor, or None when the
        per-finding cap is off (no run cost ceiling, or the share set to 0)."""
        ceiling, share = self.limits.cost_limit_usd, self.limits.finding_cost_fraction
        if not ceiling or not share:
            return None
        return max(self.limits.min_finding_cost_usd, ceiling * share)

    def check_finding_cost(self) -> None:
        """Stop the finding under test, not the run, once it has spent its per-finding share (VER-051)."""
        cap = self.finding_cost_cap()
        if cap is not None and (self.cost - self._finding_start_cost) >= cap:
            raise LimitExceeded("finding-cost", f"per-finding spend cap ${cap:.2f} reached")

    def pace(self) -> None:
        """Wait until the next request may be sent under `rate_rps`: requests are
        spaced at least 1/rate_rps seconds apart, with no burst (VER-015)."""
        if not self.limits.rate_rps or self.limits.rate_rps <= 0:
            return
        now = self._clock()
        if self._next_request_at is not None and now < self._next_request_at:
            self._sleep(min(self._next_request_at - now, self.remaining_time()))
            self.check_time()
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
            self._ceiling_reached(f"cost ceiling ${self.limits.cost_limit_usd:.2f} exceeded")

    def check_cost(self) -> None:
        """Before a model call: none once the cost ceiling is reached or a cost could not be bounded."""
        self.note_cost(0.0)
        if self.limits.cost_limit_usd and self.cost >= self.limits.cost_limit_usd:
            self._ceiling_reached("cost ceiling reached")

    def _ceiling_reached(self, detail: str) -> None:
        """Stop at the cost ceiling, unless the operator, asked in an interactive run, typed a higher one."""
        ceiling = self.limits.cost_limit_usd
        higher = self.ask_ceiling(self) if self.ask_ceiling is not None else None
        if higher is None or not higher > max(ceiling, self.cost):
            raise LimitExceeded("cost", detail)
        self.ceiling_raises.append({"from": ceiling, "to": higher})
        self.limits.cost_limit_usd = higher

    def check_time(self) -> None:
        if self.limits.max_duration_s and (self._clock() - self.start) >= self.limits.max_duration_s:
            raise LimitExceeded("time", f"run time budget {self.limits.max_duration_s}s exceeded")

    def remaining_time(self) -> float | None:
        """Seconds left in the run time budget, or None when it is unbounded."""
        if not self.limits.max_duration_s:
            return None
        return max(0.0, self.limits.max_duration_s - (self._clock() - self.start))
