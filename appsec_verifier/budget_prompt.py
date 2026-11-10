"""The question for a higher cost ceiling in an interactive run (VER-015), as AppSec Analyzer's
``scripts/runtime/interactive_budget.py`` asks it.

When the run reaches its cost ceiling, `CeilingPrompt` pauses the status line and asks for a new total in
USD. Only an amount above the ceiling and above what the run has spent raises it; Enter, three invalid
answers, the end of input or the end of the run time keep it, and after that the run does not ask again.
A run asks at most ``MAX_RAISES`` times. Keys pressed before the question are discarded, so typing ahead
neither raises nor keeps the ceiling. The waiting time counts toward the run time.
"""

from __future__ import annotations

import re
import sys

MAX_RAISES = 16
_AMOUNT = re.compile(r"[0-9]{1,9}(?:\.[0-9]{1,2})?")


def can_prompt(interactive: bool) -> bool:
    """Whether the run may ask: interactive, and the question shows on a terminal."""
    return interactive and sys.stdin is not None and sys.stdin.isatty() and sys.stderr.isatty()


def read_answer(budget) -> str | None:
    """One line typed after the question; "" at the end of input, None once the run time is up."""
    import select
    import termios

    termios.tcflush(sys.stdin, termios.TCIFLUSH)     # what was typed while the run progressed is no answer
    while True:
        if budget.remaining_time() == 0:
            return None
        ready, _, _ = select.select([sys.stdin], [], [], 0.5)
        if ready:
            return sys.stdin.readline(128)


class CeilingPrompt:
    """`RunBudget.ask_ceiling` for an interactive run: the new total the operator typed, or None."""

    def __init__(self, progress=None, *, api_prices: bool = False, write=None, read=None):
        self._progress = progress
        self._unit = " at API prices" if api_prices else ""
        self._write = write or (lambda text: (sys.stderr.write(text), sys.stderr.flush()))
        self._read = read or read_answer
        self.declined = False

    def __call__(self, budget) -> float | None:
        if self.declined or len(budget.ceiling_raises) >= MAX_RAISES:
            return None
        if self._progress is None:
            return self._ask(budget)
        with self._progress.paused():
            return self._ask(budget)

    def _ask(self, budget) -> float | None:
        ceiling, spent = budget.limits.cost_limit_usd, budget.cost
        floor = max(ceiling, spent)
        self._write(f"\nCost limit reached: ${spent:.2f} of ${ceiling:.2f}{self._unit} used. A higher limit lets "
                    "the run go on; it does not guarantee that every finding is tested.\n")
        why = ""
        for _ in range(3):
            self._write(f"New total cost limit in USD (more than {floor:.2f}), or Enter to stop testing: ")
            line = self._read(budget)
            if line is None:
                why = ": the run time is up"
                break
            if not line.strip() or len(line) >= 128:
                why = ": the input ended" if not line else ""
                break
            if _AMOUNT.fullmatch(line.strip()) and float(line) > floor:
                amount = float(line)
                self._write(f"Cost limit raised from ${ceiling:.2f} to ${amount:.2f}{self._unit}.\n\n")
                if self._progress is not None:
                    self._progress.raise_cost_limit(amount)
                return amount
            self._write(f"Enter an amount in USD above {floor:.2f}, for example {floor + 10:.0f}, or press Enter.\n")
        self.declined = True
        self._write(f"Cost limit stays at ${ceiling:.2f}{why}; the run stops testing and does not ask again.\n\n")
        return None
