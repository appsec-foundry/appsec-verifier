"""The question for write requests the run's mode does not allow, in an interactive terminal (VER-052).

A run in safe mode sends no state-changing request (VER-030). When a finding needs one, the Verifier asks
the operator instead of skipping it: before the finding starts when every request it names writes
(cli.py, verify/runner.py), or when the test agent asks for one (agent/tools.py). The caller asks only
for a request the run would send in intrusive mode; nothing is asked with --read-only, when the scope
forbids state change, or without a terminal (cli.py).

`WritePrompt` pauses the status line and shows the finding, the request, the identity, that marked test
data stays on the target, and the agent's reason, marked as its claim. `y` allows writes for that
finding, `a` for the rest of the run; Enter, any other answer, the end of input, ``WAIT_S`` seconds
without an answer or the end of the run time decline, and the finding goes on read-only. Keys pressed
before the question are discarded. A finding is asked at most once. Every answer is kept in `records`
for the report. The waiting time counts toward the run time, as for the cost ceiling (VER-015). Text
from the assessment or the model is shown without control characters.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from .budget_prompt import read_answer
from .preflight import printable

WAIT_S = 120


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class WritePrompt:
    """Asks whether a finding may send write requests; called as
    ``prompt(budget, key=, finding=, requests=, reason=, identity=, asked=)`` and returning True when writes are
    allowed for that finding."""

    def __init__(self, progress=None, *, identities=(), write=None, read=None, wait: float = WAIT_S):
        self._progress = progress
        self._identities = [printable(r)[:60] for r in identities]
        self._write = write or (lambda text: (sys.stderr.write(text), sys.stderr.flush()))
        self._read = read or read_answer
        self._wait = wait
        self.records: dict[str, dict] = {}    # evidence id -> the answer for that finding
        self._whole_run: dict | None = None    # the `a` answer, once given

    def allowed(self, key: str) -> bool:
        return bool(self.records.get(key, {}).get("allowed"))

    def covered(self, key: str) -> bool:
        """Whether writes are allowed for `key` without a question: by its own answer, or by `a` for the rest
        of the run, which is then recorded for it."""
        if key not in self.records and self._whole_run is not None:
            self.records[key] = {"allowed": True, "answer": "rest of the run", "at": self._whole_run["at"],
                                 "given_for": self._whole_run["finding"], "asked": "not asked", "requests": []}
        return self.allowed(key)

    def __call__(self, budget, *, key: str, finding: str, requests: list[str], reason: str | None = None,
                 identity: str | None = None, asked: str = "before the finding") -> bool:
        """`identity` is the role of the request the agent asks for, "" without one; None before the finding
        starts, when the agent will choose among the run's identities."""
        if key in self.records:                 # one question per finding
            return self.allowed(key)
        requests = [printable(r)[:200] for r in requests[:4]]
        if self._whole_run is not None:
            self.records[key] = {"allowed": True, "answer": "rest of the run", "at": self._whole_run["at"],
                                 "given_for": self._whole_run["finding"], "asked": asked, "requests": requests}
            return True
        if identity is None:
            identity = "chosen by the test agent: " + ", ".join([*self._identities, "without login"])
        identity = printable(identity)[:200] or "without login"
        if self._progress is None:
            answer = self._ask(budget, finding, requests, identity, reason)
        else:
            with self._progress.paused():
                answer = self._ask(budget, finding, requests, identity, reason)
        record = {"allowed": answer in ("finding", "rest of the run"), "answer": answer, "at": _now(),
                  "asked": asked, "requests": requests, "identity": identity}
        self.records[key] = record
        if answer == "rest of the run":
            self._whole_run = {"at": record["at"], "finding": printable(finding)[:200]}
        return record["allowed"]

    def _ask(self, budget, finding: str, requests: list[str], identity: str, reason: str | None) -> str:
        lines = [f"\n{printable(finding)[:200]} needs write requests, which this run does not send in safe mode:",
                 *(f"  {r}" for r in requests),
                 f"Identity: {identity}",
                 "Each write carries the finding's marker; what it creates stays on the target and is not "
                 "cleaned up (VER-014)."]
        if reason:
            lines.append(f"The test agent's reason, its claim: {printable(reason)[:300]}")
        self._write("\n".join(lines) + "\n")
        self._write("Allow writes for this finding (y), for the rest of the run (a), or not (Enter)? ")
        line = self._read(budget, self._wait)
        if line is None:
            answer, said = "no answer", "no writes: no answer in time"
        elif not line:
            answer, said = "declined", "no writes: the input ended"
        elif line.strip().lower() == "y":
            answer, said = "finding", "writes allowed for this finding"
        elif line.strip().lower() == "a":
            answer, said = "rest of the run", "writes allowed for the rest of the run"
        else:
            answer, said = "declined", "no writes"
        self._write(f"{said[0].upper()}{said[1:]}.\n\n")
        return answer
