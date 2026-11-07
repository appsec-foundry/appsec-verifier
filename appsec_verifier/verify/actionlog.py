"""Per-finding action log (VER-017, VER-016).

`verify` writes `agent-log.jsonl` next to the report: one JSON object per line
for every agent step of every finding — the tool call with its arguments and
the outcome (status, length, error, the browser's blocked requests), every
proposal the step contract refused, every limit that stopped a finding, and
the verdict. Refused actions are thereby logged, not only refused. Response
bodies and source text are not logged. Each record is redacted of credential
values before it is written; JSON encoding keeps a value from breaking a line.
The file is owner-only, and each line is flushed so a cut-off run keeps its log.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class ActionLog:
    """Callable sink for the agent loop's log records (ProbeContext.log)."""

    def __init__(self, path: Path, *, redact=None, append: bool = False, clock=None):
        self.path = Path(path)
        self._redact = redact
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
        fd = os.open(self.path, flags, 0o600)
        self.path.chmod(0o600)            # also when an earlier run left the file with wider rights
        self._fh = os.fdopen(fd, "a" if append else "w", encoding="utf-8")

    def __call__(self, record: dict) -> None:
        if self._redact is not None:
            record = self._redact(record)
        stamp = self._clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        self._fh.write(json.dumps({"time": stamp, **record}, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
