"""The progress of a `verify` run on the console, in the look of AppSec Analyzer (VER-005, VER-016, VER-017).

Each event is one line in a fixed grid, ``TIME  FINDING  EVENT  PROGRESS  ELAPSED  LEFT  DETAIL``.
FINDING is the finding under test with its position among the findings that get a probe. EVENT is
``start`` and ``done`` for a finding's bounds, ``·`` for an agent step, ``↻`` for a step the step
contract refused and ``⚠`` for a limit that stopped the finding. PROGRESS counts finished findings,
ELAPSED is the run's time. LEFT extrapolates the time the finished findings took, never beyond the
run's time limit; until the first finding has finished it shows that limit (``≤29m``).

On a terminal a status line under the grid is redrawn every ``TICK_SECONDS`` with a spinner, a progress
bar, the running step and its age. Off a terminal (CI, logs) a line follows after ``HEARTBEAT_SECONDS``
without output instead. Text from the assessment, the model or the target passes the run's redaction
and `printable` before it is shown, so no credential value and no escape sequence reaches the console.
"""

from __future__ import annotations

import os
import re
import sys
import textwrap
import threading
import time

from .preflight import printable
from .term_style import Style, columns

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_ANSI = re.compile(r"\033\[[0-9;]*m")
_VERDICT_ROLES = {"confirmed": "critical", "not-reproducible": "ok", "blocked-by-control": "ok",
                  "inconclusive": "warn", "not-attempted": "muted"}
_EVENT_ROLES = {"start": "accent", "↻": "warn", "⚠": "warn"}
# A redraw begins a synchronized update and hides the cursor, then shows it again; terminals without
# synchronized updates ignore the mode. The cursor stays at the line start, as in AppSec Analyzer.
_FRAME_OPEN = "\033[?2026h\033[?25l\r"
_FRAME_CLOSE = "\r\033[?25h\033[?2026l"
_CLEAR = "\r\033[K"
_CLIP = 80


def duration(seconds: float) -> str:
    """``45s``, ``3m05s``, ``1h02m``."""
    seconds = max(0, round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, rest = divmod(seconds, 60)
    return f"{minutes}m{rest:02d}s" if minutes < 60 else f"{minutes // 60}h{minutes % 60:02d}m"


def _minutes(seconds: float) -> str:
    """``<1m``, ``13m``, ``1h05m``."""
    if seconds < 60:
        return "<1m"
    hours, minutes = divmod(int(seconds // 60), 60)
    return f"{minutes}m" if not hours else f"{hours}h{minutes:02d}m"


def _clip(text, limit: int = _CLIP) -> str:
    text = printable(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _action(tool: str, args: dict) -> str:
    """What a tool call does, in a few words: ``GET /rest/basket/2 as alice``."""
    if tool == "http_request":
        text = f"{_clip(args.get('method') or 'GET', 10)} {_clip(args.get('path', ''))}"
    elif tool == "browser_check":
        text = f"browser {_clip(args.get('path', ''))}"
    elif tool == "read_source":
        line = args.get("around_line")
        text = f"source {_clip(args.get('path', ''))}" + (f":{line}" if isinstance(line, int) else "")
    else:
        text = _clip(tool, 40)
    return text + (f" as {_clip(args['role'], 40)}" if args.get("role") else "")


def _outcome(result: dict) -> str:
    if result.get("error"):
        return f"error: {_clip(result['error'], 160)}"
    parts = []
    if isinstance(result.get("status"), int):
        parts.append(str(result["status"]))
    if isinstance(result.get("length"), int):
        parts.append(f"{result['length']} B")
    if "executed" in result:
        parts.append("script executed" if result["executed"] else "no script executed")
    if result.get("marker_read"):
        parts.append("marker file read")
    if result.get("callback_hit"):
        parts.append("callback hit")
    return " · ".join(parts) or "done"


class _StatusGuard:
    """Stands in for a terminal stream while the status line is live: whatever else in the process
    prints there first removes the status line, which the next tick draws again below it."""

    def __init__(self, stream, progress: RunProgress):
        self.stream, self._progress = stream, progress

    def write(self, text: str) -> int:
        with self._progress._lock:
            if text:
                self._progress._clear()
            return self.stream.write(text)

    def __getattr__(self, name: str):
        return getattr(self.stream, name)


class RunProgress:
    """The run's progress grid on ``stream`` (standard error by default).

    The runner calls `begin`, then `finding` and `finished` per finding with a probe; the agent loop
    calls `activity` before each model or tool call and `step` with each action-log record. `close`
    stops the status line and must run however the run ends.
    """

    TICK_SECONDS = 0.2
    HEARTBEAT_SECONDS = 120
    BAR_WIDTH = 12

    def __init__(self, stream=None, *, model: str | None = None, redact=None, remaining_time=None,
                 live: bool | None = None, clock=time.time, env=None):
        self._stream = sys.stderr if stream is None else stream
        env = os.environ if env is None else env
        self.st = Style.for_stream(self._stream, env)
        if live is None:
            try:
                live = self._stream.isatty() and env.get("TERM") != "dumb"
            except (AttributeError, ValueError):
                live = False
        self.live = live
        self._model = _clip(model, 40) if model else "the model"
        self._redact = redact
        self._remaining_time = remaining_time
        self._clock = clock
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._shown = False
        self._frame = 0
        self.total = self.done = self.number = 0
        self._id = ""
        self._id_width = 0
        self._steps, self._noted = 0, False
        self._activity, self._activity_at = "", 0.0
        self.started = self.last = self._finding_at = clock()

    # ── events ────────────────────────────────────────────────────────────────

    def begin(self, plans: list) -> None:
        """Start the grid for the findings with a probe; without any, nothing is shown."""
        self.total = total = len(plans)
        if not total:
            return
        self.started = self.last = self._clock()
        self._id_width = len(f"{total}/{total} ") + max(len(_clip(plan.id, 16)) for plan in plans)
        sys.stdout.flush()      # the run settings above, when both streams go to one log
        self._write("")
        self._write(self.st(f"{'TIME':<8}  {'FINDING':<{self._id_width}}  {'EVENT':<5}  {'PROGRESS':>8}  "
                            f"{'ELAPSED':>7}  {'LEFT':>6}  DETAIL", "muted", "bold"))
        self._thread = threading.Thread(target=self._ticker, name="appsec-verifier-progress", daemon=True)
        if self.live:
            if not isinstance(sys.stderr, _StatusGuard):
                sys.stderr = _StatusGuard(sys.stderr, self)
            if sys.stdout.isatty() and not isinstance(sys.stdout, _StatusGuard):
                sys.stdout = _StatusGuard(sys.stdout, self)
        self._thread.start()

    def finding(self, plan) -> None:
        with self._lock:
            self.number += 1
            self._id = _clip(plan.id, 16)
            self._steps, self._activity, self._noted = 0, "", False
            self._finding_at = self._clock()
            title = self._text(plan.title or plan.cwe or "")
            self._record("start", " · ".join(part for part in (_clip(plan.cls or "-", 20), _clip(title)) if part))

    def activity(self, step: int, of: int, tool: str | None = None, args: dict | None = None) -> None:
        """What runs now, for the status line and the heartbeat: a model call or a tool call."""
        what = f"asking {self._model}" if tool is None else _action(tool, self._text(args or {}))
        with self._lock:
            self._activity, self._activity_at = f"step {step}/{of} · {what}", self._clock()

    def step(self, record: dict) -> None:
        """One line per tool call, refused step and stopping limit of the action log (VER-017)."""
        record = self._text(record)
        number = record.get("step")
        with self._lock:
            self._activity = ""
            if isinstance(number, int):
                self._steps = number
            head = f"step {number}"
            args = record.get("args") if isinstance(record.get("args"), dict) else {}
            action = _action(str(record["tool"]), args) if "tool" in record else ""
            self._noted = self._noted or bool(record.get("stopped") or record.get("refused"))
            if record.get("stopped"):
                reason = f"stopped by limit: {_clip(record.get('reason', ''), 160)}"
                self._record("⚠", " · ".join(part for part in (head, action, reason) if part))
            elif record.get("refused"):
                self._record("↻", f"{head} · refused: {_clip(record['refused'], 160)}")
            elif action:
                result = record.get("result") if isinstance(record.get("result"), dict) else {}
                self._record("·", f"{head} · {action} → {_outcome(result)}")

    def finished(self, plan, result) -> None:
        verdict = printable(result.verdict)
        parts = [verdict + (f" ({_clip(result.confidence, 10)})" if result.confidence else "")]
        if self._steps:
            parts.append(f"{self._steps} step" + ("s" if self._steps != 1 else ""))
        with self._lock:
            parts.append(duration(self._clock() - self._finding_at))
            # Why it stayed inconclusive, unless a refused step or a limit above already said so.
            if verdict == "inconclusive" and result.rationale and not self._noted:
                parts.append(_clip(self._text(result.rationale), 160))
            self.done += 1
            self._activity = ""
            self._record("done", " · ".join(parts), role=_VERDICT_ROLES.get(verdict))

    def close(self) -> None:
        """Stop the ticker and remove the status line; the run's last message follows on a clean line."""
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=1)
        with self._lock:
            self._clear()
            if isinstance(sys.stderr, _StatusGuard) and sys.stderr._progress is self:
                sys.stderr = sys.stderr.stream
            if isinstance(sys.stdout, _StatusGuard) and sys.stdout._progress is self:
                sys.stdout = sys.stdout.stream

    # ── rendering ─────────────────────────────────────────────────────────────

    def _text(self, value):
        """``value`` without the credential values the run knows (VER-016)."""
        return self._redact(value) if self._redact is not None else value

    def _ticker(self) -> None:
        while not self._stop.wait(self.TICK_SECONDS if self.live else 1.0):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - a status redraw must never end the run or print a traceback
                pass

    def tick(self) -> None:
        """On a terminal redraw the status line; off it write a line after a quiet stretch."""
        with self._lock:
            if not self._id or self._stop.is_set():
                return
            now = self._clock()
            age = duration(now - self._activity_at) if self._activity else ""
            working = " · ".join(part for part in (self._activity, age) if part)
            if self.live:
                self._frame += 1
                self._status(self._row(SPINNER[self._frame % len(SPINNER)], working, now, live=True))
            elif now - self.last >= self.HEARTBEAT_SECONDS:
                self._record("·", working or "working")

    def _run(self, now: float) -> tuple[str, str, str]:
        """PROGRESS, ELAPSED and LEFT for the whole run."""
        elapsed = now - self.started
        share = f"{round(100 * self.done / self.total)}%" if self.total else ""
        if self.done >= self.total:
            return share, duration(elapsed), ""
        remaining = self._remaining_time() if self._remaining_time is not None else None
        estimate = elapsed / self.done * (self.total - self.done) if self.done else None
        if estimate is not None and (remaining is None or estimate <= remaining):
            left = _minutes(estimate) if estimate < 60 else "~" + _minutes(estimate)
        else:
            left = "≤" + _minutes(remaining) if remaining is not None else ""
        return share, duration(elapsed), left

    def _row(self, event: str, detail: str, now: float, *, live: bool = False, role: str | None = None) -> str:
        st = self.st
        finding = f"{self.number}/{self.total} {self._id}" if self._id else ""
        share, elapsed, left = self._run(now)
        stamp = time.strftime("%H:%M:%S", time.localtime(now))
        bar = f"{self._bar()}  " if live else ""
        head = (f"{st(stamp, 'muted')}  "
                + st(f"{finding:<{self._id_width}}", "accent", *(("bold",) if event in ("start", "done") else ()))
                + f"  {st(f'{event:<5}', 'accent' if live else role or _EVENT_ROLES.get(event, 'muted'))}  "
                + st(f"{share:>8}  {elapsed:>7}  {left:>6}", "muted") + f"  {bar}")
        width = columns() - 1
        indent = len(_ANSI.sub("", head))
        pieces = [detail]
        if (st.enabled or self.live) and not live and width - indent >= 30 and len(detail) > width - indent:
            pieces = textwrap.wrap(detail, width - indent, break_on_hyphens=False) or [detail]
        if event == "done" and role:
            first, sep, rest = pieces[0].partition(" · ")
            pieces[0] = st(first, role) + sep + rest
        elif event in ("↻", "⚠"):
            pieces = [st(piece, "warn") for piece in pieces]
        return "\n".join([head + pieces[0], *(" " * indent + piece for piece in pieces[1:])]).rstrip()

    def _bar(self) -> str:
        filled = round(self.BAR_WIDTH * self.done / self.total) if self.total else 0
        return self.st("━" * filled, "accent") + self.st("─" * (self.BAR_WIDTH - filled), "muted")

    def _record(self, event: str, detail: str, *, role: str | None = None) -> None:
        now = self._clock()
        self._write(self._row(event, detail, now, role=role))
        self.last = now

    def _write(self, line: str) -> None:
        with self._lock:
            self._clear()
            self._stream.write(line + "\n")
            self._stream.flush()

    def _status(self, line: str) -> None:
        """Overwrite the status line in place; a line too wide for the terminal is cut, not wrapped."""
        width = columns() - 1
        if len(_ANSI.sub("", line)) > width:
            line = _ANSI.sub("", line)[: max(width - 1, 0)] + "…"
        self._stream.write(_FRAME_OPEN + line + "\033[K" + _FRAME_CLOSE)
        self._stream.flush()
        self._shown = True

    def _clear(self) -> None:
        if self._shown:
            self._stream.write(_CLEAR)
            self._stream.flush()
            self._shown = False
