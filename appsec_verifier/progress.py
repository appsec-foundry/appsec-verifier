"""The progress of a `verify` run on the console, in the look of AppSec Analyzer (VER-005, VER-013, VER-015,
VER-016, VER-017, VER-039, VER-042).

Each event is one entry in a fixed grid, ``TIME  FINDING  EVENT  PROGRESS  ELAPSED  LEFT  DETAIL``.
FINDING is the finding under test with its position among the findings that get a probe. EVENT is
``start`` and ``done`` for a finding's bounds, ``agent`` when an agent starts or finishes, ``·`` for an
agent step, ``proof`` for the proof check, ``↻`` for a step the step contract refused and ``⚠`` for a
limit that stopped the finding. A blank line sets each finding apart.
The ``start`` entry gives the finding's title, then its severity, class and the requests the assessment
names. The ``agent`` entry after it says that the test agent started: its model in AppSec Analyzer's short
form (``Sonnet 4.5``) and runtime, its step budget, the identities it may act as and whether it may read
source code. A finding an earlier run-wide limit stopped gets no agent entries, since no agent starts for
it. A step entry gives the agent's note on what the step checks, then the request it tested with its
query and body, the result and how long the model took to propose the step; a result that a proof needs
(a script executed, the marker file read, a callback hit) is highlighted. A ``proof`` entry says when the
proof check sent a claimed confirmation back to the agent and why. When the agent finishes, an ``agent``
entry says so, then a ``proof`` entry says whether the proof was checked (VER-009 to VER-013) or why
there is none. The evidence reviewer of VER-042 gets ``agent`` entries for its start and end as well.
The ``done`` entry gives the verdict, marked and highlighted, and the first sentence of the agent's
rationale; once a finding's last variant is done, a ``rating`` entry follows when the rating after
verification differs from the Analyzer's (VER-039). The evidence reviewer's corrections and issues show
their first sentence as well, as the report does. When the run shows costs (API billing, or
``--show-costs`` as in AppSec Analyzer), an entry after model calls gives the run's spend so far
(``run $0.42``), the ``done`` entry the run's spend against its cost limit, and the status line the run's
spend as it grows; on a terminal the amounts are highlighted. Unlike AppSec Analyzer, which gives a step's
own cost as well, the grid shows only the running total. Under the ``done`` entry a line names each
screenshot the finding produced, with its path in the output directory: ``proof`` when the Verifier checked
the verdict's proof, otherwise ``img``. PROGRESS counts finished findings, ELAPSED is the run's time.
LEFT extrapolates the time the finished findings took, never beyond the run's time limit; until the first
finding has finished it shows that limit (``≤29m``).

On a terminal an entry's parts stand on rows of their own, the tested request in its own colour, and a
long row wraps under its column, at most ``MAX_COLUMNS`` wide as in AppSec Analyzer; a status line under
the grid is redrawn every ``TICK_SECONDS`` with a spinner, a progress bar, the run's spend, the running
step (``Sonnet 4.5 plans`` while the model call runs, otherwise the request) and its age. While the
question for a higher cost ceiling waits (budget_prompt.py), the status line is away. Off a terminal
(CI, logs) each entry is one plain line, and a line follows after ``HEARTBEAT_SECONDS`` without output. Text from the
assessment, the model or the target passes the run's redaction and `printable` before it is shown, so no
credential value, line break or escape sequence from it reaches the console.

With ``--console-log``, `console_log` copies what `verify` prints to standard output and standard error to
``console.log`` in the output directory, without colour codes or, ``color``, with the console's colour; the
status line is left out.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from collections import Counter
from contextlib import contextmanager

from .preflight import printable
from .term_style import Style, columns
from .verify.probes import proof_shown
from .verify.report import _VERDICT_LABEL, _first_sentence

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_ANSI = re.compile(r"\033\[[0-9;]*m")
# Seen from the finding: green confirmed, red not reproduced or blocked (a likely false positive), yellow undecided.
_VERDICT_ROLES = {"confirmed": "ok", "not-reproducible": "critical", "blocked-by-control": "critical",
                  "inconclusive": "warn", "not-attempted": "muted"}
_VERDICT_MARKS = {"confirmed": "✔", "not-reproducible": "✘", "blocked-by-control": "✘", "inconclusive": "?"}
_EVENT_ROLES = {"start": "accent", "agent": "agent", "proof": "ok", "rating": "accent", "↻": "warn", "⚠": "warn"}
_SEVERITIES = ("critical", "high", "medium", "low")
_NBSP = "\xa0"       # keeps the run's spend and the model time whole across a wrap, as in AppSec Analyzer
# A redraw begins a synchronized update and hides the cursor, then shows it again; terminals without
# synchronized updates ignore the mode. The cursor stays at the line start, as in AppSec Analyzer.
_FRAME_OPEN = "\033[?2026h\033[?25l\r"
_FRAME_CLOSE = "\r\033[?25h\033[?2026l"
_CLEAR = "\r\033[K"
_CLIP = 80
_MODEL_ID = re.compile(r"(?:claude-)?(haiku|sonnet|opus|fable)(?:-(\d+)(?:-(\d{1,2}))?)?(?:-\d{8})?")


def short_model(model: str) -> str:
    """A model as the grid names it, as AppSec Analyzer's ``short_model`` does: ``Sonnet 5.5`` for
    ``claude-sonnet-5-5``, ``Haiku`` for ``haiku``; an ID of another form without its vendor prefix."""
    match = _MODEL_ID.fullmatch(model)
    if not match:
        return model.removeprefix("claude-")
    family, major, minor = match.groups()
    return " ".join(part for part in (family.capitalize(), f"{major}.{minor}" if minor else major) if part)


def duration(seconds: float) -> str:
    """``45s``, ``3m05s``, ``1h02m``."""
    seconds = max(0, round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, rest = divmod(seconds, 60)
    return f"{minutes}m{rest:02d}s" if minutes < 60 else f"{minutes // 60}h{minutes % 60:02d}m"


def spent_text(cost: float, limit: float, *, api_prices: bool = False) -> str:
    """``$0.42 of $10.00``; ``… at API prices`` when a subscription pays and the amount is only the
    API-equivalent value the Claude CLI reports."""
    return f"${cost:.2f} of ${limit:.2f}" + (" at API prices" if api_prices else "")


def _line(*parts) -> list[tuple]:
    """One row of an entry as segments ``(text, *roles)``: the parts joined by `` · ``, empty ones left
    out. A part is a string, a segment, or a list of segments."""
    line: list[tuple] = []
    for part in parts:
        segments = [(part,)] if isinstance(part, str) else [part] if isinstance(part, tuple) else part
        if not any(segment[0] for segment in segments):
            continue
        if line:
            line.append((" · ",))
        line.extend(segments)
    return line


def _spans(text: str, first: int, rest: int) -> list[tuple[int, int]]:
    """Where ``text`` breaks into rows of at most ``first``, then ``rest`` characters: at the last space
    that fits, which is dropped, or inside a word longer than the row."""
    spans, start, width = [], 0, first
    while len(text) - start > width:
        cut = text.rfind(" ", start, start + width + 1)
        if cut <= start:
            spans.append((start, start + width))
            start += width
        else:
            spans.append((start, cut))
            start = cut + 1
        width = rest
    spans.append((start, len(text)))
    return spans


def _minutes(seconds: float) -> str:
    """``<1m``, ``13m``, ``1h05m``."""
    if seconds < 60:
        return "<1m"
    hours, minutes = divmod(int(seconds // 60), 60)
    return f"{minutes}m" if not hours else f"{hours}h{minutes:02d}m"


def _clip(text, limit: int = _CLIP) -> str:
    text = printable(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _variant_detail(plan) -> str | None:
    """For a variant, its key and its own request, so sibling variants of one finding do not read alike."""
    variant = getattr(plan, "variant_id", None)
    variants = (getattr(plan, "verification_context", {}) or {}).get("variants") or []
    if not variant or not variants:
        return None
    request = variants[0].get("request") or {}
    path = request.get("path")
    route = f"{request.get('method', 'GET')} {path}" if path else None
    return f"{variant} · {route}" if route else variant


def _action(tool: str, args: dict) -> str:
    """What a tool call does, in a few words: ``GET /rest/basket/2 as alice``, with the query and the
    body the agent chose, where an injection's payload sits."""
    if tool == "http_request":
        path = str(args.get("path", ""))
        text = f"{_clip(args.get('method') or 'GET', 10)} {_clip(path)}"
        params = args.get("params")
        if isinstance(params, dict) and params:
            query = "&".join(f"{key}={value}" for key, value in params.items())
            text += _clip(("&" if "?" in path else "?") + query, 60)
        if isinstance(args.get("json"), dict):
            text += " " + _clip(json.dumps(args["json"], ensure_ascii=False, separators=(",", ":")), 60)
    elif tool == "browser_check":
        text = f"browser {_clip(args.get('path', ''))}"
    elif tool == "read_source":
        line = args.get("around_line")
        text = f"source {_clip(args.get('path', ''))}" + (f":{line}" if isinstance(line, int) else "")
    else:
        text = _clip(tool, 40)
    return text + (f" as {_clip(args['role'], 40)}" if args.get("role") else "")


def _outcome(result: dict) -> list[tuple]:
    """A tool result as segments; what a proof needs stands out."""
    if result.get("error"):
        return [(f"error: {_clip(result['error'], 160)}",)]
    parts = []
    if isinstance(result.get("status"), int):
        parts.append(str(result["status"]))
    if isinstance(result.get("length"), int):
        parts.append(f"{result['length']} B")
    elif result.get("body_withheld"):          # an engine error or login artifact, never shown to a model
        parts.append("body withheld")
    if "executed" in result:
        parts.append(("script executed", "ok", "bold") if result["executed"] else "no script executed")
    if result.get("marker_read"):
        parts.append(("marker file read", "ok", "bold"))
    if result.get("callback_hit"):
        parts.append(("callback hit", "ok", "bold"))
    return _line(*parts) or [("done",)]


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


class ConsoleLog:
    """The copy of the console for ``console.log``. What is printed before the output directory exists is
    held until `start` names the file, and dropped if the run ends before that; from then on every line is
    written as it comes, so a cut-off run keeps its log. The status line's redraws are not copied, and
    ``plain`` leaves out the colour codes."""

    def __init__(self, *, plain: bool = False):
        self._plain = plain
        self._lock = threading.Lock()
        self._held: list[str] = []
        self._fh = None
        self.path = None

    def start(self, path, *, append: bool = False) -> None:
        """Write to ``path``, owner-only; ``append`` continues it (--resume), otherwise it is replaced."""
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
        fd = os.open(path, flags, 0o600)
        os.chmod(path, 0o600)             # also when an earlier run left the file with wider rights
        with self._lock:
            self._fh = os.fdopen(fd, "a" if append else "w", encoding="utf-8", buffering=1)
            self._fh.write("".join(self._held))
            self._held = []
            self.path = path

    def write(self, text: str) -> None:
        if text == _CLEAR or text.startswith(_FRAME_OPEN):
            return
        if self._plain:
            text = _ANSI.sub("", text)
        with self._lock:
            if self._fh is not None:
                self._fh.write(text)
            else:
                self._held.append(text)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
            self._held = []


class _Tee:
    """Stands in for standard output or error during `verify`: writes go to the console and to the log."""

    def __init__(self, stream, log: ConsoleLog):
        self.stream, self._log = stream, log

    def write(self, text: str) -> int:
        written = self.stream.write(text)
        self._log.write(text)
        return written

    def __getattr__(self, name: str):
        return getattr(self.stream, name)


@contextmanager
def console_log(*, plain: bool = False):
    """Copy standard output and error to a `ConsoleLog` until the block ends."""
    log = ConsoleLog(plain=plain)
    out, err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _Tee(out, log), _Tee(err, log)
    try:
        yield log
    finally:
        sys.stdout, sys.stderr = out, err
        log.close()


class RunProgress:
    """The run's progress grid on ``stream`` (standard error by default).

    The runner calls `begin`, then `finding`, `agent_finished` and `finished` per finding with a probe;
    the agent loop calls `activity` before each model or tool call and `step` with each action-log record.
    `close` stops the status line and must run however the run ends.
    """

    TICK_SECONDS = 0.2
    HEARTBEAT_SECONDS = 120
    BAR_WIDTH = 12
    MAX_COLUMNS = 140       # AppSec Analyzer's DEFAULT_COLUMNS: longer lines are hard to read on a wide window

    def __init__(self, stream=None, *, model: str | None = None, runtime: str | None = None,
                 max_steps: int | None = None, roles=(), source: bool = False, redact=None, remaining_time=None,
                 spent=None, cost_limit: float = 0.0, api_prices: bool = False,
                 live: bool | None = None, clock=time.time, env=None, out_dir=None):
        self._stream = sys.stderr if stream is None else stream
        self._out_dir = out_dir           # where the evidence paths of a result lie
        env = os.environ if env is None else env
        self.st = Style.for_stream(self._stream, env)
        if live is None:
            try:
                live = self._stream.isatty() and env.get("TERM") != "dumb"
            except (AttributeError, ValueError):
                live = False
        self.live = live
        self._model = _clip(short_model(str(model)), 40) if model else "the model"
        self._redact = redact
        # The test agent's start entry: what tests the finding, with which budget and authority.
        who = " via ".join(part for part in (self._model if model else "", _clip(runtime or "", 40)) if part)
        names = _clip(self._text(", ".join(str(role) for role in roles)), 60)
        self._agent = _line(who, f"≤{max_steps} steps" if max_steps else "",
                            f"identities {names}" if names else "no identities",
                            "source code" if source else "")
        self._remaining_time = remaining_time
        self._spent, self._cost_limit, self._api_prices = spent, cost_limit, api_prices   # spent: None hides costs
        self._step_spent_at = 0.0       # the spend when the finding began or an entry last showed it
        self._clock = clock
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._shown = False
        self._paused = False        # a question waits for the operator: no status line, no heartbeat
        self._frame = 0
        self.total = self.done = self.number = 0
        self._variants: Counter = Counter()     # variants per finding of the grid; findings, not variants, count
        self._finished: Counter = Counter()     # variants of each finding that have finished
        self._numbered = None                   # the finding the current number belongs to
        self._id = ""
        self._id_width = 0
        self._steps, self._noted = 0, False
        self._explained = False         # a proof entry said why the finding has no proof
        self._reviewing = False         # an evidence reviewer started and has not finished
        self._planned = False           # a plan of the current finding was already accepted
        self._in_controls = False       # the last step was a generated control of an experiment
        self._review_from = None        # when the current evidence review started
        self._review_time = 0.0         # time of the finding's evidence review, kept off its done line
        self._activity, self._activity_at = "", 0.0
        self._asked: tuple[int, float] | None = None     # (step, when the model call for it began)
        self._took: tuple[int, float] | None = None      # (step, how long the model took to propose it)
        self.started = self.last = self._finding_at = clock()

    # ── events ────────────────────────────────────────────────────────────────

    def begin(self, plans: list) -> None:
        """Start the grid for the findings with a probe; without any, nothing is shown. `plans` holds one entry
        per variant; the grid counts findings, so the variants of one finding share its number and the finding
        counts as done once its last variant is."""
        self._variants = Counter(plan.id for plan in plans)
        self._finished = Counter()
        self._numbered = None
        self.total = total = len(self._variants)
        if not total:
            return
        self.started = self.last = self._clock()
        self._id_width = len(f"{total}/{total} ") + max(len(_clip(plan.id, 16)) for plan in plans)
        sys.stdout.flush()      # the run settings above, when both streams go to one log
        self._write("")
        self._write(self.st(f"{'TIME':<8}  {'FINDING':<{self._id_width}}  {'EVENT':<7}  {'PROGRESS':>8}  "
                            f"{'ELAPSED':>7}  {'LEFT':>6}  DETAIL", "muted", "bold"))
        self._thread = threading.Thread(target=self._ticker, name="appsec-verifier-progress", daemon=True)
        if self.live:
            if not isinstance(sys.stderr, _StatusGuard):
                sys.stderr = _StatusGuard(sys.stderr, self)
            if sys.stdout.isatty() and not isinstance(sys.stdout, _StatusGuard):
                sys.stdout = _StatusGuard(sys.stdout, self)
        self._thread.start()

    def finding(self, plan, *, agent: bool = True) -> None:
        """The finding's ``start`` entry; ``agent`` off when no agent starts for it."""
        with self._lock:
            if self.number:
                self._write("")         # sets the finding apart from the one before
            if plan.id != self._numbered:   # another variant of the same finding keeps its number
                self.number += 1
                self._numbered = plan.id
            self._id = _clip(plan.id, 16)
            self._steps, self._activity, self._noted, self._explained = 0, "", False, False
            self._planned = self._in_controls = False
            self._review_from, self._review_time = None, 0.0
            self._asked = self._took = None
            self._finding_at = self._clock()
            self._step_spent_at = self._spent() if self._spent is not None else 0.0
            title = _clip(self._text(plan.title or plan.cwe or "")) or "-"
            severity = _clip(self._text(plan.severity or ""), 10).lower()
            # A variant names its own request and key, so its line differs from its siblings'; otherwise the
            # finding's named requests.
            requests = _variant_detail(plan) or ", ".join(str(e) for e in getattr(plan, "endpoints", ())[:2])
            self._record("start", [(title, "bold")],
                         _line((severity, severity if severity in _SEVERITIES else "muted"),
                               _clip(plan.cls or "-", 20), _clip(self._text(requests), 120)))
            if agent:
                self._record("agent", _line(("▶ test agent started", "agent", "bold"), self._agent))

    def activity(self, step: int, of: int, tool: str | None = None, args: dict | None = None) -> None:
        """What runs now, for the status line and the heartbeat: a model call or a tool call."""
        what = f"{self._model} plans" if tool is None else _action(tool, self._text(args or {}))
        with self._lock:
            now = self._clock()
            if tool is None:
                self._asked = (step, now)
            elif self._asked is not None and self._asked[0] == step:
                self._took = (step, now - self._asked[1])
            self._activity, self._activity_at = f"step {step}/{of} · {what}", now

    def step(self, record: dict) -> None:
        """One line per tool call, refused step and stopping limit of the action log (VER-017)."""
        record = self._text(record)
        number = record.get("step")
        with self._lock:
            self._activity = ""
            if isinstance(number, int):
                self._steps = number
            head = f"step {number}"
            note = _clip(record["note"]) if isinstance(record.get("note"), str) else ""
            args = record.get("args") if isinstance(record.get("args"), dict) else {}
            action = _action(str(record["tool"]), args) if "tool" in record else ""
            took = f"model{_NBSP}{duration(self._took[1])}" if self._took and self._took[0] == number else ""
            cost = self._run_cost() if record.get("stopped") or record.get("refused") or action else []
            self._noted = self._noted or bool(record.get("stopped") or record.get("refused"))
            if record.get("tool") == "proof_feedback":
                # The proof check refused a claimed confirmation and the agent gets another try (agent/loop.py).
                result = record.get("result") if isinstance(record.get("result"), dict) else {}
                missing = result.get("missing") if isinstance(result.get("missing"), list) else []
                reason = _clip(missing[0], 200) if missing else "the class's proof is missing"
                self._record("proof", _line(head, [("✗ proof not accepted", "warn", "bold"), (f": {reason}", "warn")],
                                            "back to the agent", cost), role="warn")
            elif record.get("stopped"):
                # A test agent that made no progress was stopped; it did not reach a budget (limits.py).
                stop = "stopped" if record.get("stopped") == "stagnation" else "stopped by limit"
                reason = f"{stop}: {_clip(record.get('reason', ''), 240)}"
                self._record("⚠", _line(head, note, action, reason, cost))
            elif record.get("refused"):
                self._record("↻", _line(head, f"refused: {_clip(record['refused'], 160)}", cost))
            elif record.get("tool") == "technical_review":
                # The technical QA's outcome after the agent, no step of its own (agent/loop.py); with an objection
                # it stands beside the verdict, so its first one is shown (VER-046).
                result = record.get("result") if isinstance(record.get("result"), dict) else {}
                issues = [i for i in result.get("issues") or [] if isinstance(i, dict)]
                detail = _clip(str(issues[0].get("detail") or ""), 240) if issues else ""
                self._record("qa", _line(f"Technical QA: {_clip(str(result.get('status') or ''), 40)}", detail,
                                         cost))
            elif action:
                # The request tested against the target in its own colour, on its own row under the note when
                # there is one.
                result = record.get("result") if isinstance(record.get("result"), dict) else {}
                if record["tool"] == "plan_test" and result.get("accepted"):
                    # One row: the request and, for a revision, the plan's own note. The report keeps the whole
                    # plan (Test planning, verify/report.py).
                    reason = (args.get("strategy") or {}).get("revision_reason") or args.get("note") or ""
                    label = "plan revised" if self._planned else "test plan"
                    self._planned = True
                    self._record("plan", _line(label, _clip(args.get("path", "")),
                                               _clip(reason, 180) if reason else ""))
                    return
                control = record.get("control") if isinstance(record.get("control"), str) else ""
                if control:
                    # A generated control (agent/loop.py): the series' first row shows the request, the others
                    # only which control they are, since they differ in a value the row would cut off.
                    role = f" as {_clip(args['role'], 40)}" if args.get("role") else ""
                    action = (f"control {_clip(control, 40)} · {action}" if not self._in_controls
                              else f"control {_clip(control, 40)}{role}")
                self._in_controls = bool(control)
                tested = (action, "agent") if record["tool"] in ("http_request", "browser_check") else (action,)
                tested = _line([tested, (" → ",), *_outcome(result)], (took, "muted"), cost)
                hang = len(head) + 3
                if note:
                    self._record("·", _line(head, note), tested, hang=hang)
                else:
                    self._record("·", _line(head, tested), hang=hang)

    def evidence_review(self, finding: str, stage: str, round_: int, detail: str) -> None:
        """Presentation work has its own rows; it never counts as a target test step (VER-042)."""
        with self._lock:
            old_id = self._id
            self._id = _clip(self._text(finding), 16)
            label = "initial" if stage == "review" and round_ == 0 else f"correction {round_}/2"
            text = self._text(detail)
            if stage == "issue":        # without the variant key in front; the report names it
                text = text.partition(": ")[2] or text
            # The reviewer's words, first sentence each, as the report shows them.
            text = _clip(_first_sentence(text), 160) if stage in ("revise", "issue") else _clip(text, 300)
            self._activity = f"{self._id} · evidence {stage} · {label}" if stage in ("review", "revise") else ""
            self._activity_at = self._clock()
            cost = self._run_cost()
            if stage == "review" and round_ == 0:       # the reviewer's first call: it starts
                self._reviewing = True
                self._review_from = self._clock()
                self._record("agent", _line(("▶ evidence reviewer started", "agent", "bold"), text, cost))
            elif stage == "quality" and self._reviewing:
                self._reviewing = False
                # The review's own time, shown here and left out of the variant's done line.
                took = 0.0
                if self._review_from is not None:
                    took = self._clock() - self._review_from
                    self._review_time += took
                    self._review_from = None
                self._record("agent", _line(("■ evidence reviewer finished", "agent", "bold"), text, duration(took),
                                            cost))
            elif stage == "issue":
                self._record(stage, _line(text, cost))
            else:
                self._record(stage, _line(label, text, cost))
            self._id = old_id

    def agent_finished(self, plan, result) -> None:
        """The test agent's end, then whether its verdict's proof was checked or why there is none (VER-013)."""
        with self._lock:
            self._activity = ""
            steps = f"{self._steps} step" + ("s" if self._steps != 1 else "") if self._steps else ""
            self._record("agent", _line(("■ test agent finished", "agent", "bold"), steps,
                                        duration(self._clock() - self._finding_at)))
            proof = result.proof if isinstance(result.proof, dict) else {}
            if result.verdict == "confirmed" and proof.get("checked") is True:
                cited = [n for n in proof.get("steps") or [] if isinstance(n, int)]
                where = f"step{'s' if len(cited) > 1 else ''} {', '.join(map(str, cited))}" if cited else ""
                shown = (proof_shown(proof, plan.cls) or (None,))[0]
                self._record("proof", _line([("✓ proof checked", "ok", "bold"),
                                             *([(f": {shown}", "ok")] if shown else [])], where), role="ok")
                return
            missing = proof.get("missing") if proof.get("checked") is False else None
            if isinstance(missing, list) and missing:
                why = missing[0]                # what the proof check missed in a claimed confirmation
            elif result.limits_hit == "stagnation":
                why = "the test agent made no progress and was stopped"   # the ⚠ entry above says why
            elif result.limits_hit:
                why = f"stopped by the {result.limits_hit} limit"      # the ⚠ entry above has the detail
            else:
                why = result.rationale or "no verdict"
            why = _clip(self._text(why), 200)
            self._record("proof", [("✗ no proof", "warn", "bold"), (f": {why}", "warn")], role="warn")
            self._explained = True

    def finished(self, plan, result, rating: dict | None = None) -> None:
        """The finding's verdict, marked and highlighted; with ``rating`` (VER-039) its change, if any."""
        verdict = printable(result.verdict)
        label = _VERDICT_LABEL.get(verdict, verdict)      # as the report and the results at the end name it
        role = _VERDICT_ROLES.get(verdict)
        label += f" ({_clip(result.confidence, 10)})" if result.confidence else ""
        mark = _VERDICT_MARKS.get(verdict)
        parts = [(f"{mark} {label}" if mark else label, *([role] if role else []), "bold")]
        with self._lock:
            # An evidence review of the finding has its own row with its time (evidence_review).
            parts.append(duration(max(0.0, self._clock() - self._finding_at - self._review_time)))
            if self._spent is not None:
                parts.append([("run" + _NBSP,), *self._spend()])
            # Why, in its first sentence, unless a refused step, a limit or the proof entry above already said so.
            why = (_clip(_first_sentence(self._text(result.rationale)), 160)
                   if result.rationale and not self._noted and not self._explained else "")
            # A finding is done once its last variant is; a plan begin() did not see counts on its own.
            self._finished[plan.id] += 1
            if self._finished[plan.id] >= self._variants.get(plan.id, 1):
                self.done += 1
            self._activity = ""
            self._record("done", _line(*parts), *([_line(why)] if why else []), role=role)
            if rating and rating.get("changed"):
                self._rating(rating)
            # A screenshot shows proof only where the Verifier checked the verdict's proof (proof.py).
            event = "proof" if isinstance(result.proof, dict) and result.proof.get("checked") is True else "img"
            for entry in result.evidence or []:
                if isinstance(entry, dict) and entry.get("kind") == "screenshot" and entry.get("path"):
                    path = os.path.join(self._out_dir, entry["path"]) if self._out_dir else entry["path"]
                    self._record(event, _line(f"screenshot {printable(path)}"))

    @contextmanager
    def paused(self):
        """Remove the status line and keep it away while a question waits for the operator (VER-015)."""
        with self._lock:
            self._paused = True
            self._clear()
        try:
            yield
        finally:
            with self._lock:
                self._paused = False
                self.last = self._clock()

    def raise_cost_limit(self, limit: float) -> None:
        """The higher cost ceiling the operator typed, for the run's spend shown from now on (VER-015)."""
        with self._lock:
            self._cost_limit = limit

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

    def _rating(self, rating: dict) -> None:
        """``severity Medium → High · likelihood Low → High · confirmed with a checked proof`` (verify/rating.py)."""
        before, after = rating.get("analyzer") or {}, rating.get("after_verification") or {}
        changes = [f"{name} {_clip(before.get(name), 20)} → {_clip(after.get(name), 20)}"
                   for name in ("severity", "likelihood") if before.get(name) != after.get(name)]
        why = _clip(str(rating.get("reason", "")).partition(": ")[0], 120)
        self._record("rating", _line(*[(change, "bold") for change in changes], (why, "muted")))

    def _ticker(self) -> None:
        while not self._stop.wait(self.TICK_SECONDS if self.live else 1.0):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - a status redraw must never end the run or print a traceback
                pass

    def tick(self) -> None:
        """On a terminal redraw the status line; off it write a line after a quiet stretch."""
        with self._lock:
            if not self._id or self._stop.is_set() or self._paused:
                return
            now = self._clock()
            age = duration(now - self._activity_at) if self._activity else ""
            spend = self._spend(qualified=False) if self._spent is not None else []
            if self.live:
                self._frame += 1
                self._status(self._row(SPINNER[self._frame % len(SPINNER)], [_line(spend, self._activity, age)],
                                       now, live=True))
            elif now - self.last >= self.HEARTBEAT_SECONDS:
                self._record("·", _line(spend, self._activity or "working", age))

    def _spend(self, *, qualified: bool = True) -> list[tuple]:
        """The run's spend against its cost limit, ``$0.42 of $10.00``, the amount highlighted as in AppSec
        Analyzer; ``qualified`` adds ``at API prices`` where a subscription pays."""
        amount, _, rest = spent_text(self._spent(), self._cost_limit,
                                     api_prices=qualified and self._api_prices).partition(" ")
        return [(amount, "accent"), (_NBSP + rest.replace(" ", _NBSP),)]

    def _run_cost(self) -> list[tuple]:
        """The run's spend so far, ``run $0.42`` with the amount highlighted, when model calls cost something
        since the finding began or an entry last showed it; nothing when the run shows no costs."""
        if self._spent is None:
            return []
        total = self._spent()
        grew, self._step_spent_at = total > self._step_spent_at, total
        return [("run" + _NBSP,), (f"${total:.2f}", "accent")] if grew else []

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

    def _row(self, event: str, lines: list[list[tuple]], now: float, *, live: bool = False,
             role: str | None = None, hang: int = 0) -> str:
        """The grid columns, then the entry's ``lines`` of segments. On a terminal each line starts a row of
        its own and wraps; the rows after the first are indented by ``hang`` more. Off a terminal, and on
        the status line, the lines are joined into one."""
        st = self.st
        finding = f"{self.number}/{self.total} {self._id}" if self._id else ""
        share, elapsed, left = self._run(now)
        stamp = time.strftime("%H:%M:%S", time.localtime(now))
        bar = f"{self._bar()}  " if live else ""
        head = (f"{st(stamp, 'muted')}  "
                + st(f"{finding:<{self._id_width}}", *(("bold",) if event in ("start", "done") else ()))
                + f"  {st(f'{event:<7}', 'accent' if live else role or _EVENT_ROLES.get(event, 'muted'))}  "
                + st(f"{share:>8}  {elapsed:>7}  {left:>6}", "muted") + f"  {bar}")
        indent = len(_ANSI.sub("", head))
        if event in ("↻", "⚠"):        # needs attention: all but the highlighted amounts in the warning colour
            lines = [[segment if len(segment) > 1 else (segment[0], "warn") for segment in line] for line in lines]
        rows: list[str] = []
        width = min(columns(), self.MAX_COLUMNS) - 1 - indent
        if (st.enabled or self.live) and not live:
            for line in lines:
                text = "".join(segment[0] for segment in line)
                first = width - (hang if rows else 0)
                spans = _spans(text, first, width - hang) if width - hang >= 30 else [(0, len(text))]
                rows += [self._paint(line, start, end) for start, end in spans]
        else:
            line = _line(*lines)
            rows.append(self._paint(line, 0, sum(len(segment[0]) for segment in line)))
        first, *rest = rows or [""]
        return "\n".join([head + first, *(" " * (indent + hang) + row for row in rest)]).rstrip()

    def _paint(self, line: list[tuple], start: int, end: int) -> str:
        """Characters ``start`` to ``end`` of a line of segments, each piece in its segment's roles."""
        pieces, pos = [], 0
        for text, *roles in line:
            a, b = max(start, pos), min(end, pos + len(text))
            if a < b:
                pieces.append(self.st(text[a - pos:b - pos].replace(_NBSP, " "), *roles))
            pos += len(text)
        return "".join(pieces)

    def _bar(self) -> str:
        filled = round(self.BAR_WIDTH * self.done / self.total) if self.total else 0
        return self.st("━" * filled, "accent") + self.st("─" * (self.BAR_WIDTH - filled), "muted")

    def _record(self, event: str, *lines: list[tuple], role: str | None = None, hang: int = 0) -> None:
        now = self._clock()
        self._write(self._row(event, list(lines), now, role=role, hang=hang))
        self.last = now

    def _write(self, line: str) -> None:
        with self._lock:
            self._clear()
            self._stream.write(line + "\n")
            self._stream.flush()

    def _status(self, line: str) -> None:
        """Overwrite the status line in place; a line too wide for the terminal or ``MAX_COLUMNS`` is cut, not
        wrapped."""
        width = min(columns(), self.MAX_COLUMNS) - 1
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
