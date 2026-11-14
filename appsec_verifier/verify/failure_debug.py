"""The private debug file of a run's failed verifications (VER-063).

When the test of a finding ends inconclusive because of an error in the Verifier, a failed call or unusable answer
of the model host or a breach of its confinement (agent/hosts.py), or a test agent stopped without progress
(agent/controller.py), `failed-findings.json` keeps what a person or a model needs to find the cause: every model
call of that finding with its instructions, schema, prompt and answer, the error with its traceback and the source
of the Verifier function it passed last, and the run's identity. A reached limit, a cancelled run and a test that
found no sufficient proof are not failures.

Target and source data reach the file only as the model received them. The tool actions and the recorded requests
stay in the action log and the evidence files, which the file names instead of copying them. Before an entry is
kept, credential values and the marker file's content are replaced (VER-012, VER-016). The file is owner-only,
rewritten atomically after each failure, and never enters the report or the Analyzer export (VER-021, VER-022).
A run removes the file an earlier run left in its directory, so the file names only its own failures. Its
structure follows AppSec Analyzer's `failed-jobs.json`. Writing it never changes the run.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path

FILE_NAME = "failed-findings.json"
SCHEMA_VERSION = 1
MAX_MESSAGE_CHARS = 16_384   # an error's text; prompts and answers are never shortened
MAX_CODE_LINES = 200         # a longer function shows the lines around the failure
_PACKAGE = Path(__file__).resolve().parents[1]

READING_GUIDE = (
    "Each entry in findings is one finding whose verification failed. failure.kind says how: error is an exception "
    "in the Verifier, with its type, message, traceback and location (code holds the source of the Verifier function "
    "at that location); model is a failed model call, an answer that was no usable step, or a breach of the model "
    "host's confinement; stagnation is a test agent stopped after repeated failed actions without a usable "
    "observation. calls lists every model call of that finding in order: the system instructions (by "
    "instructions_sha256 in instructions), the output schema (by schema_sha256 in schemas), the exact prompt, and "
    "the model's answer, or the failure of a call that returned none. The tool actions and their outcomes are the "
    "records with the same finding in the action log named by action_log; recorded requests and responses are in "
    "the evidence files the entry lists. Credential values and the marker file's content are replaced by "
    "placeholders. Decide for each finding whether the cause lies in the Verifier (instructions, schema, step "
    "contract, tools or code), in the model's answers, or in the model host or environment, and cite the call or "
    "the code location."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode(errors="backslashreplace")).hexdigest()


def _message(text) -> str:
    """An error's text without control characters, bounded."""
    text = "".join(c if c.isprintable() or c in "\n\t" else " " for c in str(text))
    if len(text) > MAX_MESSAGE_CHARS:
        half = MAX_MESSAGE_CHARS // 2
        text = text[:half] + " … [message truncated] … " + text[-half:]
    return text


def _where(filename: str) -> tuple[str, bool]:
    """A frame's file relative to the package, or its last two path parts outside it (no home directory)."""
    path = Path(filename).resolve()
    try:
        return path.relative_to(_PACKAGE).as_posix(), True
    except ValueError:
        return "/".join(path.parts[-2:]), False


def failure(ctx, result, error: BaseException | None = None) -> dict | None:
    """Why the finding's verification failed, or None when it did not fail."""
    if error is not None:
        frames, location = [], None
        for frame in traceback.extract_tb(error.__traceback__):
            path, inside = _where(frame.filename)
            frames.append({"at": f"{path}:{frame.lineno}", "function": frame.name, "line": frame.line})
            location = f"{path}:{frame.lineno}" if inside else location
        return {"kind": "error", "type": type(error).__name__, "message": _message(error), "location": location,
                "traceback": frames}
    if result.verdict != "inconclusive":
        return None
    if result.limits_hit == "stagnation":
        return {"kind": "stagnation", "message": result.rationale}
    reason = getattr(ctx, "model_failure", None)
    if reason and not result.limits_hit:
        return {"kind": "model", "message": _message(reason)}
    return None


def _code(location: str) -> dict | None:
    """The source of the Verifier function that holds `location` (`path/in/package.py:line`)."""
    name, _, number = location.rpartition(":")
    path = (_PACKAGE / name).resolve()
    if not number.isdigit() or not path.is_relative_to(_PACKAGE) or path.suffix != ".py" or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
        return None
    line, enclosing = int(number), None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.lineno <= line <= (node.end_lineno or 0):
            if enclosing is None or node.lineno >= enclosing.lineno:
                enclosing = node
    start, end = (enclosing.lineno, enclosing.end_lineno) if enclosing else (line, line)
    if end - start + 1 > MAX_CODE_LINES:
        start = max(start, line - MAX_CODE_LINES // 2)
        end = min(end, start + MAX_CODE_LINES - 1)
    return {"function": enclosing.name if enclosing else None, "path": name, "line": line, "start_line": start,
            "end_line": end, "code": "\n".join(text.splitlines()[start - 1:end])}


def run_identity(*, verifier_version: str, agent: dict, assessment: Path, target: str, safe: bool,
                 read_only: bool) -> dict:
    """What the file names about the run, with explicitly selected fields only: no connection settings, no
    credentials and no names of the variables that hold them."""
    try:
        digest = hashlib.sha256(Path(assessment).read_bytes()).hexdigest()
    except OSError:
        digest = None
    return {
        "started": _now(),
        "verifier_version": verifier_version,
        "profile": agent.get("profile"),
        "model": agent.get("model"),
        "runtime": agent.get("runtime"),
        "mode": "safe" if safe else "intrusive",
        "read_only": bool(read_only),
        "target": target,
        "assessment": str(assessment),
        "assessment_sha256": digest,
    }


class FailureDebug:
    """Keeps the run's failed verifications in one private file; a storage failure never changes the run."""

    def __init__(self, directory: Path, *, run: dict, redact=None, hidden: str | None = None):
        self.path = Path(directory) / FILE_NAME
        self.path.unlink(missing_ok=True)    # an earlier run's failures are not this run's, also after --resume
        self._redact = redact
        self._hidden = hidden or None
        self.run = self._clean(run)
        self.findings: list[dict] = []
        self.instructions: dict[str, str] = {}
        self.schemas: dict[str, object] = {}
        self.code: dict[str, dict] = {}
        self.written = 0             # how many findings the file on disk holds
        self.disabled = False

    def record(self, plan, ctx, result, error: BaseException | None = None) -> None:
        """Keep the finding when its verification failed, and rewrite the file."""
        if self.disabled:
            return
        try:
            why = failure(ctx, result, error)
            if why is None:
                return
            self.findings.append(self._entry(plan, ctx, result, why))
            self._write()
            self.written = len(self.findings)
        except Exception as exc:  # noqa: BLE001 - the debug file must never change the run or replace its error
            self.disabled = True
            print(f"debug file not written ({type(exc).__name__}); the run goes on", file=sys.stderr)

    def _clean(self, value):
        """`value` with credential values and the marker file's content replaced (VER-012, VER-016)."""
        from ..agent.tools import _hide

        return _hide(self._redact(value) if self._redact is not None else value, self._hidden)

    def _entry(self, plan, ctx, result, why: dict) -> dict:
        calls = []
        for exchange in getattr(ctx, "model_exchanges", None) or ():
            call = {key: value for key, value in exchange.items() if key not in ("instructions", "schema")}
            system = str(exchange.get("instructions", ""))
            call["instructions_sha256"] = key = _sha256(system)
            if key not in self.instructions:
                self.instructions[key] = self._clean(system)
            schema = json.dumps(exchange.get("schema"), sort_keys=True, default=str)
            call["schema_sha256"] = key = _sha256(schema)
            if key not in self.schemas:
                self.schemas[key] = self._clean(json.loads(schema))
            if "answer" in call:
                call["answer"] = json.loads(call["answer"])
            calls.append(call)
        location = why.get("location")
        if location and location not in self.code and (found := _code(location)) is not None:
            self.code[location] = found
        return self._clean({
            "finding": plan.id,
            "variant": plan.variant_id,
            "title": plan.title or None,
            "class": plan.cls,
            "cwe": plan.cwe or None,
            "recorded": _now(),
            "rationale": result.rationale,
            "failure": why,
            "calls": calls,
            "evidence": [e["path"] for e in result.evidence or ()
                         if isinstance(e, dict) and isinstance(e.get("path"), str)],
        })

    def _write(self) -> None:
        data = json.dumps({
            "schema_version": SCHEMA_VERSION,
            "kind": "appsec-verifier failed verifications",
            "reading_guide": READING_GUIDE,
            "written": _now(),
            "run": self.run,
            "action_log": "agent-log.jsonl",
            "findings": self.findings,
            "instructions": self.instructions,
            "schemas": self.schemas,
            "code": self.code,
        }, ensure_ascii=False, indent=1, default=str)
        fd, temporary = tempfile.mkstemp(prefix=f".{FILE_NAME}.", suffix=".tmp", dir=self.path.parent)  # owner-only
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(data)
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
