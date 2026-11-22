"""Start from an earlier confirmation (VER-068).

Before a run tests its findings, it looks up for each finding variant the newest confirmation that an earlier run
of the same project made against the same target, with a proof the code checked under the current contract
(`report.checked_verdict`). Nothing is stored for this: the reports the runs keep in the data directory (VER-058)
are read, the newest first, and with --resume first the report the run continues (VER-037). A linked, too large,
unreadable or invalid report is passed over; a run never needs a hint. A finding variant is the same when its
class, `match_key`, `instance` and variant digest are (VER-007); a changed variant of a regenerated assessment
gets no hint.

A hint holds the proof's form and path and the requests its decisive steps sent, one line each with the body the
proof of concept shows: no answer, no other step, without the target's origin, and with the Verifier's markers and
controls (`vrf…`) replaced by `<marker>`, since every run generates its own. The test agent receives it as data
in its finding's seed (agent/prompts.py). It is a hint, never evidence: its requests pass the same checks as any
other, and only the current run's proof confirms. Removing a run (VER-064) removes its hints.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from ..run_dirs import REPORT, RUN_NAME
from .report import checked_verdict, read_report

MAX_RUNS = 20                        # the newest runs of the project that are read
MAX_REPORT_BYTES = 8 * 1024 * 1024   # a larger report is passed over
MAX_REQUESTS = 6
MAX_LINE = 240
MAX_BODY = 300
_MARKER = re.compile(r"vrf[0-9a-f]{6,}")
# The second part of an XSS marker, which the payload joins to the first at runtime: alert('vrf…'.concat('…')).
_MARKER_PART = re.compile(r"(<marker>(?:['\"`]|%2[27]|%60)\.concat(?:\(|%28)(?:['\"`]|%2[27]|%60))[0-9a-f]{8}")
NOTE = ("how an earlier run against this target confirmed this finding; a starting point, not evidence: its "
        "requests pass the usual checks, and <marker> stands for a marker or control this run generates anew")


def plan_key(plan) -> tuple | None:
    """The finding variant a hint belongs to; None without a match_key."""
    return _key(plan.cls, plan.match_key, plan.instance, plan.variant_digest)


def earlier_confirmations(project_dir: Path | None, target: str, *, first: Path | None = None,
                          wanted: set | None = None) -> dict:
    """The hint of each finding variant (plan_key -> hint) from its newest checked confirmation against `target`:
    from `first`, the report --resume continues, then from the newest runs in `project_dir`. With `wanted`, only
    those variants, and reading stops once each has one."""
    hints: dict = {}
    for path in _reports(project_dir, first):
        if wanted is not None and wanted <= hints.keys():
            break
        doc = _read(path)
        if doc is None or not _same_target((doc["meta"].get("target") or {}).get("base_url"), target):
            continue
        for r in doc.get("results") or []:
            ref = r.get("finding_ref") or {}
            key = _key(r.get("class"), ref.get("match_key"), ref.get("instance"), ref.get("variant_digest"))
            if key is None or key in hints or (wanted is not None and key not in wanted):
                continue
            if hint := _hint(r, path.parent.name, target):
                hints[key] = hint
    return hints


def for_prompt(hint: dict) -> dict:
    """What the test agent reads: the requests and the proof's form, without the run they came from."""
    return {"note": NOTE, **{k: hint[k] for k in ("form", "kind", "path", "requests") if hint.get(k)}}


def provenance(hint: dict) -> dict:
    """What the report records: the run the hint came from and when that run tested the finding."""
    return {"run": hint["run"], "tested": hint.get("tested")}


def _same_target(recorded, target: str) -> bool:
    """The same scheme, host, port and base path; a trailing slash makes no difference."""
    if not isinstance(recorded, str):
        return False
    a, b = urlsplit(recorded), urlsplit(target)
    return (a.scheme.lower(), a.netloc.lower(), a.path.rstrip("/")) == (b.scheme.lower(), b.netloc.lower(),
                                                                        b.path.rstrip("/"))


def _key(cls, match_key, instance, variant_digest) -> tuple | None:
    return (cls, match_key, instance, variant_digest) if match_key else None


def _reports(project_dir: Path | None, first: Path | None) -> Iterator[Path]:
    paths = [first] if first is not None else []
    try:
        if project_dir is not None and project_dir.is_dir() and not project_dir.is_symlink():
            runs = sorted((p for p in project_dir.iterdir() if RUN_NAME.fullmatch(p.name) and not p.is_symlink()),
                          key=lambda p: p.name, reverse=True)
            paths += [run / REPORT for run in runs[:MAX_RUNS]]
    except OSError:
        pass
    seen = set()
    for path in paths:
        try:
            real = path.resolve()
        except OSError:
            continue
        if real not in seen:
            seen.add(real)
            yield path


def _read(path: Path) -> dict | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
            return None
    except OSError:
        return None
    doc, errors = read_report(path)
    return None if errors else doc


def _hint(r: dict, run: str, target: str) -> dict | None:
    if r.get("verdict") != "confirmed" or not checked_verdict(r):
        return None
    poc = r.get("poc") or {}
    bodies = {s.get("step"): _body(s.get("request")) for s in poc.get("shown") or [] if isinstance(s, dict)}
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None
    requests: list[str] = []
    for s in poc.get("steps") or []:
        if not isinstance(s, dict) or not s.get("decisive") or not isinstance(s.get("line"), str):
            continue
        line = s["line"].split(" → ", 1)[0]          # the request; what answered stays out
        line = _clean(line.replace(origin, "") if origin else line, MAX_LINE)
        body = bodies.get(s.get("step"))
        entry = f"{line} body {body}" if body else line
        if entry and entry not in requests:
            requests.append(entry)
    if not requests:
        return None
    proof = r.get("proof") or {}
    return {"run": run, "tested": (r.get("timing") or {}).get("started"), "form": proof.get("form"),
            "kind": proof.get("kind"), "path": _clean(proof.get("tested_path"), MAX_LINE),
            "requests": requests[:MAX_REQUESTS]}


def _body(request) -> str | None:
    """The body of a raw request as the proof of concept shows it, without its headers."""
    if not isinstance(request, str) or "\n\n" not in request:
        return None
    return _clean(request.split("\n\n", 1)[1].strip(), MAX_BODY)


def _clean(text, limit: int) -> str | None:
    if not isinstance(text, str) or not text.strip():
        return None
    text = _MARKER_PART.sub(r"\1<marker>", _MARKER.sub("<marker>", text.strip()))
    return text if len(text) <= limit else text[: limit - 1] + "…"
