"""The Analyzer's report with the verification results (VER-038).

`verify --annotate` also writes `security-assessment.annotated.md`: a copy of the Markdown report that
AppSec Analyzer saved next to the assessment, in which each tested finding gets a verification section
(verdict, rationale, rating after verification of VER-039, proof of concept and screenshots), a summary of
the verification precedes the findings, and the changelog table gets a row for the verification run. The
original report is never changed.

The copy relies on the Analyzer's Markdown layout (scripts/renderers/compose_threat_model.py and
templates/fragments/changelog-table.md.j2 in AppSec Analyzer): one `<a id="t-…"></a>` anchor line per
finding of the findings register, and a `## Changelog` table. A finding without exactly one such anchor is
listed at the end of the copy, never left out. Figures the report references by a plain file name are
copied next to the copy so that it renders; nothing else of the Analyzer's directory is read.

The report is untrusted input (VER-005): its size is capped, and code fences are respected when the copy
looks for anchors and headings. Proofs of concept and screenshots can show target data (VER-022); the
summary says so.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
from pathlib import Path

from .poc import TARGET_DATA_NOTE
from .report import _VERDICT_LABEL, _poc_markdown, _review_markdown, _when, write_text_atomically

ANNOTATED_REPORT = "security-assessment.annotated.md"
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FIGURE_BYTES = 16 * 1024 * 1024

_FINDING_ANCHOR = re.compile(r'^<a id="t-\d+"></a>')
_HEADING = re.compile(r"^(#{1,6}) ")
_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_FIGURE_REF = re.compile(r'(?:src|srcset)="([^"]+)"|!\[[^\]]*\]\(([^)\s]+)\)')
_FIGURE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.(?:svg|png|jpe?g)", re.IGNORECASE)


def write_annotated_report(assessment: Path, annotated: dict, doc: dict, out_dir: Path) -> str:
    """Write the copy into out_dir when the Analyzer's report lies next to the assessment.
    Returns the line the run prints: the path written, or why nothing was written."""
    source = Path(assessment).with_suffix(".md")
    if source.is_symlink() or not source.is_file():
        return f"not written: no file {source.name} next to the assessment"
    body = _read_bounded(source, MAX_REPORT_BYTES)
    if len(body) > MAX_REPORT_BYTES:
        return f"not written: {source.name} is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB"
    markdown = body.decode("utf-8", errors="replace")
    dest = Path(out_dir) / ANNOTATED_REPORT
    write_text_atomically(dest, annotate_report(markdown, annotated, doc))
    copy_figures(markdown, source.parent, Path(out_dir))
    return f"{dest} ({TARGET_DATA_NOTE})"


def annotate_report(markdown: str, annotated: dict, doc: dict) -> str:
    """The report with the verification results; `annotated` is the output of annotate_assessment."""
    lines = markdown.splitlines()
    fenced = _fenced_lines(lines)
    results = {r.get("result_id"): r for r in doc["results"]}
    blocks = [t for t in annotated.get("threats") or [] if isinstance(t, dict) and t.get("dynamic_verification")]
    tested = [t for t in blocks if t["dynamic_verification"]["verdict"] != "not-attempted"]

    inserts: list[tuple[int, list[str]]] = []
    placed, unplaced = set(), []
    for t in tested:
        anchor = _anchor(lines, fenced, str(t.get("id") or ""))
        if anchor is None:
            unplaced.append(t)
            continue
        placed.add(t.get("id"))
        inserts.append((_section_end(lines, fenced, anchor), ["", *_section(t, results)]))

    changelog_row = _changelog_row(doc, tested)
    at = _changelog_insert(lines, fenced)
    if at is not None:
        inserts.append((at[0], [_table_row(changelog_row, at[1])]))
    summary = _summary(annotated, doc, tested, placed, not_tested=len(blocks) - len(tested),
                       changelog_in_table=at is not None, row=changelog_row)
    inserts.append((_summary_insert(lines, fenced), [*summary, ""]))

    for index, block in sorted(inserts, key=lambda item: item[0], reverse=True):
        lines[index:index] = block
    if unplaced:
        lines += ["", "## Dynamic verification: findings not placed", "",
                  "These tested findings have no unique anchor in the Analyzer's report, so their results stand here.",
                  ""]
        for t in unplaced:
            lines += [f"#### {_one_line(t.get('id'))} · {_one_line(t.get('title'))}", "", *_section(t, results), ""]
    return "\n".join(lines) + "\n"


def copy_figures(markdown: str, source_dir: Path, out_dir: Path) -> list[str]:
    """Copy the figures the report names by a plain file name (svg, png, jpg) next to the copy.
    A path, a link, a missing or an oversized file is skipped; nothing outside source_dir is read."""
    copied: list[str] = []
    for match in _FIGURE_REF.finditer(markdown):
        name = match.group(1) or match.group(2)
        if not _FIGURE_NAME.fullmatch(name) or name in copied:
            continue
        src, dest = source_dir / name, out_dir / name
        if src.is_symlink() or not src.is_file() or src.stat().st_size > MAX_FIGURE_BYTES:
            continue
        if dest.resolve() == src.resolve():
            continue
        data = _read_bounded(src, MAX_FIGURE_BYTES)
        if len(data) > MAX_FIGURE_BYTES:
            continue
        _write_bytes_atomically(dest, data)
        copied.append(name)
    return copied


def _read_bounded(path: Path, limit: int) -> bytes:
    """At most limit + 1 bytes of a regular file; a link put in its place after the check is not followed."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        return fh.read(limit + 1)


def _write_bytes_atomically(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)       # replaces a link at `path` itself, never the file it points to
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ── where things go ─────────────────────────────────────────────────────────

def _fenced_lines(lines: list[str]) -> list[bool]:
    """Per line, whether it belongs to a fenced code block (fence lines included)."""
    out, fence = [], None
    for line in lines:
        m = _FENCE.match(line)
        if fence is None:
            if m:
                fence = m.group(1)
            out.append(fence is not None)
        else:
            out.append(True)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line.strip(fence[0] + " "):
                fence = None
    return out


def _anchor(lines: list[str], fenced: list[bool], threat_id: str) -> int | None:
    """The line of the finding's anchor, when there is exactly one."""
    if not threat_id:
        return None
    needle = f'<a id="{threat_id.lower()}"></a>'
    hits = [i for i, line in enumerate(lines) if not fenced[i] and needle in line]
    return hits[0] if len(hits) == 1 else None


def _section_end(lines: list[str], fenced: list[bool], anchor: int) -> int:
    """The index after the last line of the finding that starts at `anchor`: before the next finding's
    anchor or the next heading of level 1 to 4, trailing blank lines left out."""
    i = anchor + 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i < len(lines) and not fenced[i] and _HEADING.match(lines[i]):
        i += 1                                              # the finding's own heading
    while i < len(lines):
        heading = _HEADING.match(lines[i])
        if not fenced[i] and (_FINDING_ANCHOR.match(lines[i]) or (heading and len(heading.group(1)) <= 4)):
            break
        i += 1
    while i > anchor + 1 and not lines[i - 1].strip():
        i -= 1
    return i


def _summary_insert(lines: list[str], fenced: list[bool]) -> int:
    """Before the first second-level section that is neither the changelog nor the table of contents."""
    for i, line in enumerate(lines):
        if not fenced[i] and line.startswith("## ") and line[3:].strip() not in ("Changelog", "Table of Contents"):
            return i
    for i, line in enumerate(lines):
        if not fenced[i] and line.startswith("# "):
            return i + 1
    return 0


def _changelog_insert(lines: list[str], fenced: list[bool]) -> tuple[int, int] | None:
    """Where the verification row goes in the changelog table (first row, newest first), and its cell count."""
    start = next((i for i, line in enumerate(lines) if not fenced[i] and line.strip() == "## Changelog"), None)
    if start is None:
        return None
    for i in range(start + 1, len(lines) - 1):
        if lines[i].startswith("## "):
            return None
        if lines[i].startswith("|") and re.fullmatch(r"\|[\s:|-]*-[\s:|-]*\|?", lines[i + 1].strip()):
            cells = len(lines[i].strip().strip("|").split("|"))
            return (i + 2, cells) if cells >= 3 else None
    return None


# ── what goes there ─────────────────────────────────────────────────────────

def _one_line(value) -> str:
    return " ".join(str(value or "").split())[:300]


def _cell(value) -> str:
    return _one_line(value).replace("|", "\\|") or "–"


def _verdict(block: dict) -> str:
    label = _VERDICT_LABEL.get(block.get("verdict"), block.get("verdict"))
    return f"{label} ({block['confidence']})" if block.get("confidence") else str(label)


def _rating_line(rating: dict) -> str:
    if not rating["changed"]:
        return f"**Rating after verification:** unchanged ({rating['reason']})."
    return (f"**Rating after verification:** {rating['reason']}; impact unchanged. "
            "The Analyzer's rating above stays as it is.")


def _section(t: dict, results: dict) -> list[str]:
    block = t["dynamic_verification"]
    out = ["##### Dynamic verification", "",
           f"**Verdict:** {_verdict(block)} · tested {_when(block.get('verified_at'))} "
           f"by AppSec Verifier {block.get('verifier_version')}",
           "", _rating_line(block["rating"])]
    if block.get("coverage") == "partial":
        out += ["", "Not every declared variant has a checked result; the verdict covers the tested variants only."]
    refs = [v.get("result_ref") for v in block.get("variants") or []] or [block.get("result_ref")]
    for ref in refs:
        r = results.get(ref)
        if not r:
            continue
        if block.get("variants"):
            out += ["", f"**Variant {_one_line(r['finding_ref'].get('variant'))}:** {_verdict(r)}"]
        if r.get("rationale"):            # the model's words, quoted so that they cannot start a section
            out += ["", *(f"> {line}".rstrip() for line in str(r["rationale"]).splitlines())]
        out += _poc_markdown(r, level=6) + _review_markdown(r, 6)
    return out


def _counts(tested: list[dict]) -> str:
    tally: dict[str, int] = {}
    for t in tested:
        verdict = t["dynamic_verification"]["verdict"]
        tally[verdict] = tally.get(verdict, 0) + 1
    return " · ".join(f"{n} {_VERDICT_LABEL.get(v, v)}" for v, n in tally.items()) or "none"


def _changelog_row(doc: dict, tested: list[dict]) -> dict:
    meta = doc["meta"]
    changed = sum(1 for t in tested if t["dynamic_verification"]["rating"]["changed"])
    mode = (meta.get("safety") or {}).get("mode") or "safe"
    return {"label": "verification", "date": _when(meta.get("generated")),
            "middle": [f"dynamic verification · {mode}", meta.get("model") or meta.get("profile"), _counts(tested)],
            "note": f"AppSec Verifier {meta.get('verifier_version')}; ratings changed: {changed}"}


def _table_row(row: dict, cells: int) -> str:
    middle = (row["middle"] + ["–"] * cells)[: cells - 3]
    return "| " + " | ".join(_cell(c) for c in [row["label"], row["date"], *middle, row["note"]]) + " |"


def _summary(annotated: dict, doc: dict, tested: list[dict], placed: set, *, not_tested: int,
             changelog_in_table: bool, row: dict) -> list[str]:
    meta, run = doc["meta"], annotated.get("dynamic_verification") or {}
    target = (meta.get("target") or {}).get("base_url")
    report = _one_line(run.get("verification_report"))
    out = ["## Dynamic verification", "",
           f"_Added by AppSec Verifier {run.get('verifier_version')} from `{report}`, "
           f"generated {_when(run.get('generated'))}. The Analyzer's ratings stay as they are; the rating after "
           f"verification stands next to them and follows fixed rules. The proofs of concept and screenshots in "
           f"this copy {TARGET_DATA_NOTE}._", "",
           f"Target `{_one_line(target)}` · {len(tested)} findings tested: {_counts(tested)}"
           + (f" · {not_tested} not tested." if not_tested else ".")]
    if not changelog_in_table:
        out += ["", f"Changelog: {row['label']} on {row['date']}, {row['note']}."]
    if not tested:
        return out
    out += ["", "| Finding | Verdict | Severity (Analyzer) | After verification |", "| --- | --- | --- | --- |"]
    changed = 0
    for t in tested:
        block, rating = t["dynamic_verification"], t["dynamic_verification"]["rating"]
        tid = _cell(t.get("id"))
        link = f"[{tid}](#{str(t.get('id')).lower()})" if t.get("id") in placed else tid
        after = _cell(rating["after_verification"]["severity"]) + (" (changed)" if rating["changed"] else "")
        changed += rating["changed"]
        out.append(f"| {link} {_cell(t.get('title'))} | {_cell(_verdict(block))} | "
                   f"{_cell(rating['analyzer']['severity'])} | {after} |")
    out += ["", f"{changed} of {len(tested)} ratings changed." if changed else "No rating changed."]
    return out
