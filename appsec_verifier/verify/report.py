"""Serialize a verification run: the standalone report (verification.yaml +
verification.md, VER-020), the AppSec Analyzer re-ingest export (VER-021), and
an additive annotation of a copy of the assessment (VER-027) with the rating
after verification (VER-039, verify/rating.py). The Analyzer's Markdown report
with the results is verify/annotated_report.py (VER-038).

verification.md opens with a summary (VER-020, VER-039): the tested findings,
linked to their entries, with result, rating and what the test showed, and the
findings not tested with what the run lacked (VER-024). Results and severities
carry colours, the severities as in AppSec Analyzer's report. A tested
finding's entry leads with a card of result, rating, weakness and a link to the
finding in the Analyzer's report, then what the checked proof showed (built
from the cited steps, never from the model's words) or why it is not
confirmed, its requests and its proof of concept (VER-034): the decisive steps
as HTTP excerpts in code fences that target content cannot close, and its
screenshots (VER-035). A collapsed appendix holds the test plan, the test
agent's own text, technical QA (VER-046) and evidence review (VER-042). Recorded responses and
screenshots can show target data; the report says so and the export never
references them (VER-022).

Reports and an annotated assessment are written through a temporary file and a
rename, so an interrupted write leaves the old file or the new one, never a
cut-off one. A report read back for `--resume` or `export` is checked against
schemas/verification.schema.yaml first. Resuming preserves each result's test
time; legacy results retain their original report time as a fallback (VER-037).
"""

from __future__ import annotations

import contextlib
import html
import os
import re
import secrets
from pathlib import Path
from urllib.parse import quote

import yaml

from ..version_info import resource_root
from .poc import ROLE_TITLES, TARGET_DATA_NOTE
from .presentation import COMPOSED_NOTE
from .probes import proof_shown

_VERDICT_LABEL = {
    "confirmed": "confirmed",
    "not-reproducible": "not reproducible",
    "blocked-by-control": "blocked by control",
    "inconclusive": "inconclusive",
    "not-attempted": "not attempted",
}


# Verdicts a resumed run keeps; a finding with any other result is tested again.
VERIFIED = ("confirmed", "not-reproducible", "blocked-by-control")
# Run-wide limits: a finding stopped by one, or not tested because of one, was cut off with the run.
RUN_LIMITS = ("requests", "cost", "time", "calls", "window")


def resume_problems(existing: dict, assessment_sha256: str | None, target: str) -> list[str]:
    """Why a run cannot continue `existing`: it must come from the same assessment,
    unchanged, and the same target, so the merged report describes one test."""
    meta = existing.get("meta") or {}
    problems = []
    if not assessment_sha256 or meta.get("source_assessment_sha256") != assessment_sha256:
        problems.append("it was written for another assessment, or the assessment has changed since")
    if (meta.get("target") or {}).get("base_url") != target:
        problems.append("it was written for another target")
    return problems


def verified_findings(existing: dict) -> set[str]:
    """The findings a resumed run keeps: those with a definite verdict."""
    return {r["finding_ref"]["id"] for r in existing.get("results") or [] if r.get("verdict") in VERIFIED
            and (r.get("proof") or {}).get("checked") is True and (r.get("proof") or {}).get("contract") == 2}


def remaining_variants(plans, existing):
    """Old aggregate results never invent coverage for a named variant."""
    from ..planning import expand_variants

    completed = {(r["finding_ref"]["id"], r["finding_ref"].get("variant_digest"))
                 for r in existing.get("results", []) if r.get("verdict") in VERIFIED
                 and (r.get("proof") or {}).get("checked") is True
                 and (r.get("proof") or {}).get("contract") == 3
                 and (r.get("class") != "access-control" or r.get("verdict") != "confirmed"
                      or (r.get("proof") or {}).get("access_restriction"))}
    return [p for p in expand_variants(plans) if (p.id, p.variant_digest) not in completed]


def merge_reports(existing: dict, new: dict) -> dict:
    """Continue a prior report with a new run's results (VER-027, `--resume`): a
    finding tested again replaces its earlier result; findings not re-tested are
    kept. Result ids are renumbered and the summary recomputed. Meta comes from
    the new run; the earlier generated time is kept as `previous_generated`.
    Each result retains its source report time for legacy timestamp fallback (VER-037)."""
    by_id: dict[str, dict] = {}
    order: list[str] = []
    rows = [dict(r, source_generated=r.get("source_generated", doc.get("meta", {}).get("generated")))
            for doc in (existing, new) for r in doc.get("results") or []]
    for r in rows:
        ref = r.get("finding_ref", {})
        key = (ref.get("id") or r.get("result_id"), ref.get("variant_digest") or
               (r.get("proof") or {}).get("variant"))
        if key not in by_id:
            order.append(key)
        by_id[key] = r
    merged = []
    for i, key in enumerate(order, start=1):
        r = dict(by_id[key])
        r["result_id"] = f"VF-{i:03d}"
        merged.append(r)
    tally = {"confirmed": 0, "not_reproducible": 0, "blocked": 0, "inconclusive": 0, "not_attempted": 0}
    _key = {"confirmed": "confirmed", "not-reproducible": "not_reproducible", "blocked-by-control": "blocked",
            "inconclusive": "inconclusive", "not-attempted": "not_attempted"}
    for r in merged:
        tally[_key[r["verdict"]]] += 1
    tally["total"] = len(merged)
    meta = dict(new["meta"])
    meta["summary"] = tally
    meta["previous_generated"] = existing.get("meta", {}).get("generated")
    return {"meta": meta, "results": merged}


_MAX_ERRORS = 5


def read_report(path: Path) -> tuple[dict | None, list[str]]:
    """An earlier verification.yaml, or why it cannot be used. The messages name
    the place and the rule, never a value from the file."""
    from jsonschema.validators import validator_for

    from ..loader import _rule

    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        return None, [f"cannot read it: {type(exc).__name__}"]
    if not isinstance(doc, dict):
        return None, ["it is not a verification report (no mapping at the top level)"]
    with open(resource_root() / "schemas" / "verification.schema.yaml", encoding="utf-8") as fh:
        schema = yaml.safe_load(fh)
    found = sorted(validator_for(schema)(schema).iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    errors = [f"{'/'.join(map(str, e.absolute_path)) or 'file'}: {_rule(e)}" for e in found]
    if errors:
        return None, errors[:_MAX_ERRORS] + ([f"… {len(errors) - _MAX_ERRORS} more"]
                                             if len(errors) > _MAX_ERRORS else [])
    return doc, []


def write_text_atomically(path: Path, text: str) -> None:
    """Replace `path` with `text` through a temporary file in the same directory.
    An existing file keeps its permissions; a new one gets those open() would give it.
    A symbolic link is followed, as open() would, so the file it points to is replaced."""
    path = Path(path).resolve()
    try:
        mode = path.stat().st_mode & 0o7777
    except FileNotFoundError:
        mode = None
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)    # the umask applies, as for open()
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def write_reports(doc: dict, out_dir: Path, assessment: dict | None = None) -> dict:
    """Write verification.yaml + verification.md (+ an empty evidence/ dir) into
    out_dir. With `assessment`, the report shows each finding's rating before and
    after verification (VER-039). Returns the written paths."""
    out_dir = Path(out_dir)
    (out_dir / "evidence").mkdir(parents=True, exist_ok=True)
    yaml_path = out_dir / "verification.yaml"
    md_path = out_dir / "verification.md"
    write_text_atomically(yaml_path, yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))
    write_text_atomically(md_path, to_markdown(doc, assessment, analyzer_report=_analyzer_report(doc, out_dir)))
    return {"yaml": yaml_path, "md": md_path, "evidence": out_dir / "evidence"}


def _analyzer_report(doc: dict, out_dir: Path) -> str | None:
    """The link from out_dir to the Analyzer's report, found as for the annotated report (VER-038): the
    assessment's name with .md, next to it, not a symlink. None when there is none."""
    source = doc["meta"].get("source_assessment")
    if not source:
        return None
    report = Path(str(source)).with_suffix(".md")
    if report.is_symlink() or not report.is_file():
        return None
    relative = os.path.relpath(os.path.abspath(report), os.path.abspath(out_dir))
    return quote(Path(relative).as_posix())


_ORDER = ("confirmed", "blocked-by-control", "not-reproducible", "inconclusive", "not-attempted")
_LABEL = {**_VERDICT_LABEL, "not-attempted": "not tested"}
# Colours as AppSec Analyzer's report shows them: its severity badges (scripts/renderers/compact_tables.py,
# BADGES), and for the result of a test a square, so that a result never reads as a severity.
_SEVERITY_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "informational": "⚪", "info": "⚪"}
_RESULT_BADGE = {"confirmed": "🟥", "blocked-by-control": "🟩", "not-reproducible": "🟩", "inconclusive": "🟨",
                 "not-attempted": "⬜"}
_LEGEND = ("🟥 confirmed · 🟩 not reproducible or blocked by control · 🟨 inconclusive · ⬜ not tested. Severity as "
           "in the assessment: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low.")
_CLASS = {"xss": "XSS", "ssrf": "SSRF", "access-control": "access control", "open-redirect": "open redirect",
          "path-traversal": "path traversal"}
_MAX_STEP_ROWS = 15
# A verdict the proof check lowered names its reason before the agent's claim (agent/proof.py, _downgrade).
_LOWERED = re.compile(r"indicative, not (?:proven|executed): (.*?)\. Agent's claim:", re.S)
# A recorded step (verify/poc.py, _line): tool, method, URL or opened page, identity and answer.
_STEP = re.compile(r"(\S+) (\S+) (.+) as (\S+) → (.*)", re.S)
# Why a finding was not tested (cli._blocker, loader.classify, verify/runner.py), said as what the run lacks.
_NOT_TESTED = (
    (r"no supported proof method for (.+)", r"no test method for \1"),
    (r"no read request to run controls on, and no injection_inputs entry",
     "needs a read request, or an injection_inputs entry in a scope file"),
    (r"the proof repeats each control, and every request the assessment names writes",
     "needs a read request: the injection proof repeats requests and never repeats a write"),
    (r"the assessment names no request for this finding.*", "needs a request: the assessment names none"),
    (r"no marker_file in the scope", "needs a marker file on the target: marker_file in a scope file"),
    (r"no callback in the scope", "needs a callback listener: callback in a scope file"),
    (r"no proof browser.*", "needs the proof browser: Playwright and Google Chrome"),
    (r"no test identity.*", "needs test accounts: --identities"),
    (r"safe mode; without a declared test resource.*",
     "needs --allow-intrusive: the Verifier would create its own test record"),
    (r"safe mode; every request the source registers for its handlers writes",
     "needs --allow-intrusive: every request the source registers for its handlers writes"),
    (r"safe mode; the finding needs (.+), which this run does not send.*",      # refused during the test (VER-052)
     r"needs --allow-intrusive: its test needs \1"),
    (r"safe mode;.*", "needs --allow-intrusive: every request it names writes"),
    (r"no declared test resource, and neither.*",
     "needs a test resource (test_resources), two test accounts with --allow-intrusive, or a privileged account"),
    (r"a declared test resource names roles unavailable in this run", "needs the accounts its test resource names"),
    (r"no write request that creates a record.*", "needs a request that creates a test record; the finding names none"),
    (r"no GET request to read with, and no write request that changes the record",
     "needs a request that reads or changes the record; the finding names none"),
    (r"no GET request to read with", "needs a request that reads the record; the finding names none"),
    (r"no operator-identified session cookie.*", "needs the session cookie to check: session_checks in a scope file"),
    (r"declared variants need unavailable capabilities: (.+)", r"needs a capability the Verifier lacks: \1"),
)


def _inline(value, limit: int = 300, *, cell: bool = False) -> str:
    """Text from the assessment, the model or the target on one line of Markdown: no line break or HTML, and
    in a table `cell` no column separator."""
    text = " ".join(str("" if value is None else value).split())[:limit].replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|") if cell else text


def _sentence(value, limit: int = 600) -> str:
    text = _inline(value, limit)
    return text if text.endswith((".", "!", "?")) else text + "."


def _code(value, limit: int = 90, *, cell: bool = False) -> str:
    """A request or path in a code span, shortened; as plain text where a backtick would end the span."""
    text = " ".join(str(value or "").split())
    text = text if len(text) <= limit else text[:limit - 1] + "…"
    if "`" in text:
        return _inline(text, cell=cell)
    return "`" + (text.replace("|", "\\|") if cell else text) + "`"


def _first_sentence(value, limit: int = 240) -> str:
    """The first sentence of a model's text, one line, for a list of issues in a code fence."""
    text = " ".join(str(value or "").split())
    text = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _when(value) -> str:
    """An ISO-8601 UTC time to the minute, as the Analyzer's changelog shows times."""
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::\d{2}(?:\.\d+)?)?(?:Z|\+00:00)", str(value or ""))
    return f"{m.group(1)} {m.group(2)} UTC" if m else " ".join(str(value or "").split())[:300]


def _anchor(finding_id) -> str:
    return re.sub(r"[^a-z0-9_-]", "", str(finding_id or "").lower())


def _overall(rows: list[dict]) -> str:
    """One verdict for a finding's results: theirs when they agree, confirmed when a variant was, else
    inconclusive."""
    verdicts = {r["verdict"] for r in rows}
    if len(verdicts) == 1:
        return verdicts.pop()
    return "confirmed" if "confirmed" in verdicts else "inconclusive"


def _rank(rows: list[dict]) -> int:
    verdict = _overall(rows)
    return _ORDER.index(verdict) if verdict in _ORDER else len(_ORDER)


def _severity(value) -> str:
    """`🟠 High` with the Analyzer's colour, or – when unknown."""
    text = _inline(value, 40, cell=True)
    badge = _SEVERITY_BADGE.get(text.lower())
    return f"{badge} {text.capitalize()}" if badge else (text or "–")


def _severity_of(threat: dict | None) -> str | None:
    threat = threat or {}
    return threat.get("effective_severity") or threat.get("risk") or threat.get("severity")


def _rating_text(rating: dict | None, threat: dict | None = None, *, unchanged: bool = False) -> str:
    """`🟠 High`, with `unchanged` `🟠 High, unchanged`, and `**🟠 High → 🔴 Critical**` for a change (VER-039); for
    a finding not tested the Analyzer's severity alone, or – when unknown."""
    if rating is None:
        return _severity(_severity_of(threat))
    before, after = (_severity(rating[k].get("severity")) for k in ("analyzer", "after_verification"))
    if rating["changed"]:
        return f"**{before} → {after}**"
    return f"{before}, unchanged" if unchanged else before


def _display_id(finding_id) -> str:
    """The id a reader sees in the Analyzer's report: T-NNN appears there as F-NNN, as AppSec Analyzer's
    display_id (scripts/_severity_rollup.py) renders it; other ids stay as they are."""
    return re.sub(r"^T-(\d+)$", r"F-\1", str(finding_id or ""))


def _step_line(step: dict) -> str:
    """A recorded step without the target's origin and the name of the HTTP tool. The line carries a URL the
    model chose, so it is only ever shown in a code fence."""
    tool, _, rest = str(step["line"]).partition(" ")
    rest = re.sub(r"^(\S+ )[a-z][a-z0-9+.-]*://[^/\s]+", r"\1", rest, count=1)   # METHOD scheme://host/path
    name = {"http_request": "", "browser_check": "browser "}.get(tool, tool + " ")
    return f"step {step['step']}: {name}{rest}"


def _steps(r: dict) -> list[dict]:
    """A result's recorded steps (verify/poc.py), with method, path, identity and answer where the line has them."""
    out = []
    for s in (r.get("poc") or {}).get("steps") or []:
        line = str(s.get("line") or "")
        m = _STEP.fullmatch(line)
        tool, method, url, role, answer = m.groups() if m else ("", "", "", "", "")
        status = re.match(r"\d{3}\b", answer)
        path = re.sub(r"^[a-z][a-z0-9+.-]*://[^/\s]+", "", url) or ("/" if url else "")
        out.append({"step": s.get("step"), "decisive": bool(s.get("decisive")), "line": line, "tool": tool,
                    "method": method, "path": path, "role": role, "answer": answer,
                    "status": int(status.group()) if status else None})
    return out


def _refs(*steps) -> str:
    """`step 6`, `steps 2 and 3`."""
    numbers = [str(n) for n in sorted({s["step"] for s in steps if s and isinstance(s.get("step"), int)})]
    if not numbers:
        return ""
    return ("step " if len(numbers) == 1 else "steps ") + (
        numbers[0] if len(numbers) == 1 else ", ".join(numbers[:-1]) + " and " + numbers[-1])


def _shown(r: dict, *, detail: bool = True) -> str | None:
    """What a confirmed result showed, in one sentence built from the proof the code checked and its cited
    steps, never from the model's words. With `detail` the request and step numbers follow in brackets."""
    proof = r.get("proof") or {}
    if r["verdict"] != "confirmed" or not proof.get("checked"):
        return None
    cited = [s for s in _steps(r) if s["decisive"] and s["role"]]

    def at(step, *more, request: bool = True) -> str:
        if not detail or not step:
            return ""
        parts = [_code(f"{step['method']} {step['path']}")] if request else []
        return f" ({', '.join([*parts, _refs(step, *more)])})"

    def who(step) -> str:
        return _inline(step["role"], 60)

    if proof.get("form") in ("selected-access", "declared-exposure"):
        from .probes import PROOF_FORMS

        return PROOF_FORMS[proof["form"]][1] + "."
    if proof.get("kind") == "access-control" and cited:
        writes = [s for s in cited if s["method"] in ("POST", "PUT", "PATCH")]
        reads = [s for s in cited if s["method"] == "GET"]
        owner = writes[0] if writes else None
        anonymous = next((s for s in cited if s["role"] == "anonymous"), None)
        reference = re.search(r"the same answer as for (\S+) ", str(proof.get("scope") or ""))
        if proof.get("second_marker") and owner:
            change = next((s for s in writes if s["role"] != owner["role"]), None)
            after = change and next((s for s in reads if s["role"] == owner["role"] and s["step"] > change["step"]),
                                    None)
            if change and after:
                return (f"{who(change)} changed a record that {who(owner)} created{at(change)}; "
                        f"{who(owner)}'s next read showed {who(change)}'s marker{at(after, request=False)}.")
        elif proof.get("marker") and owner:
            other = next((s for s in reads if s["role"] not in (owner["role"], "anonymous")
                          and (s["status"] or 0) < 300), None)
            if other:
                text = f"{who(other)} read the record that {who(owner)} created, with its marker{at(other)}"
                if anonymous:
                    text += f"; without a login the marker did not show{at(anonymous, request=False)}"
                return text + "."
        elif proof.get("form") == "comparison-without-credentials":     # VER-057
            signed = next((s for s in reads if s["role"] != "anonymous"), None)
            same = next((s for s in reads if s["role"] == "anonymous" and s["path"] == proof.get("tested_path")), None)
            control = next((s for s in reads if s["role"] == "anonymous" and s["path"] != proof.get("tested_path")),
                           None)
            if signed and same:
                text = f"Without a login the same answer as {who(signed)}, compared in code{at(same, signed)}"
                if control and control["status"]:
                    text += f"; a random path next to it: {control['status']}{at(control)}"
                return text + "."
        elif reference:
            privileged = next((s for s in reads if s["role"] == reference.group(1)), None)
            normal = next((s for s in reads if s["role"] not in (reference.group(1), "anonymous")), None)
            if privileged and normal:
                text = f"{who(normal)} got the same answer as {who(privileged)}{at(normal, privileged)}"
                if anonymous and anonymous["status"]:
                    text += f"; without a login: {anonymous['status']}{at(anonymous, request=False)}"
                return text + "."
    shown = (proof_shown(proof, r.get("class")) or (None, None))[1]
    if not shown:
        return None
    first = next((s for s in cited if s["tool"] == "browser_check"), None) if r.get("class") == "xss" else None
    steps = [first] if first else [s for s in _steps(r) if s["decisive"]]
    return shown + (f" ({_refs(*steps)})" if detail and _refs(*steps) else "") + "."


def _not_tested(rationale) -> str:
    """Why a finding was not tested, as what the run lacks; the recorded reason where no wording fits."""
    why = re.sub(r"^not tested: ", "", " ".join(str(rationale or "").split()))
    for pattern, said in _NOT_TESTED:
        if m := re.fullmatch(pattern, why):
            return m.expand(said)
    return why


def _why_not(r: dict) -> str | None:
    """Why a tested finding is not confirmed, as the code knows it: what the proof check missed, the limit
    that stopped the test, why the check lowered the agent's verdict, or which comparison is missing."""
    if r["verdict"] not in ("inconclusive", "not-attempted"):
        return None
    proof = r.get("proof") or {}
    if proof.get("missing"):
        return "; ".join(str(m) for m in proof["missing"])
    if r.get("limits_hit") == "safe-mode":         # a write the run refused during the test (VER-052)
        return _not_tested(r.get("rationale"))
    if r.get("limits_hit"):
        stopped = re.sub(r"^stopped(?: by limit)?: ", "", str(r.get("rationale") or ""))
        return f"stopped: {stopped}" if stopped else f"stopped by the {r['limits_hit']} limit"
    lowered = _LOWERED.match(r.get("rationale") or "")
    if lowered:
        return lowered.group(1)
    accounts = {s["role"] for s in _steps(r) if s["role"] and s["status"] is not None} - {"anonymous"}
    if r.get("class") == "access-control" and len(accounts) == 1:
        return f"only {next(iter(accounts))} sent requests; the comparison with another account is missing"
    return "the test agent ended without a proof the Verifier could check"


def to_markdown(doc: dict, assessment: dict | None = None, *, analyzer_report: str | None = None) -> str:
    """verification.md (VER-020): the run; a summary of the selected findings, the tested ones linked to their
    entries with result, rating before and after verification (VER-039) and what the test showed, the ones not
    tested with what the run lacked (VER-024); each tested finding led by its result, what the checked proof
    showed, its steps and its proof of concept (VER-034, VER-035), and with `analyzer_report` (a link to the
    Analyzer's report) a link to the finding there; an appendix, collapsed, with the test plan, the test agent's
    explanation and the evidence review (VER-042). Text from the assessment, the model or the target stays on
    one line, in a code span or in a fence."""
    threats = {t.get("id"): t for t in (assessment or {}).get("threats") or [] if isinstance(t, dict)}
    groups: dict[str, list[dict]] = {}
    for r in doc["results"]:
        groups.setdefault((r.get("finding_ref") or {}).get("id") or r["result_id"], []).append(r)
    ordered = sorted(groups.items(), key=lambda item: _rank(item[1]))
    ratings = {fid: rating_after_verification(threats[fid], rows) if fid in threats and any(
        r["verdict"] != "not-attempted" for r in rows) else None for fid, rows in groups.items()}
    tested = [(fid, rows) for fid, rows in ordered if _overall(rows) != "not-attempted"]
    untested = [(fid, rows) for fid, rows in ordered if _overall(rows) == "not-attempted"]
    details = {id(r): _details(r) for _, rows in tested for r in rows}
    lines = _run_lines(doc, analyzer_report) + _summary(tested, untested, threats, ratings)
    if tested:
        lines += ["", "## Tested findings"]
        for fid, rows in tested:
            for i, r in enumerate(rows):
                lines += _entry(r, ratings[fid], first=i == 0, details=bool(details[id(r)]),
                                analyzer_report=analyzer_report, several=len(rows) > 1)
    if any(details.values()):
        lines += ["", "## Appendix: test details", "",
                  "The test agent's plan and own words and the evidence review, per finding. They are not proof: "
                  "a verdict rests only on the steps the Verifier checked."]
        for fid, rows in tested:
            for i, r in enumerate(rows):
                if details[id(r)]:
                    anchor = _anchor(fid)
                    name = html.escape(f"{fid}{_variant(r) if len(rows) > 1 else ''}")
                    lines += ["", *([f'<a id="details-{anchor}"></a>'] if i == 0 and anchor else []), "<details>",
                              f"<summary>{name}: test plan, the test agent's explanation, evidence review</summary>",
                              *details[id(r)], "", "</details>"]
    return "\n".join(lines) + "\n"


def _variant(r: dict) -> str:
    variant = (r.get("finding_ref") or {}).get("variant")
    return f" · variant {_inline(variant)}" if variant else ""


def _run_lines(doc: dict, analyzer_report: str | None = None) -> list[str]:
    meta = doc["meta"]
    target, safety = meta.get("target") or {}, meta.get("safety") or {}
    auth, scope = meta.get("authorization") or {}, meta.get("scope") or {}
    if safety.get("read_only") and safety.get("writes_allowed_for"):     # VER-052
        mode = (f"{safety.get('mode') or 'safe'}, read-only; the operator allowed writes for "
                + ", ".join(_inline(f, 20) for f in safety["writes_allowed_for"][:20])
                + "; what the test created stays on the target")
    elif safety.get("read_only"):
        mode = f"{safety.get('mode') or 'safe'}, read-only"
    else:
        mode = f"{safety.get('mode') or 'intrusive'}, writes allowed"
        if not safety.get("state_changes_cleaned"):
            mode += "; what the test created stays on the target"
    if not meta.get("contacted_target"):
        mode += "; the target was not contacted"
    where = _inline(target.get("base_url")) + (f" ({_inline(target['environment'])})" if target.get("environment")
                                               else "")
    lines = ["# Verification report", "",
             f"- **Target:** {where} · build {_inline(target.get('build_match') or 'unknown')}",
             f"- **Assessment:** {_inline(meta.get('source_assessment'))}"
             + (f" · [the Analyzer's report]({analyzer_report})" if analyzer_report else ""),
             f"- **Run:** {_when(meta.get('generated'))} · AppSec Verifier {_inline(meta.get('verifier_version'))}"
             + (f" · model {_inline(meta['model'])}" if meta.get("model") else ""),
             f"- **Mode:** {mode}",
             f"- **Scope:** scope file of {_inline(scope.get('owner'))}" if scope.get("file")
             else "- **Scope:** no scope file; only the target's host and port",
             "- **Authorisation:** " + (f"confirmed ({_inline(auth.get('mode'))}) at {_when(auth.get('at'))}"
                                       if auth.get("confirmed") else "not confirmed")]
    if meta.get("previous_generated"):
        lines.append(f"- **Continues:** the report of {_when(meta['previous_generated'])}")
    if meta.get("interrupted"):
        lines.append("- **Interrupted:** the findings the run did not reach are listed as not tested.")
    raises = [r for r in (meta.get("limits") or {}).get("cost_limit_raises") or []
              if isinstance(r, dict) and all(isinstance(r.get(k), int | float) for k in ("from", "to"))]
    if raises:          # VER-015: each raise the operator typed during the run
        amounts = [raises[0]["from"], *(r["to"] for r in raises)]
        lines.append("- **Cost limit:** raised during the run at the operator's request, "
                     + " → ".join(f"${amount:.2f}" for amount in amounts))
    if any(r.get("poc") or r.get("evidence") for r in doc["results"]):
        lines.append(f"- **Evidence:** the proofs of concept and screenshots {TARGET_DATA_NOTE}.")
    return lines


def _summary(tested, untested, threats: dict, ratings: dict) -> list[str]:
    """The overview of the selected findings (VER-020): the counts; the tested findings, each linked to its entry
    with result, rating (VER-039) and what the test showed or why it is not confirmed; the findings not tested,
    most severe first, with what the run lacked. Their row is their entry."""
    tally: dict[str, int] = {}
    for _, rows in [*tested, *untested]:
        tally[_overall(rows)] = tally.get(_overall(rows), 0) + 1
    counts = [f"{_RESULT_BADGE.get(v, '')} " + (f"**{n} {_LABEL.get(v, v)}**" if v == "confirmed"
                                                  else f"{n} {_LABEL.get(v, v)}")
              for v, n in sorted(tally.items(), key=lambda kv: _ORDER.index(kv[0]) if kv[0] in _ORDER else 99)]
    selected = len(tested) + len(untested)
    counts.append(f"{selected} of {len(threats)} findings selected" if threats else f"{selected} findings selected")
    changed = [(fid, ratings[fid]) for fid, _ in tested if ratings.get(fid) and ratings[fid]["changed"]]
    if any(ratings.values()) and not changed:
        counts.append("no rating changed")
    lines = ["", "## Summary", "", " · ".join(counts)]
    if tested:
        lines += ["", "| Result | Finding | Severity | What the test showed |", "| --- | --- | --- | --- |"]
        for fid, rows in tested:
            verdict, anchor, fr = _overall(rows), _anchor(fid), (rows[0].get("finding_ref") or {})
            label = _LABEL.get(verdict, verdict).capitalize() + (f" ({len(rows)} variants)" if len(rows) > 1 else "")
            result = f"{_RESULT_BADGE.get(verdict, '')} " + (f"**{label}**" if verdict == "confirmed" else label)
            link = f"[{_inline(fid, cell=True)}](#{anchor})" if anchor else _inline(fid, cell=True)
            what = next((s for s in (_shown(r, detail=False) for r in rows) if s), None)
            if what is None:
                why = next((w for w in (_why_not(r) for r in rows) if w), "")
                what = why[:1].upper() + why[1:] + ("." if why and not why.endswith(".") else "")
            lines.append(f"| {result} | {link} · {_inline(fr.get('title') or fr.get('cwe'), 110, cell=True)} | "
                         f"{_rating_text(ratings[fid], threats.get(fid))} | {_inline(what, 220, cell=True) or '–'} |")
        lines += ["", _LEGEND]
    if changed:
        lines += ["", "Ratings changed after verification: " + "; ".join(
            f"[{_inline(fid)}](#{_anchor(fid)}) {_inline(rating['reason'])}" for fid, rating in changed) + "."]
    if untested:
        def rank(item):
            severity = str(_severity_of(threats.get(item[0])) or "").lower()
            return (list(_SEVERITY_BADGE).index(severity) if severity in _SEVERITY_BADGE else 99, str(item[0]))

        lines += ["", "### Not tested", "", "| Finding | Severity | Why not tested |", "| --- | --- | --- |"]
        for fid, rows in sorted(untested, key=rank):
            fr, anchor = (rows[0].get("finding_ref") or {}), _anchor(fid)
            mark = f'<a id="{anchor}"></a>' if anchor else ""
            title = _inline(fr.get("title") or fr.get("cwe"), 110, cell=True)
            why = _inline(_not_tested(rows[0].get("rationale")), 220, cell=True)
            lines.append(f"| {mark}{_inline(fid, cell=True)} · {title} | {_rating_text(None, threats.get(fid))} | "
                         f"{why or '–'} |")
    return lines


def _entry(r: dict, rating: dict | None, *, first: bool, details: bool, analyzer_report: str | None = None,
           several: bool = False) -> list[str]:
    """A tested finding (VER-020): a card with result, rating, weakness and the link to the finding in the
    Analyzer's report; what the checked proof showed or why it is not confirmed; limits and deviations; the
    requests; the proof of concept; the cross-run key and files."""
    fr, proof, verdict = (r.get("finding_ref") or {}), r.get("proof") or {}, r["verdict"]
    fid = fr.get("id") or r["result_id"]
    anchor, badge = _anchor(fid), _RESULT_BADGE.get(verdict, "")
    result = f"{badge} **{_LABEL.get(verdict, verdict).capitalize()}**"
    if r.get("confidence"):
        result += f", {_inline(r['confidence'], 20, cell=True)} confidence"
    weakness = " · ".join(_inline(v, 60, cell=True) for v in (fr.get("cwe"), _CLASS.get(r.get("class"), r.get("class")))
                          if v)
    head = ["Result", "Severity", "Weakness"]
    cells = [result, _rating_text(rating, unchanged=True) if rating else "–", weakness or "–"]
    if review := r.get("technical_review"):
        head.append("Technical QA")
        cells.append(_inline(review["status"], 40, cell=True))
    if tested := (r.get("timing") or {}).get("finished"):
        head.append("Tested")
        cells.append(_when(tested))
    elif generated := r.get("source_generated"):
        head.append("Original report")
        cells.append(_when(generated))
    if permission := r.get("write_permission"):     # the operator's answer for this finding (VER-052)
        head.append("Writes")
        cells.append(("allowed by the operator" if permission.get("allowed") else
                      "no answer" if permission.get("answer") == "no answer" else "declined by the operator")
                     + (" for the rest of the run" if permission.get("answer") == "rest of the run" else "")
                     + (f", {_when(permission['at'])}" if permission.get("at") else ""))
    if analyzer_report and fr.get("id") and anchor:
        head.append("In the assessment report")
        cells.append(f"[{_inline(_display_id(fid), cell=True)}]({analyzer_report}#{anchor})")
    out = ["", *([f'<a id="{anchor}"></a>'] if first and anchor else []),
           f"### {badge} {_inline(fid)} · {_inline(fr.get('title') or fr.get('cwe'))}{_variant(r) if several else ''}",
           "",
           "| " + " | ".join(head) + " |", "|" + " --- |" * len(head), "| " + " | ".join(cells) + " |"]
    if shown := _shown(r):
        out += ["", f"**What the test showed:** {shown}"]
    if why := _why_not(r):
        out += ["", f"**Why not confirmed:** {_sentence(why)}"]
    notes = []
    restriction = proof.get("access_restriction")
    if isinstance(restriction, dict):
        description = restriction.get("restriction") or (
            "Allowed: " + ", ".join(restriction.get("allowed_roles", []))
            + "; denied: " + ", ".join(restriction.get("denied_roles", [])))
        notes.append(f"**Expected access:** {_sentence(description)} "
                     f"Source: {_sentence(restriction.get('source'))}")
    observation = proof.get("access_observation")
    if observation:
        notes.append("**Compared observation:** " + _code(observation.get("pointer") or "literal text")
                     + " = " + _code(str(observation.get("value"))) + "; declared by the operator.")
    for item in proof.get("cookie_observations", []):
        attributes = ", ".join(
            f"{c['name']}: Secure={c['secure']}, HttpOnly={c['httponly']}, SameSite={c['samesite'] or 'missing'}"
            for c in item.get("session_cookies", []))
        notes.append("**Login cookie observation:** " + _code(f"{item['method']} {item['path']}")
                     + f" (HTTP {item['status']}, {_inline(item['role'])}): " + _code(attributes))
    limits = re.sub(r"^cited requests only[;,]?\s*", "", str(proof.get("scope") or "")) if proof.get("checked") else ""
    limits = re.sub(r"^on ", "tested on ", limits)
    if limits:
        notes.append(f"**Limits:** {_sentence(limits[:1].upper() + limits[1:])}")
    if rating and rating["changed"]:
        notes.append(f"**Rating changed:** {_sentence(rating['reason'])}")
    review = r.get("technical_review") or {}
    if r["verdict"] == "confirmed" and review.get("status") == "needs-attention" and review.get("issues"):
        # VER-046: an objection QA kept beside a checked proof is named where the result is, not only below.
        notes.append(f"**Technical QA objection:** {_sentence(review['issues'][0].get('detail'))}")
    deviations = [*([r["deviation"]] if r.get("deviation") else []),
                  *(o for o in r.get("observations") or [] if o.startswith("Deviation:"))]
    notes += [f"**Deviation:** {_sentence(re.sub(r'^Deviation:[ ]*', '', d))}" for d in deviations]
    if r.get("selection_reason"):
        notes.append(f"**Additionally selected:** {_sentence(r['selection_reason'])}")
    if not _application(r):
        unavailable = [o for o in r.get("observations") or [] if o.startswith("Application screenshot unavailable:")]
        if unavailable:
            reason = re.sub(r"^Application screenshot unavailable:\s*", "", unavailable[0]).split(";")[0]
            notes.append(f"**Application screenshot:** none, {_sentence(reason)}")
    out += ["", *(f"- {note}" for note in notes)] if notes else []
    table = _step_table(r)
    if table:
        rests = "proof rests on" if verdict == "confirmed" else "verdict rests on"
        bold = any(s["decisive"] for s in _steps(r))
        out += ["", f"**Requests**{f' (bold: the steps the {rests})' if bold else ''}", "", *table]
    out += _poc_markdown(r, level=4, steps=False, limitations=False)
    footer = [f"Cross-run key {_code(fr['match_key'])}"] if fr.get("match_key") else []
    files = [_code(e["path"]) for e in r.get("evidence") or [] if e.get("path")]
    if files:
        footer.append("files: " + ", ".join(files))
    if details and first and anchor:
        footer.append(f"[test details](#details-{anchor})")
    out += ["", " · ".join(footer)] if footer else []
    return out


def _application(r: dict) -> list[dict]:
    """The application screenshots of a result (VER-035)."""
    return [e for e in r.get("evidence") or []
            if e.get("kind") == "screenshot" and (e.get("presentation") == "application" or
                re.search(r"-(?:xss|access-control)-[0-9]+\.png$", e.get("path", ""))) and e.get("path")]


def _step_table(r: dict) -> list[str]:
    """The requests of a result as a table, the steps its verdict rests on in bold; a line format the table
    cannot split stays as lines in a fence. Paths are the model's choice, so they stay in code spans."""
    steps = _steps(r)
    if not steps:
        return []
    if not all(s["method"] for s in steps):
        return [_fenced("\n".join(_step_line(s) for s in steps), "text")]
    rows = ["| Step | Request | Identity | Answer |", "| --- | --- | --- | --- |"]
    for s in steps[:_MAX_STEP_ROWS]:
        number = f"**{s['step']}**" if s["decisive"] else str(s["step"])
        request = ("browser " if s["tool"] == "browser_check" else "") + f"{s['method']} {s['path']}"
        rows.append(f"| {number} | {_code(request, cell=True)} | {_inline(s['role'], 60, cell=True)} | "
                    f"{_inline(s['answer'], 120, cell=True)} |")
    if len(steps) > _MAX_STEP_ROWS:
        rows.append(f"| … | {len(steps) - _MAX_STEP_ROWS} more in the HAR file | | |")
    return rows


def _details(r: dict) -> list[str]:
    """The appendix part of a tested finding (VER-020): the test plan, the test agent's own explanation and
    observations, technical QA (VER-046) and evidence review (VER-042). Model text stays in code fences."""
    out = []
    if r.get("planning"):
        plan = yaml.safe_dump(r["planning"], sort_keys=False, allow_unicode=True, width=110).rstrip()
        out += ["", "**Test plan** (assumptions are not proof)", "", _fenced(plan, "yaml")]
    if r.get("rationale") and not r.get("limits_hit"):
        out += ["", "**Test agent's explanation** (not proof)", "", _fenced(str(r["rationale"]), "text")]
    notes = [o for o in r.get("observations") or []
             if not o.startswith(("Application screenshot unavailable:", "Deviation:", COMPOSED_NOTE))]
    if notes:
        out += ["", "**Other observations** (not verified)", "", _fenced("\n".join(notes), "text")]
    return out + _review_markdown(r, 4)


def _fenced(text: str, info: str = "http") -> str:
    """`text` in a code fence longer than any backtick run inside it, so target content cannot close it."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{info}\n{text}\n{fence}"


def _review_markdown(r: dict, level: int) -> list[str]:
    technical = _technical_review_markdown(r, level)
    review = r.get("evidence_review")
    if not review:
        return technical
    shown = review.get("images_reviewed") or []
    seen = ("Screenshots a model reviewed: " + ", ".join(f"`{p}`" for p in shown) + "." if shown
            else "No screenshot was shown to a model.")
    status = (f"{_inline(review['status'], 40)} after {_inline(review['rounds'], 4)} of 2 correction rounds and "
              f"{_inline(review['reviews'], 4)} reviews")
    out = technical + ["", f"{'#' * level} Evidence review", "",
           f"{status[:1].upper() + status[1:]}. The review judges how the evidence is presented, not the verdict. "
           f"{seen}"]
    # The reviewer's words, first sentence each: model text, so it stays in a fence.
    text = [_first_sentence(review.get("reason"), 300)] if review.get("reason") else []
    variants = {i.get("variant") for i in review["issues"]}
    if review["issues"]:
        text += ["", "Open issues:", *(f"- {i['variant'] + ': ' if len(variants) > 1 else ''}"
                                      f"{_first_sentence(i['detail'])}" for i in review["issues"])]
    if text:
        out += ["", _fenced("\n".join(text), "text")]
    return out


def _technical_review_markdown(r: dict, level: int) -> list[str]:
    """Technical questions stay visible beside, and separate from, checked proof (VER-046)."""
    review = r.get("technical_review")
    if not review:
        return []
    out = ["", f"{'#' * level} Technical QA", "",
           f"{_inline(review['status'], 40)}. {review['reviews']} technical reviews and "
           f"{review['rounds']} correction rounds for this variant; the finding shares at most two rounds. "
           "QA does not assign the technical verdict."]
    text = [review.get("reason", "")]
    if review.get("inspected_steps"):
        text.append("Additional recorded responses inspected: " + ", ".join(map(str, review["inspected_steps"])))
    for issue in review.get("issues", []):
        text += ["", issue["detail"], "Follow-up question: " + issue["question"]]
    return out + ["", _fenced("\n".join(text), "text")]


def _poc_markdown(r: dict, level: int = 4, *, steps: bool = True, limitations: bool = True) -> list[str]:
    """The proof of concept (VER-034, VER-035): the application screenshots with the test agent's explanation,
    with `limitations` why there is none, with `steps` the requests as a table, then each step the verdict rests
    on as one HTTP excerpt of request and response, ⟦…⟧ around what the proof rests on."""
    poc = r.get("poc") or {}
    application = _application(r)
    out = []
    if application:
        out += ["", f"{'#' * level} Exploit in the application", ""]
        for ev in application:
            out += [f"![Application screenshot {ev['path']}]({ev['path']})", ""]
            details = []
            if ev.get("source") == "recorded-html":
                details.append("Rendered from a recorded response; scripts and external resources disabled.")
            elif ev.get("source") == "live-browser":
                details.append("Application browser capture; highlights and captions added by the Verifier.")
            if ev.get("proof_step"):
                details.append(f"Illustrates recorded step {ev['proof_step']}.")
            if ev.get("role"):
                details.append(f"View as {ev['role']}.")
            if ev.get("executed_via"):
                details.append("Dialog drawn from the recorded execution event.")
            if ev.get("credential_masked"):
                details.append("Known credentials masked; each placeholder names its account and kind.")
            if details:
                out += [_fenced(" ".join(details), "text"), ""]
            if ev.get("explanation"):      # model text: fenced, so it stays text (VER-035)
                out += [_fenced(f"Test agent's explanation: {ev['explanation']}", "text"), ""]
    elif limitations:
        unavailable = [o for o in r.get("observations") or [] if o.startswith("Application screenshot unavailable:")]
        out += ["", *(_sentence(o) for o in dict.fromkeys(unavailable))] if unavailable else []
    if not poc.get("steps") or not (steps or poc.get("shown")):
        return out
    out += ["", f"{'#' * level} Proof of concept", ""]
    if steps:
        out += [*_step_table(r), ""]
    note = "⟦…⟧ marks what the proof rests on. " if any("request_excerpt" in s for s in poc.get("shown") or []) else ""
    if poc.get("file"):
        note += f"All requests and responses: {_code(poc['file'])}."
    out += [note.strip()] if note.strip() else []
    # VER-059: the test agent's presentation, its words fenced as model text, or why the Verifier composed it.
    composed = poc.get("presentation") or {}
    agent = composed.get("composed_by") == "test-agent"
    if agent:
        left_out, not_shown = composed.get("left_out") or [], composed.get("not_shown") or []
        out += ["", "The test agent chose the steps, excerpts and marks below; the Verifier found each in the record."
                + (f" It left out {_inline('; '.join(left_out), 600)}." if left_out else "")
                + (" After them follow, as the Verifier shows them, the steps the verdict also rests on that the "
                   f"test agent left out: {', '.join(_inline(n, 8) for n in not_shown)}." if not_shown else "")]
        out += ["", _fenced(f"Test agent's account: {composed['summary']}", "text")] if composed.get("summary") else []
    elif composed.get("reason"):
        out += ["", _fenced(f"Excerpts composed by the Verifier: {composed['reason']}.", "text")]
    parsed = {s["step"]: s for s in _steps(r)}
    for shown in poc.get("shown") or []:
        s = parsed.get(shown["step"]) or {}
        mine = agent and shown.get("composed_by") != "verifier"     # a step the agent's presentation shows
        title = f"**Step {_inline(shown['step'], 8)}**"
        if shown.get("role") in ROLE_TITLES:     # the normal requests come first, then the attacks (VER-035)
            title = (f"**{ROLE_TITLES[shown['role']]} · step {_inline(shown['step'], 8)}**"
                     + (f" ({_inline(shown['role_label'], 80)})" if shown.get("role_label") and not mine else ""))
        if s.get("method"):
            title += (f" · {_code(s['method'] + ' ' + s['path'])} as {_inline(s['role'], 60)} → "
                      f"{_inline(s['answer'], 80)}")
        facts = shown.get("facts") or []
        if mine and shown.get("role_label"):       # model text stays in the fence
            facts = [f"Test agent: {shown['role_label']}", *facts]
        out += ["", title]
        if facts:
            out += ["", _fenced("\n".join(facts), "text")]
        if any(str(f).startswith("opened in the browser:") for f in facts):
            out += ["", "The page's first request below; the part after # stays in the browser."]
        request = shown.get("request_excerpt", shown["request"]).rstrip()
        response = shown.get("response_excerpt", shown["response"]).rstrip()
        out += ["", _fenced(f"{request}\n\n{response}")]
    return out


def build_annotations(doc: dict, *, verification_report: str) -> dict:
    """Produce the AppSec Analyzer re-ingest document (VER-021)."""
    meta = doc["meta"]
    annotations = []
    for r in doc["results"]:
        fr = r.get("finding_ref", {})
        annotations.append({
            "finding_id": fr.get("id"),
            "match_key": fr.get("match_key"),
            "instance": fr.get("instance"),
            "class": r.get("class"),
            "verdict": r["verdict"],
            "confidence": r.get("confidence"),
            "rationale": r.get("rationale"),
            "tested_scope": {k: (r.get("proof") or {})[k]
                             for k in ("checked", "contract", "variant", "tested_path", "scope")
                             if k in (r.get("proof") or {})},
            "verified_at": ((r.get("timing") or {}).get("finished")
                            or r.get("source_generated") or meta.get("generated")),
            "result_ref": r.get("result_id"),
            # Screenshots and recorded responses can show target data and stay out of the export (VER-022).
            "evidence_ref": next((e.get("path") for e in r.get("evidence") or []
                                  if e.get("kind") not in ("screenshot", "har")), None),
        })
    return {
        "meta": {
            "schema_version": 1,
            "generated": meta.get("generated"),
            "verifier_version": meta.get("verifier_version"),
            "source_assessment": meta.get("source_assessment"),
            "source_assessment_sha256": meta.get("source_assessment_sha256"),
            "verification_report": verification_report,
            "target": {
                "base_url": meta.get("target", {}).get("base_url"),
                "environment": meta.get("target", {}).get("environment"),
                "build_match": meta.get("target", {}).get("build_match"),
            },
        },
        "annotations": annotations,
    }


ANNOTATION_SCHEMA_VERSION = 1


def _rating_input(rows: list[dict], coverage: str | None) -> tuple[str | None, bool]:
    """The verdict a threat's rating after verification rests on (VER-039), and whether its proof was checked.
    Of several variants, one confirmed variant counts; a block counts only when every variant was blocked;
    otherwise the variants' verdict as verification.md gives it."""
    def checked(row):
        return (row.get("proof") or {}).get("checked") is True

    if any(row["verdict"] == "confirmed" and checked(row) for row in rows):
        return "confirmed", True
    if coverage in (None, "complete") and rows and all(
            row["verdict"] == "blocked-by-control" and checked(row) for row in rows):
        return "blocked-by-control", True
    return _overall(rows), False


def _coverage(threat: dict, variants: list[dict]) -> str | None:
    """``complete`` when each variant the threat names has a checked proof, else ``partial``; None for a threat
    tested without variants."""
    if not any(row["finding_ref"].get("variant") for row in variants):
        return None
    expected = {v["id"] for v in (threat.get("verification_context") or {}).get("variants", [])}
    completed = {(row.get("proof") or {}).get("variant") for row in variants
                 if (row.get("proof") or {}).get("checked") is True}
    return "complete" if expected and expected <= completed else "partial"


def rating_after_verification(threat: dict, rows: list[dict]) -> dict:
    """The rating after verification (VER-039) of a threat from the results of its tested variants, as
    `annotate_assessment` gives it; the console shows it as soon as the last variant is done."""
    from .rating import rate

    coverage = _coverage(threat, rows)
    return rate(threat, *_rating_input(rows if coverage else rows[:1], coverage))


_TESTED_SCOPE = ("checked", "contract", "variant", "tested_path", "scope")


def _tested_scope(row: dict) -> dict:
    """What a result's checked proof covers (VER-013); never what it observed in the target's answers."""
    proof = row.get("proof") or {}
    return {k: proof[k] for k in _TESTED_SCOPE if k in proof}


def _pointers(rows: list[dict]) -> dict:
    """Paths of the proof of concept and screenshots, relative to the report (VER-027); never their content."""
    har = [row["poc"]["file"] for row in rows if (row.get("poc") or {}).get("file")]
    shots = [ev["path"] for row in rows for ev in row.get("evidence") or []
             if ev.get("kind") == "screenshot" and ev.get("path")]
    return {"proof_of_concept": list(dict.fromkeys(har)), "screenshots": list(dict.fromkeys(shots))}


def annotate_assessment(assessment: dict, doc: dict, *, verification_report: str) -> dict:
    """Return a copy of the assessment with an additive `dynamic_verification`
    block on each matched finding and a top-level `dynamic_verification` record
    of the run that wrote them (VER-027): verdict, confidence, the rating after
    verification (VER-039) and pointers to the proof of concept and screenshots.
    Never changes or removes a finding. The key is the Verifier's own: AppSec
    Analyzer uses `threats[].verification` for its static verification findings
    (REQ-040). The fields are defined in schemas/annotated-assessment.schema.yaml."""
    from ..matchkey import match_key
    from .rating import rate

    by_id = {r["finding_ref"]["id"]: r for r in doc["results"] if r["finding_ref"].get("id")}
    # The cross-run key finds a result whose finding has another id in this assessment, and only for a finding
    # that alone carries that key: another finding that shares the key of a tested one was not tested.
    threats = [t for t in assessment.get("threats") or [] if isinstance(t, dict)]
    present = {t.get("id") for t in threats}
    unmatched = [match_key(t) for t in threats if t.get("id") not in by_id]
    by_key = {}
    for r in doc["results"]:
        mk = r["finding_ref"].get("match_key")
        if mk and r["finding_ref"].get("id") not in present and unmatched.count(mk) == 1:
            by_key.setdefault(mk, r)

    import copy
    out = copy.deepcopy(assessment)
    out["dynamic_verification"] = {
        "schema_version": ANNOTATION_SCHEMA_VERSION,
        "generated": doc["meta"].get("generated"),
        "verifier_version": doc["meta"].get("verifier_version"),
        "verification_report": verification_report,
    }
    for t in out.get("threats") or []:
        if not isinstance(t, dict):
            continue
        r = by_id.get(t.get("id")) or by_key.get(match_key(t) or "")
        if not r:
            continue
        variants = [row for row in doc["results"] if row["finding_ref"].get("id") == t.get("id")]
        coverage = _coverage(t, variants)
        rows = variants if coverage else [r]
        # One verdict for all variants, as verification.md gives it; the head cites the result that carries it.
        verdict = _overall(rows)
        lead = next((row for row in rows if row["verdict"] == verdict), {})
        t["dynamic_verification"] = {
            "verdict": verdict,
            "confidence": lead.get("confidence"),
            # When the result was tested, also for one kept from an earlier run (VER-037).
            "verified_at": ((lead.get("timing") or {}).get("finished") or lead.get("source_generated")
                            or doc["meta"].get("generated")),
            "verifier_version": doc["meta"].get("verifier_version"),
            "result_ref": lead.get("result_id"),
            "tested_scope": _tested_scope(lead),
        }
        if coverage:
            t["dynamic_verification"].update({
                "coverage": coverage,
                "variants": [{"variant": row["finding_ref"].get("variant"), "verdict": row["verdict"],
                              "result_ref": row["result_id"], "tested_scope": _tested_scope(row)}
                             for row in variants],
            })
        t["dynamic_verification"]["rating"] = rate(t, *_rating_input(rows, coverage))
        t["dynamic_verification"].update(_pointers(rows))
    return out
