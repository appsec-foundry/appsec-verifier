"""Serialize a verification run: the standalone report (verification.yaml +
verification.md, VER-020), the AppSec Analyzer re-ingest export (VER-021), and
an additive annotation of a copy of the assessment (VER-027) with the rating
after verification (VER-039, verify/rating.py). The Analyzer's Markdown report
with the results is verify/annotated_report.py (VER-038).

verification.md opens with an overview of the selected findings, linked to
their entries, with verdict and rating (VER-020, VER-039). A tested finding's
entry leads with its verdict and what the code checked, then the steps its
verdict rests on and its proof of concept (VER-034): the decisive steps as
HTTP excerpts in code fences that target content cannot close, and its
screenshots (VER-035). The findings not tested follow with the reason (VER-024),
and an appendix holds the test plan, the test agent's own text and the evidence
review (VER-042). Recorded responses and screenshots can show target data; the
report says so and the export never references them (VER-022).

Reports and an annotated assessment are written through a temporary file and a
rename, so an interrupted write leaves the old file or the new one, never a
cut-off one. A report read back for `--resume` or `export` is checked against
schemas/verification.schema.yaml first.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
from pathlib import Path

import yaml

from ..version_info import resource_root
from .poc import TARGET_DATA_NOTE

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
                 and (r.get("proof") or {}).get("contract") == 3}
    return [p for p in expand_variants(plans) if (p.id, p.variant_digest) not in completed]


def merge_reports(existing: dict, new: dict) -> dict:
    """Continue a prior report with a new run's results (VER-027, `--resume`): a
    finding tested again replaces its earlier result; findings not re-tested are
    kept. Result ids are renumbered and the summary recomputed. Meta comes from
    the new run; the earlier generated time is kept as `previous_generated`."""
    by_id: dict[str, dict] = {}
    order: list[str] = []
    for r in (existing.get("results") or []) + (new.get("results") or []):
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
    write_text_atomically(md_path, to_markdown(doc, assessment))
    return {"yaml": yaml_path, "md": md_path, "evidence": out_dir / "evidence"}


_ORDER = ("confirmed", "blocked-by-control", "not-reproducible", "inconclusive", "not-attempted")
_LABEL = {**_VERDICT_LABEL, "not-attempted": "not tested"}
# A verdict the proof check lowered names its reason before the agent's claim (agent/proof.py, _downgrade).
_LOWERED = re.compile(r"indicative, not (?:proven|executed): (.*?)\. Agent's claim:", re.S)


def _inline(value, limit: int = 300, *, cell: bool = False) -> str:
    """Text from the assessment, the model or the target on one line of Markdown: no line break or HTML, and
    in a table `cell` no column separator."""
    text = " ".join(str("" if value is None else value).split())[:limit].replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|") if cell else text


def _sentence(value, limit: int = 600) -> str:
    text = _inline(value, limit)
    return text if text.endswith((".", "!", "?")) else text + "."


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


def _rating_text(rating: dict | None, threat: dict | None = None) -> str:
    """`High, unchanged`, `**High → Critical**` for a change (VER-039), for a finding not tested the Analyzer's
    severity alone, or – when unknown."""
    if rating is None:
        severity = (threat or {}).get("effective_severity") or (threat or {}).get("risk")
        return _inline(severity, 40, cell=True) or "–"
    before, after = (_inline(rating[k].get("severity"), 40, cell=True) or "–"
                     for k in ("analyzer", "after_verification"))
    return f"**{before} → {after}**" if rating["changed"] else f"{before}, unchanged"


def _step_line(step: dict) -> str:
    """A recorded step without the target's origin and the name of the HTTP tool. The line carries a URL the
    model chose, so it is only ever shown in a code fence."""
    tool, _, rest = str(step["line"]).partition(" ")
    rest = re.sub(r"^(\S+ )[a-z][a-z0-9+.-]*://[^/\s]+", r"\1", rest, count=1)   # METHOD scheme://host/path
    name = {"http_request": "", "browser_check": "browser "}.get(tool, tool + " ")
    return f"step {step['step']}: {name}{rest}"


def _why_not(r: dict) -> str | None:
    """Why a tested finding is not confirmed, as the code knows it: what the proof check missed, the limit
    that stopped the test, or why the check lowered the agent's verdict."""
    if r["verdict"] not in ("inconclusive", "not-attempted"):
        return None
    proof = r.get("proof") or {}
    if proof.get("missing"):
        return "; ".join(str(m) for m in proof["missing"])
    if r.get("limits_hit"):
        return r.get("rationale") or f"stopped by the {r['limits_hit']} limit"
    lowered = _LOWERED.match(r.get("rationale") or "")
    if lowered:
        return lowered.group(1)
    return "the test agent ended without a checked proof; its explanation is in the appendix"


def to_markdown(doc: dict, assessment: dict | None = None) -> str:
    """verification.md (VER-020): the run; an overview of the selected findings, each linked to its entry,
    with verdict and rating before and after verification (VER-039); each tested finding led by its verdict,
    the steps its proof rests on and its proof of concept (VER-034, VER-035); the findings not tested with
    the reason (VER-024); an appendix with the test plan, the test agent's explanation and the evidence
    review (VER-042). Text from the assessment, the model or the target stays on one line or in a fence."""
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
    lines = _run_lines(doc) + _overview(ordered, threats, ratings)
    if tested:
        lines += ["", "## Tested findings"]
        for fid, rows in tested:
            for i, r in enumerate(rows):
                lines += _entry(r, ratings[fid], first=i == 0, details=bool(details[id(r)]))
    if untested:
        lines += ["", "## Not tested", "", "| Finding | Why not |", "| --- | --- |"]
        for fid, rows in untested:
            fr, anchor = (rows[0].get("finding_ref") or {}), _anchor(fid)
            mark = f'<a id="{anchor}"></a>' if anchor else ""
            why = re.sub(r"^not tested: ", "", str(rows[0].get("rationale") or ""))
            title = _inline(fr.get("title") or fr.get("cwe"), 120, cell=True)
            lines.append(f"| {mark}{_inline(fid, cell=True)} {title} | {_inline(why, cell=True) or '–'} |")
    if any(details.values()):
        lines += ["", "## Appendix: test details"]
        for fid, rows in tested:
            for i, r in enumerate(rows):
                if details[id(r)]:
                    anchor = _anchor(fid)
                    lines += ["", *([f'<a id="details-{anchor}"></a>'] if i == 0 and anchor else []),
                              f"### {_inline(fid)}{_variant(r)}", *details[id(r)]]
    return "\n".join(lines) + "\n"


def _variant(r: dict) -> str:
    variant = (r.get("finding_ref") or {}).get("variant")
    return f" · variant {_inline(variant)}" if variant else ""


def _run_lines(doc: dict) -> list[str]:
    meta = doc["meta"]
    target, safety = meta.get("target") or {}, meta.get("safety") or {}
    auth, scope = meta.get("authorization") or {}, meta.get("scope") or {}
    if safety.get("read_only"):
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
             f"- **Assessment:** {_inline(meta.get('source_assessment'))}",
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
    if any(r.get("poc") or r.get("evidence") for r in doc["results"]):
        lines.append(f"- **Evidence:** the proofs of concept and screenshots {TARGET_DATA_NOTE}.")
    return lines


def _overview(ordered, threats: dict, ratings: dict) -> list[str]:
    tally: dict[str, int] = {}
    for _, rows in ordered:
        tally[_overall(rows)] = tally.get(_overall(rows), 0) + 1
    counts = " · ".join(f"{n} {_LABEL.get(v, v)}" for v, n in sorted(tally.items(), key=lambda kv: (
        _ORDER.index(kv[0]) if kv[0] in _ORDER else len(_ORDER))))
    of = f" of {len(threats)}" if threats else ""
    lines = ["", "## Overview", "", f"{len(ordered)}{of} findings selected: {counts or 'none'}.", "",
             "| Finding | Result | Rating, Analyzer → after verification |", "| --- | --- | --- |"]
    changed = []
    for fid, rows in ordered:
        verdict, anchor, fr = _overall(rows), _anchor(fid), (rows[0].get("finding_ref") or {})
        label = _LABEL.get(verdict, verdict) + (f" ({len(rows)} variants)" if len(rows) > 1 else "")
        link = f"[{_inline(fid, cell=True)}](#{anchor})" if anchor else _inline(fid, cell=True)
        lines.append(f"| {link} {_inline(fr.get('title') or fr.get('cwe'), 120, cell=True)} | "
                     f"{'**' + label + '**' if verdict == 'confirmed' else label} | "
                     f"{_rating_text(ratings[fid], threats.get(fid))} |")
        if ratings[fid] and ratings[fid]["changed"]:
            changed.append(f"[{_inline(fid)}](#{anchor}) {_inline(ratings[fid]['reason'])}")
    if changed:
        lines += ["", "Ratings changed: " + "; ".join(changed) + "."]
    elif any(ratings.values()):
        lines += ["", "No rating changed."]
    return lines


def _entry(r: dict, rating: dict | None, *, first: bool, details: bool) -> list[str]:
    """A tested finding: verdict first, then what the code checked, the steps the verdict rests on and the
    proof of concept (VER-020)."""
    fr, proof, verdict = (r.get("finding_ref") or {}), r.get("proof") or {}, r["verdict"]
    fid = fr.get("id") or r["result_id"]
    anchor = _anchor(fid)
    head = [f"**{_LABEL.get(verdict, verdict).capitalize()}**"]
    if rating is not None:
        head.append("rating " + _rating_text(rating))
    if r.get("confidence"):
        head.append(f"confidence {_inline(r['confidence'])}")
    head += [_inline(v) for v in (fr.get("cwe"), r.get("class")) if v]
    if fr.get("match_key"):
        head.append(f"key {_inline(fr['match_key'])}")
    out = ["", *([f'<a id="{anchor}"></a>'] if first and anchor else []),
           f"### {_inline(fid)} · {_inline(fr.get('title') or fr.get('cwe'))}{_variant(r)}", "", " · ".join(head), ""]
    facts = []
    if verdict == "confirmed" and proof.get("checked"):
        from ..progress import _PROVEN

        shown = _PROVEN.get(r.get("class"))
        facts.append("Proof checked by the code" + (f": {shown}." if shown else "."))
    if why := _why_not(r):
        facts.append(f"Not confirmed: {_sentence(why)}")
    if proof.get("checked") and proof.get("scope"):
        facts.append(f"Checked scope: {_sentence(proof['scope'])}")
    if rating and rating["changed"]:
        facts.append(f"Rating changed: {_sentence(rating['reason'])}")
    deviations = [*([f"Deviation: {r['deviation']}"] if r.get("deviation") else []),
                  *(o for o in r.get("observations") or [] if o.startswith("Deviation:"))]
    facts += [_sentence(d) for d in deviations]
    if r.get("selection_reason"):
        facts.append(f"Additionally selected: {_sentence(r['selection_reason'])}")
    out += [f"- {fact}" for fact in facts]
    steps = (r.get("poc") or {}).get("steps") or []
    decisive = [s for s in steps if s.get("decisive")]
    rest = [s for s in steps if not s.get("decisive")]
    if decisive:
        label = "Steps the proof rests on" if verdict == "confirmed" else "Steps the verdict rests on"
        out += ["", f"{label}:", "", _fenced("\n".join(_step_line(s) for s in decisive), "text")]
    if rest:
        out += ["", "Other requests:" if decisive else "Requests sent:", "",
                _fenced("\n".join(_step_line(s) for s in rest), "text")]
    out += _poc_markdown(r, level=4, steps=False)
    files = [_inline(e["path"]) for e in r.get("evidence") or [] if e.get("path")]
    if files:
        out += ["", "Files: " + ", ".join(files)]
    if details and first and anchor:
        out += ["", f"Test plan, the test agent's explanation and the evidence review: [details](#details-{anchor})"]
    return out


def _details(r: dict) -> list[str]:
    """The appendix part of a tested finding (VER-020): the test plan, the test agent's own explanation and
    observations, and the evidence review (VER-042). Model text, so it stays in code fences."""
    out = []
    if r.get("planning"):
        plan = yaml.safe_dump(r["planning"], sort_keys=False, allow_unicode=True, width=110).rstrip()
        out += ["", "Test plan (assumptions are not proof):", "", _fenced(plan, "yaml")]
    if r.get("rationale") and not r.get("limits_hit"):
        out += ["", "Test agent's explanation (not proof):", "", _fenced(str(r["rationale"]), "text")]
    notes = [o for o in r.get("observations") or []
             if not o.startswith(("Application screenshot unavailable:", "Deviation:"))]
    if notes:
        out += ["", "Other observations, not verified:", "", _fenced("\n".join(notes), "text")]
    return out + _review_markdown(r, 4)


def _fenced(text: str, info: str = "http") -> str:
    """`text` in a code fence longer than any backtick run inside it, so target content cannot close it."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{info}\n{text}\n{fence}"


def _review_markdown(r: dict, level: int) -> list[str]:
    review = r.get("evidence_review")
    if not review:
        return []
    shown = review.get("images_reviewed") or []
    seen = ("Screenshots a model reviewed: " + ", ".join(f"`{p}`" for p in shown) + "." if shown
            else "No screenshot was shown to a model.")
    out = ["", f"{'#' * level} Evidence presentation review", "",
           f"Technical verdict unchanged. {seen}", "",
           _fenced(f"Status: {review['status']} · corrections: {review['rounds']}/2 · "
                   f"reviews: {review['reviews']}\n{review['reason']}", "text")]
    if review["issues"]:
        out += ["", "Unresolved presentation issues:", "",
                _fenced("\n".join(f"{i['variant']}: {i['detail']}" for i in review["issues"]), "text")]
    for presentation in review["presentations"]:
        out += ["", "Original test agent explanation (not additional proof):", "",
                _fenced(f"{presentation['variant']}: {presentation['explanation']}", "text")]
        for quote in presentation["quotes"]:
            out += ["", f"Recorded excerpt, step {quote['step']}, {quote['part']}:", "", _fenced(quote["text"])]
    return out


def _poc_markdown(r: dict, level: int = 4, *, steps: bool = True) -> list[str]:
    """The proof of concept (VER-034, VER-035): the application screenshots with the test agent's explanation,
    with `steps` one line per request, then the steps the verdict rests on as HTTP excerpts, ⟦…⟧ around
    what the proof rests on."""
    poc = r.get("poc") or {}
    application = [e for e in r.get("evidence") or []
                   if e.get("kind") == "screenshot" and (e.get("presentation") == "application" or
                       re.search(r"-(?:xss|access-control)-[0-9]+\.png$", e.get("path", ""))) and e.get("path")]
    out = []
    if application:
        out += ["", f"{'#' * level} Exploit in the application", ""]
        for ev in application:
            out += [f"![Application screenshot {ev['path']}]({ev['path']})", ""]
            if ev.get("explanation"):      # model text: fenced, so it stays text (VER-035)
                out += [_fenced(f"Test agent's explanation: {ev['explanation']}", "text"), ""]
    limitations = [o for o in r.get("observations") or []
                   if o.startswith("Application screenshot unavailable:")]
    out += ["", *(_sentence(o) for o in dict.fromkeys(limitations))] if limitations else []
    if not poc.get("steps") or not (steps or poc.get("shown")):
        return out
    out += ["", f"{'#' * level} Proof of concept", ""]
    if steps:
        # The lines carry URLs the model chose: inside a fence they stay text, whatever they contain.
        out += [_fenced("\n".join(_step_line(s) + (" (shown below)" if s.get("decisive") else "")
                                  for s in poc["steps"]), "text"), ""]
    har = f"All requests and responses: {_inline(poc['file'])}." if poc.get("file") else ""
    if any("request_excerpt" in s for s in poc.get("shown") or []):
        har = f"⟦…⟧ marks what the proof rests on. {har}".rstrip()
    out += [har] if har else []
    for shown in poc.get("shown") or []:
        facts = shown.get("facts") or []
        if facts:
            out += ["", _fenced("\n".join(facts), "text")]
        browser = any(str(f).startswith("opened in the browser:") for f in facts)
        request = ("the page's first request; the part after # stays in the browser" if browser else "request")
        out += ["", f"Step {shown['step']}, {request}:", "",
                _fenced(shown.get("request_excerpt", shown["request"]).rstrip()), "", "Response:", "",
                _fenced(shown.get("response_excerpt", shown["response"]).rstrip())]
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
            "verified_at": meta.get("generated"),
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
    Of several variants, one confirmed variant counts; a block counts only when every variant was blocked."""
    def checked(row):
        return (row.get("proof") or {}).get("checked") is True

    if any(row["verdict"] == "confirmed" and checked(row) for row in rows):
        return "confirmed", True
    if coverage in (None, "complete") and rows and all(
            row["verdict"] == "blocked-by-control" and checked(row) for row in rows):
        return "blocked-by-control", True
    return (rows[0]["verdict"] if len(rows) == 1 else "inconclusive"), False


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
        t["dynamic_verification"] = {
            "verdict": r["verdict"],
            "confidence": r.get("confidence"),
            "verified_at": doc["meta"].get("generated"),
            "verifier_version": doc["meta"].get("verifier_version"),
            "result_ref": r.get("result_id"),
            "tested_scope": {k: (r.get("proof") or {})[k]
                             for k in ("checked", "contract", "variant", "tested_path", "scope")
                             if k in (r.get("proof") or {})},
        }
        variants = [row for row in doc["results"] if row["finding_ref"].get("id") == t.get("id")]
        coverage = _coverage(t, variants)
        rows = variants if coverage else [r]
        if coverage:
            t["dynamic_verification"].update({
                "verdict": "confirmed" if any(row["verdict"] == "confirmed" for row in variants) else "inconclusive",
                "coverage": coverage,
                "variants": [{"variant": row["finding_ref"].get("variant"), "verdict": row["verdict"],
                              "result_ref": row["result_id"], "tested_scope": row.get("proof")}
                             for row in variants],
            })
        t["dynamic_verification"]["rating"] = rate(t, *_rating_input(rows, coverage))
        t["dynamic_verification"].update(_pointers(rows))
    return out
