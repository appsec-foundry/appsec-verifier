"""Serialize a verification run: the standalone report (verification.yaml +
verification.md, VER-020), the AppSec Analyzer re-ingest export (VER-021), and
an additive assessment annotation (VER-027).

Each tested finding's section in verification.md ends with its proof of
concept (VER-034): one line per step and the decisive steps as raw HTTP, in
code fences that target content cannot close, and its screenshots (VER-035).
Recorded responses and screenshots can show target data; the report says so
and the export never references them (VER-022).

Reports and an annotated assessment are written through a temporary file and a
rename, so an interrupted write leaves the old file or the new one, never a
cut-off one. A report read back for `--resume` or `export` is checked against
schemas/verification.schema.yaml first.
"""

from __future__ import annotations

import contextlib
import json
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


def merge_reports(existing: dict, new: dict) -> dict:
    """Continue a prior report with a new run's results (VER-027, `--resume`): a
    finding tested again replaces its earlier result; findings not re-tested are
    kept. Result ids are renumbered and the summary recomputed. Meta comes from
    the new run; the earlier generated time is kept as `previous_generated`."""
    by_id: dict[str, dict] = {}
    order: list[str] = []
    for r in (existing.get("results") or []) + (new.get("results") or []):
        key = r.get("finding_ref", {}).get("id") or r.get("result_id")
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


def write_reports(doc: dict, out_dir: Path) -> dict:
    """Write verification.yaml + verification.md (+ an empty evidence/ dir) into
    out_dir. Returns the written paths."""
    out_dir = Path(out_dir)
    (out_dir / "evidence").mkdir(parents=True, exist_ok=True)
    yaml_path = out_dir / "verification.yaml"
    md_path = out_dir / "verification.md"
    write_text_atomically(yaml_path, yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))
    write_text_atomically(md_path, to_markdown(doc))
    return {"yaml": yaml_path, "md": md_path, "evidence": out_dir / "evidence"}


def to_markdown(doc: dict) -> str:
    meta, results = doc["meta"], doc["results"]
    s = meta.get("summary", {})
    tgt = meta.get("target", {})
    lines = [
        "# AppSec Verifier — verification report",
        "",
        f"- **Assessment:** {meta.get('source_assessment')}",
        f"- **Target:** {tgt.get('base_url')} ({tgt.get('environment')}) · build {tgt.get('build_match')}",
        f"- **Scope owner:** {meta.get('scope', {}).get('owner')}" if meta.get("scope", {}).get("file")
        else "- **Scope:** no scope file; only the target's host and port, read-only",
        f"- **Authorisation:** confirmed={meta.get('authorization', {}).get('confirmed')} "
        f"({meta.get('authorization', {}).get('mode')})",
        f"- **Mode:** {meta.get('safety', {}).get('mode')} · "
        f"{'read-only' if meta.get('safety', {}).get('read_only') else 'state-changing'} · "
        f"target contacted: {meta.get('contacted_target')}",
        f"- **Generated:** {meta.get('generated')} · verifier {meta.get('verifier_version')}",
        *([f"- **Evidence:** the proofs of concept and screenshots below {TARGET_DATA_NOTE}"]
          if any(r.get("poc") or r.get("evidence") for r in results) else []),
        "",
        "## Summary",
        "",
        f"{s.get('total', 0)} findings — "
        f"{s.get('confirmed', 0)} confirmed · {s.get('not_reproducible', 0)} not reproducible · "
        f"{s.get('blocked', 0)} blocked · {s.get('inconclusive', 0)} inconclusive · "
        f"{s.get('not_attempted', 0)} not attempted",
        "",
        "## Findings",
        "",
    ]
    for r in results:
        fr = r.get("finding_ref", {})
        verdict = _VERDICT_LABEL.get(r["verdict"], r["verdict"])
        conf = f" ({r['confidence']})" if r.get("confidence") else ""
        lines.append(f"### {r['result_id']} · {fr.get('id')} · {fr.get('title') or fr.get('cwe')} — {verdict}{conf}")
        lines.append(f"- class: {r.get('class')} · CWE: {fr.get('cwe')} · match_key: `{fr.get('match_key')}`")
        if r.get("rationale"):
            lines.append(f"- {r['rationale']}")
        proof = r.get("proof") or {}
        if proof.get("checked"):
            detail = {k: proof[k] for k in ("variant", "tested_path", "hypothesis", "observation_pointer", "steps")
                      if proof.get(k) is not None}
            lines += ["", "Checked scope: cited requests only; other variants remain untested.",
                      _fenced(json.dumps(detail, ensure_ascii=False, indent=2), "json")]
        if proof.get("missing"):
            lines += ["", "Missing evidence:", _fenced("\n".join(proof["missing"]), "text")]
        if r.get("deviation"):
            lines.append(f"- deviation: {r['deviation']}")
        for ev in r.get("evidence") or []:
            note = f" ({ev['note']})" if ev.get("note") else ""
            lines.append(f"- evidence: {ev.get('kind')} → {ev.get('path')}{note}")
        lines += _poc_markdown(r)
        lines.append("")
    return "\n".join(lines)


def _fenced(text: str, info: str = "http") -> str:
    """`text` in a code fence longer than any backtick run inside it, so target content cannot close it."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{info}\n{text}\n{fence}"


def _poc_markdown(r: dict) -> list[str]:
    """The proof of concept (VER-034): one line per step, then the steps the verdict rests on as raw HTTP."""
    poc = r.get("poc") or {}
    if not poc.get("steps"):
        return []
    out = ["", "#### Proof of concept", ""]
    if poc.get("file"):
        out += [f"All requests and responses: `{poc['file']}` (HAR, {TARGET_DATA_NOTE}).", ""]
    # The lines carry URLs the model chose: inside a fence they stay text, whatever they contain.
    out.append(_fenced("\n".join(f"step {s['step']}: {s['line']}" + (" (shown below)" if s.get("decisive") else "")
                                 for s in poc["steps"]), "text"))
    for shown in poc.get("shown") or []:
        took = f" (answered in {shown['elapsed_ms']} ms)" if shown.get("elapsed_ms") else ""
        out += ["", f"Step {shown['step']}{took}, request:", "", _fenced(shown["request"]), "",
                "Response:", "", _fenced(shown["response"])]
    for ev in r.get("evidence") or []:
        if ev.get("kind") == "screenshot" and ev.get("path"):
            out += ["", f"![Screenshot {ev['path']}]({ev['path']})"]
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


def annotate_assessment(assessment: dict, doc: dict) -> dict:
    """Return a copy of the assessment with an additive `verification` block on
    each matched finding (VER-027). Never changes or removes a finding."""
    from ..matchkey import match_key

    by_id = {r["finding_ref"]["id"]: r for r in doc["results"] if r["finding_ref"].get("id")}
    by_key = {}
    for r in doc["results"]:
        mk = r["finding_ref"].get("match_key")
        if mk:
            by_key.setdefault(mk, r)

    import copy
    out = copy.deepcopy(assessment)
    for t in out.get("threats") or []:
        if not isinstance(t, dict):
            continue
        r = by_id.get(t.get("id")) or by_key.get(match_key(t) or "")
        if not r:
            continue
        t["verification"] = {
            "verdict": r["verdict"],
            "confidence": r.get("confidence"),
            "verified_at": doc["meta"].get("generated"),
            "verifier_version": doc["meta"].get("verifier_version"),
            "result_ref": r.get("result_id"),
            "tested_scope": {k: (r.get("proof") or {})[k]
                             for k in ("checked", "contract", "variant", "tested_path", "scope")
                             if k in (r.get("proof") or {})},
        }
    return out
