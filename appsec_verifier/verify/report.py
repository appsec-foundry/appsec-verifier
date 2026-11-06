"""Serialize a verification run: the standalone report (verification.yaml +
verification.md, VER-020), the AppSec Analyzer re-ingest export (VER-021), and
an additive assessment annotation (VER-027).
"""

from __future__ import annotations

from pathlib import Path

import yaml

_VERDICT_LABEL = {
    "confirmed": "confirmed",
    "not-reproducible": "not reproducible",
    "blocked-by-control": "blocked by control",
    "inconclusive": "inconclusive",
    "not-attempted": "not attempted",
}


def write_reports(doc: dict, out_dir: Path) -> dict:
    """Write verification.yaml + verification.md (+ an empty evidence/ dir) into
    out_dir. Returns the written paths."""
    out_dir = Path(out_dir)
    (out_dir / "evidence").mkdir(parents=True, exist_ok=True)
    yaml_path = out_dir / "verification.yaml"
    md_path = out_dir / "verification.md"
    with open(yaml_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True)
    md_path.write_text(to_markdown(doc), encoding="utf-8")
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
        f"- **Scope owner:** {meta.get('scope', {}).get('owner')}",
        f"- **Authorisation:** confirmed={meta.get('authorization', {}).get('confirmed')} "
        f"({meta.get('authorization', {}).get('mode')})",
        f"- **Mode:** {meta.get('safety', {}).get('mode')} · "
        f"{'read-only' if meta.get('safety', {}).get('read_only') else 'state-changing'} · "
        f"target contacted: {meta.get('contacted_target')}",
        f"- **Generated:** {meta.get('generated')} · verifier {meta.get('verifier_version')}",
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
        if r.get("deviation"):
            lines.append(f"- deviation: {r['deviation']}")
        for ev in r.get("evidence") or []:
            lines.append(f"- evidence: {ev.get('kind')} → {ev.get('path')}")
        lines.append("")
    return "\n".join(lines)


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
            "verified_at": meta.get("generated"),
            "result_ref": r.get("result_id"),
            "evidence_ref": (r.get("evidence") or [{}])[0].get("path") if r.get("evidence") else None,
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
        }
    return out
