"""Read the assessment and the verifiable-CWE catalog, and classify each finding
for verification planning (VER-005, VER-006, VER-026). Offline: no network, no
model calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .matchkey import match_key
from .version_info import resource_root

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return data


def load_verifiable_cwes() -> dict[str, dict]:
    """Map CWE id → {class, proof_method, ...} from data/verifiable-cwes.yaml."""
    doc = _load_yaml(resource_root() / "data" / "verifiable-cwes.yaml")
    return {e["cwe"].strip().upper(): e for e in doc.get("verifiable_cwes", []) if e.get("cwe")}


@dataclass
class FindingPlan:
    id: str
    cwe: str
    severity: str
    title: str
    match_key: str | None
    instance: str | None            # "file:line" when the finding has a location
    status: str                     # dynamic | static-only | input-incomplete
    cls: str | None                 # weakness class when dynamic
    reason: str


def _first_location(threat: dict) -> str | None:
    insts = threat.get("instances")
    if isinstance(insts, list):
        for i in insts:
            if isinstance(i, dict) and i.get("file"):
                return f"{i['file']}:{i.get('line')}"
    ev = threat.get("evidence")
    if isinstance(ev, list):
        ev = next((e for e in ev if isinstance(e, dict)), {})
    elif not isinstance(ev, dict):
        ev = {}
    if ev.get("file"):
        return f"{ev['file']}:{ev.get('line')}"
    return None


def classify(threat: dict, catalog: dict[str, dict]) -> FindingPlan:
    cwe = (threat.get("cwe") or "").strip().upper()
    mk = match_key(threat)
    loc = _first_location(threat)
    entry = catalog.get(cwe)
    if entry is None:
        status, cls, reason = "static-only", None, f"{cwe or 'no CWE'} not dynamically verifiable"
    elif mk is None or loc is None:
        status, cls, reason = "input-incomplete", entry["class"], "no evidence file/line in the finding"
    else:
        status, cls, reason = "dynamic", entry["class"], f"proof: {entry.get('proof_method')}"
    return FindingPlan(
        id=str(threat.get("id") or ""),
        cwe=cwe,
        severity=str(threat.get("severity") or threat.get("effective_severity") or "").strip(),
        title=str(threat.get("title") or ""),
        match_key=mk,
        instance=loc,
        status=status,
        cls=cls,
        reason=reason,
    )


def load_plans(assessment_path: Path) -> list[FindingPlan]:
    doc = _load_yaml(assessment_path)
    threats = doc.get("threats") or []
    catalog = load_verifiable_cwes()
    return [classify(t, catalog) for t in threats if isinstance(t, dict)]


def select(
    plans: list[FindingPlan], *,
    classes: set[str] | None = None,
    severities: set[str] | None = None,
    min_severity: str | None = None,
    cwes: set[str] | None = None,
    ids: set[str] | None = None,
) -> list[FindingPlan]:
    """Apply the VER-026 selectors (AND-combined). `ids` overrides the rest."""
    if ids:
        return [p for p in plans if p.id in ids]
    floor = _SEVERITY_RANK.get((min_severity or "").lower(), 0)
    out = []
    for p in plans:
        if classes and p.cls not in classes:
            continue
        if cwes and p.cwe not in cwes:
            continue
        if severities and p.severity.lower() not in severities:
            continue
        if floor and _SEVERITY_RANK.get(p.severity.lower(), 0) < floor:
            continue
        out.append(p)
    return out
