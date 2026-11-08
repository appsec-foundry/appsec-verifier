"""Read the assessment and the verifiable-CWE catalog, and classify each finding
for verification planning (VER-005, VER-006, VER-026). The assessment is checked
against schemas/assessment.schema.yaml, which covers only the fields read here,
and its finding ids must be unique (VER-032). Error messages name the place and
the rule; the only value they quote is a repeated id, escaped by repr. Each plan
also carries the requests the finding names and its scenario (endpoints.py).
Offline: no network, no model calls.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from jsonschema.validators import validator_for

from .endpoints import Endpoint, finding_brief, finding_endpoints, preparation_endpoints
from .matchkey import match_key
from .verification_context import context_errors, finding_context
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


def list_categories() -> list[str]:
    """Selectable category names: every class and technique in the catalog."""
    names = set()
    for e in load_verifiable_cwes().values():
        if e.get("class"):
            names.add(e["class"])
        if e.get("technique"):
            names.add(e["technique"])
    return sorted(names)


@dataclass
class FindingPlan:
    id: str
    cwe: str
    severity: str
    title: str
    match_key: str | None
    instance: str | None            # "file:line" when the finding has a location
    status: str                     # dynamic | unsupported | static-only (legacy reports) | input-incomplete
    cls: str | None                 # weakness class when dynamic
    reason: str
    technique: str | None = None    # finer category (e.g. idor, sqli) when dynamic
    endpoints: tuple[Endpoint, ...] = ()    # requests the finding names (endpoints.py)
    preparation: tuple[Endpoint, ...] = ()  # evidenced creation requests, owner-only under an accepted plan
    brief: str = ""                 # its scenario and attack steps, for the agent
    context: dict = field(default_factory=dict)
    verification_context: dict = field(default_factory=dict)
    selection_reason: str | None = None
    variant_id: str | None = None
    variant_digest: str | None = None


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


def classify(threat: dict, catalog: dict[str, dict], surface=None) -> FindingPlan:
    cwe = (threat.get("cwe") or "").strip().upper()
    mk = match_key(threat)
    loc = _first_location(threat)
    entry = catalog.get(cwe)
    if entry is None:
        status, cls, reason = "unsupported", None, f"no supported proof method for {cwe or 'missing CWE'}"
    elif mk is None or loc is None:
        status, cls, reason = "input-incomplete", entry["class"], "no evidence file/line in the finding"
    else:
        status, cls, reason = "dynamic", entry["class"], f"proof: {entry.get('proof_method')}"
    endpoints = finding_endpoints(threat, surface)
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
        technique=(entry.get("technique") if entry else None),
        endpoints=endpoints,
        preparation=preparation_endpoints(threat, surface, endpoints),
        brief=finding_brief(threat),
        context=finding_context(threat),
        verification_context=threat.get("verification_context") or {},
    )


class AssessmentError(ValueError):
    """The assessment lacks the structure the Verifier reads (VER-005, VER-032)."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


_MAX_ERRORS = 10


def _rule(error) -> str:
    if error.validator == "type":
        types = error.validator_value if isinstance(error.validator_value, list) else [error.validator_value]
        return "must be " + " or ".join(t for t in types if t != "null")
    if error.validator == "required":
        return error.message            # names the property from the schema, not a value from the file
    if error.validator == "minLength":
        return "must not be empty"
    return f"fails the {error.validator} rule"


def assessment_errors(doc: dict) -> list[str]:
    """Why `doc` cannot be read as an assessment; empty when it can."""
    with open(resource_root() / "schemas" / "assessment.schema.yaml", encoding="utf-8") as fh:
        schema = yaml.safe_load(fh)
    found = sorted(validator_for(schema)(schema).iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    errors = [f"{'/'.join(map(str, e.absolute_path)) or 'file'}: {_rule(e)}" for e in found]
    if not errors:
        ids = [t["id"] for t in doc["threats"]]
        errors = [f"threats: id {i[:40]!r} is used {n} times" for i, n in Counter(ids).items() if n > 1]
        for n, threat in enumerate(doc["threats"]):
            if "verification_context" in threat:
                errors += [f"threats/{n}/{e}" for e in context_errors(threat["verification_context"])]
    return errors[:_MAX_ERRORS] + ([f"… {len(errors) - _MAX_ERRORS} more"] if len(errors) > _MAX_ERRORS else [])


def read_assessment(assessment_path: Path) -> dict:
    """The assessment, or AssessmentError when it lacks the structure read here."""
    doc = _load_yaml(assessment_path)
    errors = assessment_errors(doc)
    if errors:
        raise AssessmentError(errors)
    return doc


def plans_from(doc: dict) -> list[FindingPlan]:
    from .planning import enrich

    catalog = load_verifiable_cwes()
    return enrich([classify(t, catalog, doc.get("attack_surface")) for t in doc["threats"]], doc)


def load_plans(assessment_path: Path) -> list[FindingPlan]:
    return plans_from(read_assessment(assessment_path))


def select(
    plans: list[FindingPlan], *,
    categories: set[str] | None = None,
    classes: set[str] | None = None,
    severities: set[str] | None = None,
    min_severity: str | None = None,
    cwes: set[str] | None = None,
    ids: set[str] | None = None,
) -> list[FindingPlan]:
    """Apply the VER-026 selectors (AND-combined). `ids` overrides the rest.
    `categories` matches a finding's class OR its finer technique (e.g. "idor"),
    so a category can be selected without naming a CWE."""
    if ids:
        return [p for p in plans if p.id in ids]
    cats = {c.lower() for c in (categories or set())}
    floor = _SEVERITY_RANK.get((min_severity or "").lower(), 0)
    out = []
    for p in plans:
        if cats and (p.cls or "").lower() not in cats and (p.technique or "").lower() not in cats:
            continue
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
