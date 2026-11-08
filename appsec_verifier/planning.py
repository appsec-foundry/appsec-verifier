"""Assessment relationships, bounded planning context and supplemental selection (VER-005/008/026)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from urllib.parse import urlsplit

from .verification_context import bounded

TEXT = {"type": "string", "minLength": 10, "maxLength": 1000}
STRATEGY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["data_flow", "prerequisites", "choice", "counter_hypothesis", "expected", "stop"],
    "properties": {
        **{key: TEXT for key in ("data_flow", "choice", "counter_hypothesis", "expected", "stop")},
        "prerequisites": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["condition", "status"],
                "properties": {
                    "condition": TEXT,
                    "status": {"enum": ["observed", "assumed", "missing"]},
                    "steps": {
                        "type": "array",
                        "maxItems": 12,
                        "uniqueItems": True,
                        "items": {"type": "integer", "minimum": 1},
                    },
                },
            },
        },
        "revision_reason": TEXT,
    },
}


def _ids(value, depth=0):
    if depth > 8:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return set().union(*(_ids(v, depth + 1) for v in value[:32])) if value else set()
    if isinstance(value, dict):
        return set().union(
            *(
                _ids(v, depth + 1)
                for k, v in list(value.items())[:32]
                if k in ("id", "ref", "component", "component_id", "from", "to")
            )
        )
    return set()


def enrich(plans, doc):
    """Resolve only related report objects; report text never supplies run authority."""
    known = {p.id for p in plans}
    threats = {t["id"]: t for t in doc["threats"]}
    chains = doc.get("compound_chains", [])
    chains = chains.get("chains", []) if isinstance(chains, dict) else chains
    chains = chains if isinstance(chains, list) else []
    for p in plans:
        threat = threats[p.id]
        refs = set().union(
            *(_ids(threat.get(k)) for k in ("component", "component_id", "affected_components", "boundary_refs"))
        )
        architecture = {}
        # Boundaries first so their connected components and flows can also be resolved.
        for key in ("trust_boundaries", "components", "data_flows", "security_controls"):
            rows = doc.get(key, [])
            if not isinstance(rows, list):
                continue
            related = [r for r in rows if isinstance(r, dict) and _ids(r) & refs][:12]
            if related:
                architecture[key] = bounded(related)
                for row in related:
                    refs.update(_ids(row))
        dependencies = threat.get("verification_dependencies", [])
        dependencies = [d for d in dependencies if d in known and d != p.id]
        related_chains = [
            c
            for c in chains[:100]
            if isinstance(c, dict)
            and p.id in (_ids(c.get("findings")) | _ids(c.get("keystones")) | _ids(c.get("contributors")))
        ]
        extra = {
            "architecture": architecture,
            "dependencies": dependencies,
            "attack_chains": bounded(related_chains),
            "walkthrough": bounded(threat.get("attack_walkthrough", {})),
        }
        p.context = {**p.context, **extra}
    return plans


def management_candidate(plan):
    """Specific access/exposure findings, never a generic endpoint scan or a health check."""
    if plan.status != "dynamic" or plan.cls != "access-control":
        return False
    for endpoint in plan.endpoints:
        try:
            path = urlsplit(endpoint.path).path.lower()
        except ValueError:
            continue
        if re.search(r"/(?:actuator|management|admin|metrics|debug)(?:/|$)", path) and not re.search(
            r"/(?:health|healthz|ready|readyz|live|livez)(?:/|$)", path
        ):
            return True
    return False


def supplement(selected, eligible, *, enabled=True, cap=8):
    """Extend a severity floor within other explicit selectors, with a fixed additional-finding cap."""
    if not enabled:
        return selected
    chosen = {p.id: p for p in selected}
    available = {p.id: p for p in eligible if p.status == "dynamic"}
    reasons = {}
    pending = list(chosen)
    while pending and len(reasons) < cap:
        parent = pending.pop(0)
        for dep in chosen[parent].context.get("dependencies", []):
            if dep in available and dep not in chosen and len(reasons) < cap:
                chosen[dep] = available[dep]
                reasons[dep] = f"prerequisite named by {parent}; transition remains unverified"
                pending.append(dep)
    for p in eligible:
        if len(reasons) >= cap:
            break
        if p.id not in chosen and management_candidate(p):
            chosen[p.id] = p
            reasons[p.id] = "management access or exposure finding with a concrete endpoint"
    return [replace(p, selection_reason=reasons.get(p.id)) for p in chosen.values()]


def dependency_order(plans):
    """Stable prerequisite-first order; cyclic relationships stay explicit and unproven."""
    by_id = {p.id: p for p in plans}
    out, visiting, done = [], set(), set()

    for root in plans:
        stack = [(root, False)]
        while stack:
            p, finish = stack.pop()
            if p.id in done:
                continue
            if finish:
                visiting.discard(p.id)
                done.add(p.id)
                out.append(p)
            elif p.id not in visiting:
                visiting.add(p.id)
                stack.append((p, True))
                stack.extend(
                    (by_id[d], False)
                    for d in reversed(p.context.get("dependencies", []))
                    if d in by_id and d not in visiting
                )

    return out


def variant_key(plan, variant):
    material = {"finding": plan.match_key, "variant": {k: v for k, v in variant.items() if k != "id"}}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def expand_variants(plans):
    out = []
    for p in plans:
        variants = p.verification_context.get("variants", [])
        if not variants:
            out.append(p)
        for v in variants:
            out.append(
                replace(
                    p,
                    verification_context={**p.verification_context, "variants": [v]},
                    variant_id=v["id"],
                    variant_digest=variant_key(p, v),
                )
            )
    return out


def evidence_id(plan):
    digest = getattr(plan, "variant_digest", None)
    return plan.id + ("-" + digest[:16] if digest else "")
