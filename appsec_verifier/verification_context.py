"""Bounded, source-grounded planning context, never authority (VER-005, VER-008, VER-019)."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator

from .version_info import resource_root


@lru_cache(maxsize=1)
def context_validator():
    schema = json.loads((resource_root() / "schemas/verification-context.schema.json").read_text())
    return Draft202012Validator(schema)


def context_errors(value) -> list[str]:
    errors = [
        f"verification_context/{'/'.join(map(str, e.path))}: invalid {e.validator}"
        for e in context_validator().iter_errors(value)
    ]
    if not errors:
        ids = [v["id"] for v in value["variants"]]
        if len(ids) != len(set(ids)):
            errors.append("verification_context: variant ids must be unique")
    return errors[:10]


def bounded(value, *, depth=0):
    """Bound legacy context by field, preserving JSON structure and signalling omissions."""
    if depth > 8:
        return "[context depth limit]"
    if isinstance(value, str):
        return value if len(value) <= 3000 else value[:3000] + " [truncated]"
    if isinstance(value, list):
        return [bounded(v, depth=depth + 1) for v in value[:12]] + (["[more entries]"] if len(value) > 12 else [])
    if isinstance(value, dict):
        return {str(k)[:128]: bounded(v, depth=depth + 1) for k, v in list(value.items())[:20]}
    return value if value is None or isinstance(value, int | float | bool) else None


def finding_context(threat: dict) -> dict:
    keys = (
        "affected_parameter",
        "mechanism_trace",
        "evidence_summary",
        "evidence_basis",
        "controls_in_place",
        "verification_contradicted",
        "evidence_review_unproven",
        "evidence_review_contradicted",
        "evidence",
        "instances",
        "scenario",
        "attack_steps",
        "boundary_refs",
    )
    return {key: bounded(threat[key]) for key in keys if threat.get(key) is not None}


_PLACEHOLDER = re.compile(r":\w+|\{\w+\}|<\w+>")
_RECORD_ID = re.compile(r"\d+|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")


def route_matches(template: str, path: str) -> bool:
    """Match literal route segments and one-segment placeholders, never a model regex."""
    try:
        expected, actual = urlsplit(template), urlsplit(path)
    except ValueError:
        return False
    if expected.netloc and expected.netloc != actual.netloc:
        return False
    a, b = expected.path.split("/"), actual.path.split("/")
    return len(a) == len(b) and all(
        x == y or (bool(y) and bool(_PLACEHOLDER.fullmatch(x))) for x, y in zip(a, b, strict=True)
    )


def record_segment(template: str, path: str | None = None) -> str | None:
    """The segment of a request path that names an existing record (VER-014): one at a placeholder of its route
    template, or one of digits or a UUID; None when it names none. Without `path`, the template's own."""
    try:
        expected = urlsplit(template).path.split("/")
        actual = urlsplit(path).path.split("/") if path is not None else expected
    except ValueError:
        return template if path is None else path
    for i, segment in enumerate(actual):
        if (i < len(expected) and _PLACEHOLDER.fullmatch(expected[i])) or _RECORD_ID.fullmatch(unquote(segment)):
            return segment
    return None


def missing_capabilities(variant: dict, *, safe: bool, browser: bool) -> list[str]:
    request = variant["request"]
    required = set(variant.get("required_capabilities", []))
    required.update(i["location"] for i in request.get("inputs", []))
    if request["method"] not in ("GET", "HEAD", "OPTIONS"):
        required.add("state-change")
    supported = {"query", "json", "form", "path"}
    if not safe:
        supported.add("state-change")
    if browser:
        supported.add("browser-navigation")
    missing = required - supported
    if request["method"] == "DELETE":
        missing.add("DELETE")
    return sorted(missing)
