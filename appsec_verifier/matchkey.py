"""Cross-run stable finding identity, recomputed the way AppSec Analyzer does
its changelog delta: ``<normalized-file>|<cwe-family>`` (VER-007).

The file path — the one signal derived from source, not model phrasing — anchors
identity; a narrow CWE "family" absorbs the few CWE swaps the Analyzer observed
for the same finding. This mirrors `_match_key` and `_CWE_FAMILIES` in the
Analyzer's `scripts/model/build_threat_model_yaml.py` (`MATCH_KEY_VERSION` 2),
the reference, so the Verifier's key equals the Analyzer's for the same finding.
One deliberate difference: a finding without an evidence file gets no key here
(input-incomplete, VER-006) instead of the Analyzer's fallback fingerprint.
"""

from __future__ import annotations

# Only CWEs the Analyzer observed to swap for the SAME finding. Kept identical to
# the Analyzer's table so keys match across tools. Unlisted CWEs map to themselves.
_CWE_FAMILIES: dict[str, str] = {
    "CWE-798": "hardcoded-key", "CWE-321": "hardcoded-key", "CWE-320": "hardcoded-key",
    "CWE-312": "hardcoded-key", "CWE-522": "hardcoded-key",
    "CWE-256": "password-weak", "CWE-257": "password-weak", "CWE-259": "password-weak",
    "CWE-261": "password-weak", "CWE-916": "password-weak",
    "CWE-347": "sig-verify", "CWE-345": "sig-verify", "CWE-295": "sig-verify", "CWE-924": "sig-verify",
    "CWE-400": "resource-exhaustion", "CWE-770": "resource-exhaustion",
    "CWE-405": "resource-exhaustion", "CWE-1333": "resource-exhaustion",
    "CWE-94": "code-eval", "CWE-95": "code-eval",
}


def cwe_family(cwe: str) -> str:
    return _CWE_FAMILIES.get((cwe or "").strip().upper(), (cwe or "").strip().upper())


def norm_file(path: str) -> str:
    """Lowercased, leading-``./``-stripped path, for stable cross-run comparison."""
    raw = (path or "").strip()
    while raw.startswith("./"):
        raw = raw[2:]
    return raw.strip().lower()


def _anchor_file(threat: dict) -> str:
    insts = threat.get("instances")
    if isinstance(insts, list):
        for i in insts:
            if isinstance(i, dict) and i.get("file"):
                return norm_file(i["file"])
    ev = threat.get("evidence")
    if isinstance(ev, list):
        ev = next((e for e in ev if isinstance(e, dict)), {})
    elif not isinstance(ev, dict):
        ev = {}
    return norm_file(ev.get("file") or "")


def match_key(threat: dict) -> str | None:
    """``<file>|<cwe-family>`` for a threat, or None when it has no evidence file
    (such a finding is input-incomplete for dynamic verification, VER-006)."""
    f = _anchor_file(threat)
    if not f:
        return None
    return f"{f}|{cwe_family(threat.get('cwe') or '')}"
