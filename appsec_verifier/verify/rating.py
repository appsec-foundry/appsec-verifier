"""Rating after verification (VER-039): fixed rules applied in code, never the model's judgement.

A rating changes only on a verdict whose proof check passed (VER-013):

- confirmed: a likelihood below High becomes High and the severity rises one level; a likelihood of High
  or Critical already assumes the exploit, so nothing changes;
- blocked by a control: likelihood and severity each fall one level;
- any other verdict, or no checked proof: nothing changes.

Impact never changes. Severity is the Analyzer's `effective_severity`, else its `risk`; its own rating stays
as it is and is repeated next to the rating after verification. The level names are those of AppSec
Analyzer's `threats[].likelihood`, `impact` and `risk` (schemas/threat-model.output.schema.yaml). A threat
whose likelihood or severity is not one of them is not rated.
"""

from __future__ import annotations

LEVELS = ("Informational", "Low", "Medium", "High", "Critical")
_RANK = {name.lower(): i for i, name in enumerate(LEVELS)}
_HIGH = _RANK["high"]


def _level(value) -> int | None:
    return _RANK.get(str(value).strip().lower()) if isinstance(value, str) else None


def rate(threat: dict, verdict: str | None, checked: bool) -> dict:
    """The rating after verification of one threat, given its verdict and whether its proof check passed."""
    analyzer = {"likelihood": threat.get("likelihood"), "impact": threat.get("impact"),
                "severity": threat.get("effective_severity") or threat.get("risk")}
    likelihood, severity = _level(analyzer["likelihood"]), _level(analyzer["severity"])

    def unchanged(reason: str) -> dict:
        return {"analyzer": analyzer, "after_verification": dict(analyzer), "changed": False, "reason": reason}

    if verdict not in ("confirmed", "blocked-by-control"):
        return unchanged(f"the verdict {verdict or 'none'} does not change the rating")
    if not checked:
        return unchanged("no checked proof")
    if likelihood is None or severity is None:
        return unchanged("the assessment gives no likelihood or severity the rules can use")
    if verdict == "confirmed":
        if likelihood >= _HIGH:
            return unchanged("confirmed; the likelihood was already High or above")
        new_likelihood, new_severity = _HIGH, min(severity + 1, len(LEVELS) - 1)
        why = "confirmed with a checked proof"
    else:
        if likelihood == 0 and severity == 0:
            return unchanged("blocked by a control; the rating is already at its lowest level")
        new_likelihood, new_severity = max(likelihood - 1, 0), max(severity - 1, 0)
        why = "blocked by a control with a checked proof, for the tested requests only"
    after = {"likelihood": LEVELS[new_likelihood], "impact": analyzer["impact"], "severity": LEVELS[new_severity]}
    steps = [f"{name} {LEVELS[old]} → {after[name]}" for name, old in (("likelihood", likelihood),
                                                                      ("severity", severity))
             if LEVELS[old] != after[name]]
    return {"analyzer": analyzer, "after_verification": after, "changed": True,
            "reason": f"{why}: {', '.join(steps)}"}
