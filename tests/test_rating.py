"""Rating after verification (VER-039): fixed rules, only on a checked proof, impact never changes."""

from __future__ import annotations

import pytest

from appsec_verifier.verify.rating import rate


def _threat(likelihood="Medium", impact="High", severity="High", **extra):
    return {"likelihood": likelihood, "impact": impact, "risk": severity, "effective_severity": severity, **extra}


def test_confirmed_raises_a_likelihood_below_high_and_the_severity_one_level():
    r = rate(_threat(), "confirmed", True)
    assert r["changed"] is True
    assert r["analyzer"] == {"likelihood": "Medium", "impact": "High", "severity": "High"}
    assert r["after_verification"] == {"likelihood": "High", "impact": "High", "severity": "Critical"}
    assert "likelihood Medium → High" in r["reason"] and "severity High → Critical" in r["reason"]


@pytest.mark.parametrize("likelihood", ["High", "Critical"])
def test_confirmed_changes_nothing_when_the_exploit_was_already_assumed(likelihood):
    r = rate(_threat(likelihood=likelihood), "confirmed", True)
    assert r["changed"] is False and r["after_verification"] == r["analyzer"]


def test_confirmed_never_goes_above_critical():
    r = rate(_threat(likelihood="Low", severity="Critical"), "confirmed", True)
    assert r["after_verification"]["severity"] == "Critical" and r["after_verification"]["likelihood"] == "High"


def test_a_block_lowers_likelihood_and_severity_one_level_each():
    r = rate(_threat(likelihood="High", severity="Critical"), "blocked-by-control", True)
    assert r["after_verification"] == {"likelihood": "Medium", "impact": "High", "severity": "High"}
    assert "tested requests only" in r["reason"]


def test_a_block_never_goes_below_informational():
    r = rate(_threat(likelihood="Informational", severity="Low"), "blocked-by-control", True)
    after = r["after_verification"]
    assert after["likelihood"] == "Informational" and after["severity"] == "Informational"
    lowest = rate(_threat(likelihood="Informational", severity="Informational"), "blocked-by-control", True)
    assert lowest["changed"] is False


@pytest.mark.parametrize("verdict", ["confirmed", "blocked-by-control"])
def test_nothing_changes_without_a_checked_proof(verdict):
    r = rate(_threat(likelihood="Low"), verdict, False)
    assert r["changed"] is False and r["reason"] == "no checked proof"


@pytest.mark.parametrize("verdict", ["not-reproducible", "inconclusive", "not-attempted", None])
def test_other_verdicts_change_nothing(verdict):
    assert rate(_threat(likelihood="Low"), verdict, True)["changed"] is False


@pytest.mark.parametrize("threat", [
    {"risk": "High"},                                            # no likelihood
    {"likelihood": "Medium"},                                    # no severity
    {"likelihood": "probable", "risk": "High"},                  # not one of the Analyzer's levels
    {"likelihood": ["High"], "risk": "High"},
])
def test_a_threat_the_rules_cannot_read_is_not_rated(threat):
    r = rate(threat, "confirmed", True)
    assert r["changed"] is False and "no likelihood or severity" in r["reason"]


def test_impact_never_changes_and_severity_falls_back_to_risk():
    r = rate({"likelihood": "low", "impact": "Low", "risk": "medium"}, "confirmed", True)
    assert r["analyzer"]["severity"] == "medium"
    assert r["after_verification"] == {"likelihood": "High", "impact": "Low", "severity": "High"}
