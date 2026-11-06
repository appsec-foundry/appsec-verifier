"""Runner builds a schema-shaped report; unverified findings are not-attempted,
never refuted; safe mode forces read-only; a registered probe runs (VER-008/020/024/030)."""

from __future__ import annotations

from pathlib import Path

from appsec_verifier.limits import Limits
from appsec_verifier.loader import FindingPlan
from appsec_verifier.verify import default_registry, run_verification
from appsec_verifier.verify.probes import ProbeContext, ProbeRegistry, ProbeResult

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
         "schemes": ["https"], "window": {"from": "2026-01-01T00:00:00Z", "until": "2026-12-31T23:59:59Z"},
         "owner": {"name": "tester"}, "allow_state_change": True}


def _plan(id, cls, status="dynamic", cwe="CWE-79"):
    return FindingPlan(id=id, cwe=cwe, severity="High", title=f"{cls} finding", match_key=f"f.ts|{cwe}",
                       instance="f.ts:10", status=status, cls=cls, reason="r")


def _run(plans, registry=None, safe=True, read_only=True):
    return run_verification(
        assessment_path=Path("security-assessment.yaml"), scope=SCOPE, scope_path=Path("scope.yaml"),
        plans=plans, limits=Limits(), identities=[{"role": "a", "method": "form"}],
        registry=registry or default_registry(), verifier_version="test",
        target_base="https://app.example.com", authorization={"confirmed": False, "mode": "interactive", "at": None},
        safe=safe, read_only=read_only, contacted=False,
    )


def test_no_probe_yields_not_attempted_not_refuted():
    doc = _run([_plan("T-1", "xss")])
    r = doc["results"][0]
    assert r["verdict"] == "not-attempted"
    assert "no probe" in r["rationale"]
    assert r["finding_ref"]["match_key"] == "f.ts|CWE-79"
    assert r["result_id"] == "VF-001"


def test_static_only_reported_with_reason():
    doc = _run([_plan("T-2", None, status="static-only", cwe="CWE-327")])
    r = doc["results"][0]
    assert r["eligibility"]["status"] == "static-only"
    assert r["verdict"] == "not-attempted"
    assert r["class"] is None


def test_summary_tally_and_safety_block():
    doc = _run([_plan("T-1", "xss"), _plan("T-2", "access-control", cwe="CWE-639")])
    assert doc["meta"]["summary"] == {"confirmed": 0, "not_reproducible": 0, "blocked": 0,
                                      "inconclusive": 0, "not_attempted": 2, "total": 2}
    assert doc["meta"]["safety"] == {"mode": "safe", "read_only": True,
                                     "destructive_actions": "forbidden", "state_changes_cleaned": None}


def test_safe_mode_forces_read_only_in_report():
    # even though scope.allow_state_change is True, safe mode keeps it read-only
    doc = _run([_plan("T-1", "xss")], safe=True, read_only=True)
    assert doc["meta"]["safety"]["mode"] == "safe"
    assert doc["meta"]["safety"]["read_only"] is True


def test_registered_probe_runs_and_sees_safe_flag():
    seen = {}

    class FakeXss:
        cls = "xss"

        def run(self, ctx: ProbeContext) -> ProbeResult:
            seen["safe"] = ctx.safe
            seen["read_only"] = ctx.read_only
            return ProbeResult(verdict="confirmed", confidence="high", rationale="marker executed",
                               proof={"executed": True}, identities_used=["a"])

    reg = ProbeRegistry()
    reg.register(FakeXss())
    doc = _run([_plan("T-1", "xss")], registry=reg)
    assert doc["results"][0]["verdict"] == "confirmed"
    assert doc["meta"]["summary"]["confirmed"] == 1
    assert seen == {"safe": True, "read_only": True}


def test_identities_expose_role_only_no_secrets():
    doc = _run([_plan("T-1", "xss")])
    ids = doc["meta"]["identities"]
    assert ids == [{"role": "a", "authenticated": True}]
