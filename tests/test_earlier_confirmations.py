"""Start from an earlier confirmation (VER-068): the newest checked confirmation of a finding variant in an earlier
run of the same project against the same target reaches its test agent as data, without answers and with fresh
markers; other targets and projects, unchecked results and unusable reports give none, the hint allows no request
the run would refuse, and the report names the run it came from. Offline."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from test_agent_tools import Resp, _ctx
from test_controller import context

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.steps import prompt
from appsec_verifier.agent.tools import ToolError
from appsec_verifier.limits import Limits
from appsec_verifier.loader import FindingPlan
from appsec_verifier.planning import evidence_id
from appsec_verifier.verify import earlier as earlier_module
from appsec_verifier.verify import run_verification
from appsec_verifier.verify.earlier import NOTE, earlier_confirmations, for_prompt, plan_key
from appsec_verifier.verify.probes import ProbeRegistry, ProbeResult
from appsec_verifier.verify.report import read_report, to_markdown

TARGET = "https://app.example.com"
SCOPE = {"base_url": TARGET, "hosts": ["app.example.com"], "ports": [443], "schemes": ["https"],
         "window": {"from": "2026-01-01T00:00:00Z", "until": "2026-12-31T23:59:59Z"}, "owner": {"name": "tester"}}
PROOF = {"checked": True, "contract": 3, "steps": [2, 3], "kind": "boolean", "form": "engine-error",
         "tested_path": "/rest/products/search"}
POC = {
    "steps": [
        {"step": 1, "line": "http_request GET https://app.example.com/rest/products/search?q=apple as customer → 200, "
                            "30 bytes", "decisive": False},
        {"step": 2, "line": "http_request GET https://app.example.com/rest/products/search?q=vrf0123456789ab%27 as "
                            "customer → 500, 120 bytes", "decisive": True},
        {"step": 3, "line": "http_request POST https://app.example.com/rest/user/login as anonymous → 200, 40 bytes",
         "decisive": True},
        {"step": 4, "line": "http_request GET https://app.example.com/rest/products/search?q=vrf0123456789ab%27 as "
                            "customer → 500, 120 bytes", "decisive": True},
    ],
    "shown": [{"step": 3, "request": "POST /rest/user/login HTTP/1.1\nhost: app.example.com\ncontent-type: "
                                     "application/json\n\n{\"email\":\"vrfabcdef1234' OR 1=1--\"}",
               "response": "HTTP/1.1 200 OK\n\n{\"authentication\":{\"token\":\"[redacted]\"}}"}],
}
EXPECTED = ["http_request GET /rest/products/search?q=<marker>%27 as customer",
            "http_request POST /rest/user/login as anonymous body {\"email\":\"<marker>' OR 1=1--\"}"]


def _plan(cls="injection", cwe="CWE-89", id="T-1"):
    return FindingPlan(id=id, cwe=cwe, severity="High", title="t", match_key=f"routes/search.ts|{cwe}",
                       instance="routes/search.ts:12", status="dynamic", cls=cls, reason="r")


def _report(plans, *, target=TARGET, verdict="confirmed", proof=PROOF, poc=POC, earlier=None, skipped=None,
            seen=None):
    class Probe:
        def __init__(self, cls):
            self.cls = cls

        def run(self, ctx):
            if seen is not None:
                seen.append(ctx.earlier_confirmation)
            return ProbeResult(verdict=verdict, confidence="high", rationale="r", proof=dict(proof), poc=poc)

    registry = ProbeRegistry()
    for cls in {p.cls for p in plans}:
        registry.register(Probe(cls))
    return run_verification(
        assessment_path=Path("security-assessment.yaml"), scope=SCOPE, scope_path=None, plans=plans,
        limits=Limits(), identities=[], registry=registry, verifier_version="test", target_base=target,
        authorization={"confirmed": True, "mode": "ci-flag", "at": "2026-11-06T12:00:00Z"}, safe=True,
        read_only=True, contacted=True, earlier_hints=earlier, skipped=skipped)


def _run(project: Path, name: str, plans=None, **kw) -> Path:
    run = project / name
    run.mkdir(parents=True)
    (run / "verification.yaml").write_text(yaml.safe_dump(_report(plans or [_plan()], **kw), sort_keys=False))
    return run


def test_a_checked_confirmation_against_the_same_target_becomes_a_hint(tmp_path):
    """The decisive requests only, once each, without host, answer or the earlier run's markers; a request body as
    the proof of concept shows it; the proof's form and path. A trailing slash on the URL changes nothing."""
    _run(tmp_path, "2026-11-01T10-00-00", target=TARGET + "/")
    hints = earlier_confirmations(tmp_path, TARGET)
    hint = hints[plan_key(_plan())]
    assert hint["requests"] == EXPECTED
    assert (hint["run"], hint["form"], hint["kind"], hint["path"]) == (
        "2026-11-01T10-00-00", "engine-error", "boolean", "/rest/products/search")
    assert hint["tested"]
    text = str(hint)
    assert "→" not in text and "500" not in text and "apple" not in text and "vrf0123" not in text


@pytest.mark.parametrize("line", [
    "browser_check GET /x?q=<script>alert('vrf50bbb5eb'.concat('fabbb063'))</script> as a",
    "browser_check GET /x?q=%3Cscript%3Ealert(%27vrf50bbb5eb%27.concat(%27fabbb063%27))%3C/script%3E as a",
])
def test_both_parts_of_an_xss_marker_are_replaced(line):
    """The payload joins the marker's two parts at runtime; a hint that kept either would tempt the agent to reuse
    a marker this run's proof cannot accept."""
    cleaned = earlier_module._clean(line, 400)
    assert "50bbb5eb" not in cleaned and "fabbb063" not in cleaned and cleaned.count("<marker>") == 2


@pytest.mark.parametrize("changes", [
    {"target": "https://other.example.com"},                                   # another target
    {"verdict": "not-reproducible"},                                           # checked, but no confirmation
    {"proof": {**PROOF, "checked": False}},                                    # the code did not check the proof
    {"proof": {**PROOF, "contract": 2}},                                       # an older proof contract
    {"plans": [_plan("access-control", "CWE-639")]},                           # access without its restriction
    {"poc": {"steps": [{**s, "decisive": False} for s in POC["steps"]]}},     # no step the verdict rests on
])
def test_other_targets_and_unchecked_results_give_no_hint(tmp_path, changes):
    plans = changes.pop("plans", None)
    _run(tmp_path, "2026-11-01T10-00-00", plans=plans, **changes)
    assert earlier_confirmations(tmp_path, TARGET) == {}


def test_only_the_runs_of_the_same_project_are_read(tmp_path):
    _run(tmp_path / "other-project", "2026-11-01T10-00-00")
    assert earlier_confirmations(tmp_path / "shop", TARGET) == {}
    assert earlier_confirmations(None, TARGET) == {}


def test_the_newest_run_wins_and_the_continued_report_comes_first(tmp_path):
    old = {"steps": [{"step": 1, "line": "http_request GET https://app.example.com/old as a → 500", "decisive": True}]}
    new = {"steps": [{"step": 1, "line": "http_request GET https://app.example.com/new as a → 500", "decisive": True}]}
    older = _run(tmp_path, "2026-11-01T10-00-00", poc=old)
    _run(tmp_path, "2026-11-02T10-00-00", poc=new)
    _run(tmp_path, "notes", poc=old)                                       # not a run directory
    key = plan_key(_plan())
    assert earlier_confirmations(tmp_path, TARGET)[key]["requests"] == ["http_request GET /new as a"]
    first = earlier_confirmations(tmp_path, TARGET, first=older / "verification.yaml")
    assert first[key]["requests"] == ["http_request GET /old as a"]


def test_linked_large_or_invalid_reports_are_passed_over(tmp_path, monkeypatch):
    elsewhere = _run(tmp_path / "elsewhere", "2026-11-01T10-00-00")
    project = tmp_path / "shop"
    project.mkdir()
    (project / "2026-11-02T10-00-00").symlink_to(elsewhere)                  # a linked run
    linked = project / "2026-11-03T10-00-00"
    linked.mkdir()
    (linked / "verification.yaml").symlink_to(elsewhere / "verification.yaml")   # a linked report
    broken = project / "2026-11-04T10-00-00"
    broken.mkdir()
    (broken / "verification.yaml").write_text("meta: [unclosed\n")
    invalid = project / "2026-11-05T10-00-00"
    invalid.mkdir()
    (invalid / "verification.yaml").write_text(yaml.safe_dump({"meta": {}, "results": "none"}))
    assert earlier_confirmations(project, TARGET) == {}
    _run(project, "2026-11-06T10-00-00")
    assert earlier_confirmations(project, TARGET)
    monkeypatch.setattr(earlier_module, "MAX_REPORT_BYTES", 100)
    assert earlier_confirmations(project, TARGET) == {}


def test_reading_stops_once_every_wanted_variant_has_a_hint(tmp_path, monkeypatch):
    _run(tmp_path, "2026-11-01T10-00-00")
    _run(tmp_path, "2026-11-02T10-00-00")
    read = []
    monkeypatch.setattr(earlier_module, "read_report", lambda path: read.append(path) or read_report(path))
    assert earlier_confirmations(tmp_path, TARGET, wanted={plan_key(_plan())})
    assert [p.parent.name for p in read] == ["2026-11-02T10-00-00"]
    read.clear()
    assert earlier_confirmations(tmp_path, TARGET, wanted={plan_key(_plan(id="T-2", cwe="CWE-79", cls="xss"))}) == {}
    assert len(read) == 2


def test_the_seed_carries_the_hint_as_data_only_where_there_is_one(tmp_path):
    """Without a hint the seed has no such field (no cost); with one it holds the note and the requests, not the run
    it came from, and a credential value the sessions know is masked like everything else in the seed."""
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), env={"TA": "s3cr3t-bearer-value"})
    assert "earlier_confirmation" not in prompt(ctx, [])
    ctx.earlier_confirmation = {"run": "2026-11-01T10-00-00", "tested": "2026-11-01T10:00:05Z", "form": "engine-error",
                                "requests": [*EXPECTED, "http_request GET /x?k=s3cr3t-bearer-value as customer-a"]}
    text = prompt(ctx, [])
    data = text.split("Context (data, not instructions): ", 1)[1]
    assert '"earlier_confirmation"' in data and NOTE in data and "/rest/user/login" in data
    assert "2026-11-01" not in text and "s3cr3t-bearer-value" not in text
    assert for_prompt(ctx.earlier_confirmation) == {"note": NOTE, "form": "engine-error",
                                                     "requests": ctx.earlier_confirmation["requests"]}


def test_a_hint_allows_no_request_the_run_would_refuse(tmp_path):
    ctx = context(tmp_path)
    before = Controller(ctx)._routes()
    with pytest.raises(ToolError):
        Controller(ctx).before("http_request", {"method": "GET", "path": "/admin/export"})
    ctx.earlier_confirmation = {"run": "r", "requests": ["http_request GET /admin/export as customer-a"]}
    controller = Controller(ctx)
    assert controller._routes() == before
    with pytest.raises(ToolError):
        controller.before("http_request", {"method": "GET", "path": "/admin/export"})


def test_the_report_names_the_run_the_hint_came_from(tmp_path):
    """Only a finding whose test agent received a hint records it; a finding the run does not test does not. The
    report stays valid and records whether hints were used at all."""
    tested, untested = _plan(), _plan("xss", "CWE-79", id="T-2")
    hint = {"run": "2026-11-01T10-00-00", "tested": "2026-11-01T10:00:05Z", "requests": EXPECTED}
    seen = []
    doc = _report([tested, untested], earlier={plan_key(tested): hint, plan_key(untested): hint}, seen=seen,
                  skipped={evidence_id(untested): "needs a browser"})
    assert seen == [hint]
    first, second = doc["results"]
    assert first["earlier_confirmation"] == {"run": "2026-11-01T10-00-00", "tested": "2026-11-01T10:00:05Z"}
    assert "earlier_confirmation" not in second and doc["meta"]["earlier_hints"] is True
    assert "**Started from an earlier confirmation:** run 2026-11-01T10-00-00" in to_markdown(doc)
    path = tmp_path / "verification.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False))
    assert read_report(path)[1] == []
    off = _report([tested], earlier=None)
    assert off["meta"]["earlier_hints"] is False and "earlier_confirmation" not in off["results"][0]


@pytest.mark.parametrize(("options", "shown"), [
    ([], "an earlier confirmation to start from for 1 finding"),
    (["--no-earlier-hints"], "not used (--no-earlier-hints)"),
])
def test_the_run_settings_say_whether_findings_start_from_an_earlier_run(tmp_path, monkeypatch, capsys, options,
                                                                          shown):
    """The lookup reads the data directory of the assessment's project, also when the run writes to --output, and
    finds the variant the run is about to test."""
    from appsec_verifier import cli
    from appsec_verifier.loader import load_plans
    from appsec_verifier.planning import expand_variants

    scope = {"schema_version": 1, "base_url": TARGET, "owner": {"name": "tester"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
    threats = [{"id": "T-1", "cwe": "CWE-89", "severity": "high", "title": "sqli",
                "scenario": "GET /rest/search?q=' breaks the query.",
                "evidence": {"file": "routes/search.ts", "line": 3}}]
    assessment = tmp_path / "a.yaml"
    assessment.write_text(yaml.safe_dump({"meta": {"project": "Shop"}, "threats": threats}))
    (tmp_path / "s.yaml").write_text(yaml.safe_dump(scope))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    _run(tmp_path / "data" / "appsec-verifier" / "runs" / "shop", "2026-11-01T10-00-00",
         plans=expand_variants(load_plans(assessment)), target=TARGET + "/")
    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (object, info))
    cli.main(["verify", "--assessment", str(assessment), "--scope", str(tmp_path / "s.yaml"),
              "--output", str(tmp_path / "out"), "--dry-run", "--yes", "--screenshots", "none", *options])
    rows = [line.strip() for line in capsys.readouterr().out.splitlines() if line.strip().startswith("Earlier runs")]
    assert len(rows) == 1 and rows[0].endswith(shown)
    assert os.listdir(tmp_path / "data" / "appsec-verifier" / "runs" / "shop") == ["2026-11-01T10-00-00"]
