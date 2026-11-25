"""VER-007: an assessment of several repositories (the Analyzer's schema version 2) names each location's file
relative to its repository and the repository by `repository_id`. The Verifier reads it as `<label>/<file>`, as the
Analyzer's report, route inventory and change keys do, so findings in files of the same name stay apart."""

from __future__ import annotations

from dataclasses import replace

import pytest
import yaml
from test_agent_tools import Resp, _ctx
from test_report import _doc

from appsec_verifier.agent.derivation import source_registrations
from appsec_verifier.agent.source_reader import SourceReader
from appsec_verifier.loader import load_plans, plans_from, repository_labels
from appsec_verifier.verify.report import annotate_assessment

RID_A, RID_B = "repo-" + "a" * 16, "repo-" + "b" * 16


def _assessment(*threats, labels=("orders-api", "user-service"), surface=()):
    repos = [{"repository_id": rid, "label": label} for rid, label in zip((RID_A, RID_B), labels, strict=True)]
    return {"meta": {"schema_version": 2, "project": "shop"},
            "source_inventory": {"schema_version": 2, "repositories": repos},
            "attack_surface": list(surface), "threats": list(threats)}


def _finding(tid, rid, cwe="CWE-89", file="app.py", line=42):
    return {"id": tid, "cwe": cwe,
            "evidence": [{"repository_id": rid, "file": file, "line": line, "sha256": "0" * 64}]}


def test_findings_in_files_of_the_same_name_in_two_repositories_stay_apart():
    a, b = plans_from(_assessment(_finding("T-001", RID_A), _finding("T-002", RID_B)))
    # The Analyzer's own change keys for these two findings.
    assert (a.match_key, b.match_key) == ("orders-api/app.py|CWE-89", "user-service/app.py|CWE-89")
    assert (a.instance, b.instance) == ("orders-api/app.py:42", "user-service/app.py:42")


def test_the_test_plan_names_the_repository_of_each_finding():
    from appsec_verifier import cli

    plans = plans_from(_assessment(_finding("T-001", RID_A), _finding("T-002", RID_B)))
    assert [p.repository for p in plans] == ["orders-api", "user-service"]
    rows = [line for line in cli._test_cases(cli.Style(False), plans, {}) if line.lstrip().startswith("T-00")]
    assert "· orders-api ·" in rows[0] and "· user-service ·" in rows[1]


def test_an_assessment_read_from_its_file_is_qualified_once(tmp_path):
    path = tmp_path / "appsec-assessment.yaml"
    path.write_text(yaml.safe_dump(_assessment(_finding("T-001", RID_A))))
    plan, = load_plans(path)
    assert plan.instance == "orders-api/app.py:42"


def test_an_assessment_of_one_repository_keeps_its_paths():
    plan, = plans_from({"meta": {"schema_version": 1}, "threats": [
        {"id": "T-001", "cwe": "CWE-89", "evidence": [{"file": "app.py", "line": 42}]}]})
    assert (plan.match_key, plan.instance, plan.repository) == ("app.py|CWE-89", "app.py:42", None)


@pytest.mark.parametrize("labels", [("../etc", "user-service"), ("a/b", "user-service"), (".git", "user-service"),
                                    ("", "user-service"), ("a\\b", "user-service"), ("x\x1b[31m", "user-service"),
                                    ("orders-api", "orders-api")])
def test_a_location_under_an_unusable_label_locates_nothing(labels):
    """Refused cases: a label that is no plain directory name, or that names two repositories, never becomes part of a
    path; the finding is input-incomplete instead of being placed in another repository."""
    plan, = plans_from(_assessment(_finding("T-001", RID_A), labels=labels))
    assert plan.status == "input-incomplete" and plan.instance is None and plan.match_key is None
    assert RID_A not in repository_labels(_assessment(labels=labels))


def test_a_location_of_an_unlisted_repository_locates_nothing():
    plan, = plans_from(_assessment(_finding("T-001", "repo-" + "c" * 16)))
    assert plan.status == "input-incomplete"


def test_the_route_inventory_gives_each_finding_the_route_of_its_own_repository():
    """The Analyzer writes a handler as `<label>/<file>:<line>` in the route inventory's notes."""
    surface = [{"entry_point": "GET /api/orders/:id", "protocol": "HTTP", "auth_required": True,
                "notes": "handler: orders-api/app.py:42"},
               {"entry_point": "GET /api/users/:id", "protocol": "HTTP", "auth_required": True,
                "notes": "handler: user-service/app.py:42"}]
    a, b = plans_from(_assessment(_finding("T-001", RID_A, cwe="CWE-639"), _finding("T-002", RID_B, cwe="CWE-639"),
                                  surface=surface))
    assert [(e.method, e.path) for e in a.endpoints] == [("GET", "/api/orders/:id")]
    assert [(e.method, e.path) for e in b.endpoints] == [("GET", "/api/users/:id")]


PAYMENT = ("export function getPaymentMethods () { return async (req, res) => res.json([]) }\n"
           "export function getPaymentMethodById () { return async (req, res) => res.json({}) }\n")


def _service(root, label, route):
    (root / label / "routes").mkdir(parents=True)
    (root / label / "routes" / "payment.ts").write_text(PAYMENT)
    (root / label / "server.ts").write_text(
        "import * as payment from './routes/payment'\n"
        f"app.get('{route}', security.appendUserId(), utils.asyncHandler(payment.getPaymentMethodById()))\n")


def test_a_route_is_resolved_in_the_findings_own_checkout(tmp_path):
    """VER-008 with a directory that holds each checkout under its label: the finding's own service supplies the
    route, and the file of the same name in the other service is not credited."""
    system = tmp_path / "system"
    _service(system, "orders-api", "/api/Cards/:id")
    _service(system, "user-service", "/users/cards/:id")
    plan, = plans_from(_assessment(_finding("T-010", RID_A, cwe="CWE-639", file="routes/payment.ts", line=2)))
    ctx = _ctx(tmp_path, lambda *a, **k: Resp())
    ctx.plan = replace(ctx.plan, instance=plan.instance, endpoints=())
    ctx.source = SourceReader(system)
    assert [(r["method"], r["path"], r["source_file"]) for r in source_registrations(ctx)] == [
        ("GET", "/api/Cards/:id", "orders-api/server.ts")]


def test_a_result_finds_its_finding_by_the_key_that_names_the_repository():
    """A regenerated assessment numbers its findings anew: the result of T-900 belongs to the orders-api finding only,
    and the annotated copy keeps the Analyzer's locations."""
    doc = _doc()
    doc["results"][0]["finding_ref"].update(id="T-900", match_key="orders-api/app.py|CWE-89",
                                            instance="orders-api/app.py:42")
    assessment = _assessment(_finding("T-001", RID_A), _finding("T-002", RID_B))
    out = annotate_assessment(assessment, doc, verification_report="v.yaml")
    a, b = out["threats"]
    assert a["dynamic_verification"]["result_ref"] == doc["results"][0]["result_id"]
    assert "dynamic_verification" not in b
    assert a["evidence"] == assessment["threats"][0]["evidence"]
