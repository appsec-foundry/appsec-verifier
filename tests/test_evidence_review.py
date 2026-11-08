"""VER-042: bounded per-finding review, exact recorded quotes, no testing authority."""

from __future__ import annotations

import copy
import io
import json
import struct
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from jsonschema import Draft202012Validator
from test_runner import _plan, _run

from appsec_verifier.agent.hosts import HostPlanner, HostReply
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.progress import RunProgress
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.verify.evidence_review import (
    REVIEW_SCHEMA,
    REVISION_SCHEMA,
    _images,
    presentation_document,
    review_finding,
)
from appsec_verifier.verify.probes import ProbeContext, ProbeRegistry, ProbeResult
from appsec_verifier.verify.report import _poc_markdown

CLEAR = {"status": "clear", "issues": []}
SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443], "schemes": ["https"]}


def issue(code="comparison", variant="T-1", detail="Explain the contrast between the two roles."):
    return {"status": "needs-attention", "issues": [{"variant": variant, "code": code, "detail": detail}]}


def revision(text="The recorded response contains the test marker.", quote="marker"):
    return {"explanation": text, "quotes": [{"step": 1, "part": "response", "text": quote}]}


class Host:
    label = "offline fake"
    broken = None

    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def call(self, system, prompt, timeout, budget, *, schema):
        self.calls.append((system, json.loads(prompt), schema))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply if isinstance(reply, HostReply) else HostReply(step=reply, usd=0.01)


class Planner(HostPlanner):
    def __init__(self, host):
        super().__init__(host)
        self.requests = []

    def structured(self, ctx, system, payload, schema):
        self.requests.append((ctx, json.loads(payload)))
        return super().structured(ctx, system, payload, schema)


def pair(replies, *, name="T-1", limits=None):
    host = Host(replies)
    original, reviewers = Planner(host), []

    def factory():
        reviewers.append(Planner(host))
        return reviewers[-1]

    ctx = ProbeContext(
        plan=_plan(name, "xss"),
        scope=SCOPE.copy(),
        guard=ScopeGuard(SCOPE),
        budget=RunBudget(limits or Limits()),
        http=None,
        identities=[],
        callback={},
        evidence_test_planner=original,
        evidence_reviewer_factory=factory,
    )
    res = ProbeResult(
        "confirmed",
        confidence="high",
        rationale="marker executed",
        proof={"checked": True, "executed": True},
        poc={
            "file": "evidence/T-1.har",
            "steps": [{"step": 1, "line": "GET /x", "decisive": True}],
            "shown": [{"step": 1, "request": "GET /x HTTP/1.1", "response": "HTTP/1.1 200 OK\nmarker"}],
        },
    )
    return ctx, res, host, original, reviewers


def test_clear_review_needs_one_call_and_never_changes_technical_result():
    ctx, res, host, original, reviewers = pair([CLEAR])
    before = copy.deepcopy(res)
    assert review_finding([(ctx, res)]) is None
    assert len(host.calls) == 1 and not original.requests and len(reviewers) == 1
    assert res.evidence_review["status"] == "clear" and res.evidence_review["rounds"] == 0
    assert res.evidence_review["visual_review"] == "not-performed"
    assert replace(res, evidence_review=None) == before
    assert ctx.budget.calls == 1 and ctx.budget.cost == 0.01 and ctx.budget.requests == 0


def test_feedback_returns_to_original_planner_then_independent_reviewer():
    ctx, res, host, original, reviewers = pair([issue(), revision(), CLEAR])
    review_finding([(ctx, res)])
    assert len(host.calls) == 3 and len(original.requests) == 1 and len(reviewers[0].requests) == 2
    assert original.requests[0][0] is ctx
    assert original.requests[0][1]["feedback"] == issue()["issues"]
    assert reviewers[0].requests[1][1]["variants"][0]["presentation"] == revision()
    assert res.evidence_review["status"] == "clear" and res.evidence_review["rounds"] == 1
    assert res.proof == {"checked": True, "executed": True}


def test_two_rounds_and_five_calls_are_shared_by_all_variants():
    ctx, res, host, first, reviewers = pair(
        [
            issue(),
            revision(),
            issue("context", "T-1-ab"),
            revision("Clarified second variant."),
            issue("excerpt", "T-1-ab"),
        ]
    )
    ctx2 = replace(ctx, plan=replace(ctx.plan, variant_digest="ab"), evidence_test_planner=Planner(host))
    res2 = copy.deepcopy(res)
    review_finding([(ctx, res), (ctx2, res2)])
    assert len(host.calls) == 5 and ctx.budget.calls == 5
    assert len(first.requests) == 1 and len(ctx2.evidence_test_planner.requests) == 1
    assert len(reviewers) == 1 and len(reviewers[0].requests) == 3
    assert res.evidence_review == res2.evidence_review
    assert res.evidence_review["rounds"] == 2 and res.evidence_review["status"] == "needs-attention"
    assert "Two correction" in res.evidence_review["reason"]


def test_repeated_issue_category_stops_even_if_model_rephrases_it():
    ctx, res, host, *_ = pair([issue(), revision(), issue(detail="Same comparison still needs explanation.")])
    review_finding([(ctx, res)])
    assert len(host.calls) == 3 and res.evidence_review["rounds"] == 1
    assert "Repeated issues" in res.evidence_review["reason"]


@pytest.mark.parametrize(
    "bad",
    [
        {"action": "http_request", "args_json": '{"path":"/new"}'},
        {**revision(), "verdict": "not-reproducible"},
        revision(quote="invented evidence"),
        {"explanation": "new", "quotes": [{"step": 99, "part": "response", "text": "marker"}]},
        {"explanation": "new", "quotes": [{"step": 1, "part": "body", "text": "marker"}]},
    ],
)
def test_invalid_revision_is_rejected_without_actions_or_changed_proof(bad):
    ctx, res, host, *_ = pair([issue(), bad])
    review_finding([(ctx, res)])
    assert res.evidence_review["status"] == "stopped"
    assert not res.evidence_review["presentations"]
    assert res.verdict == "confirmed" and ctx.budget.requests == 0 and len(host.calls) == 2


@pytest.mark.parametrize(
    "bad",
    [
        issue(variant="T-OTHER"),
        {"status": "clear", "issues": issue()["issues"]},
        {**CLEAR, "tool": "shell"},
        '{"status":"clear","status":"clear","issues":[]}',
    ],
)
def test_invalid_review_is_not_accepted(bad):
    ctx, res, host, *_ = pair([bad])
    review_finding([(ctx, res)])
    assert res.evidence_review["status"] == "stopped" and len(host.calls) == 1


def test_quote_from_another_variant_is_not_accepted():
    ctx, res, host, *_ = pair([issue(), revision(quote="other variant")])
    ctx2 = replace(ctx, plan=replace(ctx.plan, variant_digest="ab"), evidence_test_planner=Planner(host))
    res2 = copy.deepcopy(res)
    res2.poc["shown"][0]["response"] = "other variant"
    review_finding([(ctx, res), (ctx2, res2)])
    assert res.evidence_review["status"] == "stopped" and not res.evidence_review["presentations"]


@pytest.mark.parametrize(
    "lim,expected,calls", [(Limits(max_calls=1), "calls", 1), (Limits(cost_limit_usd=0.005), "cost", 1)]
)
def test_budget_stops_review_without_overwriting_technical_verdict(lim, expected, calls):
    ctx, res, host, *_ = pair([issue(), revision()], limits=lim)
    assert review_finding([(ctx, res)]) == expected
    assert res.evidence_review["status"] == "stopped" and res.verdict == "confirmed"
    assert len(host.calls) == calls and res.limits_hit is None


@pytest.mark.parametrize("kind", ["time", "window"])
def test_expired_time_or_authorization_prevents_review_call(kind):
    ctx, res, host, *_ = pair([CLEAR])
    if kind == "time":
        ctx.budget = RunBudget(Limits(max_duration_s=1), clock=lambda: 2)
        ctx.budget.start = 0
    else:
        ctx.guard = ScopeGuard({**SCOPE, "window": {"until": "2000-01-01T00:00:00Z"}})
    assert review_finding([(ctx, res)]) == kind
    assert not host.calls and res.verdict == "confirmed"


def test_interrupt_retains_result_and_previous_unresolved_feedback():
    ctx, res, host, *_ = pair([issue(), revision(), KeyboardInterrupt()])
    assert review_finding([(ctx, res)]) == "interrupted"
    assert res.verdict == "confirmed" and res.evidence_review["issues"] == issue()["issues"]


def test_host_confinement_breach_prevents_further_review_and_test_calls():
    ctx, res, host, *_ = pair([HostReply(breach="tool use", usd=0.01)])
    review_finding([(ctx, res)])
    review_finding([(ctx, res)])
    assert host.broken == "tool use" and len(host.calls) == 1
    assert res.evidence_review["status"] == "stopped" and ctx.budget.cost == 0.01


def test_no_reviewer_is_explicit_and_skipped_findings_have_no_review():
    ctx, res, host, *_ = pair([CLEAR])
    ctx.evidence_reviewer_factory = None
    review_finding([(ctx, res)])
    assert res.evidence_review["status"] == "not-reviewed" and not host.calls
    assert _run([_plan("T-1", "xss")])["results"][0]["evidence_review"] is None


def test_model_packets_exclude_credentials_marker_file_and_image_pixels():
    ctx, res, host, *_ = pair([issue(), revision(), CLEAR])
    ctx.sessions = SimpleNamespace(redact=lambda x: json.loads(json.dumps(x).replace("test-credential", "[redacted]")))
    ctx.scope["marker_file"] = {"content": "private-marker-content"}
    res.rationale += " test-credential private-marker-content"
    res.poc["shown"][0]["response"] += " test-credential private-marker-content"
    ctx.evidence_panels = [{"text": "private-marker-content test-credential", "body_font_px": 16}]
    review_finding([(ctx, res)])
    wire = json.dumps(host.calls)
    assert "private-marker-content" not in wire and "test-credential" not in wire
    assert "[marker-file]" in wire and "[redacted]" in wire
    assert "base64" not in wire and "image_url" not in wire
    assert all(c[1].get("variants", [{}])[0].get("image_pixels_reviewed", False) is False for c in host.calls)


def png(path, width=1200, height=700):
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + struct.pack(">II", width, height))


def test_dimensions_are_independent_of_model_opinion_and_paths_are_confined(tmp_path):
    ctx, res, host, *_ = pair([CLEAR, revision(), CLEAR])
    ctx.evidence_dir = tmp_path / "evidence"
    ctx.evidence_dir.mkdir()
    png(ctx.evidence_dir / "tall.png", height=4000)
    res.evidence = [{"kind": "screenshot", "path": "evidence/tall.png"}]
    review_finding([(ctx, res)])
    assert res.evidence_review["status"] == "needs-attention"
    assert res.evidence_review["issues"][0]["code"] == "readability"
    outside = tmp_path / "outside.png"
    png(outside)
    (ctx.evidence_dir / "link.png").symlink_to(outside)
    for path in ["../outside.png", str(outside), "evidence/../outside.png", "evidence/link.png"]:
        res.evidence = [{"kind": "screenshot", "path": path}]
        assert _images(ctx, res)[0]["available"] is False


def test_revision_render_uses_existing_quotes_and_keeps_original_evidence(tmp_path):
    ctx, res, host, *_ = pair([issue(), revision(quote="<script>"), CLEAR])
    res.poc["shown"][0]["response"] += "<script>"
    pages = []

    def render(**kwargs):
        pages.append(kwargs["html"])
        return [{"kind": "screenshot", "path": "evidence/explanation.png", "redacted": True}]

    ctx.browser = SimpleNamespace(screenshots={"xss"}, render_exchanges=render)
    ctx.evidence_dir = tmp_path
    png(tmp_path / "explanation.png")
    res.evidence = [{"kind": "har", "path": "evidence/original.har"}]
    review_finding([(ctx, res)])
    assert len(pages) == 1 and "&lt;script&gt;" in pages[0] and "<script>" not in pages[0]
    assert res.evidence[0] == {"kind": "har", "path": "evidence/original.har"}
    assert res.evidence[1]["presentation_review"] and ctx.budget.requests == 0
    assert res.evidence_review["status"] == "clear"


def test_report_fences_untrusted_explanation_and_console_shows_rounds():
    ctx, res, host, *_ = pair([issue(), revision("```\n<script>unsafe()</script>"), CLEAR])
    stream = io.StringIO()
    progress = RunProgress(stream=stream)
    ctx.progress = progress
    try:
        review_finding([(ctx, res)])
    finally:
        progress.close()
    text = stream.getvalue()
    assert all(word in text for word in ("review", "revise", "quality", "T-1", "1/2", "image pixels"))
    report = "\n".join(_poc_markdown({"evidence_review": res.evidence_review}))
    assert "````text" in report and "Image pixels were not inspected" in report
    assert "Technical verdict unchanged" in report and "not additional proof" in report


def test_runner_groups_variants_and_report_matches_schema():
    ctx, _, host, _, reviewers = pair([CLEAR, issue(), revision(), CLEAR])
    agents = []

    class Probe:
        def run(self, actual):
            agents.append(Planner(host))
            actual.evidence_test_planner = agents[-1]
            actual.evidence_reviewer_factory = ctx.evidence_reviewer_factory
            return pair([])[1]

    a = _plan("T-1", "xss")
    b = replace(a, variant_digest="ab")
    doc = _run([a, _plan("T-2", "xss"), b], registry=ProbeRegistry({"xss": Probe()}))
    # T-2 finishes before the second T-1 variant, so its review is first.
    # Give it the clear response and reserve corrections for the grouped T-1.
    assert len(reviewers) == 2 and len(host.calls) == 4
    assert len(agents[0].requests) == 1 and not agents[1].requests and not agents[2].requests
    assert doc["results"][0]["evidence_review"]["status"] == "clear"
    schema = yaml.safe_load(Path("schemas/verification.schema.yaml").read_text())
    Draft202012Validator(schema).validate(doc)
    assert doc["results"][0]["evidence_review"] == doc["results"][2]["evidence_review"]
    assert doc["results"][0]["evidence_review"]["variants"] == ["T-1", "T-1-ab"]


def test_strict_schemas_reject_unknown_fields_at_every_object():
    def check(value):
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value["additionalProperties"] is False
                assert set(value["required"]) == set(value["properties"])
            for v in value.values():
                check(v)
        elif isinstance(value, list):
            for v in value:
                check(v)

    check(REVIEW_SCHEMA)
    check(REVISION_SCHEMA)


def test_rendered_panel_escapes_explanation_and_retains_quote_label():
    page = presentation_document("T-1", "inconclusive", revision("<img src=/target>"))
    assert "<img" not in page and "&lt;img" in page and "recorded excerpt" in page


def test_all_five_hosts_forward_review_schema_without_enabling_tools():
    from test_host_anthropic import _host, _msg
    from test_hosts import (
        CLAUDE_INIT,
        ENV,
        _claude,
        _claude_result,
        _codex,
        _codex_events,
        _copilot,
        _lines,
        _openai_response,
    )

    from appsec_verifier.agent.host_openai import OpenAIHost

    budget = RunBudget(Limits())
    anthropic, client = _host([_msg(CLEAR)])
    assert anthropic.call("s", "p", 10, budget, schema=REVIEW_SCHEMA).step == CLEAR
    assert client.calls[0]["output_config"]["format"]["schema"] == REVIEW_SCHEMA
    assert "tools" not in client.calls[0]
    claude, run = _claude([_lines(CLAUDE_INIT, _claude_result(CLEAR))])
    assert claude.call("s", "p", 10, budget, schema=REVIEW_SCHEMA).step == CLEAR
    argv = run.calls[0]["argv"]
    assert json.loads(argv[argv.index("--json-schema") + 1]) == REVIEW_SCHEMA
    seen = []

    def inspect(argv, cwd):
        seen.append(json.loads(Path(argv[argv.index("--output-schema") + 1]).read_text()))

    codex, _ = _codex([_codex_events({"type": "agent_message", "text": json.dumps(CLEAR)})], inspect)
    assert codex.call("s", "p", 10, budget, schema=REVIEW_SCHEMA).step == CLEAR
    assert seen == [REVIEW_SCHEMA]
    copilot, run = _copilot([json.dumps(CLEAR)])
    assert copilot.call("s", "p", 10, budget, schema=REVIEW_SCHEMA).step == CLEAR
    assert json.dumps(REVIEW_SCHEMA) in run.calls[0]["input"]
    sent = []

    def post(url, headers, body, timeout):
        sent.append(body)
        return 200, _openai_response(CLEAR)

    openai = OpenAIHost.resolve(model=None, environ=ENV, post=post)
    assert openai.call("s", "p", 10, budget, schema=REVIEW_SCHEMA).step == CLEAR
    assert sent[0]["text"]["format"]["schema"] == REVIEW_SCHEMA and "tools" not in sent[0]
    assert sent[0]["store"] is False


def test_exact_cost_ceiling_prevents_any_new_model_call():
    ctx, res, host, *_ = pair([CLEAR], limits=Limits(cost_limit_usd=0.01))
    ctx.budget.note_cost(0.01)
    assert review_finding([(ctx, res)]) == "cost"
    assert not host.calls and ctx.budget.calls == 0
    assert res.evidence_review["reviews"] == res.evidence_review["rounds"] == 0


def test_unchanged_revision_stops_before_third_review():
    ctx, res, host, *_ = pair([issue(), revision(), issue("context"), revision()])
    review_finding([(ctx, res)])
    assert len(host.calls) == 4 and res.evidence_review["rounds"] == 2
    assert "unchanged" in res.evidence_review["reason"]


def test_runner_stops_later_tests_after_review_budget_limit():
    ctx, _, host, *_ = pair([CLEAR])
    tested = []

    class Probe:
        def run(self, actual):
            tested.append(actual.plan.id)
            actual.evidence_test_planner = Planner(host)
            actual.evidence_reviewer_factory = ctx.evidence_reviewer_factory
            actual.budget.note_call()
            actual.budget.limits.max_calls = 1
            return pair([])[1]

    doc = _run([_plan("T-1", "xss"), _plan("T-2", "xss")], registry=ProbeRegistry({"xss": Probe()}))
    assert tested == ["T-1"] and not host.calls
    first, second = doc["results"]
    assert first["verdict"] == "confirmed" and first["evidence_review"]["status"] == "stopped"
    assert second["verdict"] == "not-attempted" and second["limits_hit"] == "calls"


def test_reply_credentials_are_redacted_before_persistence_and_progress():
    ctx, res, host, *_ = pair([issue(detail="test-credential"), revision("test-credential"), CLEAR])
    ctx.sessions = SimpleNamespace(redact=lambda x: json.loads(json.dumps(x).replace("test-credential", "[redacted]")))
    log = []
    ctx.log = log.append
    review_finding([(ctx, res)])
    assert "test-credential" not in json.dumps(res.evidence_review)
    assert "test-credential" not in json.dumps(log)
    assert "test-credential" not in json.dumps(host.calls)


def test_too_many_variants_do_not_create_unbounded_model_context():
    ctx, res, host, *_ = pair([CLEAR])
    group = [(replace(ctx, plan=replace(ctx.plan, variant_digest=str(i))), copy.deepcopy(res)) for i in range(17)]
    review_finding(group)
    assert not host.calls and group[0][1].evidence_review["status"] == "not-reviewed"


def test_review_receives_checked_browser_proof_without_pixels():
    ctx, res, host, *_ = pair([CLEAR])
    res.evidence = [{"kind": "screenshot", "path": "evidence/x.png", "presentation": "application",
                     "source": "live-browser", "executed_via": ["alert"], "marked": 1}]
    review_finding([(ctx, res)])
    supplied = host.calls[0][1]["variants"][0]
    assert supplied["code_checked_proof"]["executed"] is True
    assert supplied["browser_observations"][0]["executed_via"] == ["alert"]
    assert supplied["image_pixels_reviewed"] is False


def test_inconclusive_without_excerpts_can_be_explained_without_inventing_quotes():
    ctx, res, host, *_ = pair([issue(), {"explanation": "No evidence was collected.", "quotes": []}, CLEAR])
    res.verdict, res.poc, res.proof = "inconclusive", None, None
    review_finding([(ctx, res)])
    assert res.evidence_review["status"] == "clear"
    assert res.evidence_review["presentations"][0]["quotes"] == []
    assert ctx.budget.requests == 0


def test_application_image_precedes_http_and_review_in_report():
    ctx, res, *_ = pair([CLEAR])
    res.evidence = [{"kind": "screenshot", "path": "evidence/app.png", "presentation": "application"},
                    {"kind": "screenshot", "path": "evidence/exchange.png"}]
    review_finding([(ctx, res)])
    from dataclasses import asdict

    text = "\n".join(_poc_markdown(asdict(res)))
    assert text.index("![Application") < text.index("Evidence review") < text.index("GET /x HTTP")
    assert text.count("](evidence/app.png)") == 1
    assert "](evidence/exchange.png)" not in text


def test_existing_excerpts_still_require_a_recorded_quote():
    ctx, res, *_ = pair([issue(), {"explanation": "Unsupported correction.", "quotes": []}])
    review_finding([(ctx, res)])
    assert res.evidence_review["status"] == "stopped"
    assert res.evidence_review["reason"] == "Evidence review stopped: missing recorded quote."
    assert not res.evidence_review["presentations"]
