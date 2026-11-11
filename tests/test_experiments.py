"""Mechanism-driven experiments, independent proofs and retained context (VER-005, VER-008..013)."""

from __future__ import annotations

import copy
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode

import pytest

from appsec_verifier.agent.experiments import PLAN_SCHEMA
from appsec_verifier.agent.proof import check_proof
from appsec_verifier.agent.steps import check_action, prompt
from appsec_verifier.loader import assessment_errors, plans_from
from appsec_verifier.verification_context import context_errors
from appsec_verifier.verify.probes import ProbeResult

STRATEGY = dict(
    data_flow="Input reaches the evidenced operation",
    prerequisites=[],
    choice="Compare independent controls on the same route",
    counter_hypothesis="Ordinary application behavior explains the difference",
    expected="Only the mechanism-specific controls change the observation",
    stop="Stop when the responses cannot distinguish the hypothesis",
)


def plan(kind="boolean", **extra):
    values = dict(
        kind=kind,
        strategy=copy.deepcopy(STRATEGY),
        hypothesis="The selected query condition controls the result",
        path="/search",
        input_location="params",
        input_name="q",
        baseline="plain",
        positive="plain' AND '1'='1",
        negative="plain' AND '1'='2",
        pointer="/result",
    )
    if kind == "timing":
        values.pop("negative")
    values.update(extra)
    return {"tool": "plan_test", "args": values, "result": {"accepted": True}}


def req(q="plain", value="fixture-record", ms=80, role="alice", status=200, path="/search"):
    body = json.dumps({"result": value})
    return {
        "tool": "http_request",
        "args": {"path": path, "role": role, "params": {"q": q}},
        "result": {
            "status": status,
            "length": len(body),
            "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "elapsed_ms": ms,
        },
        "_body": body,
    }


def context(history, cls="injection", **kw):
    return SimpleNamespace(
        plan=SimpleNamespace(id="T-1", cls=cls),
        scope={},
        sessions=None,
        evidence_dir=None,
        responses={
            n: {"body": h.get("_body", ""), "complete": True, "identity": h.get("args", {}).get("role")}
            for n, h in enumerate(history, 1)
            if "_body" in h
        },
        **kw,
    )


def check(history, cited=None, verdict="confirmed", ctx=None):
    requests = [n for n, h in enumerate(history, 1) if n > 1 and h.get("tool") != "plan_test"]
    return check_proof(
        ctx or context(history),
        history,
        ProbeResult(verdict=verdict, confidence="high", rationale="claim"),
        cited if cited is not None else requests,
    )


def boolean_history():
    p = plan()
    return [
        p,
        *[
            req(p["args"][k], value)
            for _ in range(2)
            for k, value in [("baseline", "fixture-record"), ("positive", "fixture-record"), ("negative", [])]
        ],
    ]


def test_repeated_declared_semantic_flip_confirms():
    result = check(boolean_history())
    assert result.verdict == "inconclusive"
    assert "ordinary input-dependent" in result.rationale


@pytest.mark.parametrize(
    "change",
    [
        "unstable",
        "reflection",
        "status",
        "role",
        "other-input",
        "missing-body",
        "truncated",
        "same-observation",
        "no-plan",
        "duplicate",
        "before-plan",
    ],
)
def test_injection_controls_fail_closed(change):
    history = boolean_history()
    cited = list(range(2, 8))
    if change == "unstable":
        history[4]["_body"] = '{"result":"timestamp-changed"}'
    if change == "reflection":
        history[2]["_body"] = json.dumps({"result": history[2]["args"]["params"]["q"]})
    if change == "status":
        history[3]["result"]["status"] = 500
    if change == "role":
        history[3]["args"]["role"] = "bob"
    if change == "other-input":
        history[3]["args"]["params"]["page"] = 2
    if change == "same-observation":
        for h in history[1:]:
            h["_body"] = '{"result":"fixture-record"}'
    if change == "no-plan":
        history[0] = {"tool": "read_source", "args": {}, "result": {}}
    if change == "duplicate":
        cited = [2, 2, 3, 3, 4, 4]
    if change == "before-plan":
        history.append(plan())
    ctx = context(history)
    if change == "missing-body":
        ctx.responses.pop(3)
    if change == "truncated":
        ctx.responses[3]["complete"] = False
    result = check(history, cited, ctx=ctx)
    assert result.verdict == "inconclusive"
    assert result.confidence == "low" and result.proof["missing"]


def timing_history():
    p = plan("timing")
    return [p, req(), req(p["args"]["positive"], ms=3100), req(), req(p["args"]["positive"], ms=3150)]


def test_timing_requires_independent_alternating_repetitions():
    assert check(timing_history()).verdict == "inconclusive"
    history = timing_history()[:3]
    assert check(history, [2, 2, 3, 3]).verdict == "inconclusive"
    history = timing_history()
    history[2], history[3] = history[3], history[2]
    assert check(history).verdict == "inconclusive"


@pytest.mark.parametrize("failure", ["one-slow", "short", "long-outlier", "missing-time", "changed-response"])
def test_timing_rejects_jitter_outliers_and_different_responses(failure):
    history = timing_history()
    if failure == "one-slow":
        history[-1]["result"]["elapsed_ms"] = 85
    elif failure == "short":
        history[2]["result"]["elapsed_ms"] = 1500
    elif failure == "long-outlier":
        history[-1]["result"]["elapsed_ms"] = 60000
    elif failure == "missing-time":
        history[-1]["result"].pop("elapsed_ms")
    else:
        history[-1]["result"]["body_sha256"] = "different"
    assert check(history).verdict == "inconclusive"


def resource():
    return {
        "id": "basket-b",
        "finding_id": "T-1",
        "path": "/basket/2",
        "allowed_roles": ["bob"],
        "denied_roles": ["alice"],
        "pointer": "/result",
        "value": "fixture-record",
    }


def access_history():
    return [
        plan("access-control", path="/basket/2", resource="basket-b"),
        req(path="/basket/2", role="bob"),
        req(path="/basket/2", role="alice"),
    ]


def test_access_needs_resource_ownership_and_independent_credentials():
    history = access_history()
    for h in history[1:]:
        h["args"]["params"] = {}
    ctx = context(history, cls="access-control")
    ctx.scope = {"test_resources": [resource()]}
    assert check(history, ctx=ctx).verdict == "confirmed"
    ctx.responses[3]["identity"] = "bob"
    assert check(history, ctx=ctx).verdict == "inconclusive"
    ctx.responses[3]["identity"] = "alice"
    ctx.responses[3]["body"] = '{"result":"alice-own-resource"}'
    assert check(history, ctx=ctx).verdict == "inconclusive"
    ctx.scope = {}
    assert check(history, ctx=ctx).verdict == "inconclusive"


@pytest.mark.parametrize("verdict", ["not-reproducible", "blocked-by-control"])
def test_no_requests_cannot_support_negative_verdict(verdict):
    assert check([], [], verdict).verdict == "not-attempted"


def second_context(history, positive="plain OR 1=1", negative="plain AND 1=2"):
    """The same experiment once more in another declared context: a numeric control pair for the same input."""
    again = copy.deepcopy(history)
    swap = {again[0]["args"]["positive"]: positive, again[0]["args"]["negative"]: negative}
    again[0]["args"].update(positive=positive, negative=negative)
    for h in again[1:]:
        args = h["args"]
        if "params" in args:
            args["params"]["q"] = swap.get(args["params"]["q"], args["params"]["q"])
        else:
            route, _, query = args["path"].partition("?")
            values = dict(parse_qsl(query))
            values["q"] = swap.get(values["q"], values["q"])
            args["path"] = route + "?" + urlencode(values)
    return history + again


def test_repeated_no_effect_supports_only_the_tested_negative():
    """VER-013: a negative verdict needs the true and false controls to answer alike in two declared contexts
    on one input; the proof names them, and what it cannot exclude."""
    history = boolean_history()
    for h in history[1:]:
        h["_body"] = '{"result":"fixture-record"}'
    one = check(history, verdict="not-reproducible")
    assert one.verdict == "inconclusive" and "at least two declared contexts" in one.rationale
    result = check(second_context(history), verdict="not-reproducible")
    assert result.verdict == "not-reproducible" and result.confidence == "medium"
    assert [c["plan_step"] for c in result.proof["contexts"]] == [1, 8]
    assert "answered alike in 2 declared contexts" in result.proof["scope"]
    assert "syntax error the target answers like an empty result is not excluded" in result.proof["scope"]


def _coerced(values=("fixture-record", [], [])):
    """An input the target turns into a number before the query: the baseline finds its record, both controls
    become the same non-matching value and find nothing."""
    history = boolean_history()
    for h in history[1:]:
        q = h["args"]["params"]["q"]
        h["_body"] = json.dumps({"result": dict(zip(("plain", "plain' AND '1'='1", "plain' AND '1'='2"),
                                                    values, strict=True))[q]})
    return second_context(history)


def test_controls_that_answer_alike_but_unlike_the_baseline_support_a_negative():
    """VER-013: the controls need not reproduce the baseline; an empty answer to both, while the baseline
    answers with content, is no split between true and false."""
    assert check(_coerced(), verdict="not-reproducible").verdict == "not-reproducible"


@pytest.mark.parametrize("values, reason", [
    (("fixture-record", "fixture-record", []), "answer differently"),          # a split: no negative result
    (([], [], []), "baseline does not answer with the same content"),          # nothing shows the query works
])
def test_a_negative_without_a_working_baseline_or_with_a_split_stays_inconclusive(values, reason):
    result = check(_coerced(values), verdict="not-reproducible")
    assert result.verdict == "inconclusive" and reason in result.rationale


def test_a_negative_names_cited_steps_outside_its_experiments_and_other_inputs():
    history = boolean_history()
    for h in history[1:]:
        h["_body"] = '{"result":"fixture-record"}'
    early = [req()] + second_context(history)
    assert "step 1 precedes every plan" in check(early, list(range(1, len(early) + 1)), "not-reproducible").rationale
    other = second_context(history)
    for h in other[7:]:
        if h["tool"] == "plan_test":
            h["args"]["input_name"] = "page"
        else:
            h["args"]["params"] = {"page": h["args"]["params"]["q"]}
    assert "cite experiments on one input" in check(other, verdict="not-reproducible").rationale


def _unchanged_history(plan_path="/search?q=<test>"):
    history = boolean_history()
    history[0]["args"]["path"] = plan_path
    for h in history[1:]:
        h["_body"] = '{"result":"fixture-record"}'
    return history


def test_a_query_template_in_the_plan_path_still_matches_its_requests():
    """The plan may show its input as `?q=<test>`; the requests go to the same route (VER-011)."""
    assert check(second_context(_unchanged_history()), verdict="not-reproducible").verdict == "not-reproducible"


def test_the_input_may_travel_in_the_path_query_as_the_controller_sends_it():
    history = _unchanged_history("/search")
    for h in history[1:]:
        h["args"]["path"] = "/search?" + urlencode(h["args"].pop("params"))
    assert check(second_context(history), verdict="not-reproducible").verdict == "not-reproducible"


@pytest.mark.parametrize("change, reason", [
    ("other-route", "declared target"),
    ("other-query-input", "only the declared input may change"),
    ("query-without-input", "declared control value"),
])
def test_route_and_query_of_experiment_requests_fail_closed(change, reason):
    history = _unchanged_history()
    if change == "other-route":
        history[3]["args"]["path"] = "/other"
    if change == "other-query-input":
        history[3]["args"]["path"] = "/search?page=2"
    if change == "query-without-input":
        history[3]["args"]["path"] = "/search?" + urlencode(history[3]["args"].pop("params") | {"q": "unplanned"})
    result = check(history, verdict="not-reproducible")
    assert result.verdict == "inconclusive" and reason in result.rationale


def test_error_does_not_count_as_target_control():
    history = [plan("control"), req(), req("changed", status=500)]
    assert check(history, verdict="blocked-by-control").verdict == "inconclusive"


def test_repeatable_rejection_needs_working_matched_controls():
    history = boolean_history()
    for h in history[1:]:
        if h["args"]["params"]["q"] != history[0]["args"]["baseline"]:
            h["result"]["status"] = 403
    result = check(second_context(history), verdict="blocked-by-control")
    assert result.verdict == "blocked-by-control" and result.confidence == "medium"
    assert check(history, verdict="blocked-by-control").verdict == "inconclusive"     # one context only
    history[-1]["args"]["params"]["page"] = 2
    assert check(second_context(history), verdict="blocked-by-control").verdict == "inconclusive"


def test_access_negative_cannot_override_observed_resource():
    history = access_history()
    for h in history[1:]:
        h["args"]["params"] = {}
    ctx = context(history, cls="access-control")
    ctx.scope = {"test_resources": [resource()]}
    assert check(history, ctx=ctx, verdict="not-reproducible").verdict == "inconclusive"
    history[2]["result"]["status"] = 403
    history[2]["_body"] = '{"error":"denied"}'
    ctx.responses[3]["body"] = history[2]["_body"]
    assert check(history, ctx=ctx, verdict="blocked-by-control").verdict == "blocked-by-control"


def test_a_timing_experiment_supports_no_negative_verdict():
    """VER-013: a timing experiment has no true and false controls, so an undelayed answer is no negative."""
    history = timing_history()
    for h in history[1:]:
        h["result"]["elapsed_ms"] = 90
    result = check(history, verdict="not-reproducible")
    assert result.verdict == "inconclusive" and "has no true and false controls" in result.rationale


def verification_context():
    return {
        "version": 1,
        "variants": [
            {
                "id": "search",
                "request": {"method": "GET", "path": "/search", "inputs": [{"location": "query", "name": "q"}]},
                "hypothesis": "Concatenation changes SQL syntax",
                "mechanism": {
                    "expression": "SELECT id FROM items WHERE name LIKE '%<q>%'",
                    "dialect": "SQLite",
                    "binding": "concatenated",
                },
                "processing": [
                    {"operation": "filter", "description": "Rejects literal keywords before decoding"},
                    {"operation": "decode", "description": "Decodes once after the filter"},
                ],
                "controls": [
                    {
                        "kind": "denylist",
                        "description": "Literal comparison",
                        "status": "observed",
                        "limitation": "Normalization follows the comparison",
                    }
                ],
                "prerequisites": ["Known harmless test row"],
                "expected_observations": ["True repeats baseline"],
                "negative_controls": ["False condition suppresses the test row"],
                "unknowns": ["Proxy filtering unknown"],
                "evidence": [{"file": "search.py", "line": 4}],
            }
        ],
    }


def test_context_survives_intake_and_can_be_read_separately():
    v = verification_context()
    threat = {
        "id": "T-1",
        "title": "injection",
        "cwe": "CWE-89",
        "evidence": {"file": "search.py", "line": 4},
        "scenario": "s" * 2000,
        "attack_steps": ["important final step"],
        "verification_context": v,
        "mechanism_trace": {"connection": "q is concatenated"},
    }
    doc = {"threats": [threat]}
    assert assessment_errors(doc) == []
    p = plans_from(doc)[0]
    assert p.verification_context == v and p.context["attack_steps"] == ["important final step"]
    assert p.context["mechanism_trace"]["connection"] == "q is concatenated"
    assert p.endpoints[0].path == "/search"
    old = copy.deepcopy(doc)
    old["threats"][0].pop("verification_context")
    assert not assessment_errors(old)


@pytest.mark.parametrize("mutation", ["version", "unknown-field", "oversize", "duplicate"])
def test_malformed_context_is_rejected(mutation):
    v = verification_context()
    if mutation == "version":
        v["version"] = 2
    if mutation == "unknown-field":
        v["authority"] = "execute anything"
    if mutation == "oversize":
        v["variants"][0]["hypothesis"] = "x" * 1001
    if mutation == "duplicate":
        v["variants"] *= 2
    assert context_errors(v)


def test_results_are_structured_and_measurements_survive_excerpt_bounding():
    ctx = SimpleNamespace(
        plan=SimpleNamespace(id="T-1", cwe="CWE-89", cls="injection", title="test", instance="x:1"),
        target_base="https://app.example",
    )
    text = prompt(
        ctx, [{"tool": "http_request", "args": {}, "result": {"body_excerpt": "x" * 8000, "elapsed_ms": 3100}}]
    )
    assert '"elapsed_ms": 3100' in text and "[truncated]" in text
    assert PLAN_SCHEMA["additionalProperties"] is False
    proposal = {"verdict": {"verdict": "confirmed", "rationale": "r", "proof_steps": [1, 1, 2, 2]}}
    assert check_action(proposal)["verdict"]["verdict"] == "inconclusive"


# ── VER-053: engine-error classification and the Verifier-built UNION ──────────


@pytest.mark.parametrize("body", [
    'unrecognized token: "\'))"',                               # SQLite, the stray quote
    'near "UNION": syntax error',                               # SQLite, an unbalanced UNION
    "You have an error in your SQL syntax near '...'",          # MySQL
    "syntax error at or near \"'\"",                            # PostgreSQL
    "ORA-00933: SQL command not properly ended",               # Oracle
    '{"errmsg":"Regular expression is invalid: missing )"}',    # MongoDB $regex
    "net.sf.saxon.trans.XPathException: Invalid XPath",         # XPath / Saxon
    "jinja2.exceptions.TemplateSyntaxError: unexpected end of template",   # Jinja2
    "Twig\\Error\\SyntaxError: Unexpected token \"end of template\"",      # Twig
    "freemarker.core.ParseException: Syntax error in template",          # FreeMarker
    "SyntaxError: Unexpected end of input",                     # an evaluated JavaScript expression
])
def test_engine_error_signature_catches_each_engine(body):
    from appsec_verifier.agent.experiments import engine_error_signature

    assert engine_error_signature(body) is True


@pytest.mark.parametrize("body", [
    "Internal Server Error",                                    # a generic 500
    "Bad Request",                                              # input validation
    '{"error":"Invalid email or password."}',                  # an ordinary application error
    "",                                                        # no body
    '{"data":[1,2,3]}',                                         # a normal success body
    '{"data":[{"name":"Velocity Runner"},{"name":"Twig Basket"}]}',   # engine names as ordinary words
    "<p>Handlebars, Mako shark poster, Smarty pants</p>",
])
def test_a_generic_failure_is_not_an_engine_error(body):
    from appsec_verifier.agent.experiments import engine_error_signature

    assert engine_error_signature(body) is False


def test_marker_controls_builds_only_null_and_a_concatenated_marker():
    """VER-053: the Verifier owns the SELECT list, so no FROM or real column can be injected, and each marker is a
    concatenation the database computes (an echo cannot reproduce the joined value)."""
    from appsec_verifier.agent.experiments import marker_controls

    plan = {"sql_marker": {"prefix": "'))", "columns": 3, "column": 1, "comment": "-- "}}
    out = marker_controls(plan)
    for control in (out["positive"], out["negative"]):
        assert control.startswith("'))") and "UNION SELECT NULL," in control and control.endswith("-- ")
        assert "FROM" not in control.upper() and "'||'" in control
    assert out["markers"]["positive"] != out["markers"]["negative"]
    # The joined marker (what the database computes) is not present verbatim in the sent payload.
    assert out["markers"]["positive"] not in out["positive"]


@pytest.mark.parametrize("template, reason", [
    ("1 || {{predicate}}", "contains no ||"),
    ("2 && {{predicate}}", "starts with the baseline"),
    ("1 + {{predicate}}", "join {{predicate}} to the baseline with &&"),
    ("1 && {{predicate}} && {{predicate}}", "exactly one {{predicate}} placeholder"),
])
def test_a_javascript_predicate_template_joins_the_baseline_with_and_only(template, reason):
    """VER-011: no || can widen the answer beyond the baseline's record, and the predicate is joined to it."""
    from appsec_verifier.agent.experiments import js_controls

    with pytest.raises(ValueError) as refused:
        js_controls({"baseline": "1", "js_predicate_template": template})
    assert reason in str(refused.value)


def test_javascript_predicate_controls_are_fresh_and_complementary():
    from appsec_verifier.agent.experiments import js_controls

    first = js_controls({"baseline": "1", "js_predicate_template": "1 && {{predicate}}"})
    second = js_controls({"baseline": "1", "js_predicate_template": "1 && {{predicate}}"})
    controls = [first[k] for k in ("positive", "negative", "positive_other", "negative_other")]
    assert len(set(controls)) == 4 and all(c.startswith("1 && (") and "||" not in c for c in controls)
    assert first["positive"] != second["positive"]                         # fresh values per plan
    assert "===" in first["positive"] and "!==" in first["positive_other"]
