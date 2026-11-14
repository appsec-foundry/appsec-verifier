"""VER-059: after its verdict the test agent receives the recorded steps and presents its proof of concept from them;
the code leaves out and names what is not an exact quote, withheld, or not a recorded request, shortens what is too
long, names the steps the verdict rests on that the image does not show, and shows its own presentation only when
none, none readable, or none of those steps remains. Before it leaves anything out, the agent may correct it once;
a presentation never costs the checked verdict, and an evidence review can ask for it again (VER-042)."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from jsonschema import Draft202012Validator
from test_evidence_review import CLEAR, pair
from test_poc import Resp, _ctx, _get, _run

from appsec_verifier.agent import AgentTools
from appsec_verifier.agent.steps import system_prompt
from appsec_verifier.verify import presentation as pres
from appsec_verifier.verify.evidence_review import REVISION_SCHEMA, _images, review_finding
from appsec_verifier.verify.report import to_markdown

SUMMARY = "customer-a, who must not see it, read customer-b's basket with bob's email address."


class Browser:
    """Renders nothing; keeps every exchange page it was asked to render."""

    screenshots = frozenset({"access-control", "injection"})

    def __init__(self):
        self.pages = []

    def render(self, **kw):
        return []

    def render_exchanges(self, *, html, name, marked, kind="http"):
        self.pages.append(html)
        return [{"kind": "screenshot", "path": f"evidence/{name}-http-{len(self.pages)}.png", "marked": marked}]


def _good(**over):
    """A presentation of the declared-resource proof _run records: step 2 customer-a (denied), step 3 customer-b."""
    p = {"summary": SUMMARY,
         "steps": [{"step": 3, "role": "normal", "label": "the owner reads the basket"},
                   {"step": 2, "role": "outcome", "label": "another customer reads it too",
                    "excerpt": '"email":"bob@shop.test"'}],
         "marks": [{"step": 2, "part": "response", "text": "bob@shop.test", "label": "the owner's email"},
                   {"step": 2, "part": "request", "text": "/rest/basket/2", "label": "the owner's basket"}]}
    p.update(over)
    return p


def _verdict(presentation, verdict="confirmed"):
    return {"verdict": {"verdict": verdict, "rationale": "a read b's basket", "proof_steps": [1, 2],
                        **({"presentation": presentation} if presentation is not None else {})}}


def _probe(tmp_path, *verdicts, transport=None):
    browser, sent = Browser(), []
    ctx = _ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or (transport or (lambda: Resp()))(), browser=browser)
    result, planner = _run(ctx, [_get("customer-a"), _get("customer-b"), *verdicts])
    return result, planner, browser, sent, ctx


# ── the loop: accepted, repaired once, refused ──────────────────────────────


def test_an_accepted_presentation_leads_the_images_and_the_report(tmp_path):
    result, planner, browser, _, ctx = _probe(tmp_path, _verdict(_good()))
    assert result.verdict == "confirmed"
    assert result.poc["presentation"] == {"composed_by": "test-agent", "summary": SUMMARY}
    assert [(s["step"], s["role"], s["role_label"]) for s in result.poc["shown"]] == [
        (3, "normal", "the owner reads the basket"), (2, "outcome", "another customer reads it too")]
    assert "⟦bob@shop.test⟧" in result.poc["shown"][1]["response_excerpt"]
    assert "⟦bob@shop.test⟧: the owner's email" in result.poc["shown"][1]["facts"]      # the label stays
    assert "GET ⟦/rest/basket/2⟧" in result.poc["shown"][1]["request_excerpt"]
    page = browser.pages[-1]
    assert "(the test agent's words)" in page and "class=outcome" in page and "Outcome" in page
    images = [e for e in result.evidence if e.get("kind") == "screenshot"]
    assert images and all(e["composed_by"] == "test-agent" and e["reviewable"] is True for e in images)
    assert not any(o.startswith(pres.COMPOSED_NOTE) for o in result.observations)
    assert not any("presentation_feedback" in seen for seen in planner.seen)


def test_after_the_verdict_the_agent_gets_the_record_and_only_its_answer_s_presentation_counts(tmp_path):
    """The answer says inconclusive and cites nothing: the checked confirmation stands, its presentation is used."""
    answer = {"verdict": {"verdict": "inconclusive", "rationale": "changed my mind", "presentation": _good()}}
    result, planner, browser, sent, _ = _probe(tmp_path, _verdict(None), answer)
    assert result.verdict == "confirmed" and result.rationale == "a read b's basket"
    assert result.poc["presentation"] == {"composed_by": "test-agent", "summary": SUMMARY}
    request = json.loads(planner.seen[-1])[-1]
    assert request["tool"] == "presentation_request" and request["result"]["required_steps"] == [2, 3]
    assert [item["step"] for item in request["result"]["recorded_evidence"]] == [2, 3]
    assert len(sent) == 2                                              # the request sent nothing to the target


def test_a_presentation_with_a_wrong_quote_goes_back_once_then_only_the_quote_is_left_out(tmp_path):
    wrong = _good(steps=[_good()["steps"][0], {**_good()["steps"][1], "excerpt": '"email":"alice@shop.test"'}])
    result, planner, browser, _, _ = _probe(tmp_path, _verdict(None), _verdict(wrong), _verdict(wrong))
    left = ["the excerpt of step 2, which is not an exact quote from its recorded answer",
            "mark 1, which is not in the answer shown of step 2"]
    assert result.verdict == "confirmed"
    assert result.poc["presentation"] == {"composed_by": "test-agent", "summary": SUMMARY, "left_out": left}
    feedback = json.loads(planner.seen[-1])[-1]
    assert feedback["tool"] == "presentation_feedback"
    assert feedback["result"]["reason"] == "it would leave out " + "; ".join(left)
    assert feedback["result"]["recorded_evidence"]
    assert [h["tool"] for h in json.loads(planner.seen[-1])].count("presentation_feedback") == 1
    assert "Left out by the Verifier: " + "; ".join(left) + "." in browser.pages[-1]
    assert "alice@shop.test" not in browser.pages[-1] and "the owner&#x27;s basket" in browser.pages[-1]
    assert all(e["composed_by"] == "test-agent" for e in result.evidence if e.get("kind") == "screenshot")
    assert not any(o.startswith(pres.COMPOSED_NOTE) for o in result.observations)


def test_a_tool_call_after_the_request_ends_the_finding_with_the_verdict_s_own_presentation(tmp_path):
    result, _, browser, sent, _ = _probe(tmp_path, _verdict(_good(steps=[_good()["steps"][1]])), _get("customer-a"))
    assert result.verdict == "confirmed" and len(sent) == 2            # the proposed request never ran
    assert result.poc["presentation"] == {"composed_by": "test-agent", "summary": SUMMARY, "not_shown": [3]}
    assert "Also part of the proof, not shown here: step 3 (in the report and the HAR file)." in browser.pages[-1]
    assert [(s["step"], s.get("composed_by")) for s in result.poc["shown"]] == [(2, None), (3, "verifier")]


def test_a_verdict_without_a_presentation_is_asked_for_it_once(tmp_path):
    result, planner, _, _, _ = _probe(tmp_path, _verdict(None))
    assert result.verdict == "confirmed"
    assert result.poc["presentation"] == {"composed_by": "verifier",
                                          "reason": "the test agent composed no presentation"}
    tools = [h["tool"] for h in json.loads(planner.seen[-1])]
    assert tools.count("presentation_request") == 1 and "presentation_feedback" not in tools


def test_at_the_last_decision_the_verdict_s_own_presentation_counts_without_a_request(tmp_path):
    browser = Browser()
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), browser=browser)
    result, planner = _run(ctx, [_get("customer-a"), _get("customer-b"), _verdict(_good())], max_steps=4)
    assert result.poc["presentation"] == {"composed_by": "test-agent", "summary": SUMMARY}
    assert not any("presentation_request" in seen for seen in planner.seen)


@pytest.mark.parametrize("value, reason", [
    (None, "the test agent composed no presentation"),
    ("as text", "its presentation cannot be read as steps with their roles"),
    ([1], "its presentation cannot be read as steps with their roles"),
])
def test_a_presentation_of_any_other_type_never_costs_the_checked_verdict(tmp_path, value, reason):
    verdict = _verdict(None)
    verdict["verdict"]["presentation"] = value
    result, _, _, _, _ = _probe(tmp_path, verdict)
    assert result.verdict == "confirmed" and result.poc["presentation"]["reason"] == reason


def test_a_presentation_with_an_outcome_cannot_present_a_verdict_that_is_not_confirmed(tmp_path):
    result, _, browser, _, _ = _probe(tmp_path, _verdict(_good(), verdict="inconclusive"),
                                      _verdict(_good(), verdict="inconclusive"))
    assert result.verdict == "inconclusive"
    assert result.poc["presentation"]["left_out"] == [
        "the outcome role of step 2, since the verdict is inconclusive; shown as an attack"]
    assert [(s["step"], s["role"]) for s in result.poc["shown"]] == [(3, "normal"), (2, "attack")]
    assert "class=outcome" not in browser.pages[-1]


def test_the_model_is_offered_the_precise_schema_but_any_object_keeps_the_verdict(tmp_path):
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp())
    actions = json.loads(system_prompt(ctx).split("argument schemas are:\n", 1)[1].split("\nOmit optional", 1)[0])
    offered = next(a for a in actions if a["name"] == "submit_verdict")["input_schema"]
    assert "presentation" not in offered.get("required", [])          # asked for after the verdict
    assert offered["properties"]["presentation"]["properties"]["steps"]["items"]["properties"]["role"]["enum"] == [
        "normal", "attack", "outcome", "control"]
    result, _, _, _, _ = _probe(tmp_path, _verdict({"summary": 3}), _verdict({"summary": 3}))
    assert result.verdict == "confirmed"
    assert result.poc["presentation"]["reason"] == "its presentation cannot be read as steps with their roles"


# ── the checks: what is left out, shortened or makes the Verifier show its own ──────────────


def _recorded(tmp_path, *answers):
    """Steps 1.. as AgentTools records them, one GET each, answered by `answers` (status, text, content type)."""
    queue = list(answers)

    def transport(m, u, h, **k):
        status, text, kind = queue.pop(0)
        return Resp(status, text, {"content-type": kind})

    ctx = _ctx(tmp_path, transport)
    tools, steps, history = AgentTools(ctx), [], []
    for n, path in enumerate(["/search?q=a%27b", "/rest/basket/2", "/rest/basket/2"][:len(answers)], 1):
        result = tools.call("http_request", {"role": "customer-a", "path": path})
        steps.append({"step": n, "tool": "http_request", "entries": tools.take_exchanges()})
        history.append({"tool": "http_request", "args": {"path": path}, "result": result})
    return ctx, history, steps


PAGE = ("text/html", "<html><body><nav>Home</nav><p>Welcome to the protected area admin</p>\n<p>Logout</p>"
        "<script>var x='hidden';</script></body></html>")
JSON = ("application/json", '{"id": 2, "email": "bob@shop.test"}')


def _three(tmp_path):
    return _recorded(tmp_path, (200, PAGE[1], PAGE[0]), (200, JSON[1], JSON[0]), (404, "", "text/plain"))


def _p(steps, marks=(), summary="The injected name signs in without the password."):
    return {"summary": summary, "steps": steps, "marks": list(marks)}


def test_a_text_observation_names_the_text_its_proof_looked_for(tmp_path):
    """VER-055, VER-059: under the agent's presentation a reader sees which text 'present' and 'absent' refer to."""
    ctx, history, steps = _recorded(tmp_path, (200, PAGE[1], PAGE[0]), (200, "<p>Login failed</p>", PAGE[0]))
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89")
    history.append({"tool": "plan_test", "args": {}, "result": {"accepted": True, "experiment": {
        "kind": "boolean", "text": "Welcome to the protected area", "path": "/search"}}})
    presentation = _p([{"step": 1, "role": "attack", "label": "true condition"},
                       {"step": 2, "role": "control", "label": "false condition"}])
    facts = [fields["facts"] for _, _, fields in pres.report_steps(ctx, history, steps, presentation)]
    assert facts == [["Verifier's observation: text present: \"Welcome to the protected area\""],
                     ["Verifier's observation: text absent: \"Welcome to the protected area\""]]


def test_verbatim_quotes_pass_with_other_whitespace_from_page_text_and_json(tmp_path):
    _, history, steps = _three(tmp_path)
    good = _p([{"step": 1, "role": "attack", "label": "signed in", "excerpt": "Welcome  to the\nprotected area admin"},
               {"step": 2, "role": "outcome", "label": "the record", "excerpt": '"id": 2, "email": "bob@shop.test"'},
               {"step": 3, "role": "control", "label": "a random path is not found"}],
              [{"step": 1, "part": "request", "text": "q=a'b", "label": "the input, decoded"},
               {"step": 1, "part": "response", "text": "admin", "label": "signed in as admin"}])
    checked = pres.check(history, steps, "confirmed", {1, 2, 3}, good)
    assert checked.why is None and checked.left_out == ()
    assert checked.shown == {**good, "left_out": [], "not_shown": []}


@pytest.mark.parametrize("presentation, verdict, decisive, reason, left", [
    (None, "confirmed", {1}, "the test agent composed no presentation", ()),
    (_p([{"step": 1, "role": "victim", "label": "abc"}]), "confirmed", {1},
     "its presentation cannot be read as steps with their roles", ("an entry without a step number and a known role",)),
    (_p([{"step": 9, "role": "attack", "label": "abc"}, {"step": 2, "role": "attack", "label": "abc"}]), "confirmed",
     {1}, "none of the steps the verdict rests on remains in its presentation",
     ("step 9, which is not a recorded request",)),
])
def test_the_verifier_shows_its_own_only_without_a_usable_presentation(tmp_path, presentation, verdict, decisive,
                                                                        reason, left):
    _, history, steps = _three(tmp_path)
    assert pres.check(history, steps, verdict, decisive, presentation) == (None, reason, left)


@pytest.mark.parametrize("presentation, verdict, left", [
    (_p([{"step": 1, "role": "attack", "label": "abc"}] * 2), "confirmed", "the second entry of step 1"),
    (_p([{"step": 2, "role": "outcome", "label": "abc"}]), "inconclusive",
     "the outcome role of step 2, since the verdict is inconclusive; shown as an attack"),
    (_p([{"step": 1, "role": "attack", "label": "abc", "excerpt": "Welcome to the admin area"}]), "confirmed",
     "the excerpt of step 1, which is not an exact quote from its recorded answer"),
    (_p([{"step": 2, "role": "outcome", "label": "abc", "excerpt": '"id": 2'}],
        [{"step": 2, "part": "response", "text": "bob@shop.test", "label": "email"}]), "confirmed",
     "mark 1, which is not in the answer shown of step 2"),
    (_p([{"step": 1, "role": "attack", "label": "abc"}],
        [{"step": 1, "part": "request", "text": "q=a%27b", "label": "input"}]), "confirmed",
     "mark 1, which is not in the URL-decoded request of step 1"),
    (_p([{"step": 1, "role": "attack", "label": "abc"}],
        [{"step": 3, "part": "request", "text": "GET", "label": "input"}]), "confirmed",
     "mark 1, on step 3, which the presentation does not show"),
    (_p([{"step": 1, "role": "attack", "label": "abc"}],
        [{"step": 1, "part": "request", "text": "GET", "label": "a"}] * 4), "confirmed", "the marks after the first 3"),
    ({"steps": [{"step": 1, "role": "attack", "label": "abc"}]}, "confirmed", "its summary sentence"),
])
def test_what_is_not_true_to_the_record_is_left_out_and_named_the_rest_stays(tmp_path, presentation, verdict, left):
    _, history, steps = _three(tmp_path)
    checked = pres.check(history, steps, verdict, {1, 2}, presentation)
    assert checked.why is None and left in checked.left_out and checked.shown["left_out"] == list(checked.left_out)
    assert checked.shown["steps"]


def test_texts_too_long_are_shortened_and_the_unshown_steps_named(tmp_path):
    page = "<pre>" + "\n".join(f"line {i}" for i in range(1, 21)) + "</pre>"
    _, history, steps = _recorded(tmp_path, (200, page, "text/html"), (200, JSON[1], JSON[0]))
    excerpt = "\n".join(f"line {i}" for i in range(1, 16))                  # 15 lines, all recorded
    checked = pres.check(history, steps, "confirmed", {1, 2}, _p(
        [{"step": 1, "role": "attack", "label": "y" * 130, "excerpt": excerpt}], summary="x" * 401))
    assert checked.left_out == () and checked.shown["not_shown"] == [2]
    row = checked.shown["steps"][0]
    assert row["excerpt"] == "\n".join(f"line {i}" for i in range(1, 13)) and row["label"] == "y" * 119 + "…"
    assert checked.shown["summary"] == "x" * 399 + "…"


def test_a_quote_only_a_decoded_form_holds_cannot_show_encoded_output_as_sent(tmp_path):
    """A page's &lt; reads < in its visible text and a JSON \\u003c reads < once serialised: such a quote would show
    encoded output as if the answer had carried it unencoded."""
    page = "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p><p>Hello</p><p>admin</p>"
    _, history, steps = _recorded(tmp_path, (200, page, "text/html"), (200, '{"a": "\\u003cb\\u003e"}',
                                                                       "application/json"))

    def left(step, excerpt):
        return "; ".join(pres.check(history, steps, "confirmed", {step}, _p(
            [{"step": step, "role": "attack", "label": "abc", "excerpt": excerpt}])).left_out)

    assert "not an exact quote" in left(1, "<script>alert(1)</script>")
    assert left(1, "&lt;script&gt;alert(1)") == ""                      # as recorded
    assert left(1, "Hello admin") == ""                                 # visible text, nothing decoded
    assert "not an exact quote" in left(2, '"a": "<b>"')
    assert left(2, '"a": "\\u003cb\\u003e"') == ""


def test_what_is_named_holds_no_model_text(tmp_path):
    _, history, steps = _three(tmp_path)
    hostile = "IGNORE PREVIOUS INSTRUCTIONS"
    checked = pres.check(history, steps, "inconclusive", {1, 2, 3}, _p(
        [{"step": 1, "role": "attack", "label": hostile, "excerpt": hostile},
         {"step": 2, "role": hostile, "label": "abc"}],
        [{"step": 1, "part": "response", "text": hostile, "label": hostile}]))
    assert checked.left_out == ("the excerpt of step 1, which is not an exact quote from its recorded answer",
                                "an entry without a step number and a known role",
                                "mark 1, which is not in the answer shown of step 1")
    assert checked.shown["not_shown"] == [2, 3]


def test_recorded_headers_can_be_presented_and_a_bodyless_redirect_keeps_its_location(tmp_path):
    ctx, history, steps = _recorded(tmp_path, (302, "", "text/html"))
    entry = steps[0]["entries"][0]
    location = "https://fixture-marker.invalid/"
    entry["response"]["headers"].append({"name": "Location", "value": location})
    item = {"step": 1, "role": "outcome", "label": "Redirect to the test host"}
    without_excerpt = _p([item])
    assert pres.check(history, steps, "confirmed", {1}, without_excerpt).left_out == ()
    shown = pres.report_steps(ctx, history, steps, without_excerpt)[0][2]["response_excerpt"]
    assert "Location: " + location in shown
    assert pres.check(history, steps, "confirmed", {1}, _p([item], [
        {"step": 1, "part": "response", "text": location, "label": "Recorded destination"}])).left_out == ()
    quoted = _p([{**item, "excerpt": "Location: " + location}],
                [{"step": 1, "part": "response", "text": location, "label": "Recorded destination"}])
    assert pres.check(history, steps, "confirmed", {1}, quoted).left_out == ()
    quoted["steps"][0]["excerpt"] = location
    assert "not an exact quote" in pres.check(history, steps, "confirmed", {1}, quoted).left_out[0]
    quoted["steps"][0]["excerpt"] = "Location: https://invented.invalid/"
    assert "not an exact quote" in pres.check(history, steps, "confirmed", {1}, quoted).left_out[0]


def test_presentation_repairs_receive_exact_redacted_records_but_no_withheld_answer(tmp_path):
    ctx, history, steps = _recorded(tmp_path, (200, "<p>fixture-sensitive-value</p>", "text/html"),
                                  (200, "withheld-answer", "text/plain"))
    ctx.sessions.remember_secret("fixture-sensitive-value")
    steps[1]["entries"][0]["response"]["content"]["_omitted"] = "body not kept"
    steps[1]["entries"][0]["response"]["headers"].append({"name": "Location", "value": "withheld-header-value"})
    result = SimpleNamespace(verdict="confirmed", proof={"checked": True, "steps": [1, 2]})
    feedback = pres.repair_context(ctx, history, steps, result, [1, 2])
    assert feedback["required_steps"] == [1, 2]
    assert feedback["recorded_evidence"][0]["body_excerpt"] == "<p>[redacted]</p>"
    assert feedback["recorded_evidence"][1]["response_withheld"] is True
    assert "fixture-sensitive-value" not in json.dumps(feedback)
    assert "withheld-answer" not in json.dumps(feedback)
    assert "withheld-header-value" not in json.dumps(feedback)
    item = {"step": 2, "role": "control", "label": "Withheld comparison"}
    for text in ("withheld-header-value", "body not kept"):
        presentation = _p([item], [{"step": 2, "part": "response", "text": text, "label": "No invented evidence"}])
        assert pres.check(history, steps, "confirmed", {2}, presentation).left_out == (
            "mark 1, which is not in the answer shown of step 2",)


def test_repair_excerpt_focuses_on_the_checked_text_after_redaction(tmp_path):
    observation = "Welcome fixture-sensitive-value to the protected resource"
    body = "<nav>" + "navigation " * 200 + "</nav><p>" + observation + "</p>"
    ctx, history, steps = _recorded(tmp_path, (200, body, "text/html"))
    ctx.plan = replace(ctx.plan, cls="injection", cwe="CWE-89")
    ctx.sessions.remember_secret("fixture-sensitive-value")
    history.insert(0, {"tool": "plan_test", "args": {}, "result": {"accepted": True,
                       "experiment": {"kind": "boolean", "text": observation}}})
    steps[0]["step"] = 2
    result = SimpleNamespace(verdict="confirmed", proof={"checked": True, "steps": [2]})
    feedback = pres.repair_context(ctx, history, steps, result, [2])
    assert "Welcome [redacted] to the protected resource" in feedback["recorded_evidence"][0]["body_excerpt"]
    assert "fixture-sensitive-value" not in json.dumps(feedback)


def test_the_presentation_request_supplies_evidence_without_logging_response_bodies(tmp_path):
    records = []
    browser = Browser()
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), browser=browser)
    ctx.log = records.append
    result, planner = _run(ctx, [_get("customer-a"), _get("customer-b"), _verdict(None), _verdict(_good())])
    assert result.verdict == "confirmed" and result.poc["presentation"]["composed_by"] == "test-agent"
    request = json.loads(planner.seen[-1])[-1]["result"]
    assert request["required_steps"] == [2, 3] and request["recorded_evidence"]
    logged = next(r["result"] for r in records if r.get("tool") == "presentation_request")
    assert logged["required_steps"] == [2, 3] and "recorded_evidence" not in logged
    assert "bob@shop.test" not in json.dumps(logged)


def test_a_cited_step_that_sent_nothing_need_not_and_cannot_be_listed(tmp_path):
    """A cited source read or plan has no request to show: only the cited requests count."""
    ctx, history, steps = _three(tmp_path)
    history.append({"tool": "read_source", "args": {"path": "a.php"}, "result": {"text": "x"}})
    result = SimpleNamespace(verdict="inconclusive", proof=None)
    shown = _p([{"step": 1, "role": "attack", "label": "the input reaches the page"}])
    checked = pres.assess(ctx, history, steps, result, [1, 4], shown)
    assert checked.why is None and checked.shown["steps"] == shown["steps"] and checked.shown["not_shown"] == []
    assert pres.assess(ctx, history, steps, result, [4], shown) == (None, "the verdict cites no step", ())


def test_the_verifier_s_presentation_is_an_issue_only_where_it_can_be_presented_again():
    ctx, res, *_ = pair([CLEAR])
    res.poc["presentation"] = {"composed_by": "verifier", "reason": "the test agent composed no presentation"}
    review_finding([(ctx, res)])                                        # no represent hook: nothing to ask for
    assert res.evidence_review["status"] == "clear"


def test_a_withheld_or_not_kept_answer_carries_no_excerpt(tmp_path):
    """VER-049, VER-053, VER-057: what no model read cannot be quoted, even where the text matches."""
    _, history, steps = _three(tmp_path)
    quote = _p([{"step": 2, "role": "outcome", "label": "abc", "excerpt": '"id": 2'}])
    left = ("the excerpt of step 2, whose answer is withheld or not kept",)
    history[1]["result"] = {"status": 200, "engine_error": True}
    checked = pres.check(history, steps, "confirmed", {2}, quote)
    assert checked.left_out == left and "excerpt" not in checked.shown["steps"][0]
    _, history, steps = _three(tmp_path)
    content = steps[1]["entries"][-1]["response"]["content"]
    content["_omitted"] = "body not kept: compared in code only (VER-057)"
    assert pres.check(history, steps, "confirmed", {2}, quote).left_out == left
    status_only = _p([{"step": 2, "role": "outcome", "label": "the same answer without a login"}])
    assert pres.check(history, steps, "confirmed", {2}, status_only).left_out == ()


def test_the_rendered_page_escapes_every_model_text_and_runs_nothing(tmp_path):
    ctx, history, steps = _three(tmp_path)
    hostile = "<img src=x onerror=alert(1)>"
    shown = _p([{"step": 1, "role": "attack", "label": hostile, "excerpt": "protected area admin"}],
               [{"step": 1, "part": "response", "text": "admin", "label": hostile}], summary=hostile + " summary")
    result = SimpleNamespace(verdict="confirmed", proof={"checked": True})
    page, marks = pres.document(ctx, history, steps, shown, result, "evidence/T-001-poc.har")
    assert "<img" not in page and "<script" not in page and page.count("&lt;img src=x") == 3 and marks == 1


def test_a_revision_presentation_has_a_strict_form_whose_nulls_are_dropped():
    strict = {"summary": SUMMARY, "steps": [{"step": 1, "role": "attack", "label": "abc", "excerpt": None}],
              "marks": []}
    assert Draft202012Validator(pres.REVISION_PRESENTATION).is_valid(strict)
    assert not Draft202012Validator(pres.REVISION_PRESENTATION).is_valid({**strict, "steps": [{"step": 1}]})
    assert pres.normalized(strict)["steps"] == [{"step": 1, "role": "attack", "label": "abc"}]
    assert Draft202012Validator(pres.PRESENTATION_SCHEMA).is_valid(pres.normalized(strict))


# ── the evidence review sees the agent's image and can ask for a presentation (VER-042) ─────────────────────────


def test_the_reviewer_may_see_a_cleared_image_the_agent_composed_but_not_the_verifier_s():
    res = SimpleNamespace(evidence=[
        {"kind": "screenshot", "path": "evidence/a.png", "composed_by": "test-agent", "reviewable": True},
        {"kind": "screenshot", "path": "evidence/b.png", "composed_by": "test-agent", "reviewable": False},
        {"kind": "screenshot", "path": "evidence/c.png", "composed_by": "verifier"}])
    items = _images(SimpleNamespace(evidence_dir=None), res)
    assert [(i["test_agent_composed"], i["cleared_for_model"]) for i in items] == [
        (True, True), (True, False), (False, False)]


def _revision(presentation):
    return {"explanation": "The marker ran in the page.", "quotes": [], "page": None, "presentation": presentation}


STRICT = {"summary": "The page ran the injected script with the finding's marker.",
          "steps": [{"step": 1, "role": "outcome", "label": "the marker runs", "excerpt": None}], "marks": []}


def test_a_presentation_the_verifier_composed_goes_back_to_the_agent_and_is_rendered_again():
    ctx, res, *_ = pair([CLEAR, _revision(STRICT), CLEAR])
    res.poc["presentation"] = {"composed_by": "verifier", "reason": "the test agent composed no presentation"}
    calls = []

    def represent(presentation):
        calls.append(presentation)
        res.poc["presentation"] = {"composed_by": "test-agent", "summary": presentation["summary"]}

    ctx.represent = represent
    review_finding([(ctx, res)])
    assert calls == [pres.normalized(STRICT)]
    assert res.evidence_review["status"] == "clear" and res.evidence_review["rounds"] == 1
    assert ctx.budget.requests == 0


def test_a_revised_presentation_the_code_refuses_changes_nothing_and_the_loop_stops():
    ctx, res, *_ = pair([CLEAR, _revision(STRICT), CLEAR, _revision(STRICT), CLEAR])
    res.poc["presentation"] = {"composed_by": "verifier", "reason": "the test agent composed no presentation"}
    ctx.represent = lambda presentation: "step 1 is not a recorded request"
    review_finding([(ctx, res)])
    assert res.poc["presentation"]["composed_by"] == "verifier"
    assert res.evidence_review["status"] == "needs-attention"
    assert res.evidence_review["reason"] == "Repeated issues without improvement; correction loop stopped."


def test_the_revision_schema_takes_a_presentation_or_null():
    base = {"explanation": "x", "quotes": [], "page": None}
    validator = Draft202012Validator(REVISION_SCHEMA)
    assert validator.is_valid({**base, "presentation": None}) and validator.is_valid({**base, "presentation": STRICT})
    assert not validator.is_valid(base)


def test_present_replaces_the_images_and_excerpts_unless_nothing_usable_remains(tmp_path):
    result, _, browser, _, ctx = _probe(tmp_path, _verdict(None))
    before = copy.deepcopy(result.poc)
    unusable = _good(steps=[{"step": 9, "role": "attack", "label": "not a request"}], marks=[])
    assert ctx.represent(unusable) == "none of the steps the verdict rests on remains in its presentation"
    assert result.poc == before
    assert ctx.represent(_good(steps=[_good()["steps"][1]])) is None
    assert result.poc["presentation"] == {"composed_by": "test-agent", "summary": SUMMARY, "not_shown": [3]}
    assert [(s["step"], s.get("composed_by")) for s in result.poc["shown"]] == [(2, None), (3, "verifier")]
    assert ctx.represent(_good()) is None
    assert result.poc["presentation"] == {"composed_by": "test-agent", "summary": SUMMARY}
    assert [e["composed_by"] for e in result.evidence if e.get("kind") == "screenshot"] == ["test-agent"]
    assert not any(o.startswith(pres.COMPOSED_NOTE) for o in result.observations)
    assert "Outcome" in browser.pages[-1]


# ── the report keeps model text fenced; the schema takes both forms ─────────


def _row(result):
    from dataclasses import asdict

    return {**asdict(result), "result_id": "VF-001", "finding_ref": {"id": "T-001", "title": "Missing ownership"}}


def test_the_report_fences_the_agent_s_words_and_states_why_the_verifier_composed(tmp_path):
    link = "[click](https://evil.example/x) ![i](https://evil.example/i.png)"
    result, _, _, _, _ = _probe(tmp_path, _verdict(_good(summary=SUMMARY + " " + link, steps=[
        {**_good()["steps"][0], "label": link}, _good()["steps"][1]])))
    text = to_markdown({"meta": {}, "results": [_row(result)]})
    assert "Test agent's account: " + SUMMARY in text and "Test agent: " + link in text
    fenced = [block for block in text.split("```") if link in block]
    assert len(fenced) == text.count(link)                                 # every copy inside a fence
    result, _, _, _, _ = _probe(tmp_path, _verdict(None))
    text = to_markdown({"meta": {}, "results": [_row(result)]})
    assert "Excerpts composed by the Verifier: the test agent composed no presentation." in text
    assert "**Other observations**" not in text


def test_the_report_names_what_was_left_out_and_shows_the_unshown_steps_as_the_verifier_s(tmp_path):
    wrong = _good(steps=[{**_good()["steps"][1], "excerpt": '"email":"alice@shop.test"'}], marks=[])
    result, _, _, _, _ = _probe(tmp_path, _verdict(None), _verdict(wrong), _verdict(wrong))
    text = to_markdown({"meta": {}, "results": [_row(result)]})
    assert ("the Verifier found each in the record. It left out the excerpt of step 2, which is not an exact quote "
            "from its recorded answer. After them follow, as the Verifier shows them, the steps the verdict also rests "
            "on that the test agent left out: 3.") in text
    rows = {s["step"]: s for s in result.poc["shown"]}
    assert rows[3]["composed_by"] == "verifier" and f"Test agent: {rows[3]['role_label']}" not in text
    assert f"· step 3** ({rows[3]['role_label']})" in text and "Test agent: another customer reads it too" in text


def test_the_verification_schema_takes_either_presentation():
    schema = yaml.safe_load((Path(__file__).resolve().parent.parent / "schemas" / "verification.schema.yaml")
                            .read_text())
    poc = schema["properties"]["results"]["items"]["properties"]["poc"]
    shown = {"step": 2, "request": "GET /", "response": "HTTP/1.1 200 OK", "role": "outcome"}
    for presentation in ({"composed_by": "test-agent", "summary": SUMMARY},
                         {"composed_by": "test-agent", "summary": SUMMARY, "not_shown": [3],
                          "left_out": ["the excerpt of step 2, which is not an exact quote from its recorded answer"]},
                         {"composed_by": "verifier", "reason": "the test agent composed no presentation"}):
        Draft202012Validator(poc).validate({"file": None, "steps": [], "shown": [shown],
                                            "presentation": presentation})
    assert not Draft202012Validator(poc).is_valid({"file": None, "steps": [], "shown": [],
                                                   "presentation": {"composed_by": "model"}})
