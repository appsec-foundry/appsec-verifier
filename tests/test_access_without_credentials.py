"""The comparison without credentials (VER-057): a request without credentials gets an account's answer, while a
random path next to it does not. The Verifier sends the three reads itself and compares them in code; only the answer
without credentials, which anyone can read, is kept and shown to the model, the other two are not."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from test_agent_tools import Resp, _ctx
from test_experiments import STRATEGY

from appsec_verifier.agent import AgentProbe
from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.experiments import access_methods, comparison_path
from appsec_verifier.agent.prompts import _system
from appsec_verifier.agent.proof import check_proof
from appsec_verifier.agent.steps import _offered_schema
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.loader import load_verifiable_cwes
from appsec_verifier.verify.probes import ProbeResult

MARKER = ("vrf1a2b3c4d", "5e6f7a8b")
PATH = "/rest/admin/application-configuration"
CONTROL = "/rest/admin/vrf1a2b3c4d00ff00ff"
SECRET = '{"config":{"server":{"secret":"s3cr3t-config-value"}}}'
IDENTITIES = [{"role": "account-1", "method": "bearer", "auth": {"token_env": "A"}},
              {"role": "admin-1", "method": "bearer", "auth": {"token_env": "C"}, "privileged": True}]
ENV = {"A": "token-account-1", "C": "token-admin-1"}


# ── the proof check ───────────────────────────────────────────────────────────

def _plan_step(**extra):
    args = {"kind": "access-control", "hypothesis": "The configuration is served without a login", "path": PATH,
            "strategy": copy.deepcopy(STRATEGY), "signed_in": "account-1", **extra}
    return {"tool": "plan_test", "args": args,
            "result": {"accepted": True, "experiment": {**args, "control_path": CONTROL}}}


def _read(role, body, status=200, path=PATH, identity=None, comparison=True):
    args = {"path": path, "method": "GET", **({"role": role} if role else {}),
            **({"comparison": True} if comparison else {})}
    return {"tool": "http_request", "args": args, "experiment": comparison,
            "result": {"role": role, "status": status, "length": len(body), "body_sha256": None,
                       "body_withheld": True},
            "_response": {"body": "[withheld]", "complete": True, "identity": identity or role or "anonymous",
                          "digest": f"d:{body}"}}


def comparison(anonymous=SECRET, anonymous_status=200, control="<h1>404</h1>", control_status=404, signed=SECRET):
    return [_plan_step(), _read("account-1", signed), _read(None, anonymous, anonymous_status),
            _read(None, control, control_status, path=CONTROL)]


def _check(history, verdict="confirmed", cited=None, scope=None, cwe="CWE-306"):
    history = copy.deepcopy(history)
    responses = {n: h.pop("_response") for n, h in enumerate(history, 1) if "_response" in h}
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-1", cls="access-control", cwe=cwe), scope=scope or {},
                          identities=[{"role": "account-1"}], marker=MARKER, responses=responses, sessions=None,
                          evidence_dir=None)
    if cited is None:
        cited = [n for n, h in enumerate(history, 1) if h["tool"] == "http_request"]
    return check_proof(ctx, history, ProbeResult(verdict=verdict, confidence="high", rationale="claim"), cited)


def _change(history, step, **changes):
    history = copy.deepcopy(history)
    for key, value in changes.items():
        if key in ("identity",):
            history[step]["_response"][key] = value
        else:
            history[step]["args"][key] = value
    return history


def test_the_account_answer_without_credentials_confirms_at_medium():
    result = _check(comparison())
    assert result.verdict == "confirmed" and result.confidence == "medium", result.rationale
    assert "taken from the finding" in result.proof["scope"] and "not kept" in result.proof["scope"]
    assert result.proof["tested_path"] == PATH


def test_a_random_path_answered_with_another_page_still_confirms():
    """A 200 not-found page differs from the account's answer; only the identical answer marks a catch-all."""
    assert _check(comparison(control="<html>not found</html>", control_status=200)).verdict == "confirmed"


@pytest.mark.parametrize("history, reason", [
    (comparison(control=SECRET, control_status=200), "answers every path alike"),       # a catch-all, e.g. an SPA
    (comparison(anonymous_status=401, anonymous='{"error":"login"}'), "did not receive the identical answer"),
    (comparison(anonymous='{"config":{}}'), "did not receive the identical answer"),     # a reduced public view
    (comparison(signed=""), "was not answered with content"),
    (_change(comparison(), 2, identity="account-1"), "did not receive the identical answer"),   # the same session
    (_change(comparison(), 2, comparison=False), "cite only the comparison"),            # the agent's own request
    (comparison()[:3], "random path next to the finding's"),
    (comparison()[:2] + comparison()[3:], "cite the request without credentials"),
    ([{**_plan_step(), "result": {"accepted": True}}, *comparison()[1:]], "no random path of the Verifier"),
])
def test_a_comparison_without_the_full_contrast_stays_inconclusive(history, reason):
    result = _check(history)
    assert result.verdict == "inconclusive" and reason in result.rationale


@pytest.mark.parametrize("verdict", ["not-reproducible", "blocked-by-control"])
def test_the_comparison_supports_no_negative_verdict(verdict):
    result = _check(comparison(anonymous_status=401, anonymous='{"error":"login"}'), verdict=verdict)
    assert result.verdict == "inconclusive" and "only confirms" in result.rationale


def test_the_steps_the_feedback_reported_stand_in_for_a_wrong_citation():
    history = comparison() + [{"tool": "experiment", "args": {}, "result": {"proof": "holds", "steps": [2, 3, 4]}}]
    assert _check(history, cited=[2, 3]).verdict == "confirmed"
    assert _check(comparison(), cited=[2, 3]).verdict == "inconclusive"       # no feedback said it holds


def test_an_operator_resource_takes_precedence():
    resource = {"id": "config", "finding_id": "T-1", "path": PATH, "allowed_roles": ["account-1"],
                "denied_roles": ["anonymous"], "pointer": "", "value": "s3cr3t"}
    result = _check(comparison(), scope={"test_resources": [resource]})
    assert result.verdict == "inconclusive" and "takes precedence" in result.rationale


# ── which findings and runs it serves ─────────────────────────────────────────

def test_exposure_cwes_are_access_control_findings():
    catalog = load_verifiable_cwes()
    for cwe in ("CWE-497", "CWE-530", "CWE-538", "CWE-548", "CWE-552"):
        assert catalog[cwe]["class"] == "access-control" and catalog[cwe]["technique"] == "information-exposure"
    assert "CWE-532" not in catalog and "CWE-258" not in catalog


@pytest.mark.parametrize("cwe, identities, expected", [
    ("CWE-306", [{"role": "a"}], ["signed_in"]),
    ("CWE-548", [{"role": "admin", "privileged": True}], ["signed_in"]),
    ("CWE-200", [], []),
    ("CWE-862", [{"role": "a"}], ["signed_in"]),
    ("CWE-862", [{"role": "a"}, {"role": "admin", "privileged": True}], ["reference", "signed_in"]),
    ("CWE-639", [{"role": "a"}, {"role": "admin", "privileged": True}], []),       # an IDOR: another's record
])
def test_any_account_allows_the_comparison_except_for_an_idor(cwe, identities, expected):
    assert access_methods("T-1", cwe, {}, identities, writes=False) == expected


@pytest.mark.parametrize("path, expected", [
    ("/metrics", "/X"), ("/rest/admin/config", "/rest/admin/X"), ("/ftp/", "/X/"),
    ("/encryptionkeys/jwt.pub", "/encryptionkeys/X"), ("/", "/X"),
])
def test_the_random_path_sits_next_to_the_finding(path, expected):
    assert comparison_path(path, "X") == expected


# ── what plan_test accepts ────────────────────────────────────────────────────

def _tools(tmp_path, *, cwe="CWE-306", identities=IDENTITIES, transport=None):
    ctx = _ctx(tmp_path, transport or (lambda *a, **k: Resp()), env=ENV, idents=identities)
    ctx.marker = MARKER
    ctx.plan = replace(ctx.plan, cwe=cwe, endpoints=(Endpoint("GET", PATH, None),))
    return AgentTools(ctx)


def _args(**extra):
    return {k: v for k, v in _plan_step(**extra)["args"].items()}


def test_a_comparison_plan_is_accepted_in_safe_mode_and_gets_a_fresh_random_path(tmp_path):
    tools = _tools(tmp_path)
    first, second = tools.plan_test(**_args()), tools.plan_test(**_args(signed_in="admin-1"))
    paths = [r["experiment"]["control_path"] for r in (first, second)]
    assert all(p.startswith("/rest/admin/" + MARKER[0]) for p in paths) and paths[0] != paths[1]
    assert first["accepted"] is True and "marker" not in first


@pytest.mark.parametrize("cwe, plan, reason", [
    ("CWE-306", {"path": "/rest/admin/:name"}, "one concrete GET"),
    ("CWE-306", {"path": PATH + "?x=1"}, "one concrete GET"),
    ("CWE-306", {"signed_in": "nobody"}, "account of this run"),
    ("CWE-306", {"fixed": {"json": {"a": "b"}}}, "fixed may give params only"),
    ("CWE-306", {"method": "POST"}, "read with GET"),
    ("CWE-639", {}, "other than an IDOR"),
])
def test_plan_test_refuses_a_comparison_the_run_cannot_send(tmp_path, cwe, plan, reason):
    with pytest.raises(ToolError, match=reason):
        _tools(tmp_path, cwe=cwe).plan_test(**_args(**plan))


def test_an_exposure_finding_offers_no_other_plan_and_no_own_requests(tmp_path):
    tools = _tools(tmp_path)
    reference = {k: v for k, v in _args().items() if k != "signed_in"} | {"reference": "admin-1"}
    with pytest.raises(ToolError, match="proven with signed_in"):
        tools.plan_test(**reference)
    with pytest.raises(ToolError, match="exposure checks use only the operator-declared .* signed_in"):
        tools.http_request(role="account-1", path=PATH)


# ── what the Verifier sends and keeps ─────────────────────────────────────────

def test_only_the_answer_without_credentials_is_kept_and_only_the_plan_sends_a_request(tmp_path):
    """Refused case: the account's answer and the random path's keep no body anywhere; the answer without
    credentials to the finding's path is kept and shown like any other response."""
    tools = _tools(tmp_path, transport=lambda *a, **k: Resp(200, SECRET))
    with pytest.raises(ToolError, match="one the accepted comparison sends"):
        tools.http_request(path=PATH, comparison=True)                        # no accepted plan yet
    plan = tools.plan_test(**_args())["experiment"]
    requests = tools.experiment_requests()
    assert [(r["path"], r.get("role")) for r in requests] == [(PATH, "account-1"), (PATH, None),
                                                              (plan["control_path"], None)]
    seen = []
    for request in requests:
        out = tools.http_request(**request)
        seen.append((out, tools.take_response(), tools.take_exchanges()))
    (account, _, account_record), (anonymous, response, record), (control, _, control_record) = seen
    assert anonymous["status"] == 200 and "body_withheld" not in anonymous and "s3cr3t" in anonymous["body_excerpt"]
    assert "s3cr3t" in response["body"] and "s3cr3t" in record[0]["response"]["content"]["text"]
    for out, kept in ((account, account_record), (control, control_record)):
        assert out["body_withheld"] is True and out["length"] == len(SECRET)
        assert "s3cr3t" not in json.dumps([out, kept])
        assert kept[0]["response"]["content"]["_omitted"].startswith("body not kept: compared in code only")
    with pytest.raises(ToolError, match="one the accepted comparison sends"):
        tools.http_request(path="/rest/admin/other", comparison=True)
    with pytest.raises(ToolError, match="one the accepted comparison sends"):
        tools.http_request(path=plan["control_path"], role="account-1", comparison=True)
    with pytest.raises(ToolError, match="already ran"):
        tools.experiment_requests(write=True)
    tools.plan_test(**_args(fixed={"params": {"format": "json"}}))
    assert all(r["params"] == {"format": "json"} for r in tools.experiment_requests())


def test_the_agent_cannot_mark_its_own_request_as_part_of_the_comparison():
    from appsec_verifier.agent.steps import _ARG_VALIDATORS

    assert not _ARG_VALIDATORS["http_request"].is_valid({"path": PATH, "comparison": True})
    assert not _ARG_VALIDATORS["plan_test"].is_valid({**_args(), "control_path": "/anything"})


def test_only_the_comparison_reaches_the_random_path(tmp_path):
    ctx = _tools(tmp_path).ctx
    c = Controller(ctx)
    c.plan = {"kind": "access-control", "path": PATH, "signed_in": "account-1", "control_path": CONTROL}
    c.before("http_request", {"path": CONTROL, "comparison": True})
    with pytest.raises(ToolError, match="no matching route"):
        c.before("http_request", {"path": CONTROL})                           # the agent's own request
    with pytest.raises(ToolError, match="read once without credentials"):
        c.before("http_request", {"path": CONTROL, "role": "account-1", "comparison": True})
    with pytest.raises(ToolError, match="out of scope"):
        c.plan = {**c.plan, "control_path": "https://elsewhere.example.org/x"}
        c.before("http_request", {"path": "https://elsewhere.example.org/x", "comparison": True})


# ── through the loop ──────────────────────────────────────────────────────────

def _run(tmp_path, transport, verdict_steps=(2, 3, 4), browser=None, presentation=None):
    sent = []

    def recording(m, u, h, **k):
        sent.append((m, urlsplit(u).path, h.get("Authorization")))
        return transport(m, urlsplit(u).path, h)

    class Planner:
        def __init__(self):
            self.seen = []

        def next_step(self, ctx, history):
            self.seen.append(json.dumps(history, default=str))
            if not history:
                return {"tool": "plan_test", "args": _args()}
            return {"verdict": {"verdict": "confirmed", "rationale": "served without login",
                                "proof_steps": list(verdict_steps),
                                **({"presentation": presentation} if presentation else {})}}

    planners = []

    def factory():
        planners.append(Planner())
        return planners[-1]

    ctx = _ctx(tmp_path, recording, env=ENV, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, cwe="CWE-306", endpoints=(Endpoint("GET", PATH, None),))
    ctx.marker = MARKER
    ctx.evidence_dir = tmp_path / "evidence"
    ctx.browser = browser
    result = AgentProbe("access-control", factory).run(ctx)
    return result, sent, planners[0].seen


def test_a_configuration_served_without_login_is_confirmed_and_shows_what_anyone_can_read(tmp_path):
    def target(m, path, h):
        return Resp(200, SECRET) if path == PATH else Resp(404, "<h1>Not found</h1>")

    result, sent, seen = _run(tmp_path, target)
    assert result.verdict == "confirmed" and result.confidence == "medium", result.rationale
    assert [(m, p, a) for m, p, a in sent] == [("GET", PATH, "Bearer token-account-1"), ("GET", PATH, None),
                                              ("GET", sent[2][1], None)]
    assert sent[2][1].startswith("/rest/admin/" + MARKER[0])
    history = json.loads(seen[-1])
    assert "s3cr3t" not in json.dumps(history[1]) and history[1]["result"]["body_withheld"] is True   # the account
    assert "s3cr3t" in history[2]["result"]["body_excerpt"]                       # without credentials: shown
    feedback = history[4]
    assert feedback["tool"] == "experiment" and "step 3, the answer without credentials" in feedback["result"]["next"]
    har = json.loads(next(Path(tmp_path / "evidence").glob("*-poc.har")).read_text())
    kept = {e["_step"]: "s3cr3t" in (e["response"]["content"].get("text") or "") for e in har["log"]["entries"]}
    assert kept == {2: False, 3: True, 4: False}
    assert not any("Application screenshot unavailable: the compared answers" in o for o in result.observations)


def test_the_agent_can_quote_the_answer_without_credentials_but_not_the_account_s(tmp_path):
    """VER-057 with VER-059: the readable answer can be shown in the presentation; the account's, never kept, cannot."""
    def target(m, path, h):
        return Resp(200, SECRET) if path == PATH else Resp(404, "<h1>Not found</h1>")

    def presentation(step):
        return {"summary": "Without a login anyone reads the server secret from the admin configuration.",
                "steps": [{"step": 2, "role": "normal", "label": "the signed-in account reads the configuration"},
                          {"step": 3, "role": "outcome", "label": "the same answer without a login",
                           **({"excerpt": '"secret":"s3cr3t-config-value"'} if step == 3 else {})},
                          {"step": 4, "role": "control", "label": "a random path next to it: not found",
                           **({"excerpt": '"secret":"s3cr3t-config-value"'} if step == 2 else {})}]}

    result, _, _ = _run(tmp_path, target, presentation=presentation(3))
    assert result.poc["presentation"]["composed_by"] == "test-agent"
    shown = {s["step"]: s for s in result.poc["shown"]}
    assert "s3cr3t-config-value" in shown[3]["response_excerpt"] and "s3cr3t" not in shown[2]["response_excerpt"]
    refused = presentation(2)
    refused["steps"][0]["excerpt"] = '"secret":"s3cr3t-config-value"'          # the account's answer
    result, _, _ = _run(tmp_path, target, presentation=refused)
    assert result.poc["presentation"]["composed_by"] == "verifier"
    assert "the answer of step 2 is withheld or not kept" in result.poc["presentation"]["reason"]


def test_a_target_that_answers_every_path_alike_confirms_nothing(tmp_path):
    result, _, seen = _run(tmp_path, lambda m, path, h: Resp(200, "<html><app-root></app-root></html>"))
    assert result.verdict == "inconclusive" and "answers every path alike" in result.rationale
    assert '"proof": "missing"' in seen[-1]


def test_a_refused_request_without_credentials_confirms_nothing(tmp_path):
    def target(m, path, h):
        return Resp(200, SECRET) if h.get("Authorization") else Resp(401, '{"error":"login"}')

    result, _, _ = _run(tmp_path, target)
    assert result.verdict == "inconclusive" and "identical answer" in result.rationale


# ── what the model is told ────────────────────────────────────────────────────

def test_the_prompt_offers_the_comparison_to_access_control_only(tmp_path):
    ctx = _tools(tmp_path).ctx
    text = _system(ctx)
    assert "Comparison without credentials" in text and "your own requests reach only a configured" in text
    plan_test = {"name": "plan_test", "input_schema": {"properties": {"signed_in": {}, "kind": {}}}}
    assert "signed_in" in _offered_schema(plan_test, ctx)["properties"]
    injection = SimpleNamespace(plan=SimpleNamespace(cls="injection", cwe="CWE-89"))
    assert "signed_in" not in _offered_schema(plan_test, injection)["properties"]


def test_a_confirmed_comparison_reads_as_the_same_answer_on_the_console_in_the_report_and_image(tmp_path):
    """T-058 (run 133): the comparison's answers are compared in code, so every place that shows the proof says the
    answer without credentials was the same as the account's, never a different one or one not recorded."""
    from appsec_verifier.verify.probes import proof_shown
    from appsec_verifier.verify.report import _shown

    pages = []
    browser = SimpleNamespace(screenshots=("access-control",),
                              render_exchanges=lambda html, name, marked: pages.append(html) or [])

    def target(m, path, h):
        return Resp(200, SECRET) if path == PATH else Resp(404, "<h1>Not found</h1>")

    result, _, _ = _run(tmp_path, target, browser=browser)
    assert result.verdict == "confirmed" and result.proof["form"] == "comparison-without-credentials"
    assert proof_shown(result.proof, "access-control")[0] == "same answer without credentials, unlike a random path"
    facts = [f for s in result.poc["shown"] for f in s["facts"]]
    assert any("same status 200, the identical answer, compared in code over the whole body" in f for f in facts)
    page = "".join(pages)
    assert "without login, and without login to a random path next to it" in page           # the Test line
    assert "without login: 200, the same answer" in page                                    # the Result line
    assert "a different answer" not in page and "not recorded to compare" not in page
    shown = _shown({"verdict": "confirmed", "class": "access-control", "proof": result.proof, "poc": result.poc})
    assert shown.startswith("Without a login the same answer as account-1, compared in code") and "404" in shown


def test_a_comparison_whose_answers_differ_says_so_and_one_without_digests_is_not_called_different():
    from appsec_verifier.verify import poc

    entry = {"_step": 3, "response": {"status": 200, "content": {"_omitted": True}}}
    ref = (2, {"_step": 2, "response": {"status": 200, "content": {"_omitted": True}}})
    ctx = SimpleNamespace(plan=SimpleNamespace(cls="access-control"),
                          responses={2: {"digest": "a"}, 3: {"digest": "b"}})
    assert poc.difference(ctx, [], entry, ref).endswith("a different answer, compared in code over the whole body, "
                                                        "which is not kept.")
    ctx.responses = {}
    assert poc.difference(ctx, [], entry, ref).endswith("the answers are not recorded to compare.")


# ── technical QA's one follow-up on a resource meant to be public (VER-046) ─────

KEYS = "/keys/:file"
PUBLIC_RESOURCE = {"code": "public-resource", "detail": "public.pub is a public key; the finding names secret keys",
                   "question": "Is /keys/secret.key served without a login?"}
INTENDED = {"code": "interpretation", "detail": "the key may be shared on purpose", "question": "Is it?"}


def _qa_run(tmp_path, *, secret_exposed, replies, second_verdict="inconclusive"):
    from test_technical_review import scripted_factory

    def target(method, url, headers, **kwargs):
        path, signed = urlsplit(url).path, headers.get("Authorization") == "Bearer token-account-1"
        if path == "/keys/public.pub":
            return Resp(200, "-----BEGIN PUBLIC KEY-----")
        if path == "/keys/secret.key":
            return Resp(200, "secret-key-bytes") if signed or secret_exposed else Resp(401, "unauthorized")
        return Resp(404, "<h1>Not found</h1>")

    def plan(path):
        return {"tool": "plan_test", "args": {**_args(), "path": path, "hypothesis": "keys are served without login"}}

    def verdict(kind):
        return {"verdict": {"verdict": kind, "rationale": f"{kind} on the comparison", "proof_steps": []}}

    actions = [plan("/keys/public.pub"), verdict("confirmed"), plan("/keys/secret.key"), verdict(second_verdict)]
    factory, host, _, histories = scripted_factory(actions, replies)
    ctx = _ctx(tmp_path, target, env=ENV, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, cwe="CWE-306", endpoints=(Endpoint("GET", KEYS, None),))
    ctx.marker = MARKER
    return AgentProbe("access-control", factory).run(ctx), host, histories, actions


def _review(*issues):
    return {"action": "review", "status": "needs-attention" if issues else "clear", "issues": list(issues),
            "steps": [], "pointer": None, "offset": 0}


def test_qa_sends_a_public_resource_objection_back_once_and_a_checked_confirmation_replaces_the_first(tmp_path):
    """T-058 (run 133): QA holds jwt.pub public while the finding names secret keys. That objection alone returns to
    the test agent; the comparison on the protected resource confirms, and that confirmation is the result."""
    result, host, histories, _ = _qa_run(tmp_path, secret_exposed=True, second_verdict="confirmed",
                                         replies=[_review(PUBLIC_RESOURCE, INTENDED), _review()])
    assert result.verdict == "confirmed" and result.proof["tested_path"] == "/keys/secret.key"
    feedback = [h for h in histories[-1] if h["tool"] == "qa_feedback"]
    assert len(feedback) == 1 and feedback[0]["result"]["issues"] == [PUBLIC_RESOURCE]   # only that objection
    assert [call[1]["public_resource_follow_up"] for call in host.calls] == [True, False]
    assert result.technical_review["status"] == "clear" and result.technical_review["rounds"] == 1


def test_a_follow_up_without_a_checked_confirmation_leaves_the_first_one_and_its_objection(tmp_path):
    """The protected resource is refused without a login: the agent's inconclusive follow-up does not change the
    code-checked verdict; the objection stays beside it and the follow-up's outcome is recorded."""
    result, _, _, _ = _qa_run(tmp_path, secret_exposed=False, replies=[_review(PUBLIC_RESOURCE)])
    assert result.verdict == "confirmed" and result.proof["tested_path"] == "/keys/public.pub"
    assert result.technical_review["status"] == "needs-attention"
    assert result.technical_review["issues"] == [PUBLIC_RESOURCE]
    assert any(o.startswith("Technical QA follow-up on a protected resource ended without a checked confirmation")
               for o in result.observations)
    import yaml
    from jsonschema import Draft202012Validator

    schema = yaml.safe_load(Path("schemas/verification.schema.yaml").read_text())
    Draft202012Validator(schema["$defs"]["technical_review"]).validate(result.technical_review)


def test_no_other_objection_and_no_second_public_resource_objection_starts_a_test(tmp_path):
    """Refused cases: an objection that the access is intended stays beside the verdict without a test, and a
    public-resource objection to the follow-up's own confirmation is not sent back a second time."""
    result, _, histories, actions = _qa_run(tmp_path, secret_exposed=True, replies=[_review(INTENDED)])
    assert result.verdict == "confirmed" and result.proof["tested_path"] == "/keys/public.pub"
    assert result.technical_review["rounds"] == 0 and len(actions) == 2          # the follow-up never ran
    assert not any(h["tool"] == "qa_feedback" for h in histories[-1])
    result, _, _, _ = _qa_run(tmp_path, secret_exposed=True, second_verdict="confirmed",
                              replies=[_review(PUBLIC_RESOURCE), _review(PUBLIC_RESOURCE)])
    assert result.verdict == "confirmed" and result.proof["tested_path"] == "/keys/secret.key"
    assert result.technical_review["rounds"] == 1 and result.technical_review["status"] == "needs-attention"
