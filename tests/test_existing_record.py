"""VER-067: prove a read of a record an account already has, shown by its user name or its collection's list,
without writes."""
from __future__ import annotations

import base64
import copy
import io
import json
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from test_agent_tools import Resp, _ctx
from test_endpoints import _blocker, _plan
from test_experiments import STRATEGY

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.experiments import access_methods, existing_collection
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.prompts import _system
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.loader import plans_from

USERS = {"1": "alice@example.com", "2": "bob@example.com", "3": "carol@example.com"}
NAMED = [{"role": "account-1", "method": "basic", "auth": {"username_env": "U1", "password_env": "P1"}},
         {"role": "account-2", "method": "basic", "auth": {"username_env": "U2", "password_env": "P2"}},
         {"role": "admin-1", "method": "basic", "auth": {"username_env": "U3", "password_env": "P3"},
          "privileged": True}]
ENV = {"U1": USERS["1"], "P1": "pw-account-1", "U2": USERS["2"], "P2": "pw-account-2", "U3": USERS["3"],
       "P3": "pw-admin-1"}
TOKENS = [{"role": "account-1", "method": "bearer", "auth": {"token_env": "A"}},
          {"role": "account-2", "method": "bearer", "auth": {"token_env": "B"}}]


def document(path="/api/users/:id"):
    return {"threats": [{"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "Read another user's record",
                         "scenario": f"GET {path}", "evidence": {"file": "routes/users.ts", "line": 20}}]}


def requester(headers):
    value = headers.get("Authorization", "")
    if not value.startswith("Basic "):
        return None
    user = base64.b64decode(value[6:]).decode().split(":", 1)[0]
    return next(i for i, name in USERS.items() if name == user)


REFUSALS = {"protected": 403, "refused": 400, "limited": 429}


def target(kind):
    """A fake user API: `kind` decides what another account's read of the owner's record gets."""
    def transport(method, url, headers, **kw):
        assert method == "GET", "the existing-record proof only reads"
        record = url.rsplit("/", 1)[1]
        me = requester(headers)
        if me is None and kind != "public":
            return Resp(401, '{"error":"login required"}')
        if kind in REFUSALS and me != record:
            return Resp(REFUSALS[kind], '{"error":"Malicious activity detected."}')
        if kind == "own-only" and me != record:
            record = me
        if kind == "list":
            return Resp(200, json.dumps({"data": [{"id": i, "email": e} for i, e in USERS.items()]}))
        body = {"id": int(record), "plan": "basic"} if kind == "unnamed" else {"id": int(record),
                                                                              "email": USERS[record]}
        if kind == "viewer":
            body["viewer"] = USERS[me]
        return Resp(200, json.dumps({"status": "success", "data": body}))
    return transport


def context(tmp_path, transport, *, identities=NAMED, safe=True, path="/api/users/:id"):
    ctx = _ctx(tmp_path, transport, safe=safe, read_only=safe, env=ENV | {"A": "token-1", "B": "token-2"},
               idents=copy.deepcopy(identities))
    ctx.plan, ctx.marker = plans_from(document(path))[0], ("vrf1a2b3c4d", "5e6f7a8b")
    ctx.assume_restrictions = True
    ctx.budget = ctx.http._budget
    ctx.evidence_dir = tmp_path / "evidence"
    return ctx


PLAN = {"kind": "access-control", "existing": "account-1", "path": "/api/users/:id",
        "hypothesis": "Another account reads the owner's profile by its id", "strategy": STRATEGY}
READS = [{"tool": "http_request", "args": {"path": "/api/users/1", **({"role": role} if role else {})}}
         for role in ("account-1", None, "account-2")] + [
    {"tool": "http_request", "args": {"path": "/api/users/2", "role": "account-2"}}]


def run(ctx, verdict, steps=None):
    steps = [{"tool": "plan_test", "args": PLAN}, *READS] if steps is None else steps

    class Planner:
        def next_step(self, ctx, history):
            if len(history) < len(steps):
                return copy.deepcopy(steps[len(history)])
            if history[-1].get("tool") == "proof_feedback":
                return {"verdict": {"verdict": "inconclusive", "rationale": "the proof check did not accept it"}}
            return {"verdict": {"verdict": verdict, "rationale": "Compare the owner's existing record",
                                "proof_steps": list(range(2, len(steps) + 1))}}

    return AgentProbe("access-control", Planner, max_steps=10).run(ctx)


def test_another_account_reading_a_record_that_names_its_owner_confirms_in_safe_mode(tmp_path):
    ctx = context(tmp_path, target("vulnerable"))
    result = run(ctx, "confirmed")
    assert (result.verdict, result.confidence) == ("confirmed", "medium"), result.rationale
    assert result.proof["form"] == "named-record"
    assert result.proof["access_restriction"]["assumed"] is True
    assert result.proof["access_restriction"]["allowed_roles"] == ["account-1"]
    assert "nothing was created" in result.proof["scope"]


@pytest.mark.parametrize("kind,why", [
    ("public", "visible without a login"),
    ("list", "names its user name and no other account's"),
    ("unnamed", "names its user name and no other account's"),
    ("viewer", "identical answer"),
])
def test_a_record_that_does_not_single_out_its_owner_confirms_nothing(tmp_path, kind, why):
    """Public, naming every account, naming none, or naming whoever asks: the record is not shown to be the owner's,
    or the other account did not get the owner's answer."""
    ctx = context(tmp_path, target(kind))
    result = run(ctx, "confirmed")
    assert result.verdict == "inconclusive"
    assert why in result.rationale


def test_the_other_accounts_own_record_must_name_it(tmp_path):
    steps = [{"tool": "plan_test", "args": PLAN}, *READS[:3]]
    result = run(context(tmp_path, target("vulnerable")), "confirmed", steps)
    assert result.verdict == "inconclusive"
    assert "read of its own record must name its user name" in result.rationale


@pytest.mark.parametrize("kind,verdict", [("protected", "blocked-by-control"), ("refused", "blocked-by-control"),
                                          ("own-only", "not-reproducible")])
def test_a_refused_or_different_answer_for_the_other_account_is_a_negative_verdict(tmp_path, kind, verdict):
    """A 400 refuses the owner's record as 403 does, because the same request returns the other account's own."""
    result = run(context(tmp_path, target(kind)), verdict)
    assert (result.verdict, result.confidence) == (verdict, "medium"), result.rationale


def test_a_client_error_refuses_only_with_the_other_accounts_own_record_and_never_a_rate_limit(tmp_path):
    result = run(context(tmp_path, target("refused")), "blocked-by-control",
                 [{"tool": "plan_test", "args": PLAN}, *READS[:3]])
    assert result.verdict == "inconclusive"
    assert "together with that account's answered read of its own record" in result.rationale
    result = run(context(tmp_path, target("limited")), "blocked-by-control")
    assert result.verdict == "inconclusive"


def test_a_negative_verdict_is_refused_when_the_other_account_got_the_record(tmp_path):
    result = run(context(tmp_path, target("vulnerable")), "not-reproducible")
    assert result.verdict == "inconclusive"
    assert "present for the other account" in result.rationale


CARDS = {"5": "Bearer token-1", "6": "Bearer token-2"}         # card id: the session of the account that owns it


def cards(kind):
    """A fake card API for accounts without a user name: GET /api/cards lists the caller's own cards; `kind` decides
    what another account's read of a card gets."""
    def transport(method, url, headers, **kw):
        assert method == "GET", "the existing-record proof only reads"
        me, path = headers.get("Authorization"), urlsplit(url).path
        if me is None and kind != "public":
            return Resp(401, '{"error":"login required"}')
        if path == "/api/cards":
            items = [{"id": int(i), "last4": "4242"} for i, owner in CARDS.items() if kind == "unscoped" or owner == me]
            return Resp(200, json.dumps({"status": "success", "data": items}))
        card = path.rsplit("/", 1)[1]
        if kind in REFUSALS and CARDS.get(card) != me:
            return Resp(REFUSALS[kind], '{"status":"error","data":"Malicious activity detected."}')
        body = {"last4": "4242"} if kind == "static" else {"id": int(card), "last4": "4242", "UserId": CARDS[card][-1]}
        return Resp(200, json.dumps({"status": "success", "data": body}))
    return transport


CARD_PLAN = {**PLAN, "path": "/api/cards/:id", "hypothesis": "Another account reads the owner's card by its id"}
LISTS = [{"tool": "http_request", "args": {"path": "/api/cards", "role": role}} for role in ("account-1", "account-2")]
CARD_READS = [{"tool": "http_request", "args": {"path": "/api/cards/5", **({"role": role} if role else {})}}
              for role in ("account-1", None, "account-2")] + [
    {"tool": "http_request", "args": {"path": "/api/cards/6", "role": "account-2"}}]
CARD_STEPS = [{"tool": "plan_test", "args": CARD_PLAN}, *LISTS, *CARD_READS]


def card_context(tmp_path, kind):
    return context(tmp_path, cards(kind), identities=TOKENS, path="/api/cards/:id")


def test_a_record_only_the_owners_list_shows_confirms_for_accounts_without_a_user_name(tmp_path):
    """Run 149: a record that names its owner only by an internal id. Each account's list of the collection shows
    whose record it is, without a user name and in safe mode; the collection GET is sent under the plan."""
    result = run(card_context(tmp_path, "vulnerable"), "confirmed", CARD_STEPS)
    assert (result.verdict, result.confidence) == ("confirmed", "medium"), result.rationale
    assert result.proof["form"] == "listed-record"
    assert result.proof["access_restriction"]["assumed"] is True
    assert "nothing was created" in result.proof["scope"]


@pytest.mark.parametrize("kind,steps,why", [
    ("unscoped", CARD_STEPS, "does not hold it"),                    # a list every account gets alike
    ("vulnerable", [CARD_STEPS[0], LISTS[0], *CARD_READS], "does not hold it"),   # no list of the other account
    ("public", CARD_STEPS, "visible without a login"),
    ("static", CARD_STEPS, "with another answer"),                   # every identifier answers alike
])
def test_a_list_that_does_not_single_out_the_owner_confirms_nothing(tmp_path, kind, steps, why):
    result = run(card_context(tmp_path, kind), "confirmed", steps)
    assert result.verdict == "inconclusive"
    assert why in result.rationale


@pytest.mark.parametrize("kind,steps,verdict", [
    ("refused", CARD_STEPS, "blocked-by-control"),        # Juice's 400, with the other account's own card answered
    ("protected", CARD_STEPS, "blocked-by-control"),
    ("refused", CARD_STEPS[:-1], "inconclusive"),         # without the other account's own card
    ("limited", CARD_STEPS, "inconclusive"),              # a rate limit refuses nothing
])
def test_a_card_refused_to_the_other_account_is_blocked_by_control(tmp_path, kind, steps, verdict):
    result = run(card_context(tmp_path, kind), "blocked-by-control", steps)
    assert result.verdict == verdict, result.rationale


def test_one_round_of_proof_feedback_names_every_request_the_proof_cites(tmp_path):
    """Run 153: a negative verdict that cites a source read sent before the plan and lacks three reads. A check names
    only its first failing condition and a variant gets two repairs, so the feedback also names every request the
    proof cites, and the refusal the requests that can be cited."""
    source = {"tool": "read_source", "args": {"path": "routes/basket.ts"}}
    first = [source, CARD_STEPS[0], LISTS[0], CARD_READS[2], LISTS[1]]       # steps 1-5
    rest = [CARD_READS[0], CARD_READS[1], CARD_READS[3]]                      # owner's card, without login, own card
    feedback = []

    class Planner:
        queue = [*first, {"verdict": {"verdict": "blocked-by-control", "rationale": "card refused",
                                      "proof_steps": [1, 3, 4, 5]}}]
        final = None

        def next_step(self, ctx, history):
            if history and history[-1].get("tool") == "proof_feedback":
                feedback.append(history[-1]["result"])
                n = len(history)
                self.final = {"verdict": {"verdict": "blocked-by-control", "rationale": "card refused",
                                          "proof_steps": [3, 4, 5, n + 1, n + 2, n + 3]}}
                self.queue = [*rest, self.final]
            if not self.queue:
                return copy.deepcopy(self.final)                     # the presentation round repeats the verdict
            return copy.deepcopy(self.queue.pop(0))

    result = AgentProbe("access-control", Planner, max_steps=12).run(card_context(tmp_path, "refused"))
    assert (result.verdict, result.proof["form"]) == ("blocked-by-control", "listed-record"), result.rationale
    assert len(feedback) == 1
    assert "step 1 precedes the plan in step 2" in feedback[0]["missing"][0]
    assert feedback[0]["missing"][0].endswith("sent after its plan: steps 3-5")
    needs = feedback[0]["needs"]
    assert "account-1's and the other account's GET of /api/cards" in needs
    assert all(part in needs for part in ("account-1's read of its record", "the same read without a role",
                                          "another normal account's read of it", "its own record"))


ORIENTATION = [{"tool": "read_source", "args": {"path": "routes/basket.ts", "around_line": n}} for n in range(1, 7)]


class Run160:
    """Run 160: six source reads, the plan at step 7, both lists and the other account's read, a negative verdict
    the check refuses for three missing reads, then those reads and the verdict again."""
    calls = 0

    def __init__(self):
        self.queue = [*ORIENTATION, CARD_STEPS[0], LISTS[0], LISTS[1], CARD_READS[2],
                      {"verdict": {"verdict": "blocked-by-control", "rationale": "card refused",
                                   "proof_steps": [8, 9, 10]}}]
        self.final, self.plans, self.feedback = None, [], []

    def next_step(self, ctx, history):
        type(self).calls += 1
        last = history[-1] if history else {}
        if last.get("tool") == "plan_test":
            self.plans.append(last["result"])
        if last.get("tool") == "proof_feedback":
            self.feedback.append(last["result"])
            n = len(history)
            self.final = {"verdict": {"verdict": "blocked-by-control", "rationale": "card refused",
                                      "proof_steps": [8, 9, 10, n + 1, n + 2, n + 3]}}
            self.queue = [CARD_READS[0], CARD_READS[1], CARD_READS[3], self.final]
        if not self.queue:
            return copy.deepcopy(self.final)                     # the presentation round repeats the verdict
        return copy.deepcopy(self.queue.pop(0))


def test_a_plan_after_long_orientation_keeps_the_steps_its_proof_needs(tmp_path):
    """Run 160 (VER-015): with 12 steps the refused verdict at step 11 left one step for three missing reads. The
    first accepted plan keeps the steps its proof needs, its six requests plus three, here up to step 16, and its
    answer names every request the proof cites."""
    planners = []

    def factory():
        planners.append(Run160())
        return planners[-1]

    result = AgentProbe("access-control", factory, max_steps=12).run(card_context(tmp_path, "refused"))
    assert result.verdict == "blocked-by-control", result.rationale
    assert result.proof["form"] == "listed-record"
    agent = planners[0]
    assert agent.plans[0]["max_steps"] == 16
    assert "account-1's and the other account's GET of /api/cards" in agent.plans[0]["needs"]
    assert agent.feedback[0]["remaining_steps"] == 5


def test_steps_are_added_only_to_a_first_plan_whose_proof_would_not_fit(tmp_path):
    """Refused cases (VER-015): without a plan, and with a plan that leaves its proof enough steps, the bound stays;
    a revised plan adds none, so planning again gains no steps."""
    class Reader:
        calls = 0

        def __init__(self, plans=()):
            self.plans, self.results = dict(plans), []

        def next_step(self, ctx, history):
            type(self).calls += 1
            if history and history[-1].get("tool") == "plan_test":
                self.results.append(history[-1]["result"])
            if len(history) + 1 in self.plans:
                return {"tool": "plan_test", "args": self.plans[len(history) + 1]}
            return {"tool": "read_source", "args": {"path": "routes/basket.ts", "around_line": len(history) + 1}}

    revised = {**CARD_PLAN, "hypothesis": "The other account reads the owner's card through its list",
               "strategy": {**CARD_PLAN.get("strategy", STRATEGY), "revision_reason": "read through the list"}}
    for plans, decisions, raised in (((), 12, None), ({1: CARD_PLAN}, 12, None), ({7: CARD_PLAN, 15: revised}, 16, 16)):
        Reader.calls = 0
        agent = Reader(plans)
        result = AgentProbe("access-control", lambda agent=agent: agent, max_steps=12).run(
            card_context(tmp_path, "refused"))
        assert result.limits_hit == "attempts" and Reader.calls == decisions, (plans, Reader.calls)
        assert agent.results and agent.results[0].get("max_steps") == raised or not plans
        assert all("max_steps" not in r for r in agent.results[1:])


def test_a_negative_verdict_citing_a_source_read_names_the_requests_to_cite(tmp_path):
    steps = [CARD_STEPS[0], {"tool": "read_source", "args": {"path": "routes/basket.ts"}}, *CARD_STEPS[1:]]
    result = run(card_context(tmp_path, "refused"), "blocked-by-control", steps)      # cites steps 2-8
    assert result.verdict == "inconclusive"
    assert "step 2 is not one: cite only steps 3-8" in result.rationale


@pytest.mark.parametrize("make,steps,verdict,lead", [
    (lambda p: card_context(p, "vulnerable"), CARD_STEPS, "confirmed",
     "account-2 reads the record that account-1 already had"),
    (lambda p: card_context(p, "refused"), CARD_STEPS, "blocked-by-control",
     "Insecure direct object reference blocked: account-2 was refused the record that account-1 already had "
     "(400 Bad Request), while it got its own."),
    (lambda p: context(p, target("vulnerable")), None, "confirmed",
     "account-2 reads the record that account-1 already had"),
])
def test_the_image_shows_the_other_accounts_own_records_as_allowed(tmp_path, make, steps, verdict, lead):
    """Run 155: the other account's own list and record are reads it may send, the contrast of the proof, not
    controls expected to be refused. As in the report, a confirmation heads the image in red, a blocked access in
    green with what was refused."""
    ctx, pages = make(tmp_path), []
    ctx.browser = SimpleNamespace(screenshots=("access-control",),
                                  render_exchanges=lambda html, name, marked: pages.append(html) or [])
    result = run(ctx, verdict, steps)
    assert result.verdict == verdict, result.rationale
    page = pages[-1]
    assert lead in page and f"<header class='head {verdict}'>" in page
    for label in ("another account reads its own record", *(("another account lists its records",) if steps else ())):
        row = page[page.index(label):]
        assert "<td>allowed</td>" in row[:row.index("</tr>")], label
    assert page.count("is not open to everyone") <= 1                      # the read without login only
    assert "header.confirmed,header.shown-without-exploit{border-bottom-color:#b00020}" in page
    assert "header.blocked-by-control,header.not-reproducible{border-bottom-color:#2e7d32}" in page


def test_the_plan_allows_a_get_of_the_collection_and_nothing_else_there(tmp_path):
    assert existing_collection("/api/cards/:id") == "/api/cards"
    assert existing_collection("/api/orders/{id}/owned") == "/api/orders"
    assert [existing_collection(p) for p in ("/:id", "/api/me", "/a/:x/b/:y")] == [None, None, None]
    ctx = card_context(tmp_path, "vulnerable")
    controller = Controller(ctx)
    with pytest.raises(ToolError, match="no matching route"):
        controller.before("http_request", {"role": "account-1", "path": "/api/cards"})
    controller.plan = {k: v for k, v in CARD_PLAN.items() if k != "strategy"}
    controller.before("http_request", {"role": "account-1", "path": "/api/cards"})
    with pytest.raises(ToolError):
        controller.before("http_request", {"role": "account-1", "method": "POST", "path": "/api/cards",
                                           "json": {"last4": "vrf1a2b3c4d"}})


def test_accounts_without_a_user_name_prove_it_only_by_a_list(tmp_path):
    """A bearer token or pasted session names no user name a record could contain, so only the list remains."""
    result = run(context(tmp_path, target("vulnerable"), identities=TOKENS), "confirmed")
    assert result.verdict == "inconclusive"
    assert "GET of /api/users lists" in result.rationale and "names its user name" not in result.rationale
    assert access_methods("T-1", "CWE-639", {}, TOKENS, writes=False) == ["existing"]
    assert access_methods("T-1", "CWE-639", {}, NAMED, writes=False) == ["existing"]
    assert access_methods("T-1", "CWE-306", {}, NAMED, writes=False) == ["signed_in"]     # exposure: unchanged


def test_only_a_normal_account_owns_the_record_and_the_plan_only_reads(tmp_path):
    """Even in intrusive mode and with a write the finding names, the accepted plan sends no write: the owner may
    write only under an own-resource plan (VER-010)."""
    ctx = context(tmp_path, target("vulnerable"), safe=False)
    doc = document()
    doc["threats"][0]["scenario"] += " and PUT /api/users/:id"
    ctx.plan = plans_from(doc)[0]
    tools = AgentTools(ctx)
    with pytest.raises(ToolError, match="normal account"):
        tools.plan_test(**{**PLAN, "existing": "admin-1"})
    with pytest.raises(ToolError, match="read with GET"):
        tools.plan_test(**{**PLAN, "method": "PUT"})
    tools.plan_test(**PLAN)
    controller = Controller(ctx)
    controller.plan = {k: v for k, v in PLAN.items() if k != "strategy"}
    controller.before("http_request", {"role": "account-2", "path": "/api/users/1"})
    for role in ("account-1", "account-2"):
        for path, value in (("/api/users/1", "vrf1a2b3c4d"), ("/api/users", "vrf1a2b3c4d")):
            with pytest.raises(ToolError):
                controller.before("http_request", {"role": role, "method": "PUT", "path": path,
                                                   "json": {"email": value}})


def test_the_test_plan_tests_an_idor_in_safe_mode_where_a_name_or_a_list_can_show_the_owner():
    plan = replace(_plan("access-control"), cwe="CWE-639")
    assert _blocker(plan, identities=NAMED, safe=True) is None
    assert _blocker(plan, identities=TOKENS, safe=True) is None                # names no GET: the source may
    listed = replace(plan, endpoints=(Endpoint("GET", "/api/cards/:id", None),))
    assert _blocker(listed, identities=TOKENS, safe=True) is None
    profile = replace(plan, endpoints=(Endpoint("GET", "/api/profile", None),))
    assert _blocker(profile, identities=NAMED, safe=True) is None
    assert _blocker(profile, identities=TOKENS, safe=True)[0] == "intrusive"
    assert _blocker(profile, identities=TOKENS, safe=False) is None


def test_the_agent_is_told_of_the_proof_and_not_to_search_for_a_creation_route(tmp_path):
    ctx = context(tmp_path, target("vulnerable"), safe=False)
    text = _system(ctx)
    assert "Existing-record proof (VER-067)" in text
    assert "No request of this finding, no evidenced preparation" in text
    assert "prefer it to searching for a creation route" in text
    assert "each account's GET of that collection lists the identifier of its own record" in text
    tokens = _system(context(tmp_path, target("vulnerable"), identities=TOKENS, safe=False))
    assert "Existing-record proof (VER-067)" in tokens and "prefer it to searching for a creation route" in tokens


def test_a_run_that_may_write_does_not_claim_to_test_findings_at_the_same_time():
    from appsec_verifier.progress import ParallelProgress, RunProgress

    plans = [replace(_plan("xss"), id="T-1"), replace(_plan("xss"), id="T-2")]
    for writes, shown in ((False, True), (True, False)):
        stream = io.StringIO()
        ParallelProgress(RunProgress(stream, live=False, env={}), 4, writes=writes).begin(plans)
        assert ("findings are tested at the same time" in stream.getvalue()) is shown
