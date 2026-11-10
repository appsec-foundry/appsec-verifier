"""A confirmed verdict stands only with the proof its class requires, checked in
code against the cited steps (VER-009 to VER-013, VER-022)."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from appsec_verifier.agent.proof import check_proof
from appsec_verifier.verify.probes import ProbeResult


def _ctx(cls, **kw):
    return SimpleNamespace(**{"plan": SimpleNamespace(id="T-1", cls=cls), "sessions": None, "evidence_dir": None,
                              **kw})


def _req(role="alice", path="/rest/basket/2", status=200, length=40, sha="h1", method=None, params=None, body=None):
    args = {"path": path}
    for key, value in (("role", role), ("method", method), ("params", params), ("json", body)):
        if value is not None:
            args[key] = value
    return {"tool": "http_request", "args": args,
            "result": {"role": role, "status": status, "length": length, "body_sha256": sha}}


def _check(cls, history, cited, verdict="confirmed", **ctx):
    result = ProbeResult(verdict=verdict, confidence="high", rationale="the model says so")
    if cls == "access-control":
        history, cited, extra = _access_fixture(history, cited)
        ctx = {**extra, **ctx}
    return check_proof(_ctx(cls, **ctx), history, result, cited)


def _access_fixture(history, cited):
    history = copy.deepcopy(history)
    first = next((h["args"] for h in history if h.get("tool") == "http_request"), {})
    plan = {"tool": "plan_test", "args": {"kind": "access-control", "hypothesis": "Other account reads owner data",
            "path": "/rest/basket/2", "resource": "basket"}, "result": {"accepted": True}}
    resource = {"id": "basket", "finding_id": "T-1", "path": "/rest/basket/2", "allowed_roles": ["alice"],
                "denied_roles": ["bob", "anonymous"], "pointer": "/marker", "value": "owner-test-marker",
                "params": first.get("params") or {}, "json": first.get("json") or {}}
    history.insert(0, plan)
    responses = {n: {"body": '{"marker":"owner-test-marker"}', "complete": True,
                     "identity": h.get("args", {}).get("role", "anonymous")}
                 for n, h in enumerate(history, 1) if h.get("tool") == "http_request"}
    cited = [n + 1 if type(n) is int and n > 0 else n for n in cited] if isinstance(cited, list) else cited
    return history, cited, {"scope": {"test_resources": [resource]}, "responses": responses}


READ = {"tool": "read_source", "args": {"path": "r.ts"}, "result": {"path": "r.ts", "start_line": 1}}


# ── access-control (VER-010) ──────────────────────────────────────────────────

@pytest.mark.parametrize("history, cited", [
    ([_req("alice"), _req("bob")], [1, 2]),
    ([READ, _req("alice"), _req(None)], [2, 3]),                                   # anonymous vs identity
    ([_req("alice", method="get"), _req("bob", method="GET", params={})], [1, 2]),  # defaults compare equal
    ([_req("alice", status=403), _req("alice"), _req("bob")], [1, 2, 3]),          # one qualifying pair suffices
])
def test_access_control_contrast_confirms(history, cited):
    assert _check("access-control", history, cited).verdict == "confirmed"


@pytest.mark.parametrize("history, cited, reason", [
    ([_req("alice"), _req("bob")], None, "at least two steps"),
    ([_req("alice"), _req("bob")], [1], "at least two steps"),
    ([_req("alice"), _req("bob")], [1, 9], "does not exist"),
    ([_req("alice"), _req("bob")], [0, 1], "does not exist"),
    ([_req("alice"), _req("bob")], [1, True], "distinct integer"),
    ([READ, _req("bob")], [1, 2], "not an answered http_request"),
    ([_req("alice"), {"tool": "http_request", "args": {"path": "/x"}, "result": {"error": "refused"}}], [1, 2],
     "not an answered http_request"),
    ([_req("alice"), _req("alice")], [1, 2], "independent denied identity"),          # no contrast
    ([_req("alice"), _req("bob", status=403)], [1, 2], "independent denied identity"),  # the control held
    ([_req("alice"), _req("bob", length=0)], [1, 2], "independent denied identity"),   # nothing was read
    ([_req("alice"), _req("bob", path="/rest/basket/3")], [1, 2], "declared resource with the same inputs"),
    ([_req("alice", params={"id": 2}), _req("bob", params={"id": 3})], [1, 2],
     "declared resource with the same inputs"),
    ([_req("alice"), _req("bob", method="POST")], [1, 2], "declared resource with the same inputs"),
])
def test_access_control_without_the_contrast_is_downgraded(history, cited, reason):
    res = _check("access-control", history, cited)
    assert res.verdict == "inconclusive" and reason in res.rationale
    assert res.rationale.startswith("indicative, not proven") and "the model says so" in res.rationale


# ── injection (VER-011) ───────────────────────────────────────────────────────

@pytest.mark.parametrize("history", [
    [_req(params={"q": "1' AND '1'='1"}, sha="h1"), _req(params={"q": "1' AND '1'='2"}, sha="h2")],
    [_req(params={"q": "x"}, status=200), _req(params={"q": "x'"}, status=500, sha="h1")],
    [_req(method="POST", body={"q": "a"}, sha="h1"), _req(method="POST", body={"q": "a'--"}, sha="h3")],
])
def test_a_bare_status_or_body_flip_no_longer_confirms(history):
    res = _check("injection", history, [1, 2])
    assert res.verdict == "inconclusive" and "declare a plan_test" in res.rationale


@pytest.mark.parametrize("history", [
    [_req(params={"q": "a"}, sha="h1"), _req(params={"q": "a"}, sha="h2")],          # same input
    [_req(params={"q": "a"}), _req(params={"q": "b"})],                              # same answer
    [_req("alice", params={"q": "a"}), _req("bob", params={"q": "b"}, sha="h2")],    # different identity
    [_req(path="/a", params={"q": "a"}), _req(path="/b", params={"q": "b"}, sha="h2")],
])
def test_injection_without_a_flip_is_downgraded(history):
    res = _check("injection", history, [1, 2])
    assert res.verdict == "inconclusive" and "declare a plan_test" in res.rationale


def _timed(q, ms, path="/rest/search", role="alice"):
    step = _req(role, path=path, params={"q": q}, sha="same")                 # same status and body throughout
    step["result"]["elapsed_ms"] = ms
    return step


@pytest.mark.parametrize("history", [
    [_timed("a", 80), _timed("a' AND SLEEP(3)--", 3100), _timed("b", 95), _timed("b' AND SLEEP(3)--", 3050)],
    [_timed("a", 80), _timed("a", 120), _timed("x' OR SLEEP(3)--", 3200), _timed("x' OR SLEEP(3)--", 3150)],
])
def test_undeclared_timing_samples_are_insufficient(history, tmp_path):
    res = check_proof(_ctx("injection", evidence_dir=tmp_path / "evidence"), history,
                      ProbeResult(verdict="confirmed"), list(range(1, len(history) + 1)))
    assert res.verdict == "inconclusive" and "declare a plan_test" in res.rationale


@pytest.mark.parametrize("history", [
    [_timed("a", 80), _timed("a' SLEEP", 3100)],                                    # one of each
    [_timed("a", 80), _timed("b", 90), _timed("a' SLEEP", 3100)],                   # one delayed
    [_timed("a", 80), _timed("b", 90), _timed("c", 1500), _timed("d", 2000)],       # under 2 s apart
    [_timed("a", 80), _timed("b", 1500), _timed("c", 3100), _timed("d", 3200)],     # a slow undelayed one
    [_timed("a", 80), _timed("b", 90), _timed("a", 3100), _timed("b", 3200)],       # same input, slow once
    [_timed("a", 80), _timed("b", 90), _timed("c", 3100, role="bob"), _timed("d", 3200, role="bob")],
    [_timed("a", 80), _timed("b", 90), _timed("c", 3100, path="/x"), _timed("d", 3200, path="/x")],
    [_req(params={"q": "a"}, sha="s"), _req(params={"q": "b"}, sha="s"),            # no timing at all
     _req(params={"q": "c"}, sha="s"), _req(params={"q": "d"}, sha="s")],
])
def test_injection_without_a_clear_delay_is_downgraded(history):
    res = _check("injection", history, list(range(1, len(history) + 1)))
    assert res.verdict == "inconclusive" and "declare a plan_test" in res.rationale


# ── xss (VER-009) ─────────────────────────────────────────────────────────────

def _xss_history(checked_path):
    plan = {"tool": "plan_test", "args": {"kind": "execution", "hypothesis": "q reaches innerHTML",
                                          "path": "/#/search?q=<test>"}, "result": {"accepted": True}}
    check = {"tool": "browser_check", "args": {"path": checked_path},
             "result": {"executed": True, "context_verified": True, "evidence": []}}
    return [plan, check]


@pytest.mark.parametrize("checked_path, verdict", [
    ("/#/search?q=<svg/onload=alert('m1'.concat('m2'))>", "confirmed"),
    ("/#/score-board?q=<svg/onload=alert('m1'.concat('m2'))>", "inconclusive"),  # another route of the app
    ("/search?q=<svg/onload=alert('m1'.concat('m2'))>", "inconclusive"),         # not the planned # route
])
def test_xss_execution_counts_only_on_the_planned_route(checked_path, verdict):
    res = _check("xss", _xss_history(checked_path), [2], marker=("m1", "m2"))
    assert res.verdict == verdict
    if verdict == "inconclusive":
        assert "no browser_check saw the marker execute on the planned route /#/search?q=<test>" in res.rationale


def test_an_execution_before_the_latest_plan_counts_and_a_missing_assumption_blocks_nothing():
    """VER-043: a plan revised after the browser saw the marker execute does not discard the execution."""
    plan, check = _xss_history("/#/search?q=<svg/onload=alert('m1'.concat('m2'))>")
    plan["args"]["strategy"] = {"prerequisites": [{"condition": "q reaches the sink", "status": "missing"}]}
    assert _check("xss", [check, plan], [1], marker=("m1", "m2")).verdict == "confirmed"


def test_an_operator_resource_contrast_sent_before_the_plan_counts():
    history, cited, extra = _access_fixture([_req("alice"), _req("bob")], [1, 2])
    history = [*history[1:], history[0]]                    # the plan follows the requests it describes
    responses = {n - 1: r for n, r in extra["responses"].items()}
    res = check_proof(_ctx("access-control", scope=extra["scope"], responses=responses), history,
                      ProbeResult(verdict="confirmed", confidence="high", rationale="claim"), [1, 2])
    assert res.verdict == "confirmed"


# ── open redirect (VER-012) ───────────────────────────────────────────────────

MARKER = ("vrf0a1b2c3d", "4e5f6a7b")
HOST = "vrf0a1b2c3d4e5f6a7b.invalid"
NO_REDIRECT = "answered with a redirect"


def _redirect(location, status=302, path="/redirect"):
    step = _req(None, path=path, status=status, params={"to": f"https://{HOST}/"})
    if location is not None:
        step["result"]["location"] = location
    return step


@pytest.mark.parametrize("step", [
    _redirect(f"https://{HOST}/"),
    _redirect(f"https://{HOST.upper()}:8443/x?https://github.com/allowed"),          # wrapped past an allow-list
    _redirect(f"//{HOST}/x", status=301),                                            # scheme-relative
    _redirect(f"http://{HOST}./", status=308),                                       # trailing dot
])
def test_open_redirect_to_the_marker_host_confirms(step):
    res = _check("open-redirect", [READ, step], [2], marker=MARKER, target_base="https://app.example.com")
    assert res.verdict == "confirmed"


@pytest.mark.parametrize("history, cited, reason", [
    ([_redirect(f"https://{HOST}/")], None, "at least one step"),
    ([_redirect(f"https://{HOST}/")], [], "at least one step"),
    ([READ, _redirect(f"https://{HOST}/")], [1], "not an answered http_request"),
    ([_redirect(f"https://{HOST}/", status=200)], [1], NO_REDIRECT),                    # not a redirect
    ([_redirect(f"https://{HOST}/", status=304)], [1], NO_REDIRECT),
    ([_redirect(None)], [1], NO_REDIRECT),                                               # no location
    ([_redirect(f"https://app.example.com/login?next=https://{HOST}/")], [1], NO_REDIRECT),  # marker only in query
    ([_redirect(f"/{HOST}/x")], [1], NO_REDIRECT),                                     # relative: stays on target
    ([_redirect(f"https://{HOST}.evil.example/")], [1], NO_REDIRECT),                  # marker as a subdomain
    ([_redirect("https://vrf00000000ffffffff.invalid/")], [1], NO_REDIRECT),           # another finding's host
    ([_redirect("https://[::1/")], [1], NO_REDIRECT),                                  # unparseable location
])
def test_open_redirect_without_the_marker_redirect_is_downgraded(history, cited, reason):
    res = _check("open-redirect", history, cited, marker=MARKER, target_base="https://app.example.com")
    assert res.verdict == "inconclusive" and reason in res.rationale


def test_open_redirect_without_a_marker_is_never_confirmed():
    res = _check("open-redirect", [_redirect("https://.invalid/")], [1], marker=("", ""), target_base="")
    assert res.verdict == "inconclusive" and "no redirect marker" in res.rationale


def test_open_redirect_evidence_names_the_host_not_the_location(tmp_path):
    step = _redirect(f"https://{HOST}/?session=abc123")
    res = check_proof(_ctx("open-redirect", marker=MARKER, target_base="https://app.example.com",
                           evidence_dir=tmp_path / "evidence"), [step], ProbeResult(verdict="confirmed"), [1])
    record = json.loads((tmp_path / "evidence" / "T-1-exchanges.json").read_text())
    assert res.verdict == "confirmed" and record["exchanges"][0]["location_host"] == HOST
    assert "abc123" not in json.dumps(record)


# ── path traversal (VER-012) ──────────────────────────────────────────────────

CONTENT = "vrfMarkerContent0123456789"
TRAVERSAL_SCOPE = {"marker_file": {"path": "/srv/verifier-marker.txt", "content": CONTENT}}
NO_READ = "content of the scope's marker file"


def _read(marker_read, params=None):
    step = _req(None, path="/download", params=params or {"file": "../../srv/verifier-marker.txt"})
    step["result"]["marker_read"] = marker_read
    return step


def test_traversal_that_read_the_marker_file_confirms(tmp_path):
    res = check_proof(_ctx("path-traversal", scope=TRAVERSAL_SCOPE, evidence_dir=tmp_path / "evidence"),
                      [READ, _read(False), _read(True)], ProbeResult(verdict="confirmed"), [3])
    record = json.loads((tmp_path / "evidence" / "T-1-exchanges.json").read_text())
    assert res.verdict == "confirmed" and record["exchanges"][0]["marker_read"] is True
    assert CONTENT not in json.dumps(record)


@pytest.mark.parametrize("history, cited, scope, reason", [
    ([_read(True)], [1], {}, "names no marker file"),
    ([_read(True)], None, TRAVERSAL_SCOPE, "at least one step"),
    ([_read(False)], [1], TRAVERSAL_SCOPE, NO_READ),
    ([_req(None)], [1], TRAVERSAL_SCOPE, NO_READ),                               # no marker_read at all
    ([_read(True, params={"q": CONTENT})], [1], TRAVERSAL_SCOPE, NO_READ),       # an echo, not a read
    ([_read("yes")], [1], TRAVERSAL_SCOPE, NO_READ),                              # only True counts
])
def test_traversal_without_a_read_marker_is_downgraded(history, cited, scope, reason):
    res = _check("path-traversal", history, cited, scope=scope)
    assert res.verdict == "inconclusive" and reason in res.rationale


# ── SSRF (VER-012) ────────────────────────────────────────────────────────────

class FakeListener:
    def __init__(self, hits):
        self._hits = hits

    def hits(self, marker):
        return list(self._hits.get(marker, []))


def test_ssrf_confirms_on_a_listener_hit_and_records_it(tmp_path):
    hit = {"at": "2026-11-07T10:00:00Z", "method": "GET", "source": "127.0.0.1"}
    listener = FakeListener({"vrf0a1b2c3d4e5f6a7b": [hit]})
    ctx = _ctx("ssrf", listener=listener, marker=MARKER, evidence_dir=tmp_path / "evidence")
    ctx.scope = {"callback": {"expect_rejected": True}}
    ctx.callback_records = {"fresh-attempt": [hit]}
    history = [{"tool": "http_request", "result": {"callback_hit": True, "callback_attempt": "fresh-attempt"}}]
    res = check_proof(ctx, history, ProbeResult(verdict="confirmed"), None)
    path = tmp_path / "evidence" / "T-1-callback-hits.json"
    assert res.verdict == "confirmed" and res.evidence[0]["kind"] == "callback"
    assert json.loads(path.read_text())["callback_hits"] == [hit] and (path.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize("listener, marker, reason", [
    (None, MARKER, "no callback listener"),
    (FakeListener({}), ("", ""), "no callback listener"),
    (FakeListener({}), MARKER, "observation window"),
    (FakeListener({"vrf00000000ffffffff": [{"at": "t"}]}), MARKER, "observation window"),  # other finding
])
def test_ssrf_without_a_hit_is_downgraded(listener, marker, reason):
    res = _check("ssrf", [_req(None)], [1], listener=listener, marker=marker)
    assert res.verdict == "inconclusive" and reason in res.rationale


# ── out-of-band injection (VER-048) ───────────────────────────────────────────

_OOB_URL = "http://127.0.0.1:9/vrf0a1b2c3d4e5f6a7b"
_OOB_POS = "#{http.get('" + _OOB_URL + "')}"


def _oob_plan():
    return {"tool": "plan_test",
            "args": {"kind": "boolean", "hypothesis": "username reaches a template evaluation sink",
                     "path": "/profile", "method": "POST", "input_location": "json", "input_name": "username",
                     "oob_template": "#{http.get('{{callback}}')}", "positive": _OOB_POS, "negative": _OOB_URL},
            "result": {"accepted": True}}


def _oob_req(value, hit):
    return {"tool": "http_request",
            "args": {"path": "/profile", "method": "POST", "json": {"username": value}},
            "result": {"status": 200, "callback_hit": hit, "callback_attempt": "a", "role": None}}


def test_oob_injection_confirms_on_a_positive_hit_and_a_quiet_inert_control(tmp_path):
    history = [_oob_plan(), _oob_req(_OOB_POS, True), _oob_req(_OOB_POS, True), _oob_req(_OOB_URL, False)]
    res = check_proof(_ctx("injection", evidence_dir=tmp_path / "evidence"),
                      history, ProbeResult(verdict="confirmed"), [2, 3, 4])
    assert res.verdict == "confirmed" and res.confidence == "medium"


@pytest.mark.parametrize("history, cited, reason", [
    ([_oob_plan(), _oob_req(_OOB_POS, True), _oob_req(_OOB_POS, True), _oob_req(_OOB_URL, True)], [2, 3, 4],
     "inert-URL control reached the listener"),
    ([_oob_plan(), _oob_req(_OOB_POS, True), _oob_req(_OOB_POS, False), _oob_req(_OOB_URL, False)], [2, 3, 4],
     "correlated callback hit"),
    ([_oob_plan(), _oob_req(_OOB_POS, True), _oob_req(_OOB_URL, False)], [2, 3],
     "at least twice"),
    ([_oob_plan(), _oob_req(_OOB_POS, True), _oob_req(_OOB_POS, True)], [2, 3],
     "inert-URL control, whose missing callback"),
])
def test_oob_injection_downgrades(history, cited, reason):
    res = _check("injection", history, cited)
    assert res.verdict == "inconclusive" and reason in res.rationale


# ── auth-artifact injection (VER-049) ─────────────────────────────────────────

def _auth_plan():
    return {"tool": "plan_test",
            "args": {"kind": "boolean", "hypothesis": "email is spliced into the login SQL query",
                     "path": "/rest/user/login", "method": "POST", "input_location": "json", "input_name": "email",
                     "pointer": "/authentication/token", "auth_artifact": True, "baseline": "nobody@x",
                     "sql_template": "x' OR {{predicate}} -- ", "positive": "x' OR (1=1) -- ",
                     "negative": "x' OR (1=2) -- ", "positive_other": "x' OR (2<>1) -- ",
                     "negative_other": "x' OR (2<>2) -- "},
            "result": {"accepted": True}}


def _auth_req(value, authenticated):
    return {"tool": "http_request",
            "args": {"path": "/rest/user/login", "method": "POST", "json": {"email": value, "password": "p"}},
            "result": {"status": 200 if authenticated else 401, "auth_artifact": authenticated, "role": None}}


_AUTH_HISTORY = [
    _auth_plan(),
    _auth_req("x' OR (1=1) -- ", True), _auth_req("x' OR (2<>1) -- ", True),      # true predicates authenticate
    _auth_req("nobody@x", False), _auth_req("x' OR (1=2) -- ", False), _auth_req("x' OR (2<>2) -- ", False),
]


def test_auth_artifact_injection_confirms_on_the_true_false_auth_flip(tmp_path):
    res = check_proof(_ctx("injection", evidence_dir=tmp_path / "evidence"),
                      _AUTH_HISTORY, ProbeResult(verdict="confirmed"), [2, 3, 4, 5, 6])
    assert res.verdict == "confirmed" and res.confidence == "medium"


@pytest.mark.parametrize("flip, reason", [
    ({4: True}, "also authenticated"),              # the baseline authenticates too
    ({5: True}, "also authenticated"),              # a false predicate authenticates
    ({2: False}, "every true-predicate control"),   # a true predicate does not authenticate
])
def test_auth_artifact_injection_downgrades(flip, reason):
    history = copy.deepcopy(_AUTH_HISTORY)
    for step, value in flip.items():
        history[step - 1]["result"]["auth_artifact"] = value
    res = _check("injection", history, [2, 3, 4, 5, 6])
    assert res.verdict == "inconclusive" and reason in res.rationale


def _sql_plan():
    return {"tool": "plan_test",
            "args": {"kind": "boolean", "hypothesis": "q is spliced into the product search SQL",
                     "path": "/rest/products/search", "method": "GET", "input_location": "params",
                     "input_name": "q", "pointer": "/data", "baseline": "x",
                     "sql_template": "x%' AND {{predicate}})) -- ",
                     "positive": "x%' AND (397515=397515))) -- ", "negative": "x%' AND (397515=402298))) -- ",
                     "positive_other": "x%' AND (402298<>397515))) -- ",
                     "negative_other": "x%' AND (402298<>402298))) -- "},
            "result": {"accepted": True}}


_TRUE_SET = '{"status":"success","data":[{"id":1,"name":"Apple Juice"}]}'
_EMPTY_SET = '{"status":"success","data":[]}'
# The uninjected baseline matches on name and description, so it is a larger set than the true injection.
_BASELINE_SET = '{"status":"success","data":[{"id":1,"name":"A"},{"id":2,"name":"B"},{"id":3,"name":"C"}]}'


def _sql_fixture(positive_other=_TRUE_SET):
    plan = _sql_plan()
    args = plan["args"]
    order = [("baseline", _BASELINE_SET), ("positive", _TRUE_SET), ("negative", _EMPTY_SET),
             ("positive_other", positive_other), ("negative_other", _EMPTY_SET)] * 2
    history, responses = [plan], {}
    for key, body in order:
        history.append(_req(path="/rest/products/search", method="GET", params={"q": args[key]}))
        responses[len(history)] = {"body": body, "complete": True}
    return history, list(range(2, len(history) + 1)), responses


def test_a_collection_emptiness_flip_confirms_without_matching_the_baseline(tmp_path):
    history, cited, responses = _sql_fixture()
    res = check_proof(_ctx("injection", evidence_dir=tmp_path / "evidence", responses=responses),
                      history, ProbeResult(verdict="confirmed"), cited)
    assert res.verdict == "confirmed" and res.confidence == "medium"


def test_input_variation_not_decided_by_truth_value_is_downgraded(tmp_path):
    # A true predicate's complement observes a different result, so the signal tracks the literal
    # text rather than the predicate's truth value; that is ordinary input dependence, not injection.
    history, cited, responses = _sql_fixture(positive_other='{"status":"success","data":[{"id":9,"name":"Other"}]}')
    res = check_proof(_ctx("injection", evidence_dir=tmp_path / "evidence", responses=responses),
                      history, ProbeResult(verdict="confirmed"), cited)
    assert res.verdict == "inconclusive" and "complementary true predicates" in res.rationale


# ── unknown classes ───────────────────────────────────────────────────────────


def test_an_unknown_class_is_never_confirmed():
    assert _check("crypto", [_req("alice"), _req("bob")], [1, 2]).verdict == "inconclusive"


@pytest.mark.parametrize("verdict", ["not-reproducible", "blocked-by-control", "inconclusive"])
def test_other_verdicts_pass_unchanged(verdict):
    res = _check("ssrf", [], None, verdict=verdict)
    if verdict == "inconclusive":
        assert res.verdict == verdict and res.rationale == "the model says so"
    else:
        assert res.verdict == "not-attempted" and "no answered target request" in res.rationale


# ── evidence record (VER-022) ─────────────────────────────────────────────────

def test_the_evidence_record_is_the_codes_redacted_and_owner_only(tmp_path):
    secret = {"token": "Bearer s3cret-value"}
    history = [_req("alice", params=secret), _req("bob", params=secret)]
    sessions = SimpleNamespace(redact=lambda v: json.loads(json.dumps(v).replace("s3cret-value", "[redacted]")))
    result = ProbeResult(verdict="confirmed", rationale="r", evidence=[{"kind": "note", "path": "model-made.txt"}])
    history, cited, extra = _access_fixture(history, [1, 2])
    res = check_proof(_ctx("access-control", sessions=sessions, evidence_dir=tmp_path / "evidence", **extra),
                      history, result, cited)
    path = tmp_path / "evidence" / "T-1-exchanges.json"
    assert [e["path"] for e in res.evidence] == ["evidence/T-1-exchanges.json"]   # the model's evidence is replaced
    assert "s3cret-value" not in path.read_text() and (path.stat().st_mode & 0o777) == 0o600
    assert json.loads(path.read_text())["exchanges"][1]["role"] == "bob"
