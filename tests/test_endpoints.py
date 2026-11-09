"""The requests a finding names, read from the assessment, and what a run needs to test it (VER-005, VER-008)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from appsec_verifier import cli
from appsec_verifier.endpoints import BRIEF_CAP, MAX_ENDPOINTS, Endpoint, finding_brief, finding_endpoints
from appsec_verifier.loader import FindingPlan, plans_from

SURFACE = [
    {"entry_point": "GET /rest/basket/:id", "auth_required": True, "notes": "handler: server.ts:603"},
    {"entry_point": "PUT /api/Addresss/:id", "auth_required": True, "notes": "handler: server.ts:450"},
    {"entry_point": "GET /rest/products/search", "auth_required": None, "notes": "handler: server.ts:602"},
    {"entry_point": "ALL /ftp(?!/quarantine)/:file", "auth_required": None},
    "not an entry", {"entry_point": 7}, {"entry_point": "no path"},
]


def test_a_request_named_in_the_text_takes_the_attack_surface_template_and_its_login():
    threat = {"scenario": "GET /rest/basket/2 returns another user's basket.",
              "attack_steps": ["I send PUT /api/Addresss/<victimAddressId> with my token.",
                               "Then GET /rest/basket/7 again."]}
    assert finding_endpoints(threat, SURFACE) == (Endpoint("GET", "/rest/basket/:id", True),
                                                  Endpoint("PUT", "/api/Addresss/:id", True))


def test_a_request_without_a_matching_entry_is_kept_once_without_a_login_claim():
    threat = {"scenario": "PUT /api/Products/:id and PUT /api/Products/1. Also GET /ftp/legal.md."}
    assert finding_endpoints(threat, SURFACE) == (Endpoint("PUT", "/api/Products/:id", None),
                                                  Endpoint("GET", "/ftp/:file", None))


BASKET = ["GET /rest/basket/:id (login)", "PUT /rest/basket/7", "PATCH /rest/basket/7"]


@pytest.mark.parametrize(("text", "expected"), [
    ("GET and DELETE /api/BasketItems/:id need only a login.",
     ["GET /api/BasketItems/:id", "DELETE /api/BasketItems/:id"]),
    ("GET, PUT or PATCH /rest/basket/7.", BASKET),
    ("GET, PUT, and PATCH /rest/basket/7", BASKET),
    ("GET/POST /ftp/a.md", ["GET /ftp/:file", "POST /ftp/:file"]),
    ("GET the list, then DELETE /api/Products/1.", ["DELETE /api/Products/1"]),        # a method without its path
    ("GET or the like /x", []),
])
def test_methods_that_share_one_path_each_name_a_request(text, expected):
    assert [str(e) for e in finding_endpoints({"scenario": text}, SURFACE)] == expected


def test_an_entry_whose_handler_is_at_a_finding_location_and_a_browser_route_count():
    threat = {"instances": [{"file": "server.ts", "line": 602, "scenario": "Open /#/search?q=<img src=x>."}]}
    assert finding_endpoints(threat, SURFACE) == (Endpoint("GET", "/rest/products/search", None),
                                                  Endpoint("PAGE", "/#/search", None))
    assert [str(e) for e in finding_endpoints({"evidence": [{"file": "server.ts", "line": 603}]}, SURFACE)] == [
        "GET /rest/basket/:id (login)"]


# The Analyzer's attack surface since it publishes route IDs: an imported handler is named where it is defined,
# its registration as `registered:`.
ROUTED = [
    {"entry_point": "POST /profile/image/url", "auth_required": True, "route_ids": ["R-008"],
     "notes": "authorization-review-required; registered: server.ts:311; handler: routes/profileImageUrlUpload.ts:16"},
    {"entry_point": "POST /rest/user/data-export", "route_ids": ["R-070", "R-071"], "notes": "handler: server.ts:620"},
    {"entry_point": "GET /redirect", "route_ids": ["R-090", "not-an-id", 7], "notes": "handler: server.ts:659"},
]


def test_a_route_id_of_the_finding_or_an_instance_names_the_entry_point_that_lists_it():
    ssrf = {"instances": [{"file": "routes/profileImageUrlUpload.ts", "line": 24, "route_ids": []},
                          {"file": "routes/profileImageUrlUpload.ts", "line": 24, "route_ids": ["R-008"]}]}
    assert [str(e) for e in finding_endpoints(ssrf, ROUTED)] == ["POST /profile/image/url (login)"]
    export = {"route_ids": ["R-071"], "evidence": {"file": "routes/dataExport.ts", "line": 33}}
    assert [str(e) for e in finding_endpoints(export, ROUTED)] == ["POST /rest/user/data-export"]
    # A named request comes first; the same route by ID is not added twice.
    both = {"scenario": "POST /rest/user/data-export with a crafted email.", "route_ids": ["R-070", "R-090"]}
    assert [str(e) for e in finding_endpoints(both, ROUTED)] == ["POST /rest/user/data-export", "GET /redirect"]


@pytest.mark.parametrize("refs", [["R-999"], ["r-008"], ["R-8"], ["R-008 "], "R-008", [8], None])
def test_a_route_id_the_attack_surface_does_not_list_or_a_malformed_one_names_nothing(refs):
    assert finding_endpoints({"route_ids": refs, "instances": [{"route_ids": refs}]}, ROUTED) == ()


def test_route_ids_without_published_ones_in_the_attack_surface_name_nothing():
    """Assessments written before the attack surface listed route IDs carry them on instances only."""
    assert finding_endpoints({"instances": [{"file": "routes/a.ts", "line": 1, "route_ids": ["R-008"]}]},
                             SURFACE) == ()


def test_a_finding_at_the_registration_or_at_the_handler_definition_names_the_entry_point():
    at_registration = {"evidence": [{"file": "server.ts", "line": 311}]}
    at_handler = {"evidence": [{"file": "routes/profileImageUrlUpload.ts", "line": 16}]}
    for threat in (at_registration, at_handler):
        assert [str(e) for e in finding_endpoints(threat, ROUTED)] == ["POST /profile/image/url (login)"]
    assert finding_endpoints({"evidence": [{"file": "routes/profileImageUrlUpload.ts", "line": 24}]}, ROUTED) == ()


def test_odd_input_yields_nothing_and_the_list_is_bounded():
    assert finding_endpoints({"scenario": 7, "attack_steps": "GET /a", "instances": "x"}, "not a list") == ()
    many = {"scenario": " ".join(f"GET /p{n}" for n in range(10))}
    assert len(finding_endpoints(many, [])) == MAX_ENDPOINTS
    late = {"route_ids": [f"R-{n}" for n in range(100, 140)] + ["R-008"]}       # only the first 40 IDs are read
    assert finding_endpoints(late, ROUTED) == ()


def test_the_brief_joins_scenario_and_steps_on_one_line_and_is_capped():
    assert finding_brief({"scenario": "A\n  B", "attack_steps": ["one", 7, "two"]}) == "A B Attack steps: 1. one 2. two"
    assert finding_brief({"instances": [{"scenario": "from the instance"}]}) == "from the instance"
    assert len(finding_brief({"scenario": "x " * 5000})) == BRIEF_CAP
    assert finding_brief({}) == ""


def test_plans_carry_the_endpoints_and_the_brief():
    doc = {"attack_surface": SURFACE, "threats": [
        {"id": "T-1", "cwe": "CWE-89", "severity": "high", "title": "sqli", "scenario": "GET /rest/products/search?q='",
         "evidence": {"file": "routes/search.ts", "line": 23}}]}
    plan = plans_from(doc)[0]
    assert plan.endpoints == (Endpoint("GET", "/rest/products/search", None),) and plan.brief.startswith("GET /rest")


# ── what a run needs to test a finding ───────────────────────────────────────

def _plan(cls, *endpoints):
    return FindingPlan(id="T-1", cwe="CWE-1", severity="high", title="t", match_key="k", instance="a.ts:1",
                       status="dynamic", cls=cls, reason="", endpoints=tuple(endpoints))


def _blocker(plan, identities=(), browser=None, listener=None, scope=None, safe=True, source=True):
    """With `source` a finding that names no request can still find its route, so the other rules decide."""
    return cli._blocker(plan, identities=list(identities), browser=browser, listener=listener, scope=scope or {},
                        safe=safe, source=source)


GET_LOGIN, POST = Endpoint("GET", "/a", True), Endpoint("POST", "/b", None)
ALICE = [{"role": "alice"}]
CONTRACT = {"injection_inputs": [{"finding_id": "T-1", "path": "/a", "input_location": "params", "input_name": "q",
                                  "semantics": "literal"}]}


def test_a_class_without_its_proof_prerequisite_is_not_tested():
    assert _blocker(_plan("access-control")) == ("identity", "no test identity; the proof compares two identities")
    assert _blocker(_plan("access-control"), identities=ALICE)[0] == "resource"
    assert _blocker(_plan("xss"))[0] == "browser"
    assert _blocker(_plan("xss"), browser=object()) is None
    assert _blocker(_plan("path-traversal")) == ("marker", "no marker_file in the scope")
    assert _blocker(_plan("path-traversal"), scope={"marker_file": {"path": "/m"}}) is None
    assert _blocker(_plan("ssrf")) == ("callback", "no callback in the scope")
    assert _blocker(_plan("ssrf"), listener=object()) is None


def test_the_requests_a_finding_names_decide_whether_safe_mode_or_a_missing_login_rule_it_out():
    blocker = _blocker                                       # open redirect: no proof prerequisite of its own

    assert blocker(_plan("open-redirect", POST)) == ("intrusive", "safe mode; every request the assessment names "
                                                                  "writes")
    assert blocker(_plan("open-redirect", POST), safe=False) is None
    assert blocker(_plan("open-redirect", GET_LOGIN)) == ("identity", "no test identity; every request the "
                                                                      "assessment names requires a login")
    assert blocker(_plan("open-redirect", GET_LOGIN), identities=ALICE) is None
    assert blocker(_plan("open-redirect", GET_LOGIN, Endpoint("GET", "/c", None))) is None     # one needs no login
    assert blocker(_plan("open-redirect", POST, Endpoint("PAGE", "/#/x", None)))[0] == "intrusive"
    assert blocker(_plan("open-redirect")) is None                                             # nothing named: tried


def test_injection_without_its_contract_or_with_only_writes_is_not_tested():
    get = Endpoint("GET", "/a", None)
    assert _blocker(_plan("injection", get)) == ("contract", "no literal-input contract for this finding in "
                                                             "injection_inputs")
    elsewhere = {"injection_inputs": [{**CONTRACT["injection_inputs"][0], "finding_id": "T-9"}]}
    assert _blocker(_plan("injection", get), scope=elsewhere)[0] == "contract"            # another finding's
    assert _blocker(_plan("injection", get), scope=CONTRACT) is None
    # Every proof repeats its controls and a write is never repeated, so --allow-intrusive cannot help.
    assert _blocker(_plan("injection", POST), safe=False) == ("repeat", "the proof repeats each control, and "
                                                                        "every request the assessment names writes")
    assert _blocker(_plan("injection", POST))[0] == "repeat"                              # not "intrusive mode"
    written = _plan("injection")
    written.verification_context = {"variants": [{"id": "v", "request": {"method": "PATCH", "path": "/b"}}]}
    assert _blocker(written, safe=False)[0] == "repeat"
    assert _blocker(_plan("injection", POST, get), safe=False)[0] == "contract"            # a read can carry it


def test_a_contract_does_not_make_writes_repeatable_but_a_declared_query_parameter_is_read():
    """A JSON or form field travels in the body of the write the finding names; a query parameter the
    contract declares travels in a GET on its path, which the proof may repeat, also in safe mode."""
    body = {"injection_inputs": [{**CONTRACT["injection_inputs"][0], "path": "/b", "input_location": "json",
                                  "input_name": "email"}]}
    for safe in (True, False):
        assert _blocker(_plan("injection", POST), scope=body, safe=safe)[0] == "repeat"
        form = {"injection_inputs": [{**body["injection_inputs"][0], "input_location": "form"}]}
        assert _blocker(_plan("injection", POST), scope=form, safe=safe)[0] == "repeat"
        query = {"injection_inputs": [{**body["injection_inputs"][0], "input_location": "params"}]}
        assert _blocker(_plan("injection", POST), scope=query, safe=safe) is None
    assert _blocker(_plan("injection", GET_LOGIN), scope=body)[0] == "identity"            # the read needs a login
    assert _blocker(_plan("injection"), scope=body) is None                    # nothing named: the contract's path


def test_a_finding_without_any_route_is_tested_only_with_the_source():
    reason = ("route", "the assessment names no request for this finding, and without --source none can be read")
    assert _blocker(_plan("ssrf"), listener=object(), source=False) == reason
    assert _blocker(_plan("open-redirect"), source=False) == reason
    assert _blocker(_plan("ssrf"), listener=object()) is None                              # the source may name it
    assert _blocker(_plan("ssrf", POST), listener=object(), safe=False, source=False) is None
    assert _blocker(_plan("xss", Endpoint("PAGE", "/#/x", None)), browser=object(), source=False) is None
    assert _blocker(_plan("injection"), scope=CONTRACT, source=False) is None              # the contract names it
    session = {"session_checks": [{"finding_id": "T-1", "path": "/", "cookie": "sid"}]}
    assert _blocker(_plan("session"), scope=session, source=False) is None
    with_variant = _plan("open-redirect")
    with_variant.verification_context = {"variants": [{"id": "v", "request": {"method": "GET", "path": "/r"}}]}
    assert _blocker(with_variant, source=False) is None


# ── verify lists the test cases first and does not test what it cannot confirm ─

BASE = "https://app.example.com"
SCOPE = {"schema_version": 1, "base_url": BASE, "owner": {"name": "tester"},
         "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
         "injection_inputs": [
             {"finding_id": f, "path": p, "input_location": loc, "input_name": n, "semantics": "literal"}
             for f, p, loc, n in (("T-1", "/rest/products/search", "params", "q"),
                                  ("T-2", "/rest/user/login", "json", "email"))]}
THREATS = [
    {"id": "T-1", "cwe": "CWE-89", "severity": "critical", "title": "sqli in search",
     "scenario": "GET /rest/products/search?q=' breaks the query.",
     "evidence": {"file": "routes/search.ts", "line": 23}},
    {"id": "T-2", "cwe": "CWE-89", "severity": "high", "title": "sqli in login",
     "attack_steps": ["I send POST /rest/user/login with ' OR 1=1--."],
     "evidence": {"file": "routes/login.ts", "line": 3}},
    {"id": "T-3", "cwe": "CWE-639", "severity": "high", "title": "idor",
     "evidence": {"file": "routes/b.ts", "line": 1}},
]


def _verify(tmp_path, monkeypatch, *extra):
    import yaml

    from appsec_verifier.tools import httpx_transport

    asked, sent = [], []

    class Planner:
        def next_step(self, ctx, history):
            asked.append(ctx.plan.id)
            return {"verdict": {"verdict": "not-reproducible", "rationale": "checked"}}

    def transport(method, url, headers, **kw):
        sent.append((method, url))
        return SimpleNamespace(status_code=200, headers={}, text="ok", content=b"ok", url=url)

    for name, doc in (("a.yaml", {"threats": THREATS}), ("s.yaml", SCOPE)):
        (tmp_path / name).write_text(yaml.safe_dump(doc))
    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: transport)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "a.yaml"), "--scope", str(tmp_path / "s.yaml"),
                   "--output", str(tmp_path / "out"), "--yes", "--rate", "0", "--screenshots", "none", *extra])
    path = tmp_path / "out" / "verification.yaml"
    report = yaml.safe_load(path.read_text()) if path.exists() else {"results": []}
    return rc, asked, sent, {r["finding_ref"]["id"]: (r["verdict"], r["rationale"]) for r in report["results"]}


def test_verify_shows_the_test_plan_and_does_not_test_what_this_run_cannot_confirm(tmp_path, monkeypatch, capsys):
    rc, asked, _, results = _verify(tmp_path, monkeypatch)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK and asked == ["T-1"]
    assert out.index("Test plan     1 of 3 findings will be tested") < out.index("Preflight")   # before contact
    assert "  T-1  critical  injection  sqli in search · GET /rest/products/search\n" in out
    assert "Not testable  2 findings need what this run does not have (--test-all tries anyway)" in out
    assert "test identity" in out and "→ test accounts: --account, or --identities FILE" in " ".join(out.split())
    # T-2's contract declares a JSON field of the login POST: no read request carries it, so no mode helps.
    assert "unsupported write-injection proof" in out
    assert "→ this proof method cannot repeat write requests" in " ".join(out.split())
    # verify gives a few words per need; preflight shows how to provide it
    assert "how to provide each, with lines to copy: appsec-verifier preflight" in out
    assert "create an identities file" not in out and "the injection proof sends every control twice" not in out
    assert "Identities  :" not in out            # what is missing is said once, in the test plan
    listed = out[out.index("\nResults\n"):]
    assert "T-1  critical  injection       not attempted (low)" in listed
    assert "no answered target request" in listed
    assert "· T-2 high injection needs unsupported write-injection proof sqli in login" in " ".join(listed.split())
    assert "· T-3 high access-control needs test identity idor" in " ".join(listed.split())
    assert "Verdicts   : 3 not tested\n" in out
    assert results["T-1"][0] == "not-attempted"
    assert results["T-2"] == ("not-attempted", "not tested: the proof repeats each control, and every request the "
                                               "assessment names writes")
    assert results["T-3"] == ("not-attempted", "not tested: no test identity; the proof compares two identities")


def test_test_all_tests_them_anyway(tmp_path, monkeypatch, capsys):
    assert _verify(tmp_path, monkeypatch, "--test-all")[1] == ["T-1", "T-2", "T-3"]
    out = capsys.readouterr().out
    assert "Test plan     3 of 3 findings will be tested" in out and "cannot be confirmed" in out


def test_when_nothing_can_be_tested_nothing_is_contacted_or_written(tmp_path, monkeypatch, capsys):
    rc, asked, sent, results = _verify(tmp_path, monkeypatch, "--only", "T-2,T-3")
    assert rc == cli.EXIT_BLOCKED and asked == [] and sent == [] and results == {}
    captured = capsys.readouterr()
    assert "Test plan     this run can test none of them" in captured.out
    assert "✗ Nothing to test in this run; no report was written" in captured.err
    assert "→ provide what the findings above need, or use --test-all" in captured.err
    assert "Nothing was contacted." in captured.err and "The same run without questions" not in captured.out


def test_the_test_plan_gives_lines_to_copy_and_the_browser_s_actual_cause(monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    plans = [_plan("ssrf"), _plan("xss")]
    plans[1].id = "T-2"
    blocked = {"T-1": ("callback", "no callback in the scope"), "T-2": ("browser", "no proof browser")}
    lines = cli._test_cases(cli.Style(False), plans, blocked, {"browser": ["Playwright is not installed; run `x`"]})
    text = "\n".join(lines)
    assert '  callback: {host: 127.0.0.1, port: 8099, base_url: "http://127.0.0.1:8099"}\n' in text
    assert "→ Playwright is not installed; run `x`" in text and "install Playwright and Google Chrome" not in text
    brief = "\n".join(cli._test_cases(cli.Style(False), plans, blocked, {"browser": ["Playwright is not installed"]},
                                      full=False))
    assert "→ a callback in a scope file\n" in brief and "callback: {host" not in brief
    assert "→ Playwright is not installed\n" in brief and "appsec-verifier preflight" in brief


def test_on_a_terminal_verify_cuts_a_test_plan_line_to_fit_and_preflight_shows_it_whole(monkeypatch):
    monkeypatch.setenv("COLUMNS", "80")
    plan = _plan("access-control", GET_LOGIN, Endpoint("GET", "/a/very/long/path/to/a/record/:id", True))
    plan.title = "Missing ownership check on records"
    sgr = __import__("re").compile(r"\x1b\[[0-9;]*m")
    line = sgr.sub("", cli._test_cases(cli.Style(True), [plan], {}, full=False)[-1])
    assert line.startswith("  T-1  high  access-control  Missing ownership check on records · GET /a, GET")
    assert line.endswith("…") and len(line) == 79 and "(login)" not in line
    whole = cli._test_cases(cli.Style(True), [plan], {}, full=True)[-1]
    assert sgr.sub("", whole).endswith("· GET /a, GET /a/very/long/path/to/a/record/:id")
    assert cli._test_cases(cli.Style(False), [plan], {}, full=False)[-1].endswith("/record/:id")   # not a terminal


def test_the_request_hint_names_a_scope_entry_only_where_one_can_name_the_request(monkeypatch):
    """--source helps only when the finding's file declares its route; a test_resources entry names the request
    of an access-control finding, and no scope entry does that for SSRF and the other classes."""
    monkeypatch.setenv("COLUMNS", "200")
    reason = ("route", "the assessment names no request for this finding, and without --source none can be read")
    ssrf, access = _plan("ssrf"), _plan("access-control")
    access.id = "T-2"
    for full, source, scope in ((True, "with --source, a route declared in the finding's file", "access-control "
                                 "finding can name its request in a test_resources entry"),
                                (False, "→ --source, if the finding's file declares its route",
                                 "for access control a test_resources entry")):
        alone = "\n".join(cli._test_cases(cli.Style(False), [ssrf], {"T-1": reason}, full=full))
        assert source in alone and "test_resources" not in alone and "scope entry" not in alone
        both = "\n".join(cli._test_cases(cli.Style(False), [ssrf, access], {"T-1": reason, "T-2": reason}, full=full))
        assert source in both and scope in both and "injection_inputs" not in both


def test_the_identity_hint_names_the_login_the_assessment_lists_and_an_example():
    hints = cli._run_hints({"attack_surface": [{"entry_point": "POST /rest/user/login"}]}, "http://127.0.0.1:3000/",
                           None)
    assert "login the assessment names: POST http://127.0.0.1:3000/rest/user/login" in hints["identity"]
    assert hints["identity"][-1].startswith("example: ") and "browser" not in hints
    assert cli._run_hints({}, "http://x", "Playwright is not installed")["browser"] == ["Playwright is not installed"]
    assert not any(line.startswith("login") for line in cli._run_hints({}, "http://x", None)["identity"])


def test_the_settings_name_the_report_and_only_overwrite_replaces_it(tmp_path, monkeypatch, capsys):
    _verify(tmp_path, monkeypatch)
    out = capsys.readouterr().out
    assert f"Report     : {tmp_path / 'out' / 'verification.md'}\n" in out
    assert f"Report     : {tmp_path / 'out' / 'verification.md'} (Markdown)\n" in out          # in Done
    before = (tmp_path / "out" / "verification.md").read_text()
    for removed in (None, "verification.yaml"):                 # the Markdown report alone counts too
        if removed:
            (tmp_path / "out" / removed).unlink()
        rc, asked, sent, _ = _verify(tmp_path, monkeypatch)
        captured = capsys.readouterr()
        assert rc == cli.EXIT_BLOCKED and asked == [] and sent == []
        assert f"There is already a report in {tmp_path / 'out'}" in captured.err
        assert "replace it with --overwrite, continue it with --resume" in captured.err
        assert "Nothing was contacted." in captured.err and "Report     :" not in captured.out
    assert (tmp_path / "out" / "verification.md").read_text() == before
    rc, asked, _, _ = _verify(tmp_path, monkeypatch, "--overwrite")
    assert rc == cli.EXIT_OK and asked == ["T-1"]
    assert f"Report     : replaces {tmp_path / 'out' / 'verification.md'}" in capsys.readouterr().out


def test_resume_and_overwrite_together_are_a_usage_error(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(["verify", "--assessment", "a.yaml", "--url", "http://x", "--resume", "--overwrite"])
    assert stop.value.code == cli.EXIT_BLOCKED
    assert "argument --overwrite: not allowed with argument --resume" in capsys.readouterr().err
