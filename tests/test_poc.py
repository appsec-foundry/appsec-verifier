"""Proof of concept per tested finding (VER-034, VER-035, VER-016, VER-022):
every exchange is recorded by the code, redacted of credentials, written
owner-only as HAR for every verdict, shown in the report as raw HTTP, and kept
away from the model. Access-control screenshots render a recorded HTML page
without a new request and mark only values found in it."""

from __future__ import annotations

import copy
import json
import stat
from types import SimpleNamespace

import httpx
import pytest
from test_experiments import STRATEGY

from appsec_verifier.agent import AgentProbe, AgentTools
from appsec_verifier.auth import SessionManager
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient
from appsec_verifier.tools.browser import SCREENSHOT_CLASSES
from appsec_verifier.verify import poc
from appsec_verifier.verify.probes import ProbeContext
from appsec_verifier.verify.report import build_annotations, to_markdown

SCOPE = {"base_url": "https://shop.example.com", "hosts": ["shop.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}
TA, TB = "tok-alice-123456", "tok-bob-654321"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.c2lnbmF0dXJl"


class Resp:
    def __init__(self, status=200, text='{"id":2,"UserId":2,"email":"bob@shop.test"}', headers=None):
        self.status_code, self.text = status, text
        self.headers = headers if headers is not None else {"content-type": "application/json"}


class Planner:
    def __init__(self, steps):
        self.steps, self.seen = list(steps), []

    def next_step(self, ctx, history):
        self.seen.append(json.dumps(history, default=str))
        return self.steps.pop(0) if self.steps else {"verdict": {"verdict": "inconclusive", "rationale": "end"}}


def _ctx(tmp_path, transport, cls="access-control", browser=None, scope=None):
    scope = scope or SCOPE
    http = GuardedHttpClient(ScopeGuard(scope), RunBudget(Limits()), transport)
    idents = [{"role": "customer-a", "method": "bearer", "auth": {"token_env": "TA"}},
              {"role": "customer-b", "method": "bearer", "auth": {"token_env": "TB"}}]
    sessions = SessionManager(idents, http, env={"TA": TA, "TB": TB})
    plan = FindingPlan(id="T-001", cwe="CWE-639", severity="High", title="Missing ownership check",
                       match_key="routes/basket.ts|CWE-639", instance="routes/basket.ts:1",
                       status="dynamic", cls=cls, reason="p",
                       endpoints=tuple(Endpoint("GET", path, None) for path in
                                       ("/rest/basket/:id", "/download", "/go", "/search",
                                        "/fetch", "/s", "/#/search")))
    return ProbeContext(plan=plan, scope=scope, guard=ScopeGuard(scope), budget=RunBudget(Limits()), http=http,
                        identities=idents, callback={}, safe=True, read_only=True, sessions=sessions,
                        target_base=scope["base_url"], evidence_dir=tmp_path / "evidence", browser=browser,
                        marker=("vrfaa11", "bb22"))


def _run(ctx, steps, max_steps=12):
    steps = copy.deepcopy(steps)
    if ctx.plan.cls == "access-control":
        ctx.scope = {
            **ctx.scope,
            "test_resources": [
                {
                    "id": "basket",
                    "finding_id": "T-001",
                    "path": "/rest/basket/2",
                    "allowed_roles": ["customer-b"],
                    "denied_roles": ["customer-a"],
                    "pointer": "",
                    "value": "bob@shop.test",
                }
            ],
        }
        for step in steps:
            if "verdict" in step and "proof_steps" in step["verdict"]:
                step["verdict"]["proof_steps"] = [n + 1 for n in step["verdict"]["proof_steps"]]
        steps.insert(
            0,
            {
                "tool": "plan_test",
                "args": {
                    "kind": "access-control",
                    "strategy": STRATEGY,
                    "hypothesis": "A reads B's basket",
                    "path": "/rest/basket/2",
                    "resource": "basket",
                },
            },
        )
    planner = Planner(steps)
    return AgentProbe(ctx.plan.cls, lambda: planner, max_steps=max_steps).run(ctx), planner


def _get(role, path="/rest/basket/2", **params):
    return {"tool": "http_request", "args": {**({"role": role} if role else {}), "method": "GET", "path": path,
                                             **({"params": params} if params else {})}}


def _har(tmp_path, finding="T-001"):
    path = tmp_path / "evidence" / f"{finding}-poc.har"
    return path, json.loads(path.read_text())


# ── redaction of a recorded exchange (VER-016) ───────────────────────────────


def _raw(**over):
    raw = {"method": "GET", "url": "https://shop.example.com/a?id=2&access_token=abc123&q=x",
           "headers": [("Authorization", f"Bearer {TA}"), ("Cookie", f"sid={TA}; theme=dark"),
                       ("X-Api-Key", "k-999999"), ("Accept", "application/json")],
           "body": None, "status": 302,
           "response_headers": [("Content-Type", "text/html"), ("Set-Cookie", "sid=newsession99; Path=/; HttpOnly"),
                                ("Location", f"https://shop.example.com/next?t={TA}"),
                                ("WWW-Authenticate", 'Bearer realm="api"')],
           "content": f"<p>{TA} and {JWT} for bob@shop.test</p>".encode(), "elapsed_ms": 12, "time": "T"}
    raw.update(over)
    return raw


def test_entry_redacts_credentials_and_keeps_what_the_proof_needs():
    sessions = SimpleNamespace(redact=lambda v: v.replace(TA, "[redacted]") if isinstance(v, str) else v)
    e = poc.entry(_raw(), redact=sessions.redact, identity={"Authorization": f"Bearer {TA}"}, role="customer-a")
    headers = {h["name"]: h["value"] for h in e["request"]["headers"]}
    assert headers["Authorization"] == "[identity customer-a]"
    assert headers["Cookie"] == "sid=[redacted]; theme=[redacted]"        # names stay, values go
    assert headers["X-Api-Key"] == "[redacted]" and headers["Accept"] == "application/json"
    assert "access_token=%5Bredacted%5D" in e["request"]["url"] and "id=2" in e["request"]["url"]
    res = {h["name"]: h["value"] for h in e["response"]["headers"]}
    assert res["Set-Cookie"] == "sid=[redacted]; Path=/; HttpOnly"
    assert res["WWW-Authenticate"] == 'Bearer realm="api"'          # a challenge, no credential
    assert TA not in res["Location"] and TA not in e["response"]["redirectURL"]
    text = e["response"]["content"]["text"]
    assert TA not in text and JWT not in text and "bob@shop.test" in text  # target data stays: it is the proof
    assert TA not in json.dumps(e) and "newsession99" not in json.dumps(e) and "k-999999" not in json.dumps(e)


def test_entry_cuts_long_bodies_after_redaction_and_omits_binary_ones():
    long = poc.entry(_raw(content=("x" * (poc.MAX_BODY_CHARS + 10)).encode(),
                          response_headers=[("Content-Type", "text/plain")]))
    assert len(long["response"]["content"]["text"]) == poc.MAX_BODY_CHARS
    assert long["response"]["content"]["_truncated"] is True
    png = poc.entry(_raw(content=b"\x89PNG\r\n\x1a\n\x00\xff", response_headers=[("Content-Type", "image/png")]))
    assert "text" not in png["response"]["content"] and png["response"]["content"]["_omitted"] == "binary body"
    script = poc.entry(_raw(response_headers=[("Content-Type", "text/javascript")]), omit_body="not kept")
    assert "text" not in script["response"]["content"] and script["response"]["content"]["_omitted"] == "not kept"
    cut = poc.entry(_raw(content=b"abc", content_size=9_000_000, response_headers=[("Content-Type", "text/html")]))
    assert cut["response"]["content"]["size"] == 9_000_000 and cut["response"]["content"]["_truncated"] is True


def test_a_finding_keeps_bodies_only_up_to_its_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(poc, "MAX_FINDING_BODY_CHARS", 50)
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp(200, "z" * 40, {"content-type": "text/plain"}))
    tools = AgentTools(ctx)
    for _ in range(3):
        tools.call("http_request", {"role": "customer-a", "path": "/rest/basket/2"})
    contents = [e["response"]["content"] for e in tools.take_exchanges()]
    assert [c.get("text") for c in contents[:2]] == ["z" * 40, "z" * 40]
    assert "text" not in contents[2] and "size limit" in contents[2]["_omitted"]


def test_capture_takes_the_request_as_httpx_sent_it():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": 1})))
    resp = client.post("https://shop.example.com/api", json={"a": 1}, headers={"X-Trace": "1"})
    raw = poc.capture(resp, method="POST", url="ignored", headers={}, body=None)
    assert raw["url"] == "https://shop.example.com/api" and json.loads(raw["body"]) == {"a": 1}
    assert ("x-trace", "1") in raw["headers"] and ("content-type", "application/json") in raw["headers"]
    assert raw["status"] == 200 and json.loads(raw["content"]) == {"ok": 1}


# ── every verdict gets its proof of concept (VER-034) ────────────────────────


def test_confirmed_idor_writes_the_cited_exchanges_owner_only_and_hides_them_from_the_model(tmp_path):
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp())
    result, planner = _run(ctx, [
        _get("customer-a"), _get("customer-b"),
        {"verdict": {"verdict": "confirmed", "rationale": "a read b's basket", "proof_steps": [1, 2],
                     "evidence": [{"kind": "screenshot", "path": "evidence/made-up.png"}]}}])
    assert result.verdict == "confirmed"
    path, har = _har(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [e["_step"] for e in har["log"]["entries"]] == [2, 3]
    assert all(e["_decisive"] for e in har["log"]["entries"])
    first = har["log"]["entries"][0]
    assert {"name": "Authorization", "value": "[identity customer-a]"} in first["request"]["headers"]
    assert TA not in path.read_text() and TB not in path.read_text()
    assert "bob@shop.test" in first["response"]["content"]["text"]
    kinds = [e["kind"] for e in result.evidence]
    assert "har" in kinds and "exchange" in kinds
    assert all(e["path"] != "evidence/made-up.png" for e in result.evidence)   # the model's account is not taken
    assert [s["step"] for s in result.poc["shown"]] == [2, 3]
    assert result.poc["shown"][0]["request"].startswith("GET /rest/basket/2 HTTP/1.1\nHost: shop.example.com\n")
    assert "HTTP/1.1 200 OK" in result.poc["shown"][0]["response"]
    assert all("_step" not in seen and "headers" not in seen for seen in planner.seen)   # history stays as it was


def test_a_refuted_finding_still_gets_its_proof_of_concept(tmp_path):
    answers = iter([Resp(403, '{"error":"forbidden"}'), Resp(200)])
    ctx = _ctx(tmp_path, lambda m, u, h, **k: next(answers))
    result, _ = _run(ctx, [_get("customer-a"), _get("customer-b"),
                           {"verdict": {"verdict": "blocked-by-control", "rationale": "403 for a",
                                        "proof_steps": [1, 99]}}])
    assert result.verdict == "inconclusive"
    _, har = _har(tmp_path)
    assert [e["_decisive"] for e in har["log"]["entries"]] == [True, False]
    assert [s["step"] for s in result.poc["shown"]] == [2]
    assert "HTTP/1.1 403 Forbidden" in result.poc["shown"][0]["response"]
    assert [s["decisive"] for s in result.poc["steps"]] == [True, False]
    assert "customer-b" in result.poc["steps"][1]["line"]


def test_a_finding_stopped_by_a_limit_keeps_what_it_sent(tmp_path):
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp())
    result, _ = _run(ctx, [_get("customer-a"), _get("customer-b")], max_steps=2)
    assert result.limits_hit == "attempts"
    _, har = _har(tmp_path)
    assert len(har["log"]["entries"]) == 1 and result.poc["shown"] == []


def test_a_finding_that_sent_nothing_has_no_proof_of_concept(tmp_path):
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp())
    result, _ = _run(ctx, [{"verdict": {"verdict": "inconclusive", "rationale": "nothing to do"}}])
    assert result.poc is None and not (tmp_path / "evidence" / "T-001-poc.har").exists()


def test_the_marker_file_is_in_the_proof_but_never_reaches_the_model(tmp_path):
    content = "verifier-marker-7f3a9c"
    scope = {**SCOPE, "marker_file": {"path": "/srv/verifier-marker.txt", "content": content}}
    body = "x" * 3000 + content + "y" * 3000
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp(200, body, {"content-type": "text/plain"}),
               cls="path-traversal", scope=scope)
    result, planner = _run(ctx, [_get(None, "/download", file="../../srv/verifier-marker.txt"),
                                 {"verdict": {"verdict": "confirmed", "rationale": "read", "proof_steps": [1]}}])
    assert result.verdict == "confirmed"
    assert content in result.poc["shown"][0]["response"]          # the excerpt is centred on the marker's content
    assert "characters" in result.poc["shown"][0]["response"] and "T-001-poc.har" in result.poc["shown"][0]["response"]
    assert all(content not in seen for seen in planner.seen)


def test_browser_exchanges_are_redacted_and_kept_out_of_the_tool_result(tmp_path):
    raw = poc.capture(Resp(200, "<p>hi</p>", {"content-type": "text/html"}), method="GET",
                      url="https://shop.example.com/s", headers={"Authorization": f"Bearer {TA}"})
    browser = SimpleNamespace(check=lambda url, **kw: {"executed": False, "_exchanges": [{**raw, "navigation": True}]})
    tools = AgentTools(_ctx(tmp_path, None, cls="xss", browser=browser))
    result = tools.call("browser_check", {"path": "/s", "role": "customer-a"})
    assert "_exchanges" not in result
    [e] = tools.take_exchanges()
    assert e["_navigation"] is True and TA not in json.dumps(e)
    assert {"name": "Authorization", "value": "[identity customer-a]"} in e["request"]["headers"]
    assert tools.take_exchanges() == []


# ── access-control screenshots (VER-035) ─────────────────────────────────────


class RenderBrowser:
    def __init__(self, screenshots=SCREENSHOT_CLASSES):
        self.screenshots, self.calls, self.exchanges = frozenset(screenshots), [], []

    def render(self, **kw):
        self.calls.append(kw)
        return [{"kind": "screenshot", "path": f"evidence/T-001-access-control-{len(self.calls)}.png"}]

    def render_exchanges(self, **kw):
        self.exchanges.append(kw)
        return [{"kind": "screenshot", "path": "evidence/T-001-exchange-1.png", "marked": kw["marked"]}]


def _html(m, u, h, **k):
    return Resp(200, "<html><body><h1>Basket of bob@shop.test</h1></body></html>",
                {"content-type": "text/html; charset=utf-8"})


@pytest.mark.parametrize(
    "transport, screenshots, verdict, pages, exchanges",
    [
        (_html, SCREENSHOT_CLASSES, "confirmed", 2, 1),  # the pages, and the exchanges beside them
        (lambda m, u, h, **k: Resp(), SCREENSHOT_CLASSES, "confirmed", 0, 1),  # JSON: the exchanges instead
        (_html, ("xss",), "confirmed", 0, 0),  # turned off for the class
        (_html, SCREENSHOT_CLASSES, "not-reproducible", 0, 1),  # no page proof: the exchanges
    ],
)
def test_access_control_screenshots(tmp_path, transport, screenshots, verdict, pages, exchanges):
    browser = RenderBrowser(screenshots)
    sent = []
    ctx = _ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or transport(m, u, h, **k), browser=browser)
    result, _ = _run(ctx, [_get("customer-a"), _get("customer-b"),
                           {"verdict": {"verdict": verdict, "rationale": "r", "proof_steps": [1, 2],
                                        "highlight": ["bob@shop.test", "not on the page"]}}])
    assert (len(browser.calls), len(browser.exchanges)) == (pages, exchanges)
    assert len(sent) == 2                                          # rendering sends nothing to the target
    if pages:
        call = browser.calls[0]
        assert call["highlight"] == ["bob@shop.test"]              # only values found in the response
        assert "<h1>Basket of bob@shop.test</h1>" in call["html"]
        assert "customer-a" in call["caption"][1] and "no new request" in call["caption"][2]
        assert sum(e["kind"] == "screenshot" for e in result.evidence) == 3
    if exchanges:
        page = browser.exchanges[0]["html"]
        assert "<mark>[identity customer-a]</mark>" in page and "<mark>[identity customer-b]</mark>" in page
        if verdict == "confirmed":
            assert "<mark>bob@shop.test</mark>" in page and "not on the page" not in page
            assert "<span class=tag>named in the verdict ▸</span><mark>bob@shop.test</mark>" in page
        else:
            assert result.verdict == "inconclusive" and "protected resource is present" in result.rationale


# ── the exchange image (VER-035) ─────────────────────────────────────────────


def _shot(tmp_path, cls, transport, steps, scope=None, listener=None):
    browser = RenderBrowser()
    ctx = _ctx(tmp_path, transport, cls=cls, browser=browser, scope=scope)
    ctx.listener = listener
    result, _ = _run(ctx, steps)
    return result, (browser.exchanges[0] if browser.exchanges else None)


def test_exchange_image_marks_the_redirect(tmp_path):
    host = "vrfaa11bb22.invalid"
    result, shot = _shot(tmp_path, "open-redirect",
                         lambda m, u, h, **k: Resp(302, "", {"location": f"https://{host}/"}),
                         [_get(None, "/go", to=f"https://{host}/"),
                          {"verdict": {"verdict": "confirmed", "rationale": "r", "proof_steps": [1]}}])
    assert result.verdict == "confirmed"
    assert f"<mark>location: https://{host}/</mark>" in shot["html"] and f"<mark>{host}</mark>" in shot["html"]
    assert shot["marked"] >= 2 and shot["finding_id"] == "T-001"


def test_exchange_image_marks_the_marker_file(tmp_path):
    content = "verifier-marker-7f3a9c"
    scope = {**SCOPE, "marker_file": {"path": "/srv/verifier-marker.txt", "content": content}}
    _, shot = _shot(tmp_path, "path-traversal", lambda m, u, h, **k: Resp(200, f"a {content} b",
                                                                        {"content-type": "text/plain"}),
                    [_get(None, "/download", file="../../srv/verifier-marker.txt"),
                     {"verdict": {"verdict": "confirmed", "rationale": "r", "proof_steps": [1]}}], scope=scope)
    assert f"<mark>{content}</mark>" in shot["html"] and "<mark>verifier-marker.txt</mark>" in shot["html"]
    assert "<b>marker file read: yes</b>" in shot["html"]


def test_exchange_image_marks_the_input_and_answer_that_differ(tmp_path):
    def transport(m, u, h, **k):
        return Resp(200, '{"items":[1,2,3]}' if "1=1" in str(k.get("params")) else '{"items":[]}')

    _, shot = _shot(tmp_path, "injection", transport,
                    [_get(None, "/search", q="x' OR 1=1--"), _get(None, "/search", q="x' OR 1=2--"),
                     {"verdict": {"verdict": "confirmed", "rationale": "r", "proof_steps": [1, 2]}}])
    page = shot["html"]
    assert "<mark>x%27+OR+1%3D1--</mark>" in page and "<mark>x%27+OR+1%3D2--</mark>" in page   # as httpx sends it
    assert "<mark>1</mark></span>,2,3]}" in page and "<mark>]}</mark>" in page      # where the two answers part
    assert page.count("<mark>") == 4 and "HTTP/<mark>" not in page             # once, not wherever "1" recurs
    assert page.count("<span class=tag>input ▸</span><mark>x%27+OR+1%3D") == 2       # each mark says what it is
    assert page.count("<span class=tag>answer differs ▸</span><mark>") == 2
    assert "<b>input, decoded: x&#x27; OR 1=1--</b>" in page
    assert "answered in" not in page                                           # no time: not a timing proof


def test_exchange_image_marks_the_times_of_a_timing_proof(tmp_path):
    from datetime import timedelta

    def transport(m, u, h, **k):
        slow = "SLEEP" in str(k.get("params"))
        resp = Resp(200, '{"items":[]}')
        resp.elapsed = timedelta(milliseconds=2600 if slow else 40)
        return resp

    _, shot = _shot(tmp_path, "injection", transport,
                    [_get(None, "/search", q="x"), _get(None, "/search", q="x' AND SLEEP(2)--"),
                     {"verdict": {"verdict": "not-reproducible", "rationale": "r", "proof_steps": [1, 2]}}])
    assert "<b>answered in 40 ms</b>" in shot["html"] and "<b>answered in 2600 ms</b>" in shot["html"]


def test_exchange_image_marks_the_callback_marker(tmp_path):
    listener = SimpleNamespace(
        base_url="http://127.0.0.1:4444",
        wait_for=lambda marker, timeout: True,
        hits=lambda marker: [{"time": "t", "method": "GET", "source": "127.0.0.1"}],
    )
    _, shot = _shot(
        tmp_path,
        "ssrf",
        lambda m, u, h, **k: Resp(200, "{}"),
        [
            _get(None, "/fetch", url="http://127.0.0.1:4444/vrfaa11bb22"),
            {"verdict": {"verdict": "confirmed", "rationale": "r"}},
        ],
        listener=listener,
        scope={**SCOPE, "callback": {"expect_rejected": True}},
    )
    assert "callback" in shot["html"] and "<mark>vrf" in shot["html"]
    assert "<b>callback listener received the marker: yes</b>" in shot["html"]


def test_exchange_image_escapes_everything_the_target_sent(tmp_path):
    _, shot = _shot(tmp_path, "access-control",
                    lambda m, u, h, **k: Resp(403, "<script>alert(1)</script><img src=x>",
                                              {"content-type": "application/json", "x-evil": "<b>"}),
                    [_get("customer-a"), {"verdict": {"verdict": "blocked-by-control", "rationale": "r",
                                                      "proof_steps": [1]}}])
    page = shot["html"]
    assert "<script" not in page and "<img" not in page and "<b>" not in page.split("</header>", 1)[1]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_a_verdict_that_cites_no_step_gets_an_image_that_says_it_proves_nothing(tmp_path):
    """VER-035: e.g. a finding a limit stopped; the report still shows no step as one the verdict rests on."""
    result, shot = _shot(tmp_path, "injection", lambda m, u, h, **k: Resp(),
                         [_get(None, "/search"), {"verdict": {"verdict": "not-reproducible", "rationale": "r"}}])
    assert "Step 1 · GET as anonymous" in shot["html"]
    assert "cites no step" in shot["html"] and "proves nothing" in shot["html"]
    assert "what the verdict rests on" not in shot["html"]
    assert result.poc["shown"] == [] and not any(s["decisive"] for s in result.poc["steps"])


def test_a_finding_a_limit_stopped_gets_the_image_of_its_requests(tmp_path):
    browser = RenderBrowser()
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp(500, "{}"), cls="injection", browser=browser)
    result, _ = _run(ctx, [_get(None, "/search", q=str(n)) for n in range(5)])   # three server errors stop it
    assert result.limits_hit == "stagnation" and len(browser.exchanges) == 2
    assert all("cites no step" in panel["html"] for panel in browser.exchanges)
    assert sum(panel["html"].count("<section>") for panel in browser.exchanges) == 3


def test_the_uncited_image_shows_only_answered_requests_after_the_last_plan():
    history = [{"tool": "http_request", "result": {"status": 200}},
               {"tool": "plan_test", "result": {"accepted": True}},
               {"tool": "http_request", "result": {"error": "request refused"}},
               {"tool": "http_request", "result": {"status": 401}},
               {"tool": "plan_test", "result": {"error": "rejected"}},
               {"tool": "browser_check", "result": {"status": 200}}]
    steps = [{"step": n, "entries": [{"n": n}]} for n in (1, 3, 4, 6)]
    assert [n for n, _ in poc._tried(history, steps)] == [4, 6]
    assert [n for n, _ in poc._tried(history[2:], [{"step": 2, "entries": [{}]}])] == [2]   # no plan: all


def test_an_executed_xss_gets_the_exchange_image_beside_the_page_with_the_opened_page_marked(tmp_path):
    raw = poc.capture(
        Resp(200, "<html><app-root></app-root></html>", {"content-type": "text/html"}),
        method="GET",
        url="https://shop.example.com/",
    )  # the fragment never reaches the server
    page = {
        "executed": True,
        "context_verified": True,
        "evidence": [{"kind": "screenshot", "path": "evidence/T-001-xss-1.png"}],
        "_exchanges": [{**raw, "navigation": True}],
    }
    browser = RenderBrowser()
    browser.check = lambda url, **kw: {**page, "_exchanges": list(page["_exchanges"])}
    ctx = _ctx(tmp_path, None, cls="xss", browser=browser)
    result, _ = _run(
        ctx,
        [
            {
                "tool": "browser_check",
                "args": {"path": "/#/search?q=%3Ciframe%20src%3D%22javascript:alert('vrfaa11'%2B'bb22')%22%3E"},
            },
            {"verdict": {"verdict": "confirmed", "rationale": "r"}},
        ],
    )
    assert result.verdict == "confirmed" and len(browser.exchanges) == 1
    assert [e["kind"] for e in result.evidence].count("screenshot") == 2
    html = browser.exchanges[0]["html"]
    assert (
        "<b>opened in the browser: /#/search?q=&lt;iframe src=&quot;javascript:alert(&#x27;vrfaa11&#x27;+"
        "&#x27;bb22&#x27;)&quot;&gt;</b>"
    ) in html
    assert "<b>marker executed in the browser: yes</b>" in html


def _session_image(cwe, history):
    raw = {"method": "GET", "url": SCOPE["base_url"] + "/account", "body": None, "status": 200,
           "headers": [("Accept", "*/*"), ("Authorization", f"Bearer {TA}")],
           "response_headers": [("Content-Type", "text/html"), ("Set-Cookie", "sid=s3cr3tvalue; Path=/; Secure"),
                                ("Set-Cookie", "lang=de; Path=/")],
           "content": b"<h1>Account</h1>", "time": "2026-11-08T10:12:03.123456Z"}
    e = poc.entry(raw, identity={"Authorization": f"Bearer {TA}"}, role="customer-a")
    check = {"finding_id": "T-051", "id": "account", "path": "/account", "role": "customer-a", "cookie_name": "sid"}
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-051", cls="session", cwe=cwe), marker=("vrfaa", "bb"),
                          scope={**SCOPE, "session_checks": [check]})
    return poc.exchange_document(ctx, history, [(2, e), (3, e)], "confirmed", "evidence/T-051-poc.har")


@pytest.mark.parametrize(
    "cwe, seen, label",
    [
        ("CWE-1004", {"httponly": False}, "HttpOnly missing"),
        ("CWE-614", {"secure": True}, "Secure set"),
        ("CWE-1275", {"samesite": ""}, "SameSite missing"),
        ("CWE-1275", {"samesite": "none"}, "SameSite=None"),
    ],
)
def test_exchange_image_marks_the_set_cookie_line_of_the_observed_session_cookie(cwe, seen, label):
    cookie = {"name": "sid", "secure": True, "httponly": False, "samesite": "lax", "active": True, **seen}
    observed = {"tool": "http_request", "args": {"path": "/account", "role": "customer-a"},
                "result": {"status": 200, "session_cookies": [cookie]}}
    plan = {"tool": "plan_test", "args": {"kind": "session", "resource": "account"}, "result": {"accepted": True}}
    page, marked = _session_image(cwe, [plan, observed, observed])
    assert page.count(f"<span class=hit><span class=tag>{label} ▸</span><mark>Set-Cookie: sid=") == 2
    assert marked == 2 and "<mark>Set-Cookie: lang=" not in page and "s3cr3tvalue" not in page
    assert "[identity customer-a]" in page and "<mark>[identity customer-a]</mark>" not in page  # not decisive here
    assert "First captured 2026-11-08T10:12:03Z." in page


def test_exchange_image_marks_no_cookie_without_a_declared_session_plan():
    page, marked = _session_image("CWE-1004", [{}, {}, {}])
    assert marked == 0 and "<mark>" not in page and "Set-Cookie: sid=" in page


def test_screenshots_show_times_to_the_second():
    assert poc.shown_time("2026-11-08T13:24:45.623716Z") == "2026-11-08T13:24:45Z"
    assert poc.shown_time("2026-11-08T13:24:45.5+01:00") == "2026-11-08T13:24:45+01:00"
    assert poc.shown_time("2026-11-08T13:24:45Z") == "2026-11-08T13:24:45Z"


# ── report and export ────────────────────────────────────────────────────────


def _doc(tmp_path):
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp(200, 'bob@shop.test see ```` here'))
    result, _ = _run(ctx, [_get("customer-a"), _get("customer-b"),
                           {"verdict": {"verdict": "confirmed", "rationale": "r", "proof_steps": [1, 2]}}])
    r = {"result_id": "VF-001", "finding_ref": {"id": "T-001", "cwe": "CWE-639", "match_key": "k"},
         "class": "access-control", "verdict": result.verdict, "evidence": result.evidence, "poc": result.poc}
    return {"meta": {"summary": {"total": 1, "confirmed": 1}}, "results": [r]}


def test_report_shows_the_proof_of_concept_as_raw_http_that_target_content_cannot_break(tmp_path):
    md = to_markdown(_doc(tmp_path))
    assert "#### Proof of concept" in md and "evidence/T-001-poc.har" in md
    assert "Authorization: ⟦[identity customer-a]⟧" in md and TA not in md
    assert "identity ▸" not in md                       # the image's labels stay out of the recorded text
    # Request and response in one fence longer than the body's four backticks.
    block = md.split("`````http\n", 1)[1].split("\n`````", 1)[0]
    assert "HTTP/1.1 200 OK" in block and block.index("HTTP/1.1") < block.index("HTTP/1.1 200 OK")
    assert "review before sharing" in md.split("## Summary")[0]


_NOTES = json.dumps({"data": [{"id": i, "role": "customer", "note": "n" * 40} for i in range(30)]})


@pytest.mark.parametrize("cls, mime, body, marks, shown, hidden", [
    # A page the XSS marker did not reach: the browser decides, its source is noise.
    ("xss", "text/html", "<html><title>Shop</title>" + "x" * 900 + "</html>", [("payload", "m1")],
     "page source omitted", "<title>"),
    # A page that holds the marker keeps the window around it.
    ("xss", "text/html", "<p>" + "a" * 900 + "m1</p>", [("payload", "m1")], "m1", "page source omitted"),
    ("access-control", "text/html", "<html><style>body{margin:0}</style><h1>No Authorization header</h1>"
     + " " * 900 + "</html>", [], "Visible text: No Authorization header", "margin:0"),
    ("access-control", "application/json", _NOTES, [], "/data/0/role", "/note"),
    ("access-control", "application/json", '{"id":50,"description":"m1 marker"}', [("marker", "m1")],
     '{"id":50,"description":"m1 marker"}', "Selected JSON fields"),           # short: whole
])
def test_the_report_shows_the_decisive_part_of_a_long_response(cls, mime, body, marks, shown, hidden):
    """VER-034: each step the verdict rests on with the decisive part of its response."""
    e = poc.entry(poc.capture(Resp(200, body, {"content-type": mime}), method="GET",
                              url="https://shop.example.com/x"))
    ctx = SimpleNamespace(plan=SimpleNamespace(cls=cls), marker=("m1", "m2"))
    text = poc._report_body(ctx, e, body, marks)
    assert shown in text and hidden not in text


def test_a_browser_step_names_the_page_it_opened(tmp_path):
    """The # part of the opened page never reaches the server: the step line names the page, not GET /."""
    raw = poc.capture(Resp(200, "<html></html>", {"content-type": "text/html"}), method="GET",
                      url="https://shop.example.com/")
    step = {"step": 1, "tool": "browser_check", "entries": [poc.entry(raw)]}
    history = [{"tool": "browser_check", "args": {"path": "/#/search?q=<img>"}, "result": {"executed": True}}]
    line = poc._line(step, history)
    assert line.startswith("browser_check GET /#/search?q=<img> as anonymous → 200") and "marker executed" in line


def test_step_lines_with_markup_stay_inside_a_fence(tmp_path):
    doc = _doc(tmp_path)
    doc["results"][0]["poc"]["steps"][0]["line"] = "browser_check GET https://shop.example.com/?q=<img src=x>"
    md = to_markdown(doc)
    fence = md.split("```text\n", 1)[1].split("\n```", 1)[0]
    assert "<img src=x>" in fence and md.count("<img src=x>") == 1


def test_export_never_points_at_recorded_responses(tmp_path):
    ann = build_annotations(_doc(tmp_path), verification_report="v.yaml")["annotations"][0]
    assert ann["evidence_ref"] == "evidence/T-001-exchanges.json"


def test_a_report_with_a_proof_of_concept_is_schema_valid(tmp_path):
    from pathlib import Path

    import yaml
    from jsonschema.validators import validator_for

    from appsec_verifier.verify import default_registry, run_verification

    plan = FindingPlan(id="T-001", cwe="CWE-639", severity="High", title="IDOR", match_key="k|CWE-639",
                       instance="k:1", status="dynamic", cls="access-control", reason="p")
    doc = run_verification(assessment_path=Path("a.yaml"), scope=SCOPE, scope_path=Path("s.yaml"), plans=[plan],
                           limits=Limits(), identities=[], registry=default_registry(), verifier_version="test",
                           target_base=SCOPE["base_url"], authorization={"confirmed": True, "mode": "ci-flag"})
    sample = _doc(tmp_path)["results"][0]
    doc["results"][0].update(verdict="confirmed", evidence=sample["evidence"], poc=sample["poc"])
    schema = yaml.safe_load((Path(__file__).resolve().parent.parent / "schemas" /
                             "verification.schema.yaml").read_text())
    assert not sorted(e.message for e in validator_for(schema)(schema).iter_errors(doc))


def test_final_screenshot_deadline_keeps_verdict_and_har(tmp_path, monkeypatch):
    import time

    ctx = _ctx(tmp_path, lambda *a, **kw: Resp(302, "", {"location": "https://vrfaa11bb22.invalid/"}),
               cls="open-redirect", browser=RenderBrowser())
    ctx.budget = RunBudget(Limits(max_duration_s=1))
    completed = []

    def stuck(*args):
        time.sleep(3)
        completed.append(True)
        return []

    monkeypatch.setattr(poc, "_exchange_screenshot", stuck)
    result, _ = _run(ctx, [_get(None, "/go"),
                          {"verdict": {"verdict": "confirmed", "rationale": "redirected", "proof_steps": [1]}}])
    assert result.verdict == "confirmed" and result.limits_hit == "time"
    assert not completed and result.poc and result.poc["steps"]
    assert any(e["kind"] == "har" for e in result.evidence)
    assert any("screenshots may be missing" in note for note in result.observations)
    _, har = _har(tmp_path)
    assert len(har["log"]["entries"]) == 1


def test_expired_run_only_saves_existing_exchanges(tmp_path):
    ctx = _ctx(tmp_path, lambda *a, **kw: Resp(), browser=RenderBrowser())
    ticks = [0.0]
    ctx.budget = RunBudget(Limits(max_duration_s=1), clock=lambda: ticks[0])

    class Planner:
        def next_step(self, context, history):
            if not history:
                return _get("customer-a")
            ticks[0] = 2.0
            return {"verdict": {"verdict": "inconclusive", "rationale": "finished"}}

    result = AgentProbe("access-control", Planner).run(ctx)
    assert result.limits_hit == "time" and result.verdict == "inconclusive"
    assert result.poc and len(result.poc["steps"]) == 1
    assert not ctx.browser.calls and not ctx.browser.exchanges
    _, har = _har(tmp_path)
    assert len(har["log"]["entries"]) == 1


def test_interrupted_har_write_does_not_replace_previous_evidence(tmp_path, monkeypatch):
    from appsec_verifier.limits import LimitExceeded

    ctx = _ctx(tmp_path, lambda *a, **kw: Resp())
    ctx.evidence_dir.mkdir()
    path = ctx.evidence_dir / "T-001-poc.har"
    path.write_text("previous complete record")

    def interrupted(*args):
        raise LimitExceeded("time", "interrupted")

    monkeypatch.setattr(poc.os, "replace", interrupted)
    with pytest.raises(LimitExceeded):
        poc._write_har(ctx, [])
    assert path.read_text() == "previous complete record"
    assert list(ctx.evidence_dir.iterdir()) == [path]


def test_compact_images_keep_late_markers_and_escape_untrusted_text():
    marker = 'verifier-late-marker'
    text = 'x' * 5000 + marker + '<script>alert(1)</script>'
    excerpt = poc._image_excerpt(text, [('marker', marker)])
    assert marker in excerpt and len(excerpt) < 800 and '[…]' in excerpt
    rendered, count = poc._marked(excerpt, [('marker', marker)])
    assert count == 1 and '<script>' not in rendered and '&lt;script&gt;' in rendered


def test_compact_error_response_omits_css_and_preserves_original_record():
    e = poc.entry(_raw(status=401, response_headers=[('Content-Type', 'text/html')],
                       content=b'<style>body{height:99999px}</style><h1>Unauthorized</h1><script>evil()</script>'))
    before = copy.deepcopy(e)
    ctx = SimpleNamespace(plan=SimpleNamespace(cls='access-control'))
    text = poc._image_response(ctx, e, [], [])
    assert '401' in text and 'Unauthorized' in text
    assert 'height:99999px' not in text and 'evil()' not in text
    assert e == before


def test_report_excerpts_are_marked_while_http_images_stay_saved(tmp_path):
    browser = RenderBrowser()
    ctx = _ctx(tmp_path, lambda *a, **kw: Resp(), browser=browser)
    result, _ = _run(ctx, [_get("customer-a"), _get("customer-b"),
                          {"verdict": {"verdict": "confirmed", "rationale": "cross-account read",
                                       "proof_steps": [1, 2], "highlight": ["bob@shop.test"]}}])
    from dataclasses import asdict

    from appsec_verifier.verify.report import _poc_markdown

    text = "\n".join(_poc_markdown(asdict(result)))
    assert "⟦[identity customer-a]⟧" in text
    assert "⟦bob@shop.test⟧" in text
    assert "```http" in text
    assert "![" not in text  # API-only: neither HTTP screenshots nor a manufactured UI
    assert any(e["path"].endswith("-exchange-1.png") for e in result.evidence)
    har = json.loads((tmp_path / result.poc["file"]).read_text())
    assert "⟦" not in json.dumps(har)
    assert "bob@shop.test" in result.poc["shown"][0]["response"]
