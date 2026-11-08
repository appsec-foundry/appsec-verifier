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

from appsec_verifier.agent import AgentProbe, AgentTools
from appsec_verifier.auth import SessionManager
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
                       status="dynamic", cls=cls, reason="p")
    return ProbeContext(plan=plan, scope=scope, guard=ScopeGuard(scope), budget=RunBudget(Limits()), http=http,
                        identities=idents, callback={}, safe=True, read_only=True, sessions=sessions,
                        target_base=scope["base_url"], evidence_dir=tmp_path / "evidence", browser=browser,
                        marker=("vrfaa11", "bb22"))


def _run(ctx, steps, max_steps=12):
    steps = copy.deepcopy(steps)
    if ctx.plan.cls == "access-control":
        ctx.scope = {**ctx.scope, "test_resources": [{"id": "basket", "finding_id": "T-001",
                     "path": "/rest/basket/2", "allowed_roles": ["customer-b"], "denied_roles": ["customer-a"],
                     "pointer": "", "value": "bob@shop.test"}]}
        for step in steps:
            if "verdict" in step and "proof_steps" in step["verdict"]:
                step["verdict"]["proof_steps"] = [n + 1 for n in step["verdict"]["proof_steps"]]
        steps.insert(0, {"tool": "plan_test", "args": {"kind": "access-control", "hypothesis": "A reads B's basket",
                         "path": "/rest/basket/2", "resource": "basket"}})
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


@pytest.mark.parametrize("transport, screenshots, verdict, pages, exchanges", [
    (_html, SCREENSHOT_CLASSES, "confirmed", 2, 1),                     # the pages, and the exchanges beside them
    (lambda m, u, h, **k: Resp(), SCREENSHOT_CLASSES, "confirmed", 0, 1),   # JSON: the exchanges instead
    (_html, ("xss",), "confirmed", 0, 0),                               # turned off for the class
    (_html, SCREENSHOT_CLASSES, "not-reproducible", 0, 1),              # no page proof: the exchanges
])
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
    assert "<mark>marker file read: yes</mark>" in shot["html"]


def test_exchange_image_marks_the_input_and_answer_that_differ(tmp_path):
    def transport(m, u, h, **k):
        return Resp(200, '{"items":[1,2,3]}' if "1=1" in str(k.get("params")) else '{"items":[]}')

    _, shot = _shot(tmp_path, "injection", transport,
                    [_get(None, "/search", q="x' OR 1=1--"), _get(None, "/search", q="x' OR 1=2--"),
                     {"verdict": {"verdict": "confirmed", "rationale": "r", "proof_steps": [1, 2]}}])
    page = shot["html"]
    assert "<mark>x%27+OR+1%3D1--</mark>" in page and "<mark>x%27+OR+1%3D2--</mark>" in page   # as httpx sends it
    assert "<mark>1</mark>,2,3]}" in page and "<mark>]}</mark>" in page      # where the two answers part
    assert page.count("<mark>") == 6 and "HTTP/<mark>" not in page             # once, not wherever "1" recurs
    assert page.count("<span class=tag>input ▸</span><mark>x%27+OR+1%3D") == 2       # each mark says what it is
    assert page.count("<span class=tag>answer differs ▸</span><mark>") == 2
    assert "<mark>input, decoded: x&#x27; OR 1=1--</mark>" in page
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
    assert "<mark>answered in 40 ms</mark>" in shot["html"] and "<mark>answered in 2600 ms</mark>" in shot["html"]


def test_exchange_image_marks_the_callback_marker(tmp_path):
    listener = SimpleNamespace(base_url="http://127.0.0.1:4444", wait_for=lambda marker, timeout: True,
                               hits=lambda marker: [{"time": "t", "method": "GET", "source": "127.0.0.1"}])
    _, shot = _shot(tmp_path, "ssrf", lambda m, u, h, **k: Resp(200, "{}"),
                    [_get(None, "/fetch", url="http://127.0.0.1:4444/vrfaa11bb22"),
                     {"verdict": {"verdict": "confirmed", "rationale": "r"}}], listener=listener)
    assert "<mark>vrfaa11bb22</mark>" in shot["html"]
    assert "<mark>callback listener received the marker: yes</mark>" in shot["html"]


def test_exchange_image_escapes_everything_the_target_sent(tmp_path):
    _, shot = _shot(tmp_path, "access-control",
                    lambda m, u, h, **k: Resp(403, "<script>alert(1)</script><img src=x>",
                                              {"content-type": "application/json", "x-evil": "<b>"}),
                    [_get("customer-a"), {"verdict": {"verdict": "blocked-by-control", "rationale": "r",
                                                      "proof_steps": [1]}}])
    page = shot["html"]
    assert "<script" not in page and "<img" not in page and "<b>" not in page.split("</header>", 1)[1]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_no_exchange_image_without_decisive_steps(tmp_path):
    _, shot = _shot(tmp_path, "injection", lambda m, u, h, **k: Resp(),
                    [_get(None, "/search"), {"verdict": {"verdict": "not-reproducible", "rationale": "r"}}])
    assert shot is None


def test_an_executed_xss_gets_the_exchange_image_beside_the_page_with_the_opened_page_marked(tmp_path):
    raw = poc.capture(Resp(200, "<html><app-root></app-root></html>", {"content-type": "text/html"}),
                      method="GET", url="https://shop.example.com/")       # the fragment never reaches the server
    page = {"executed": True, "evidence": [{"kind": "screenshot", "path": "evidence/T-001-xss-1.png"}],
            "_exchanges": [{**raw, "navigation": True}]}
    browser = RenderBrowser()
    browser.check = lambda url, **kw: {**page, "_exchanges": list(page["_exchanges"])}
    ctx = _ctx(tmp_path, None, cls="xss", browser=browser)
    result, _ = _run(ctx, [{"tool": "browser_check", "args": {"path": "/#/search?q=%3Ciframe%20src%3D%22javascript:"
                                                                      "alert('vrfaa11'%2B'bb22')%22%3E"}},
                           {"verdict": {"verdict": "confirmed", "rationale": "r"}}])
    assert result.verdict == "confirmed" and len(browser.exchanges) == 1
    assert [e["kind"] for e in result.evidence].count("screenshot") == 2
    html = browser.exchanges[0]["html"]
    assert ("<mark>opened in the browser: /#/search?q=&lt;iframe src=&quot;javascript:alert(&#x27;vrfaa11&#x27;+"
            "&#x27;bb22&#x27;)&quot;&gt;</mark>") in html
    assert "<mark>marker executed in the browser: yes</mark>" in html


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
    assert "Authorization: [identity customer-a]" in md and TA not in md
    assert "`````http\nHTTP/1.1 200 OK" in md          # a fence longer than the body's four backticks
    assert "review before sharing" in md.split("## Summary")[0]


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
