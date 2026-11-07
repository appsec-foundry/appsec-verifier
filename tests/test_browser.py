"""XSS proof browser, offline (VER-009, VER-018, VER-022): browser requests are
answered only through the guarded client, identity headers stay on the target
origin, safe mode and limits hold, redirects go back to the browser, only the
evaluated marker counts, a confirmed XSS needs an executed marker, and
screenshots stay out of the Analyzer export. Chrome itself is not started here;
see test_browser_live.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from appsec_verifier.agent import AgentProbe, AgentTools, ToolError
from appsec_verifier.agent.prompts import _system
from appsec_verifier.cli import _proof_browser
from appsec_verifier.limits import LimitExceeded, Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient
from appsec_verifier.tools.browser import (
    SCREENSHOT_NOTE,
    Abort,
    BrowserError,
    BrowserUnavailable,
    Fulfil,
    ProofBrowser,
    _init_script,
    _isolation_problem,
    _wrapper_script,
    answer,
    marker_expression,
    new_marker,
)
from appsec_verifier.verify.probes import ProbeContext
from appsec_verifier.verify.report import build_annotations, to_markdown

SCOPE = {"base_url": "https://shop.example.com", "hosts": ["shop.example.com", "cdn.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}
BASE = SCOPE["base_url"]


class Transport:
    def __init__(self, responses=None):
        self.calls, self.responses = [], list(responses or [])

    def __call__(self, method, url, headers, **kw):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), **kw})
        if self.responses:
            return self.responses.pop(0)
        return SimpleNamespace(status_code=200, headers={"content-type": "text/html"}, content=b"<p>ok</p>")


def _http(transport):
    return GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), transport)


def _answer(transport, method="GET", url=BASE + "/p", headers=None, body=None, identity=None, safe=True):
    return answer(method, url, headers or {}, body, http=_http(transport),
                  identity_headers=identity or {}, target_base=BASE, safe=safe)


# ── every browser request goes through the guarded client ─────────────────────

def test_in_scope_request_is_answered_with_identity_headers_on_the_target_origin():
    t = Transport()
    out = _answer(t, headers={"accept": "text/html", "host": "x", "cookie": "app=1"},
                  identity={"Authorization": "Bearer AAA", "Cookie": "sid=2"})
    assert isinstance(out, Fulfil) and out.status == 200 and out.body == b"<p>ok</p>"
    sent = t.calls[0]["headers"]
    assert sent["Authorization"] == "Bearer AAA" and sent["Cookie"] == "app=1; sid=2" and "host" not in sent


def test_identity_headers_never_go_to_another_origin():
    t = Transport()
    _answer(t, url="https://cdn.example.com/app.js", identity={"Authorization": "Bearer AAA"})
    assert "Authorization" not in t.calls[0]["headers"]


def test_out_of_scope_request_is_aborted_without_contact():
    t = Transport()
    out = _answer(t, url="https://evil.example.net/steal")
    assert isinstance(out, Abort) and "out of scope" in out.reason and t.calls == []


def test_safe_mode_blocks_state_changing_requests_from_page_scripts():
    t = Transport()
    assert isinstance(_answer(t, method="POST", body=b"x=1"), Abort) and t.calls == []
    assert isinstance(_answer(t, method="POST", body=b"x=1", safe=False), Fulfil)
    assert t.calls[0]["content"] == b"x=1"


def test_redirects_go_back_to_the_browser_for_a_fresh_check():
    t = Transport([SimpleNamespace(status_code=302, headers={"Location": "https://evil.example.net/"}, content=b"")])
    out = _answer(t)
    assert out.status == 302 and out.headers["location"] == "https://evil.example.net/" and len(t.calls) == 1


def test_response_headers_are_cleaned_for_fulfilment():
    headers = httpx.Headers([("Content-Encoding", "gzip"), ("Content-Length", "9"), ("Set-Cookie", "a=1"),
                             ("Set-Cookie", "b=2"), ("Content-Type", "text/html")])
    out = _answer(Transport([SimpleNamespace(status_code=200, headers=headers, content=b"<p>x</p>")]))
    assert out.headers == {"set-cookie": "a=1\nb=2", "content-type": "text/html"}


def test_oversized_response_is_aborted():
    big = SimpleNamespace(status_code=200, headers={}, content=b"x" * (5 * 1024 * 1024 + 1))
    assert isinstance(_answer(Transport([big])), Abort)


def test_request_budget_stops_the_browser():
    budget = RunBudget(Limits(max_requests=1))
    budget.note_request()                                              # the cap is already used up
    http = GuardedHttpClient(ScopeGuard(SCOPE), budget, Transport())
    with pytest.raises(LimitExceeded):
        answer("GET", BASE + "/p", {}, None, http=http, identity_headers={}, target_base=BASE, safe=True)


def test_guarded_client_can_hand_redirects_back():
    t = Transport([SimpleNamespace(status_code=302, headers={"Location": "/next"}, content=b"")])
    resp = _http(t).request("GET", BASE + "/a", {}, follow_redirects=False)
    assert resp.status_code == 302 and len(t.calls) == 1


# ── marker: only the evaluated join counts ────────────────────────────────────

def test_marker_parts_are_random_and_only_their_join_is_in_the_page_hook():
    a, b = new_marker()
    assert a.startswith("vrf") and (a, b) != new_marker()
    script = _init_script((a, b))
    assert f'"{a}{b}"' in script and marker_expression((a, b)) == f"'{a}'+'{b}'"
    assert "text === marker" in script


def test_system_prompt_gives_the_marker_only_for_xss():
    plan = SimpleNamespace(cls="xss")
    ctx = SimpleNamespace(plan=plan, identities=[], safe=True, marker=("vrfaa", "bb"))
    assert "alert('vrfaa'+'bb')" in _system(ctx)
    ctx.plan = SimpleNamespace(cls="access-control")
    assert "vrfaa" not in _system(ctx)


# ── agent tool ────────────────────────────────────────────────────────────────

class FakeBrowser:
    def __init__(self, result=None, error=None):
        self.calls, self.result, self.error = [], result or {"executed": False}, error

    def check(self, url, **kw):
        self.calls.append({"url": url, **kw})
        if self.error:
            raise self.error
        return self.result


def _ctx(cls="xss", browser=None, sessions=None, safe=True):
    plan = FindingPlan(id="T-9", cwe="CWE-79", severity="High", title="xss", match_key="s.ts|CWE-79",
                       instance="s.ts:1", status="dynamic", cls=cls, reason="r")
    return ProbeContext(plan=plan, scope=SCOPE, guard=ScopeGuard(SCOPE), budget=RunBudget(Limits()), http=None,
                        identities=[], callback={}, safe=safe, read_only=safe, sessions=sessions,
                        target_base=BASE, browser=browser, marker=("vrfaa", "bb"))


def test_browser_check_passes_identity_marker_and_mode():
    browser = FakeBrowser()
    sessions = SimpleNamespace(headers_for=lambda role: {"Authorization": f"Bearer {role}"},
                               origin_for=lambda role: None)
    AgentTools(_ctx(browser=browser, sessions=sessions)).call("browser_check", {"path": "/s?q=x", "role": "a"})
    call = browser.calls[0]
    assert call["url"] == BASE + "/s?q=x" and call["identity_headers"] == {"Authorization": "Bearer a"}
    assert call["marker"] == ("vrfaa", "bb") and call["safe"] is True and call["finding_id"] == "T-9"
    assert call["target_base"] == BASE   # identity headers only for the identity's origin


def test_browser_check_attaches_identity_only_to_its_declared_origin():
    browser = FakeBrowser()
    sessions = SimpleNamespace(headers_for=lambda role: {"Authorization": "Bearer a"},
                               origin_for=lambda role: "https://cdn.example.com")
    AgentTools(_ctx(browser=browser, sessions=sessions)).call("browser_check", {"path": "/s", "role": "a"})
    assert browser.calls[0]["target_base"] == "https://cdn.example.com"


@pytest.mark.parametrize("ctx", [_ctx(cls="access-control", browser=FakeBrowser()), _ctx(browser=None),
                                 _ctx(browser=FakeBrowser(error=BrowserError("could not start")))])
def test_browser_check_refusals_become_tool_errors(ctx):
    with pytest.raises(ToolError):
        AgentTools(ctx).call("browser_check", {"path": "/"})


# ── VER-009: confirmed XSS needs an executed marker ───────────────────────────

class Scripted:
    def __init__(self, actions):
        self.actions = list(actions)

    def next_step(self, ctx, history):
        return self.actions.pop(0)


CONFIRM = {"verdict": {"verdict": "confirmed", "rationale": "payload reflected",
                       "evidence": [{"kind": "screenshot", "path": "evidence/fake.png"}]}}


def test_confirmed_xss_without_executed_marker_is_downgraded():
    res = AgentProbe("xss", lambda: Scripted([CONFIRM])).run(_ctx(browser=FakeBrowser()))
    assert res.verdict == "inconclusive" and res.rationale.startswith("indicative, not executed")
    assert res.evidence == []


def test_confirmed_xss_with_executed_marker_keeps_browser_evidence_only():
    proof = [{"kind": "browser-event", "path": "evidence/T-9-xss-1.json"},
             {"kind": "screenshot", "path": "evidence/T-9-xss-1.png", "note": SCREENSHOT_NOTE}]
    browser = FakeBrowser({"executed": True, "evidence": proof})
    planner = Scripted([{"tool": "browser_check", "args": {"path": "/s?q=p"}}, CONFIRM])
    res = AgentProbe("xss", lambda: planner).run(_ctx(browser=browser))
    assert res.verdict == "confirmed" and res.evidence == proof


def test_other_classes_are_not_affected():
    res = AgentProbe("access-control", lambda: Scripted([CONFIRM])).run(_ctx(cls="access-control"))
    assert res.verdict == "confirmed"


# ── report and export ─────────────────────────────────────────────────────────

def _doc():
    ev = [{"kind": "screenshot", "path": "evidence/T-9-xss-1.png", "note": SCREENSHOT_NOTE},
          {"kind": "browser-event", "path": "evidence/T-9-xss-1.json"}]
    result = {"result_id": "VF-001", "verdict": "confirmed", "class": "xss", "evidence": ev,
              "finding_ref": {"id": "T-9", "cwe": "CWE-79", "match_key": "s.ts|CWE-79", "title": "xss"}}
    meta = {"generated": "2026-11-06T00:00:00Z", "summary": {"confirmed": 1, "not_reproducible": 0, "blocked": 0,
            "inconclusive": 0, "not_attempted": 0, "total": 1}, "target": {"base_url": BASE},
            "source_assessment": "a.yaml", "verifier_version": "t"}
    return {"meta": meta, "results": [result]}


def test_screenshot_is_marked_in_the_report_and_kept_out_of_the_export():
    assert SCREENSHOT_NOTE in to_markdown(_doc())
    ann = build_annotations(_doc(), verification_report="v.yaml")["annotations"][0]
    assert ann["evidence_ref"] == "evidence/T-9-xss-1.json"


# ── wiring ────────────────────────────────────────────────────────────────────

def _sel(cls):
    return [SimpleNamespace(status="dynamic", cls=cls)]


def test_browser_is_prepared_only_for_xss_and_reports_when_unavailable(monkeypatch, tmp_path):
    args = SimpleNamespace(output=str(tmp_path), headful=False)
    assert _proof_browser(args, None, _sel("access-control")) == (None, None)

    def missing():
        raise BrowserUnavailable("install appsec-verifier[browser] (Playwright) and Google Chrome")

    monkeypatch.setattr(ProofBrowser, "check_available", staticmethod(missing))
    browser, note = _proof_browser(args, None, _sel("xss"))
    assert browser is None and "cannot be confirmed" in note
    monkeypatch.setattr(ProofBrowser, "check_available", staticmethod(lambda: None))
    browser, note = _proof_browser(args, None, _sel("xss"))
    assert isinstance(browser, ProofBrowser) and "first use" in note


def test_launch_failure_leaves_xss_unproven(tmp_path):
    def launcher(headless):
        raise OSError("no chrome")

    browser = ProofBrowser(None, Path(tmp_path), launcher=launcher)
    with pytest.raises(BrowserError):
        browser._ensure()
    browser.close()


# ── Chrome gets no network of its own (VER-018) ──────────────────────────────

def test_chrome_is_started_inside_a_network_namespace():
    script = _wrapper_script("/usr/bin/unshare", "/opt/google chrome/chrome")
    assert script.startswith("#!/bin/sh\nexec /usr/bin/unshare --user --net --map-current-user ")
    assert "'/opt/google chrome/chrome' \"$@\"" in script            # quoted, arguments passed through


def _which(present):
    return lambda name: f"/usr/bin/{name}" if name in present else None


@pytest.mark.parametrize("platform, present, rc, reason", [
    ("darwin", {"unshare", "google-chrome"}, 0, "needs Linux"),
    ("linux", {"google-chrome"}, 0, "unshare"),
    ("linux", {"unshare"}, 0, "Google Chrome"),
    ("linux", {"unshare", "google-chrome"}, 1, "network namespace"),
])
def test_without_network_isolation_the_browser_is_unavailable(monkeypatch, platform, present, rc, reason):
    import appsec_verifier.tools.browser as browser_mod

    monkeypatch.setattr(browser_mod.sys, "platform", platform)
    monkeypatch.setattr(browser_mod.shutil, "which", _which(present))
    problem = _isolation_problem(run=lambda argv, **kw: SimpleNamespace(returncode=rc))
    assert problem and reason in problem


def test_isolation_probe_runs_unshare_with_the_namespace_flags(monkeypatch):
    import appsec_verifier.tools.browser as browser_mod

    calls = []
    monkeypatch.setattr(browser_mod.sys, "platform", "linux")
    monkeypatch.setattr(browser_mod.shutil, "which", _which({"unshare", "google-chrome"}))
    assert _isolation_problem(run=lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0)) is None
    assert calls == [["/usr/bin/unshare", "--user", "--net", "--map-current-user", "true"]]


def test_check_available_refuses_when_chrome_cannot_be_isolated(monkeypatch):
    import sys as _sys

    import appsec_verifier.tools.browser as browser_mod

    monkeypatch.setitem(_sys.modules, "playwright", SimpleNamespace())
    monkeypatch.setitem(_sys.modules, "playwright.sync_api", SimpleNamespace())
    monkeypatch.setattr(browser_mod, "_isolation_problem", lambda: "cannot create a network namespace")
    with pytest.raises(BrowserUnavailable, match="network namespace"):
        ProofBrowser.check_available()
