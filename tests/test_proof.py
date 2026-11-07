"""A confirmed verdict stands only with the proof its class requires, checked in
code against the cited steps (VER-009 to VER-013, VER-022)."""

from __future__ import annotations

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
    return check_proof(_ctx(cls, **ctx), history, result, cited)


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
    ([_req("alice"), _req("bob")], [1, True], "does not exist"),
    ([READ, _req("bob")], [1, 2], "not an answered http_request"),
    ([_req("alice"), {"tool": "http_request", "args": {"path": "/x"}, "result": {"error": "refused"}}], [1, 2],
     "not an answered http_request"),
    ([_req("alice"), _req("alice")], [1, 2], "two different identities"),          # no contrast
    ([_req("alice"), _req("bob", status=403)], [1, 2], "two different identities"),  # the control held
    ([_req("alice"), _req("bob", length=0)], [1, 2], "two different identities"),   # nothing was read
    ([_req("alice"), _req("bob", path="/rest/basket/3")], [1, 2], "two different identities"),
    ([_req("alice", params={"id": 2}), _req("bob", params={"id": 3})], [1, 2], "two different identities"),
    ([_req("alice"), _req("bob", method="POST")], [1, 2], "two different identities"),
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
def test_injection_flip_confirms(history):
    assert _check("injection", history, [1, 2]).verdict == "confirmed"


@pytest.mark.parametrize("history", [
    [_req(params={"q": "a"}, sha="h1"), _req(params={"q": "a"}, sha="h2")],          # same input
    [_req(params={"q": "a"}), _req(params={"q": "b"})],                              # same answer
    [_req("alice", params={"q": "a"}), _req("bob", params={"q": "b"}, sha="h2")],    # different identity
    [_req(path="/a", params={"q": "a"}), _req(path="/b", params={"q": "b"}, sha="h2")],
])
def test_injection_without_a_flip_is_downgraded(history):
    res = _check("injection", history, [1, 2])
    assert res.verdict == "inconclusive" and "VER-011" in res.rationale


# ── open redirect (VER-012) ───────────────────────────────────────────────────

MARKER = ("vrf0a1b2c3d", "4e5f6a7b")
HOST = "vrf0a1b2c3d4e5f6a7b.invalid"


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
    ([_redirect(f"https://{HOST}/", status=200)], [1], "VER-012"),                    # not a redirect
    ([_redirect(f"https://{HOST}/", status=304)], [1], "VER-012"),
    ([_redirect(None)], [1], "VER-012"),                                               # no location
    ([_redirect(f"https://app.example.com/login?next=https://{HOST}/")], [1], "VER-012"),  # marker only in query
    ([_redirect(f"/{HOST}/x")], [1], "VER-012"),                                     # relative: stays on target
    ([_redirect(f"https://{HOST}.evil.example/")], [1], "VER-012"),                  # marker as a subdomain
    ([_redirect("https://vrf00000000ffffffff.invalid/")], [1], "VER-012"),           # another finding's host
    ([_redirect("https://[::1/")], [1], "VER-012"),                                  # unparseable location
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


# ── classes without the required infrastructure, unknown classes ──────────────

@pytest.mark.parametrize("cls", ["path-traversal", "ssrf"])
def test_classes_whose_proof_is_not_implemented_are_never_confirmed(cls):
    res = _check(cls, [_req("alice"), _req("bob")], [1, 2])
    assert res.verdict == "inconclusive" and "VER-012" in res.rationale


def test_an_unknown_class_is_never_confirmed():
    assert _check("crypto", [_req("alice"), _req("bob")], [1, 2]).verdict == "inconclusive"


@pytest.mark.parametrize("verdict", ["not-reproducible", "blocked-by-control", "inconclusive"])
def test_other_verdicts_pass_unchanged(verdict):
    res = _check("ssrf", [], None, verdict=verdict)
    assert res.verdict == verdict and res.rationale == "the model says so"


# ── evidence record (VER-022) ─────────────────────────────────────────────────

def test_the_evidence_record_is_the_codes_redacted_and_owner_only(tmp_path):
    secret = {"token": "Bearer s3cret-value"}
    history = [_req("alice", params=secret), _req("bob", params=secret)]
    sessions = SimpleNamespace(redact=lambda v: json.loads(json.dumps(v).replace("s3cret-value", "[redacted]")))
    result = ProbeResult(verdict="confirmed", rationale="r", evidence=[{"kind": "note", "path": "model-made.txt"}])
    res = check_proof(_ctx("access-control", sessions=sessions, evidence_dir=tmp_path / "evidence"), history, result,
                      [1, 2])
    path = tmp_path / "evidence" / "T-1-exchanges.json"
    assert [e["path"] for e in res.evidence] == ["evidence/T-1-exchanges.json"]   # the model's evidence is replaced
    assert "s3cret-value" not in path.read_text() and (path.stat().st_mode & 0o777) == 0o600
    assert json.loads(path.read_text())["exchanges"][1]["role"] == "bob"
