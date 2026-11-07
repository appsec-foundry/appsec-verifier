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


# ── classes without the required infrastructure, unknown classes ──────────────

@pytest.mark.parametrize("cls", ["path-traversal", "open-redirect", "ssrf"])
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
