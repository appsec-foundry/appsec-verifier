"""The evidence the code requires before a finding counts as confirmed
(VER-009 to VER-013, VER-022).

The model's verdict alone never confirms a finding. A confirmed verdict cites
its proof in `proof_steps`: step numbers of the loop's history, counted from 1
as the prompt and the action log number them. The code checks those steps
against what the tools actually returned:

- xss (VER-009): a browser_check in which the marker executed. The browser's
  screenshot and event record become the evidence; no proof_steps are needed.
  If any request of the probe carried the marker already joined (also
  percent-encoded), the dialog could be a page echoing a parameter through
  alert(), so it does not count.
- access-control (VER-010): a declared operator-owned resource is present for
  an allowed identity and an independently authenticated denied identity.
- injection (VER-011): a declared experiment repeats baseline and true/false
  conditions twice, holding every other input and identity fixed. A selected
  JSON value reproduces the nonempty baseline only for the true condition.
  Timing needs alternating controls and two 2–5 s separations with identical
  response bodies. Error codes, body hashes and reflections alone are no proof.
- open-redirect (VER-012): a cited http_request answered 301, 302, 303, 307 or
  308 whose `location` leads to the finding's redirect host,
  `<marker>.invalid`. The marker is random per finding, so only a target that
  took the destination from the request can name it; `.invalid` never
  resolves (RFC 6761), so nothing is contacted, and the redirect is not
  followed.
- path-traversal (VER-012): a cited http_request whose response body held the
  content of the marker file the operator placed (scope `marker_file`), seen
  in code (`marker_read`). The model never sees that content, and a request
  that carried it does not count, so an echo cannot stand in for a read.
- ssrf (VER-012): a request with the finding's marker arrived at the
  Verifier's callback listener (tools/callback.py). The listener's record is
  the evidence; no proof_steps are needed. The guard never lets the Verifier
  itself contact the listener, so only the target can have sent it.
- any other class: never confirmed, there is no check for it.

A confirmed verdict that fails its check becomes inconclusive with the reason;
the model's claim stays in the rationale. A passing check replaces the model's
evidence with the code's: for xss the browser's files, for ssrf the listener's
hits (time, method, source address), otherwise a record of the cited exchanges
(method, path, params, body, identity, status, length, body hash, for a
redirect the host it leads to, for a traversal whether the marker was read; no
response body, no headers), redacted of credential values and written
owner-only under evidence/.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ..verify.probes import ProbeResult
from .experiments import access_check, experiment_groups, injection_check, latest_plan, observation, token
from .tools import _decoded

_REDIRECTS = (301, 302, 303, 307, 308)


def redirect_host(marker) -> str | None:
    """The host an open-redirect proof must lead to, or None without a marker."""
    return "".join(marker) + ".invalid" if marker and all(marker) else None


def check_proof(ctx, history: list[dict], result: ProbeResult, cited) -> ProbeResult:
    """`result` if it is not confirmed or its proof holds, else an inconclusive result with the reason."""
    if result.verdict not in ("confirmed", "not-reproducible", "blocked-by-control"):
        return result
    if result.verdict != "confirmed":
        return _negative(ctx, history, result, cited)
    cls = getattr(ctx.plan, "cls", None)
    if cls == "xss":
        executed = [n for n, h in enumerate(history, 1) if h.get("tool") == "browser_check"
                    and h.get("result", {}).get("executed") is True]
        return _checked(_xss(ctx, history, result), history, executed)
    if cls == "ssrf":
        hits = [n for n, h in enumerate(history, 1) if h.get("tool") == "http_request"
                and h.get("result", {}).get("callback_hit") is True]
        return _checked(_ssrf(ctx, result), history, hits)
    check, minimum = {"access-control": (None, 2), "injection": (None, 2),
                      "open-redirect": (_redirect, 1), "path-traversal": (_traversal, 1)}.get(cls, (None, 0))
    if check is None and cls not in ("access-control", "injection"):
        return _downgrade(result, f"there is no proof check for class {cls!r}")
    exchanges, problem = _cited_exchanges(ctx, history, cited, minimum)
    if problem is None:
        if cls == "access-control":
            problem = access_check(ctx, history, cited)
        elif cls == "injection":
            problem = injection_check(ctx, history, cited)
        else:
            problem = check(ctx, exchanges)
    if problem is not None:
        return _downgrade(result, problem)
    result.evidence = _write_record(ctx, "exchanges", exchanges)
    return _checked(result, history, cited)


def _checked(result, history, cited):
    if result.verdict not in ("confirmed", "not-reproducible", "blocked-by-control"):
        return result
    _, plan = latest_plan(history)
    result.confidence = ("high" if result.verdict == "confirmed" and plan.get("kind") not in ("boolean", "timing")
                         else "medium")
    events = {k: v for k, v in (result.proof or {}).items() if k in ("executed", "callback_hit")}
    result.proof = {**events, "checked": True, "contract": 2, "steps": cited or [],
                    "kind": plan.get("kind", "marker"), "tested_path": plan.get("path"),
                    "variant": plan.get("variant"), "hypothesis": plan.get("hypothesis"),
                    "observation_pointer": plan.get("pointer"), "scope": "cited requests only"}
    result.identities_used = sorted({h.get("args", {}).get("role") or "anonymous" for h in history
                                    if h.get("tool") in ("http_request", "browser_check")})
    return result


def _negative(ctx, history, result, cited):
    answered = [h for h in history if h.get("tool") in ("http_request", "browser_check")
                and type(h.get("result", {}).get("status")) is int]
    if not answered:
        return ProbeResult(verdict="not-attempted", confidence="low",
                           rationale="no answered target request supports the proposed verdict")
    if (not isinstance(cited, list) or not cited or any(type(n) is not int or not 1 <= n <= len(history)
                                                      for n in cited) or len(cited) != len(set(cited))):
        return _downgrade(result, "cite distinct executed attempts for a negative verdict")
    selected = [history[n - 1] for n in cited]
    if ctx.plan.cls == "xss" and result.verdict == "not-reproducible":
        marker = getattr(ctx, "marker", None) or ()
        if all(h.get("tool") == "browser_check" and h.get("result", {}).get("executed") is False
               and type(h["result"].get("status")) is int and 200 <= h["result"]["status"] < 300
               and marker and all(part in _decoded(h.get("args", {}).get("path", "")) for part in marker)
               and not h["result"].get("error") and not h["result"].get("blocked") for h in selected):
            return _checked(result, history, cited)
        return _downgrade(result, "the browser did not complete an unblocked execution attempt")
    start, plan = latest_plan(history)
    if not start or len(cited) < 2 or any(n <= start for n in cited):
        return _downgrade(result, "declare a hypothesis and cite a reference plus a fresh test attempt")
    if any(h.get("tool") != "http_request" or h.get("args", {}).get("path") != plan.get("path")
           or type(h.get("result", {}).get("status")) is not int for h in selected):
        return _downgrade(result, "negative proof must contain answered requests to the planned target")
    if ctx.plan.cls == "access-control":
        problem = access_check(ctx, history, cited, negative=True, blocked=result.verdict == "blocked-by-control")
        if problem:
            return _downgrade(result, problem)
    elif ctx.plan.cls == "injection":
        plan, groups, error = experiment_groups(history, cited)
        if error or plan.get("kind") not in ("boolean", "timing") or any(len(g) < 2 for g in groups.values()):
            return _downgrade(result, error or "repeat each planned input before drawing a negative conclusion")
        statuses = [h["result"]["status"] for h in selected]
        if result.verdict == "blocked-by-control":
            baseline = [r["status"] for _, r in groups["baseline"]]
            tests = [r["status"] for k, g in groups.items() if k != "baseline" for _, r in g]
            if not (len(set(baseline)) == 1 and all(200 <= s < 300 for s in baseline)
                    and tests and len(set(tests)) == 1 and all(s in (400, 403, 406, 422) for s in tests)):
                return _downgrade(result, "no repeatable target rejection contrasts with a working reference")
        elif plan["kind"] == "timing":
            times = [h["result"].get("elapsed_ms") for h in selected]
            if (any(type(t) is not int or t < 0 for t in times) or max(times) - min(times) > 500
                    or len({h["result"].get("body_sha256") for h in selected}) != 1
                    or any(not h["result"].get("length") for h in selected)
                    or len(set(statuses)) != 1 or not all(200 <= s < 300 for s in statuses)):
                return _downgrade(result, "the timing observations do not establish a stable undelayed result")
        else:
            try:
                values = [observation(ctx, n, plan["pointer"]) for n in cited]
            except (ValueError, KeyError, TypeError, IndexError, RecursionError):
                return _downgrade(result, "the planned response observation cannot be compared")
            if (len({token(v) for v in values}) != 1 or values[0] in (None, '', [], {})
                    or any(str(plan[k]) in token(v) for k in ('positive', 'negative') for v in values)
                    or len(set(statuses)) != 1 or not all(200 <= s < 300 for s in statuses)):
                return _downgrade(result, "the observations do not establish a stable negative result")
    else:
        return _downgrade(result, "this class has no checked negative experiment; "
                          "report the observations as inconclusive")
    exchanges, error = _cited_exchanges(ctx, history, cited, 2)
    if error:
        return _downgrade(result, error)
    result.evidence = _write_record(ctx, "exchanges", exchanges)
    return _checked(result, history, cited)


def _downgrade(result: ProbeResult, reason: str, label: str = "indicative, not proven") -> ProbeResult:
    return ProbeResult(
        verdict="inconclusive", confidence="low", identities_used=result.identities_used,
        proof={"checked": False, "contract": 2, "missing": [reason]},
        observations=result.observations,
        rationale=f"{label}: {reason}. Agent's claim: {result.rationale or ''}".strip(),
    )


def _xss(ctx, history: list[dict], result: ProbeResult) -> ProbeResult:
    proofs = [h["result"] for h in history if h.get("tool") == "browser_check"
              and isinstance(h.get("result"), dict) and h["result"].get("executed") is True]
    if not proofs:
        return _downgrade(result, "no browser_check saw the marker execute", "indicative, not executed")
    joined = "".join(getattr(ctx, "marker", None) or ())
    if joined and any(joined in _decoded(json.dumps(h.get("args") or {}, default=str)) for h in history):
        # A page that shows a parameter with alert() would echo it: only a marker joined at runtime counts.
        return _downgrade(result, "a request carried the already joined marker, so the dialog may be an echo, "
                                  "not executed script", "indicative, not executed")
    result.evidence = [e for p in proofs for e in p.get("evidence") or []]
    result.proof = {"executed": True}
    return result


def _location_host(ctx, location) -> str | None:
    """The host a redirect's Location leads to, resolved against the target as a browser would."""
    if not isinstance(location, str):
        return None
    try:
        host = urlsplit(urljoin(getattr(ctx, "target_base", None) or "", location)).hostname
    except ValueError:
        return None
    return host.rstrip(".") if host else None


def _cited_exchanges(ctx, history: list[dict], cited, minimum: int) -> tuple[list[dict], str | None]:
    if not isinstance(cited, list) or len(cited) < minimum:
        steps = "two steps" if minimum == 2 else "one step"
        return [], f"a confirmed verdict must cite at least {steps} in proof_steps"
    if any(type(n) is not int for n in cited) or len(cited) != len(set(cited)):
        return [], "proof steps must be distinct integer request ids"
    exchanges = []
    for n in cited:
        if type(n) is not int or not 1 <= n <= len(history):
            return [], f"proof step {n!r} does not exist"
        step = history[n - 1]
        res, args = step.get("result") or {}, step.get("args") or {}
        if step.get("tool") != "http_request" or not isinstance(res.get("status"), int):
            return [], f"proof step {n} is not an answered http_request"
        exchange = {
            "step": n, "method": str(args.get("method") or "GET").upper(), "path": args.get("path"),
            "params": args.get("params") or {}, "json": args.get("json"), "form": args.get("form"),
            "role": args.get("role"),
            "status": res["status"], "length": res.get("length"), "body_sha256": res.get("body_sha256"),
        }
        if "location" in res:
            exchange["location_host"] = _location_host(ctx, res["location"])
        if "marker_read" in res:
            exchange["marker_read"] = res["marker_read"] is True
        if isinstance(res.get("elapsed_ms"), int) and not isinstance(res["elapsed_ms"], bool):
            exchange["elapsed_ms"] = res["elapsed_ms"]
        exchanges.append(exchange)
    return exchanges, None


def _redirect(ctx, exchanges: list[dict]) -> str | None:
    host = redirect_host(getattr(ctx, "marker", None))
    if host is None:
        return "this run has no redirect marker for the finding"
    if any(e["status"] in _REDIRECTS and e.get("location_host") == host for e in exchanges):
        return None
    return f"no cited step was answered with a redirect (301, 302, 303, 307, 308) to {host}"


def _traversal(ctx, exchanges: list[dict]) -> str | None:
    content = ((getattr(ctx, "scope", None) or {}).get("marker_file") or {}).get("content")
    if not content:
        return "the scope names no marker file to read"
    for e in exchanges:
        sent = json.dumps([e["path"], e["params"], e["json"], e.get("form")], default=str)
        if e.get("marker_read") and content not in sent:     # an echo of the content is not a read
            return None
    return "no cited step returned the content of the scope's marker file"


def _ssrf(ctx, result: ProbeResult) -> ProbeResult:
    listener, marker = getattr(ctx, "listener", None), "".join(getattr(ctx, "marker", None) or ())
    if listener is None or not marker:
        return _downgrade(result, "this run has no callback listener for the finding")
    hits = listener.hits(marker)
    if not hits:
        return _downgrade(result, "no request with the finding's marker reached the callback listener")
    result.evidence = _write_record(ctx, "callback_hits", hits, kind="callback")
    result.proof = {"callback_hit": True}
    return result


def _write_record(ctx, key: str, items: list[dict], kind: str = "exchange") -> list[dict]:
    """`items` as an owner-only evidence file; [] when the run has no evidence directory."""
    directory = getattr(ctx, "evidence_dir", None)
    if directory is None:
        return []
    record = {"finding_id": ctx.plan.id, "class": ctx.plan.cls, key: items,
              "captured": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    if ctx.sessions is not None:
        record = ctx.sessions.redact(record)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', ctx.plan.id)}-{key.replace('_', '-')}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(record, indent=2, default=str))
    path.chmod(0o600)                 # also when an earlier run left the file with wider rights
    return [{"kind": kind, "path": f"evidence/{path.name}", "redacted": True,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]
