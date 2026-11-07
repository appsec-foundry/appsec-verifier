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
- access-control (VER-010): two cited http_request steps with the same method,
  path, params and body, sent as two different identities (no role is the
  anonymous identity), both answered 2xx with a non-empty body.
- injection (VER-011): two cited http_request steps with the same method, path
  and identity but different params or body, whose answers differ in status or
  body, so the input flipped the response. Or a timing difference: among cited
  steps with the same method, path and identity, at least two delayed and two
  undelayed answers, every delayed one at least 2 s slower (`elapsed_ms`) than
  every undelayed one, and no delayed step sent the same input as an
  undelayed one. Two of each keep one slow moment of the target from counting.
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
from .tools import _decoded

_REDIRECTS = (301, 302, 303, 307, 308)
_DELAY_MS = 2000


def redirect_host(marker) -> str | None:
    """The host an open-redirect proof must lead to, or None without a marker."""
    return "".join(marker) + ".invalid" if marker and all(marker) else None


def check_proof(ctx, history: list[dict], result: ProbeResult, cited) -> ProbeResult:
    """`result` if it is not confirmed or its proof holds, else an inconclusive result with the reason."""
    if result.verdict != "confirmed":
        return result
    cls = getattr(ctx.plan, "cls", None)
    if cls == "xss":
        return _xss(ctx, history, result)
    if cls == "ssrf":
        return _ssrf(ctx, result)
    check, minimum = {"access-control": (_contrast, 2), "injection": (_flip, 2),
                      "open-redirect": (_redirect, 1), "path-traversal": (_traversal, 1)}.get(cls, (None, 0))
    if check is None:
        return _downgrade(result, f"there is no proof check for class {cls!r}")
    exchanges, problem = _cited_exchanges(ctx, history, cited, minimum)
    if problem is None:
        problem = check(ctx, exchanges)
    if problem is not None:
        return _downgrade(result, problem)
    result.evidence = _write_record(ctx, "exchanges", exchanges)
    return result


def _downgrade(result: ProbeResult, reason: str, label: str = "indicative, not proven") -> ProbeResult:
    return ProbeResult(
        verdict="inconclusive", confidence=result.confidence, identities_used=result.identities_used,
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
            "params": args.get("params") or {}, "json": args.get("json"), "role": args.get("role"),
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


def _same_request(a: dict, b: dict) -> bool:
    return all(a[k] == b[k] for k in ("method", "path", "params", "json"))


def _readable(e: dict) -> bool:
    return 200 <= e["status"] < 300 and bool(e["length"])


def _pairs(exchanges: list[dict]):
    return ((a, b) for i, a in enumerate(exchanges) for b in exchanges[i + 1:])


def _contrast(ctx, exchanges: list[dict]) -> str | None:
    if any(_same_request(a, b) and a["role"] != b["role"] and _readable(a) and _readable(b)
           for a, b in _pairs(exchanges)):
        return None
    return ("the cited steps do not show the same request answered 2xx with content for two different "
            "identities")


def _flip(ctx, exchanges: list[dict]) -> str | None:
    if any(a["method"] == b["method"] and a["path"] == b["path"] and a["role"] == b["role"]
           and (a["params"], a["json"]) != (b["params"], b["json"])
           and (a["status"], a["body_sha256"]) != (b["status"], b["body_sha256"])
           for a, b in _pairs(exchanges)):
        return None
    if _delayed(exchanges):
        return None
    return ("the cited steps do not show one request whose response changes with the input "
            "(same method, path and identity; different input; different status or body, or two answers "
            "delayed by at least 2 s against two undelayed ones)")


def _input(e: dict) -> str:
    return json.dumps([e["params"], e["json"]], sort_keys=True, default=str)


def _delayed(exchanges: list[dict]) -> bool:
    """A gap of at least 2 s between the undelayed and the delayed answers to one request, two on each side."""
    groups: dict[tuple, list[dict]] = {}
    for e in exchanges:
        if "elapsed_ms" in e:
            groups.setdefault((e["method"], e["path"], e["role"]), []).append(e)
    for group in groups.values():
        group.sort(key=lambda e: e["elapsed_ms"])
        for i in range(2, len(group) - 1):
            fast, slow = group[:i], group[i:]
            if (slow[0]["elapsed_ms"] - fast[-1]["elapsed_ms"] >= _DELAY_MS
                    and not {_input(e) for e in slow} & {_input(e) for e in fast}):
                return True
    return False


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
        sent = json.dumps([e["path"], e["params"], e["json"]], default=str)
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
