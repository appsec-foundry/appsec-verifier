"""The evidence the code requires before a finding counts as confirmed
(VER-009 to VER-013, VER-022).

The model's verdict alone never confirms a finding. A confirmed verdict cites
its proof in `proof_steps`: step numbers of the loop's history, counted from 1
as the prompt and the action log number them. The code checks those steps
against what the tools actually returned:

- xss (VER-009): a browser_check in which the marker executed. The browser's
  screenshot and event record become the evidence; no proof_steps are needed.
- access-control (VER-010): two cited http_request steps with the same method,
  path, params and body, sent as two different identities (no role is the
  anonymous identity), both answered 2xx with a non-empty body.
- injection (VER-011): two cited http_request steps with the same method, path
  and identity but different params or body, whose answers differ in status or
  body, so the input flipped the response. Timing proofs are not supported.
- path-traversal, open-redirect, ssrf (VER-012): never confirmed yet. The
  marker file, the landing on the operator's URL and the callback listener
  these classes require are not implemented.
- any other class: never confirmed, there is no check for it.

A confirmed verdict that fails its check becomes inconclusive with the reason;
the model's claim stays in the rationale. A passing check replaces the model's
evidence with the code's: for xss the browser's files, otherwise a record of
the cited exchanges (method, path, params, body, identity, status, length, body
hash; no response body, no headers), redacted of credential values and written
owner-only under evidence/.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from ..verify.probes import ProbeResult

_NOT_YET = {
    "path-traversal": "reading back a pre-placed marker file",
    "open-redirect": "landing on the operator's benign URL",
    "ssrf": "a request arriving at the Verifier's callback listener",
}


def check_proof(ctx, history: list[dict], result: ProbeResult, cited) -> ProbeResult:
    """`result` if it is not confirmed or its proof holds, else an inconclusive result with the reason."""
    if result.verdict != "confirmed":
        return result
    cls = getattr(ctx.plan, "cls", None)
    if cls == "xss":
        return _xss(history, result)
    if cls in _NOT_YET:
        return _downgrade(result, f"this version cannot produce the proof {cls} needs: {_NOT_YET[cls]} (VER-012)")
    check = {"access-control": _contrast, "injection": _flip}.get(cls)
    if check is None:
        return _downgrade(result, f"there is no proof check for class {cls!r}")
    exchanges, problem = _cited_exchanges(history, cited)
    if problem is None:
        problem = check(exchanges)
    if problem is not None:
        return _downgrade(result, problem)
    result.evidence = _write_record(ctx, exchanges)
    return result


def _downgrade(result: ProbeResult, reason: str, label: str = "indicative, not proven") -> ProbeResult:
    return ProbeResult(
        verdict="inconclusive", confidence=result.confidence, identities_used=result.identities_used,
        observations=result.observations,
        rationale=f"{label}: {reason}. Agent's claim: {result.rationale or ''}".strip(),
    )


def _xss(history: list[dict], result: ProbeResult) -> ProbeResult:
    proofs = [h["result"] for h in history if h.get("tool") == "browser_check"
              and isinstance(h.get("result"), dict) and h["result"].get("executed") is True]
    if not proofs:
        return _downgrade(result, "no browser_check saw the marker execute (VER-009)", "indicative, not executed")
    result.evidence = [e for p in proofs for e in p.get("evidence") or []]
    return result


def _cited_exchanges(history: list[dict], cited) -> tuple[list[dict], str | None]:
    if not isinstance(cited, list) or len(cited) < 2:
        return [], "a confirmed verdict must cite at least two steps in proof_steps"
    exchanges = []
    for n in cited:
        if type(n) is not int or not 1 <= n <= len(history):
            return [], f"proof step {n!r} does not exist"
        step = history[n - 1]
        res, args = step.get("result") or {}, step.get("args") or {}
        if step.get("tool") != "http_request" or not isinstance(res.get("status"), int):
            return [], f"proof step {n} is not an answered http_request"
        exchanges.append({
            "step": n, "method": str(args.get("method") or "GET").upper(), "path": args.get("path"),
            "params": args.get("params") or {}, "json": args.get("json"), "role": args.get("role"),
            "status": res["status"], "length": res.get("length"), "body_sha256": res.get("body_sha256"),
        })
    return exchanges, None


def _same_request(a: dict, b: dict) -> bool:
    return all(a[k] == b[k] for k in ("method", "path", "params", "json"))


def _readable(e: dict) -> bool:
    return 200 <= e["status"] < 300 and bool(e["length"])


def _pairs(exchanges: list[dict]):
    return ((a, b) for i, a in enumerate(exchanges) for b in exchanges[i + 1:])


def _contrast(exchanges: list[dict]) -> str | None:
    if any(_same_request(a, b) and a["role"] != b["role"] and _readable(a) and _readable(b)
           for a, b in _pairs(exchanges)):
        return None
    return ("the cited steps do not show the same request answered 2xx with content for two different "
            "identities (VER-010)")


def _flip(exchanges: list[dict]) -> str | None:
    if any(a["method"] == b["method"] and a["path"] == b["path"] and a["role"] == b["role"]
           and (a["params"], a["json"]) != (b["params"], b["json"])
           and (a["status"], a["body_sha256"]) != (b["status"], b["body_sha256"])
           for a, b in _pairs(exchanges)):
        return None
    return ("the cited steps do not show one request whose response changes with the input "
            "(same method, path and identity; different input; different status or body) (VER-011)")


def _write_record(ctx, exchanges: list[dict]) -> list[dict]:
    """The cited exchanges as an owner-only evidence file; [] when the run has no evidence directory."""
    directory = getattr(ctx, "evidence_dir", None)
    if directory is None:
        return []
    record = {"finding_id": ctx.plan.id, "class": ctx.plan.cls, "exchanges": exchanges,
              "captured": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    if ctx.sessions is not None:
        record = ctx.sessions.redact(record)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', ctx.plan.id)}-exchanges.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(record, indent=2, default=str))
    path.chmod(0o600)                 # also when an earlier run left the file with wider rights
    return [{"kind": "exchange", "path": f"evidence/{path.name}", "redacted": True,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]
