"""The proof of concept of every tested finding (VER-034, VER-035, VER-016, VER-022).

Every request an agent step sends to the target is recorded with the answer to
it, by the code from what was sent and received: by `http_request`, and by
`browser_check` for each request of the page that the guarded client answered.
The model sees none of it beyond its own tool results, and its own account of
evidence is not taken over.

Each exchange is redacted when it is recorded: headers the identity added
read `[identity <role>]`; Authorization, cookies and other headers whose name
names a credential, query parameters named like a token, every credential
value the sessions know and every JWT read `[redacted]`. Cookie names and
Set-Cookie attributes stay. Bodies are kept as text up to `MAX_BODY_CHARS`, cut
after redaction, and up to `MAX_FINDING_BODY_CHARS` for all bodies of a
finding together; binary bodies only by type, length and hash. A browser keeps
bodies only for documents, XHR and fetch.

When a finding ends, `attach` writes its exchanges owner-only as an HTTP
Archive (HAR 1.2, `evidence/<finding>-poc.har`) and puts a summary into the
result: one line per step, and for each step the verdict rests on the request
and the decisive part of its response as raw HTTP. Those steps are the ones
the proof check relied on for a confirmed verdict (VER-009 to VER-012), else
the ones the verdict cites. For a confirmed access-control finding whose
response is an HTML page, the proof browser renders that recorded response
without a new request and marks the values the verdict names (VER-035).
Response bodies and screenshots can show target data and are marked for
review before sharing (VER-022).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

REDACTED = "[redacted]"
TARGET_DATA_NOTE = "may show target data; review before sharing"
MAX_BODY_CHARS = 256 * 1024
MAX_FINDING_BODY_CHARS = 4 * 1024 * 1024        # all bodies of one finding together
MAX_RAW_BYTES = 4 * MAX_BODY_CHARS              # what a browser capture keeps of a body before redaction
EXCERPT_CHARS = 1500
_MAX_HEADERS = 100
_MAX_VALUE = 8192
MAX_BROWSER_EXCHANGES = 50
_MAX_HIGHLIGHTS = 3
_SECRET_NAME = re.compile(r"^(?:proxy-)?authorization$|^cookie$|^set-cookie$|token|secret|passw|api[-_]?key|"
                          r"session|credential|(?:^|[-_])auth(?:$|[-_])", re.I)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
_TEXT_TYPES = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded")
BODY_RESOURCE_TYPES = ("document", "xhr", "fetch")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _items(headers) -> list[tuple[str, str]]:
    if headers is None:
        return []
    if hasattr(headers, "multi_items"):
        return [(str(k), str(v)) for k, v in headers.multi_items()]
    if isinstance(headers, dict):
        return [(str(k), str(v)) for k, v in headers.items()]
    return [(str(k), str(v)) for k, v in headers]


def _as_bytes(body) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    return str(body).encode("utf-8")


def _elapsed_ms(resp) -> int | None:
    try:
        elapsed = getattr(resp, "elapsed", None)
        return round(elapsed.total_seconds() * 1000) if elapsed is not None else None
    except (AttributeError, RuntimeError):
        return None


def capture(resp, *, method: str, url: str, headers=None, body=None) -> dict:
    """The raw exchange, before redaction. The request is taken from the
    response when the transport records it (httpx), else from what the caller
    sent. Kept in memory only until `entry` has redacted it."""
    sent = None
    try:
        request = resp.request
        if isinstance(request, httpx.Request):
            sent = (request.method, str(request.url), _items(request.headers), request.content)
    except (AttributeError, RuntimeError, httpx.RequestNotRead):
        sent = None
    if sent is None:
        sent = (method, url, _items(headers), _as_bytes(body))
    content = getattr(resp, "content", None)
    if not isinstance(content, bytes):
        text = getattr(resp, "text", None)
        content = text.encode("utf-8") if isinstance(text, str) else b""
    return {"method": str(sent[0]).upper(), "url": str(sent[1]), "headers": sent[2], "body": sent[3],
            "status": getattr(resp, "status_code", None), "response_headers": _items(getattr(resp, "headers", None)),
            "content": content, "elapsed_ms": _elapsed_ms(resp), "time": _now()}


class _Redactor:
    def __init__(self, redact, identity: dict | None, role: str | None):
        self._redact = redact or (lambda value: value)
        self._identity = {k.lower(): str(v) for k, v in (identity or {}).items() if v}
        self._role = role

    def text(self, value: str) -> str:
        return _JWT.sub(REDACTED, self._redact(value))

    def header(self, name: str, value: str) -> str:
        low = name.lower()
        own = self._identity.get(low)
        if own and own in value:
            return f"[identity {self._role}]"
        if low == "cookie":
            return "; ".join(f"{part.split('=', 1)[0].strip()}={REDACTED}" if "=" in part else REDACTED
                             for part in value.split(";"))
        if low == "set-cookie":
            first, sep, attributes = value.partition(";")
            name_part = first.split("=", 1)[0].strip() if "=" in first else ""
            return f"{name_part}={REDACTED}" + (sep + self.text(attributes) if sep else "")
        if _SECRET_NAME.search(low):
            return REDACTED
        return self.text(value)[:_MAX_VALUE]

    def url(self, url: str) -> str:
        try:
            parts = urlsplit(url)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError:
            return self.text(url)[:_MAX_VALUE]
        if any(_SECRET_NAME.search(k) for k, _ in pairs):
            query = urlencode([(k, REDACTED if _SECRET_NAME.search(k) else v) for k, v in pairs])
            url = urlunsplit(parts._replace(query=query))
        return self.text(url)[:_MAX_VALUE]

    def headers(self, items) -> list[dict]:
        return [{"name": k, "value": self.header(k, v)} for k, v in items[:_MAX_HEADERS]]


def _content_type(items) -> str:
    return next((v for k, v in items if k.lower() == "content-type"), "")


def _is_text(content_type: str, raw: bytes) -> bool:
    if content_type:
        return any(t in content_type.lower() for t in _TEXT_TYPES)
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _body(raw: bytes | None, content_type: str, red: _Redactor, omit: str | None = None,
          size: int | None = None) -> dict:
    """HAR content of a body: redacted text, cut after redaction; binary bodies only by length and hash.
    `size` is the body's full length when `raw` was already cut."""
    raw = raw or b""
    size = len(raw) if size is None else size
    out: dict = {"size": size, "mimeType": content_type or ""}
    if not size:
        return out
    if omit:
        out["_omitted"] = omit
    elif not _is_text(content_type, raw):
        out["_omitted"] = "binary body"
        out["_sha256"] = hashlib.sha256(raw).hexdigest()
    else:
        text = red.text(raw.decode("utf-8", "replace"))
        out["text"] = text[:MAX_BODY_CHARS]
        if len(text) > MAX_BODY_CHARS or size > len(raw):
            out["_truncated"] = True
    return out


def entry(raw: dict, *, redact=None, identity: dict | None = None, role: str | None = None,
          omit_body: str | None = None, navigation: bool = False) -> dict:
    """One HAR 1.2 entry from a raw capture, redacted (VER-016). Custom fields start with `_`."""
    red = _Redactor(redact, identity, role)
    url = red.url(raw["url"])
    req_ct = _content_type(raw["headers"])
    res_ct = _content_type(raw["response_headers"])
    location = next((v for k, v in raw["response_headers"] if k.lower() == "location"), "")
    request = {"method": raw["method"], "url": url, "httpVersion": "HTTP/1.1", "cookies": [],
               "headers": red.headers(raw["headers"]),
               "queryString": [{"name": k, "value": v} for k, v in parse_qsl(urlsplit(url).query,
                                                                             keep_blank_values=True)],
               "headersSize": -1, "bodySize": len(raw["body"] or b"")}
    if raw["body"]:
        posted = _body(raw["body"], req_ct, red)
        request["postData"] = {"mimeType": req_ct, "text": posted.get("text", "")}
    status = raw["status"] if isinstance(raw["status"], int) else 0
    content = _body(raw["content"], res_ct, red, omit_body, raw.get("content_size"))
    response = {"status": status, "statusText": _phrase(status), "httpVersion": "HTTP/1.1", "cookies": [],
                "headers": red.headers(raw["response_headers"]), "content": content,
                "redirectURL": red.url(location) if location else "", "headersSize": -1,
                "bodySize": content["size"]}
    elapsed = raw.get("elapsed_ms") or 0
    out = {"startedDateTime": raw["time"], "time": elapsed, "request": request, "response": response,
           "cache": {}, "timings": {"send": 0, "wait": elapsed, "receive": 0}, "_role": role}
    if navigation:
        out["_navigation"] = True
    return out


def _phrase(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return ""


# ── per finding ──────────────────────────────────────────────────────────────

def decisive_steps(ctx, history: list[dict], verdict: str, cited) -> list[int]:
    """The steps a verdict rests on: the cited ones, and for a confirmed XSS or
    SSRF verdict also the steps whose proof the code saw (VER-009, VER-012)."""
    steps = {n for n in (cited if isinstance(cited, list) else [])
             if type(n) is int and 1 <= n <= len(history)}
    if verdict == "confirmed":
        cls = getattr(ctx.plan, "cls", None)
        for n, h in enumerate(history, 1):
            res = h.get("result") if isinstance(h.get("result"), dict) else {}
            if (cls == "xss" and h.get("tool") == "browser_check" and res.get("executed") is True) or \
                    (cls == "ssrf" and h.get("tool") == "http_request" and res.get("callback_hit") is True):
                steps.add(n)
    return sorted(steps)


def _shown_entry(step: dict) -> dict | None:
    """The exchange a step shows in the report: the page for a browser check, else the last request."""
    entries = step["entries"]
    pages = [e for e in entries if e.get("_navigation")]
    return (pages or entries or [None])[-1]


def _text(e: dict) -> str:
    return e["response"]["content"].get("text") or ""


def _focus(ctx, shown: list[dict], e: dict) -> int:
    """Where the decisive part of a response begins: the marker file's content,
    the XSS marker, the first difference between two injection answers, or 0."""
    text, cls = _text(e), getattr(ctx.plan, "cls", None)
    needle = None
    if cls == "path-traversal":
        needle = ((getattr(ctx, "scope", None) or {}).get("marker_file") or {}).get("content")
    elif cls == "xss":
        needle = (getattr(ctx, "marker", None) or ("",))[0]
    if needle and needle in text:
        return text.index(needle)
    if cls == "injection":
        others = [_text(o) for o in shown if o is not e and o["request"]["url"].split("?")[0]
                  == e["request"]["url"].split("?")[0]]
        if others:
            return min(len(os.path.commonprefix([text, o])) for o in others)
    return 0


def _raw_request(e: dict) -> str:
    req = e["request"]
    parts = urlsplit(req["url"])
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    lines = [f"{req['method']} {target} HTTP/1.1"]
    if not any(h["name"].lower() == "host" for h in req["headers"]):
        lines.append(f"Host: {parts.netloc}")
    lines += [f"{h['name']}: {h['value']}" for h in req["headers"]]
    body = (req.get("postData") or {}).get("text") or ""
    if len(body) > EXCERPT_CHARS:
        body = body[:EXCERPT_CHARS] + f"\n[… {EXCERPT_CHARS} of {len(body)} characters shown]"
    return "\n".join(lines) + "\n\n" + body


def _raw_response(e: dict, focus: int, har_path: str | None) -> str:
    res = e["response"]
    lines = [f"HTTP/1.1 {res['status']} {res['statusText']}".rstrip()]
    lines += [f"{h['name']}: {h['value']}" for h in res["headers"]]
    content, text = res["content"], _text(e)
    if content.get("_omitted"):
        body = f"[{content['_omitted']}, {content['size']} bytes]"
    elif len(text) <= EXCERPT_CHARS:
        body = text
    else:
        start = max(0, min(focus - EXCERPT_CHARS // 3, len(text) - EXCERPT_CHARS))
        where = f"; full response in {har_path}" if har_path else ""
        body = (("[…]\n" if start else "") + text[start:start + EXCERPT_CHARS]
                + f"\n[… characters {start + 1} to {start + EXCERPT_CHARS} of {len(text)} shown{where}]")
    return "\n".join(lines) + "\n\n" + body


def _line(step: dict, history: list[dict]) -> str:
    e = _shown_entry(step)
    res = (history[step["step"] - 1].get("result") or {}) if step["step"] <= len(history) else {}
    who = e.get("_role") or "anonymous"
    text = f"{step['tool']} {e['request']['method']} {e['request']['url'][:200]} as {who} → " \
           f"{e['response']['status']}, {e['response']['content']['size']} bytes"
    if step["tool"] == "browser_check":
        text += f", marker {'executed' if res.get('executed') is True else 'not executed'}, " \
                f"{len(step['entries'])} requests"
    return text


def _write_har(ctx, steps: list[dict]) -> list[dict]:
    directory = getattr(ctx, "evidence_dir", None)
    if directory is None:
        return []
    from ..version_info import ENGINE_VERSION

    entries = []
    for step in steps:
        for e in step["entries"]:
            entries.append({**e, "_step": step["step"], "_tool": step["tool"], "_decisive": step["decisive"]})
    har = {"log": {"version": "1.2", "creator": {"name": "AppSec Verifier", "version": ENGINE_VERSION},
                   "comment": f"Proof of concept for {ctx.plan.id}, redacted of credentials; {TARGET_DATA_NOTE}",
                   "entries": entries}}
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', ctx.plan.id)}-poc.har"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(har, indent=1, default=str))
    path.chmod(0o600)                 # also when an earlier run left the file with wider rights
    return [{"kind": "har", "path": f"evidence/{path.name}", "redacted": True,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "note": TARGET_DATA_NOTE}]


def _screenshots(ctx, steps: list[dict], highlight) -> list[dict]:
    """Access control (VER-035): each decisive response that is an HTML page, rendered without a new request."""
    browser = getattr(ctx, "browser", None)
    if browser is None or "access-control" not in getattr(browser, "screenshots", ()):
        return []
    out = []
    for step in steps:
        e = _shown_entry(step)
        if not step["decisive"] or e is None or "html" not in e["response"]["content"]["mimeType"].lower():
            continue
        text = _text(e)
        if not text:
            continue
        values = [v for v in (highlight if isinstance(highlight, list) else [])[:_MAX_HIGHLIGHTS]
                  if isinstance(v, str) and 3 <= len(v) <= 200 and v in text]
        caption = [f"AppSec Verifier · {ctx.plan.id} · access control · step {step['step']}",
                   f"{e['request']['method']} {e['request']['url'][:300]} as {e.get('_role') or 'anonymous'} "
                   f"→ {e['response']['status']}",
                   f"captured {e['startedDateTime']} · rendered from the recorded response, no new request"]
        try:
            out += browser.render(url=e["request"]["url"], status=e["response"]["status"],
                                  content_type=e["response"]["content"]["mimeType"], html=text,
                                  finding_id=ctx.plan.id, caption=caption, highlight=values)
        except Exception:  # noqa: BLE001 - a screenshot only illustrates; the verdict stands without it
            continue
    return out


def attach(ctx, history: list[dict], steps: list[dict], result, cited, highlight=None):
    """Write the finding's proof of concept and add it to `result` (VER-034, VER-035)."""
    if not steps:
        return result
    decisive = set(decisive_steps(ctx, history, result.verdict, cited))
    for step in steps:
        step["decisive"] = step["step"] in decisive
    har = _write_har(ctx, steps)
    har_path = har[0]["path"] if har else None
    shown_entries = [(s["step"], _shown_entry(s)) for s in steps if s["decisive"]]
    shown_entries = [(n, e) for n, e in shown_entries if e is not None]
    others = [e for _, e in shown_entries]
    result.poc = {
        "file": har_path,
        "steps": [{"step": s["step"], "line": _line(s, history), "decisive": s["decisive"]} for s in steps],
        "shown": [{"step": n, "request": _raw_request(e), "response": _raw_response(e, _focus(ctx, others, e),
                                                                                     har_path)}
                  for n, e in shown_entries],
    }
    shots = _screenshots(ctx, steps, highlight) if result.verdict == "confirmed" and \
        getattr(ctx.plan, "cls", None) == "access-control" else []
    result.evidence = [*(result.evidence or []), *har, *shots]
    return result
