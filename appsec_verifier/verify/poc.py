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
the ones the verdict cites.

Screenshots (VER-035), for the classes the run enables: XSS keeps the page in
which its marker executed (tools/browser.py). For a confirmed access-control
finding whose response is an HTML page, the proof browser renders that
recorded response without a new request and marks the values the verdict
names. Live application observations are attached before this renderer. The
report displays application images and marked HTTP excerpts; exchange images
are saved for later use, not embedded. Every finding with decisive steps also gets an image of those
exchanges, and one whose verdict cites none (a limit stopped it) an image of its
answered requests after the last test plan, whose header says it proves nothing:
request and response side by side, built here as escaped HTML with
what the code can locate marked, each kind labelled by a red tag: the
identities an access-control proof compares, the XSS or SSRF marker, the
redirect host and Location header, the marker file and its content, the input
and answer that differ between injection requests, the session cookie's
Set-Cookie line. Facts about a step, such as the page a browser check opened
or the time of each answer, stand above it, in bold where they decide.
Response bodies and screenshots can show target data and are marked for
review before sharing (VER-022).
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

import httpx

from ..planning import evidence_id, evidence_name

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


def shown_time(stamp: str) -> str:
    """A recorded time as a screenshot shows it, to the second."""
    return re.sub(r"\.\d+(?=Z$|[+-]\d\d:\d\d$)", "", str(stamp))


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
    lines = [f"{req['method']} {_target(req['url'])} HTTP/1.1"]
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
    url = e["request"]["url"][:200]
    if step["tool"] == "browser_check":     # the page the browser opened; its # part never reaches the server
        opened = (history[step["step"] - 1].get("args") or {}).get("path") if step["step"] <= len(history) else None
        url = str(opened)[:200] if opened else url
    text = f"{step['tool']} {e['request']['method']} {url} as {who} → " \
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
    path = directory / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', evidence_id(ctx.plan))}-poc.har"
    data = json.dumps(har, indent=1, default=str).encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    fd, temporary = tempfile.mkstemp(prefix=".har-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return [{"kind": "har", "path": f"evidence/{path.name}", "redacted": True,
             "sha256": digest, "note": TARGET_DATA_NOTE}]


def _values(highlight, text: str) -> list[str]:
    """The values the model named that really occur in `text`; only those are marked."""
    return [v for v in (highlight if isinstance(highlight, list) else [])[:_MAX_HIGHLIGHTS]
            if isinstance(v, str) and 3 <= len(v) <= 200 and v in text]


def _page_screenshots(ctx, steps: list[dict], highlight) -> list[dict]:
    """Access control (VER-035): each decisive response that is an HTML page, rendered without a new request."""
    browser = ctx.browser
    out = []
    for step in steps:
        e = _shown_entry(step)
        if not step["decisive"] or e is None or "html" not in e["response"]["content"]["mimeType"].lower():
            continue
        text = _text(e)
        if not text or not 200 <= e["response"]["status"] < 300:
            continue
        values = _values(highlight, text)
        caption = [f"AppSec Verifier · {ctx.plan.id} · access control · step {step['step']}",
                   f"{e['request']['method']} {e['request']['url'][:300]} as {e.get('_role') or 'anonymous'} "
                   f"→ {e['response']['status']}",
                   f"captured {shown_time(e['startedDateTime'])} · rendered from the recorded response, "
                   "no new request"]
        try:
            out += browser.render(url=e["request"]["url"], status=e["response"]["status"],
                                  content_type=e["response"]["content"]["mimeType"], html=text,
                                  name=evidence_name(ctx.plan), caption=caption, highlight=values)
        except Exception:  # noqa: BLE001 - a screenshot only illustrates; the verdict stands without it
            continue
    return out


# ── the exchange image (VER-035) ─────────────────────────────────────────────

_TOKEN_START = set(" \n&?=\"':,{[")
_TOKEN_END = set(" \n&\"',;}]")


def _diff_token(a: str, b: str, region: str) -> tuple[str, str, str] | None:
    """The token of `a` around its first difference from `b`, e.g. the value of the changed parameter, as
    (region, the text before it, token): marked once, where it stands, not wherever it recurs."""
    i = len(os.path.commonprefix([a, b]))
    if i >= len(a):
        return None
    start, end = i, i
    while start > 0 and a[start - 1] not in _TOKEN_START:
        start -= 1
    while end < len(a) and a[end] not in _TOKEN_END:
        end += 1
    token = (a[start:end] or a[i:i + 40])[:200]
    return (region, a[max(0, start - 24):start], token) if token.strip() else None


def _target(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + ("?" + parts.query if parts.query else "")


def _marked(text: str, needles=(), lines=()) -> tuple[str, int]:
    """`text` as escaped HTML with what `needles` and `lines` name in <mark>, each a (label, what) pair: a
    string at each occurrence, a (region, context, token) from `_diff_token` once in the request line or the
    body, and in `lines` a prefix that marks each line starting with it. A red tag before the first mark of
    each label says what is marked; tag and mark wrap to the next line together, not inside a word. Nothing of
    `text` is ever parsed as markup."""
    spans = []
    blank = text.find("\n\n")
    body_start = blank + 2 if blank >= 0 else len(text)
    first_line_end = text.find("\n") if "\n" in text else len(text)
    for label, needle in needles:
        if isinstance(needle, tuple):
            region, context, token = needle
            lo, hi = (0, first_line_end) if region == "line" else (body_start, len(text))
            i = text.find(context + token, lo, hi)
            if i >= 0:
                spans.append((i + len(context), i + len(context) + len(token), label))
            elif (i := text.find(token, lo, hi)) >= 0:
                spans.append((i, i + len(token), label))
            continue
        start = 0
        while needle and len(spans) < 50 and (i := text.find(needle, start)) >= 0:
            spans.append((i, i + len(needle), label))
            start = i + len(needle)
    pos = 0
    for line in text.split("\n"):
        label = next((label for label, prefix in lines if line.lower().startswith(prefix.lower())), None)
        if label is not None:
            spans.append((pos, pos + len(line), label))
        pos += len(line) + 1
    merged: list[list] = []
    for a, b, label in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
            merged[-1][2].append(label)
        else:
            merged.append([a, b, [label]])
    out, last, tagged = [], 0, set()
    for a, b, labels in merged:
        new = [label for label in dict.fromkeys(labels) if label not in tagged]
        tagged.update(new)
        tag = f"<span class=tag>{html.escape(' · '.join(new))} ▸</span>" if new else ""
        out += [html.escape(text[last:a]), f"<span class=hit>{tag}<mark>{html.escape(text[a:b])}</mark></span>"]
        last = b
    out.append(html.escape(text[last:]))
    return "".join(out), len(merged)


class _CodeMarks(HTMLParser):
    """Reuse deterministic proof locations as plain code-block annotations (VER-035): ⟦…⟧ around what is
    marked. The image's labels stay out, so a recorded value reads as it was sent or answered."""

    def __init__(self):
        super().__init__()
        self.parts = []
        self._label = False

    def handle_starttag(self, tag, attrs):
        if tag == "mark":
            self.parts.append("⟦")
        elif tag == "span" and ("class", "tag") in attrs:
            self._label = True

    def handle_endtag(self, tag):
        if tag == "mark":
            self.parts.append("⟧")
        elif tag == "span":
            self._label = False

    def handle_data(self, data):
        if not self._label:
            self.parts.append(data)


def _code_excerpt(text, needles=(), lines=()):
    parser = _CodeMarks()
    parser.feed(_marked(text, needles, lines)[0])
    return "".join(parser.parts)


_SHORT_BODY = 600


def _report_body(ctx, e, body, marks) -> str:
    """The decisive part of a response body for the report (VER-034): a short body whole; a page an XSS marker
    did not reach as no source, since the browser decides; another page as its visible text; a JSON body,
    except for injection, as its marked and ownership fields; else a window around the first located value."""
    text, content = _text(e), e["response"]["content"]
    mime, cls = content.get("mimeType", "").lower(), getattr(ctx.plan, "cls", None)
    located = any(v and v in text for v in (m[2] if isinstance(m, tuple) else m for _, m in marks))
    if not content.get("_omitted") and len(text) > _SHORT_BODY:
        if "html" in mime and cls == "xss" and not located:
            return "[page source omitted: the browser observation above decides the XSS test; full record in HAR]"
        if "html" in mime and not located:
            parser = _VisibleText()
            parser.feed(text[:MAX_BODY_CHARS])
            return _image_excerpt("Visible text: " + " ".join(" ".join(parser.parts).split()), marks, limit=400)
        if "json" in mime and cls != "injection":
            try:
                return _json_fields(json.loads(text), marks)
            except (ValueError, RecursionError):
                pass
    return _image_excerpt(body, marks, limit=1000)


def _report_excerpts(ctx, history, n, entry, shown, highlight, har_path):
    req, res, lines, facts = _exchange_marks(ctx, history, n, entry, shown, highlight)
    response = _raw_response(entry, _focus(ctx, [e for _, e in shown], entry), har_path)
    headers, _, body = response.partition("\n\n")
    kept = [line for i, line in enumerate(headers.splitlines())
            if i == 0 or line.lower().startswith(("content-type:", "location:", "www-authenticate:", "set-cookie:"))]
    response = "\n".join(kept) + "\n\n" + _report_body(ctx, entry, body, res)
    return {"request_excerpt": _code_excerpt(_image_request(entry, req), req),
            "response_excerpt": _code_excerpt(response, res, lines),
            "facts": [fact for fact, decisive in facts if decisive]}


def _exchange_marks(ctx, history: list[dict], n: int, e: dict, shown: list[tuple[int, dict]],
                    highlight) -> tuple[list[tuple], list[tuple], list[tuple[str, str]], list[tuple[str, bool]]]:
    """What the image of step `n` marks, as the code can locate it, each with its label: needles in the
    request, needles and line prefixes in the response, and facts about the step with whether they decide."""
    from ..agent.proof import redirect_host

    cls, marker = getattr(ctx.plan, "cls", None), getattr(ctx, "marker", None) or ("", "")
    step = history[n - 1] if n <= len(history) else {}
    res = step.get("result") or {}
    req_marks, res_marks, res_lines = [], [], []
    facts: list[tuple[str, bool]] = []
    times = [o.get("time") or 0 for _, o in shown]
    timing = cls == "injection" and max(times) - min(times) >= 2000        # a timing proof rests on the times
    if e.get("time"):
        facts.append((f"answered in {e['time']} ms", timing))
    if cls == "access-control" and e.get("_role"):      # elsewhere the step heading names the identity
        req_marks.append(("identity", f"[identity {e['_role']}]"))
    if cls == "xss" and marker[0]:
        req_marks.append(("payload", marker[0]))
        res_marks.append(("payload in the answer", marker[0]))
        if step.get("tool") == "browser_check":     # a fragment (#/search?q=…) never reaches the server
            facts.append((f"opened in the browser: {unquote(str((step.get('args') or {}).get('path', '')))[:300]}",
                          True))
        if "executed" in res:
            facts.append((f"marker executed in the browser: {'yes' if res['executed'] is True else 'no'}", True))
    elif cls == "open-redirect":
        host = redirect_host(marker)
        if host:
            req_marks.append(("redirect target", host))
        res_lines.append(("redirect", "location:"))
    elif cls == "path-traversal":
        marker_file = (getattr(ctx, "scope", None) or {}).get("marker_file") or {}
        name = str(marker_file.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1]
        req_marks += [("marker file", name)] if name else []
        res_marks += [("marker file content", marker_file["content"])] if marker_file.get("content") else []
        if "marker_read" in res:
            facts.append((f"marker file read: {'yes' if res['marker_read'] is True else 'no'}", True))
    elif cls == "ssrf":
        joined = res.get("callback_attempt") or "".join(marker)
        req_marks += [("callback marker", joined)] if joined else []
        if "callback_hit" in res:
            facts.append((f"callback listener received the marker: {'yes' if res['callback_hit'] is True else 'no'}",
                          True))
    elif cls == "injection":
        path = e["request"]["url"].split("?")[0]
        for _, o in shown:
            if o is e or o["request"]["url"].split("?")[0] != path:
                continue
            a_url, b_url = _target(e["request"]["url"]), _target(o["request"]["url"])
            a_body = (e["request"].get("postData") or {}).get("text") or ""
            b_body = (o["request"].get("postData") or {}).get("text") or ""
            token = (_diff_token(a_url, b_url, "line") if a_url != b_url
                     else _diff_token(a_body, b_body, "body"))
            if token:
                req_marks.append(("input", token))
                decoded = (unquote_plus if token[0] == "line" else unquote)(token[2])   # a query's + is a space
                if decoded != token[2]:
                    facts.append((f"input, decoded: {decoded}", True))
            token = _diff_token(_text(e), _text(o), "body")
            res_marks += [("answer differs", token)] if token else []
            if e["response"]["status"] != o["response"]["status"]:
                res_lines.append(("status differs", "HTTP/1.1 "))
    elif cls == "access-control":
        own_marker = "".join(marker)
        if own_marker and own_marker in _text(e):
            res_marks.append(("test marker", own_marker))
        res_marks += [("named in the verdict", value) for value in _values(highlight, _text(e))]
    elif cls == "session":
        res_lines += _session_cookie_line(ctx, history, res)
    return req_marks, res_marks, res_lines, facts


_SESSION_ATTRIBUTES = {"CWE-614": "Secure", "CWE-1004": "HttpOnly", "CWE-1275": "SameSite"}


def _session_cookie_line(ctx, history: list[dict], res: dict) -> list[tuple[str, str]]:
    """The Set-Cookie line of the session cookie the plan observes, labelled with the attribute the finding
    is about as the step saw it, e.g. "HttpOnly missing"; nothing without a declared session plan."""
    from ..agent.experiments import latest_plan

    _, plan = latest_plan(history)
    resource = next((r for r in (getattr(ctx, "scope", None) or {}).get("session_checks", [])
                     if r.get("finding_id") == ctx.plan.id and r.get("id") == plan.get("resource")), None)
    attribute = _SESSION_ATTRIBUTES.get(getattr(ctx.plan, "cwe", None))
    if not resource or not resource.get("cookie_name") or not attribute:
        return []
    name = resource["cookie_name"]
    seen = next((c for c in res.get("session_cookies") or [] if c.get("name") == name), None)
    if seen is None:
        label = "session cookie"
    elif attribute == "SameSite":
        label = f"SameSite={seen['samesite'][:20].capitalize()}" if seen.get("samesite") else "SameSite missing"
    else:
        label = f"{attribute} {'set' if seen.get(attribute.lower()) else 'missing'}"
    return [(label, f"set-cookie: {name}=")]


class _VisibleText(HTMLParser):
    """Extract a bounded text excerpt; never execute recorded markup."""

    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.parts.append(data.strip())


def _image_excerpt(text: str, needles=(), *, limit=700) -> str:
    """An explicitly shortened window around the first located evidence value."""
    values = [v[2] if isinstance(v, tuple) else v for _, v in needles]
    focus = next((text.index(v) for v in values if v and v in text), 0)
    start = max(0, focus - 100) if len(text) > limit else 0
    excerpt = text[start:start + limit]
    lines = excerpt.splitlines()
    if len(lines) > 12:
        # Keep the located evidence within the visible lines, including late JSON fields.
        index = excerpt[:max(0, focus - start)].count("\n")
        offset = max(0, index - 3)
        lines = lines[offset:offset + 12]
        excerpt = ("[…]\n" if offset else "") + "\n".join(lines) + "\n[…]"
    return ("[…]" if start else "") + excerpt + (
        "\n[…] excerpt; full record in HAR" if start + limit < len(text) else "")


def _image_request(e, marks):
    req = e["request"]
    lines = [f"{req['method']} {_target(req['url'])} HTTP/1.1"]
    lines += [f"{h['name']}: {h['value']}" for h in req["headers"]
              if h["name"].lower() in ("authorization", "content-type")]
    body = (req.get("postData") or {}).get("text") or ""
    return _image_excerpt("\n".join(lines), marks, limit=450) + "\n\n" + _image_excerpt(body, marks, limit=350)


def _json_fields(value, marks):
    """Bounded scalar projection with explicit paths, prioritising marked data and ownership fields."""
    fields = []
    needles = [v for _, v in marks if isinstance(v, str)]

    def visit(item, path="", depth=0):
        if len(fields) >= 128 or depth > 8:
            return
        if isinstance(item, dict):
            for key, child in list(item.items())[:32]:
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                visit(child, path + "/" + escaped, depth + 1)
        elif isinstance(item, list):
            for index, child in enumerate(item[:8]):
                visit(child, path + "/" + str(index), depth + 1)
        else:
            rendered = json.dumps(item, ensure_ascii=False)
            priority = (0 if any(v in rendered for v in needles) else
                        1 if path.rsplit("/", 1)[-1].lower() in ("id", "userid", "ownerid", "role") else 2)
            fields.append((priority, path or "/", rendered))

    visit(value)
    chosen = sorted(fields, key=lambda row: row[0])[:7]
    return "Selected JSON fields (other content in HAR):\n" + "\n".join(
        f"{path}: {_image_excerpt(value, marks, limit=180)}" for _, path, value in chosen)


def _image_response(ctx, e, marks, marked_lines):
    res = e["response"]
    lines = [f"HTTP/1.1 {res['status']} {res['statusText']}".rstrip()]
    keep = {"location", "www-authenticate", "set-cookie"}
    lines += [f"{h['name']}: {h['value']}" for h in res["headers"]
              if h["name"].lower() in keep or any(h["name"].lower() + ":" == prefix.lower()
                                                for _, prefix in marked_lines)]
    text = _text(e)
    mime = res["content"].get("mimeType", "").lower()
    if "html" in mime:
        if getattr(ctx.plan, "cls", None) == "xss":
            text = "Application HTML omitted here. The browser execution observation above decides the XSS test."
        else:
            parser = _VisibleText()
            parser.feed(text[:MAX_BODY_CHARS])
            text = "Visible text excerpt: " + " ".join(parser.parts)
    else:
        try:
            if getattr(ctx.plan, "cls", None) == "access-control":
                text = _json_fields(json.loads(text), marks)
            elif getattr(ctx.plan, "cls", None) != "injection":
                text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except (ValueError, RecursionError):
            pass
    if res["content"].get("_omitted"):
        text = "[Body omitted from the record]"
    return _image_excerpt("\n".join(lines), limit=450) + "\n\n" + _image_excerpt(text, marks)


_EXCHANGE_CSS = """body{margin:0;background:#fff;color:#111;font:16px/1.45 ui-monospace,Menlo,Consolas,monospace}
header{background:#111;color:#fff;padding:10px 14px;border-bottom:4px solid #b00020;white-space:pre-wrap}
header b{font-size:20px}section{margin:14px;border:1px solid #ccc}
h2{margin:0;padding:6px 10px;background:#f0f0f0;font-size:16px;border-bottom:1px solid #ccc}
.facts{padding:4px 10px;border-bottom:1px solid #ccc}.cols{display:flex}.cols>div{flex:1;min-width:0}
.cols>div+div{border-left:1px solid #ccc}h3{margin:0;padding:4px 10px;font-size:15px;color:#555}
pre{margin:0;padding:6px 10px 10px;white-space:pre-wrap;overflow-wrap:anywhere}
mark{background:#ffeb3b;color:#000;outline:2px solid #b00020}.hit{display:inline-block;max-width:100%}
.tag{background:#b00020;color:#fff;font:bold 13px sans-serif;padding:1px 5px;margin-right:3px;border-radius:3px}"""


def exchange_document(ctx, history: list[dict], shown: list[tuple[int, dict]], verdict: str, har_path,
                      highlight=None, *, cited: bool = True, comparison=None) -> tuple[str, int]:
    """The decisive exchanges of a finding as one HTML page for its screenshot (VER-035): request and
    response side by side per step, what the verdict rests on marked. Without `cited` they are the answered
    requests after the last test plan of a verdict that cites no step, and the header says so. Returns the page
    and the number of marks. Every recorded value is escaped; the page has no script."""
    cls = getattr(ctx.plan, "cls", None) or "finding"
    captured = shown[0][1].get("startedDateTime", "") if shown else ""
    head = (f"<b>AppSec Verifier · {html.escape(str(ctx.plan.id))} · {html.escape(cls)} · "
            f"{html.escape(verdict)}</b>\nRecorded, redacted exchanges"
            f"{' from ' + html.escape(har_path) if har_path else ''}; no new request. "
            f"First captured {html.escape(shown_time(captured))}.\n"
            + ("Marked: what the verdict rests on, as the code locates it." if cited else
               "The verdict cites no step: the answered requests after the last test plan. Marked: what the code "
               "locates in them; it proves nothing."))
    interpretation = {
        "confirmed": "The proof checker accepted the cited evidence.",
        "inconclusive": "Not established: the observations do not complete the required proof.",
        "blocked-by-control": "The tested operation was refused with matched control evidence.",
        "not-reproducible": "Not reproduced in the cited attempts; this does not prove absence.",
    }.get(verdict, "No completed proof.")
    overview = " | ".join(f"step {n}: {e.get('_role') or 'anonymous'} → {e['response']['status']}"
                          for n, e in (comparison or shown)[:12])
    head += "\n" + html.escape(interpretation) + "\nComparison: " + html.escape(overview)
    head += "\nSelected excerpts; routine headers and unrelated body content omitted. Full record in HAR."
    parts, total = [f"<header>{head}</header>"], 0
    for n, e in shown[:6]:
        req_marks, res_marks, res_lines, facts = _exchange_marks(ctx, history, n, e, comparison or shown, highlight)
        req_html, a = _marked(_image_request(e, req_marks), req_marks)
        res_html, b = _marked(_image_response(ctx, e, res_marks, res_lines), res_marks, res_lines)
        fact_html = " · ".join(f"<b>{html.escape(t)}</b>" if decides else html.escape(t) for t, decides in facts)
        total += a + b
        who = html.escape(e.get("_role") or "anonymous")
        parts.append(f"<section><h2>Step {n} · {html.escape(e['request']['method'])} as {who} → "
                     f"{e['response']['status']} {html.escape(e['response']['statusText'])}</h2>"
                     + (f"<div class=facts>{fact_html}</div>" if facts else "")
                     + f"<div class=cols><div><h3>Request</h3><pre>{req_html}</pre></div>"
                     f"<div><h3>Response</h3><pre>{res_html}</pre></div></div></section>")
    page = (f"<!doctype html><html><head><meta charset=utf-8><style>{_EXCHANGE_CSS}</style></head>"
            f"<body>{''.join(parts)}</body></html>")
    return page, total


def _tried(history: list[dict], steps: list[dict]) -> list[tuple[int, dict]]:
    """For a verdict that cites no step (VER-035): the answered requests after the last accepted test plan."""
    start = max((n for n, h in enumerate(history, 1)
                 if h.get("tool") == "plan_test" and (h.get("result") or {}).get("accepted") is True), default=0)
    out = []
    for s in steps:
        h = history[s["step"] - 1] if 1 <= s["step"] <= len(history) else {}
        e = _shown_entry(s)
        if s["step"] > start and e is not None and type((h.get("result") or {}).get("status")) is int:
            out.append((s["step"], e))
    return out


def _exchange_screenshot(ctx, history: list[dict], shown: list[tuple[int, dict]], verdict: str, har_path,
                         highlight, *, cited: bool = True) -> list[dict]:
    shots = []
    # Two exchanges per panel preserve the comparison without a long full-page image.
    for start in range(0, min(len(shown), 6), 2):
        page, marked = exchange_document(ctx, history, shown[start:start + 2], verdict, har_path,
                                         highlight, cited=cited, comparison=shown)
        visible = _VisibleText()
        visible.feed(page)
        ctx.evidence_panels.append({"text": "\n".join(visible.parts)[:8000], "body_font_px": 16})
        try:
            shots += ctx.browser.render_exchanges(html=page, name=evidence_name(ctx.plan), marked=marked)
        except Exception:  # noqa: BLE001 - a screenshot only illustrates; the verdict stands without it
            break
    return shots


def attach(ctx, history: list[dict], steps: list[dict], result, cited, highlight=None):
    """Bound final rendering; retain recorded exchanges after a stop (VER-036).

    Saving existing evidence has a separate five-second shutdown allowance.
    It never starts a browser, model call or target request.
    """
    from ..limits import LimitExceeded, execution_deadline

    if getattr(ctx, "archive_attempt", None):
        attempt = dict(ctx.archive_attempt)
        result.proof = {**(result.proof or {}), "archive_attempt": attempt}
        result.observations.append(
            f"Archive test marker {attempt['marker']}; cleanup: {attempt['cleanup']}."
        )
    remaining = ctx.budget.remaining_time()
    window = ctx.guard.remaining_time()
    kind = "window" if window is not None and window <= remaining else "time"
    seconds = min(remaining, window) if window is not None else remaining
    try:
        with execution_deadline(seconds, kind=kind):
            return _attach(ctx, history, steps, result, cited, highlight)
    except LimitExceeded as exc:
        result.limits_hit = result.limits_hit or exc.kind
        result.observations.append("Evidence rendering stopped at the execution deadline; screenshots may be missing.")
        if steps and not result.poc:
            try:
                with execution_deadline(5):
                    for step in steps:
                        step.setdefault("decisive", False)
                    har = _write_har(ctx, steps)
                    result.evidence = [*(result.evidence or []), *har]
                    result.poc = {
                        "file": har[0]["path"] if har else None,
                        "steps": [{"step": s["step"], "line": _line(s, history), "decisive": s["decisive"]}
                                  for s in steps],
                        "shown": [],
                    }
            except LimitExceeded:
                result.observations.append("Saving recorded exchanges exceeded the five-second shutdown allowance.")
        return result


def _attach(ctx, history: list[dict], steps: list[dict], result, cited, highlight=None):
    for step in history:
        if step.get("tool") == "browser_check" and (problem := step.get("result", {}).get("screenshot_error")):
            note = "Application screenshot unavailable: " + problem + "."
            if note not in result.observations:
                result.observations.append(note)
    # The plan as accepted: plan_test may have counted an unsupported observed prerequisite as assumed.
    accepted = [(n, h["result"].get("experiment") or h["args"]) for n, h in enumerate(history, 1)
                if h.get("tool") == "plan_test" and h.get("result", {}).get("accepted") is True]
    result.planning = [{"step": n, "path": p.get("path"), "hypothesis": p.get("hypothesis"),
                        "strategy": p.get("strategy")} for n, p in accepted]
    if ctx.sessions is not None:
        result.planning = ctx.sessions.redact(result.planning)
    """Write the finding's proof of concept and add it to `result` (VER-034, VER-035)."""
    if not steps:
        return result
    decisive = set(decisive_steps(ctx, history, result.verdict, cited))
    for step in steps:
        step["decisive"] = step["step"] in decisive
    har = _write_har(ctx, steps)
    result.evidence = [*(result.evidence or []), *har]
    har_path = har[0]["path"] if har else None
    shown_entries = [(s["step"], _shown_entry(s)) for s in steps if s["decisive"]]
    shown_entries = [(n, e) for n, e in shown_entries if e is not None]
    others = [e for _, e in shown_entries]
    result.poc = {
        "file": har_path,
        "steps": [{"step": s["step"], "line": _line(s, history), "decisive": s["decisive"]} for s in steps],
        "shown": [{"step": n, "request": _raw_request(e), "elapsed_ms": e.get("time"),
                   "response": _raw_response(e, _focus(ctx, others, e), har_path),
                   **_report_excerpts(ctx, history, n, e, shown_entries, highlight, har_path)}
                  for n, e in shown_entries],
    }
    shots: list[dict] = []
    cls, browser = getattr(ctx.plan, "cls", None), getattr(ctx, "browser", None)
    if browser is not None and cls in getattr(browser, "screenshots", ()):
        if result.verdict == "confirmed" and cls == "access-control" and not any(
                e.get("presentation") == "application" for e in result.evidence):
            shots = _page_screenshots(ctx, steps, highlight)
        if shown_entries:                        # the exchanges, also beside a page that shows the proof
            shots += _exchange_screenshot(ctx, history, shown_entries, result.verdict, har_path, highlight)
        elif not decisive and (tried := _tried(history, steps)):     # e.g. a finding a limit stopped
            shots += _exchange_screenshot(ctx, history, tried, result.verdict, har_path, highlight, cited=False)
    result.evidence = [*(result.evidence or []), *shots]
    if result.verdict == "confirmed" and not any(
        e.get("presentation") == "application" for e in result.evidence
    ) and not any(o.startswith("Application screenshot unavailable:") for o in result.observations):
        if browser is None:
            reason = "the proof browser is unavailable"
        elif cls not in getattr(browser, "screenshots", ()):
            reason = "screenshots are disabled for this class"
        else:
            reason = ("no application page showing the confirmed effect was captured; "
                      "for API-only findings the recorded HTTP exchanges are the primary evidence")
        result.observations.append("Application screenshot unavailable: " + reason + ".")
    return result
