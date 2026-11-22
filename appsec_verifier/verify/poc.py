"""The proof of concept of every tested finding (VER-034, VER-035, VER-016, VER-022, VER-059, VER-066, VER-067).

Every request an agent step sends to the target is recorded with the answer to
it, by the code from what was sent and received: by `http_request`, and by
`browser_check` for each request of the page that the guarded client answered.
The model sees none of it beyond its own tool results, and its own account of
evidence is not taken over.

Each exchange is redacted when it is recorded, each mask naming what it hides:
headers the identity added read `[identity <role>]`, every credential value the
sessions know its placeholder, such as `[account-1 password]`
(auth/sessions.py), an Authorization header its scheme and `[credential]`, a
unrecognized cookie value `[session cookie]`, another
header named like a credential `[credential]`, a query parameter named like a
token `[token]`, and every JWT `[JWT]`. A parameter named like a password keeps
its value unless the sessions know it: the agent never knows a password. Other cookie values are settings, not
secrets, and stay, as do cookie names and Set-Cookie attributes. Bodies are kept as text up to `MAX_BODY_CHARS`, cut
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
are saved for later use, not embedded. Every image starts with the verdict and one
sentence that says why (`headline`, `verdict_sentence`, VER-035): the weakness, the
tested input and because what the proof showed, or the reason the report gives.
An access-control comparison gets one image of its own (`comparison_document`):
a table row per identity, the answer once, and why the verdict follows. Images
and report say why a confirmed result is confirmed (`why_summary`): the rule
that makes it a proof and every step it rests on. Every finding with decisive
steps also gets an image of those exchanges: as the test agent presents them,
with what verify/presentation.py left out and the steps it does not show named,
the report showing those steps after the agent's (VER-059); where the Verifier
shows its own presentation instead, one image of the steps the proof compares,
two side by side with the attack first or one with its request beside its
answer, the other steps named below, the reason in its small print and in the
observations; an injection experiment's image comes first. One whose verdict
cites none (a limit stopped it) gets an image of its answered requests after
the last test plan that says so, built here as escaped HTML with
what the code can locate marked, each kind labelled by a red tag: the
identities an access-control proof compares, the XSS payload (in a request
URL-decoded; in an answer its HTML source lines), the SSRF marker, the
redirect host and Location header, the marker file and its content, the input
and answer that differ between injection requests, the session cookie's
Set-Cookie line. Facts about a step, such as the page a browser check opened
or the time of each answer, stand above it, in bold where they decide. A step
whose proof check reads an observation of its own (an executed marker, a read
marker file, a callback hit, an authenticated artifact, an engine error or a
returned generated marker; VER-048, VER-049, VER-053) is shown by that, framed
where its answer shows it, not by a status or answer difference.
Where the accepted test plan or the finding's payload says what a step is
(`step_roles`), its heading names it; a line says how an attack's answer
compares only where the image does not show what it is compared with. An
injection experiment's JSON answer is shortened around the observed field,
which is framed (`_json_excerpt`); a deeper field is shown by its value view,
entries the compared answer lacks marked `+`.
The report lists normal requests before attacks, with the same comparison.
Response bodies and screenshots can show target data and are marked for
review before sharing (VER-022).
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

import httpx

from ..auth.model_data import credential_text
from ..auth.sessions import secret_cookie
from ..planning import evidence_id, evidence_name

# What a mask hides, where the sessions know no placeholder for the value (VER-016).
JWT_MASK, SESSION_COOKIE_MASK, TOKEN_MASK, CREDENTIAL_MASK = "[JWT]", "[session cookie]", "[token]", "[credential]"
MASKS = (JWT_MASK, SESSION_COOKIE_MASK, TOKEN_MASK, CREDENTIAL_MASK)
TARGET_DATA_NOTE = "may show target data; review before sharing"
MAX_BODY_CHARS = 256 * 1024
MAX_FINDING_BODY_CHARS = 4 * 1024 * 1024        # all bodies of one finding together
MAX_RAW_BYTES = 4 * MAX_BODY_CHARS              # what a browser capture keeps of a body before redaction
EXCERPT_CHARS = 1500
_MAX_HEADERS = 100
_MAX_VALUE = 8192
MAX_BROWSER_EXCHANGES = 50
_MAX_HIGHLIGHTS = 3
_AUTHORIZATION = re.compile(r"^(?:proxy-)?authorization$", re.I)
# A query parameter named like a token; a header so named, or named like a password, carries a credential.
_TOKEN_NAME = re.compile(r"token|secret|api[-_]?key|session|credential|(?:^|[-_])auth(?:$|[-_])", re.I)
_CREDENTIAL_HEADER = re.compile(_TOKEN_NAME.pattern + "|passw", re.I)
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
        return _JWT.sub(JWT_MASK, self._redact(value))

    def header(self, name: str, value: str) -> str:
        low = name.lower()
        own = self._identity.get(low)
        if own and own in value:
            return f"[identity {self._role}]"
        if low == "cookie":
            return "; ".join(self._cookie(part.strip()) for part in value.split(";"))
        if low == "set-cookie":
            first, sep, attributes = value.partition(";")
            return self._cookie(first.strip()) + (sep + self.text(attributes) if sep else "")
        if _AUTHORIZATION.match(low):
            scheme, _, credential = value.strip().partition(" ")
            return f"{self.text(scheme[:40])} {CREDENTIAL_MASK}" if credential else CREDENTIAL_MASK
        if _CREDENTIAL_HEADER.search(low):
            return CREDENTIAL_MASK
        return self.text(value)[:_MAX_VALUE]

    def _cookie(self, pair: str) -> str:
        """`name=value` with the value's placeholder, `[session cookie]` for a value that can be a session, or the
        value itself: another cookie, such as `security=low`, is a setting (VER-016)."""
        name, sep, value = pair.partition("=")
        if not sep:
            return self.text(pair)
        shown = self.text(value)
        return f"{name.strip()}={SESSION_COOKIE_MASK if shown == value and secret_cookie(name, value) else shown}"

    def url(self, url: str) -> str:
        try:
            parts = urlsplit(url)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError:
            return self.text(url)[:_MAX_VALUE]
        if any(_TOKEN_NAME.search(k) for k, _ in pairs):
            query = urlencode([(k, TOKEN_MASK if _TOKEN_NAME.search(k) else v) for k, v in pairs])
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
          size: int | None = None, *, response=False) -> dict:
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
        if response:
            text = credential_text(text)
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
    content = _body(raw["content"], res_ct, red, omit_body, raw.get("content_size"), response=True)
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
    the XSS marker, the earliest place where an injection answer differs from another (`_answer_difference`), or 0."""
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
        at = [_located(text, d) for o in others if (d := _answer_difference(text, o))]
        at = [i for i in at if i >= 0] or [len(os.path.commonprefix([text, o])) for o in others]
        if at:
            return min(at)
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
        # The answer's size in the step lines' unit, bytes; a count of the redacted text would be a third figure.
        body = (("[…]\n" if start else "") + text[start:start + EXCERPT_CHARS]
                + f"\n[… characters {start + 1} to {start + EXCERPT_CHARS} shown of a {content.get('size')}-byte "
                  f"answer{where}]")
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
    from ..output_files import write_output

    write_output(path, data)
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
            images = browser.render(url=e["request"]["url"], status=e["response"]["status"],
                                    content_type=e["response"]["content"]["mimeType"], html=text,
                                    name=evidence_name(ctx.plan), caption=caption, highlight=values)
            out += [{**image, "finding_id": ctx.plan.id, "proof_step": step["step"],
                     "role": e.get("_role") or "anonymous"} for image in images]
        except Exception:  # noqa: BLE001 - a screenshot only illustrates; the verdict stands without it
            continue
    return out


# ── the exchange image (VER-035) ─────────────────────────────────────────────

_TOKEN_START = set(" \t\n&?=\"':,{[")
_TOKEN_END = set(" \t\n&\"',;}]")
_TAG = re.compile(r"<[^<>]*>")      # [^<>] keeps the scan linear in an answer full of unclosed "<"
_LINE_MARK = 300                    # the longest answer line framed whole as where two answers differ


def _token_at(a: str, i: int, region: str) -> tuple[str, str, str] | None:
    start, end = i, i
    while start > 0 and a[start - 1] not in _TOKEN_START:
        start -= 1
    while end < len(a) and a[end] not in _TOKEN_END:
        end += 1
    token = (a[start:end] or a[i:i + 40])[:200]
    return (region, a[max(0, start - 24):start], token) if token.strip() else None


def _diff_token(a: str, b: str, region: str) -> tuple[str, str, str] | None:
    """The token of `a` around its first difference from `b`, e.g. the value of the changed parameter, as
    (region, the text before it, token): marked once, where it stands, not wherever it recurs."""
    i = len(os.path.commonprefix([a, b]))
    return None if i >= len(a) else _token_at(a, i, region)


def _shown_text(line: str) -> str:
    return " ".join(_TAG.sub(" ", line).split())


def _answer_difference(a: str, b: str) -> tuple[str, str, str] | None:
    """Where answer `a` differs from answer `b` for a reader, as `_diff_token` gives it (VER-035): the first line
    whose text, without tags and spacing, no line of `b` has, such as an error message or another page title, framed
    without its indentation and, beyond _LINE_MARK characters, to the end of a word before it; in a line `b` has in
    changed form (it begins like one of them for at least half its length), the value where it starts to differ.
    Tags and spacing alone are no difference, unless the answers differ in nothing else; where `a` only lacks lines
    of `b`, nothing of `a` is marked."""
    lines_b = b.split("\n")
    texts_b = {_shown_text(line) for line in lines_b}
    pos = 0
    for line in a.split("\n"):
        text = _shown_text(line)
        if text and text not in texts_b:
            shown = line.strip()
            start = pos + line.index(shown)
            same = max((len(os.path.commonprefix([shown, o.strip()])) for o in lines_b), default=0)
            if 2 * same < len(shown):
                cut = shown if len(shown) <= _LINE_MARK else shown[:_LINE_MARK].rsplit(" ", 1)[0]
                return "body", a[max(0, start - 24):start], cut
            return _token_at(a, start + min(same, len(shown) - 1), "body")
        pos += len(line) + 1
    if texts_b - {_shown_text(line) for line in a.split("\n")}:
        return None
    return _diff_token(a, b, "body")


def _located(text: str, needle) -> int:
    """Where a mark stands in `text`: a (region, context, token) after its context, else, like a plain string, at
    the first occurrence of its token; -1 if absent."""
    if isinstance(needle, tuple):
        _, context, needle = needle
        i = text.find(context + needle) if needle else -1
        if i >= 0:
            return i + len(context)
    return text.find(needle) if needle else -1


def _target(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + ("?" + parts.query if parts.query else "")


# ── what each shown step is in the test (VER-035) ────────────────────────────

ROLE_TITLES = {"normal": "Normal request", "control": "Control", "attack": "Attack", "effect": "Effect",
               "outcome": "Outcome"}     # outcome: a step the test agent presents so (VER-059)
_ROLE_ORDER = {kind: i for i, kind in enumerate(ROLE_TITLES)}
_MISSING = object()
_EXPERIMENT_ROLES = {"baseline": ("normal", "baseline input"), "positive": ("attack", "true condition"),
                     "negative": ("attack", "false condition"),
                     "positive_other": ("attack", "true condition, second form"),
                     "negative_other": ("attack", "false condition, second form")}


def _sink(plan: dict, args: dict):
    """The value a request sent for the experiment's declared input, as the proof check reads it (VER-011)."""
    location = {"path": "path_inputs", "query": "params"}.get(plan.get("input_location"),
                                                               plan.get("input_location") or "params")
    raw = args.get(location)
    values = dict(raw) if isinstance(raw, dict) else {}
    if location == "params":
        values.update(parse_qsl((args.get("path") or "").partition("?")[2], keep_blank_values=True))
    from ..agent.experiments import brackets, take_sink

    value = take_sink(values, plan.get("input_name"), brackets(plan))
    return _MISSING if value is None else value


def _declared_resource(ctx, plan: dict) -> dict | None:
    """The operator's test resource the plan names for this finding, or None."""
    return next((r for r in (getattr(ctx, "scope", None) or {}).get("test_resources", [])
                 if r.get("id") == plan.get("resource") and r.get("finding_id") == ctx.plan.id), None)


def step_roles(ctx, history: list[dict], shown: list[tuple[int, dict]]) -> dict[int, tuple[str, str]]:
    """What each shown step is in the test, as (kind, label): `normal` (the baseline, the identity a resource
    belongs to or a request without the finding's payload), `control` (a request without a role that must be
    refused), `attack`, or `effect` (the owner's read after another account's change). Only the latest accepted
    test plan, the declared test resource and the finding's markers decide; a step they do not place gets no
    role, nothing is guessed (VER-035)."""
    from ..agent.experiments import existing_collection, latest_plan, normal_roles, token

    cls, marker = getattr(ctx.plan, "cls", None), getattr(ctx, "marker", None) or ("", "")
    _, plan = latest_plan(history)
    steps = {n: history[n - 1] if 1 <= n <= len(history) else {} for n, _ in shown}
    args = {n: h.get("args") or {} for n, h in steps.items()}
    roles: dict[int, tuple[str, str]] = {}
    if cls == "injection" and plan.get("error_set") and plan.get("input_name"):
        # VER-053: the engine-error sweep's requests are a syntax break and its balanced counterpart per
        # metacharacter; label which each step carried.
        for n, _ in shown:
            sent = _sink(plan, args[n])
            if sent is _MISSING:
                continue
            for entry in plan["error_set"]:
                if token(sent) == token(entry["break"]):
                    roles[n] = ("attack", f"syntax break {entry['name']!r}")
                elif token(sent) == token(entry["balance"]):
                    roles[n] = ("control", f"balanced {entry['name']!r}")
    elif cls == "injection" and plan.get("name_set") and plan.get("input_name"):
        # VER-066: the name test's requests are a fresh unknown name and a name the language knows, per pair.
        for n, _ in shown:
            sent = _sink(plan, args[n])
            if sent is _MISSING:
                continue
            for entry in plan["name_set"]:
                if token(sent) == token(entry["unknown"]):
                    roles[n] = ("attack", "unknown name")
                elif token(sent) == token(entry["known"]):
                    roles[n] = ("control", f"known name {entry['name']!r}")
    elif cls == "injection" and plan.get("kind") in ("boolean", "timing") and plan.get("input_name"):
        for n, _ in shown:
            sent = _sink(plan, args[n])
            group = next((k for k in _EXPERIMENT_ROLES if k in plan and sent is not _MISSING
                          and token(sent) == token(plan[k])), None)
            if group == "positive" and plan["kind"] == "timing":
                roles[n] = ("attack", "delay condition")
            elif group:
                roles[n] = _EXPERIMENT_ROLES[group]
    elif cls == "access-control" and plan.get("kind") == "access-control":
        role = {n: a.get("role") or None for n, a in args.items()}
        method = {n: (a.get("method") or "GET").upper() for n, a in args.items()}
        resource = _declared_resource(ctx, plan)
        if resource is not None:
            for n, _ in shown:
                if args[n].get("path") != resource.get("path"):
                    continue
                if role[n] in resource.get("allowed_roles", []):
                    roles[n] = ("normal", "allowed identity")
                elif role[n] in resource.get("denied_roles", []):
                    roles[n] = ("attack", "denied identity")
                elif role[n] is None:
                    roles[n] = ("control", "without login")
        elif plan.get("signed_in"):         # VER-057: the comparison the Verifier sent
            for n, _ in shown:
                if args[n].get("path") == plan.get("control_path"):
                    roles[n] = ("control", "random path next to it, without login")
                elif args[n].get("path") != plan.get("path"):
                    continue
                elif role[n] == plan["signed_in"]:
                    roles[n] = ("normal", "signed-in account")
                elif role[n] is None:
                    roles[n] = ("attack", "without login")
        elif plan.get("existing"):          # VER-067: a record the owner already has
            owner = plan["existing"]
            collection = existing_collection(plan.get("path", ""))
            listing = {n for n, _ in shown
                       if collection and urlsplit(args[n].get("path") or "").path.rstrip("/") == collection}
            owner_paths = {args[n].get("path") for n, _ in shown if role[n] == owner and n not in listing}
            for n, _ in shown:
                if n in listing:
                    roles[n] = (("normal", "owner lists its records") if role[n] == owner
                                else ("control", "another account lists its records"))
                elif role[n] == owner:
                    roles[n] = ("normal", "owner reads its record")
                elif role[n] is None:
                    roles[n] = ("control", "without login")
                elif args[n].get("path") in owner_paths:
                    roles[n] = ("attack", "another account reads the owner's record")
                else:
                    roles[n] = ("control", "another account reads its own record")
        elif plan.get("owner") or plan.get("reference"):
            owner = plan.get("owner") or plan.get("reference")
            normal = set(normal_roles(getattr(ctx, "identities", None))) - {owner}
            owner_paths = {args[n].get("path") for n, _ in shown if role[n] == owner and method[n] == "GET"}
            changes = [n for n, _ in shown if role[n] in normal and method[n] in ("POST", "PUT", "PATCH", "DELETE")]
            for n, _ in shown:
                if role[n] == owner and method[n] != "GET" and plan.get("owner"):
                    roles[n] = ("normal", "owner creates the record")
                elif role[n] == owner and plan.get("change") and changes and n > min(changes):
                    roles[n] = ("effect", "owner reads the record after the change")
                elif role[n] == owner:
                    roles[n] = ("normal", "owner reads its record" if plan.get("owner") else "privileged account")
                elif args[n].get("path") not in owner_paths and n not in changes:
                    continue        # another resource: not the comparison the plan declares
                elif role[n] is None:
                    roles[n] = ("control", "without login")
                elif n in changes:
                    roles[n] = ("attack", "another account changes the owner's record")
                elif role[n] in normal:
                    roles[n] = ("attack", "another account reads the owner's record" if plan.get("owner")
                                else "normal account calls the privileged function")
    elif cls == "session":
        roles = {n: ("normal", "the session cookie as set") for n, _ in shown}
    elif cls in ("xss", "open-redirect", "path-traversal", "ssrf"):
        from ..agent.proof import redirect_host

        marker_file = (getattr(ctx, "scope", None) or {}).get("marker_file") or {}
        payload = {"xss": marker[0], "open-redirect": redirect_host(marker),
                   "path-traversal": str(marker_file.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1],
                   "ssrf": "".join(marker)}[cls]
        noun = "the XSS payload" if cls == "xss" else "the payload"
        if payload:
            for n, _ in shown:
                sent = unquote(json.dumps(args[n], ensure_ascii=False))
                roles[n] = ("attack", f"carries {noun}") if payload in sent else ("normal", f"without {noun}")
    return roles


def by_role(shown: list[tuple[int, dict]], roles: dict[int, tuple[str, str]]) -> list[tuple[int, dict]]:
    """The normal requests first, then controls, attacks and effects, each in the order sent; steps without a
    role last (VER-035)."""
    return sorted(shown, key=lambda s: (_ROLE_ORDER.get(roles.get(s[0], ("",))[0], len(_ROLE_ORDER)), s[0]))


def _closest(test: tuple[int, dict], refs: list[tuple[int, dict]], used: set[int], roles) -> tuple[int, dict]:
    """The normal request to show above `test`: the same request target first, then a normal request before a
    control, an unused one before one already shown, the earlier one first."""
    n, e = test
    method, path = e["request"]["method"], urlsplit(e["request"]["url"]).path

    def score(ref):
        m, r = ref
        same = (r["request"]["method"] == method) + 0
        target = 0 if urlsplit(r["request"]["url"]).path == path else 1
        return (target, -same, roles[m][0] != "normal", m in used, m)

    return min(refs, key=score)


def panels(shown: list[tuple[int, dict]], roles: dict[int, tuple[str, str]], limit: int = 3,
           opposite=None) -> list[list]:
    """The exchange images (VER-035): each attack, one per label, below the normal request it is compared with;
    then the other normal requests, controls and steps without a role. Two exchanges per image; without both
    kinds, in role order. With `opposite` (a boolean experiment, see `opposites`), per form the true condition
    below the false one its proof compares it with, then the true condition below the baseline."""
    refs = [s for s in by_role(shown, roles) if roles.get(s[0], ("",))[0] in ("normal", "control")]
    tests = [s for s in by_role(shown, roles) if roles.get(s[0], ("",))[0] in ("attack", "effect")]
    out = []
    for label in opposite or ():
        true = next((s for s in tests if roles[s[0]][1] == label), None)
        false = compared_with(*true, shown, roles, opposite) if true else None
        if false is not None and roles[false[0]][1] == opposite[label]:
            out.append([false, true])
    if out:
        if refs and len(out) < limit:
            out.append([_closest(out[0][1], refs, set(), roles), out[0][1]])
        return out
    if not refs or not tests:
        ordered = by_role(shown, roles)
        return [ordered[i:i + 2] for i in range(0, min(len(ordered), 2 * limit), 2)]
    out, used, labels = [], set(), set()
    for test in tests:
        if roles[test[0]] in labels or len(out) == limit:
            continue
        labels.add(roles[test[0]])
        ref = _closest(test, refs, used, roles)
        used.add(ref[0])
        out.append([ref, test])
    rest = [s for s in refs if s[0] not in used] + [s for s in by_role(shown, roles) if s[0] not in roles]
    out += [rest[i:i + 2] for i in range(0, len(rest), 2)][:limit - len(out)]
    return out


def compared_with(n: int, e: dict, shown: list[tuple[int, dict]], roles, opposite=None) -> tuple[int, dict] | None:
    """The step an attack or effect is compared with, or None: the opposite condition of a boolean experiment
    when `opposite` names one among `shown`, the nearest such step; else the normal request."""
    if roles.get(n, ("",))[0] not in ("attack", "effect"):
        return None
    other = (opposite or {}).get(roles[n][1])
    pair = [s for s in shown if other and roles.get(s[0], ("", ""))[1] == other]
    if pair:
        return min(pair, key=lambda s: (abs(s[0] - n), s[0]))
    refs = [s for s in shown if roles.get(s[0], ("",))[0] == "normal"]
    return _closest((n, e), refs, set(), roles) if refs else None


# A boolean experiment's proof compares its true condition with the false one of the same form (VER-011), so the
# image and the report compare the true condition with that, not with the baseline (VER-035).
_OPPOSITE = {"true condition": "false condition", "true condition, second form": "false condition, second form"}
_GROUP_OF = {label: group for group, (_, label) in _EXPERIMENT_ROLES.items()}
# Forms whose proof reads each step's own observation or computed value, not a split between true and false.
_OWN_OBSERVATION_FORMS = ("expression_template", "sql_marker", "auth_artifact", "error_probe", "error_set",
                          "name_template", "name_set")


def opposites(history: list[dict]) -> dict[str, str]:
    """The false condition each true condition is compared with, for a boolean experiment whose proof splits its
    true from its false condition; else none."""
    from ..agent.experiments import latest_plan

    plan = latest_plan(history)[1]
    split = plan.get("kind") == "boolean" and not any(plan.get(k) for k in _OWN_OBSERVATION_FORMS)
    return _OPPOSITE if split else {}


def _split_reason(ctx, history: list[dict], everything: list[tuple[int, dict]], roles) -> str | None:
    """Why the shown conditions are not the split a boolean proof counts, in the proof check's words (VER-011):
    None when they are, "" when the experiment has no complementary forms to compare."""
    from ..agent.experiments import boolean_classes, complementary, latest_plan

    plan = latest_plan(history)[1]
    values: dict[str, list] = {}
    for n, e in everything:
        group = _GROUP_OF.get(roles.get(n, ("", ""))[1])
        value = (plan["text"] in _text(e)) if plan.get("text") else observed(ctx, history, e)
        if value is _MISSING and plan.get("pointer") and _json(e) is not _MISSING:
            value = None        # a field the answer lacks, as the proof check reads it (agent/experiments.py)
        if group is None or value is _MISSING:
            continue
        values.setdefault(group, []).append(value)
    if not complementary(plan) or not {"positive", "negative", "positive_other", "negative_other"} <= values.keys():
        return ""
    reason = boolean_classes(plan, values)
    return reason.split(";")[0] if reason else None


def _json(e: dict):
    try:
        return json.loads(_text(e))
    except (ValueError, RecursionError):
        return _MISSING


def observed(ctx, history: list[dict], e: dict):
    """The value the injection experiment observes (its JSON pointer) in this redacted response, or _MISSING."""
    from ..agent.experiments import latest_plan

    _, plan = latest_plan(history)
    pointer = plan.get("pointer") if getattr(ctx.plan, "cls", None) == "injection" else None
    if not isinstance(pointer, str) or e["response"]["content"].get("_omitted"):
        return _MISSING
    value = _json(e)
    try:
        for part in pointer.split("/")[1:]:
            part = part.replace("~1", "/").replace("~0", "~")
            value = value[int(part)] if isinstance(value, list) else value[part]
    except (KeyError, IndexError, ValueError, TypeError):
        return _MISSING
    return value


def _brief(value) -> str:
    if isinstance(value, list):
        return f"{len(value)} entr{'y' if len(value) == 1 else 'ies'}"
    if isinstance(value, dict):
        return f"an object with {len(value)} field{'' if len(value) == 1 else 's'}"
    return json.dumps(value, ensure_ascii=False)[:60]


_ID_KEYS = ("id", "_id", "uuid", "key")
_NAME_KEYS = ("name", "title", "email", "username", "label", "description", "comment", "message")


def _row(item) -> str:
    """One entry of an observed list in a line: its identifier and name, else its first two plain fields."""
    if not isinstance(item, dict):
        return json.dumps(item, ensure_ascii=False)[:80]
    lower = {str(k).lower(): k for k in list(item)[:64]}
    keys = [next((lower[k] for k in group if k in lower), None) for group in (_ID_KEYS, _NAME_KEYS)]
    plain = [k for k in keys if k is not None and not isinstance(item[k], dict | list)]
    if not plain:
        plain = [k for k in list(item)[:32] if not isinstance(item[k], dict | list)][:2]
    return " · ".join(f"{k} {json.dumps(item[k], ensure_ascii=False)[:50]}" for k in plain) or "{…}"


_VIEW_ROWS = 8


def _value_view(pointer: str, value, normal=_MISSING, other="the normal request") -> tuple[str, list[tuple[str, str]]]:
    """The observed value as lines for the image, and the line to mark: a list as one row per entry, `+` before
    an entry the compared answer (`normal`, the answer of `other`) does not contain."""
    from ..agent.experiments import token

    differs = normal is not _MISSING and token(value) != token(normal)
    head = f"{pointer}: {_brief(value)}"          # its label says how the normal request's differs
    lines, new = [head], 0
    if isinstance(value, list):
        # Against an empty answer every entry is new, which the count's label already says.
        known = {token(v) for v in normal} if differs and isinstance(normal, list) and normal else None
        new = sum(token(v) not in known for v in value) if known is not None else 0
        for i, item in enumerate(value[:_VIEW_ROWS]):
            lines.append(f"{'+' if known is not None and token(item) not in known else ' '} [{i}] {_row(item)}")
        if len(value) > _VIEW_ROWS:
            lines.append(f"  … {len(value) - _VIEW_ROWS} more; full record in HAR")
    elif isinstance(value, dict):
        lines += [f"  {k}: {json.dumps(v, ensure_ascii=False)[:60]}" for k, v in list(value.items())[:_VIEW_ROWS]]
    marks = []
    if differs:      # the labels say why the line counts, not only that it is marked
        both = isinstance(value, list) and isinstance(normal, list)
        marks.append((f"{len(value)} entries instead of {len(normal)}" if both
                       else f"{_brief(value)} instead of {_brief(normal)}", head))
    if any(line.startswith("+") for line in lines):
        marks.append((f"{new} entr{'y' if new == 1 else 'ies'} {other} does not get", "+ ["))
    return "\n".join(lines), marks


_EXCERPT_KEYS = 12


def _short(value, limit: int = 50) -> str:
    """A JSON value in one short line: a string or number cut at `limit` characters, an object or list as {…} or […]."""
    if isinstance(value, dict):
        return "{}" if not value else "{…}"
    if isinstance(value, list):
        return "[]" if not value else "[…]"
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit - 2] + "…" + text[-1] * isinstance(value, str)


def _entry(item) -> str:
    """One entry of an observed list as shortened JSON: its identifier and name, else its first two plain fields."""
    if not isinstance(item, dict):
        return _short(item, 80)
    lower = {str(k).lower(): k for k in list(item)[:64]}
    keys = [k for k in (next((lower[k] for k in group if k in lower), None) for group in (_ID_KEYS, _NAME_KEYS))
            if k is not None and not isinstance(item[k], dict | list)]
    keys = keys or [k for k in list(item)[:32] if not isinstance(item[k], dict | list)][:2]
    fields = ", ".join(f"{json.dumps(str(k), ensure_ascii=False)}: {_short(item[k])}" for k in keys)
    return "{" + fields + (", …" if len(item) > len(keys) else "") + "}"


def _json_excerpt(e: dict, pointer, value, other=_MISSING) -> tuple[str, list[tuple[str, str]]] | None:
    """A JSON object answer for an image, shortened around the top-level field an injection experiment observes
    (VER-035): that field in full, a list there one entry per line, every other value cut short. Returns the text
    and the field to frame, with how it compares with `other`, the value in the step compared with; None where the
    answer is no object or the pointer names no top-level field of it."""
    from ..agent.experiments import token

    if not isinstance(pointer, str) or pointer.count("/") != 1 or e["response"]["content"].get("_omitted"):
        return None
    doc = _json(e)
    key = pointer[1:].replace("~1", "/").replace("~0", "~")
    if not isinstance(doc, dict) or key not in doc:
        return None
    lines, field = ["{"], ""
    keys = list(doc)[:_EXCERPT_KEYS]
    for i, k in enumerate(keys):
        comma = "," if i < len(keys) - 1 or len(doc) > len(keys) else ""
        name = json.dumps(str(k), ensure_ascii=False)
        if k != key:
            lines.append(f" {name}: {_short(doc[k])}{comma}")
            continue
        if isinstance(value, list) and value:
            rows = [f"  {_entry(item)}{',' if j < min(len(value), _VIEW_ROWS) - 1 else ''}"
                    for j, item in enumerate(value[:_VIEW_ROWS])]
            more = [f"  … {len(value) - _VIEW_ROWS} more; full record in HAR"] if len(value) > _VIEW_ROWS else []
            field = "\n".join([f"{name}: [", *rows, *more, " ]" + comma])
        else:
            field = f"{name}: {_short(value, 120)}{comma}"
        lines.append(" " + field)
    lines += [" …"] if len(doc) > len(keys) else []
    lines.append("}")
    if other is _MISSING or token(other) == token(value):
        return "\n".join(lines), []
    both = isinstance(value, list) and isinstance(other, list)
    return "\n".join(lines), [(f"{_brief(value)} instead of {len(other) if both else _brief(other)}", field)]


_OWNER_KEYS = {"userid", "user_id", "ownerid", "owner_id", "owner", "customerid", "accountid", "email", "username"}


def _same_owner_fields(e: dict, ref: tuple[int, dict]) -> list[tuple[str, str]]:
    """The ownership fields an attack's JSON answer shares with the normal request's, such as `/data/UserId: 1`
    another account received, as response lines to mark; at most two."""
    mine, theirs = _json(e), _json(ref[1])
    if not isinstance(mine, dict | list) or not isinstance(theirs, dict | list):
        return []
    x, y = _leaves(mine), _leaves(theirs)
    who, other = e.get("_role") or "a request without login", ref[1].get("_role") or "a request without login"
    return [(f"{who} gets the same {p.rsplit('/', 1)[-1]} as {other}", f"{p}: {json.dumps(v, ensure_ascii=False)}")
            for p, v in x.items() if p.rsplit("/", 1)[-1].lower() in _OWNER_KEYS and p in y and y[p] == v][:2]


def _leaves(value, path="", out=None):
    out = {} if out is None else out
    if len(out) >= 256:
        return out
    if isinstance(value, dict):
        for k, v in list(value.items())[:64]:
            _leaves(v, f"{path}/{k}", out)
    elif isinstance(value, list):
        for i, v in enumerate(value[:64]):
            _leaves(v, f"{path}/{i}", out)
    else:
        out[path or "/"] = value
    return out


def _same_in_code(ctx, a, b) -> bool | None:
    """Whether the answers of steps `a` and `b` were the same bytes, by the digest the Verifier keeps in memory for
    the finding (agent/tools.py, VER-057); None where either step has none."""
    responses = getattr(ctx, "responses", None)
    responses = responses if isinstance(responses, dict) else {}
    x, y = ((responses.get(n) or {}).get("digest") for n in (a, b))
    return None if not x or not y else x == y


def difference(ctx, history: list[dict], e: dict, ref: tuple[int, dict], ref_label: str | None = None,
               discount: str | None = None, *, step: int | None = None) -> str:
    """How an attack's answer compares with the normal request's, or with the condition `ref_label` names, in one
    sentence from the recorded answers; `discount` says why the proof does not count a difference in the value."""
    m, r = ref
    other = ref_label or "normal request"
    start = f"Compared with the {other} in step {m}: "
    a, b = e["response"]["status"], r["response"]["status"]
    status = f"status {a} instead of {b}" if a != b else f"same status {a}"
    mine, theirs = observed(ctx, history, e), observed(ctx, history, r)
    if mine is not _MISSING and theirs is not _MISSING:
        from ..agent.experiments import latest_plan, token

        pointer = latest_plan(history)[1].get("pointer")
        if token(mine) == token(theirs):
            return start + f"{status}, the same {pointer} ({_brief(mine)})."
        text = f"{status}; {pointer} has {_brief(theirs)} there and {_brief(mine)} here"
        if isinstance(mine, list) and isinstance(theirs, list):
            known = {token(v) for v in theirs}
            new = sum(token(v) not in known for v in mine)
            whose = "the normal answer" if ref_label is None else f"the {ref_label}'s answer"
            text += f", {new} of them not in {whose}" if new else ""
        return start + text + (f"; the proof does not count this difference: {discount}." if discount else ".")
    response = getattr(ctx, "responses", {}).get(e.get("_step") if step is None else step, {})
    if response.get("access_observation"):
        selected = response["access_observation"]
        return start + f"{status}; declared observation {selected['pointer'] or 'text marker'}: " + (
            "matched." if selected["matched"] else "not matched.")
    ce, cr = e["response"]["content"], r["response"]["content"]
    in_code = _same_in_code(ctx, e.get("_step") if step is None else step, m)
    if ce.get("_omitted") or cr.get("_omitted"):      # no text to compare: by the digest or a binary body's hash
        same = in_code if in_code is not None else (ce.get("_sha256") == cr.get("_sha256")
                                                    if ce.get("_sha256") and cr.get("_sha256") else None)
        if same is None:
            return start + f"{status}, the answers are not recorded to compare."
        same = "the identical" if same else "a different"
        return start + f"{status}, {same} answer, compared in code over the whole body, which is not kept."
    if _text(e) == _text(r):
        if in_code:
            return start + f"{status}, the identical answer, compared in code over the whole body."
        cut = ce.get("_truncated") or cr.get("_truncated")
        return start + f"{status}, the identical answer" + (" as far as recorded." if cut else ".")
    mine, theirs = _json(e), _json(r)
    if isinstance(mine, dict | list) and isinstance(theirs, dict | list):
        x, y = _leaves(mine), _leaves(theirs)
        changed = [p for p in dict.fromkeys([*y, *x]) if x.get(p, _MISSING) != y.get(p, _MISSING)]
        if not changed:
            return start + f"{status}, the same JSON content."
        examples = "; ".join(f"{p}: {_brief(y[p]) if p in y else 'absent'} → {_brief(x[p]) if p in x else 'absent'}"
                             for p in changed[:2])
        return start + f"{status}; {len(changed)} of {len(set(x) | set(y))} JSON values differ, e.g. {examples}."
    return start + f"{status}; the answer differs ({len(_text(r))} → {len(_text(e))} characters)."


def _marked(text: str, needles=(), lines=(), *, sent: bool = False) -> tuple[str, int]:
    """`text` as escaped HTML with what `needles` and `lines` name in <mark>, each a (label, what) pair: a
    string at each occurrence, a (region, context, token) from `_diff_token` once in the request line or the
    body, and in `lines` a prefix that marks each line starting with it. A red tag before the first mark of
    each label says what is marked; tag and mark wrap to the next line together, not inside a word. `sent` marks
    what a request carried, in a colour of its own, so it is not read as the proof in a response. Nothing of
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
    pos, previous = 0, None
    for line in text.split("\n"):
        label = next((label for label, prefix in lines if line.lower().startswith(prefix.lower())), None)
        if label is not None and previous is not None and spans[previous][2] == label \
                and spans[previous][1] == pos - 1:
            spans[previous] = (spans[previous][0], pos + len(line), label)    # consecutive lines: one framed block
        elif label is not None:
            previous = len(spans)
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
        words, block = html.escape(" · ".join(new)), "\n" in text[a:b]
        marked = f"<mark>{html.escape(text[a:b])}</mark>"
        if sent:          # what a request carried: highlighted after its label
            tag = f"<span class=tag>{words} ▸</span>" if new else ""
            hit = f'<span class="hit sent">{tag}{marked}</span>'
        elif block:       # an answer's lines: one red frame, the note above it
            note = f"<span class=note>▼ {words}</span>" if new else ""
            hit = f'<span class="hit block">{note}{marked}</span>'
        else:             # an answer's value: a red frame, the note beside it
            note = f"<span class=note>◀ {words}</span>" if new else ""
            hit = f"<span class=hit>{marked}{note}</span>"
        before = text[last:a]
        cut = len(before.rstrip(" ")) - 1
        if block and not sent and before[cut:cut + 1] == "\n":    # a block starts its own line; the report's
            out += [html.escape(before[:cut]), f"<span class=nl>{html.escape(before[cut:])}</span>", hit]
        else:                                                      # excerpt keeps the break and the indent
            out += [html.escape(before), hit]
        last = b
        if block and text[b:b + 1] == "\n":     # a block ends its own line; the report's excerpt keeps the break
            out.append("<span class=nl>\n</span>")
            last = b + 1
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
        elif tag == "span" and (("class", "tag") in attrs or ("class", "note") in attrs):
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


def _report_excerpts(ctx, history, n, entry, shown, highlight, har_path, roles=None):
    req, res, lines, facts = _exchange_marks(ctx, history, n, entry, shown, highlight)
    response = _raw_response(entry, _focus(ctx, [e for _, e in shown], entry), har_path)
    headers, _, body = response.partition("\n\n")
    kept = [line for i, line in enumerate(headers.splitlines())
            if i == 0 or line.lower().startswith(("content-type:", "location:", "www-authenticate:", "set-cookie:"))]
    response = "\n".join(kept) + "\n\n" + _report_body(ctx, entry, body, res)
    opposite = opposites(history)
    ref = compared_with(n, entry, shown, roles or {}, opposite)
    ref_label = roles[ref[0]][1] if ref and roles.get(ref[0], ("",))[0] == "attack" else None
    reason = _split_reason(ctx, history, shown, roles) if ref_label and opposite else None
    role = {"role": roles[n][0], "role_label": roles[n][1]} if roles and n in roles else {}
    decoded = getattr(ctx.plan, "cls", None) == "xss"
    return {**role, "request_excerpt": _code_excerpt(_image_request(entry, req, decoded=decoded), req),
            "response_excerpt": _code_excerpt(response, res, lines),
            "facts": [fact for fact, decisive in facts if decisive]
            + ([difference(ctx, history, entry, ref, ref_label, reason, step=n)] if ref else [])}


def _exchange_marks(ctx, history: list[dict], n: int, e: dict, shown: list[tuple[int, dict]], highlight,
                    beside=None) -> tuple[list[tuple], list[tuple], list[tuple[str, str]], list[tuple[str, bool]]]:
    """What the image of step `n` marks, as the code can locate it, each with its label: needles in the
    request, needles and line prefixes in the response, and facts about the step with whether they decide.
    An injection's input is found against every step in `shown`; how its answer differs only against the steps
    `beside` it in the same image (default `shown`), since a mark claims what the image shows (VER-035)."""
    from ..agent.proof import redirect_host

    cls, marker = getattr(ctx.plan, "cls", None), getattr(ctx, "marker", None) or ("", "")
    step = history[n - 1] if n <= len(history) else {}
    res = step.get("result") or {}
    seen = _proof_observation(ctx, history, n, e)
    req_marks, res_marks, res_lines = [], [], []
    facts: list[tuple[str, bool]] = []
    times = [o.get("time") or 0 for _, o in shown]
    timing = cls == "injection" and max(times) - min(times) >= 2000        # a timing proof rests on the times
    if e.get("time"):
        facts.append((f"answered in {e['time']} ms", timing))
    if cls == "access-control" and e.get("_role"):      # elsewhere the step heading names the identity
        req_marks.append(("identity", f"[identity {e['_role']}]"))
    if cls == "xss" and marker[0]:
        payload = _xss_payload(e, marker[0])
        req_marks.append(("XSS payload", payload))
        res_marks.append(("XSS payload in the answer", payload) if payload in _text(e)
                         else ("XSS marker in the answer, not the full payload", marker[0]))
        if step.get("tool") == "browser_check":     # a fragment (#/search?q=…) never reaches the server
            facts.append((f"opened in the browser: {unquote(str((step.get('args') or {}).get('path', '')))[:300]}",
                          True))
    elif cls == "open-redirect":
        host = redirect_host(marker)
        if host:
            req_marks.append(("redirect target", host))
        location = next((h["value"] for h in e["response"]["headers"] if h["name"].lower() == "location"), "")
        res_lines.append(("redirect to the test host" if host and host in location else "redirect", "location:"))
    elif cls == "path-traversal":
        marker_file = (getattr(ctx, "scope", None) or {}).get("marker_file") or {}
        name = str(marker_file.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1]
        req_marks += [("marker file", name)] if name else []
        res_marks += [("marker file content", marker_file["content"])] if marker_file.get("content") else []
    elif cls == "ssrf":
        joined = res.get("callback_attempt") or "".join(marker)
        req_marks += [("callback marker", joined)] if joined else []
    elif cls == "injection":
        path = e["request"]["url"].split("?")[0]
        status_differs = False
        for _, o in shown:
            if o is e or o["request"]["url"].split("?")[0] != path:
                continue
            a_url, b_url = _target(e["request"]["url"]), _target(o["request"]["url"])
            a_body = (e["request"].get("postData") or {}).get("text") or ""
            b_body = (o["request"].get("postData") or {}).get("text") or ""
            token = (_diff_token(a_url, b_url, "line") if a_url != b_url
                     else _diff_token(a_body, b_body, "body"))
            # The sink value this step carries is the same whatever partner it is diffed against, so the input
            # mark and its decoding belong to the step once, not once per partner (VER-035).
            if token and ("input", token) not in req_marks:
                req_marks.append(("input", token))
                decoded = (unquote_plus if token[0] == "line" else unquote)(token[2])   # a query's + is a space
                if decoded != token[2]:
                    facts.append((f"input, decoded: {decoded}", True))
            if seen is not None:
                continue        # the proof reads the step's own observation, not how the answers differ
            if beside is not None and not any(o is b for _, b in beside):
                continue        # a difference from a step in another image is not marked in this one
            token = _answer_difference(_text(e), _text(o))
            if token and ("answer differs", token) not in res_marks:
                res_marks.append(("answer differs", token))
            status_differs = status_differs or e["response"]["status"] != o["response"]["status"]
        if status_differs:
            res_lines.append(("status differs", "HTTP/1.1 "))
    elif cls == "access-control":
        own_marker = "".join(marker)
        if own_marker and own_marker in _text(e):
            res_marks.append(("test marker", own_marker))
        res_marks += [("named in the verdict", value) for value in _values(highlight, _text(e))]
    elif cls == "session":
        res_lines += _session_cookie_line(ctx, history, res)
    if seen is not None:
        key, yes, frame = seen
        facts.append((f"{_OBSERVATIONS[key][1]}: {'yes' if yes else 'no'}", True))
        res_marks += [(_OBSERVATIONS[key][1], frame)] if frame else []
    return req_marks, res_marks, res_lines, facts


# What a proof check reads from a step itself, recorded by the code, never taken from the model (VER-009, VER-012,
# VER-013, VER-048, VER-049, VER-053): the classes whose proof reads it, the fact the image states, and the Result
# line's words for yes and no. Such a step is shown by this observation, not by its status or answer difference.
_OBSERVATIONS = {
    "executed": (("xss",), "XSS payload ran in the browser", "marker executed", "marker not executed"),
    "marker_read": (("path-traversal",), "marker file read", "marker file read", "marker file not read"),
    "callback_hit": (("ssrf", "injection"), "callback listener received the marker", "callback received",
                     "no callback"),
    "auth_access": (("injection",), "declared protected resource accessed", "protected resource accessed",
                    "protected resource not accessed"),
    "auth_artifact": (("injection",), "authenticated artifact in the answer", "authenticated artifact",
                      "no authenticated artifact"),
    "engine_error": (("injection",), "engine error", "engine error", "no engine error"),
    # VER-066: a server error, or a refusal naming the error for the fresh name (experiments.name_failed)
    "name_error": (("injection",), "evaluation error", "evaluation failed", "evaluated without error"),
    "marker_returned": (("injection",), "its generated marker returned", "its marker returned",
                        "its marker absent"),
    "text_present": (("injection",), "the selected text in the answer", "text present", "text absent"),
    "result_returned": (("injection",), "its computed result in the answer", "its result returned",
                        "its result absent"),
}


def _proof_observation(ctx, history: list[dict], n: int, e: dict) -> tuple[str, bool, tuple | None] | None:
    """The observation the proof check reads from step `n` itself, as (key in _OBSERVATIONS, yes or no, where
    the answer shows it or None), or None where the proof compares answers instead. The returned-marker form
    (VER-053) reads the step's own generated marker from its recorded answer, the others what the code recorded
    in the step's result; the engine error and the marker are located for a frame."""
    from ..agent.experiments import latest_plan, name_failed, token

    cls = getattr(ctx.plan, "cls", None)
    step = history[n - 1] if 1 <= n <= len(history) else {}
    res = step.get("result") or {}
    key = next((k for k, row in _OBSERVATIONS.items() if k in res and cls in row[0]), None)
    if key is not None:
        yes = (res[key].get("matched") is True if key == "auth_access" else name_failed(res) if key == "name_error"
               else res[key] is True)
        return key, yes, _engine_error(e) if key == "engine_error" and yes else None
    _, plan = latest_plan(history)
    if cls == "injection" and plan.get("kind") == "boolean" and not plan.get("pointer"):
        # VER-055: a page or text answer, observed through the selected text or the step's own computed result.
        if plan.get("expression_template"):
            sent = _sink(plan, step.get("args") or {})
            own = next((value for group, value in (plan.get("expected_values") or {}).items()
                        if sent is not _MISSING and group in plan and token(sent) == token(plan[group])), None)
            if own is None:
                return None
            body = _text(e)
            found = re.search(rf"(?<!\d){re.escape(str(own))}(?!\d)", body)     # as the proof check reads it
            if found is None:
                return "result_returned", False, None
            before = body[found.start() - 1] if found.start() else ""
            # The character before the whole number locates it, so a longer number holding its digits is not framed.
            return "result_returned", True, ("body", before if before not in "<>" else "", str(own))
        if isinstance(plan.get("text"), str) and plan["text"]:
            yes = plan["text"] in _text(e)
            return "text_present", yes, ("body", "", plan["text"]) if yes else None
    if cls != "injection" or not plan.get("sql_marker"):
        return None
    sent = _sink(plan, step.get("args") or {})
    group = next((g for g in ("positive", "negative")
                  if sent is not _MISSING and g in plan and token(sent) == token(plan[g])), None)
    own = (plan.get("markers") or {}).get(group) if group else None
    if not isinstance(own, str) or not own:
        return None
    yes = own in _text(e)
    return "marker_returned", yes, ("body", "", own) if yes else None


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


def _engine_error(e: dict) -> tuple[str, str, str] | None:
    """VER-053: the engine error in an answer as the image and the report show it, an HTML page by its visible
    text: the first match and those right after it, e.g. `SQLITE_ERROR: near "'%'": syntax error`, marked once."""
    from ..agent.experiments import _ENGINE_ERROR

    text = _text(e)
    if "html" in e["response"]["content"].get("mimeType", "").lower():
        parser = _VisibleText()
        parser.feed(text[:MAX_BODY_CHARS])
        text = " ".join(parser.parts)
    found = _ENGINE_ERROR.finditer(text)
    first = next(found, None)
    if first is None:
        return None
    end = first.end()
    for match in found:
        if match.start() > end + 3:
            break
        end = match.end()
    return "body", "", text[first.start():end][:200]


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
    focus = next((i for _, v in needles if (i := _located(text, v)) >= 0), 0)
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


def _xss_payload(e: dict, part: str) -> str:
    """The XSS payload as a reader finds it in the URL-decoded request: the query or form value that carries the
    marker part, else the part itself (a payload in the path or a JSON body, or in a fragment the server never
    receives)."""
    req = e["request"]
    pairs = parse_qsl(urlsplit(req["url"]).query, keep_blank_values=True)
    post = req.get("postData") or {}
    if "x-www-form-urlencoded" in str(post.get("mimeType", "")).lower():
        pairs += parse_qsl(post.get("text") or "", keep_blank_values=True)
    return next((value for _, value in pairs if part in value), part)


def _image_request(e, marks, *, decoded: bool = False):
    """A request for an image or the report; `decoded` shows its line and a form body URL-decoded, as an XSS
    payload is read (presentation.request_text)."""
    from .presentation import request_text

    req = e["request"]
    if decoded:
        line, _, body = request_text(e).partition("\n\n")
    else:
        line, body = f"{req['method']} {_target(req['url'])} HTTP/1.1", (req.get("postData") or {}).get("text") or ""
    lines = [line] + [f"{h['name']}: {h['value']}" for h in req["headers"]
                      if h["name"].lower() in ("authorization", "content-type")]
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


_SOURCE_SPAN = 150      # characters of HTML source an XSS image keeps on each side of the reflected payload


def _xss_source(text: str, marks) -> str | None:
    """The HTML source around the first reflected XSS payload or marker that `marks` locates in `text` (VER-034):
    its line, cut to _SOURCE_SPAN characters on each side, and the nearest non-blank line before and after it,
    indentation removed; None if the answer does not contain it."""
    needle = next((v for _, v in marks if isinstance(v, str) and v and v in text), None)
    if needle is None:
        return None
    i = text.index(needle)
    j = i + len(needle)
    lo, hi = text.rfind("\n", 0, i) + 1, text.find("\n", j)
    hi = len(text) if hi < 0 else hi
    a, b = max(lo, i - _SOURCE_SPAN), min(hi, j + _SOURCE_SPAN)
    line = ("…" + text[a:i] if a > lo else text[lo:i].lstrip()) + needle + (
        text[j:b] + "…" if b < hi else text[j:hi].rstrip())

    def cut(s: str) -> str:
        s = s.strip()
        return s if len(s) <= _SOURCE_SPAN else s[:_SOURCE_SPAN] + "…"

    before, after = text[:lo].rstrip(), text[hi:].lstrip()
    k, m = before.rfind("\n"), after.find("\n")
    shown = ([cut(before[k + 1:])] if before else []) + [line] + ([cut(after[:m if m >= 0 else None])] if after else [])
    more_before, more_after = bool(before[:max(k, 0)].strip()), m >= 0 and bool(after[m:].strip())
    return ("HTML source around the XSS payload, indentation removed:\n" + ("[…]\n" if more_before else "")
            + "\n".join(shown) + ("\n[…] excerpt; full record in HAR" if more_after else ""))


def _image_response(ctx, e, marks, marked_lines, view: str | None = None):
    res = e["response"]
    lines = [f"HTTP/1.1 {res['status']} {res['statusText']}".rstrip()]
    keep = {"content-length", "location", "www-authenticate", "set-cookie"}
    lines += [f"{h['name']}: {h['value']}" for h in res["headers"]
              if h["name"].lower() in keep or any(h["name"].lower() + ":" == prefix.lower()
                                                for _, prefix in marked_lines)]
    if view is not None:      # the experiment's observed value, already bounded
        return _image_excerpt("\n".join(lines), limit=450) + "\n\n" + view
    text = _text(e)
    mime = res["content"].get("mimeType", "").lower()
    if "html" in mime:
        if getattr(ctx.plan, "cls", None) == "xss":
            source = None if res["content"].get("_omitted") else _xss_source(text, marks)
            if source is not None:
                return _image_excerpt("\n".join(lines), limit=450) + "\n\n" + source
            text = ("HTML omitted: the XSS payload does not appear unchanged in this answer. The browser observation "
                    "above decides whether it ran; the full answer is in the HAR.")
        else:
            parser = _VisibleText()
            parser.feed(text[:MAX_BODY_CHARS])
            visible = " ".join(parser.parts)
            needles = [v[2] if isinstance(v, tuple) else v for _, v in marks]
            # A mark located in HTML can disappear when tags/entities are stripped. Keep the recorded
            # source as escaped text in that case, so both the excerpt and its mark use the same text.
            text = ("HTML excerpt: " + text if any(v and v in text and v not in visible for v in needles)
                    else "Visible text excerpt: " + visible)
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


_EXCHANGE_CSS = """body{margin:0;background:#fff;color:#111;font:16px/1.45 system-ui,Helvetica,Arial,sans-serif}
pre,code{font-family:ui-monospace,Menlo,Consolas,monospace}
header{background:#111;color:#fff;padding:10px 14px;border-bottom:4px solid #b00020;white-space:pre-wrap}
header b{font-size:20px}header .k{color:#ffeb3b;font-weight:bold}header small{color:#bbb;font-size:13px}
header.head{white-space:normal;padding:12px 16px 14px}header.head .id{font-size:14px;color:#bbb}
header.head .lead{font-size:21px;font-weight:bold;line-height:1.3;margin-top:4px}
header.head p{margin:6px 0 0}header.head small{display:block;margin-top:6px}
.verdict{background:#555;color:#fff;font:bold 15px sans-serif;padding:1px 8px;border-radius:4px;margin-right:10px;
text-transform:uppercase;vertical-align:2px}.verdict.confirmed,.verdict.shown-without-exploit{background:#b00020}
.verdict.inconclusive{background:#b26a00}
.what{margin:10px 14px 0;font-size:15px}
.pair{display:flex;gap:14px;margin:10px 14px 0}.pair section{flex:1;min-width:0;margin:0}
.pair h3{padding-top:6px}pre.req{border-bottom:1px solid #ddd}.dec{color:#555}
.why{margin:12px 14px 0;padding:8px 12px;background:#111;color:#fff;border-radius:4px;font-size:15px}
.why b{color:#ffeb3b;margin-right:6px}.why p{margin:0}.why p+p{margin-top:4px}
.why .closing{color:#ccc;font-size:13px}
footer{margin:8px 14px 12px;color:#777;font-size:12px}
.hit.block{display:block}.block mark{display:block;background:none;outline:none;border:2px solid #b00020}
.sent mark{background:#ffeb3b;outline:2px solid #b00020;outline-offset:0}
.note{color:#b00020;font:bold 14px sans-serif;margin-left:8px}.block .note{display:block;margin:0 0 3px}
.nl{display:none}
section{margin:14px;border:1px solid #ccc}
h2{margin:0;padding:6px 10px;background:#f0f0f0;font-size:15px;border-bottom:1px solid #ccc}
.facts{padding:4px 10px;border-bottom:1px solid #ccc}.cols{display:flex}.cols>div{flex:1;min-width:0}
.cols>div+div{border-left:1px solid #ccc}h3{margin:0;padding:4px 10px 0;font-size:13px;color:#666;font-weight:normal}
pre{margin:0;padding:4px 10px 8px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:14px}
mark{background:none;color:#000;outline:2px solid #b00020;outline-offset:1px}.hit{display:inline-block;max-width:100%}
.hit:not(.block)>mark{display:inline-block}
.tag{background:#b00020;color:#fff;font:bold 13px sans-serif;padding:1px 5px;margin-right:3px;border-radius:3px}
section.normal{border:2px solid #2e7d32}section.control{border:2px solid #546e7a}
section.attack{border:2px solid #b00020}section.effect{border:2px solid #e65100}
.normal h2{background:#e8f5e9}.control h2{background:#eceff1}.attack h2{background:#fdecea}
.effect h2{background:#fff3e0}
.role{color:#fff;font:bold 14px sans-serif;text-transform:uppercase;padding:2px 8px;margin-right:8px;border-radius:3px}
.normal .role{background:#2e7d32}.control .role{background:#546e7a}.attack .role{background:#b00020}
.effect .role{background:#e65100}
.diff{padding:6px 10px;border-bottom:1px solid #ccc;background:#fff8e1;font-weight:bold}"""


_VERDICT_SENTENCE = {
    "confirmed": "The proof check accepted it.",
    "shown-without-exploit": "The proof check accepted it as shown without an exploit; no exploit ran.",
    "inconclusive": "This does not complete the required proof.",
    "blocked-by-control": "The operation was refused, with matched control evidence.",
    "not-reproducible": "Not reproduced in these attempts, which does not prove absence.",
}


def _step_observation(ctx, history: list[dict], n: int, e: dict, everything: list[tuple[int, dict]], roles,
                      timing: bool) -> str:
    """What step `n` showed, as the proof reads it: its own observation, else its observed value, its answer time
    for a timing experiment, its status, or how its answer compares with its reference."""
    value, ref = observed(ctx, history, e), compared_with(n, e, everything, roles, opposites(history))
    if proof := _proof_observation(ctx, history, n, e):     # what the proof reads, not the status or value
        return _OBSERVATIONS[proof[0]][2 if proof[1] else 3]
    if value is not _MISSING:
        return _brief(value)
    if timing and isinstance(e.get("time"), int):
        return f"{e['time']} ms"
    if ref is None:
        return str(e["response"]["status"])
    same = _same_in_code(ctx, n, ref[0])
    if same is None and not (e["response"]["content"].get("_omitted")
                             or ref[1]["response"]["content"].get("_omitted")):
        same = _text(e) == _text(ref[1])
    return f"{e['response']['status']}, " + ("an answer not recorded to compare" if same is None
                                             else f"{'the same' if same else 'a different'} answer")


def observation_groups(ctx, history: list[dict], everything: list[tuple[int, dict]], roles
                       ) -> list[tuple[str, list[int], list[str]]]:
    """The steps per kind of step, as (name, step numbers, what they showed), in role order."""
    from ..agent.experiments import latest_plan

    timing = latest_plan(history)[1].get("kind") == "timing"
    cls = getattr(ctx.plan, "cls", None)
    groups: dict[str, tuple[list[int], list[str]]] = {}
    for n, e in by_role(everything, roles):
        kind, label = roles.get(n, ("", ""))
        if roles and not kind:        # outside the comparison the plan declares
            continue
        who = e.get("_role")
        name = (label.replace(", second form", "") + (f" {who}" if who and cls == "access-control" else "")
                if kind else f"step {n} as {who or 'anonymous'}")
        seen = _step_observation(ctx, history, n, e, everything, roles, timing)
        steps, values = groups.setdefault(name, ([], []))
        steps.append(n)
        if seen not in values:
            values.append(seen)
    return [(name, steps, values) for name, (steps, values) in groups.items()]


def weakness(ctx) -> str:
    """The finding's weakness by a short name, for the sentence that heads its images and report entry (VER-035)."""
    from .probes import CLASS_NAMES, WEAKNESS_NAMES

    return (WEAKNESS_NAMES.get(str(getattr(ctx.plan, "cwe", "") or ""))
            or CLASS_NAMES.get(str(getattr(ctx.plan, "cls", "") or "")) or "The finding")


def _input_name(ctx, history: list[dict]) -> str | None:
    """The input an injection experiment tests, as its accepted plan names it; None for other classes."""
    from ..agent.experiments import latest_plan

    if getattr(ctx.plan, "cls", None) != "injection":
        return None
    name = latest_plan(history)[1].get("input_name")
    return str(name)[:60] if isinstance(name, str) and name else None


def headline(ctx, history: list[dict], form: str | None) -> str:
    """A confirmed finding's sentence (VER-035): the weakness, the input it was tested through, and because what the
    checked proof form showed, e.g. `NoSQL injection through id, because a condition added to id changes what the
    database query returns.`"""
    from .probes import BECAUSE, QUERY_NOUNS

    name = _input_name(ctx, history)
    query = QUERY_NOUNS.get(str(getattr(ctx.plan, "cwe", "") or ""), "the server")
    because = BECAUSE.get(form or "", "").format(input=name or "the input", query=query)
    return f"{weakness(ctx)}{' through ' + name if name else ''}" + (f", because {because}." if because else ".")


def verdict_sentence(ctx, verdict: str, result=None) -> str:
    """The sentence that heads an image without a `why_summary` (VER-035): for a finding the proof does not confirm,
    the weakness and the reason the report gives (VER-024), else what the verdict means."""
    if verdict == "confirmed":
        return f"{weakness(ctx)}. {_VERDICT_SENTENCE['confirmed']}"
    if verdict == "shown-without-exploit":       # VER-066
        return f"{weakness(ctx)} shown without an exploit. {_VERDICT_SENTENCE[verdict]}"
    reason = None
    if result is not None and verdict == "inconclusive":
        from .report import why_not_confirmed

        reason = why_not_confirmed({"verdict": verdict, "limits_hit": getattr(result, "limits_hit", None),
                                    "rationale": getattr(result, "rationale", None),
                                    "observations": getattr(result, "observations", None) or [],
                                    "proof": getattr(result, "proof", None) or {},
                                    "class": getattr(ctx.plan, "cls", None)})
    return f"{weakness(ctx)} not confirmed. " + (reason or _VERDICT_SENTENCE.get(verdict, "No completed proof."))


def head_html(ctx, verdict: str, sentence: str, more: str = "") -> str:
    """An image's head (VER-035): the finding, then its verdict and the sentence that says why, then `more` (HTML the
    caller escaped). Every recorded value is escaped."""
    from ..planning import _TITLE_LOCATION
    from .report import _VERDICT_LABEL

    title = _TITLE_LOCATION.sub("", str(getattr(ctx.plan, "title", "") or "")[:300])[:90]
    label = _VERDICT_LABEL.get(verdict, verdict)
    return (f"<header class=head><div class=id>{html.escape(' · '.join(filter(None, (str(ctx.plan.id), title))))}"
            f"</div><div class=lead><span class='verdict {html.escape(verdict)}'>{html.escape(label)}</span>"
            f"{html.escape(sentence)}</div>{more}</header>")


def why_html(why: dict | None) -> str:
    """The checks and conclusion of `why_summary` as one block below an image's steps, escaped; the sentence that
    heads the image is its `lead`."""
    if not why:
        return ""
    checks = "".join(f"<p><b>{'' if c['ok'] else '✗ '}{html.escape(c['name'])}</b> {html.escape(c['text'])}</p>"
                     for c in why["checks"])
    closing = f"<p class=closing>{html.escape(why['closing'])}</p>" if why.get("closing") else ""
    return f"<div class=why>{checks}{closing}</div>"


# Proof forms whose controls carry values the Verifier generated at random for the finding (VER-011 to VER-013).
_RANDOM_CONTROLS = ("predicate", "returned-marker", "computed-expression", "out-of-band", "auth-artifact",
                    "auth-resource")
CHECKED_IN_CODE = ("The Verifier checked this in code against the recorded steps; a model's verdict alone never "
                   "confirms.")


def why_summary(ctx, history: list[dict], shown: list[tuple[int, dict]], result) -> dict | None:
    """Why a result has its verdict, for its images and the report (VER-034, VER-035): `lead`, the sentence that
    names the weakness and says because what; `checks`, the rule that makes it a proof and every step the proof
    rests on with what it showed; `closing`, that the code checked it. An access-control comparison names its
    controls and the access rule (VER-010). None where the proof check confirmed nothing."""
    from .probes import PROOF_FORMS, PROOF_RULES, proof_shown

    cls, proof = getattr(ctx.plan, "cls", None), result.proof or {}
    rows = comparison_rows(ctx, history, shown) if cls == "access-control" else None
    if rows is not None:
        summary = comparison_summary(ctx, history, rows, result)
        return {k: summary[k] for k in ("lead", "checks", "closing")} if summary["checks"] else None
    said = proof_shown(proof, cls)
    if result.verdict not in ("confirmed", "shown-without-exploit") or proof.get("checked") is not True or said is None:
        return None
    form = next(k for k, v in PROOF_FORMS.items() if v is said)
    roles = step_roles(ctx, history, shown)
    groups = observation_groups(ctx, history, shown, roles)[:6]
    steps = "; ".join(f"{name}, step{'s' if len(numbers) > 1 else ''} {', '.join(map(str, numbers))}: "
                      f"{', '.join(seen[:3])}" for name, numbers, seen in groups)
    checks = [{"ok": True, "name": "Why this proves it", "text": PROOF_RULES[form]}]
    if sum(len(numbers) for _, numbers, _ in groups) > 1:       # one step: its image and excerpt say it all
        checks.append({"ok": True, "name": "All steps", "text": steps + "." + (
            " The Verifier generated the values at random." if form in _RANDOM_CONTROLS else "")})
    return {"lead": headline(ctx, history, form), "checks": checks, "closing": CHECKED_IN_CODE}


def exchange_document(ctx, history: list[dict], shown: list[tuple[int, dict]], verdict: str, har_path,
                      highlight=None, *, cited: bool = True, comparison=None, composed: str | None = None,
                      why: dict | None = None, result=None) -> tuple[str, int]:
    """The decisive exchanges of a finding as one HTML page for its screenshot (VER-035): a head with the verdict and
    the sentence that says why (`why`, else `verdict_sentence`), the steps as recorded, two side by side as the proof
    compares them with the attack first, one with its request beside its response, what the verdict rests on marked,
    then why that is a proof, or what the steps showed. Without `cited` they are the answered requests after the
    last test plan of a verdict that cites no step, and the page says so; `composed` says why the test agent's
    presentation is not used (VER-059). Returns the page and the number of marks. Every recorded value is escaped;
    the page has no script."""
    from ..agent.experiments import latest_plan

    cls = getattr(ctx.plan, "cls", None) or "finding"
    captured = shown[0][1].get("startedDateTime", "") if shown else ""
    everything = comparison or shown
    roles = step_roles(ctx, history, everything)
    shown = by_role(shown, roles)[:6]
    opposite = opposites(history)
    # Compared with the step of its kind in the same image, else the closest one of the finding. A step another one
    # in this image is compared with is that one's reference: it stands after it and is compared with nothing.
    refs = {n: compared_with(n, e, shown, roles, opposite) or compared_with(n, e, everything, roles, opposite)
            for n, e in shown}
    referenced = {ref[0] for ref in refs.values() if ref and any(ref[0] == m for m, _ in shown)}
    # The attack first, then what it is compared with: its reference, a normal request, a control.
    shown.sort(key=lambda s: (roles.get(s[0], ("",))[0] not in ("attack", "effect"), s[0] in referenced))
    pair = len(shown) == 2
    pointer = latest_plan(history)[1].get("pointer")
    name = _input_name(ctx, history)
    # VER-011: a boolean experiment's value is framed only where its proof counts the split, never against the
    # baseline; the line under the true condition says why a difference from the false one does not count.
    reason = _split_reason(ctx, history, everything, roles) if opposite else ""
    counts = verdict == "confirmed" and reason is None
    sentence = (why or {}).get("lead") or verdict_sentence(ctx, verdict, result)
    described = "; ".join(f"step {n}{', ' + roles[n][1] if roles.get(n, ('', ''))[1] else ''}" for n, _ in shown)
    intro = (f"{'The proof' if cited and verdict == 'confirmed' else 'The steps'} as recorded: {described}. "
             if cited else f"The last answered requests, which the verdict does not cite: {described}. ")
    parts = [head_html(ctx, verdict, sentence),
             f"<p class=what>{html.escape(intro)}Yellow marks what a request sent, a red frame what the proof reads "
             "in an answer.</p>"]
    sections, total = [], 0
    for i, (n, e) in enumerate(shown):
        kind, label = roles.get(n, ("", ""))
        req_marks, res_marks, res_lines, facts = _exchange_marks(ctx, history, n, e, everything, highlight, shown)
        facts = [(t, d) for t, d in facts if d or not t.startswith("answered in")]   # a time only where it decides
        decoded = [t.removeprefix("input, decoded: ") for t, _ in facts if t.startswith("input, decoded: ")]
        facts = [(t, d) for t, d in facts if not t.startswith("input, decoded: ")]
        ref = None if n in referenced else refs[n]
        ref_label = roles[ref[0]][1] if ref and roles.get(ref[0], ("",))[0] == "attack" else None
        partner = shown[1 - i] if pair else ref
        view, value = None, observed(ctx, history, e)
        if value is not _MISSING:
            both = kind == "attack" and partner is not None and roles.get(partner[0], ("",))[0] == "attack"
            framed = partner is not None and (not opposite or (both and counts))
            other = observed(ctx, history, partner[1]) if framed else _MISSING
            excerpt = _json_excerpt(e, pointer, value, other)
            if excerpt is not None:
                view, needles = excerpt
                res_marks = [m for m in res_marks if m[0] != "answer differs"] + needles
            else:
                partner_label = roles.get(partner[0], ("", ""))[1] if partner else ""
                view, view_lines = _value_view(pointer, value, other,
                                               f"the {partner_label}" if partner_label else "the normal request")
                res_marks = [m for m in res_marks if m[0] != "answer differs"]    # the view shows the difference
                res_lines = [*res_lines, *view_lines]
        if ref and cls == "access-control":       # e.g. the owner's UserId in another account's answer
            res_lines = [*res_lines, *_same_owner_fields(e, ref)]
        req_html, a = _marked(_image_request(e, req_marks, decoded=cls == "xss").rstrip(), req_marks, sent=True)
        req_html += "".join(f"\n<span class=dec>decoded{' ' + html.escape(name) if name else ''}: "
                            f"{html.escape(d)}</span>" for d in decoded)
        res_html, b = _marked(_image_response(ctx, e, res_marks, res_lines, view), res_marks, res_lines)
        fact_html = " · ".join(f"<b>{html.escape(t)}</b>" if decides else html.escape(t) for t, decides in facts)
        total += a + b
        who = html.escape(e.get("_role") or "anonymous")
        chip = f"<span class=role>{html.escape(label or ROLE_TITLES[kind])}</span>" if kind else ""
        # A comparison the image does not show, or one the proof does not count, is said in words.
        shows_ref = ref is not None and any(ref[0] == m for m, _ in shown)
        discount = reason if ref_label and opposite else None
        diff = (difference(ctx, history, e, ref, ref_label, discount, step=n)
                if ref and (discount or not shows_ref) else "")
        head = (f"<h2>{chip}Step {n} · {html.escape(e['request']['method'])} as {who} → "
                f"{e['response']['status']} {html.escape(e['response']['statusText'])}</h2>"
                + (f"<div class=diff>{html.escape(diff)}</div>" if diff else "")
                + (f"<div class=facts>{fact_html}</div>" if facts else ""))
        if pair:
            sections.append(f"<section{' class=' + kind if kind else ''}>{head}<h3>Request as sent</h3>"
                            f"<pre class=req>{req_html}</pre><h3>Response as received</h3><pre>{res_html}</pre>"
                            "</section>")
        else:
            sections.append(f"<section{' class=' + kind if kind else ''}>{head}<div class=cols><div><h3>Request as "
                            f"sent</h3><pre>{req_html}</pre></div><div><h3>Response as received</h3><pre>{res_html}"
                            "</pre></div></div></section>")
    parts.append(f"<div class=pair>{''.join(sections)}</div>" if pair else "".join(sections))
    if why:
        parts.append(why_html(why))
    else:
        groups = observation_groups(ctx, history, everything, roles)
        seen = " · ".join(f"{label}: {', '.join(values[:3])}" for label, _, values in groups[:5])
        parts.append(f"<div class=why><p><b>What the steps showed</b> {html.escape(seen)}.</p></div>" if seen else "")
    hidden = sorted({n for n, _ in everything} - {n for n, _ in shown})
    notes = [*([f"Also {'part of the proof' if cited else 'recorded'}, not shown here: "
                f"step{'s' if len(hidden) > 1 else ''} {', '.join(map(str, hidden))} (in the report and the HAR "
                "file)."] if hidden else []),
             *([f"Composed by the Verifier: {composed}."] if composed else []),
             f"AppSec Verifier · recorded and redacted{' in ' + har_path if har_path else ''} at "
             f"{shown_time(captured)}; nothing sent again. "
             f"{'Requests shown URL-decoded, excerpts' if cls == 'xss' else 'Excerpts'} shortened (…); the HAR file "
             "has the complete exchanges."]
    parts.append("<footer>" + "<br>".join(html.escape(note) for note in notes) + "</footer>")
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


WITHHELD_BODY = "[body withheld from the model (VER-049, VER-053)]"


def withheld_steps(history: list[dict]) -> set[int]:
    """The steps whose answer body no model may see (VER-016, VER-049, VER-053): an engine-error probe, whose error
    text stays owner-only, and a login-bypass control, whose authenticated artifact is never shown. The test agent
    got only the code's observation for them; authentication bodies stay withheld for the operator too."""
    return {n for n, h in enumerate(history, 1) if isinstance(h.get("result"), dict)
            and ("engine_error" in h["result"] or "auth_artifact" in h["result"])}


def _for_model(e: dict) -> dict:
    """An exchange as a model may see it: the request, the status and a notice in place of the answer's headers
    and body."""
    response = e["response"]
    return {**e, "response": {**response, "headers": [],
                              "content": {**response["content"], "text": WITHHELD_BODY, "mimeType": "text/plain"}}}


def _exchange_screenshot(ctx, history: list[dict], shown: list[tuple[int, dict]], verdict: str, har_path,
                         highlight, *, cited: bool = True, composed: str | None = None, why: dict | None = None,
                         overview: bool = False, result=None) -> list[dict]:
    """The Verifier's own image of the exchanges (VER-035): the steps the proof compares, as the first panel holds
    them (`panels`), the other steps named below them. `composed` says why the test agent's presentation is not used
    (VER-059), `why` is the result's reason (why_summary); `overview` marks the image a revised presentation of the
    test agent keeps beside it (VER-042)."""
    withheld = withheld_steps(history) & {n for n, _ in shown}
    # What a model reviews of the image (VER-042) is the page as it would look with every withheld answer replaced
    # by a notice; the image itself keeps the answer for the operator.
    safe = {n: _for_model(e) if n in withheld else e for n, e in shown}
    first = panels(shown, step_roles(ctx, history, shown), opposite=opposites(history))[:1]
    if not first:
        return []
    page, marked = exchange_document(ctx, history, first[0], verdict, har_path, highlight, cited=cited,
                                     comparison=shown, composed=composed, why=why, result=result)
    model_page = page
    if withheld:
        model_page, _ = exchange_document(ctx, history, [(n, safe[n]) for n, _ in first[0]], verdict, har_path,
                                          highlight, cited=cited, comparison=list(safe.items()), composed=composed,
                                          why=why, result=result)
    visible = _VisibleText()
    visible.feed(model_page)
    ctx.evidence_panels.append({"text": "\n".join(visible.parts)[:8000], "body_font_px": 16,
                                **({"overview": True} if overview else {})})
    try:
        return [{**shot, "composed_by": "verifier", **({"overview": True} if overview else {})}
                for shot in ctx.browser.render_exchanges(html=page, name=evidence_name(ctx.plan), marked=marked)]
    except Exception:  # noqa: BLE001 - a screenshot only illustrates; the verdict stands without it
        return []


_COMPARISON_CSS = """body{margin:0;background:#fff;color:#111;font:16px/1.45 system-ui,Helvetica,Arial,sans-serif}
header{background:#111;color:#fff;padding:12px 16px;border-bottom:4px solid #b00020}
header .id{font-size:14px;color:#bbb}header .lead{font-size:21px;font-weight:bold;line-height:1.3;margin-top:4px}
.verdict{background:#555;color:#fff;font:bold 15px sans-serif;padding:1px 8px;border-radius:4px;margin-right:10px;
text-transform:uppercase;vertical-align:2px}.verdict.confirmed,.verdict.shown-without-exploit{background:#b00020}
.verdict.inconclusive{background:#b26a00}
.why{margin:0 16px 12px;padding:8px 12px;background:#111;color:#fff;border-radius:4px;font-size:15px}
.why b{color:#ffeb3b;margin-right:6px}.why p{margin:0}.why p+p{margin-top:4px}
.why .closing{color:#ccc;font-size:13px}
table{border-collapse:collapse;margin:16px;width:calc(100% - 32px)}
th{text-align:left;font-size:13px;color:#555;padding:4px 10px;border-bottom:2px solid #999}
td{padding:8px 10px;border-bottom:1px solid #ccc;vertical-align:top}td.req,pre{font-family:ui-monospace,Menlo,
Consolas,monospace}td.req{overflow-wrap:anywhere}
.role{color:#fff;font:bold 13px sans-serif;text-transform:uppercase;padding:2px 8px;border-radius:3px;
background:#546e7a;white-space:nowrap}tr.normal .role{background:#2e7d32}tr.attack .role,tr.effect .role
{background:#b00020}td small{display:block;color:#555}
tr.attack.access td,tr.effect.access td{background:#fdecea}tr.access td.got{font-weight:bold;color:#b00020}
section{margin:16px;border:1px solid #ccc}h2{margin:0;padding:6px 10px;background:#f0f0f0;font-size:15px;
border-bottom:1px solid #ccc}pre{margin:0;padding:8px 10px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:15px}
mark{background:none;color:#000;outline:2px solid #b00020;outline-offset:1px}.hit{display:inline-block;max-width:100%}
.hit:not(.block)>mark{display:inline-block}
.note{color:#b00020;font:bold 13px sans-serif;margin-left:8px}.nl{display:none}
.tag{background:#b00020;color:#fff;font:bold 13px sans-serif;padding:1px 5px;margin-right:3px;border-radius:3px}
tr.access.unrated td{background:#fff4e0}tr.access.unrated td.got{color:#b26a00}td.req{width:36%}
footer{margin:0 16px 14px;color:#666;font-size:13px}"""
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def _readable_body(e: dict) -> str:
    """A recorded answer as a person reads it: a page's visible text, JSON indented, long hex values shortened."""
    text = _text(e)
    if "html" in e["response"]["content"].get("mimeType", "").lower():
        parser = _VisibleText()
        parser.feed(text[:MAX_BODY_CHARS])
        text = " ".join(parser.parts)
    else:
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except (ValueError, RecursionError):
            pass
    return _LONG_HEX.sub(lambda m: f"{m[0][:8]}…{m[0][-4:]} ({len(m[0])} hex characters)", text)


def comparison_rows(ctx, history: list[dict], shown: list[tuple[int, dict]]) -> list[dict] | None:
    """The steps of an access-control comparison as table rows (VER-010, VER-035), or None where the latest plan
    places no normal request and no attack among `shown`. `same` says whether a step got the answer of the normal
    request it is compared with: by the digests kept in memory (VER-057), else by the recorded texts, else None."""
    roles = step_roles(ctx, history, shown)
    ordered = [(n, e) for n, e in by_role(shown, roles) if roles.get(n, ("",))[0]][:6]
    # The identity that may, the one that must not, then the controls.
    ordered.sort(key=lambda s: ("normal", "attack", "effect", "control").index(roles[s[0]][0])
                 if roles[s[0]][0] != "outcome" else 4)
    kinds = {roles[n][0] for n, _ in ordered}
    if getattr(ctx.plan, "cls", None) != "access-control" or "normal" not in kinds or not kinds & {"attack", "effect"}:
        return None
    rows = []
    for n, e in ordered:
        kind, label = roles[n]
        ref = compared_with(n, e, ordered, roles) if kind in ("attack", "control") else None
        same = None
        if ref is not None:
            same = _same_in_code(ctx, n, ref[0])
            if same is None and not (e["response"]["content"].get("_omitted")
                                     or ref[1]["response"]["content"].get("_omitted")):
                same = _text(e) == _text(ref[1])
        rows.append({"step": n, "entry": e, "kind": kind, "label": label, "who": e.get("_role") or "without login",
                     "ref": ref[0] if ref else None, "same": same})
    return rows


def comparison_summary(ctx, history: list[dict], rows: list[dict], result) -> dict:
    """Why an access-control comparison has its verdict (VER-010), for its image and the report: `lead`, what was
    observed; `checks`, the access, each control with what it excludes and the rule with its source, each with
    whether it holds; `closing`, what the verdict makes of them. Without shown access only the lead. `restricted`
    says whether a rule rates the access."""
    from ..agent.experiments import latest_plan

    _, plan = latest_plan(history)
    proof, verdict = result.proof or {}, result.verdict
    access = verdict == "confirmed" or bool(proof.get("observed_access"))
    attack = next(r for r in rows if r["kind"] in ("attack", "effect"))
    operation = plan.get("change") if isinstance(plan.get("change"), dict) else plan
    target = f"{operation.get('method', 'GET')} {operation.get('path', '')}".strip()
    restriction = proof.get("access_restriction") if isinstance(proof.get("access_restriction"), dict) else None
    if not access:
        return {"lead": f"{weakness(ctx)} not confirmed. The comparison did not show the access. "
                        + _VERDICT_SENTENCE.get(verdict, "No completed proof."),
                "checks": [], "closing": "", "restricted": bool(restriction)}
    if plan.get("signed_in"):
        shown = f"without a login, {target} returns the same answer as for {plan['signed_in']}"
    elif plan.get("reference"):
        shown = f"{attack['who']} gets the same answer from {target} as the privileged account {plan['reference']}"
    elif isinstance(plan.get("change"), dict):
        shown = f"another account changed the record that {plan.get('owner')} created"
    elif plan.get("owner"):
        shown = f"{attack['who']} reads the record that {plan['owner']} created"
    else:
        shown = f"{attack['who']} gets what the allowed identity gets from {target}"
    # VER-035: the weakness and because what, or what was shown although the verdict is not a confirmation.
    lead = (f"{weakness(ctx)}, because {shown}." if verdict == "confirmed"
            else f"{weakness(ctx)} not confirmed, although {shown}.")
    if restriction:
        expected = (f"{str(restriction.get('restriction') or 'Access is restricted').rstrip('.')}. "
                    f"Source: {str(restriction.get('source') or 'not named').rstrip('.')}.")
    else:
        expected = ("No access rule is declared or assumed for this finding, so the access is shown but not rated "
                    "as a violation.")
    got = f"{attack['who']} got the answer"
    if attack["same"] and attack["ref"] is not None:
        got += f" of step {attack['ref']}, identical as compared in code"
    checks = [{"ok": True, "name": "Access shown", "text": got + f" (step {attack['step']})."}]
    for r in rows:
        if r["kind"] == "control":
            means = ("the target does not answer every path alike" if "random path" in r["label"]
                     else "the resource is not open to everyone")
            checks.append({"ok": True, "name": "Control",
                           "text": f"{r['label']}: {r['entry']['response']['status']} (step {r['step']}), "
                                   f"so {means}."})
    checks.append({"ok": bool(restriction), "name": "Rule", "text": expected})
    closing = ("Confirmed: the access violates the rule." if verdict == "confirmed" else
               f"{verdict.capitalize()}: the access is shown, " + (
                   "but the verdict is not a confirmation." if restriction else "but no rule rates it."))
    return {"lead": lead, "checks": checks, "closing": closing, "restricted": bool(restriction)}


def comparison_document(ctx, history: list[dict], shown: list[tuple[int, dict]], result, har_path,
                        highlight=None) -> tuple[str, int] | None:
    """An access-control comparison as one HTML page for its screenshot (VER-010, VER-035): what was observed, why
    the verdict follows (`comparison_summary`), one table row per identity with its request and answer, and the
    answer the attack received once, since an identical answer of the account is not kept (VER-057). Every recorded
    value is escaped; the page has no script."""
    rows = comparison_rows(ctx, history, shown)
    if rows is None:
        return None
    summary = comparison_summary(ctx, history, rows, result)
    verdict, restriction, access = result.verdict, summary["restricted"], bool(summary["checks"])
    body_row = next((r for r in rows if r["kind"] in ("attack", "effect")
                     and not r["entry"]["response"]["content"].get("_omitted") and _text(r["entry"])), None)
    table = ["<tr><th></th><th>Identity</th><th>Request</th><th>Answer</th><th>Expected</th></tr>"]
    for r in rows:
        e, res = r["entry"], r["entry"]["response"]
        url = urlsplit(e["request"]["url"])
        size = res["content"].get("size")
        answer = f"{res['status']} {res['statusText']}".strip() + (f" · {size} bytes" if type(size) is int else "")
        detail = ""
        if r["same"] is not None and r["ref"] is not None:
            detail = f"{'identical to' if r['same'] else 'differs from'} step {r['ref']}, compared in code"
        if r["kind"] == "normal":
            wanted = "allowed"
        elif r["kind"] == "control":
            wanted = "no such resource" if "random path" in r["label"] else "refused"
        else:
            wanted = "refused" if restriction else "not declared"
        violates = access and r["kind"] in ("attack", "effect")
        table.append(
            f"<tr class='{r['kind']}{' access' if violates else ''}{'' if restriction else ' unrated'}'>"
            f"<td><span class=role>{html.escape(ROLE_TITLES[r['kind']])}</span></td>"
            f"<td>{html.escape(r['who'])}<small>"
            f"{html.escape('' if r['label'] == r['who'] else r['label'] + ' · ')}step {r['step']}</small></td>"
            f"<td class=req>{html.escape(e['request']['method'])} "
            f"{html.escape(url.path + ('?' + url.query if url.query else ''))}</td>"
            f"<td class=got>{html.escape(answer)}" + (f"<small>{html.escape(detail)}</small>" if detail else "")
            + f"</td><td>{html.escape(wanted)}</td></tr>")
    parts, total = [head_html(ctx, verdict, summary["lead"]), f"<table>{''.join(table)}</table>"], 0
    if body_row is not None:
        n, e = body_row["step"], body_row["entry"]
        _, res_marks, res_lines, _ = _exchange_marks(ctx, history, n, e, shown, highlight, shown)
        res_marks = [m for m in res_marks if m[0] != "answer differs"]
        marked, total = _marked(_image_excerpt(_readable_body(e), res_marks, limit=900), res_marks, res_lines)
        twins = [r for r in rows if r is not body_row and (
            (body_row["same"] and r["step"] == body_row["ref"]) or (r["same"] and r["ref"] == n))]
        caption = f"Answer {'' if body_row['who'] == 'without login' else 'to '}{body_row['who']} (step {n})"
        if twins:
            caption += ("; " + " and ".join(f"{r['who']} (step {r['step']})" for r in twins)
                        + " got the identical answer, compared in code")
        parts.append(f"<section><h2>{html.escape(caption)}</h2><pre>{marked}</pre></section>")
    if access:
        parts.append(why_html(summary))
    captured = shown[0][1].get("startedDateTime", "") if shown else ""
    record = " in " + html.escape(har_path) if har_path else ""
    parts.append(f"<footer>AppSec Verifier · recorded and redacted{record} at "
                 f"{html.escape(shown_time(captured))}; nothing sent again. Long hex values are shortened.</footer>")
    page = (f"<!doctype html><html><head><meta charset=utf-8><style>{_COMPARISON_CSS}</style></head>"
            f"<body>{''.join(parts)}</body></html>")
    return page, total


def _comparison_screenshot(ctx, history: list[dict], shown: list[tuple[int, dict]], result, har_path, highlight
                           ) -> list[dict] | None:
    """The one image of an access-control comparison, or None where the steps form none (VER-035)."""
    built = comparison_document(ctx, history, shown, result, har_path, highlight)
    if built is None:
        return None
    page, marked = built
    visible = _VisibleText()
    visible.feed(page)
    ctx.evidence_panels.append({"text": "\n".join(visible.parts)[:8000], "body_font_px": 16, "overview": True})
    try:
        return [{**shot, "composed_by": "verifier", "overview": True}
                for shot in ctx.browser.render_exchanges(html=page, name=evidence_name(ctx.plan), marked=marked)]
    except Exception:  # noqa: BLE001 - a screenshot only illustrates; the verdict stands without it
        return []


def attach(ctx, history: list[dict], steps: list[dict], result, cited, highlight=None, presentation=None):
    """Bound final rendering; retain recorded exchanges after a stop (VER-036). `presentation` is the test agent's
    (VER-059), used as far as verify/presentation.py takes it.

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
            return _attach(ctx, history, steps, result, cited, highlight, presentation)
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


def verifier_rows(ctx, history: list[dict], steps: list[dict], numbers: set[int], har_path, highlight=None, *,
                  composed: bool = False) -> list[dict]:
    """The report's rows of the steps marked decisive whose numbers are in `numbers`, as the Verifier shows them
    (VER-034, VER-035): the normal requests first, raw request and answer, the decisive part marked, and whether no
    model read the answer (VER-053). `composed` marks them as the Verifier's beside the test agent's presentation,
    which leaves them out (VER-059)."""
    withheld = withheld_steps(history)
    entries = [(s["step"], e) for s in steps if s.get("decisive") and (e := _shown_entry(s)) is not None]
    roles = step_roles(ctx, history, entries)
    entries = by_role(entries, roles)
    if getattr(ctx.plan, "cls", None) == "access-control":      # as in the comparison image: the attack, then controls
        entries.sort(key=lambda s: roles.get(s[0], ("",))[0] == "control")
    others = [e for _, e in entries]
    return [{"step": n, "request": _raw_request(e), "elapsed_ms": e.get("time"),
             "response": _raw_response(e, _focus(ctx, others, e), har_path),
             **_report_excerpts(ctx, history, n, e, entries, highlight, har_path, roles),
             **({"withheld": True} if n in withheld else {}),
             **({"composed_by": "verifier"} if composed else {})}
            for n, e in entries if n in numbers]


def _attach(ctx, history: list[dict], steps: list[dict], result, cited, highlight=None, presentation=None):
    if getattr(getattr(ctx, "plan", None), "cls", None) == "session":
        from ..agent.proof import retain_login_observations

        retain_login_observations(ctx, history, result)
        _login_cookie_screenshot(ctx, result)
    for number, step in enumerate(history, 1):
        if step.get("tool") == "browser_check":
            paths = {e.get("path") for e in step.get("result", {}).get("evidence", [])
                     if e.get("kind") == "screenshot"}
            for image in result.evidence or []:
                if image.get("kind") == "screenshot" and image.get("path") in paths:
                    image["proof_step"] = number
        if step.get("tool") == "browser_check" and (problem := step.get("result", {}).get("screenshot_error")):
            note = "Application screenshot unavailable: " + problem + "."
            if note not in result.observations:
                result.observations.append(note)
    # The plan as accepted: plan_test may have counted an unsupported observed prerequisite as assumed.
    accepted = [(n, h["result"].get("experiment") or h["args"]) for n, h in enumerate(history, 1)
                if h.get("tool") == "plan_test" and h.get("result", {}).get("accepted") is True]
    # A strategy is optional (VER-043); a plan without one shows no empty strategy field in the report.
    result.planning = [{"step": n, "path": p.get("path"), "hypothesis": p.get("hypothesis"),
                        **({"strategy": p["strategy"]} if p.get("strategy") else {})} for n, p in accepted]
    if ctx.sessions is not None:
        result.planning = ctx.sessions.redact(result.planning)
    """Write the finding's proof of concept and add it to `result` (VER-034, VER-035)."""
    if not steps:
        return result
    from ..agent.experiments import plan_view

    # The images describe the plan the checked steps ran under, not one accepted after them (plan_view).
    cited = (result.proof or {}).get("steps") or cited
    history = plan_view(history, cited)
    decisive = set(decisive_steps(ctx, history, result.verdict, cited))
    for step in steps:
        step["decisive"] = step["step"] in decisive
    har = _write_har(ctx, steps)
    result.evidence = [*(result.evidence or []), *har]
    har_path = har[0]["path"] if har else None
    shown_entries = [(s["step"], _shown_entry(s)) for s in steps if s["decisive"]]
    shown_entries = [(n, e) for n, e in shown_entries if e is not None]
    shown_entries = by_role(shown_entries, step_roles(ctx, history, shown_entries))   # normal requests first
    from .presentation import COMPOSED_NOTE, assess, saved, shown_steps
    from .presentation import screenshots as composed_screenshots

    # VER-059: the test agent's presentation as the code takes it, the steps it leaves out after it as the Verifier
    # shows them; else the Verifier's own presentation and why.
    accepted, composed, _ = (assess(ctx, history, steps, result, cited, presentation) if decisive
                             else (None, None, ()))
    result.poc = {
        "file": har_path,
        "steps": [{"step": s["step"], "line": _line(s, history), "decisive": s["decisive"]} for s in steps],
        "shown": shown_steps(ctx, history, steps, accepted, har_path) + verifier_rows(
            ctx, history, steps, set(accepted["not_shown"]), har_path, highlight, composed=True) if accepted
        else verifier_rows(ctx, history, steps, decisive, har_path, highlight),
        **({"presentation": saved(accepted)} if accepted
           else {"presentation": {"composed_by": "verifier", "reason": composed}} if composed else {}),
    }
    if composed:
        result.observations.append(f"{COMPOSED_NOTE}{composed}.")
    shots: list[dict] = []
    cls, browser = getattr(ctx.plan, "cls", None), getattr(ctx, "browser", None)
    why = why_summary(ctx, history, shown_entries, result) if shown_entries else None
    if why:             # why the result has its verdict, for the report as for the images
        why = result.poc["why"] = ctx.sessions.redact(why) if ctx.sessions is not None else why
    # An injection experiment's proof image comes before any other: the comparison its proof rests on.
    placed = step_roles(ctx, history, shown_entries)
    overview = cls == "injection" and sum(bool(placed.get(n, ("",))[0]) for n, _ in shown_entries) >= 2
    if browser is not None and cls in getattr(browser, "screenshots", ()):
        if result.verdict == "confirmed" and cls == "access-control" and not any(
                e.get("presentation") == "application" for e in result.evidence):
            shots = _page_screenshots(ctx, steps, highlight)
        # An access-control comparison is one table (VER-010); the test agent's presentation follows it (VER-059).
        compared = (_comparison_screenshot(ctx, history, shown_entries, result, har_path, highlight)
                    if cls == "access-control" and shown_entries else None)
        shots += compared or []
        if overview:
            shots += _exchange_screenshot(ctx, history, shown_entries, result.verdict, har_path, highlight,
                                          composed=None if accepted else composed, why=why, overview=True,
                                          result=result)
        if accepted:                             # the exchanges as the test agent presents them
            shots += composed_screenshots(ctx, history, steps, accepted, result, har_path)
        elif shown_entries and compared is None and not overview:   # the exchanges, also beside a proof page
            shots += _exchange_screenshot(ctx, history, shown_entries, result.verdict, har_path, highlight,
                                          composed=composed, why=why, result=result)
        elif compared is None and not decisive and (tried := _tried(history, steps)):     # e.g. a limit stopped it
            shots += _exchange_screenshot(ctx, history, tried, result.verdict, har_path, highlight, cited=False,
                                          result=result)
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


def _login_cookie_screenshot(ctx, result):
    """Render recorded cookie facts as a labelled observation table, never as reconstructed HTTP."""
    observations = (result.proof or {}).get("cookie_observations", [])
    browser = getattr(ctx, "browser", None)
    if not observations or browser is None or "session" not in getattr(browser, "screenshots", ()):
        return
    lines = [f"{ctx.plan.id}: {result.verdict}", "Recorded login-cookie observations; cookie values omitted."]
    for item in observations:
        for cookie in item["session_cookies"]:
            lines.append(f"{item['method']} {item['origin']}{item['path']} | HTTP {item['status']} | "
                         f"{item['role']} | {cookie['name']}: Secure={cookie['secure']}, "
                         f"HttpOnly={cookie['httponly']}, SameSite={cookie['samesite'] or 'missing'}, "
                         f"active={cookie['active']}")
    text = "\n".join(lines)
    text = ctx.sessions.redact(text) if ctx.sessions is not None else text
    page = ('<!doctype html><meta charset="utf-8"><style>body{font:16px sans-serif;padding:24px}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.6}</style><pre>'
            + html.escape(text) + '</pre>')
    ctx.evidence_panels.append({"text": text[:8000], "body_font_px": 16})
    try:
        result.evidence.extend({**shot, "composed_by": "verifier"} for shot in browser.render_exchanges(
            html=page, name=evidence_name(ctx.plan) + "-cookies", marked=False))
    except Exception:  # noqa: BLE001 - the recorded facts remain evidence without an image
        result.observations.append("Cookie observation screenshot unavailable; recorded attributes are retained.")
