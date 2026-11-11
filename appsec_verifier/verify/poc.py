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
Where the accepted test plan or the finding's payload says what a step is
(`step_roles`), the image shows a normal request on top and the attack below
it, with a line on how the attack's answer compares; an injection experiment's
response shows the observed value, entries the normal answer lacks marked `+`.
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
            images = browser.render(url=e["request"]["url"], status=e["response"]["status"],
                                    content_type=e["response"]["content"]["mimeType"], html=text,
                                    name=evidence_name(ctx.plan), caption=caption, highlight=values)
            out += [{**image, "finding_id": ctx.plan.id, "proof_step": step["step"],
                     "role": e.get("_role") or "anonymous"} for image in images]
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


# ── what each shown step is in the test (VER-035) ────────────────────────────

ROLE_TITLES = {"normal": "Normal request", "control": "Control", "attack": "Attack", "effect": "Effect"}
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
    return values.get(plan.get("input_name"), _MISSING)


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
    from ..agent.experiments import latest_plan, normal_roles, token

    cls, marker = getattr(ctx.plan, "cls", None), getattr(ctx, "marker", None) or ("", "")
    _, plan = latest_plan(history)
    steps = {n: history[n - 1] if 1 <= n <= len(history) else {} for n, _ in shown}
    args = {n: h.get("args") or {} for n, h in steps.items()}
    roles: dict[int, tuple[str, str]] = {}
    if cls == "injection" and plan.get("kind") in ("boolean", "timing") and plan.get("input_name"):
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
        if payload:
            for n, _ in shown:
                sent = unquote(json.dumps(args[n], ensure_ascii=False))
                roles[n] = ("attack", "carries the payload") if payload in sent else (
                    "normal", "without the payload")
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


def panels(shown: list[tuple[int, dict]], roles: dict[int, tuple[str, str]], limit: int = 3) -> list[list]:
    """The exchange images (VER-035): each attack, one per label, below the normal request it is compared with;
    then the other normal requests, controls and steps without a role. Two exchanges per image; without both
    kinds, in role order."""
    refs = [s for s in by_role(shown, roles) if roles.get(s[0], ("",))[0] in ("normal", "control")]
    tests = [s for s in by_role(shown, roles) if roles.get(s[0], ("",))[0] in ("attack", "effect")]
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


def compared_with(n: int, e: dict, shown: list[tuple[int, dict]], roles) -> tuple[int, dict] | None:
    """The normal request an attack or effect is compared with, or None."""
    if roles.get(n, ("",))[0] not in ("attack", "effect"):
        return None
    refs = [s for s in shown if roles.get(s[0], ("",))[0] == "normal"]
    return _closest((n, e), refs, set(), roles) if refs else None


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


def _value_view(pointer: str, value, normal=_MISSING) -> tuple[str, list[tuple[str, str]]]:
    """The observed value as lines for the image, and the line to mark: a list as one row per entry, `+` before
    an entry the normal answer does not contain."""
    from ..agent.experiments import token

    differs = normal is not _MISSING and token(value) != token(normal)
    head = f"{pointer}: {_brief(value)}"          # its label says how the normal request's differs
    lines, new = [head], 0
    if isinstance(value, list):
        known = {token(v) for v in normal} if differs and isinstance(normal, list) else None
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
        marks.append((f"{new} entr{'y' if new == 1 else 'ies'} the normal request does not get", "+ ["))
    return "\n".join(lines), marks


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


def difference(ctx, history: list[dict], e: dict, ref: tuple[int, dict]) -> str:
    """How an attack's answer compares with the normal request's, in one sentence from the recorded answers."""
    m, r = ref
    start = f"Compared with the normal request in step {m}: "
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
            text += f", {new} of them not in the normal answer" if new else ""
        return start + text + "."
    ce, cr = e["response"]["content"], r["response"]["content"]
    if ce.get("_omitted") or cr.get("_omitted"):      # no text to compare: a binary body only by its hash
        same = ce.get("_sha256") and ce.get("_sha256") == cr.get("_sha256")
        return start + f"{status}, " + ("the identical answer." if same else "the answers are not recorded to compare.")
    if _text(e) == _text(r):
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
        out += [html.escape(text[last:a]), hit]
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
    ref = compared_with(n, entry, shown, roles or {})
    role = {"role": roles[n][0], "role_label": roles[n][1]} if roles and n in roles else {}
    return {**role, "request_excerpt": _code_excerpt(_image_request(entry, req), req),
            "response_excerpt": _code_excerpt(response, res, lines),
            "facts": [fact for fact, decisive in facts if decisive]
            + ([difference(ctx, history, entry, ref)] if ref else [])}


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
        location = next((h["value"] for h in e["response"]["headers"] if h["name"].lower() == "location"), "")
        res_lines.append(("redirect to the test host" if host and host in location else "redirect", "location:"))
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
            token = _diff_token(_text(e), _text(o), "body")
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


def _image_response(ctx, e, marks, marked_lines, view: str | None = None):
    res = e["response"]
    lines = [f"HTTP/1.1 {res['status']} {res['statusText']}".rstrip()]
    keep = {"location", "www-authenticate", "set-cookie"}
    lines += [f"{h['name']}: {h['value']}" for h in res["headers"]
              if h["name"].lower() in keep or any(h["name"].lower() + ":" == prefix.lower()
                                                for _, prefix in marked_lines)]
    if view is not None:      # the experiment's observed value, already bounded
        return _image_excerpt("\n".join(lines), limit=450) + "\n\n" + view
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
header b{font-size:20px}header .k{color:#ffeb3b;font-weight:bold}header small{color:#bbb;font-size:13px}
.hit.block{display:block}.block mark{display:block;background:none;outline:none;border:2px solid #b00020}
.sent mark{background:#ffeb3b;outline:2px solid #b00020;outline-offset:0}
.note{color:#b00020;font:bold 14px sans-serif;margin-left:8px}.block .note{display:block;margin:0 0 3px}
.nl{display:none}
section{margin:14px;border:1px solid #ccc}
h2{margin:0;padding:6px 10px;background:#f0f0f0;font-size:16px;border-bottom:1px solid #ccc}
.facts{padding:4px 10px;border-bottom:1px solid #ccc}.cols{display:flex}.cols>div{flex:1;min-width:0}
.cols>div+div{border-left:1px solid #ccc}h3{margin:0;padding:4px 10px;font-size:15px;color:#555}
pre{margin:0;padding:6px 10px 10px;white-space:pre-wrap;overflow-wrap:anywhere}
mark{background:none;color:#000;outline:2px solid #b00020;outline-offset:1px}.hit{display:inline-block;max-width:100%}
.tag{background:#b00020;color:#fff;font:bold 13px sans-serif;padding:1px 5px;margin-right:3px;border-radius:3px}
section.normal{border:2px solid #2e7d32}section.control{border:2px solid #546e7a}
section.attack{border:2px solid #b00020}section.effect{border:2px solid #e65100}
.normal h2{background:#e8f5e9}.control h2{background:#eceff1}.attack h2{background:#fdecea}
.effect h2{background:#fff3e0}
.role{color:#fff;font:bold 14px sans-serif;text-transform:uppercase;padding:2px 8px;margin-right:8px;border-radius:3px}
.normal .role{background:#2e7d32}.control .role{background:#546e7a}.attack .role{background:#b00020}
.effect .role{background:#e65100}
.diff{padding:6px 10px;border-bottom:1px solid #ccc;background:#fff8e1;font-weight:bold}"""


def _quoted(value) -> str:
    return json.dumps(value, ensure_ascii=False)[:60]


def _test_line(ctx, history: list[dict]) -> str:
    """What the test did, in one sentence from the accepted plan and the finding's class; "" when unknown."""
    from ..agent.experiments import latest_plan
    from ..agent.proof import redirect_host

    _, plan = latest_plan(history)
    cls, marker = getattr(ctx.plan, "cls", None), getattr(ctx, "marker", None) or ("", "")
    target = f"{plan.get('method', 'GET')} {plan['path']}" if plan.get("path") else "the finding's request"
    if cls == "injection" and plan.get("kind") in ("boolean", "timing") and plan.get("input_name"):
        normal = f"{target} with {plan['input_name']} = {_quoted(plan.get('baseline'))} as the normal input, then"
        if plan["kind"] == "timing":
            return f"{normal} with a condition that delays the answer; compared: the answer time"
        if plan.get("expression_template"):
            return f"{normal} with computed expressions; compared: {plan.get('pointer')}"
        return f"{normal} with injected conditions that are true and false; compared: {plan.get('pointer')}"
    if cls == "access-control" and plan.get("kind") == "access-control":
        resource, owner = _declared_resource(ctx, plan), plan.get("owner")
        if resource is not None:
            return (f"{resource.get('method', 'GET')} {resource.get('path')} as an identity allowed to read it and "
                    "as one that must not")
        if owner and isinstance(plan.get("change"), dict):
            return (f"{owner} creates a record with the test marker, another account changes it with "
                    f"{plan['change'].get('method')} {plan['change'].get('path')}, then {owner} reads it again")
        if owner:
            return (f"{owner} creates a record with the test marker; {owner}, a request without login and another "
                    "account read it")
        if plan.get("reference"):
            return f"{target} as the privileged account {plan['reference']}, without login and as a normal account"
    if cls == "xss":
        return "the page opened with a payload that calls alert() with the finding's marker; proof: the marker runs"
    if cls == "open-redirect" and (host := redirect_host(marker)):
        return f"a request that names {host} as the redirect target; proof: a redirect to that host"
    if cls == "path-traversal":
        return "a request for the operator's marker file; proof: the file's content in the answer"
    if cls == "ssrf":
        return "a request that makes the target call the Verifier's listener; proof: the listener gets the marker"
    if cls == "session" and (attribute := _SESSION_ATTRIBUTES.get(getattr(ctx.plan, "cwe", None))):
        return f"the session cookie as the target sets it; checked: its {attribute} attribute"
    return ""


_VERDICT_SENTENCE = {
    "confirmed": "The proof check accepted it.",
    "inconclusive": "This does not complete the required proof.",
    "blocked-by-control": "The operation was refused, with matched control evidence.",
    "not-reproducible": "Not reproduced in these attempts, which does not prove absence.",
}


def _result_line(ctx, history: list[dict], everything: list[tuple[int, dict]], roles, verdict: str,
                 cited: bool) -> str:
    """What the steps showed, per kind of step, and what the verdict makes of it."""
    from ..agent.experiments import latest_plan

    timing = latest_plan(history)[1].get("kind") == "timing"
    cls = getattr(ctx.plan, "cls", None)
    rows: dict[str, list[str]] = {}
    for n, e in by_role(everything, roles):
        kind, label = roles.get(n, ("", ""))
        if roles and not kind:        # outside the comparison the plan declares
            continue
        who = e.get("_role")
        name = (label.replace(", second form", "") + (f" {who}" if who and cls == "access-control" else "")
                if kind else f"step {n} as {who or 'anonymous'}")
        value, ref = observed(ctx, history, e), compared_with(n, e, everything, roles)
        if value is not _MISSING:
            seen = _brief(value)
        elif timing and isinstance(e.get("time"), int):
            seen = f"{e['time']} ms"
        elif ref is None:
            seen = str(e["response"]["status"])
        else:
            same = _text(e) == _text(ref[1]) and not (e["response"]["content"].get("_omitted")
                                                       or ref[1]["response"]["content"].get("_omitted"))
            seen = f"{e['response']['status']}, {'the same' if same else 'a different'} answer"
        if seen not in rows.setdefault(name, []):
            rows[name].append(seen)
    shown = [f"{name}: {', '.join(seen[:3])}" for name, seen in list(rows.items())[:5]]
    closing = (_VERDICT_SENTENCE.get(verdict, "No completed proof.") if cited
               else "The verdict cites no step, so these requests prove nothing.")
    return " · ".join(shown) + ". " + closing


def _shown_line(panel: list[tuple[int, dict]], roles) -> str:
    """The steps in this image, top and below."""
    parts = []
    for i, (n, e) in enumerate(panel):
        kind, label = roles.get(n, ("", ""))
        what = (f"the {ROLE_TITLES[kind].lower()} ({label})" if kind else
                f"{e['request']['method']} as {e.get('_role') or 'anonymous'} → {e['response']['status']}")
        parts.append(("top: " if i == 0 else "below: ") * (len(panel) > 1) + f"step {n}, {what}")
    return "; ".join(parts)


def exchange_document(ctx, history: list[dict], shown: list[tuple[int, dict]], verdict: str, har_path,
                      highlight=None, *, cited: bool = True, comparison=None) -> tuple[str, int]:
    """The decisive exchanges of a finding as one HTML page for its screenshot (VER-035): request and
    response side by side per step, what the verdict rests on marked. Without `cited` they are the answered
    requests after the last test plan of a verdict that cites no step, and the header says so. Returns the page
    and the number of marks. Every recorded value is escaped; the page has no script."""
    from ..agent.experiments import latest_plan
    from ..planning import _TITLE_LOCATION

    cls = getattr(ctx.plan, "cls", None) or "finding"
    captured = shown[0][1].get("startedDateTime", "") if shown else ""
    everything = comparison or shown
    roles = step_roles(ctx, history, everything)
    shown = by_role(shown, roles)[:6]
    title = _TITLE_LOCATION.sub("", str(getattr(ctx.plan, "title", "") or "")[:300])[:90]
    test = _test_line(ctx, history)
    if not test and cited and not latest_plan(history)[0]:
        test = "no accepted test plan; shown are the requests the verdict cites"
    lines = [f"<b>{html.escape(' · '.join(filter(None, (str(ctx.plan.id), cls, title, verdict))))}</b>",
             *([f"<span class=k>Test:</span> {html.escape(test)}"] if test else []),
             f"<span class=k>Result:</span> "
             f"{html.escape(_result_line(ctx, history, everything, roles, verdict, cited))}",
             f"<span class=k>Shown:</span> {html.escape(_shown_line(shown, roles))}",
             f"<small>AppSec Verifier · recorded and redacted{' in ' + html.escape(har_path) if har_path else ''}"
             f" at {html.escape(shown_time(captured))}; nothing sent again. Excerpts shortened; yellow marks what "
             "a request sent, a red frame what an answer shows.</small>"]
    pointer = latest_plan(history)[1].get("pointer")
    parts, total = [f"<header>{chr(10).join(lines)}</header>"], 0
    for n, e in shown:
        kind, label = roles.get(n, ("", ""))
        req_marks, res_marks, res_lines, facts = _exchange_marks(ctx, history, n, e, everything, highlight)
        facts = [(t, d) for t, d in facts if d or not t.startswith("answered in")]   # a time only where it decides
        # Compared with the normal request in the same image, else the closest one of the finding.
        ref = compared_with(n, e, shown, roles) or compared_with(n, e, everything, roles)
        view, value = None, observed(ctx, history, e)
        if value is not _MISSING:
            view, view_lines = _value_view(pointer, value, observed(ctx, history, ref[1]) if ref else _MISSING)
            res_marks = [m for m in res_marks if m[0] != "answer differs"]    # the view shows the difference
            res_lines = [*res_lines, *view_lines]
        if ref and cls == "access-control":       # e.g. the owner's UserId in another account's answer
            res_lines = [*res_lines, *_same_owner_fields(e, ref)]
        req_html, a = _marked(_image_request(e, req_marks), req_marks, sent=True)
        res_html, b = _marked(_image_response(ctx, e, res_marks, res_lines, view), res_marks, res_lines)
        fact_html = " · ".join(f"<b>{html.escape(t)}</b>" if decides else html.escape(t) for t, decides in facts)
        total += a + b
        who = html.escape(e.get("_role") or "anonymous")
        banner = (f"<span class=role>{html.escape(ROLE_TITLES[kind])}</span>{html.escape(label)} · "
                  if kind else "")
        diff = difference(ctx, history, e, ref) if ref else ""
        parts.append(f"<section{' class=' + kind if kind else ''}><h2>{banner}Step {n} · "
                     f"{html.escape(e['request']['method'])} as {who} → "
                     f"{e['response']['status']} {html.escape(e['response']['statusText'])}</h2>"
                     + (f"<div class=diff>{html.escape(diff)}</div>" if diff else "")
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
    for panel in panels(shown, step_roles(ctx, history, shown)):
        page, marked = exchange_document(ctx, history, panel, verdict, har_path,
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
    decisive = set(decisive_steps(ctx, history, result.verdict, cited))
    for step in steps:
        step["decisive"] = step["step"] in decisive
    har = _write_har(ctx, steps)
    result.evidence = [*(result.evidence or []), *har]
    har_path = har[0]["path"] if har else None
    shown_entries = [(s["step"], _shown_entry(s)) for s in steps if s["decisive"]]
    shown_entries = [(n, e) for n, e in shown_entries if e is not None]
    roles = step_roles(ctx, history, shown_entries)
    shown_entries = by_role(shown_entries, roles)       # the normal requests before the attacks (VER-035)
    others = [e for _, e in shown_entries]
    result.poc = {
        "file": har_path,
        "steps": [{"step": s["step"], "line": _line(s, history), "decisive": s["decisive"]} for s in steps],
        "shown": [{"step": n, "request": _raw_request(e), "elapsed_ms": e.get("time"),
                   "response": _raw_response(e, _focus(ctx, others, e), har_path),
                   **_report_excerpts(ctx, history, n, e, shown_entries, highlight, har_path, roles)}
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
