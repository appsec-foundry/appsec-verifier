"""Proof browser for XSS findings (VER-009, VER-016, VER-018, VER-022).

Loads one target page in headless Google Chrome, driven by Playwright (optional
extra `appsec-verifier[browser]`), and reports whether the finding's marker
expression executed. Chrome opens no connection of its own: every request of
every page is intercepted and either answered through the GuardedHttpClient,
so scope, budget, safe mode and identity headers apply exactly as for the
agent's HTTP requests, or aborted. Redirects go back to the browser, so each
hop is authorised again. Chrome itself runs in a network namespace of its own
(Linux, `unshare --user --net`) that has no interface but loopback, so nothing
it sends can leave the machine, including traffic the interception never sees
such as WebRTC/UDP. Inside it Chrome's own proxy points to a closed local port
and host resolution is disabled; WebSockets are never connected to a server
and service workers are blocked.
Chrome runs with its sandbox on. Where the namespace or the sandbox is not
available, the browser does not start and XSS stays unproven.

Only evaluation proves execution: the payload must call alert() with an
expression that joins the two marker parts at runtime, and only a dialog whose
message equals the joined marker counts. A page that merely echoes the payload
text shows the expression, not its value. Without execution the check reports
`markup_break`: whether a marker part parsed into an injected <script> element
or event-handler attribute, which is indicative only. On execution a JSON event record is
saved owner-only under evidence/, with a screenshot when screenshots are on for
XSS (VER-035): the elements that carry the payload are outlined, and what of
the page covered the payload (a dialog, a backdrop) or floats over it
(notifications, confetti) is hidden. The image (xss_frame) shows an address bar
with the URL, the dialog drawn from the recorded call, the page section around
the outlined payload, and below it a caption that names finding, identity,
time, the payload element and what was hidden. Each request
the guarded client answered is handed back for the proof of concept (VER-034),
bodies only for documents, XHR and fetch.

A post-proof observation can also capture an access-control effect on a known
application route (VER-035), read-only under the decisive response's identity.
It requires a successful read of that same resource, or of another response
with a selected value that carries the finding's marker (`observed_values`),
and the value in visible page text; it never establishes or changes a verdict. Live captures
retain the application viewport. Requests remain guarded and are recorded.

`render` screenshots a recorded HTML response for an access-control proof,
`render_exchanges` the page verify/poc.py builds from a finding's recorded
exchanges for every other screenshot (VER-035). Either page is answered from
the record, every other request is aborted and scripts are off, so they send
nothing to the target. Screenshots can show target data, so their evidence
entry says so. Files are named after the finding and its title
(`planning.evidence_name`): the application screenshot `<name>.png`, the
HTTP images `<name>-http-<n>.png`.

A Playwright error outside the page load, such as a crashed Chrome, is a
BrowserError and closes the browser; the next use starts a new one. A check
ends in bounded time even on a page that never finishes: loading has
NAVIGATION_TIMEOUT_MS, a page request other than a document at most
PAGE_REQUEST_TIMEOUT_S (a long poll), nothing is answered after the wait, and
marking and screenshot have EVIDENCE_TIMEOUT_MS each; a page that does not
answer keeps its event record without a screenshot.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..verify.poc import (
    BODY_RESOURCE_TYPES,
    MAX_BROWSER_EXCHANGES,
    MAX_RAW_BYTES,
    TARGET_DATA_NOTE,
    capture,
    shown_time,
)
from .browser_mask import capture_masked, mask_credentials
from .http import ScopeViolation, same_origin

_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_WAIT_MS = 5000
NAVIGATION_TIMEOUT_MS = 30_000
PAGE_REQUEST_TIMEOUT_S = 5.0       # any request but a document; long polls are cut here
EVIDENCE_TIMEOUT_MS = 5000         # marking and screenshot of a page whose script may never return
_DROP_REQUEST_HEADERS = {"host", "content-length", "connection"}
_DROP_RESPONSE_HEADERS = {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
_CLOSED_PROXY = "http://127.0.0.1:9"
_CHROME_ARGS = ["--host-resolver-rules=MAP * ~NOTFOUND", "--no-pings", "--disable-background-networking",
                "--disable-domain-reliability", "--disable-sync"]
# A new user and network namespace with the caller's uid: no network but loopback, and
# Chrome is not root inside it, so its own sandbox still starts.
_NETNS_ARGS = ("--user", "--net", "--map-current-user")
SCREENSHOT_NOTE = TARGET_DATA_NOTE
SCREENSHOT_CLASSES = ("xss", "access-control", "injection", "open-redirect", "path-traversal", "ssrf", "session")
_EXCHANGE_PAGE = "https://exchange.appsec-verifier.invalid/"   # never resolves; answered from the record
# VER-016: what a caption says when known credentials were masked; each placeholder names account and kind.
MASKED_NOTE = "Known credentials masked for this screenshot; each placeholder names its account and kind."
_PAGE_KINDS = ("xss", "application", "access-control")          # application screenshots, named after the finding
_HIGHLIGHT = "#b00020"


def _leave_unconnected(ws) -> None:
    """WebSocket route handler: the socket is never connected to a server. Playwright calls this handler on
    its own event loop, where a synchronous call such as `ws.close()` waits on itself and spins forever."""


def _quietly(close) -> None:
    """Close a browser context without letting a failure replace the exception already on its way."""
    try:
        close()
    except Exception:  # noqa: BLE001 - the context of a crashed browser cannot be closed; the browser is reset
        pass


def _chrome_binary() -> str | None:
    return shutil.which("google-chrome") or shutil.which("google-chrome-stable")


def _isolation_problem(run=subprocess.run) -> str | None:
    """Why Chrome cannot be started without network access here, or None."""
    if not sys.platform.startswith("linux"):
        return "the proof browser needs Linux, where Chrome runs in a network namespace without network access"
    unshare = shutil.which("unshare")
    if not unshare:
        return "`unshare` (util-linux) is needed to run Chrome without network access"
    if _chrome_binary() is None:
        return "Google Chrome (google-chrome) was not found on PATH"
    try:
        probe = run([unshare, *_NETNS_ARGS, "true"], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        probe = None
    if probe is None or probe.returncode != 0:
        return "cannot create a network namespace for Chrome (unprivileged user namespaces may be disabled)"
    return None


def _wrapper_script(unshare: str, chrome: str) -> str:
    """The executable Playwright starts: Chrome inside a namespace without network."""
    return f'#!/bin/sh\nexec {shlex.quote(unshare)} {" ".join(_NETNS_ARGS)} {shlex.quote(chrome)} "$@"\n'


def _playwright_install_command(prefix: str | None = None, root: Path | None = None) -> str:
    """How to add Playwright to the installation that is running: `pipx inject` for a pipx install;
    for a source checkout the hash-checked requirements.lock (it pins every runtime part), installed
    with the Python that runs the Verifier; otherwise that Python's pip with the version the
    `browser` extra pins."""
    from importlib.metadata import PackageNotFoundError, requires

    from ..version_info import resource_root

    try:
        pinned = next((r.split(";")[0].strip() for r in requires("appsec-verifier") or []
                       if r.startswith("playwright") and "browser" in r), "playwright==1.64.1")
    except PackageNotFoundError:
        pinned = "playwright==1.64.1"
    if (Path(prefix or sys.prefix) / "pipx_metadata.json").is_file():
        return f"pipx inject appsec-verifier {pinned}"
    python = shlex.quote(sys.executable or "python3")
    lockfile = (root or resource_root()) / "requirements.lock"
    if lockfile.is_file():
        return f"{python} -m pip install --require-hashes -r {shlex.quote(str(lockfile))}"
    return f"{python} -m pip install {pinned}"


class BrowserUnavailable(Exception):
    """The proof browser cannot run here (what is missing is the message); XSS findings cannot be proven."""


def execution_context(source, page, target, isolated=False):
    """Only execution in this check's page and effective application origin is attributable."""
    try:
        frame = source["frame"]
        # Child-frame sandbox/inheritance cannot be established from its URL alone.
        # Do not trust a page-defined window.origin property as a browser security fact.
        valid = (not isolated and source.get("page") is page and frame is page.main_frame
                 and same_origin(frame.url, target))
        parsed = urlsplit(frame.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return {"verified": bool(valid), "origin": origin if valid else "other or opaque",
                "frame": "main" if frame is page.main_frame else "child",
                "document": urlsplit(frame.url).path[:300]}
    except Exception:  # noqa: BLE001 - a detached or uninspectable frame is not proof
        return {"verified": False, "origin": "unknown", "frame": "unknown"}


class BrowserError(Exception):
    """The proof browser could not start or load the page."""


def new_marker() -> tuple[str, str]:
    """Two random parts; only their runtime concatenation counts as execution."""
    return "vrf" + secrets.token_hex(4), secrets.token_hex(4)


def marker_expression(parts: tuple[str, str]) -> str:
    """Without +, which a query string may carry as a space."""
    return f"'{parts[0]}'.concat('{parts[1]}')"


@dataclass
class Fulfil:
    status: int
    headers: dict
    body: bytes
    exchange: dict | None = field(default=None, repr=False)   # raw capture for the proof of concept


@dataclass
class Abort:
    reason: str


def answer(method: str, url: str, headers: dict, body: bytes | None, *, http, identity_headers: dict,
           target_base: str, safe: bool, timeout: float | None = None):
    """Answer one browser request through the guarded client, or abort it.
    Identity headers are added only for the target's own origin; `timeout`
    bounds the request. LimitExceeded propagates so the caller can stop the check."""
    method = (method or "GET").upper()
    if safe and method not in _SAFE_METHODS:
        return Abort(f"{method} blocked in safe/read-only mode")
    send = {k: v for k, v in (headers or {}).items() if k.lower() not in _DROP_REQUEST_HEADERS}
    if identity_headers and same_origin(url, target_base):
        for key, value in identity_headers.items():
            existing = next((k for k in send if k.lower() == key.lower()), None)
            if existing is not None and key.lower() == "cookie":
                value = f"{send.pop(existing)}; {value}"     # keep cookies the page set itself
            elif existing is not None:
                send.pop(existing)
            send[key] = value
    try:
        resp = http.request(method, url, send, purpose="target", follow_redirects=False,
                            **({"content": body} if body else {}), **({"timeout": timeout} if timeout else {}))
    except ScopeViolation as exc:
        return Abort(f"out of scope: {exc}")
    content = getattr(resp, "content", None)
    if not isinstance(content, bytes):
        content = str(getattr(resp, "text", "") or "").encode("utf-8")
    if len(content) > MAX_BODY_BYTES:
        return Abort("response exceeds the size limit")
    raw = getattr(resp, "headers", {}) or {}
    items = raw.multi_items() if hasattr(raw, "multi_items") else list(raw.items())
    out: dict[str, str] = {}
    for key, value in items:
        name = key.lower()
        if name in _DROP_RESPONSE_HEADERS:
            continue
        if name in out:
            out[name] += ("\n" if name == "set-cookie" else ", ") + str(value)
        else:
            out[name] = str(value)
    return Fulfil(int(getattr(resp, "status_code", 0) or 0), out, content,
                  capture(resp, method=method, url=url, headers=send, body=body))


def observed_values(exchanges: list[dict], observation: dict, marker_part: str, url: str) -> list[str]:
    """The selected values a read-only page observation may mark (VER-035). A visible value alone could be
    unrelated page text, so the page must have read it during this navigation, under the observation's identity,
    in a successful GET: every value when that was the cited resource; otherwise only the values that carry this
    finding's marker and do not stand in the opened URL, e.g. when a list or a search shows the marked record.
    Empty: no screenshot."""
    values = list(observation["values"])[:3]

    def read(e, value):
        return (e.get("method") == "GET" and 200 <= e.get("status", 0) < 300
                and value in e.get("content", b"").decode("utf-8", errors="replace"))

    if any(e.get("url") == observation["resource_url"] and read(e, v) for e in exchanges for v in values):
        return values
    opened = (url, unquote(url))
    return [v for v in values if marker_part and marker_part in v and not any(v in u for u in opened)
            and any(read(e, v) for e in exchanges)]


def _init_script() -> str:
    """Reports every dialog of every frame; which one counts is decided outside the page."""
    return """(() => {
  for (const name of ['alert', 'confirm', 'prompt']) {
    Object.defineProperty(window, name, { configurable: false, writable: false, value: function (message) {
      const text = String(message);
      try { window.__appsecVerifierReport(name, text); } catch (e) {}
      return name === 'confirm' ? false : null;
    } });
  }
})();"""


# VER-009: whether a marker part parsed into the DOM as markup structure rather than inert text — the text of an
# injected <script> element, or an injected event-handler (on*) attribute. This is stronger than plain reflection
# (the payload broke out of its HTML context toward script) but is not execution, so it never confirms; it is
# recorded as "indicative: breaks HTML context". The scan is conservative: a marker part sitting in ordinary text
# or a benign attribute value does not count.
_MARKUP_BREAK_SCRIPT = """(parts) => {
  try {
    for (const el of document.querySelectorAll('*')) {
      for (const p of parts) {
        if (!p) continue;
        if (el.tagName === 'SCRIPT' && (el.textContent || '').includes(p)) return true;
        for (const a of el.attributes || []) {
          if (a.name.slice(0, 2).toLowerCase() === 'on' && String(a.value).includes(p)) return true;
        }
      }
    }
  } catch (e) {}
  return false;
}"""


# Marks what a screenshot proves (VER-035): elements whose attributes or script text carry `part` (the XSS
# payload), text that equals one of `values` (access control), and a caption that says what is marked
# (`label`). The page moves clear of the caption, so it hides no mark; whatever of the page still covers the
# first mark (a dialog, a backdrop) is hidden and named in the caption. All text is set as text, never parsed as
# HTML. Returns the number of marks and what was hidden, as JSON. Without `lines` (XSS, whose frame draws the
# caption outside the page, see xss_frame) no caption is added; floating layers that do not hold the mark
# (notifications, banners, confetti) are hidden too, a bar along the top edge (the application's header) stays,
# and `crop` gives the viewport rows of the page section around the mark.
_MARK_SCRIPT = """({part, values, lines, none, color, label}) => {
  const marks = [];
  const root = document.body || document.documentElement;
  const ours = (el) => el.hasAttribute('data-appsec-verifier');
  const PANEL = 640, MIN_PANEL = 280, MAX_PANEL = 760;
  let carrier = null;
  const outline = (el) => {
    if (!el || el === root || marks.includes(el) || marks.length >= 20) return;
    el.style.setProperty('outline', '4px solid ' + color, 'important');
    el.style.setProperty('outline-offset', '2px', 'important');
    marks.push(el);
  };
  if (part) {
    for (const el of root.querySelectorAll('*')) {
      if (ours(el)) continue;
      const inAttr = Array.from(el.attributes || []).some((a) => String(a.value).includes(part));
      const inScript = el.tagName === 'SCRIPT' && (el.textContent || '').includes(part);
      if (!inAttr && !inScript) continue;
      if (carrier === null) carrier = el.outerHTML;
      outline(el.tagName === 'SCRIPT' ? el.parentElement : el);
    }
  }
  if (values && values.length) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) {
      const node = walker.currentNode, el = node.parentElement;
      if (!el || el.closest('script,style,noscript,[data-appsec-verifier]')) continue;
      const style = getComputedStyle(el);
      if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity) === 0) continue;
      if (!el.getClientRects().length || !el.checkVisibility({checkOpacity:true, checkVisibilityCSS:true})) continue;
      nodes.push(node);
    }
    for (const node of nodes) {
      for (const value of values) {
        const at = node.nodeValue.indexOf(value);
        if (at < 0 || marks.length >= 20) continue;
        const hit = node.splitText(at);
        hit.splitText(value.length);
        const mark = document.createElement('mark');
        mark.style.cssText = 'background:#ffeb3b;color:#000;outline:3px solid ' + color;
        hit.parentNode.replaceChild(mark, hit);
        mark.appendChild(hit);
        marks.push(mark);
        break;
      }
    }
  }
  const box = lines ? document.createElement('div') : null;
  if (box) {
    box.setAttribute('data-appsec-verifier', 'caption');
    const extra = (marks.length && label ? ['marked: ' + label] : [])
      .concat(carrier ? ['payload element: ' + carrier.slice(0, 300)] : (marks.length || !none ? [] : [none]));
    box.textContent = lines.concat(extra).join('\\n');
    box.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:2147483647;white-space:pre-wrap;'
      + 'word-break:break-all;background:rgba(17,17,17,.92);color:#fff;font:13px/1.4 monospace;'
      + 'padding:8px 10px;border-top:3px solid ' + color;
    root.appendChild(box);
  }
  // Without a caption, the page section around the mark: its largest ancestor that still fits a compact panel.
  let section = marks[0] || null;
  if (!box && section) {
    for (let el = section.parentElement; el && el !== root && el !== document.documentElement;
         el = el.parentElement) {
      if (el.getBoundingClientRect().height > PANEL - 32) break;
      section = el;
    }
  }
  const fit = () => {
    if (box) root.style.setProperty('margin-bottom', (box.getBoundingClientRect().height + 8) + 'px', 'important');
    const focus = box ? marks[0] : section;
    if (focus && focus.scrollIntoView) focus.scrollIntoView({block: 'center'});
  };
  fit();
  const target = marks[0], hidden = [], gone = [];
  const hide = (el) => {
    gone.push(el);
    el.style.setProperty('visibility', 'hidden', 'important');
    hidden.push((el.tagName.toLowerCase() + (el.id ? '#' + el.id : '')
      + Array.from(el.classList).slice(0, 2).map((c) => '.' + c).join('')).slice(0, 80));
  };
  if (target && document.elementsFromPoint) {
    const r = target.getBoundingClientRect();
    for (const [fx, fy] of [[0.5, 0.5], [0.15, 0.15], [0.85, 0.15], [0.15, 0.85], [0.85, 0.85]]) {
      const x = r.left + r.width * fx, y = r.top + r.height * fy;
      if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) continue;
      const stack = document.elementsFromPoint(x, y);
      const at = stack.findIndex((el) => el === target || target.contains(el));
      if (at < 0) continue;          // the mark takes no hits here, so nothing tells what covers it
      for (const el of stack.slice(0, at)) {
        if (el.contains(target) || ours(el)) continue;
        let cover = el;     // the whole layer: its outermost element that does not hold the mark
        while (cover.parentElement && !cover.parentElement.contains(target)) cover = cover.parentElement;
        if (gone.includes(cover) || gone.length >= 5) continue;
        hide(cover);
      }
    }
  }
  if (!box) {
    for (const el of root.querySelectorAll('*')) {
      if (gone.length >= 10) break;
      if (ours(el) || (target && el.contains(target)) || gone.some((g) => g.contains(el))) continue;
      const style = getComputedStyle(el);
      if (style.position !== 'fixed' || style.visibility === 'hidden' || style.display === 'none') continue;
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height || (r.top <= 0 && r.height <= 120 && r.width >= innerWidth * 0.9)) continue;
      hide(el);
    }
  }
  if (hidden.length && box) {
    box.textContent += '\\nhidden for the screenshot because it covered the mark: ' + hidden.join(', ');
    fit();
  }
  let clip = null, crop = null;
  if (!box) {
    let top = 0, bottom = Math.min(innerHeight, PANEL);
    if (section) {
      const s = section.getBoundingClientRect(), m = target.getBoundingClientRect();
      top = Math.max(0, Math.min(s.top, m.top) - 16);
      bottom = Math.min(innerHeight, Math.max(s.bottom, m.bottom) + 16, top + MAX_PANEL);
      if (bottom - top < MIN_PANEL) {
        top = Math.max(0, Math.min(top - (MIN_PANEL - (bottom - top)) / 2, innerHeight - MIN_PANEL));
        bottom = Math.min(innerHeight, top + MIN_PANEL);
      }
    }
    crop = {top: Math.round(top), height: Math.round(bottom - top)};
  }
  if (target && box) {
    const r = target.getBoundingClientRect();
    const height = box.getBoundingClientRect().height;
    if (r.width > 0 && r.height > 0 && r.height < 300 && height < 300) {
      const top = Math.max(0, r.top - 32);
      const captionTop = Math.min(innerHeight - height, r.bottom + 24);
      if (captionTop >= r.bottom) {
        box.style.setProperty('bottom', 'auto');
        box.style.setProperty('top', captionTop + 'px');
        clip = {x: 0, y: top + scrollY, width: innerWidth,
                height: Math.min(innerHeight - top, captionTop + height - top)};
      }
    }
  }
  // Page text and field values must be checked before saving an image or sending it to a model.
  const text = ((root.innerText || '') + '\\n' + Array.from(root.querySelectorAll('input,textarea'))
    .map((el) => el.value || '').join('\\n'));
  return JSON.stringify({marks: marks.length, hidden, clip, crop, carrier: carrier && carrier.slice(0, 300),
    text: text.length <= 200000 ? text : null});
}"""


_FRAME_CSS = (
    "body{margin:0;width:1280px;background:#fff;color:#1f1f1f;font:14px/1.45 system-ui,sans-serif}"
    ".bar{padding:8px 12px;background:#dee1e6}"
    ".url{background:#fff;border-radius:16px;padding:5px 14px;font:13px/1.45 monospace;word-break:break-all}"
    ".sheet{background:#dee1e6;padding:2px 0 14px}"
    ".dialog{width:460px;margin:0 auto;background:#fff;border-radius:8px;padding:16px 22px 14px;"
    "box-shadow:0 2px 8px rgba(0,0,0,.25)}"
    ".from{font-weight:600;margin-bottom:8px}.msg{font:13px/1.45 monospace;word-break:break-all}"
    ".field{border:1px solid #747775;border-radius:4px;height:22px;margin-top:8px}"
    ".buttons{text-align:right;margin-top:14px}.btn{display:inline-block;margin-left:8px;padding:4px 18px;"
    "border-radius:16px;background:#0b57d0;color:#fff}.btn.alt{background:#fff;color:#0b57d0;"
    "border:1px solid #c4c7c5}.drawn{margin-top:8px;font-size:12px;color:#5f6368;text-align:center}"
    ".page{overflow:hidden;border-top:1px solid #c4c7c5;border-bottom:1px solid #c4c7c5}.page img{display:block}"
    ".caption{background:#111;color:#fff;font:13px/1.45 monospace;padding:8px 12px;white-space:pre-wrap;"
    "word-break:break-all;border-top:3px solid " + _HIGHLIGHT + "}"
)


def xss_frame(*, url: str, image: bytes, crop: dict | None, dialog: tuple[str, str, str] | None,
              lines: list[str]) -> str:
    """The XSS evidence image as a page of its own (VER-035): an address bar with the URL the browser opened, the
    dialog the payload opened, drawn from the recorded call (`dialog` = kind, origin, message), the page section
    around the outlined payload from `image` (a 1280 by 900 viewport screenshot; `crop` gives its rows), and a
    caption below the page, so nothing covers it. All text is escaped; the page loads nothing but its image."""
    top, height = (crop["top"], crop["height"]) if crop else (0, 900)
    parts = [f'<div class=bar><div class=url>{escape(url[:2000])}</div></div>']
    if dialog:
        kind, origin, message = dialog
        buttons = '<span class="btn alt">Cancel</span><span class=btn>OK</span>' if kind != "alert" \
            else "<span class=btn>OK</span>"
        parts.append(
            f"<div class=sheet><div class=dialog><div class=from>{escape(origin)} says</div>"
            f"<div class=msg>{escape(message)}</div>{'<div class=field></div>' if kind == 'prompt' else ''}"
            f"<div class=buttons>{buttons}</div></div>"
            f"<div class=drawn>Drawn by AppSec Verifier from the recorded {escape(kind)}() call</div></div>")
    parts.append(f'<div class=page style="height:{int(height)}px"><img alt="" width=1280 height=900 '
                 f'style="margin-top:-{int(top)}px" src="data:image/png;base64,{base64.b64encode(image).decode()}">'
                 "</div>")
    parts.append(f"<div class=caption>{escape(chr(10).join(lines))}</div>")
    return ("<!doctype html><meta charset=utf-8><meta http-equiv=Content-Security-Policy content=\"default-src "
            "'none'; img-src data:; style-src 'unsafe-inline'\">"
            f"<style>{_FRAME_CSS}</style><body>{''.join(parts)}</body>")


def _launch_chrome(headless: bool):
    from playwright.sync_api import sync_playwright

    unshare, chrome = shutil.which("unshare"), _chrome_binary()
    if not sys.platform.startswith("linux") or not unshare or not chrome:
        raise BrowserUnavailable("Chrome cannot be isolated from the network here")
    playwright = sync_playwright().start()
    wrapper_dir = tempfile.mkdtemp(prefix="appsec-verifier-chrome-")   # owner-only
    try:
        wrapper = Path(wrapper_dir) / "chrome"
        wrapper.write_text(_wrapper_script(unshare, chrome), encoding="utf-8")
        wrapper.chmod(0o700)
        # Target content is untrusted: Chrome gets no network of its own (VER-018) and keeps its
        # sandbox on (Playwright turns it off by default). Playwright talks to it over a pipe.
        browser = playwright.chromium.launch(executable_path=str(wrapper), headless=headless,
                                             chromium_sandbox=True, proxy={"server": _CLOSED_PROXY},
                                             args=_CHROME_ARGS)
    except Exception:
        playwright.stop()
        raise
    finally:
        shutil.rmtree(wrapper_dir, ignore_errors=True)   # Chrome has exec'd; the wrapper is no longer needed
    return playwright, browser


class ProofBrowser:
    """One Chrome per run, started on first use; a fresh browser context per check."""

    def __init__(self, http, evidence_dir: Path, *, headless: bool = True, launcher=_launch_chrome,
                 screenshots=SCREENSHOT_CLASSES):
        self._http, self._dir, self._headless, self._launcher = http, Path(evidence_dir), headless, launcher
        self.screenshots = frozenset(screenshots)     # the classes that get screenshots (VER-035)
        # Whether a text holds a credential value or marker-file content; set by the run. Without it no
        # application screenshot is cleared for a model (VER-042).
        self.private_text = None
        self.redact = None  # Run credential redactor; marker-file content may be stored, but never sent to a model.
        self._playwright = self._browser = None
        self._counts: dict[str, int] = {}

    def _capture_error(self, marked, *texts) -> str | None:
        """Reject live screenshots with known credentials or incomplete text checks (VER-016, VER-022)."""
        if self.redact is None or not marked or not isinstance(marked.get("text"), str):
            return "the screenshot text could not be checked for credentials"
        try:
            if any(self.redact(t) != t for t in (marked["text"], *texts) if t):
                return "a credential was detected in the screenshot text"
        except Exception:  # noqa: BLE001 - omit the image, keeping the technical proof
            return "the screenshot text could not be checked for credentials"
        return None

    def _reviewable(self, marked, *texts) -> bool:
        """Whether a model may see a screenshot (VER-042): only when the page's text and every text drawn around
        it are known and none holds a credential value or the marker file's content. Fails closed."""
        if self.private_text is None or not marked or not isinstance(marked.get("text"), str):
            return False
        try:
            return not any(self.private_text(t) for t in (marked["text"], *texts) if t)
        except Exception:  # noqa: BLE001 - a check that cannot decide clears nothing
            return False

    @staticmethod
    def check_available() -> None:
        """Raise BrowserUnavailable with what is missing here and how to add it."""
        try:
            import playwright.sync_api  # noqa: F401
        except ImportError as exc:
            chrome = _chrome_binary() is not None
            raise BrowserUnavailable(("Playwright is" if chrome else "Playwright and Google Chrome are")
                                     + f" not installed; run `{_playwright_install_command()}`"
                                     + ("" if chrome else " and install Google Chrome")) from exc
        problem = _isolation_problem()
        if problem:
            raise BrowserUnavailable(problem)

    def _ensure(self):
        if self._browser is None:
            try:
                self._playwright, self._browser = self._launcher(self._headless)
            except Exception as exc:  # any launch failure leaves XSS unproven, never unconfined
                raise BrowserError(f"could not start Google Chrome: {type(exc).__name__}") from exc
        return self._browser

    def close(self) -> None:
        for closer in (self._browser, self._playwright):
            try:
                if closer is not None:
                    (closer.close if hasattr(closer, "close") else closer.stop)()
            except Exception:  # noqa: BLE001 - shutting down; nothing left to protect
                pass
        self._browser = self._playwright = None

    def _guarded(self, run, *args, **kwargs):
        """`run(...)`, with any Playwright error that escapes it (a crashed Chrome) turned into a BrowserError.
        The browser is closed, so the next use starts a new one instead of failing again."""
        from playwright.sync_api import Error as PlaywrightError

        try:
            return run(*args, **kwargs)
        except PlaywrightError as exc:
            self.close()
            raise BrowserError(f"the proof browser failed ({type(exc).__name__}); it starts again on next use") \
                from exc

    def check(self, url: str, **kwargs) -> dict:
        """Load `url` and report whether the marker executed; see `_check` for the arguments."""
        return self._guarded(self._check, url, **kwargs)

    def _check(self, url: str, *, identity_headers: dict, target_base: str, marker: tuple[str, str],
               finding_id: str, wait_ms: int, safe: bool, role: str | None = None,
               observation: dict | None = None, name: str | None = None) -> dict:
        """`finding_id` is shown in the captions, `name` (by default `finding_id`) names the files."""
        from playwright.sync_api import Error as PlaywrightError

        browser = self._ensure()
        events: list[tuple[str, str]] = []
        contexts: list[dict] = []
        attempt = secrets.token_hex(12)
        isolated_documents = set()
        blocked: list[dict] = []
        limits: list[Exception] = []
        exchanges: list[dict] = []

        def keep(request, outcome: Fulfil) -> None:
            if outcome.exchange is None or len(exchanges) >= MAX_BROWSER_EXCHANGES:
                return
            try:
                kind = request.resource_type
                navigation = request.is_navigation_request() and request.frame.parent_frame is None
            except Exception:  # noqa: BLE001 - e.g. a request without a frame; recorded without a body
                kind, navigation = "other", False
            body = outcome.exchange["content"]
            kept = kind in BODY_RESOURCE_TYPES
            exchanges.append({**outcome.exchange, "content": body[:MAX_RAW_BYTES] if kept else b"",
                              "content_size": len(body), "navigation": navigation, "keep_body": kept})

        # Chrome waits while a request is answered, so each answer is bounded: nothing after the navigation
        # time, later nothing after the wait, and no request but a document longer than PAGE_REQUEST_TIMEOUT_S.
        until = [time.monotonic() + NAVIGATION_TIMEOUT_MS / 1000]

        def on_route(route, request):
            from ..limits import LimitExceeded

            left = until[0] - time.monotonic()
            try:
                if left <= 0:
                    outcome = Abort("the check's time was up")
                else:
                    outcome = answer(request.method, request.url, request.headers, request.post_data_buffer,
                                     http=self._http, identity_headers=identity_headers, target_base=target_base,
                                     safe=safe, timeout=left if request.resource_type == "document"
                                     else min(left, PAGE_REQUEST_TIMEOUT_S))
            except LimitExceeded as exc:
                limits.append(exc)
                outcome = Abort(f"stopped by limit: {exc.kind}")
            except Exception as exc:  # noqa: BLE001 - a failed fetch aborts that request only
                outcome = Abort(f"request failed: {type(exc).__name__}")
            if isinstance(outcome, Abort):
                blocked.append({"url": request.url[:300], "reason": outcome.reason})
                route.abort("blockedbyclient")
            else:
                keep(request, outcome)
                for key, value in outcome.headers.items():
                    if key.lower() == "content-security-policy" and re.search(r"(?:^|;)\s*sandbox\b", value):
                        isolated_documents.add(request.url)
                route.fulfill(status=outcome.status, headers=outcome.headers, body=outcome.body)

        context = browser.new_context(service_workers="block", accept_downloads=False,
                                      viewport={"width": 1280, "height": 900}, device_scale_factor=1)
        try:
            context.route_web_socket(re.compile(".*"), _leave_unconnected)
            context.route("**/*", on_route)
            def on_marker(source, kind, message):
                if len(contexts) >= 20:
                    return
                observed = execution_context(source, page, url, page.url in isolated_documents)
                contexts.append({**observed, "attempt": attempt, "is_marker": message == "".join(marker)})
                if observed["verified"]:
                    events.append((str(kind), str(message)[:300]))

            context.expose_binding("__appsecVerifierReport", on_marker)
            context.add_init_script(_init_script())
            page = context.new_page()
            page.on("dialog", lambda dialog: dialog.dismiss())
            status, error = None, None
            try:
                resp = page.goto(url, wait_until="load", timeout=NAVIGATION_TIMEOUT_MS)
                status = resp.status if resp else None
            except PlaywrightError:
                error = "navigation failed or was blocked"
            wait = max(0, min(int(wait_ms), MAX_WAIT_MS))
            until[0] = min(until[0], time.monotonic() + wait / 1000)
            if not limits:
                page.wait_for_timeout(wait)
            if limits:
                raise limits[0]
            joined = marker[0] + marker[1]
            executed = any(message == joined for _, message in events)
            markup_break = False
            if not executed and error is None and observation is None:
                # VER-009: the XSS marker did not execute; record whether it still broke out of its HTML context.
                # An access-control observation carries no XSS payload, so it is not scanned.
                try:
                    markup_break = bool(page.evaluate(_MARKUP_BREAK_SCRIPT, list(marker)))
                except PlaywrightError:
                    markup_break = False
            result = {"executed": executed, "markup_break": markup_break, "status": status,
                      "final_url": page.url[:300],
                      "context_verified": executed, "attempt": attempt, "execution_contexts": contexts,
                      "dialogs": [{"kind": k, "is_marker": m == joined} for k, m in events][:20],
                      "blocked": blocked[:20], "_exchanges": exchanges}
            if error:
                result["error"] = error
            if observation is not None:
                values = observed_values(exchanges, observation, marker[0], url)
                result["evidence"] = []
                result["error"] = ("The browser read neither the cited resource nor another response with a "
                                   "selected value that carries the finding's marker, or the page did not show it.")
                application_page = any(
                    e.get("navigation") and any(k.lower() == "content-type" and "html" in v.lower()
                                                for k, v in e.get("response_headers", []))
                    for e in exchanges
                )
                if values and application_page and same_origin(page.url, url):
                    masked, problem = mask_credentials(page, self.redact, protected=values,
                                                       timeout=EVIDENCE_TIMEOUT_MS)
                    if problem:
                        result["error"] = problem
                        return result
                    lines = [f"AppSec Verifier · {finding_id} · observed exploit effect",
                             f"{url[:300]} as {role or 'anonymous'}",
                             f"captured {shown_time(datetime.now(timezone.utc).isoformat())}",
                             f"recorded proof step {observation['step']} · read-only browser observation"]
                    clean_lines = self.redact(lines)
                    masked = masked or clean_lines != lines
                    if masked:
                        clean_lines.append(MASKED_NOTE)
                    marked = self._mark(
                        page, clean_lines,
                        values=values, label="values from the confirmed proof")
                    if marked and marked["marks"]:
                        problem = self._capture_error(marked, *clean_lines)
                        if problem:
                            result["error"] = problem
                            return result
                        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                        shot = self._dir / f"{self._stem(name or finding_id, 'application')}.png"
                        try:
                            image, marked["text"] = capture_masked(page, self.redact, timeout=EVIDENCE_TIMEOUT_MS)
                        except Exception:  # noqa: BLE001 - preserve HTTP proof when the final capture is unsafe
                            result["error"] = "the application screenshot could not be safely captured"
                            return result
                        shot.write_bytes(image)
                        result["evidence"] = [self._entry(
                            shot, "screenshot", redacted=masked, credential_masked=masked, note=SCREENSHOT_NOTE,
                            presentation="application", proof_step=observation["step"],
                            finding_id=self.redact(finding_id), role=self.redact(role or "anonymous"),
                            marked=marked["marks"], source="live-browser",
                            reviewable=self._reviewable(marked, *clean_lines))]
                        result.pop("error", None)
            elif executed:
                result["evidence"] = self._save(page, finding_id, url, status, events, marker, role,
                                               execution_contexts=contexts, attempt=attempt, name=name)
                if problem := result["evidence"][0].get("screenshot_omitted"):
                    result["screenshot_error"] = problem
            return result
        finally:
            _quietly(context.close)

    def _stem(self, name: str, kind: str) -> str:
        """`<name>` for a finding's first application screenshot (XSS, application page, access-control page),
        then `<name>-2`, …; `<name>-<kind>-<n>` for the other images, e.g. `<name>-http-1`."""
        group = "page" if kind in _PAGE_KINDS else kind
        n = self._counts[(name, group)] = self._counts.get((name, group), 0) + 1
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        if group == "page":
            return safe if n == 1 else f"{safe}-{n}"
        return f"{safe}-{kind}-{n}"

    @staticmethod
    def _mark(page, lines: list[str] | None, *, part: str = "", values=(), none: str | None = None,
              label: str | None = None) -> dict | None:
        """Caption and highlights drawn over the page before its screenshot, as
        {"marks": n, "hidden": [what was hidden for the screenshot], "clip", "crop", "carrier"}; None if the page
        refused them or did not answer in time. Without `lines` no caption is drawn (see _MARK_SCRIPT). Unlike
        evaluate(), wait_for_function() has a timeout, so a page script that never returns cannot hold the check;
        the script's result is a JSON string, never falsy. The page may alter it, so every value is bounded."""
        try:
            done = page.wait_for_function(f"(arg) => ({_MARK_SCRIPT})(arg)",
                                          arg={"part": part, "values": list(values), "lines": lines, "none": none,
                                               "color": _HIGHLIGHT, "label": label},
                                          timeout=EVIDENCE_TIMEOUT_MS)
            out = json.loads(done.json_value())
            clip = out.get("clip")
            if not (isinstance(clip, dict) and set(clip) == {"x", "y", "width", "height"}
                    and all(type(v) in (int, float) and 0 <= v <= 100000 for v in clip.values())
                    and 0 < clip["width"] <= 1280 and 0 < clip["height"] <= 720):
                clip = None
            crop = out.get("crop")
            if not (isinstance(crop, dict) and set(crop) == {"top", "height"}
                    and all(type(v) is int for v in crop.values())
                    and 0 <= crop["top"] and 0 < crop["height"] <= 760 and crop["top"] + crop["height"] <= 900):
                crop = None
            carrier, text = out.get("carrier"), out.get("text")
            return {"marks": int(out["marks"]), "hidden": [str(h)[:80] for h in out.get("hidden") or []][:5],
                    "clip": clip, "crop": crop, "carrier": carrier[:300] if isinstance(carrier, str) else None,
                    "text": text if isinstance(text, str) and len(text) <= 200000 else None}
        except Exception:  # noqa: BLE001 - live images need checked text; redacted records may render unmarked
            return None

    @staticmethod
    def _entry(path: Path, kind: str, **extra) -> dict:
        path.chmod(0o600)
        return {"kind": kind, "path": f"evidence/{path.name}",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **extra}

    def _save(self, page, finding_id: str, url: str, status, events, marker: tuple[str, str],
              role: str | None, *, execution_contexts=None, attempt=None, name: str | None = None) -> list[dict]:
        from playwright.sync_api import Error as PlaywrightError

        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        joined = marker[0] + marker[1]
        stem = self._stem(name or finding_id, "xss")
        record = self._dir / f"{stem}.json"
        captured = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        via = sorted({k for k, m in events if m == joined})
        data = {"finding_id": finding_id, "url": url, "status": status, "marker": joined, "executed_via": via,
                "captured": captured, "execution_contexts": execution_contexts or [], "attempt": attempt}
        shot, reviewable, masked = None, False, False
        if "xss" in self.screenshots:
            masked, problem = mask_credentials(page, self.redact, protected=(*marker, joined),
                                               timeout=EVIDENCE_TIMEOUT_MS)
            # The page gets only the outline; address bar, dialog and caption are drawn around it (xss_frame).
            marked = self._mark(page, None, part=marker[0]) if not problem else None
            data["marked_elements"] = marked["marks"] if marked else None
            if marked and marked["hidden"]:
                data["hidden_for_screenshot"] = marked["hidden"]
            origin = next((c["origin"] for c in execution_contexts or []
                           if c.get("verified") and c.get("is_marker")), url)
            lines = [f"AppSec Verifier · {finding_id} · XSS · as {role or 'anonymous'} · HTTP {status} · "
                     f"captured {shown_time(captured)}"]
            if via:
                lines.append("The dialog shows a random value the payload assembled at runtime; a page that "
                             "only echoed the payload would show the expression.")
            lines.append(f"Outlined: payload element {marked['carrier']}" if marked and marked["carrier"]
                         else "(the element that carries the payload was not found in the page)")
            if marked and marked["hidden"]:
                lines.append("Hidden for the screenshot: " + ", ".join(marked["hidden"]))
            image = None
            # Decode before redaction: the displayed URL must not decode a masked value back into a secret.
            display = [unquote(url), origin, *lines]
            try:
                clean = self.redact(display) if self.redact is not None else display
                masked = masked or clean != display
                display_url, display_origin, *lines = clean
                if masked:
                    lines.append(MASKED_NOTE)
            except Exception:  # noqa: BLE001 - no capture without checked captions
                problem = "the screenshot captions could not be checked for credentials"
            problem = problem or self._capture_error(marked, display_url, display_origin, joined, *lines)
            if problem:
                data["screenshot_omitted"] = problem
            else:
                try:
                    image, marked["text"] = capture_masked(page, self.redact, timeout=EVIDENCE_TIMEOUT_MS)
                except Exception:  # noqa: BLE001 - retain execution when the final capture cannot be checked
                    data["screenshot_omitted"] = "the application screenshot could not be safely captured"
            if image is not None:
                frame = xss_frame(url=display_url, image=image, crop=marked["crop"] if marked else None,
                                  dialog=(via[0], urlsplit(display_origin).netloc or display_origin, joined)
                                  if via else None,
                                  lines=lines)
                reviewable = self._reviewable(marked, display_url, display_origin, joined, *lines)
                shot = self._dir / f"{stem}.png"
                try:
                    framed, _ = self._shoot_recorded(url=_EXCHANGE_PAGE, status=200,
                                                     content_type="text/html; charset=utf-8", body=frame,
                                                     name=stem, kind="xss", full_page=True,
                                                     width=1280, path=shot)
                except PlaywrightError:
                    framed = None
                if framed is None:
                    shot = None
                    data["screenshot_omitted"] = "the browser could not render the labelled screenshot"
            data["credential_masked"] = masked
        if self.redact is not None:
            try:
                data = self.redact(data)
            except Exception:  # noqa: BLE001 - retain execution facts without unchecked page metadata
                data = {k: data[k] for k in ("status", "marker", "executed_via", "captured", "screenshot_omitted")
                        if k in data}
        record.write_text(json.dumps(data, indent=2), encoding="utf-8")
        entries = [self._entry(record, "browser-event", **(
            {"screenshot_omitted": data["screenshot_omitted"]} if data.get("screenshot_omitted") else {}))]
        if shot is not None:
            entries.append(self._entry(shot, "screenshot", redacted=masked, credential_masked=masked,
                                       note=SCREENSHOT_NOTE, finding_id=data.get("finding_id"),
                                       role=self.redact(role or "anonymous"),
                                       presentation="application", source="live-browser",
                                       executed_via=via, marked=data.get("marked_elements"),
                                       reviewable=reviewable))
        return entries

    def _shoot_recorded(self, *, url: str, status: int, content_type: str, body: str, name: str,
                        kind: str, mark=None, full_page: bool = False, width: int = 1200, path: Path | None = None,
                        check_credentials: bool = False):
        """Screenshot of a page answered from a record: the navigation gets `body`, every other request is
        aborted and scripts are off, so nothing reaches the target. Saved at `path`, by default the next name
        `_stem` gives `name` and `kind`. Returns (path, marks) or (None, None)."""
        from playwright.sync_api import Error as PlaywrightError

        browser = self._ensure()
        served: list[bool] = []

        def on_route(route, request):
            if not served and request.is_navigation_request():
                served.append(True)
                route.fulfill(status=status if 200 <= int(status or 0) < 600 else 200,
                              headers={"content-type": content_type or "text/html"}, body=body.encode("utf-8"))
            else:
                route.abort("blockedbyclient")

        context = browser.new_context(service_workers="block", accept_downloads=False, java_script_enabled=False,
                                      viewport={"width": width, "height": 720}, device_scale_factor=1)
        try:
            context.route_web_socket(re.compile(".*"), _leave_unconnected)
            context.route("**/*", on_route)
            page = context.new_page()
            try:
                page.goto(url, wait_until="load", timeout=NAVIGATION_TIMEOUT_MS)
            except PlaywrightError:
                return None, None
            marked = mark(page) if mark is not None else None
            if check_credentials and (not marked or marked.get("error")):
                return None, marked
            if full_page:              # as tall as the content: a short page leaves no empty window below it
                page.set_viewport_size({"width": page.viewport_size["width"], "height": 1})
            self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            shot = path or self._dir / f"{self._stem(name, kind)}.png"
            if check_credentials:
                try:
                    image, marked["text"] = capture_masked(page, self.redact, timeout=EVIDENCE_TIMEOUT_MS,
                                                          clip=marked.get("clip"))
                except Exception:  # noqa: BLE001 - keep the recorded HTTP proof without an unchecked image
                    return None, marked
                shot.write_bytes(image)
            else:
                page.screenshot(path=str(shot), full_page=full_page,
                                **({"clip": marked["clip"]} if marked and marked.get("clip") else {}))
            return shot, marked
        finally:
            _quietly(context.close)

    def render(self, *, url: str, status: int, content_type: str, html: str, name: str,
               caption: list[str], highlight=()) -> list[dict]:
        """A screenshot of a recorded HTML response for an access-control proof (VER-035)."""
        none = "(no highlighted value was found in the page)" if highlight else None

        def mark(page):
            masked, problem = mask_credentials(page, self.redact, protected=highlight, timeout=EVIDENCE_TIMEOUT_MS)
            if problem:
                return {"error": problem}
            lines = self.redact(caption)
            masked = masked or lines != caption
            if masked:
                lines.append(MASKED_NOTE)
            marked = self._mark(page, lines, values=highlight, none=none, label="value named in the verdict")
            return {**marked, "credential_masked": masked} if marked else None

        shot, marked = self._guarded(
            self._shoot_recorded,
            url=url, status=status, content_type=content_type, body=html, name=name,
            kind="access-control", mark=mark, check_credentials=True)
        return [] if shot is None else [self._entry(shot, "screenshot", redacted=True, note=SCREENSHOT_NOTE,
                                                    credential_masked=marked.get("credential_masked", False),
                                                    presentation="application", source="recorded-html",
                                                    marked=marked["marks"] if marked else None,
                                                    reviewable=self._reviewable(marked))]

    def render_exchanges(self, *, html: str, name: str, marked: int, kind: str = "http") -> list[dict]:
        """A screenshot of the page verify/poc.py built from a finding's recorded exchanges (VER-035), or with
        kind "explanation" of an evidence review's explanation panel (VER-042)."""
        shot, _ = self._guarded(self._shoot_recorded, url=_EXCHANGE_PAGE, status=200,
                                content_type="text/html; charset=utf-8", body=html, name=name,
                                kind=kind, full_page=True)
        return [] if shot is None else [self._entry(shot, "screenshot", redacted=True, note=SCREENSHOT_NOTE,
                                                    marked=marked)]
