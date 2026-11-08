"""Proof browser for XSS findings (VER-009, VER-018, VER-022).

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
text shows the expression, not its value. On execution a banner is drawn and a
JSON event record is saved owner-only under evidence/, with a screenshot when
screenshots are on for XSS (VER-035): a caption names finding, URL, identity
and time, the elements that carry the payload are outlined and a tag with an
arrow points at the first, the banner stands on the top page also when the
payload ran in a frame, and what of the page covered the payload (a dialog, a
backdrop) is hidden and named in the caption. Each request
the guarded client answered is handed back for the proof of concept (VER-034),
bodies only for documents, XHR and fetch.

`render` screenshots a recorded HTML response for an access-control proof,
`render_exchanges` the page verify/poc.py builds from a finding's recorded
exchanges for every other screenshot (VER-035). Either page is answered from
the record, every other request is aborted and scripts are off, so they send
nothing to the target. Screenshots can show target data, so their evidence
entry says so.

A Playwright error outside the page load, such as a crashed Chrome, is a
BrowserError and closes the browser; the next use starts a new one. A check
ends in bounded time even on a page that never finishes: loading has
NAVIGATION_TIMEOUT_MS, a page request other than a document at most
PAGE_REQUEST_TIMEOUT_S (a long poll), nothing is answered after the wait, and
marking and screenshot have EVIDENCE_TIMEOUT_MS each; a page that does not
answer keeps its event record without a screenshot.
"""

from __future__ import annotations

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
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..verify.poc import BODY_RESOURCE_TYPES, MAX_BROWSER_EXCHANGES, MAX_RAW_BYTES, TARGET_DATA_NOTE, capture
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
    return f"'{parts[0]}'+'{parts[1]}'"


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


def _init_script(parts: tuple[str, str]) -> str:
    return """(() => {
  const marker = __MARKER__;
  const banner = () => { try {
    const d = document.createElement('div');
    d.id = '__appsec_verifier_banner';
    d.textContent = 'AppSec Verifier: XSS marker ' + marker + ' executed';
    d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b00020;'
      + 'color:#fff;font:bold 16px sans-serif;padding:8px';
    (document.body || document.documentElement).appendChild(d);
  } catch (e) {} };
  for (const name of ['alert', 'confirm', 'prompt']) {
    Object.defineProperty(window, name, { configurable: false, writable: false, value: function (message) {
      const text = String(message);
      try { window.__appsecVerifierReport(name, text); } catch (e) {}
      if (text === marker && window === window.top) banner();     // in a frame the screenshot draws it on top
      return name === 'confirm' ? false : null;
    } });
  }
})();""".replace("__MARKER__", json.dumps(parts[0] + parts[1]))


# Marks what a screenshot proves (VER-035): elements whose attributes or script text carry `part` (the XSS
# payload, also quoted in the caption), text that equals one of `values` (access control), and a caption.
# `banner` is drawn on the top page when the payload ran in a frame. The page moves clear of the banner and
# the caption, so neither hides a mark; whatever of the page still covers the first mark (a dialog, a
# backdrop) is hidden and named in the caption, and a tag with an arrow and `label` points at that mark.
# All text is set as text, never parsed as HTML. Returns the number of marks and what was hidden, as JSON.
_MARK_SCRIPT = """({part, values, lines, none, color, banner, label}) => {
  const marks = [];
  const root = document.body || document.documentElement;
  const ours = (el) => el.id === '__appsec_verifier_banner' || el.hasAttribute('data-appsec-verifier');
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
    while (walker.nextNode()) nodes.push(walker.currentNode);
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
  if (banner && !document.getElementById('__appsec_verifier_banner')) {
    const b = document.createElement('div');
    b.id = '__appsec_verifier_banner';
    b.textContent = banner;
    b.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:' + color + ';'
      + 'color:#fff;font:bold 16px sans-serif;padding:8px';
    root.appendChild(b);
  }
  const box = document.createElement('div');
  box.setAttribute('data-appsec-verifier', 'caption');
  const extra = carrier ? ['payload element: ' + carrier.slice(0, 300)] : (marks.length || !none ? [] : [none]);
  box.textContent = lines.concat(extra).join('\\n');
  box.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:2147483647;white-space:pre-wrap;'
    + 'word-break:break-all;background:rgba(17,17,17,.92);color:#fff;font:13px/1.4 monospace;'
    + 'padding:8px 10px;border-top:3px solid ' + color;
  root.appendChild(box);
  const bar = document.getElementById('__appsec_verifier_banner');
  const fit = () => {
    root.style.setProperty('margin-top', ((bar ? bar.getBoundingClientRect().height : 0) + 8) + 'px', 'important');
    root.style.setProperty('margin-bottom', (box.getBoundingClientRect().height + 8) + 'px', 'important');
    if (marks[0] && marks[0].scrollIntoView) marks[0].scrollIntoView({block: 'center'});
  };
  fit();
  const target = marks[0], hidden = [], gone = [];
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
        gone.push(cover);
        cover.style.setProperty('visibility', 'hidden', 'important');
        hidden.push((cover.tagName.toLowerCase() + (cover.id ? '#' + cover.id : '')
          + Array.from(cover.classList).slice(0, 2).map((c) => '.' + c).join('')).slice(0, 80));
      }
    }
  }
  if (hidden.length) {
    box.textContent += '\\nhidden for the screenshot because it covered the mark: ' + hidden.join(', ');
    fit();
  }
  if (target && label) {
    const r = target.getBoundingClientRect();
    const tag = document.createElement('div');
    tag.setAttribute('data-appsec-verifier', 'label');
    tag.style.cssText = 'position:fixed;z-index:2147483647;background:' + color + ';color:#fff;'
      + 'font:bold 14px sans-serif;padding:3px 8px;border-radius:3px;white-space:nowrap;pointer-events:none';
    tag.textContent = '▼ ' + label;
    root.appendChild(tag);
    const h = tag.getBoundingClientRect().height;
    const above = r.top - h - 8 > (bar ? bar.getBoundingClientRect().bottom : 0);
    if (!above) tag.textContent = '▲ ' + label;
    tag.style.left = Math.max(0, Math.min(r.left, innerWidth - tag.getBoundingClientRect().width)) + 'px';
    tag.style.top = (above ? r.top - h - 8 : r.bottom + 8) + 'px';
  }
  return JSON.stringify({marks: marks.length, hidden});
}"""


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
        self._playwright = self._browser = None
        self._counts: dict[str, int] = {}

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
               finding_id: str, wait_ms: int, safe: bool, role: str | None = None) -> dict:
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

        context = browser.new_context(service_workers="block", accept_downloads=False)
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
            context.add_init_script(_init_script(marker))
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
            result = {"executed": executed, "status": status, "final_url": page.url[:300],
                      "context_verified": executed, "attempt": attempt, "execution_contexts": contexts,
                      "dialogs": [{"kind": k, "is_marker": m == joined} for k, m in events][:20],
                      "blocked": blocked[:20], "_exchanges": exchanges}
            if error:
                result["error"] = error
            if executed:
                result["evidence"] = self._save(page, finding_id, url, status, events, marker, role,
                                               execution_contexts=contexts, attempt=attempt)
            return result
        finally:
            _quietly(context.close)

    def _stem(self, finding_id: str, kind: str) -> str:
        n = self._counts[(finding_id, kind)] = self._counts.get((finding_id, kind), 0) + 1
        return f"{re.sub(r'[^A-Za-z0-9_.-]', '_', finding_id)}-{kind}-{n}"

    @staticmethod
    def _mark(page, lines: list[str], *, part: str = "", values=(), none: str | None = None,
              banner: str | None = None, label: str | None = None) -> dict | None:
        """Caption, highlights, banner and label drawn over the page before its screenshot, as
        {"marks": n, "hidden": [what was hidden because it covered the first mark]}; None if the page refused
        them or did not answer in time. Unlike evaluate(), wait_for_function() has a timeout, so a page script
        that never returns cannot hold the check; the script's result is a JSON string, never falsy."""
        try:
            done = page.wait_for_function(f"(arg) => ({_MARK_SCRIPT})(arg)",
                                          arg={"part": part, "values": list(values), "lines": lines, "none": none,
                                               "color": _HIGHLIGHT, "banner": banner, "label": label},
                                          timeout=EVIDENCE_TIMEOUT_MS)
            out = json.loads(done.json_value())
            return {"marks": int(out["marks"]), "hidden": [str(h)[:80] for h in out.get("hidden") or []][:5]}
        except Exception:  # noqa: BLE001 - the screenshot is still taken, unmarked
            return None

    @staticmethod
    def _entry(path: Path, kind: str, **extra) -> dict:
        path.chmod(0o600)
        return {"kind": kind, "path": f"evidence/{path.name}",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **extra}

    def _save(self, page, finding_id: str, url: str, status, events, marker: tuple[str, str],
              role: str | None, *, execution_contexts=None, attempt=None) -> list[dict]:
        from playwright.sync_api import Error as PlaywrightError

        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        joined = marker[0] + marker[1]
        stem = self._stem(finding_id, "xss")
        record = self._dir / f"{stem}.json"
        captured = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        via = sorted({k for k, m in events if m == joined})
        data = {"finding_id": finding_id, "url": url, "status": status, "marker": joined, "executed_via": via,
                "captured": captured, "execution_contexts": execution_contexts or [], "attempt": attempt}
        shot = None
        if "xss" in self.screenshots:
            marked = self._mark(
                page, [f"AppSec Verifier · {finding_id} · XSS marker {joined} executed via {', '.join(via)}",
                       f"{unquote(url)[:300]} as {role or 'anonymous'} → {status}", f"captured {captured}"],
                part=marker[0], none="(the element that carries the payload was not found in the page)",
                banner=f"AppSec Verifier: XSS marker {joined} executed", label="payload that executed")
            data["marked_elements"] = marked["marks"] if marked else None
            if marked and marked["hidden"]:
                data["hidden_for_screenshot"] = marked["hidden"]
            shot = self._dir / f"{stem}.png"
            try:
                page.screenshot(path=str(shot), timeout=EVIDENCE_TIMEOUT_MS)
            except PlaywrightError:      # a page that does not answer: the event record still proves execution
                shot = None
        record.write_text(json.dumps(data, indent=2), encoding="utf-8")
        entries = [self._entry(record, "browser-event")]
        if shot is not None:
            entries.append(self._entry(shot, "screenshot", redacted=False, note=SCREENSHOT_NOTE))
        return entries

    def _shoot_recorded(self, *, url: str, status: int, content_type: str, body: str, finding_id: str,
                        kind: str, mark=None, full_page: bool = False):
        """Screenshot of a page answered from a record: the navigation gets `body`, every other request is
        aborted and scripts are off, so nothing reaches the target. Returns (path, marks) or (None, None)."""
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

        context = browser.new_context(service_workers="block", accept_downloads=False, java_script_enabled=False)
        try:
            context.route_web_socket(re.compile(".*"), _leave_unconnected)
            context.route("**/*", on_route)
            page = context.new_page()
            try:
                page.goto(url, wait_until="load", timeout=NAVIGATION_TIMEOUT_MS)
            except PlaywrightError:
                return None, None
            marked = mark(page) if mark is not None else None
            self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            shot = self._dir / f"{self._stem(finding_id, kind)}.png"
            page.screenshot(path=str(shot), full_page=full_page)
            return shot, marked
        finally:
            _quietly(context.close)

    def render(self, *, url: str, status: int, content_type: str, html: str, finding_id: str,
               caption: list[str], highlight=()) -> list[dict]:
        """A screenshot of a recorded HTML response for an access-control proof (VER-035)."""
        none = "(no highlighted value was found in the page)" if highlight else None
        shot, marked = self._guarded(
            self._shoot_recorded,
            url=url, status=status, content_type=content_type, body=html, finding_id=finding_id,
            kind="access-control", mark=lambda page: self._mark(page, caption, values=highlight, none=none,
                                                                label="value named in the verdict"))
        return [] if shot is None else [self._entry(shot, "screenshot", redacted=True, note=SCREENSHOT_NOTE,
                                                    marked=marked["marks"] if marked else None)]

    def render_exchanges(self, *, html: str, finding_id: str, marked: int) -> list[dict]:
        """A screenshot of the page verify/poc.py built from a finding's recorded exchanges (VER-035)."""
        shot, _ = self._guarded(self._shoot_recorded, url=_EXCHANGE_PAGE, status=200,
                                content_type="text/html; charset=utf-8", body=html, finding_id=finding_id,
                                kind="exchange", full_page=True)
        return [] if shot is None else [self._entry(shot, "screenshot", redacted=True, note=SCREENSHOT_NOTE,
                                                    marked=marked)]
