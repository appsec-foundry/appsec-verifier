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
and host resolution is disabled; WebSockets and service workers are blocked.
Chrome runs with its sandbox on. Where the namespace or the sandbox is not
available, the browser does not start and XSS stays unproven.

Only evaluation proves execution: the payload must call alert() with an
expression that joins the two marker parts at runtime, and only a dialog whose
message equals the joined marker counts. A page that merely echoes the payload
text shows the expression, not its value. On execution a banner is drawn, and
one screenshot plus a JSON event record are saved owner-only under evidence/.
Screenshots can show target data, so their evidence entry says so.
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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .http import ScopeViolation, same_origin

_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_WAIT_MS = 5000
NAVIGATION_TIMEOUT_MS = 30_000
_DROP_REQUEST_HEADERS = {"host", "content-length", "connection"}
_DROP_RESPONSE_HEADERS = {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
_CLOSED_PROXY = "http://127.0.0.1:9"
_CHROME_ARGS = ["--host-resolver-rules=MAP * ~NOTFOUND", "--no-pings", "--disable-background-networking",
                "--disable-domain-reliability", "--disable-sync"]
# A new user and network namespace with the caller's uid: no network but loopback, and
# Chrome is not root inside it, so its own sandbox still starts.
_NETNS_ARGS = ("--user", "--net", "--map-current-user")
SCREENSHOT_NOTE = "may show target data; review before sharing"


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


class BrowserUnavailable(Exception):
    """Playwright is not installed; XSS findings cannot be proven in this run."""


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


@dataclass
class Abort:
    reason: str


def answer(method: str, url: str, headers: dict, body: bytes | None, *, http, identity_headers: dict,
           target_base: str, safe: bool):
    """Answer one browser request through the guarded client, or abort it.
    Identity headers are added only for the target's own origin. LimitExceeded
    propagates so the caller can stop the check."""
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
                            **({"content": body} if body else {}))
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
    return Fulfil(int(getattr(resp, "status_code", 0) or 0), out, content)


def _init_script(parts: tuple[str, str]) -> str:
    return """(() => {
  const marker = __MARKER__;
  const banner = () => { try {
    const d = document.createElement('div');
    d.textContent = 'AppSec Verifier: XSS marker ' + marker + ' executed';
    d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b00020;'
      + 'color:#fff;font:bold 16px sans-serif;padding:8px';
    (document.body || document.documentElement).appendChild(d);
  } catch (e) {} };
  for (const name of ['alert', 'confirm', 'prompt']) {
    Object.defineProperty(window, name, { configurable: false, writable: false, value: function (message) {
      const text = String(message);
      try { window.__appsecVerifierReport(name, text); } catch (e) {}
      if (text === marker) banner();
      return name === 'confirm' ? false : null;
    } });
  }
})();""".replace("__MARKER__", json.dumps(parts[0] + parts[1]))


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

    def __init__(self, http, evidence_dir: Path, *, headless: bool = True, launcher=_launch_chrome):
        self._http, self._dir, self._headless, self._launcher = http, Path(evidence_dir), headless, launcher
        self._playwright = self._browser = None
        self._counts: dict[str, int] = {}

    @staticmethod
    def check_available() -> None:
        try:
            import playwright.sync_api  # noqa: F401
        except ImportError as exc:
            raise BrowserUnavailable("install appsec-verifier[browser] (Playwright) and Google Chrome") from exc
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

    def check(self, url: str, *, identity_headers: dict, target_base: str, marker: tuple[str, str],
              finding_id: str, wait_ms: int, safe: bool) -> dict:
        from playwright.sync_api import Error as PlaywrightError

        browser = self._ensure()
        events: list[tuple[str, str]] = []
        blocked: list[dict] = []
        limits: list[Exception] = []

        def on_route(route, request):
            from ..limits import LimitExceeded

            try:
                outcome = answer(request.method, request.url, request.headers, request.post_data_buffer,
                                 http=self._http, identity_headers=identity_headers, target_base=target_base,
                                 safe=safe)
            except LimitExceeded as exc:
                limits.append(exc)
                outcome = Abort(f"stopped by limit: {exc.kind}")
            except Exception as exc:  # noqa: BLE001 - a failed fetch aborts that request only
                outcome = Abort(f"request failed: {type(exc).__name__}")
            if isinstance(outcome, Abort):
                blocked.append({"url": request.url[:300], "reason": outcome.reason})
                route.abort("blockedbyclient")
            else:
                route.fulfill(status=outcome.status, headers=outcome.headers, body=outcome.body)

        context = browser.new_context(service_workers="block", accept_downloads=False)
        try:
            context.route_web_socket(re.compile(".*"), lambda ws: ws.close())
            context.route("**/*", on_route)
            context.expose_binding("__appsecVerifierReport",
                                   lambda source, kind, message: events.append((str(kind), str(message)[:300])))
            context.add_init_script(_init_script(marker))
            page = context.new_page()
            page.on("dialog", lambda dialog: dialog.dismiss())
            status, error = None, None
            try:
                resp = page.goto(url, wait_until="load", timeout=NAVIGATION_TIMEOUT_MS)
                status = resp.status if resp else None
            except PlaywrightError:
                error = "navigation failed or was blocked"
            if not limits:
                page.wait_for_timeout(max(0, min(int(wait_ms), MAX_WAIT_MS)))
            if limits:
                raise limits[0]
            joined = marker[0] + marker[1]
            executed = any(message == joined for _, message in events)
            result = {"executed": executed, "status": status, "final_url": page.url[:300],
                      "dialogs": [{"kind": k, "is_marker": m == joined} for k, m in events][:20],
                      "blocked": blocked[:20]}
            if error:
                result["error"] = error
            if executed:
                result["evidence"] = self._save(page, finding_id, url, status, events, joined)
            return result
        finally:
            context.close()

    def _save(self, page, finding_id: str, url: str, status, events, joined: str) -> list[dict]:
        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        n = self._counts[finding_id] = self._counts.get(finding_id, 0) + 1
        stem = f"{re.sub(r'[^A-Za-z0-9_.-]', '_', finding_id)}-xss-{n}"
        shot, record = self._dir / f"{stem}.png", self._dir / f"{stem}.json"
        page.screenshot(path=str(shot))
        record.write_text(json.dumps({
            "finding_id": finding_id, "url": url, "status": status, "marker": joined,
            "executed_via": sorted({k for k, m in events if m == joined}),
            "captured": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }, indent=2), encoding="utf-8")
        entries = []
        for path, kind in ((record, "browser-event"), (shot, "screenshot")):
            path.chmod(0o600)
            entry = {"kind": kind, "path": f"evidence/{path.name}",
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            if kind == "screenshot":
                entry.update(redacted=False, note=SCREENSHOT_NOTE)
            entries.append(entry)
        return entries
