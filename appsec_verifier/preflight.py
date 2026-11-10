"""Pre-flight checks and the authorisation gate (VER-002, VER-003, VER-016,
VER-028, VER-029, VER-032).

Before a run asks a model for a step it checks what the run depends on
(VER-032). The offline checks (assessment, scope, proxy settings, identities
file, model profile) run in cli.py; this module holds the gate, one offline
check for a source checkout, and the checks that contact something:

- `confirm_authorization`: one explicit confirmation before the first request
  to the target. Silence, a timeout, or a non-interactive run without the CI
  flag do not count (VER-002).
- `check_target`: one GET to the target URL through the GuardedHttpClient, so
  scope, address check, proxy and budget apply as in the run (VER-003, VER-029).
- `check_identities`: one login per identity that has one, never retried, and
  one request with its credentials to its `check_url`, only on the origin the
  credentials belong to (VER-028). A sign-in that needs a person happens here,
  before the first finding; a login program starts here (VER-040).
- `check_accounts`: two roles whose tokens name the same account cannot show an
  access-control contrast, so the run stops (VER-010, VER-032).
- `check_source`: only with `--source`, that the path is a readable directory.
  Offline; its contents are never read here, and that the agent will find a
  finding's code there is not proved (VER-032).
- `generation_test`: only on request, one fixed prompt without target data,
  findings or credentials; the reply must pass the host's confinement checks
  and `parse_step` (VER-017, VER-019).

A failure is reported by a fixed cause and the HTTP status. Raw errors and
response bodies are never shown, because they can carry proxy credentials or
tokens (VER-016), and every message passes `printable` on its way to the
terminal. I/O (the prompt, the transport, the host) is injected, so all of it is
testable offline.
"""

from __future__ import annotations

import socket
import ssl
import textwrap
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .auth import AuthError
from .auth.sessions import LOGIN_METHODS
from .limits import LimitExceeded
from .term_style import Style, columns
from .tools import ScopeViolation, same_origin

GENERATION_TIMEOUT_S = 60.0
_MARKS = {"ok": ("✓", "ok"), "warn": ("⚠", "warn"), "fail": ("✗", "critical"), "info": ("·", "muted")}
_LABEL_WIDTH = 12


@dataclass
class Confirmation:
    confirmed: bool
    mode: str          # "interactive" | "ci-flag"
    reason: str


def confirm_authorization(*, non_interactive: bool, assume_yes: bool, default_yes: bool = False,
                          prompt=input) -> Confirmation:
    """Decide whether the run is authorised to start.

    - ``--yes`` confirms without a prompt and is recorded as ``ci-flag``.
    - A non-interactive run without ``--yes`` is NOT confirmed (it must not
      prompt and must not assume consent).
    - An interactive run asks once; only an explicit yes confirms, or Enter
      with ``default_yes``, which only the guided run sets.
    """
    if assume_yes:
        return Confirmation(True, "ci-flag", "authorised by explicit flag")
    if non_interactive:
        return Confirmation(False, "ci-flag", "non-interactive run without --yes: not confirmed")
    try:
        answer = prompt(f"Proceed against this target? [{'Y/n' if default_yes else 'y/N'}] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return Confirmation(False, "interactive", "no input available: not confirmed")
    if answer in ("y", "yes") or (default_yes and not answer):
        return Confirmation(True, "interactive", "confirmed at the prompt")
    return Confirmation(False, "interactive", "declined at the prompt")


# ── results ────────────────────────────────────────────────────────────────────

@dataclass
class Check:
    label: str
    status: str        # ok | warn | fail | info
    message: str

    def as_dict(self) -> dict:
        return {"check": printable(self.label), "status": self.status, "message": printable(self.message)}


def printable(text) -> str:
    """`text` without control and format characters (escape sequences, bidi
    overrides), for anything from an input file or a target on its way to the terminal."""
    return "".join(ch for ch in str(text) if unicodedata.category(ch) not in ("Cc", "Cf"))


def render(checks: list[Check], st: Style | None = None) -> str:
    """One `  ✓ Label  message` row per check. On a terminal the mark takes the
    colour of its status and a long message wraps under its own column."""
    st = st or Style(False)
    indent = 2 + 2 + _LABEL_WIDTH + 1
    fit = columns() - 1 - indent if st.enabled else 0
    lines = []
    for c in checks:
        mark, role = _MARKS[c.status]
        message = printable(c.message)
        pieces = (textwrap.wrap(message, fit, break_long_words=False, break_on_hyphens=False)
                  if fit > 20 and len(message) > fit else [message])
        lines.append(f"  {st(mark, role)} {st(f'{printable(c.label):<{_LABEL_WIDTH}}', 'muted')} {pieces[0]}")
        lines += [" " * indent + piece for piece in pieces[1:]]
    return "\n".join(lines)


def failed(checks: list[Check]) -> bool:
    return any(c.status == "fail" for c in checks)


# ── target (VER-003, VER-029) ──────────────────────────────────────────────────

def proxy_for(scope: dict, url: str) -> str | None:
    """`host:port` of the scope's proxy when requests to `url` go through it, else
    None. Never the proxy's credentials."""
    proxy = scope.get("proxy") or {}
    if not proxy.get("url"):
        return None
    direct = {str(h).strip().strip("[]").lower() for h in proxy.get("no_proxy") or []}
    try:
        if (urlsplit(url).hostname or "").lower() in direct:
            return None
        parts = urlsplit(proxy["url"])
        return f"{parts.hostname}:{parts.port or {'https': 443}.get(parts.scheme, 80)}"
    except ValueError:
        return "the declared proxy"


def _chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    while exc is not None and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def _cause(exc: Exception, proxy: str | None) -> str:
    """A fixed cause for a failed request. The error text is not used: it can
    carry the proxy URL with its credentials."""
    if isinstance(exc, ScopeViolation):
        return f"refused by the scope: {exc}"
    if isinstance(exc, LimitExceeded):
        return f"stopped by a limit: {exc}"
    if isinstance(exc, httpx.ProxyError):
        code = str(exc)[:3]
        if code == "407":
            return f"the proxy {proxy} requires authentication (HTTP 407); check username_env and password_env"
        return f"the proxy {proxy} refused the connection" + (f" (HTTP {code})" if code.isdigit() else "")
    peer = f"the proxy {proxy}" if proxy else "the server"
    if isinstance(exc, httpx.ConnectTimeout):
        return f"no connection to {peer} in time"
    if isinstance(exc, httpx.TimeoutException):
        return "no answer in time"
    chain = _chain(exc)
    if any(isinstance(e, socket.gaierror) for e in chain):
        return f"the host name of {peer} does not resolve"
    if any(isinstance(e, ssl.SSLCertVerificationError) for e in chain):
        return "the TLS certificate is not accepted"
    if any(isinstance(e, ssl.SSLError) for e in chain):
        return "the TLS handshake failed"
    if any(isinstance(e, ConnectionRefusedError) for e in chain):
        return f"{peer} refused the connection"
    if isinstance(exc, httpx.ConnectError):
        return f"no connection to {peer}"
    return f"the request failed ({type(exc).__name__})"


_REQUEST_ERRORS = (httpx.HTTPError, ScopeViolation, LimitExceeded)


def check_target(http, url: str, *, proxy: str | None) -> Check:
    """One GET to the target URL; any HTTP answer means it is reachable (VER-003).
    A redirect is not followed."""
    from .tools.httpx_transport import MAX_RESPONSE_BYTES, ResponseTooLarge

    via = f" via proxy {proxy}" if proxy else ""
    try:
        resp = http.request("GET", url, {}, purpose="target", follow_redirects=False)
    except ResponseTooLarge:      # an answer all the same; the run reads none larger than this
        return Check("Target", "warn", f"{url} answers{via} with more than {MAX_RESPONSE_BYTES // 2**20} MiB, "
                                       "more than the Verifier reads of one answer")
    except _REQUEST_ERRORS as exc:
        return Check("Target", "fail", f"{url}: {_cause(exc, proxy)}")
    status = resp.status_code
    if status == 407 and proxy:
        return Check("Target", "fail", f"{url}: the proxy {proxy} requires authentication (HTTP 407); "
                                       "check username_env and password_env")
    if status >= 500:
        return Check("Target", "warn", f"{url} answers{via} with HTTP {status}"
                                       + (", possibly from the proxy" if proxy else "")
                                       + "; the application may not work")
    return Check("Target", "ok", f"{url} answers{via} · HTTP {status}")


# ── identities (VER-016, VER-028) ──────────────────────────────────────────────

def check_identities(sessions, identities: list[dict], http, target: str, *, scope: dict) -> list[Check]:
    """Each identity once: a login where it has one, then its check_url where it
    names one. Output names role, status and cause, never a value (VER-016)."""
    checks = []
    for ident in identities:
        label, method, auth = ident["role"], ident["method"], ident.get("auth") or {}
        if method == "none":
            checks.append(Check(label, "info", "no credentials"))
            continue
        try:
            headers = sessions.headers_for(label)
        except AuthError as exc:
            checks.append(Check(label, "fail", f"{method}: {exc}"))
            continue
        except _REQUEST_ERRORS as exc:
            endpoint = auth.get("login_url") or auth.get("token_url") or auth.get("issuer") or ""
            checks.append(Check(label, "fail", f"{method} login: {_cause(exc, proxy_for(scope, endpoint))}"))
            continue
        done = "logged in" if method in LOGIN_METHODS else "credentials set"
        check_url = auth.get("check_url")
        if not check_url:
            checks.append(Check(label, "ok", f"{method}: {done}") if method in LOGIN_METHODS else
                          Check(label, "info", f"{method}: {done}; not checked against the target (no check_url)"))
            continue
        checks.append(_check_url(label, method, done, check_url, headers, sessions.origin_for(label) or target,
                                 http, scope))
    return checks


def check_accounts(sessions) -> list[Check]:
    """A failing check when two roles are signed in as the same account: their tokens name the same issuer
    and subject. Roles whose session does not say (cookies, opaque tokens) are not compared (VER-032)."""
    seen: dict[tuple[str, str], str] = {}
    for role, account in sessions.accounts().items():
        if account in seen:
            return [Check("Identities", "fail", f"{seen[account]} and {role} are signed in as the same account; "
                                                "an access-control proof needs two independent accounts (VER-010). "
                                                "Sign in as the second user, e.g. in a private window")]
        seen[account] = role
    return []


def _check_url(label, method, done, url, headers, origin, http, scope) -> Check:
    if not same_origin(url, origin):
        # The credentials belong to `origin`; they are never sent anywhere else (VER-028).
        return Check(label, "fail", f"{method}: check_url is not on {origin}, where its credentials are sent")
    try:
        resp = http.request("GET", url, headers, purpose="target", follow_redirects=False)
    except _REQUEST_ERRORS as exc:
        return Check(label, "fail", f"{method}: {done}; check_url: {_cause(exc, proxy_for(scope, url))}")
    status = resp.status_code
    if 200 <= status < 300:
        return Check(label, "ok", f"{method}: {done}; accepted at check_url (HTTP {status})")
    if status in (401, 403):
        return Check(label, "fail", f"{method}: {done}, but rejected at check_url (HTTP {status})")
    return Check(label, "warn", f"{method}: {done}; check_url answers HTTP {status}, so acceptance is unclear")


# ── source (VER-032) ────────────────────────────────────────────────────────────

def check_source(source_dir: str) -> Check:
    """`--source` points to a readable directory. Offline: only the local path is
    examined, never its contents, and that the agent will find a finding's code
    there is not proved."""
    import os
    from pathlib import Path

    try:
        root = Path(source_dir).resolve()
        is_dir = root.is_dir()
    except OSError as exc:
        return Check("Source", "fail", f"{source_dir}: cannot be used ({type(exc).__name__})")
    if not is_dir:
        return Check("Source", "fail", f"{source_dir}: not a directory")
    if not os.access(root, os.R_OK | os.X_OK):
        return Check("Source", "fail", f"{source_dir}: the directory cannot be read")
    return Check("Source", "ok", f"{source_dir}: readable source checkout")


# ── model (VER-017, VER-019, VER-023) ──────────────────────────────────────────

_TEST_RATIONALE = "appsec-verifier connectivity test"
_TEST_SYSTEM = ("This is a connectivity test of AppSec Verifier, not a verification. The session has no tools. "
                'Answer with exactly one step: {"action": <name>, "args_json": <the arguments as a JSON object, '
                'encoded as a string>, "note": <a few words>}.')
_TEST_PROMPT = ('Reply with the action "submit_verdict" and the arguments '
                f'{{"verdict": "inconclusive", "rationale": "{_TEST_RATIONALE}"}}.')
_TEST_STEP = {"verdict": {"verdict": "inconclusive", "rationale": _TEST_RATIONALE}}


def generation_test(host, budget, *, timeout: float = GENERATION_TIMEOUT_S, show_costs: bool = True) -> Check:
    """One call with a fixed prompt, bounded by `budget` (one call, its own cost
    limit). It passes only when the host stays confined and the reply is exactly
    the requested step. The call's cost is named only with `show_costs`."""
    from .agent.steps import parse_step  # the agent package is loaded only when a model is used
    from .limits import execution_deadline

    label = "Model test"
    usd = None
    try:
        budget.note_cost(0.0)
        budget.note_call()
        timeout = min(timeout, budget.remaining_time())
        with execution_deadline(timeout):
            reply = host.call(_TEST_SYSTEM, _TEST_PROMPT, timeout, budget)
        budget.check_time()
        usd = reply.usd
        if usd is not None:
            budget.note_cost(usd)
    except LimitExceeded as exc:
        return Check(label, "fail", f"stopped by the test limit: {exc}")
    cost = f" · ${usd:.4f}" if usd is not None and show_costs else ""
    if reply.breach:
        return Check(label, "fail", f"confinement check failed: {reply.breach}{cost}")
    if reply.error:
        return Check(label, "fail", f"the call failed: {reply.error}{cost}")
    if parse_step(reply.step) != _TEST_STEP:
        return Check(label, "fail", f"the reply is not the requested step{cost}")
    return Check(label, "ok", f"{host.model} answered with a valid step{cost}")
