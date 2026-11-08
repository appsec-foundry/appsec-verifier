"""The operator's login program (VER-040).

An identity with `method: command` names a program as an argument list; it is
started without a shell, from the identities file's directory, with the
operator's environment minus the model providers' credentials. In an
interactive run it shares the terminal (it may ask for a one-time code on its
own); otherwise its standard input is empty. Its standard error goes to the
terminal as it is and is never recorded. Its standard output, at most 64 KiB
within `timeout` seconds, is the session:

- one line: a bearer token, sent as `Authorization: Bearer <line>`;
- or one JSON object with `headers` (name -> value), `cookies` (name -> value,
  sent as one Cookie header) and optionally `expires_at` (ISO 8601 with a time
  zone) or `expires_in` (seconds).

Only the header names the identity allows (`headers`, default Authorization)
are accepted, and a value with a control character is refused. The values are
then handled like every other credential (VER-016). The program's own requests
are outside the run's scope, limits and safe mode; the run shows the program
before it starts and the model cannot choose or change it.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path

from .sessions import AuthError, header_problem

MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT_S = 120
MAX_TIMEOUT_S = 900
# The model providers' credentials; a login program has no use for them (VER-017).
MODEL_CREDENTIALS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY",
                     "CODEX_API_KEY", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_COOKIE_VALUE = re.compile(r'^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$')   # RFC 6265 cookie-octet


def program_env(environ) -> dict:
    return {k: v for k, v in environ.items() if k not in MODEL_CREDENTIALS}


def describe(auth: dict) -> str:
    """The program as the operator wrote it, for the run settings and the confirmation."""
    import shlex
    return shlex.join(str(a) for a in auth.get("command") or [])


def obtain(auth: dict, *, base_dir: Path, interactive: bool, run=None, clock=time.time, environ=None):
    """Run the program once; (headers, expires_at or None). Raises AuthError, never with its output."""
    argv = auth.get("command")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise AuthError("command must be a non-empty list of strings")
    timeout = auth.get("timeout") or DEFAULT_TIMEOUT_S
    if not isinstance(timeout, int | float) or isinstance(timeout, bool) or not 0 < timeout <= MAX_TIMEOUT_S:
        raise AuthError(f"timeout must be between 1 and {MAX_TIMEOUT_S} seconds")
    env = program_env(os.environ if environ is None else environ)
    code, out = (run or run_program)(argv, cwd=str(base_dir), env=env, timeout=float(timeout),
                                     interactive=interactive)
    if code != 0:
        raise AuthError(f"the login program exited with status {code}")
    return parse_output(out, auth.get("headers") or ["Authorization"], clock=clock)


def run_program(argv: list[str], *, cwd: str, env: dict, timeout: float, interactive: bool) -> tuple[int, str]:
    """Start the program and read its standard output within `timeout` and the size limit."""
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=None if interactive else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=None, start_new_session=not interactive)
    except OSError as exc:
        raise AuthError(f"the login program could not be started ({type(exc).__name__})") from None
    try:
        out = _read(proc, timeout)
    finally:
        _stop(proc, group=not interactive)
    return proc.returncode, out.decode("utf-8", "replace")


def _read(proc, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    buf = bytearray()
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AuthError(f"the login program did not finish within {timeout:g} s")
            if not selector.select(left):
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_OUTPUT_BYTES:
                raise AuthError(f"the login program wrote more than {MAX_OUTPUT_BYTES // 1024} KiB")
    try:
        proc.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        raise AuthError(f"the login program did not finish within {timeout:g} s") from None
    return bytes(buf)


def _stop(proc, *, group: bool) -> None:
    """Stop the program; in a run without a terminal also what it left running in its own process group."""
    proc.stdout.close()
    try:
        if group:
            os.killpg(proc.pid, signal.SIGKILL)
        elif proc.poll() is None:
            proc.kill()
    except OSError:
        pass
    proc.wait()


def parse_output(text: str, allowed: list[str], *, clock=time.time) -> tuple[dict, float | None]:
    allowed_names = {str(n).lower(): str(n) for n in allowed}
    stripped = text.strip()
    if not stripped:
        raise AuthError("the login program wrote no session")
    if not stripped.startswith("{"):
        if "\n" in stripped or " " in stripped:
            raise AuthError("the login program's output is neither one token line nor a JSON object")
        if "authorization" not in allowed_names:
            raise AuthError("the login program wrote a token, but the identity does not allow Authorization")
        return _checked({allowed_names["authorization"]: f"Bearer {stripped}"}), None
    try:
        doc = json.loads(stripped)
    except ValueError:
        raise AuthError("the login program's output is not valid JSON") from None
    if not isinstance(doc, dict) or set(doc) - {"headers", "cookies", "expires_at", "expires_in"}:
        raise AuthError("the login program's JSON may hold only headers, cookies, expires_at and expires_in")
    headers = {}
    given = doc.get("headers") or {}
    if not isinstance(given, dict):
        raise AuthError("headers must be an object of header names and values")
    for name, value in given.items():
        canonical = allowed_names.get(str(name).lower())
        if canonical is None:
            raise AuthError(f"the login program set header {str(name)[:40]!r}, which the identity does not allow")
        if not isinstance(value, str):
            raise AuthError(f"header {canonical} must be a string")
        headers[canonical] = value
    cookies = doc.get("cookies") or {}
    if cookies:
        if not isinstance(cookies, dict) or "cookie" not in allowed_names or "cookie" in {k.lower() for k in headers}:
            raise AuthError("cookies need Cookie among the allowed headers and no Cookie in headers")
        for name, value in cookies.items():
            if not isinstance(value, str) or not _COOKIE_NAME.match(str(name)) or not _COOKIE_VALUE.match(value):
                raise AuthError(f"cookie {str(name)[:40]!r} has an invalid name or value")
        headers[allowed_names["cookie"]] = "; ".join(f"{n}={v}" for n, v in cookies.items())
    if not headers:
        raise AuthError("the login program wrote no header")
    return _checked(headers), _expiry(doc, clock)


def _checked(headers: dict) -> dict:
    for name, value in headers.items():
        problem = header_problem(name, value)
        if problem:
            raise AuthError(f"login program: {problem}")
    return headers


def _expiry(doc: dict, clock) -> float | None:
    if doc.get("expires_at") is not None:
        try:
            when = datetime.fromisoformat(str(doc["expires_at"]).replace("Z", "+00:00"))
        except ValueError:
            raise AuthError("expires_at is not an ISO 8601 time") from None
        if when.tzinfo is None:
            raise AuthError("expires_at needs a time zone, e.g. 2026-11-08T14:30:00Z")
        return when.timestamp()
    lifetime = doc.get("expires_in")
    if lifetime is None:
        return None
    if not isinstance(lifetime, int | float) or isinstance(lifetime, bool) or lifetime <= 0:
        raise AuthError("expires_in must be a positive number of seconds")
    return clock() + float(lifetime)
