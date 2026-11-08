"""Host-backed planning: one bounded, fail-closed host call per step.

A host is an agent CLI (Claude, Codex, Copilot) or a tool-less API (OpenAI)
that only proposes the next step; it never acts itself (VER-017). HostPlanner
holds what all hosts share. It refuses a call once the run's call or cost bound
is reached or a confinement check has failed, bounds each call by the remaining
run time, charges the reported cost (VER-015), and validates the step
(steps.py, VER-019). A failed call ends only its finding, but after
MAX_FAILED_CALLS failed calls in a row (an exhausted quota, a rejected login, a
provider that is down) the host makes no further call in the run. A host only
sends the request and returns a HostReply.
"""

from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass

from ..limits import LimitExceeded, execution_deadline
from .steps import inconclusive, parse_step, prompt, system_prompt

CALL_TIMEOUT_S = 300.0
MAX_OUTPUT_BYTES = 1_048_576
MAX_FAILED_CALLS = 3
# Network settings a host may need to reach its provider. Everything else a host
# receives is listed by that host; API keys of other providers and the
# identities' secret variables are never passed on (VER-016).
NETWORK_ENV = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
               "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS")
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


class HostUnavailable(Exception):
    """The selected profile cannot be used: missing CLI, login, key, or model."""


@dataclass
class HostReply:
    step: object = None          # the wire step, validated by parse_step
    usd: float | None = None     # what the call cost, when the host reports it
    error: str | None = None     # the call failed; the finding ends inconclusive
    breach: str | None = None    # the host was not confined; no further call in this run


def host_env(environ, names: tuple[str, ...]) -> dict:
    return {k: environ[k] for k in (*names, *NETWORK_ENV) if k in environ}


def check_model_name(model: str) -> str:
    if not isinstance(model, str) or not _MODEL_NAME.fullmatch(model) or ".." in model:
        raise HostUnavailable(f"invalid model name {model!r}")
    return model


def classify(text: str) -> str:
    """A fixed reason code for a failed call, so no provider prose reaches the report."""
    text = text.lower()
    rules = (
        ("quota_exhausted", ("usage limit", "usage_limit", "quota", "ai credits", "credit limit")),
        ("rate_limit", ("rate limit", "rate_limit", "429")),
        ("authentication_failed", ("unauthorized", "authentication", "not logged in", "401", "403")),
        ("budget_exhausted", ("max_budget", "budget")),
        ("model_unavailable", ("model not found", "model_not_found", "not available", "unsupported model")),
        ("timeout", ("timed out", "timeout")),
        ("connection_failed", ("failed to connect", "connection", "network", "dns")),
        ("server_error", ("internal server error", "service unavailable", "bad gateway", "overloaded")),
    )
    return next((code for code, markers in rules if any(m in text for m in markers)), "host_error")


def run_process(argv: list[str], *, input: str, cwd, env: dict, timeout: float) -> tuple[int, str, str]:
    """Run one host process in its own process group and stop the whole group
    afterwards, so a CLI cannot leave helpers running. Raises OSError or a
    subprocess.SubprocessError (including TimeoutExpired)."""
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = _communicate_bounded(proc, input.encode("utf-8"), timeout)
    finally:
        _stop_group(proc)
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def _communicate_bounded(proc, data: bytes, timeout: float):
    """Drain both pipes while feeding stdin; enforce the cap before accumulating output."""
    until = time.monotonic() + timeout
    buffers = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    size, offset = 0, 0
    with selectors.DefaultSelector() as selector:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_WRITE if stream is proc.stdin else selectors.EVENT_READ)
        try:
            while selector.get_map():
                left = until - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired(proc.args, timeout)
                for key, _ in selector.select(left):
                    stream = key.fileobj
                    if stream is proc.stdin:
                        try:
                            offset += os.write(stream.fileno(), data[offset:offset + 4096])
                        except BrokenPipeError:
                            offset = len(data)
                        if offset >= len(data):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), min(65536, MAX_OUTPUT_BYTES - size + 1))
                        if not chunk:
                            selector.unregister(stream)
                            continue
                        size += len(chunk)
                        if size > MAX_OUTPUT_BYTES:
                            raise subprocess.SubprocessError("host output exceeds its size limit")
                        buffers[stream].extend(chunk)
            proc.wait(timeout=max(0.001, until - time.monotonic()))
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
    return bytes(buffers[proc.stdout]), bytes(buffers[proc.stderr])


def _stop_group(proc) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - non-POSIX
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass
    proc.wait(timeout=5)


class HostPlanner:
    """Planner protocol over a host. Holds no conversation state: every call is
    rebuilt from the finding and the loop's history."""

    def __init__(self, host):
        self._host = host

    def next_step(self, ctx, history: list[dict]) -> dict:
        host = self._host
        if host.broken:
            return inconclusive(f"{host.label} stopped for this run: {host.broken}")
        ctx.budget.note_cost(0.0)   # no new call once the cost ceiling is already exceeded
        ctx.budget.note_call()
        timeout = CALL_TIMEOUT_S
        remaining = ctx.budget.remaining_time()
        if remaining is not None:
            timeout = min(timeout, remaining)
        try:
            with execution_deadline(timeout, kind="model-timeout"):
                reply = host.call(system_prompt(ctx), prompt(ctx, history), timeout, ctx.budget)
        except LimitExceeded as exc:
            if exc.kind != "model-timeout":
                raise
            ctx.budget.check_time()
            reply = HostReply(error="timeout")
        if reply.breach:
            host.broken = reply.breach
        if reply.usd is not None:
            ctx.budget.note_cost(reply.usd)
        if reply.breach:
            return inconclusive(f"{host.label} confinement check failed: {reply.breach}")
        if reply.error:
            # Kept on the host, not the planner: a planner lives for one finding, the host for the run.
            host.failed_calls = getattr(host, "failed_calls", 0) + 1
            if host.failed_calls >= MAX_FAILED_CALLS:
                host.broken = f"{host.failed_calls} calls in a row failed, the last with {reply.error}"
            return inconclusive(f"{host.label} call failed: {reply.error}")
        host.failed_calls = 0
        return parse_step(reply.step)


def call_process(host, argv: list[str], *, input: str, cwd, timeout: float):
    """Run a CLI host once; returns (code, stdout, stderr) or a failed HostReply."""
    try:
        return host.run(argv, input=input, cwd=cwd, env=host.env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return HostReply(error=f"no answer within {timeout:.0f}s")
    except (OSError, subprocess.SubprocessError) as exc:
        return HostReply(error=f"could not run: {type(exc).__name__}")
