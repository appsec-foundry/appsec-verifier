"""Host-backed planning: one bounded, fail-closed host call per step.

A host is an agent CLI (Claude, Codex, Copilot) or a tool-less API (OpenAI)
that only proposes the next step; it never acts itself (VER-017). HostPlanner
holds what all hosts share. It refuses a call once the run's call or cost bound
is reached or a confinement check has failed, bounds each call by the remaining
run time, charges the reported cost (VER-015), and validates the step
(steps.py, VER-019). Each call's cost and the token counts a host reports are
kept as numbers for the action log (VER-017), never any prompt or answer text.
Each call's instructions, prompt and answer stay with the finding's context, for
the debug file of a failed verification only (VER-063).
A failed call ends only its finding, but after
MAX_FAILED_CALLS failed calls in a row (an exhausted quota, a rejected login, a
provider that is down) the host makes no further call in the run. A host only
sends the request and returns a HostReply. For an evidence review a host that
can take images also receives the cleared PNG screenshots; once it rejects a
call that carries them, later reviews of the run send text only (VER-042).
"""

from __future__ import annotations

import base64
import json
import os
import re
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from ..limits import LimitExceeded, execution_deadline
from .steps import Unusable, inconclusive, parse_step, prompt, step_schema, system_prompt

CALL_TIMEOUT_S = 300.0
MAX_OUTPUT_BYTES = 1_048_576
MAX_FAILED_CALLS = 3
# Network settings a host may need to reach its provider. Everything else a host
# receives is listed by that host; API keys of other providers and the
# identities' secret variables are never passed on (VER-016).
NETWORK_ENV = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
               "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS")
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class HostUnavailable(Exception):
    """The selected profile cannot be used: missing CLI, login, key, or model."""


@dataclass
class HostReply:
    step: object = None          # the wire step, validated by parse_step
    usd: float | None = None     # what the call cost, when the host reports it
    error: str | None = None     # the call failed; the finding ends inconclusive
    breach: str | None = None    # the host was not confined; no further call in this run
    usage: dict | None = None    # token counts the host reports, numbers only (usage_counts)


USAGE_FIELDS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens")


def usage_counts(usage) -> dict | None:
    """The token counts of one model call for the action log (VER-017): only the known count fields, only
    non-negative integers, never any content. A mapping or an SDK object; None when nothing usable is there."""
    if usage is None:
        return None
    out = {}
    for field in USAGE_FIELDS:
        value = usage.get(field) if isinstance(usage, dict) else getattr(usage, field, None)
        if type(value) is int and value >= 0:
            out[field] = value
    return out or None


def host_env(environ, names: tuple[str, ...]) -> dict:
    return {k: environ[k] for k in (*names, *NETWORK_ENV) if k in environ}


def check_model_name(model: str) -> str:
    if not isinstance(model, str) or not _MODEL_NAME.fullmatch(model) or ".." in model:
        raise HostUnavailable(f"invalid model name {model!r}")
    return model


def png_base64(image: bytes) -> str:
    """A screenshot an evidence review attaches (VER-042), checked to be a PNG and base64-encoded."""
    if not isinstance(image, bytes) or not image.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("an attached image must be a PNG")
    return base64.b64encode(image).decode("ascii")


def write_images(directory, images) -> list[str]:
    """The PNG screenshots of a review call as files in a CLI host's empty temporary directory, for a CLI that
    attaches images by path; returns their paths (VER-042)."""
    paths = []
    for n, image in enumerate(images, 1):
        png_base64(image)
        path = os.path.join(directory, f"screenshot-{n}.png")
        with open(path, "wb") as fh:
            fh.write(image)
        paths.append(path)
    return paths


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


class HostCallError(Exception):
    """A bounded host call failed; its fixed reason is safe to report."""


class HostPlanner:
    """Planner protocol over a host. Holds no conversation state: every call is
    rebuilt from the finding and the loop's history."""

    def __init__(self, host):
        self._host = host

    def next_step(self, ctx, history: list[dict]) -> dict:
        """The finding's next step; structured output offers only the actions its prompt offers. A failed call or
        an answer that is no usable step ends the finding inconclusive, and the context keeps why (VER-063)."""
        try:
            action = parse_step(self._request(ctx, system_prompt(ctx), prompt(ctx, history), schema=step_schema(ctx)))
        except HostCallError as exc:
            action = inconclusive(str(exc))
        if isinstance(action.get("verdict"), Unusable):
            try:
                ctx.model_failure = action["verdict"]["rationale"]
            except AttributeError:   # a context that takes no new attributes keeps no failure
                pass
        return action

    @property
    def supports_images(self) -> bool:
        """Whether the host can attach PNG screenshots to a review call (VER-042)."""
        return bool(getattr(self._host, "supports_images", False)) and not getattr(self._host, "images_refused", False)

    def structured(self, ctx, system: str, payload: str, schema: dict, *, images=()):
        """A tool-less review/revision call; its caller validates the separate schema (VER-042). `images` are PNG
        bytes the caller has cleared for a model; a host that cannot take them never receives them."""
        ctx.guard.check_window()
        return self._request(ctx, system, payload, schema=schema, review=True,
                             images=tuple(images) if self.supports_images else ())

    def _request(self, ctx, system: str, payload: str, *, schema=None, review=False, images=()):
        host = self._host
        if host.broken:
            raise HostCallError(f"{host.label} stopped for this run: {host.broken}")
        ctx.budget.check_cost()     # no new call once the cost ceiling is reached
        ctx.budget.note_call()
        timeout = CALL_TIMEOUT_S
        remaining = ctx.budget.remaining_time()
        if remaining is not None:
            timeout = min(timeout, remaining)
        if review:
            window = ctx.guard.remaining_time()
            if window is not None:
                timeout = min(timeout, window)
        # VER-063: the call as sent, kept with the finding's context; only the debug file of a failed verification
        # reads it. The answer is encoded at once, so what the loop makes of it later cannot change it.
        exchange = {"call": "review" if review else "step", "started": _now(), "instructions": system,
                    "schema": schema, "prompt": payload, **({"images": len(images)} if images else {})}
        exchanges = getattr(ctx, "model_exchanges", None)
        if isinstance(exchanges, list):
            exchanges.append(exchange)
        began = time.monotonic()
        try:
            with execution_deadline(timeout, kind="model-timeout"):
                reply = host.call(system, payload, timeout, ctx.budget, schema=schema,
                                  **({"images": images} if images else {}))
        except LimitExceeded as exc:
            if exc.kind != "model-timeout":
                raise
            ctx.budget.check_time()
            reply = HostReply(error="timeout")
        exchange["seconds"] = round(time.monotonic() - began, 3)
        if reply.step is not None:
            exchange["answer"] = json.dumps(reply.step, default=str)
        if reply.breach or reply.error:
            exchange["failure"] = reply.breach or reply.error
        exchange.update({**({"usd": reply.usd} if reply.usd is not None else {}), **(reply.usage or {})})
        if reply.breach:
            host.broken = reply.breach
        if reply.usd is not None:
            ctx.budget.note_cost(reply.usd)
        # What this call cost and, where the host reports them, its token counts; the next action-log record of
        # the finding carries them (agent/loop.py), so cost per call can be told apart from cost per finding.
        record = {**({"usd": round(reply.usd, 6)} if reply.usd is not None else {}), **(reply.usage or {})}
        if record:
            pending = getattr(ctx, "model_calls", None)
            if not isinstance(pending, list):
                pending = []
            pending.append(record)
            try:
                ctx.model_calls = pending
            except AttributeError:   # a context that takes no new attributes logs no usage
                pass
        if reply.breach:
            raise HostCallError(f"{host.label} confinement check failed: {reply.breach}")
        if reply.error and images:
            host.images_refused = True   # later reviews of this run send text only (VER-042)
        if reply.error:
            # Kept on the host, not the planner: a planner lives for one finding, the host for the run.
            host.failed_calls = getattr(host, "failed_calls", 0) + 1
            if host.failed_calls >= MAX_FAILED_CALLS:
                host.broken = f"{host.failed_calls} calls in a row failed, the last with {reply.error}"
            raise HostCallError(f"{host.label} call failed: {reply.error}")
        host.failed_calls = 0
        return reply.step


def call_process(host, argv: list[str], *, input: str, cwd, timeout: float):
    """Run a CLI host once; returns (code, stdout, stderr) or a failed HostReply."""
    try:
        return host.run(argv, input=input, cwd=cwd, env=host.env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return HostReply(error=f"no answer within {timeout:.0f}s")
    except (OSError, subprocess.SubprocessError) as exc:
        return HostReply(error=f"could not run: {type(exc).__name__}")
