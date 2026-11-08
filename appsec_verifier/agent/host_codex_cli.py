"""`codex-cli` profile: Codex CLI (`codex exec`) with its ChatGPT login, isolated
the way AppSec Analyzer runs it (VER-023). The reference for flags, minimum
version and environment is the Analyzer's `appsec_analyzer/codex_cli.py`.

Preflight requires Codex CLI 0.163.0 or newer on Linux or macOS, the isolation
options of `codex exec`, the feature switches it turns off, and a ChatGPT login.
Each step is one ephemeral `codex exec` in an empty directory with user config,
rules, MCP servers, web search, history and every feature disabled, a read-only
sandbox, no API key in its environment, and forced ChatGPT authentication. Any
event other than reasoning, an agent message or an error item is a confinement
breach. The call reports no cost: the run is bounded by calls and time.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .host_openai import DEFAULT_MODEL, REASONING_EFFORT, catalog_model
from .hosts import HostReply, HostUnavailable, call_process, classify, host_env, run_process
from .steps import STEP_SCHEMA, strict_json

MINIMUM_VERSION = (0, 163, 0)
REQUIRED_EXEC_FLAGS = frozenset(("--ignore-user-config", "--ignore-rules", "--strict-config", "--ephemeral",
                                 "--skip-git-repo-check", "--sandbox", "--json", "--output-schema"))
REQUIRED_FEATURES = frozenset(("shell_tool", "hooks", "apps", "plugins", "multi_agent", "skip_host_skill_discovery"))
_ENV = ("PATH", "HOME", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG")
_VERSION = re.compile(r"codex-cli (\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:[-+][0-9A-Za-z.+-]*)?")
_ALLOWED_ITEMS = {"agent_message", "reasoning", "error"}


class CodexCliHost:
    label = "Codex CLI"
    profile = "codex-cli"
    api_billing = False     # subscription: no cost is reported

    def __init__(self, binary: str, version: str, *, model: str, features: dict, environ, run=run_process):
        self.binary, self.version, self.model, self.features = binary, version, model, features
        self.auth = "ChatGPT login"
        self.env = host_env(environ, _ENV)
        self.run = run
        self.broken: str | None = None

    @classmethod
    def resolve(cls, *, model: str | None, environ, which=shutil.which, run=run_process) -> CodexCliHost:
        model_id, _ = catalog_model(model or DEFAULT_MODEL)
        binary = which("codex")
        if not binary or os.name != "posix":
            raise HostUnavailable("codex-cli needs Codex CLI 0.163.0 or newer on PATH, on Linux or macOS")
        binary = str(Path(binary).resolve())
        env = host_env(environ, _ENV)
        try:
            with tempfile.TemporaryDirectory(prefix="appsec-verifier-codex-check-") as cwd:
                def query(*args: str) -> tuple[str, str]:
                    code, out, err = run([binary, *args], input="", cwd=cwd, env=env, timeout=30)
                    if code:
                        raise HostUnavailable(f"`codex {' '.join(args)}` failed")
                    return out, err

                version = _version(query("--version")[0])
                flags = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*(?![\w-])", query("exec", "--help")[0]))
                if REQUIRED_EXEC_FLAGS - flags:
                    raise HostUnavailable("Codex CLI lacks isolation options: "
                                          + ", ".join(sorted(REQUIRED_EXEC_FLAGS - flags)))
                features = _features(query("features", "list")[0])
                out, err = query("-c", 'forced_login_method="chatgpt"', "login", "status")
                if "Logged in using ChatGPT" not in (out + "\n" + err).splitlines():
                    raise HostUnavailable("Codex CLI needs a ChatGPT login; run `codex login`")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise HostUnavailable(f"could not query Codex CLI: {type(exc).__name__}") from exc
        return cls(binary, version, model=model_id, features=features, environ=environ, run=run)

    def command(self, schema_path: Path, instructions_path: Path) -> list[str]:
        features = "{" + ",".join(f"{json.dumps(k)}={str(v).lower()}" for k, v in self.features.items()) + "}"
        config = {
            "features": features,
            "model_provider": '"appsec_chatgpt"',
            "forced_login_method": '"chatgpt"',
            "approval_policy": '"never"',
            "web_search": '"disabled"',
            "mcp_servers": "{}",
            "project_doc_max_bytes": "0",
            "history.persistence": '"none"',
            "model_reasoning_effort": json.dumps(REASONING_EFFORT),
            "model_instructions_file": json.dumps(str(instructions_path)),
            "model_providers.appsec_chatgpt.name": '"OpenAI"',
            "model_providers.appsec_chatgpt.requires_openai_auth": "true",
            "model_providers.appsec_chatgpt.wire_api": '"responses"',
            "model_providers.appsec_chatgpt.supports_websockets": "false",
            "model_providers.appsec_chatgpt.request_max_retries": "0",
            "model_providers.appsec_chatgpt.stream_max_retries": "0",
        }
        return [
            self.binary, "exec",
            "--ignore-user-config", "--ignore-rules", "--strict-config", "--ephemeral", "--skip-git-repo-check",
            "--sandbox", "read-only",
            "--json", "--color", "never",
            "--model", self.model,
            "--output-schema", str(schema_path),
            *[arg for key, value in config.items() for arg in ("-c", f"{key}={value}")],
            "-",
        ]

    def call(self, system: str, prompt: str, timeout: float, budget, *, schema=None) -> HostReply:
        with tempfile.TemporaryDirectory(prefix="appsec-verifier-codex-") as cwd:
            schema_path, instructions_path = Path(cwd) / "schema.json", Path(cwd) / "instructions.txt"
            files = ((schema_path, json.dumps(schema if schema is not None else STEP_SCHEMA)),
                     (instructions_path, system))
            for path, text in files:
                path.write_text(text, encoding="utf-8")
                path.chmod(0o600)
            result = call_process(self, self.command(schema_path, instructions_path),
                                  input=prompt, cwd=cwd, timeout=timeout)
        if isinstance(result, HostReply):
            return result
        code, out, err = result
        try:
            events = [strict_json(line) for line in out.splitlines() if line.strip()]
            if any(not isinstance(e, dict) for e in events):
                raise ValueError
        except ValueError:
            return HostReply(error="output is not JSON lines")
        items = [e.get("item") for e in events if e.get("type") in ("item.started", "item.updated", "item.completed")]
        unexpected = sorted({str(i.get("type")) if isinstance(i, dict) else "?" for i in items
                             if not isinstance(i, dict) or i.get("type") not in _ALLOWED_ITEMS})
        if unexpected:
            return HostReply(breach=f"the session produced {unexpected} items")
        failures = [e for e in events if e.get("type") == "turn.failed"
                    or (e.get("type") == "error" and not _reconnect(e))]
        if code or failures:
            return HostReply(error=f"{classify(json.dumps(failures) + ' ' + err[-16384:])} (exit {code})")
        messages = [e["item"].get("text") for e in events if e.get("type") == "item.completed"
                    and e["item"].get("type") == "agent_message"]
        completed = [e for e in events if e.get("type") == "turn.completed"]
        if len(completed) != 1 or not messages or events[-1].get("type") != "turn.completed":
            return HostReply(error="incomplete_response")
        try:
            # Only the last completed agent message is the answer; never fall back to an earlier one.
            step = strict_json(messages[-1]) if isinstance(messages[-1], str) else None
        except ValueError:
            return HostReply(error="invalid_response")
        return HostReply(step=step)


def _version(text: str) -> str:
    for line in text.splitlines():
        match = _VERSION.fullmatch(line.strip())
        if match and tuple(int(p) for p in match.groups()) >= MINIMUM_VERSION:
            return line.strip().split()[1]
    raise HostUnavailable("codex-cli needs Codex CLI 0.163.0 or newer")


def _features(text: str) -> dict:
    """Every listed feature switched off, except skipping host skill discovery."""
    features = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or not re.fullmatch(r"[a-z0-9_.]+", parts[0]) or parts[-1] not in ("true", "false"):
            raise HostUnavailable("Codex CLI feature list is not in the expected format")
        if parts[1] not in ("removed", "deprecated"):
            features[parts[0]] = False
    missing = REQUIRED_FEATURES - features.keys()
    if missing:
        raise HostUnavailable("Codex CLI lacks feature switches: " + ", ".join(sorted(missing)))
    features["skip_host_skill_discovery"] = True
    return features


def _reconnect(event: dict) -> bool:
    message = event.get("message")
    return isinstance(message, str) and re.match(r"^Reconnecting\.\.\. \d{1,2}/\d{1,2}(?: \(|$)", message) is not None
