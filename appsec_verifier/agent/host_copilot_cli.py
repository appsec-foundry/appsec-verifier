"""`copilot-cli` profile: GitHub Copilot CLI with its login, run tool-less the
way AppSec Analyzer runs it (VER-023). The reference for flags, version and
environment is the Analyzer's `appsec_analyzer/copilot_cli.py`.

Preflight requires exactly the reviewed Copilot CLI version on Linux or macOS;
it does not read credentials. Each step is one call from an empty directory with
no tools, no custom instructions, no built-in MCP servers, no remote sharing and
a soft per-call credit limit. The answer must be exactly one JSON step. The CLI
prints only that text, so the tool set cannot be checked per call; the pinned
version and the flags carry the confinement. The call reports no cost: the run
is bounded by calls and time.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .hosts import HostReply, HostUnavailable, call_process, check_model_name, classify, host_env, run_process
from .steps import STEP_SCHEMA, strict_json

SUPPORTED_VERSION = "1.0.101"
DEFAULT_MODEL = "gpt-5.4"
REASONING_EFFORT = "medium"
MAX_AI_CREDITS = 30
_ENV = ("PATH", "HOME", "COPILOT_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG")


class CopilotCliHost:
    label = "Copilot CLI"
    profile = "copilot-cli"
    api_billing = False     # subscription: no cost is reported

    def __init__(self, binary: str, version: str, *, model: str, environ, run=run_process):
        self.binary, self.version, self.model = binary, version, model
        self.auth = "Copilot login"
        self.env = host_env(environ, _ENV)
        self.run = run
        self.broken: str | None = None

    @classmethod
    def resolve(cls, *, model: str | None, environ, which=shutil.which, run=run_process) -> CopilotCliHost:
        model = check_model_name(model or DEFAULT_MODEL)
        if model.lower() == "auto":
            raise HostUnavailable("copilot-cli needs an explicit model, not 'auto'")
        binary = which("copilot")
        if not binary or os.name != "posix":
            raise HostUnavailable(f"copilot-cli needs GitHub Copilot CLI {SUPPORTED_VERSION} on PATH, "
                                  "on Linux or macOS")
        binary = str(Path(binary).resolve())
        try:
            with tempfile.TemporaryDirectory(prefix="appsec-verifier-copilot-check-") as cwd:
                code, out, _ = run([binary, "--version"], input="", cwd=cwd, env=host_env(environ, _ENV), timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostUnavailable(f"could not query Copilot CLI: {type(exc).__name__}") from exc
        expected = f"GitHub Copilot CLI {SUPPORTED_VERSION}"
        if code or expected not in (line.strip().rstrip(".") for line in out.splitlines()):
            raise HostUnavailable(f"copilot-cli needs the reviewed GitHub Copilot CLI version {SUPPORTED_VERSION}")
        return cls(binary, SUPPORTED_VERSION, model=model, environ=environ, run=run)

    def command(self, cwd: Path) -> list[str]:
        return [
            self.binary,
            "--no-auto-update", "--no-color", "--no-bash-env", "--no-custom-instructions", "--no-ask-user",
            "--no-remote", "--no-remote-export", "--disable-builtin-mcps",
            "--available-tools",                # given without a list: no tools
            "--secret-env-vars", "COPILOT_GITHUB_TOKEN,GH_TOKEN,GITHUB_TOKEN",
            "--model", self.model,
            "--reasoning-effort", REASONING_EFFORT,
            "--max-ai-credits", str(MAX_AI_CREDITS),
            "--log-level", "none", "--log-dir", str(cwd / "logs"),
            "--silent", "--output-format", "text",
            "-C", str(cwd),
        ]

    def call(self, system: str, prompt: str, timeout: float, budget, *, schema=None) -> HostReply:
        instructions = (system + "\nReturn exactly one JSON value matching this JSON Schema. "
                        "Do not use Markdown fences or add prose.\n"
                        + json.dumps(schema if schema is not None else STEP_SCHEMA))
        with tempfile.TemporaryDirectory(prefix="appsec-verifier-copilot-") as cwd:
            result = call_process(self, self.command(Path(cwd)), input=instructions + "\n\n" + prompt,
                                  cwd=cwd, timeout=timeout)
        if isinstance(result, HostReply):
            return result
        code, out, err = result
        if code:
            # stdout carries model text; it counts for classification only when stderr is empty.
            return HostReply(error=f"{classify(err if err.strip() else out)} (exit {code})")
        try:
            return HostReply(step=strict_json(out.strip()))
        except ValueError:
            return HostReply(error="invalid_response")
