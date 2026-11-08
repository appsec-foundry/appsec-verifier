"""`claude` profile: Claude CLI (`claude -p`) with its login or external
credentials, as AppSec Analyzer uses it (VER-023, VER-028). The counterpart is
the Analyzer's `scripts/runtime/analyst_host.py`; this profile is stricter
(`--setting-sources ""`, `--permission-mode dontAsk`) and stays so.

Each step is one `claude -p` call without built-in tools, MCP servers, settings,
customizations, skills or session persistence, in an empty working directory.
Every call checks the session's init event: any tool besides StructuredOutput,
an MCP server, or a permission denial counts as a confinement breach. The cost
the CLI reports is charged in USD; with a subscription login it is the
API-equivalent value, not a charge, and the console shows it only with
--show-costs. As in AppSec Analyzer, the CLI bills the API when
ANTHROPIC_API_KEY is set or its login reports an API key or a cloud provider.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile

from .hosts import (
    HostReply,
    HostUnavailable,
    call_process,
    check_model_name,
    classify,
    host_env,
    png_base64,
    run_process,
)
from .steps import STEP_SCHEMA

DEFAULT_MODEL = "claude-sonnet-5-5"
_SUBTYPE = re.compile(r"error_[a-z_]{1,40}")
_ALLOWED_SESSION_TOOLS = {"StructuredOutput"}   # the tool --json-schema adds; nothing else
# ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN pass through: like Analyzer, the
# CLI uses them when set and its own login otherwise.
_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "CLAUDE_CONFIG_DIR",
        "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")


class ClaudeHost:
    label = "Claude CLI"
    profile = "claude"

    def __init__(self, binary: str, version: str, *, model: str, auth: str, environ, run=run_process,
                 api_billing: bool = False):
        self.binary, self.version, self.model, self.auth = binary, version, model, auth
        self.api_billing = api_billing
        self.env = host_env(environ, _ENV)
        self.env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
        self.run = run
        self.broken: str | None = None

    @classmethod
    def resolve(cls, *, model: str | None, environ, which=shutil.which, run=run_process) -> ClaudeHost:
        model = check_model_name(model or DEFAULT_MODEL)
        binary = which("claude")
        if not binary:
            raise HostUnavailable("Claude CLI (`claude`) was not found on PATH")
        env = host_env(environ, _ENV)
        api_billing = False
        try:
            with tempfile.TemporaryDirectory(prefix="appsec-verifier-claude-check-") as cwd:
                code, out, _ = run([binary, "--version"], input="", cwd=cwd, env=env, timeout=30)
                version = out.strip() if code == 0 else ""
                if env.get("ANTHROPIC_API_KEY"):
                    auth, api_billing = "API key", True
                elif env.get("CLAUDE_CODE_OAUTH_TOKEN"):
                    auth = "OAuth token"
                else:
                    code, out, _ = run([binary, "auth", "status", "--json"], input="", cwd=cwd, env=env, timeout=30)
                    status = json.loads(out or "{}")
                    if not (isinstance(status, dict) and status.get("loggedIn") is True):
                        raise HostUnavailable("Claude CLI is not logged in; run `claude auth login`")
                    auth = "login"
                    api_billing = bool(status.get("apiKeySource")) or status.get("apiProvider") not in (
                        None, "firstParty")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise HostUnavailable(f"could not query Claude CLI: {type(exc).__name__}") from exc
        return cls(binary, version, model=model, auth=auth, environ=environ, run=run, api_billing=api_billing)

    supports_images = True   # through --input-format stream-json, for an evidence review (VER-042)

    def command(self, system: str, max_usd: float | None, *, schema=None, images=False) -> list[str]:
        return [
            self.binary, "-p",
            "--model", self.model,
            "--safe-mode",                      # no CLAUDE.md, skills, plugins, hooks, MCP servers, agents
            "--restricted",                     # no command- or code-running tools
            "--tools", "",                      # no built-in tools at all
            "--strict-mcp-config",              # no MCP servers (none are passed)
            "--setting-sources", "",            # no user/project/local settings
            "--disable-slash-commands",
            "--no-session-persistence",         # no transcript on disk
            "--permission-mode", "dontAsk",
            "--permission-prompts", "none",     # anything that would prompt is denied
            "--output-format", "stream-json", "--verbose",
            *(["--input-format", "stream-json"] if images else []),   # one user message with image blocks
            "--json-schema", json.dumps(schema if schema is not None else STEP_SCHEMA),
            "--system-prompt", system,
            *(["--max-budget-usd", f"{max_usd:.2f}"] if max_usd is not None else []),
        ]

    def call(self, system: str, prompt: str, timeout: float, budget, *, schema=None, images=()) -> HostReply:
        if images:
            prompt = json.dumps({"type": "user", "message": {"role": "user", "content": [
                *({"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                               "data": png_base64(image)}} for image in images),
                {"type": "text", "text": prompt}]}}) + "\n"
        with tempfile.TemporaryDirectory(prefix="appsec-verifier-claude-") as cwd:
            result = call_process(self, self.command(system, budget.remaining_cost(), schema=schema,
                                                     images=bool(images)),
                                  input=prompt, cwd=cwd, timeout=timeout)
        if isinstance(result, HostReply):
            return result
        code, out, err = result
        try:
            init, final = _events(out)
        except ValueError:
            return HostReply(error="output is not JSON lines")
        cost = (final or {}).get("total_cost_usd")
        usd = float(cost) if isinstance(cost, int | float) and not isinstance(cost, bool) else None
        breach = _breach(init, final)
        if breach:
            return HostReply(usd=usd, breach=breach)
        if code != 0 or final is None or final.get("is_error"):
            subtype = (final or {}).get("subtype")
            detail = " ".join(str(x) for x in (subtype, (final or {}).get("result"), err) if x)
            # The CLI's own error kind (e.g. error_max_turns) says why; a fixed token, never provider prose.
            kind = f"{subtype}, " if isinstance(subtype, str) and _SUBTYPE.fullmatch(subtype) else ""
            return HostReply(usd=usd, error=f"{classify(detail)} ({kind}exit {code})")
        if init is None:
            return HostReply(usd=usd, error="session did not report its tool set")
        return HostReply(step=final.get("structured_output"), usd=usd)


def _events(stdout: str) -> tuple[dict | None, dict | None]:
    init = final = None
    for line in stdout.splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            continue
        if event.get("type") == "system" and event.get("subtype") == "init":
            init = event
        elif event.get("type") == "result":
            final = event
    return init, final


def _breach(init: dict | None, final: dict | None) -> str | None:
    if init is not None:
        tools = init.get("tools")
        if not isinstance(tools, list):
            return "the session did not report its tool set"
        extra = set(map(str, tools)) - _ALLOWED_SESSION_TOOLS
        if extra:
            return f"the session offered tools {sorted(extra)}"
        if init.get("mcp_servers"):
            return "the session loaded MCP servers"
    if final is not None and final.get("permission_denials"):
        return "the session attempted a tool call"
    return None
