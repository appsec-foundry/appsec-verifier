"""Report pinned container inputs that Dependabot cannot update.

Compares the Debian package versions in the Dockerfile with the candidates apt
offers in the pinned base image, and the Claude CLI version with npm's "stable"
release. Prints what to change and exits 1 when an update is available, 2 when
the pins cannot be read or checked. Needs Docker and network access.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"
NPM = "https://registry.npmjs.org"
CLAUDE_PLATFORMS = {"X64": "linux-x64", "ARM64": "linux-arm64"}


def pins(text: str) -> tuple[str, str, dict[str, str]]:
    """The base image, the Claude CLI version, and the pinned Debian packages."""
    joined = re.sub(r"\\\n", " ", text)
    base = re.search(r"^FROM (\S+@sha256:[0-9a-f]{64}) AS base$", joined, re.MULTILINE)
    claude = re.search(r"^ARG CLAUDE_CLI_VERSION=(\S+)$", joined, re.MULTILINE)
    packages = dict(
        word.split("=", 1)
        for command in re.findall(r"apt-get install ([^&\n]*)", joined)
        for word in command.split()
        if "=" in word and not word.startswith("-")
    )
    if not base or not claude or not packages:
        raise ValueError("Dockerfile pins not found")
    return base.group(1), claude.group(1), packages


def candidates(policy: str) -> dict[str, str]:
    """Candidate versions from `apt-cache policy` output."""
    return dict(re.findall(r"^(\S+):\n\s+Installed: .*\n\s+Candidate: (\S+)", policy, re.MULTILINE))


def outdated(pinned: dict[str, str], available: dict[str, str]) -> list[str]:
    missing = sorted(set(pinned) - set(available))
    if missing:
        raise ValueError(f"apt has no candidate for {', '.join(missing)}")
    return [
        f"{name}={available[name]} (pinned {pinned[name]})"
        for name in sorted(pinned)
        if available[name] != pinned[name]
    ]


def _json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def main() -> int:
    try:
        base, claude, packages = pins(DOCKERFILE.read_text(encoding="utf-8"))
        script = "apt-get update -qq >/dev/null && apt-cache policy " + " ".join(sorted(packages))
        policy = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "sh", base, "-c", script],
            capture_output=True,
            text=True,
            timeout=600,
            check=True,
        ).stdout
        updates = outdated(packages, candidates(policy))
        stable = _json(f"{NPM}/-/package/@anthropic-ai/claude-code/dist-tags")["stable"]
        if stable != claude:
            updates.append(f"ARG CLAUDE_CLI_VERSION={stable} (pinned {claude})")
            for arch, platform in CLAUDE_PLATFORMS.items():
                integrity = _json(f"{NPM}/@anthropic-ai/claude-code-{platform}/{stable}")["dist"]["integrity"]
                digest = base64.b64decode(integrity.removeprefix("sha512-")).hex()
                updates.append(f"ARG CLAUDE_CLI_SHA512_{arch}={digest}")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Cannot check the container pins: {exc}", file=sys.stderr)
        return 2
    if not updates:
        print("All Debian packages and Claude CLI are current.")
        return 0
    print("Update these pins in the Dockerfile, then rebuild and run the smoke test:")
    print("\n".join(f"  {line}" for line in updates))
    return 1


if __name__ == "__main__":
    sys.exit(main())
