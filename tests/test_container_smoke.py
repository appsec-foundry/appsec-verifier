"""Smoke test of a built container image under OpenShift-like restrictions.

Set APPSEC_CONTAINER_IMAGE to the image to test, for example after
`docker build -t appsec-verifier .`. Needs Docker; makes no model calls and runs
the container without network access.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

IMAGE = os.environ.get("APPSEC_CONTAINER_IMAGE", "")
ENGINE = shutil.which("docker")
ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    not IMAGE or not ENGINE, reason="container smoke test; set APPSEC_CONTAINER_IMAGE and install Docker"
)

# A user ID unknown to the image, in group 0 as OpenShift starts containers. Rootless
# Docker maps only 65536 IDs, so it stays below the range OpenShift assigns.
RANDOM_USER = "54321:0"
BASE = "https://app.example.com"


@functools.cache
def _host_user() -> str:
    """The container user that may write to a mounted directory, as docs/container.md describes."""
    info = subprocess.run([ENGINE, "info", "--format", "{{.SecurityOptions}}"], capture_output=True, text=True)
    # Rootless Docker maps your own user to root in the container.
    return "0:0" if "rootless" in info.stdout else f"{os.getuid()}:0"


def _run(
    *args: str, user: str = RANDOM_USER, volumes: tuple[str, ...] = (), env: tuple[str, ...] = (), entrypoint=None
):
    command = [ENGINE, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL"]
    command += ["--security-opt", "no-new-privileges", "--tmpfs", "/tmp", "--tmpfs", "/home/verifier", "--user", user]
    command += [item for volume in volumes for item in ("--volume", volume)]
    command += [item for name in env for item in ("--env", name)]
    command += ["--entrypoint", entrypoint] if entrypoint else []
    return subprocess.run([*command, IMAGE, *args], capture_output=True, text=True, timeout=300, check=False)


@pytest.fixture
def inputs(tmp_path: Path) -> Path:
    """An assessment and a scope file, readable by any container user."""
    directory = tmp_path / "input"
    directory.mkdir()
    assessment = {
        "meta": {"project": "shop", "generated": "2026-11-01"},
        "threats": [{"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor",
                     "evidence": {"file": "a.ts", "line": 1}}],
    }  # fmt: skip
    scope = {
        "schema_version": 1, "base_url": BASE, "owner": {"name": "tester"},
        "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
    }  # fmt: skip
    (directory / "security-assessment.yaml").write_text(yaml.safe_dump(assessment), encoding="utf-8")
    (directory / "scope.yaml").write_text(yaml.safe_dump(scope), encoding="utf-8")
    for path in (directory, *directory.iterdir()):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return directory


def _preflight(inputs: Path, env: tuple[str, ...] = ()):
    return _run(
        "preflight", "--assessment", "/input/security-assessment.yaml", "--scope", "/input/scope.yaml",
        "--profile", "claude", "--offline", "--non-interactive", "--json",
        volumes=(f"{inputs}:/input:ro",), env=env,
    )  # fmt: skip


def _model_check(result) -> dict:
    return next(check for check in json.loads(result.stdout)["checks"] if check["check"] == "Model")


def test_version_runs_as_a_random_user_on_a_read_only_root():
    result = _run("--version")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()


def test_claude_cli_starts():
    result = _run("--version", entrypoint="claude")
    assert result.returncode == 0, result.stderr


def test_scope_check_reads_a_read_only_input(inputs: Path):
    result = _run("scope", "--scope", "/input/scope.yaml", "--target", f"{BASE}/x", volumes=(f"{inputs}:/input:ro",))
    assert result.returncode == 0, result.stderr


def test_export_writes_to_the_output_volume(tmp_path: Path):
    output = tmp_path / "output"
    output.mkdir()
    volumes = (f"{ROOT / 'examples' / 'juice-shop' / 'result'}:/input:ro", f"{output}:/output")
    result = _run(
        "export", "--verification", "/input/verification.yaml", "--output", "/output/analyzer-verification.json",
        user=_host_user(), volumes=volumes,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert json.loads((output / "analyzer-verification.json").read_text(encoding="utf-8"))


def test_preflight_without_credentials_fails_closed(inputs: Path):
    result = _preflight(inputs)
    assert result.returncode == 2
    assert _model_check(result)["status"] == "fail"


def test_preflight_accepts_credentials_from_the_environment(inputs: Path, monkeypatch):
    # An artificial value: an offline preflight checks only that credentials are configured.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder-not-a-key")
    result = _preflight(inputs, env=("ANTHROPIC_API_KEY",))
    assert result.returncode == 0, result.stdout + result.stderr
    assert _model_check(result)["status"] == "ok"
