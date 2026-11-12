"""The container image pins its inputs and runs without privileges or built-in credentials."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
_SPEC = importlib.util.spec_from_file_location("check_pins", ROOT / "container" / "check_pins.py")
check_pins = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_pins)
SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL", re.IGNORECASE)


def _instructions(text: str) -> list[tuple[str, str]]:
    """Dockerfile instructions with continuation lines joined; comments dropped."""
    joined = re.sub(r"\\\n", " ", "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")))
    return [(line.split(None, 1)[0].upper(), line.split(None, 1)[1]) for line in joined.splitlines() if line.strip()]


def _unpinned_images(text: str) -> list[str]:
    stages = {args.split()[-1] for op, args in _instructions(text) if op == "FROM" and " AS " in args.upper()}
    images = [args.split()[0] for op, args in _instructions(text) if op == "FROM"]
    return [image for image in images if image not in stages and not re.search(r"@sha256:[0-9a-f]{64}$", image)]


def _unpinned_apt_packages(text: str) -> list[str]:
    unpinned = []
    for op, args in _instructions(text):
        for install in re.findall(r"apt-get install ([^&]*)", args) if op == "RUN" else ():
            unpinned += [word for word in install.split() if not word.startswith("-") and "=" not in word]
    return unpinned


def _secret_settings(text: str) -> list[str]:
    names = []
    for op, args in _instructions(text):
        if op in {"ENV", "ARG"}:
            names += [name for name in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", args) if SECRET_NAME.search(name)]
    return names


def _requirements(path: Path) -> dict[str, tuple[str, list[str]]]:
    """Name -> (version, hashes) of a hash-pinned requirements file."""
    text = re.sub(r"\\\n", " ", path.read_text(encoding="utf-8"))
    pins = {}
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, rest = line.split("==", 1)
            pins[name.strip().lower().replace("_", "-")] = (
                rest.split()[0],
                re.findall(r"--hash=sha256:([0-9a-f]{64})", rest),
            )
    return pins


def _run_commands(text: str) -> str:
    return " ".join(args for op, args in _instructions(text) if op == "RUN")


def test_every_base_image_is_pinned_by_digest():
    assert _unpinned_images(DOCKERFILE) == []


def test_every_debian_package_is_pinned():
    assert _unpinned_apt_packages(DOCKERFILE) == []


def test_python_packages_are_installed_only_with_hashes():
    commands = re.findall(r"pip install [^&]*", _run_commands(DOCKERFILE))
    assert commands
    for command in commands:
        # --no-index installs only the wheel built from this checkout in the same build.
        assert "--require-hashes" in command or "--no-index" in command, command
    for name in ("requirements.txt", "build-requirements.txt"):
        pins = _requirements(ROOT / "container" / name)
        assert pins and all(hashes for _, hashes in pins.values()), name


def test_runtime_requirements_cover_the_package_and_the_api_profiles():
    pins = _requirements(ROOT / "container" / "requirements.txt")
    setup = (ROOT / "setup.py").read_text(encoding="utf-8")
    declared = re.search(r"install_requires=\[([^\]]*)\]", setup).group(1)
    for requirement in [*re.findall(r'"([A-Za-z0-9_.-]+)', declared), "anthropic"]:
        assert requirement.lower() in pins, requirement


def test_build_requirements_cover_the_build_system():
    pins = _requirements(ROOT / "container" / "build-requirements.txt")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r"^requires = \[([^\]]*)\]", pyproject, re.MULTILINE).group(1)
    for requirement in re.findall(r'"([A-Za-z0-9_.-]+)', declared):
        assert requirement.lower() in pins, requirement


def _not_in_lock(container: dict, lock: dict) -> list[str]:
    """Container pins whose version or hashes requirements.lock does not hold."""
    return [
        name
        for name, (version, hashes) in container.items()
        if name not in lock or lock[name][0] != version or not set(hashes) <= set(lock[name][1])
    ]


@pytest.mark.parametrize("name", ["requirements.txt", "build-requirements.txt"])
def test_container_pins_are_those_of_the_lockfile(name):
    # Versions are raised in requirements.lock, never in the container alone.
    lock = _requirements(ROOT / "requirements.lock")
    assert _not_in_lock(_requirements(ROOT / "container" / name), lock) == []


def test_lockfile_check_rejects_a_drifted_pin():
    lock = {"httpx": ("0.28.1", ["a" * 64])}
    assert _not_in_lock({"httpx": ("0.28.2", ["a" * 64])}, lock) == ["httpx"]
    assert _not_in_lock({"httpx": ("0.28.1", ["b" * 64])}, lock) == ["httpx"]
    assert _not_in_lock({"idna": ("3.20", ["a" * 64])}, lock) == ["idna"]


def test_claude_cli_is_checked_against_a_pinned_hash():
    hashes = re.findall(r"^ARG CLAUDE_CLI_SHA512_[A-Z0-9]+=([0-9a-f]+)$", DOCKERFILE, re.MULTILINE)
    assert len(hashes) == 2 and all(len(value) == 128 for value in hashes)
    assert re.search(r"^ARG CLAUDE_CLI_VERSION=\d+\.\d+\.\d+$", DOCKERFILE, re.MULTILINE)
    assert "sha512sum --check --strict" in _run_commands(DOCKERFILE)
    assert not re.search(r"\bnpm (install|ci|exec)\b|\bnpx\b", _run_commands(DOCKERFILE))


def test_image_runs_as_non_root_without_built_in_credentials():
    instructions = _instructions(DOCKERFILE)
    final_stage = instructions[max(index for index, (op, _) in enumerate(instructions) if op == "FROM") :]
    users = [args.strip() for op, args in final_stage if op == "USER"]
    assert users and users[-1].isdigit() and int(users[-1]) != 0
    assert _secret_settings(DOCKERFILE) == []
    assert [args for op, args in final_stage if op == "EXPOSE"] == []
    assert re.search(r'^ENTRYPOINT \["appsec-verifier"\]$', DOCKERFILE, re.MULTILINE)


def test_build_context_keeps_git_and_leaves_out_run_results():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert ".git" not in ignored and ".git/" not in ignored
    # Run results hold evidence of the tested application.
    assert "verification*" in ignored


def _wheel_from_tracked_files(text: str) -> bool:
    """The build copies the checkout, removes what Git does not track, then builds the wheel."""
    steps = _instructions(text)

    def first(op: str, word: str) -> int:
        return next((index for index, (name, args) in enumerate(steps) if name == op and word in args), -1)

    copy, clean, wheel = first("COPY", ". /src"), first("RUN", "git -C /src clean -ffdx"), first("RUN", "pip wheel")
    return -1 < copy < clean < wheel


@pytest.mark.parametrize(
    ("dockerfile", "expected"),
    [
        (DOCKERFILE, True),
        ("FROM x\nCOPY . /src\nRUN pip wheel /src\n", False),
        ("FROM x\nRUN git -C /src clean -ffdx\nCOPY . /src\nRUN pip wheel /src\n", False),
    ],
)
def test_wheel_contains_only_files_git_tracks(dockerfile, expected):
    # setup.py copies whole runtime directories; ignored files must not reach the image.
    assert _wheel_from_tracked_files(dockerfile) is expected


def test_build_stops_without_readable_git_data():
    assert re.search(
        r"git -C /src rev-parse --git-dir >/dev/null\s+\|\|\s+\{[^}]*exit 1; \}", _run_commands(DOCKERFILE)
    )


def test_docker_examples_drop_rights():
    guide = re.sub(r"\\\n", " ", (ROOT / "docs" / "container.md").read_text(encoding="utf-8"))
    runs = [line for line in guide.splitlines() if line.strip().startswith("docker run")]
    assert runs
    for run in runs:
        assert "--cap-drop ALL" in run and "--security-opt no-new-privileges" in run, run


@pytest.mark.parametrize(
    ("check", "dockerfile", "found"),
    [
        (_unpinned_images, "FROM python:3.12-slim AS base\nFROM base\n", ["python:3.12-slim"]),
        (_unpinned_apt_packages, "FROM x\nRUN apt-get update && apt-get install --yes git curl=1\n", ["git"]),
        (
            _secret_settings,
            "FROM x\nENV ANTHROPIC_API_KEY=placeholder\nARG GIT_TOKEN=\n",
            ["ANTHROPIC_API_KEY", "GIT_TOKEN"],
        ),
    ],
)
def test_checks_reject_unsafe_dockerfiles(check, dockerfile, found):
    assert check(dockerfile) == found


def test_pin_check_reads_every_pin_in_the_dockerfile():
    base, claude, packages = check_pins.pins(DOCKERFILE)
    assert re.search(r"@sha256:[0-9a-f]{64}$", base)
    assert re.search(r"ARG CLAUDE_CLI_VERSION=" + re.escape(claude) + "$", DOCKERFILE, re.MULTILINE)
    installs = re.findall(r"apt-get install ([^&]*)", _run_commands(DOCKERFILE))
    expected = [word for command in installs for word in command.split() if "=" in word]
    assert expected and sorted(f"{name}={version}" for name, version in packages.items()) == sorted(expected)


def test_pin_check_reports_newer_debian_packages():
    policy = (
        "git:\n  Installed: (none)\n  Candidate: 1:2.47.3-0+deb13u2\n  Version table:\n"
        "curl:\n  Installed: (none)\n  Candidate: 8.14.1-2+deb13u7\n"
    )
    available = check_pins.candidates(policy)
    assert available == {"git": "1:2.47.3-0+deb13u2", "curl": "8.14.1-2+deb13u7"}
    pinned = {"git": "1:2.47.3-0+deb13u1", "curl": "8.14.1-2+deb13u7"}
    assert check_pins.outdated(pinned, available) == ["git=1:2.47.3-0+deb13u2 (pinned 1:2.47.3-0+deb13u1)"]


@pytest.mark.parametrize(
    "dockerfile",
    [
        "FROM python:3.12 AS base\nARG CLAUDE_CLI_VERSION=1.0.0\nRUN apt-get install git=1\n",
        "FROM base\n",
    ],
)
def test_pin_check_fails_closed_on_unreadable_pins(dockerfile):
    with pytest.raises(ValueError):
        check_pins.pins(dockerfile)


def test_pin_check_fails_closed_when_apt_lacks_a_package():
    with pytest.raises(ValueError, match="curl"):
        check_pins.outdated({"curl": "1", "git": "2"}, {"git": "2"})
