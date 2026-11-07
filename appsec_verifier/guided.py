"""Guided run from the assessment alone (VER-031).

`appsec-verifier <assessment>` reads the assessment offline, shows what it
holds, and asks only for what has no usable default: the severity floor, the
target URL when there is no scope file, an identities file when one is found,
and the model profile. Answers pass the same checks as the matching `verify`
options and are re-asked when invalid; options already given are used as
given. The settings are then handed to `verify`, which shows them with the
equivalent non-interactive invocation and asks for the one confirmation of
VER-002, where Enter proceeds.

A scope file given or found next to the assessment or in the working directory
is used as it is. Without one the run takes the target URL the operator types,
and the scope is that URL's host and port, read-only, for this run only
(VER-001, VER-004). The dialog
contacts nothing, writes no file, never asks for a secret value (credentials
stay in environment variables, VER-016), and never widens a scope. Text from
the assessment is untrusted (VER-005) and is shown without control characters.
Without a terminal, or with --non-interactive, nothing is asked: the run takes
its settings from the invocation and blocks on a missing target or profile.
"""

from __future__ import annotations

import os
import shlex
import sys
from collections import Counter
from pathlib import Path

import yaml

from . import cli
from .agent import DEFAULT_PROFILE, PROFILES
from .limits import Limits
from .preflight import printable as clean
from .scope import ScopeGuard
from .term_style import Style

SEVERITY_FLOORS = ("critical", "high", "medium", "low")
DEFAULT_FLOOR = "high"
DEFAULT_OUTPUT = "./verification"

# (args attribute, verify option, Limits field)
_LIMITS = (
    ("cost_limit", "--cost-limit", "cost_limit_usd"),
    ("max_calls", "--max-calls", "max_calls"),
    ("max_requests", "--max-requests", "max_requests"),
    ("max_attempts", "--max-attempts", "max_attempts"),
    ("max_duration", "--max-duration", "max_duration_s"),
    ("rate", "--rate", "rate_rps"),
)


class Cancelled(Exception):
    """The operator ended the dialog (Ctrl-C or end of input)."""


class Dialog:
    def __init__(self, ask, out):
        self._ask = ask
        self.out = out

    def question(self, text: str, default: str | None = None) -> str:
        try:
            answer = self._ask(f"{text}{f' [{default}]' if default else ''}: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise Cancelled from None
        return answer or (default or "")

    def yes(self, text: str, *, default: bool = False) -> bool:
        while True:
            answer = self.question(f"{text} [{'Y/n' if default else 'y/N'}]").lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.out("  answer y or n")


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def run_guided(args, *, interactive: bool, ask=None, out=print, environ=None) -> int:
    """Collect the settings of a run into `args` (the `verify` options) and hand them to verify."""
    if not interactive:
        args.non_interactive = True
        args.output = args.output or DEFAULT_OUTPUT
        missing = [flag for flag, value in (("--scope or --url", args.scope or args.target),
                                            ("--profile", args.profile)) if not value]
        if missing:
            _err(f"a non-interactive run needs {' and '.join(missing)}; nothing was contacted.")
            return cli.EXIT_BLOCKED
        return cli.cmd_verify(args)

    environ = os.environ if environ is None else environ
    cwd = Path.cwd()
    assessment = Path(args.assessment)
    _, plans, errors = cli._load_assessment(assessment)
    if errors:
        _err(f"the assessment {assessment} cannot be used:\n" + "\n".join(f"  - {clean(e)}" for e in errors))
        return cli.EXIT_BLOCKED
    try:
        Limits.load(_limit_overrides(args))
    except ValueError as exc:
        _err(f"invalid limits: {exc}")
        return cli.EXIT_BLOCKED
    if args.profile:
        try:
            cli._build_planner_factory(args)
        except cli.ProfileError as exc:
            _err(f"model profile unavailable: {exc}")
            return cli.EXIT_BLOCKED

    d = Dialog(ask or input, out)
    out(overview(assessment, plans))
    if not any(p.status == "dynamic" for p in plans):
        _err("\nno finding in this assessment can be verified dynamically; nothing to do.")
        return cli.EXIT_BLOCKED
    try:
        _ask_selection(d, args, plans)
        found = _ask_scope(d, args, assessment, cwd)
        if found is None:
            return cli.EXIT_BLOCKED
        scope, guard = found
        if _ask_identities(d, args, guard, environ, assessment, cwd) is None:
            return cli.EXIT_BLOCKED
        _ask_profile(d, args)
        _ask_mode(d, args, scope)
        _ask_output(d, args)
    except Cancelled:
        _err("\ncancelled; nothing was contacted.")
        return cli.EXIT_BLOCKED
    return cli.cmd_verify(args, invocation=equivalent_invocation(args), default_yes=True)


# ── overview and selection (VER-005, VER-006, VER-026) ───────────────────────

# What the findings of a class need before the run; without it their proof cannot be made (VER-009 to VER-012).
_NEEDS = {
    "access-control": "test identities in identities.yaml",
    "path-traversal": "marker_file in the scope and on the target",
    "ssrf": "callback in the scope",
    "xss": "Google Chrome with appsec-verifier[browser]",
}


def overview(assessment: Path, plans) -> str:
    dyn = [p for p in plans if p.status == "dynamic"]
    static = sum(1 for p in plans if p.status == "static-only")
    incomplete = sum(1 for p in plans if p.status == "input-incomplete")
    by_class = Counter(p.cls for p in dyn)
    by_sev = Counter(clean(p.severity).lower() or "unknown" for p in dyn)
    order = [*SEVERITY_FLOORS, *sorted(set(by_sev) - set(SEVERITY_FLOORS))]
    needs = " · ".join(f"{c}: {_NEEDS[c]}" for c in sorted(by_class) if c in _NEEDS)
    st = Style.for_stream(sys.stdout)
    return "\n".join([*cli._title(st, "assessment"), *cli._facts(st, [
        ("Assessment", str(assessment)),
        ("Findings", f"{len(plans)} total · {len(dyn)} dynamically verifiable · {static} static-only · "
                     f"{incomplete} input-incomplete"),
        ("By class", " · ".join(f"{c} {n}" for c, n in sorted(by_class.items())) or "—"),
        ("By severity", [(f"{s} {by_sev[s]}", cli._severity_role(s)) for s in order if by_sev[s]] or "—"),
        *([("Needs", needs)] if needs else []),
    ])])


def _ask_selection(d: Dialog, args, plans) -> None:
    """Only the severity floor is asked; the classes are all present unless --category or --class says otherwise."""
    ask_floor = not any((args.severity, args.min_severity, args.only))
    while True:
        if ask_floor:
            while True:
                answer = d.question(f"Lowest severity to verify ({', '.join(SEVERITY_FLOORS)}, or 'all')",
                                    DEFAULT_FLOOR).lower()
                if answer in (*SEVERITY_FLOORS, "all"):
                    args.min_severity = None if answer == "all" else answer
                    break
                d.out("  choose critical, high, medium, low, or all")
        dyn = sum(1 for p in cli._select(args, plans) if p.status == "dynamic")
        d.out(f"  → {dyn} finding{'' if dyn == 1 else 's'} to verify")
        if dyn or not ask_floor:
            return
        d.out("  nothing in this selection can be verified dynamically; choose again")


# ── target (VER-001, VER-004) ────────────────────────────────────────────────

def _candidates(name: str, *dirs: Path) -> list[Path]:
    seen, out = set(), []
    for directory in dirs:
        path = directory / name
        key = path.resolve()
        if key not in seen and path.is_file():
            seen.add(key)
            out.append(path)
    return out


def load_scope(path) -> tuple[dict | None, ScopeGuard | None, list[str]]:
    """The scope at `path` with its guard, or the reasons it cannot be used now."""
    try:
        scope = cli._load_yaml(Path(path))
    except (OSError, yaml.YAMLError) as exc:
        return None, None, [f"cannot read the scope file: {type(exc).__name__}"]
    if not isinstance(scope, dict):
        return None, None, ["the scope file is not a mapping"]
    errors = cli._validate_scope(scope)
    if errors:
        return None, None, errors
    guard = ScopeGuard(scope)
    window = guard.within_window()
    if not window.allowed:
        return None, None, [f"the authorisation window is not open now: {window.reason}"]
    return scope, guard, []


def _ask_scope(d: Dialog, args, assessment: Path, cwd: Path):
    """The scope file given or found, used as it is, or else the scope of the
    target URL the operator types (VER-001, VER-004). Returns the scope and its
    guard; None when a scope file cannot be used."""
    given = bool(args.scope)
    if not given:
        found = _candidates("scope.yaml", assessment.parent, cwd)
        if found:
            args.scope = str(found[0])
            d.out(f"  scope   {found[0]}")
    if args.scope:
        scope, guard, errors = load_scope(args.scope)
        if errors:
            _err(f"the scope file {args.scope} cannot be used; nothing was contacted:\n"
                 + "\n".join(f"  - {clean(e)}" for e in errors)
                 + "\ncorrect the file, e.g. its window" + ("." if given else ", or move it away to enter "
                                                                         "a target URL instead."))
            return None
        return scope, guard
    if args.target:
        scope, errors = cli.url_scope(args.target)
        if errors:
            _err(f"--url cannot be used: {clean(errors[0])}; nothing was contacted.")
            return None
        return scope, ScopeGuard(scope)
    d.out("No scope.yaml next to the assessment or in the working directory: the run tests only the host "
          "and port of the URL you enter, read-only (VER-001).")
    while True:
        url = d.question("Target URL you are authorised to test")
        scope, errors = cli.url_scope(url)
        if not errors:
            args.target = url
            return scope, ScopeGuard(scope)
        d.out(f"  {clean(errors[0])}")


# ── identities (VER-010, VER-016, VER-028) ──────────────────────────────────

def _ask_identities(d: Dialog, args, guard: ScopeGuard, environ, assessment: Path, cwd: Path):
    """The identities given, or a found identities.yaml unless the operator answers 'none'; [] without one."""
    if args.identities:
        identities, errors = cli._check_identities(args.identities, guard, environ)
        if errors:
            _err("identities are not usable; nothing was contacted:\n"
                 + "\n".join(f"  - {clean(e)}" for e in errors))
            return None
        return identities
    dirs = [Path(args.scope).parent] if args.scope else []
    found = _candidates("identities.yaml", *dirs, assessment.parent, cwd)
    if not found:
        return []
    while True:
        answer = d.question("Identities file (test roles; credentials come from environment variables), "
                            "or 'none'", str(found[0]))
        if answer.lower() == "none":
            return []
        identities, errors = cli._check_identities(answer, guard, environ)
        if not errors:
            args.identities = answer
            d.out(f"  roles: {', '.join(clean(i['role']) for i in identities)}")
            return identities
        for e in errors:
            d.out(f"  {clean(e)}")
        d.out("  set missing variables and start again, or choose another file or 'none'")


# ── model, mode, output (VER-015, VER-020, VER-023, VER-027, VER-030) ──

def _ask_profile(d: Dialog, args) -> None:
    if args.profile:
        return
    while True:
        answer = d.question(f"Model profile ({', '.join(PROFILES)})", DEFAULT_PROFILE)
        if answer not in PROFILES:
            d.out(f"  choose one of {', '.join(PROFILES)}")
            continue
        args.profile = answer
        try:
            cli._build_planner_factory(args)
            return
        except cli.ProfileError as exc:
            args.profile = None
            d.out(f"  {clean(exc)}")


def _limit_overrides(args) -> dict:
    return {field: getattr(args, attr) for attr, _, field in _LIMITS}


def _ask_mode(d: Dialog, args, scope: dict) -> None:
    if args.allow_intrusive or args.read_only or not scope.get("allow_state_change"):
        return
    d.out("The scope allows state change. Intrusive mode adds marked write requests (POST, PUT, PATCH) "
          "that are not cleaned up; use it only against a disposable test instance (VER-014, VER-030).")
    args.allow_intrusive = d.yes("Allow intrusive probes?")


def _ask_output(d: Dialog, args) -> None:
    args.output = args.output or DEFAULT_OUTPUT
    while not args.append and (Path(args.output) / "verification.yaml").exists():
        answer = d.question(f"A report already exists in {args.output}: [a]ppend to it, [o]verwrite it, "
                            "or write to a [n]ew directory", "a").lower()
        if answer in ("a", "append"):
            args.append = True
        elif answer in ("o", "overwrite"):
            return
        elif answer in ("n", "new"):
            args.output = d.question("Report directory", _free_dir(Path(args.output)))
        else:
            d.out("  answer a, o, or n")


def _free_dir(path: Path) -> str:
    n = 2
    while (candidate := path.with_name(f"{path.name}-{n}")).exists():
        n += 1
    return str(candidate)


# ── equivalent invocation ────────────────────────────────────────────────────

_VALUE_OPTIONS = (("scope", "--scope"), ("target", "--url"), ("identities", "--identities"),
                  ("source", "--source"), ("output", "--output"),
                  ("category", "--category"), ("cls", "--class"), ("severity", "--severity"),
                  ("min_severity", "--min-severity"), ("cwe", "--cwe"), ("only", "--only"),
                  *((attr, flag) for attr, flag, _ in _LIMITS), ("profile", "--profile"), ("model", "--model"),
                  ("screenshots", "--screenshots"))
_FLAGS = (("print_results", "--print"), ("append", "--append"), ("annotate", "--annotate"),
          ("in_place", "--in-place"), ("allow_intrusive", "--allow-intrusive"), ("read_only", "--read-only"),
          ("dry_run", "--dry-run"), ("headful", "--headful"))


def equivalent_invocation(args) -> str:
    """The `verify` command line that runs the same settings without questions,
    for CI: --non-interactive with --yes standing in for the confirmation (VER-002)."""
    parts = ["appsec-verifier", "verify", "--assessment", str(args.assessment)]
    for attr, flag in _VALUE_OPTIONS:
        value = getattr(args, attr, None)
        if value is not None:
            parts += [flag, str(value)]
    parts += [flag for attr, flag in _FLAGS if getattr(args, attr, False)]
    parts += ["--non-interactive", "--yes"]
    return " ".join(shlex.quote(p) for p in parts)
