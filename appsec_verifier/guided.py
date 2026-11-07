"""Guided run from the assessment alone (VER-031).

`appsec-verifier <assessment>` reads the assessment offline, shows what it
holds, and asks only for what has no usable default: the target URL when there
is no scope file, an identities file when one is found, and whether to overwrite
a report already in the output directory. The severity floor
is high and the model profile claude unless options say otherwise; the run
prints the floor, and offers the next lower severity when nothing of high or
above can be verified. A profile that is not available stops the run before
any question. Answers pass the same checks as the matching `verify`
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
    """A stop, shown like `verify`'s: the first line marked ✗, the details under it."""
    st = Style.for_stream(sys.stderr)
    lead, first = ("\n", message[1:]) if message.startswith("\n") else ("", message)
    head, _, rest = first.partition("\n")
    print(lead + st(f"✗ {head[:1].upper()}{head[1:]}", "critical", "bold") + (f"\n{rest}" if rest else ""),
          file=sys.stderr)


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
    args.profile = args.profile or DEFAULT_PROFILE
    try:
        cli._build_planner_factory(args)
    except cli.ProfileError as exc:
        _err(f"model profile unavailable: {exc}\nchoose another with --profile ({', '.join(PROFILES)}).")
        return cli.EXIT_BLOCKED

    d = Dialog(ask or input, out)
    out(overview(assessment, plans))
    if not any(p.status == "dynamic" for p in plans):
        _err("\nno finding in this assessment can be verified dynamically; nothing to do.")
        return cli.EXIT_BLOCKED
    try:
        if not _selection(d, args, plans):
            return cli.EXIT_BLOCKED
        found = _ask_scope(d, args, assessment, cwd)
        if found is None:
            return cli.EXIT_BLOCKED
        scope, guard = found
        if _ask_identities(d, args, guard, environ, assessment, cwd) is None:
            return cli.EXIT_BLOCKED
        _ask_mode(d, args, scope)
        if not _ask_output(d, args):
            return cli.EXIT_BLOCKED
    except Cancelled:
        _err("\ncancelled; nothing was contacted.")
        return cli.EXIT_BLOCKED
    return cli.cmd_verify(args, invocation=equivalent_invocation(args), default_yes=True)


# ── overview and selection (VER-005, VER-006, VER-026) ───────────────────────



def overview(assessment: Path, plans) -> str:
    dyn = [p for p in plans if p.status == "dynamic"]
    static = sum(1 for p in plans if p.status == "static-only")
    incomplete = sum(1 for p in plans if p.status == "input-incomplete")
    by_class = Counter(p.cls for p in dyn)
    by_sev = Counter(clean(p.severity).lower() or "unknown" for p in dyn)
    order = [*SEVERITY_FLOORS, *sorted(set(by_sev) - set(SEVERITY_FLOORS))]
    st = Style.for_stream(sys.stdout)
    counts = [f"{len(plans)} total", f"{len(dyn)} testable against the running app",
              *([f"{static} code-only"] if static else []),
              *([f"{incomplete} without a code location"] if incomplete else [])]
    return "\n".join([*cli._title(st, "assessment"), *cli._facts(st, [
        ("Assessment", str(assessment)),
        ("Findings", " · ".join(counts)),
        ("By class", " · ".join(f"{c} {n}" for c, n in sorted(by_class.items())) or "—"),
        ("By severity", [(f"{s} {by_sev[s]}", cli._severity_role(s)) for s in order if by_sev[s]] or "—"),
    ])])


def _selection(d: Dialog, args, plans) -> bool:
    """The severity floor is high unless --min-severity, --severity or --only says
    otherwise, and every class present is tested unless --category or --class
    narrows them. When the default floor leaves nothing to verify, the run offers
    the next lower severity that has findings. False when there is none or the
    operator declines."""
    def dynamic() -> int:
        return sum(1 for p in cli._select(args, plans) if p.status == "dynamic")

    if not any((args.severity, args.min_severity, args.only)):
        args.min_severity = DEFAULT_FLOOR
        if not dynamic():
            for lower in SEVERITY_FLOORS[SEVERITY_FLOORS.index(DEFAULT_FLOOR) + 1:]:
                args.min_severity = lower
                if n := dynamic():
                    break
            else:
                _err("no finding of a known severity can be verified dynamically in this selection; choose "
                     "findings with --only or --severity. Nothing was contacted.")
                return False
            if not d.yes(f"No finding of severity {DEFAULT_FLOOR} or above can be verified dynamically. "
                         f"Verify the {n} of severity {lower}?", default=True):
                _err("nothing to verify; nothing was contacted.")
                return False
    dyn = dynamic()
    floor = f", severity {args.min_severity} and above (--min-severity to change)" if args.min_severity else ""
    d.out(f"  → {dyn} finding{'' if dyn == 1 else 's'} to verify{floor}")
    return True


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


# ── limits, mode, output (VER-015, VER-020, VER-027, VER-030) ──

def _limit_overrides(args) -> dict:
    return {field: getattr(args, attr) for attr, _, field in _LIMITS}


def _ask_mode(d: Dialog, args, scope: dict) -> None:
    if args.allow_intrusive or args.read_only or not scope.get("allow_state_change"):
        return
    d.out("The scope allows state change. Intrusive mode adds marked write requests (POST, PUT, PATCH) "
          "that are not cleaned up; use it only against a disposable test instance (VER-014, VER-030).")
    args.allow_intrusive = d.yes("Allow intrusive probes?")


def _ask_output(d: Dialog, args) -> bool:
    """The report goes to --output or ./verification. A report already there is replaced only with
    --overwrite or a yes here, and --resume continues it; a no stops the run before anything is contacted."""
    args.output = args.output or DEFAULT_OUTPUT
    if args.resume or args.overwrite or not cli.report_exists(args.output):
        return True
    if d.yes(f"There is already a report in {clean(args.output)}. Overwrite it?"):
        args.overwrite = True
        return True
    _err(f"\nthe report in {clean(args.output)} was kept; nothing was contacted.\n"
         "  --resume continues it, --output DIR writes elsewhere.")
    return False


# ── equivalent invocation ────────────────────────────────────────────────────

_VALUE_OPTIONS = (("scope", "--scope"), ("target", "--url"), ("identities", "--identities"),
                  ("source", "--source"), ("output", "--output"),
                  ("category", "--category"), ("cls", "--class"), ("severity", "--severity"),
                  ("min_severity", "--min-severity"), ("cwe", "--cwe"), ("only", "--only"),
                  *((attr, flag) for attr, flag, _ in _LIMITS), ("profile", "--profile"), ("model", "--model"),
                  ("screenshots", "--screenshots"))
_FLAGS = (("print_results", "--print"), ("resume", "--resume"), ("overwrite", "--overwrite"),
          ("annotate", "--annotate"), ("in_place", "--in-place"), ("allow_intrusive", "--allow-intrusive"),
          ("read_only", "--read-only"), ("dry_run", "--dry-run"), ("headful", "--headful"), ("test_all", "--test-all"),
          ("show_costs", "--show-costs"))


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
