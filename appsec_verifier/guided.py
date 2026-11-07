"""Guided run from the assessment alone (VER-031).

`appsec-verifier <assessment>` reads the assessment offline, shows what it
holds, and asks for the settings of the run, each with a default. Answers pass
the same checks as the matching `verify` options and are re-asked when invalid;
options already given are used as given. The settings are then handed to
`verify`, which shows the run settings, the equivalent non-interactive
invocation, and asks for the one confirmation of VER-002.

The dialog contacts nothing, never asks for a secret value (credentials stay in
environment variables, VER-016), and never widens a scope. Without a scope file
it asks for the target, the end of the window, the owner and a reference, and
writes a scope next to the assessment that holds only these answers, never over
an existing file (VER-001, VER-004). Text from the assessment is untrusted (VER-005) and is
shown without control characters. Without a terminal, or with
--non-interactive, nothing is asked: the run takes its settings from the
invocation and blocks on a missing scope or profile.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from . import cli
from .agent import DEFAULT_PROFILE, PROFILES, SUBSCRIPTION_PROFILES
from .limits import Limits
from .loader import list_categories
from .preflight import printable as clean
from .scope import ScopeGuard
from .scope.guard import _parse_iso
from .term_style import Style

SEVERITY_FLOORS = ("critical", "high", "medium", "low")
DEFAULT_FLOOR = "high"
DEFAULT_OUTPUT = "./verification"

# (args attribute, verify option, Limits field, label, type)
_LIMITS = (
    ("cost_limit", "--cost-limit", "cost_limit_usd", "Cost ceiling, USD", float),
    ("max_calls", "--max-calls", "max_calls", "Model calls for the run", int),
    ("max_requests", "--max-requests", "max_requests", "Requests to the target", int),
    ("max_attempts", "--max-attempts", "max_attempts", "Agent steps per finding", int),
    ("max_duration", "--max-duration", "max_duration_s", "Run duration, seconds", float),
    ("rate", "--rate", "rate_rps", "Requests per second (0: no rate limit)", float),
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
        missing = [flag for flag, value in (("--scope", args.scope), ("--profile", args.profile)) if not value]
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
        _ask_target(d, args, scope, guard)
        identities = _ask_identities(d, args, guard, environ, assessment, cwd)
        if identities is None:
            return cli.EXIT_BLOCKED
        _note_access_control(d, args, plans, identities)
        _ask_profile(d, args)
        _ask_limits(d, args)
        _ask_mode(d, args, scope)
        _ask_output(d, args)
    except Cancelled:
        _err("\ncancelled; nothing was contacted.")
        return cli.EXIT_BLOCKED
    return cli.cmd_verify(args, invocation=equivalent_invocation(args))


# ── overview and selection (VER-005, VER-006, VER-026) ───────────────────────

def overview(assessment: Path, plans) -> str:
    dyn = [p for p in plans if p.status == "dynamic"]
    static = sum(1 for p in plans if p.status == "static-only")
    incomplete = sum(1 for p in plans if p.status == "input-incomplete")
    by_class = Counter(p.cls for p in dyn)
    by_sev = Counter(clean(p.severity).lower() or "unknown" for p in dyn)
    order = [*SEVERITY_FLOORS, *sorted(set(by_sev) - set(SEVERITY_FLOORS))]
    st = Style.for_stream(sys.stdout)
    return "\n".join([*cli._title(st, "assessment"), *cli._facts(st, [
        ("Assessment", str(assessment)),
        ("Findings", f"{len(plans)} total · {len(dyn)} dynamically verifiable · {static} static-only · "
                     f"{incomplete} input-incomplete"),
        ("By class", " · ".join(f"{c} {n}" for c, n in sorted(by_class.items())) or "—"),
        ("By severity", [(f"{s} {by_sev[s]}", cli._severity_role(s)) for s in order if by_sev[s]] or "—"),
    ])])


def _ask_selection(d: Dialog, args, plans) -> None:
    ask_classes = not any((args.category, args.cls, args.cwe, args.only))
    ask_floor = not any((args.severity, args.min_severity, args.only))
    present = sorted({p.cls for p in plans if p.status == "dynamic"})
    known = set(list_categories())
    while True:
        if ask_classes:
            while True:
                answer = d.question(f"Classes to verify ({', '.join(present)}, or 'all')", "all")
                chosen = {c.strip().lower() for c in answer.split(",") if c.strip()}
                if chosen == {"all"}:
                    args.category = None
                    break
                unknown = sorted(chosen - known)
                if chosen and not unknown:
                    args.category = ",".join(sorted(chosen))
                    break
                d.out(f"  unknown class: {', '.join(clean(u) for u in unknown) or '—'}; "
                      f"choose from {', '.join(sorted(known))}")
        if ask_floor:
            while True:
                answer = d.question(f"Lowest severity to verify ({', '.join(SEVERITY_FLOORS)}, or 'all')",
                                    DEFAULT_FLOOR).lower()
                if answer in (*SEVERITY_FLOORS, "all"):
                    args.min_severity = None if answer == "all" else answer
                    break
                d.out("  choose critical, high, medium, low, or all")
        sel = cli._select(args, plans)
        dyn = sum(1 for p in sel if p.status == "dynamic")
        d.out(f"  → {len(sel)} findings selected, {dyn} of them dynamically verifiable")
        if dyn or not (ask_classes or ask_floor):
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


_SCOPE_HEADER = """\
# Authorisation scope for AppSec Verifier (VER-001), written by the guided run
# from your answers. The Verifier contacts nothing outside it and never widens it.

"""

_SCOPE_MORE = """
# More settings, described under "Scope file" in docs/cli.md of
# https://github.com/appsec-foundry/appsec-verifier:
# hosts: [app.test.example.com, api.test.example.com]   all target hosts; replaces the host of base_url
# ports: [443, 8443]              all target ports; replaces the port of base_url
# path_prefixes: [/api/]          default: the whole host
# deny_paths: [/admin/]           paths that are never contacted
# networks: [10.0.0.0/8]          private networks the host names may resolve to
# Set allow_state_change to true only for a disposable instance: it allows
# marked write requests, together with --allow-intrusive.
"""


def _target_problem(url: str) -> str | None:
    """Why `url` cannot be the target of a new scope, or None."""
    if not url:
        return "a target URL is required; it is never taken from the assessment"
    if clean(url) != url or any(c.isspace() for c in url):
        return "the URL contains spaces or control characters"
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return "enter an absolute http or https URL with a host, e.g. https://app.test.example.com"
    if parts.username is not None or parts.password is not None:
        return "leave credentials out of the URL; test identities take theirs from environment variables"
    decision = ScopeGuard({"base_url": url, "schemes": [scheme]}).authorize(url, "target")
    return None if decision.allowed else clean(decision.reason)


def _window_end(answer: str) -> datetime | None:
    """The answer as a time in UTC; a date alone means the end of that day."""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", answer):
        answer += "T23:59:59Z"
    end = _parse_iso(answer)
    return end.astimezone(timezone.utc) if end else None


def _utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _create_scope(d: Dialog, args, path: Path):
    """Ask for the target, the end of the window, the owner and a reference, and
    write them as the scope at `path`, never over an existing file. Only the end
    of the window has a default, so the scope holds what the operator entered and
    nothing from the assessment (VER-001, VER-004, VER-031)."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    while True:
        url = d.question("Target URL you are authorised to test")
        problem = _target_problem(url)
        if problem is None:
            break
        d.out(f"  {problem}")
    while True:
        until = _window_end(d.question("Authorisation window ends (UTC)", now.strftime("%Y-%m-%dT23:59:59Z")))
        if until and until > now:
            break
        d.out("  enter a future date or time, e.g. 2026-11-30 or 2026-11-30T18:00:00Z")
    while not (owner := clean(d.question("Owner, the person responsible for this test")).strip()):
        d.out("  the owner is required; the report records it")
    reference = clean(d.question("Reference, e.g. ticket or approval (optional)")).strip() or None
    scope = {"schema_version": 1, "base_url": url, "schemes": [urlsplit(url).scheme.lower()],
             "window": {"from": _utc(now), "until": _utc(until)},
             "owner": {"name": owner, "contact": None, "reference": reference},
             "allow_state_change": False}
    errors = cli._validate_scope(scope)
    if errors:
        _err("the answers do not make a valid scope; nothing was written or contacted:\n"
             + "\n".join(f"  - {clean(e)}" for e in errors))
        return None
    try:
        with open(path, "x", encoding="utf-8") as fh:
            fh.write(_SCOPE_HEADER + yaml.safe_dump(scope, sort_keys=False, allow_unicode=True) + _SCOPE_MORE)
    except FileExistsError:
        _err(f"\n{path} already exists and was left unchanged. Nothing was contacted.")
        return None
    except OSError as exc:
        _err(f"\ncannot write {path}: {type(exc).__name__}. Nothing was contacted.")
        return None
    scope, guard, errors = load_scope(path)
    if errors:
        _err(f"\n{path} cannot be used:\n" + "\n".join(f"  - {clean(e)}" for e in errors))
        return None
    args.scope, args.target = str(path), url
    d.out(f"  wrote {path}\n"
          f"    target  {url} (whole host, read-only)\n"
          f"    window  {scope['window']['from']} → {scope['window']['until']}\n"
          f"    owner   {owner}")
    return scope, guard


def _ask_scope(d: Dialog, args, assessment: Path, cwd: Path):
    if args.scope:
        scope, guard, errors = load_scope(args.scope)
        if errors:
            _err("scope file is invalid:\n" + "\n".join(f"  - {clean(e)}" for e in errors))
            return None
        return scope, guard
    found = _candidates("scope.yaml", assessment.parent, cwd)
    if not found:
        d.out("No scope file found next to the assessment or in the working directory. The scope file "
              "authorises this test: target, time window, and owner (VER-001).")
    while True:
        if found:
            answer = d.question("Scope file", str(found[0]))
        else:
            answer = d.question("Scope file, or Enter to write one next to the assessment")
        if not answer:
            return _create_scope(d, args, assessment.parent / "scope.yaml")
        scope, guard, errors = load_scope(answer)
        if not errors:
            args.scope = answer
            return scope, guard
        for e in errors:
            d.out(f"  {clean(e)}")


def _ask_target(d: Dialog, args, scope: dict, guard: ScopeGuard) -> None:
    if args.target:
        return
    while True:
        answer = d.question("Target URL", str(scope.get("base_url")))
        decision = guard.authorize(answer, "target")
        if decision.allowed:
            args.target = answer
            return
        d.out(f"  out of scope: {clean(decision.reason)}")


# ── identities (VER-010, VER-016, VER-028) ──────────────────────────────────

def _ask_identities(d: Dialog, args, guard: ScopeGuard, environ, assessment: Path, cwd: Path):
    if args.identities:
        identities, errors = cli._check_identities(args.identities, guard, environ)
        if errors:
            _err("identities are not usable; nothing was contacted:\n"
                 + "\n".join(f"  - {clean(e)}" for e in errors))
            return None
        return identities
    found = _candidates("identities.yaml", Path(args.scope).parent, assessment.parent, cwd)
    while True:
        answer = d.question("Identities file (test roles; credentials come from environment variables), "
                            "or 'none'", str(found[0]) if found else "none")
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


def _note_access_control(d: Dialog, args, plans, identities) -> None:
    """Without a test identity only the anonymous caller is left, and an
    access-control finding needs two identities to be confirmed (VER-010)."""
    n = sum(1 for p in cli._select(args, plans) if p.status == "dynamic" and p.cls == "access-control")
    if n and not identities:
        d.out(f"  note: {n} access-control finding(s) selected; without a test identity they cannot be "
              "confirmed (VER-010)")


# ── model, limits, mode, output (VER-015, VER-020, VER-023, VER-027, VER-030) ──

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
    return {field: getattr(args, attr) for attr, _, field, _, _ in _LIMITS}


def _ask_limits(d: Dialog, args) -> None:
    subscription = args.profile in SUBSCRIPTION_PROFILES
    limits = Limits.load(_limit_overrides(args))
    cost = "cost not reported" if subscription else f"cost ≤ ${limits.cost_limit_usd:.2f}"
    d.out(f"Run limits: {cost} · ≤ {limits.max_calls} model calls · ≤ {limits.max_requests} requests · "
          f"≤ {limits.max_attempts} steps per finding · ≤ {int(limits.max_duration_s)} s · {limits.rate_rps} rps")
    if not d.yes("Change the run limits?"):
        return
    for attr, _, field, label, kind in _LIMITS:
        if getattr(args, attr) is not None or (attr == "cost_limit" and subscription):
            continue
        current = getattr(limits, field)
        while True:
            answer = d.question(label, str(current))
            try:
                value = kind(answer)
                Limits.load({**_limit_overrides(args), field: value})
            except ValueError as exc:
                d.out(f"  {clean(exc)}")
                continue
            if value != current:
                setattr(args, attr, value)
            break


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

_VALUE_OPTIONS = (("identities", "--identities"), ("source", "--source"), ("output", "--output"),
                  ("category", "--category"), ("cls", "--class"), ("severity", "--severity"),
                  ("min_severity", "--min-severity"), ("cwe", "--cwe"), ("only", "--only"),
                  *((attr, flag) for attr, flag, *_ in _LIMITS), ("profile", "--profile"), ("model", "--model"),
                  ("screenshots", "--screenshots"))
_FLAGS = (("print_results", "--print"), ("append", "--append"), ("annotate", "--annotate"),
          ("in_place", "--in-place"), ("allow_intrusive", "--allow-intrusive"), ("read_only", "--read-only"),
          ("dry_run", "--dry-run"), ("headful", "--headful"))


def equivalent_invocation(args) -> str:
    """The `verify` command line that runs the same settings without questions,
    for CI: --non-interactive with --yes standing in for the confirmation (VER-002)."""
    parts = ["appsec-verifier", "verify", "--assessment", str(args.assessment), "--scope", str(args.scope),
             "--url", str(args.target)]
    for attr, flag in _VALUE_OPTIONS:
        value = getattr(args, attr, None)
        if value is not None:
            parts += [flag, str(value)]
    parts += [flag for attr, flag in _FLAGS if getattr(args, attr, False)]
    parts += ["--non-interactive", "--yes"]
    return " ".join(shlex.quote(p) for p in parts)
