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
and the scope is that URL's host and port, for this run only (VER-001,
VER-004).

Identities (VER-016, VER-028, VER-031, VER-040, VER-041): with --account or
--admin-account no identities file is asked for. Otherwise a credential variable the
identities file names but the environment lacks is asked for hidden. A file the
run found, rather than one given with --identities, that starts login programs
needs its own explicit yes, because a file next to a foreign assessment could
name any program. Without an identities file, when access-control findings are
selected, the run offers to take each role's session from a request the operator
copies from the browser ("Copy as cURL"); only its Cookie and Authorization are
kept. Values entered or pasted stay in this process and are never written.

The dialog contacts nothing, writes no file, and never widens a scope. Text from
the assessment is untrusted (VER-005) and is shown without control characters.
Without a terminal, or with --non-interactive, nothing is asked: the run takes
its settings from the invocation and blocks on a missing target or profile.
"""

from __future__ import annotations

import os
import shlex
import sys
from collections import ChainMap, Counter
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from . import cli
from .agent import DEFAULT_PROFILE, PROFILES
from .auth.paste import PasteError, ask_hidden, ask_hidden_block, session_from_curl
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
    def __init__(self, ask, out, secret=None, block=None):
        self._ask = ask
        self.out = out
        self._secret = secret or ask_hidden
        self._block = block or ask_hidden_block

    def secret(self, text: str) -> str:
        """One value without echo; empty at the end of input."""
        return self._hidden(self._secret, text)

    def block(self, text: str) -> str:
        """A pasted multi-line command without echo; empty when nothing was pasted."""
        return self._hidden(self._block, text)

    @staticmethod
    def _hidden(read, text: str) -> str:
        try:
            return read(text)
        except EOFError:
            return ""
        except KeyboardInterrupt:
            raise Cancelled from None

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


def run_guided(args, *, interactive: bool, ask=None, out=print, environ=None, ask_secret=None, ask_block=None) -> int:
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
    doc, plans, errors = cli._load_assessment(assessment)
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

    d = Dialog(ask or input, out, ask_secret, ask_block)
    out(overview(assessment, plans, doc))
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
        chosen = _ask_identities(d, args, guard, environ, assessment, cwd, scope, plans)
        if chosen is None:
            return cli.EXIT_BLOCKED
        secrets, pasted = chosen
        _ask_mode(d, args, scope)
        if not _ask_output(d, args):
            return cli.EXIT_BLOCKED
    except Cancelled:
        _err("\ncancelled; nothing was contacted.")
        return cli.EXIT_BLOCKED
    invocation = equivalent_invocation(args)
    if pasted:
        invocation += ("\n  It does not include the pasted sessions: put them in an identities file "
                       "(method session) and pass it with --identities.")
    return cli.cmd_verify(args, invocation=invocation, default_yes=True, secrets=secrets, pasted=pasted)


# ── overview and selection (VER-005, VER-006, VER-026) ───────────────────────



def overview(assessment: Path, plans, doc: dict | None = None) -> str:
    """The first screen of the guided run: the assessment, how many of its findings can be tested at
    runtime and their severities. The run settings that follow do not repeat it."""
    dyn = [p for p in plans if p.status == "dynamic"]
    incomplete = sum(1 for p in plans if p.status == "input-incomplete")
    by_sev = Counter(clean(p.severity).lower() or "unknown" for p in dyn)
    order = [*SEVERITY_FLOORS, *sorted(set(by_sev) - set(SEVERITY_FLOORS))]
    st = Style.for_stream(sys.stdout)
    counts = [(cli._count(len(dyn), "runtime candidate") + f" of {len(plans)}", "bold"),
              *((f"{s} {by_sev[s]}", cli._severity_role(s)) for s in order if by_sev[s]),
              *([(f"{incomplete} without a code location", "muted")] if incomplete else [])]
    summary = cli._assessment_summary(doc or {})
    return "\n".join([*cli._title(st, "assessment"), *cli._facts(st, [
        ("Assessment", f"{assessment} · {summary}" if summary else str(assessment)),
        ("Findings", counts),
    ])])


def _selection(d: Dialog, args, plans) -> bool:
    """The severity floor is high unless --min-severity, --severity or --only says
    otherwise, and every class present is tested unless --category or --class
    narrows them. When the default floor leaves nothing to verify, the run offers
    the next lower severity that has findings. False when there is none or the
    operator declines. The selection is shown with the run settings."""
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
          "and port of the URL you enter (VER-001).")
    while True:
        url = d.question("Target URL you are authorised to test")
        scope, errors = cli.url_scope(url)
        if not errors:
            args.target = url
            return scope, ScopeGuard(scope)
        d.out(f"  {clean(errors[0])}")


# ── identities (VER-010, VER-016, VER-028) ──────────────────────────────────

def _ask_identities(d: Dialog, args, guard: ScopeGuard, environ, assessment: Path, cwd: Path, scope: dict, plans):
    """(secrets, pasted identities or None) for verify, or None when the run stops. The identities given,
    or a found identities.yaml unless the operator answers 'none'; without a file the offer to paste
    sessions. Missing credential values are asked for hidden and kept in `secrets` (VER-016)."""
    secrets: dict = {}
    env = ChainMap(secrets, environ)

    def check(path):
        return cli._check_identities(path, guard, env, interactive=True, secrets=secrets, ask_secret=d.secret)

    if getattr(args, "account", None) or getattr(args, "admin_account", None):
        return secrets, None             # accounts on the command line; verify asks their passwords (VER-041)
    if args.identities:
        identities, errors = check(args.identities)
        if errors:
            _err("identities are not usable; nothing was contacted:\n"
                 + "\n".join(f"  - {clean(e)}" for e in errors))
            return None
        return secrets, None
    dirs = [Path(args.scope).parent] if args.scope else []
    found = _candidates("identities.yaml", *dirs, assessment.parent, cwd)
    if not found:
        return secrets, _ask_pasted(d, args, guard, scope, plans, secrets) or None
    while True:
        answer = d.question("Identities file (test roles; missing credentials are asked for hidden), "
                            "or 'none'", str(found[0]))
        if answer.lower() == "none":
            return secrets, None
        identities, errors = check(answer)
        if not errors:
            programs = cli._login_programs(identities)
            if programs and not d.yes(f"{clean(answer)} starts login programs: {clean(programs)}. Run them?"):
                d.out("  choose another file or 'none'")
                continue
            args.identities = answer
            d.out(f"  roles: {', '.join(clean(i['role']) for i in identities)}")
            return secrets, None
        for e in errors:
            d.out(f"  {clean(e)}")
        d.out("  set missing variables and start again, or choose another file or 'none'")


def _ask_pasted(d: Dialog, args, guard: ScopeGuard, scope: dict, plans, secrets: dict) -> list[dict]:
    """Identities with method session from requests the operator copies from the browser, when selected
    access-control findings have test resources in the scope, so two identities are all they lack (VER-010,
    VER-031). The roles are those the test resources name."""
    resources = [r for r in scope.get("test_resources", [])
                 if any(p.id == r.get("finding_id") and p.status == "dynamic" and p.cls == "access-control"
                        for p in cli._select(args, plans))]
    roles = sorted({str(r) for res in resources
                    for r in [*res.get("allowed_roles", []), *res.get("denied_roles", [])]} - {"anonymous"})
    if not roles:
        return []
    need = {r["finding_id"] for r in resources}
    target = scope["base_url"]
    d.out(f"{len(need)} access-control finding{'' if len(need) == 1 else 's'} need two signed-in users, and there "
          "is no identities file. You can take each role's session from your browser: sign in as that user "
          f"(a private window for the second), copy a request to {clean(target)} in the developer tools with "
          "'Copy as cURL (bash)' and paste it here. It is read hidden; only its Cookie and Authorization are "
          "kept, for this run only.")
    if not d.yes(f"Paste sessions for {', '.join(clean(r) for r in roles)}?"):
        return []
    pasted = []
    for role in roles:
        while True:
            text = d.block(f"Request copied as {clean(role)} (hidden; Enter alone skips this role): ")
            if not text:
                break
            try:
                headers, method, url = session_from_curl(text, target)
            except PasteError as exc:
                d.out(f"  {clean(exc)}")
                continue
            names = {}
            for header, value in headers.items():
                names[header] = f"APPSEC_VERIFIER_PASTED_{len(secrets) + 1}"
                secrets[names[header]] = value
            auth = {"headers_env": names}
            checked = method == "GET" and guard.authorize(url, "target").allowed
            if checked:
                auth["check_url"] = url            # a request this user just made; accepted means signed in
            d.out(f"  {clean(role)}: {' and '.join(headers)} taken"
                  + (f"; checked at {clean(urlsplit(url).path)} before the first finding" if checked else ""))
            pasted.append({"role": role, "method": "session", "auth": auth})
            break
    return pasted


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
                  ("login_url", "--login-url"), ("source", "--source"), ("output", "--output"),
                  ("category", "--category"), ("cls", "--class"), ("severity", "--severity"),
                  ("min_severity", "--min-severity"), ("cwe", "--cwe"), ("only", "--only"),
                  *((attr, flag) for attr, flag, _ in _LIMITS), ("profile", "--profile"), ("model", "--model"),
                  ("screenshots", "--screenshots"), ("console_log", "--console-log"))
_FLAGS = (("print_results", "--print"), ("resume", "--resume"), ("overwrite", "--overwrite"),
          ("annotate", "--annotate"), ("allow_intrusive", "--allow-intrusive"),
          ("read_only", "--read-only"), ("dry_run", "--dry-run"), ("headful", "--headful"), ("test_all", "--test-all"),
          ("show_costs", "--show-costs"), ("strict_severity", "--strict-severity"))


def equivalent_invocation(args) -> str:
    """The `verify` command line that runs the same settings without questions,
    for CI: --non-interactive with --yes standing in for the confirmation (VER-002)."""
    parts = ["appsec-verifier", "verify", "--assessment", str(args.assessment)]
    for attr, flag in _VALUE_OPTIONS:
        value = getattr(args, attr, None)
        if value is not None:
            parts += [flag, str(value)]
    for attr, flag in (("account", "--account"), ("admin_account", "--admin-account")):
        for value in getattr(args, attr, None) or []:
            parts += [flag, str(value)]
    parts += [flag for attr, flag in _FLAGS if getattr(args, attr, False)]
    parts += ["--non-interactive", "--yes"]
    return " ".join(shlex.quote(p) for p in parts)
