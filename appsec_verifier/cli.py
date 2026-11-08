"""appsec-verifier — command-line entry point.

`scope` and `export` run offline (no network, no model calls). `verify`
contacts the target through an agent only when model access is configured;
otherwise it reports every selected finding not-attempted. Before the first
finding it runs the pre-flight checks of VER-032, one fixed model test included;
`preflight` runs them alone, shows the test plan, and verifies nothing (preflight.py). Called with an
assessment and no command, it starts the guided run of guided.py (VER-031),
which asks only for the `verify` settings without a default and then runs `verify`. See docs/cli.md
for the full design.
"""

from __future__ import annotations

import argparse
import difflib
import os
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

from .limits import Limits, RunBudget
from .loader import AssessmentError, plans_from, read_assessment, select
from .preflight import (
    Check,
    check_identities,
    check_target,
    confirm_authorization,
    failed,
    generation_test,
    printable,
    proxy_for,
    render,
)
from .progress import RunProgress, duration, spent_text
from .scope import ScopeGuard
from .term_style import Style, columns, logo
from .verify import build_annotations, run_verification, write_reports
from .verify.report import annotate_assessment, read_report, write_text_atomically
from .version_info import resource_root, version_string

EXIT_OK = 0
EXIT_BLOCKED = 2            # run could not start (bad input, unconfirmed, etc.)
EXIT_LIMIT = 3              # a limit stopped at least one finding
EXIT_INTERRUPTED = 130      # Ctrl-C; a verify run still writes what it found so far


def _csv(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {v.strip() for v in value.split(",") if v.strip()}


def _select(args: argparse.Namespace, plans):
    """Apply the selection options of `args` (VER-026)."""
    from .planning import dependency_order, supplement

    filters = dict(
        categories=_csv(args.category),
        classes=_csv(args.cls),
        severities=_csv(args.severity),
        min_severity=args.min_severity,
        cwes={c.upper() for c in (_csv(args.cwe) or set())} or None,
        ids=_csv(args.only),
    )
    selected = select(plans, **filters)
    if args.min_severity and not args.only and not args.severity:
        eligible = select(plans, **{**filters, "min_severity": None})
        selected = supplement(selected, eligible, enabled=not getattr(args, "strict_severity", False))
    return dependency_order(selected)


# ── console layout, as in AppSec Analyzer ───────────────────────────────────

_logo_shown = False
_SEVERITIES = ("critical", "high", "medium", "low")
# Facts whose value leads in a colour of its own; the others are bold.
_FACT_ROLES = {"Assessment": "accent", "Target": "accent", "Base URL": "accent", "Report": "accent",
               "Data": "accent", "Action log": "accent", "Annotated": "accent", "Profile": "agent"}


def _title(st: Style, mode: str) -> list[str]:
    """The logo on a terminal, once per process; otherwise `▶ AppSec Verifier · mode · version`."""
    global _logo_shown
    if st.enabled and not _logo_shown:
        _logo_shown = True
        return logo(st, f"{version_string()} · {mode}", columns() - 1)
    return [st(f"▶ AppSec Verifier · {mode} · {version_string()}", "bold")]


def _facts(st: Style, rows: list[tuple]) -> list[str]:
    """Rows as `  Key        : value`. A row is (key, value) or (key, value, role);
    the value up to ` (` takes the role, the rest is muted. A value given as
    [(text, role), …] is joined with ` · `. On a terminal a long value wraps
    under its own column; a path or URL is never split. Values pass `printable`
    before they are coloured."""
    width = max([11, *(len(row[0]) + 1 for row in rows)])
    fit = columns() - 1 - (2 + width + 2) if st.enabled else 0
    lines = []
    for key, value, *given in rows:
        role = (given and given[0]) or _FACT_ROLES.get(key, "bold")
        label = st(f"{key:<{width}}:", "muted")
        if isinstance(value, list):
            lines.append(f"  {label} " + st(" · ", "muted").join(st(printable(t), r) for t, r in value))
            continue
        value = printable(value)
        pieces = (textwrap.wrap(value, fit, break_long_words=False, break_on_hyphens=False)
                  if fit > 20 and len(value) > fit else [value])
        head, sep, tail = pieces[0].partition(" (")
        lines.append(f"  {label} {st(head, role)}{st(sep + tail, 'muted')}".rstrip())
        lines += [f"  {'':<{width}}  {st(piece, 'muted')}" for piece in pieces[1:]]
    return lines


def _severity_role(severity: str) -> str:
    return severity.lower() if severity.lower() in _SEVERITIES else "muted"


# ── assessment ──────────────────────────────────────────────────────────────


def _load_assessment(path: Path) -> tuple[dict | None, list, list[str]]:
    """(assessment, plans, []), or (None, [], why it cannot be used) (VER-005, VER-032)."""
    import yaml
    try:
        doc = read_assessment(path)
    except AssessmentError as exc:
        return None, [], exc.errors
    except (OSError, yaml.YAMLError) as exc:
        return None, [], [f"cannot read it: {type(exc).__name__}"]
    except ValueError as exc:                       # not a mapping at the top level
        return None, [], [str(exc)]
    return doc, plans_from(doc), []


def report_exists(output) -> bool:
    """Whether the output directory already holds a report; only --overwrite replaces it."""
    return any((Path(output) / name).is_file() for name in ("verification.yaml", "verification.md"))


def _blocked(headline: str, details=(), fix: str | None = None, *, contacted: bool = False) -> int:
    """Why a run cannot go on, shown the same way everywhere on standard error: what is wrong, the
    details, what to do, and, unless something was contacted, that nothing was. Exit 2."""
    sys.stdout.flush()                  # after the settings and the test plan, also when both go to one log
    st = Style.for_stream(sys.stderr)
    lines = ["", st(f"✗ {printable(headline)}", "critical", "bold"), *(f"  - {printable(d)}" for d in details)]
    if fix:
        lines.append(f"  → {fix}")
    if not contacted:
        lines.append(st("  Nothing was contacted.", "muted"))
    print("\n".join(lines), file=sys.stderr)
    return EXIT_BLOCKED


def _assessment_summary(doc: dict) -> str:
    """Project and date from the assessment's meta block, to tell it is the intended one."""
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    return " · ".join(printable(meta[k])[:60] for k in ("project", "generated") if meta.get(k))


# ── scope ─────────────────────────────────────────────────────────────────────


def _load_yaml(path: Path) -> dict:
    import yaml
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _validate_scope(scope: dict) -> list[str]:
    """Validate against schemas/scope.schema.yaml with jsonschema when present,
    else a minimal required-key check so the command still works."""
    schema = _load_yaml(resource_root() / "schemas" / "scope.schema.yaml")
    try:
        from jsonschema.validators import validator_for

        cls = validator_for(schema)
        cls.check_schema(schema)
        errors = [f"{'/'.join(map(str, e.path))}: {e.message}" for e in cls(schema).iter_errors(scope)]
    except ModuleNotFoundError:
        errors = [f"missing required field: {k}" for k in schema.get("required", []) if k not in scope]
    from .scope.guard import parse_network

    networks = scope.get("networks") if isinstance(scope, dict) else None
    if isinstance(networks, list):
        errors += [f"networks: {n!r} is not an IP network (CIDR)" for n in networks if parse_network(n) is None]
    if not errors:
        for check in scope.get("session_checks", []):
            url = (
                check["path"]
                if "://" in check["path"]
                else scope["base_url"].rstrip("/") + "/" + check["path"].lstrip("/")
            )
            if not ScopeGuard(scope).authorize(url, "target").allowed:
                errors.append("session_checks: a cookie observation is outside the target scope")
        resources = scope.get("test_resources", [])
        ids = [r["id"] for r in resources]
        if len(ids) != len(set(ids)):
            errors.append("test_resources: ids must be unique")
        for r in resources:
            if "json" in r and "form" in r:
                errors.append("test_resources: choose either json or form for the request body")
            if set(r["allowed_roles"]) & set(r["denied_roles"]):
                errors.append("test_resources: allowed and denied roles must be disjoint")
            if (
                not ScopeGuard(scope)
                .authorize(
                    r["path"] if "://" in r["path"] else scope["base_url"].rstrip("/") + "/" + r["path"].lstrip("/"),
                    "target",
                )
                .allowed
            ):
                errors.append("test_resources: a resource is outside the target scope")
    return errors


def _read_scope(path: Path) -> tuple[dict | None, list[str]]:
    """The scope file and why it is not valid; a file that cannot be read is an error, not an exception."""
    import yaml
    try:
        scope = _load_yaml(path)
    except (OSError, yaml.YAMLError) as exc:
        return None, [f"cannot read it: {type(exc).__name__}"]
    if not isinstance(scope, dict):
        return None, ["it is not a mapping"]
    return scope, _validate_scope(scope)


def url_scope(url: str | None) -> tuple[dict | None, list[str]]:
    """Without a scope file, the scope of the target URL alone (VER-001): its scheme, host and port, the
    whole host, read-only. It lasts for this run, so it has no window and no owner. The URL comes from the
    operator, never from the assessment (VER-004)."""
    from urllib.parse import urlsplit

    if not url:
        return None, ["a target URL is required; it is never taken from the assessment"]
    if printable(url) != url or any(c.isspace() for c in url):
        return None, ["the URL contains spaces or control characters"]
    try:
        parts = urlsplit(url)
        scheme, host = parts.scheme.lower(), parts.hostname
    except ValueError:
        scheme, host = "", None
    if scheme not in ("http", "https") or not host:
        return None, ["enter an absolute http or https URL with a host, e.g. https://app.test.example.com"]
    if parts.username is not None or parts.password is not None:
        return None, ["leave credentials out of the URL; test identities take theirs from environment variables"]
    scope = {"schema_version": 1, "base_url": url, "schemes": [scheme], "allow_state_change": False}
    decision = ScopeGuard(scope).authorize(url, "target")
    return (scope, []) if decision.allowed else (None, [printable(decision.reason)])


def cmd_scope(args: argparse.Namespace) -> int:
    scope, errors = _read_scope(Path(args.scope))
    if errors:
        print("scope file is invalid:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_BLOCKED
    window = scope.get("window", {})
    guard = ScopeGuard(scope)
    win = guard.within_window()
    state_change = bool(scope.get("allow_state_change"))
    rows = [
        ("Base URL", str(scope.get("base_url"))),
        ("Hosts", ", ".join(scope.get("hosts", []) or [scope.get("base_url", "")])),
        ("Ports", ", ".join(map(str, scope.get("ports", []) or []))),
        ("Networks", ", ".join(map(str, scope.get("networks", []) or []))
         or "— (public addresses, and hosts named by IP or as localhost)"),
        ("Path prefixes", ", ".join(scope.get("path_prefixes", []) or ["/"])),
        ("Window", f"{window.get('from')} → {window.get('until')} ({'open now' if win.allowed else 'not open now'})",
         "ok" if win.allowed else "critical"),
        ("Owner", str((scope.get("owner") or {}).get("name"))),
        ("State change", "allowed" if state_change else "read-only", "warn" if state_change else "ok"),
        ("Auth hosts", ", ".join(scope.get("auth_hosts", []) or ["—"])),
        ("Proxy", (scope.get("proxy") or {}).get("url") or "—"),
    ]
    st = Style.for_stream(sys.stdout)
    print("\n".join([*_title(st, "scope"), *_facts(st, rows)]))
    if args.target:
        d = guard.authorize(args.target, "target")
        verdict = st("INSIDE scope", "ok") if d.allowed else st(f"OUT OF SCOPE — {printable(d.reason)}", "critical")
        print(f"\ntarget {printable(args.target)}: {verdict}")
        if not d.allowed:
            return EXIT_BLOCKED
    print("\n" + st("scope only — nothing was contacted.", "muted"))
    return EXIT_OK


# ── verify ────────────────────────────────────────────────────────────────────

_IDENTITY_ENDPOINTS = ("login_url", "token_url", "authorize_url")


def _check_identities(path: str | None, guard: ScopeGuard, env) -> tuple[list[dict], list[str]]:
    """Load the identities file and check it before anything is contacted
    (VER-016, VER-025, VER-028): schema-valid, every `*_env` variable set, each
    authentication endpoint allowed by the scope for authentication, each
    `target_origin` inside the scope, and each `check_url` inside the scope on an
    identity that has credentials (VER-032). Errors name variables, never values."""
    if not path:
        return [], []
    import yaml
    from jsonschema.validators import validator_for

    try:
        doc = _load_yaml(Path(path))
    except (OSError, yaml.YAMLError) as exc:
        return [], [f"cannot read the identities file: {type(exc).__name__}"]
    schema = _load_yaml(resource_root() / "schemas" / "identities.schema.yaml")
    validator = validator_for(schema)(schema)
    errors = [f"{'/'.join(map(str, e.path)) or 'file'}: {e.message}" for e in validator.iter_errors(doc)]
    if errors:
        return [], errors
    identities = doc["identities"]
    roles = [i["role"] for i in identities]
    errors += [f"role {r!r} is defined more than once" for r in sorted({r for r in roles if roles.count(r) > 1})]
    for ident in identities:
        role, auth = ident["role"], ident.get("auth") or {}
        if ident["method"] == "oidc-authorization-code":
            errors.append(f"{role}: oidc-authorization-code is not implemented yet")
        for key, name in auth.items():
            if key.endswith("_env") and name and not env.get(name):
                errors.append(f"{role}: environment variable {name} ({key}) is not set")
        for key in _IDENTITY_ENDPOINTS:
            decision = guard.authorize(auth[key], "auth") if auth.get(key) else None
            if decision is not None and not decision.allowed:
                errors.append(f"{role}: {key} is refused for authentication: {decision.reason}")
        if auth.get("target_origin") and not guard.origin_allowed(auth["target_origin"]):
            errors.append(f"{role}: target_origin is outside the scope")
        if auth.get("check_url"):
            decision = guard.authorize(auth["check_url"], "target")
            if ident["method"] == "none":
                errors.append(f"{role}: check_url needs an identity with credentials, not method none")
            elif not decision.allowed:
                errors.append(f"{role}: check_url is outside the scope: {decision.reason}")
    return identities, errors


def _check_proxy(scope: dict, env) -> list[str]:
    """The declared proxy's URL and credential variables (VER-016, VER-029, VER-032).
    Without this, a missing variable would send no proxy credentials at all.
    Errors name variables, never values."""
    from urllib.parse import urlsplit

    proxy = scope.get("proxy") or {}
    if not proxy.get("url"):
        return []
    try:
        parts = urlsplit(proxy["url"])
        valid = parts.scheme in ("http", "https") and bool(parts.hostname) and (parts.port or 1) > 0
    except ValueError:
        valid = False
    if not valid:
        return ["proxy: url must be an http or https URL with a host and a valid port"]
    errors = []
    if parts.username or parts.password:
        errors.append("proxy: url must not contain credentials; name them with username_env and password_env")
    names = [proxy.get("username_env"), proxy.get("password_env")]
    if any(names) and not all(names):
        errors.append("proxy: username_env and password_env are needed together")
    errors += [f"proxy: environment variable {name} is not set" for name in names if name and not env.get(name)]
    return errors


class ProfileError(Exception):
    """The model profile cannot be used for this run."""


def _build_planner_factory(args, environ=None, *, check_access: bool = True):
    """Resolve the model profile (--profile) into (planner factory, agent info),
    chosen as in AppSec Analyzer: without --profile an interactive run uses
    `claude`; a non-interactive run must name its profile. An API profile's model
    metadata is read once unless `check_access` is off (VER-032)."""
    from .agent import DEFAULT_PROFILE, PROFILES, SUBSCRIPTION_PROFILES, HostUnavailable
    from .agent.profiles import resolve

    profile = args.profile
    if profile is None:
        if args.non_interactive:
            raise ProfileError(f"--non-interactive needs an explicit --profile ({', '.join(PROFILES)})")
        profile = DEFAULT_PROFILE
    if profile in SUBSCRIPTION_PROFILES and args.cost_limit is not None:
        raise ProfileError(f"--cost-limit is not available with {profile}, which reports no cost; "
                           "bound the run with --max-calls and --max-duration")
    try:
        return resolve(profile, model=args.model, environ=os.environ if environ is None else environ,
                       check_access=check_access)
    except HostUnavailable as exc:
        raise ProfileError(f"{profile}: {exc}") from exc


def cmd_verify(args: argparse.Namespace, invocation: str | None = None, default_yes: bool = False) -> int:
    """Verify the selected findings. `invocation`, from the guided run, is the
    equivalent non-interactive command line, shown before the confirmation;
    `default_yes` is set by the guided run only, so Enter at its confirmation
    proceeds (VER-002)."""
    assessment = Path(args.assessment)
    if not assessment.is_file():
        return _blocked(f"The assessment {assessment} was not found", fix="check the path given with --assessment")
    if args.scope:
        scope_path = Path(args.scope)
        scope, errors = _read_scope(scope_path)
        errors = errors or _check_proxy(scope, os.environ)
        if errors:
            return _blocked(
                f"The scope file {scope_path} cannot be used",
                errors,
                f"correct it; `appsec-verifier scope --scope {scope_path}` checks it without a run",
            )
    else:
        scope_path = None
        scope, errors = url_scope(args.target)
        if errors:
            return _blocked(
                "The target URL cannot be used",
                errors,
                "give --url as http(s)://host[:port], or a scope file with --scope",
            )

    guard = ScopeGuard(scope)
    win = guard.within_window()
    if not win.allowed:
        return _blocked(
            "The scope's test window is not open now",
            [win.reason],
            "adjust window.from and window.until in the scope file",
        )
    target = args.target or scope.get("base_url")
    td = guard.authorize(target, "target")
    if not td.allowed:
        return _blocked(
            f"The target {target} is outside the scope",
            [td.reason],
            "use the scope's base_url, or add the target to the scope file",
        )

    doc, plans, errors = _load_assessment(assessment)
    if errors:
        return _blocked(f"The assessment {assessment} cannot be used", errors)
    sel = _select(args, plans)
    if not sel:
        return _blocked(
            "No finding matches the selection", fix="widen it with --min-severity, --category, --class or --only"
        )

    try:
        limits = Limits.load(
            {
                "cost_limit_usd": args.cost_limit,
                "max_requests": args.max_requests,
                "max_attempts": args.max_attempts,
                "max_calls": args.max_calls,
                "max_duration_s": args.max_duration,
                "rate_rps": args.rate,
            }
        )
    except ValueError as exc:
        return _blocked(
            "Invalid limits",
            [str(exc)],
            "check --cost-limit, --max-calls, --max-requests, --max-attempts, --max-duration and --rate",
        )
    existing, resumed = None, None
    existing_path = Path(args.output) / "verification.yaml"
    if not args.resume and not args.overwrite and report_exists(args.output):
        return _blocked(
            f"There is already a report in {args.output}",
            fix="replace it with --overwrite, continue it with --resume, or write to another --output",
        )
    if args.resume and existing_path.is_file():  # checked now: the merge comes after the run
        from .verify.report import remaining_variants, resume_problems
        from .verify.runner import _sha256

        existing, errors = read_report(existing_path)
        errors = errors or resume_problems(existing, _sha256(assessment), target)
        if errors:
            return _blocked(
                f"The report {existing_path} cannot be continued with --resume",
                errors,
                "write to a new --output, or replace it with --overwrite instead of --resume",
            )
        todo = remaining_variants(sel, existing)
        if not any(p.status == "dynamic" for p in todo):
            print(
                f"nothing to resume: every selected finding has a verdict in {existing_path}; nothing was contacted.",
                file=sys.stderr,
            )
            return EXIT_OK
        resumed = f"continues {existing_path} · remaining variants are tested separately"
        sel = todo
    from .planning import evidence_id, expand_variants

    sel = expand_variants(sel)
    safe = not args.allow_intrusive
    read_only = True if safe else (args.read_only or not scope.get("allow_state_change", False))

    identities, id_errors = _check_identities(args.identities, guard, os.environ)
    if id_errors:
        return _blocked(
            "The identities cannot be used",
            id_errors,
            "export the variables named above, or start without --identities",
        )
    budget = RunBudget(limits)
    try:
        planner_factory, agent_info = _build_planner_factory(args)
    except ProfileError as exc:
        from .agent import PROFILES

        return _blocked(
            f"Model profile unavailable: {exc}", fix=f"choose another with --profile ({', '.join(PROFILES)})"
        )
    # As in AppSec Analyzer: costs on the console with API billing, in any mode with --show-costs.
    show_costs = args.show_costs or agent_info.get("api_billing", False)
    from .agent import SUBSCRIPTION_PROFILES, SourceReader, agent_registry
    from .auth import SessionManager
    from .tools import GuardedHttpClient
    from .tools.httpx_transport import transport_from_scope

    http = GuardedHttpClient(guard, budget, transport_from_scope(scope))
    sessions = SessionManager(identities, http, env=os.environ)
    source = SourceReader(args.source) if args.source else None
    registry = agent_registry(planner_factory, max_steps=limits.max_attempts)
    browser, browser_note, browser_missing = _proof_browser(args, http, sel)
    listener, listener_note = _callback_listener(scope, sel)
    probed = [p for p in sel if p.status == "dynamic" and registry.get(p.cls)]
    blocked = (
        {}
        if args.test_all
        else {
            evidence_id(p): need
            for p in probed
            if (need := _blocker(p, identities=identities, browser=browser, listener=listener, scope=scope, safe=safe))
        }
    )
    skipped = {fid: reason for fid, (_, reason) in blocked.items()}
    contact = any(evidence_id(p) not in skipped for p in probed)

    summary = _assessment_summary(doc)
    st = Style.for_stream(sys.stdout)
    out = Path(args.output)
    report_note = resumed or (
        ("replaces " if report_exists(args.output) else "")
        + f"{out / 'verification.md'} (Markdown, and verification.yaml for tools)"
    )
    notes = (
        ("Report", report_note),
        ("Identities", _identities_note(identities, sel)),
        ("Browser", browser_note),
        ("Callback", listener_note),
        ("Marker file", _marker_note(scope, sel)),
    )
    if not args.test_all:  # what is missing is said once, in the test plan
        notes = tuple(
            (k, v) for k, v in notes if not (v and v.startswith("unavailable") and v.endswith("cannot be confirmed"))
        )
    print(
        "\n".join(
            _verify_settings(
                st,
                f"{assessment} · {summary}" if summary else assessment,
                target,
                scope,
                sel,
                limits,
                safe,
                read_only,
                contact,
                agent_info,
                notes,
                floor=args.min_severity,
            )
        )
    )
    print("\n".join(_test_cases(st, probed, blocked, _run_hints(doc, target, browser_missing))))
    if probed and not contact:
        return _blocked(
            "Nothing to test in this run; no report was written",
            fix="provide what the findings above need, or use --test-all to try them anyway",
        )
    if invocation:
        print(f"\nThe same run without questions, e.g. in CI:\n  {invocation}")

    if contact:
        conf = confirm_authorization(non_interactive=args.non_interactive, assume_yes=args.yes, default_yes=default_yes)
        if not conf.confirmed:
            return _blocked(
                "Not authorised to proceed",
                [conf.reason],
                "confirm at the prompt, or pass --yes in a non-interactive run",
            )
        authorization = {
            "confirmed": True,
            "mode": conf.mode,
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    else:
        print(
            "\n"
            + st(
                "No target-contacting probe is available yet — emitting a report with every "
                "selected finding as not-attempted. Nothing was contacted.",
                "warn",
            )
        )
    if not contact:
        authorization = {"confirmed": False, "mode": "ci-flag" if args.non_interactive else "interactive", "at": None}

    if args.dry_run:
        print("\n" + st("--dry-run: selection and scope resolved; no report written, nothing contacted.", "muted"))
        return EXIT_OK

    if contact:  # VER-032: reachability, logins and the model before the first finding
        print("\n" + st("Preflight", "bold"), flush=True)
        checks: list[Check] = []

        def add(*items: Check) -> None:
            checks.extend(items)
            print(render(list(items), st), flush=True)

        add(check_target(http, target, proxy=proxy_for(scope, target)))
        if not failed(checks):
            add(
                *(
                    check_identities(sessions, identities, http, target, scope=scope)
                    if identities
                    else [Check("Identities", "info", "none given; only anonymous requests are possible")]
                )
            )
        if not failed(checks):
            add(_model_test(planner_factory, budget, show_costs=show_costs))
        if failed(checks):
            return _blocked(
                "A pre-flight check failed; no finding was tested", fix="see the ✗ line under Preflight", contacted=True
            )

    out_dir = Path(args.output)
    action_log = progress = None
    started = time.monotonic()
    if contact:
        from .verify.actionlog import ActionLog

        out_dir.mkdir(parents=True, exist_ok=True)
        action_log = ActionLog(out_dir / "agent-log.jsonl", redact=sessions.redact, append=existing is not None)
        priced = show_costs and agent_info["profile"] not in SUBSCRIPTION_PROFILES  # these report no amount
        progress = RunProgress(
            model=agent_info.get("model"),
            redact=sessions.redact,
            remaining_time=budget.remaining_time,
            spent=(lambda: budget.cost) if priced else None,
            cost_limit=limits.cost_limit_usd,
            api_prices=not agent_info.get("api_billing", False),
            out_dir=out_dir,
        )
    try:
        if listener is not None and contact:
            try:
                listener.start()
            except OSError as exc:
                print(
                    f"callback listener could not start ({type(exc).__name__}: {exc.strerror or exc}); "
                    "SSRF findings cannot be confirmed",
                    file=sys.stderr,
                )
                listener = None
        doc = run_verification(
            assessment_path=assessment,
            scope=scope,
            scope_path=scope_path,
            plans=sel,
            limits=limits,
            identities=identities,
            registry=registry,
            http=http,
            sessions=sessions,
            source=source,
            budget=budget,
            verifier_version=version_string(),
            target_base=target,
            authorization=authorization,
            safe=safe,
            read_only=read_only,
            contacted=contact,
            agent=agent_info,
            browser=browser,
            listener=listener if contact else None,
            log=action_log,
            evidence_dir=out_dir / "evidence",
            progress=progress,
            skipped=skipped,
        )
    finally:
        if progress is not None:
            progress.close()
        if action_log is not None:
            action_log.close()
        if browser is not None:
            browser.close()
        if listener is not None:
            listener.close()

    if existing is not None:
        from .verify import merge_reports

        doc = merge_reports(existing, doc)
    paths = write_reports(doc, out_dir)
    extra = []
    if contact:
        extra.append(("Run", _run_usage(budget, time.monotonic() - started, agent_info, show_costs)))
    if action_log is not None:
        extra.append(("Action log", str(action_log.path)))
    if args.annotate:
        import yaml

        annotated = annotate_assessment(_load_yaml(assessment), doc)
        dest = assessment if args.in_place else (out_dir / "security-assessment.annotated.yaml")
        write_text_atomically(dest, yaml.safe_dump(annotated, sort_keys=False, allow_unicode=True))
        extra.append(("Annotated", f"{dest}" + (" (in place)" if args.in_place else "")))

    print("\n".join(_results(st, doc, plans, blocked, full=args.print_results)))
    print("\n".join(_verify_summary(st, doc, paths, extra)))
    if doc["meta"].get("interrupted"):
        print(
            "\ninterrupted: the report holds the results so far; the findings not tested are marked not-attempted.",
            file=sys.stderr,
        )
        return EXIT_INTERRUPTED
    return EXIT_LIMIT if any(r.get("limits_hit") for r in doc["results"]) else EXIT_OK


# ── preflight (VER-032) ───────────────────────────────────────────────────────


def cmd_preflight(args: argparse.Namespace) -> int:
    """The checks of VER-032 without verifying anything. The offline checks come
    first; the target and its logins only after the confirmation of VER-002 and
    not with --offline; --test-model adds one bounded model call. Progress goes
    to stdout, or to stderr with --json, which prints the result on stdout."""
    from .guided import load_scope

    args.non_interactive = args.non_interactive or args.json     # a JSON run never prompts
    out = sys.stderr if args.json else sys.stdout
    st = Style.for_stream(out)
    checks: list[Check] = []

    def add(*items: Check) -> None:
        checks.extend(items)
        print(render(list(items), st), file=out, flush=True)

    print(st("Preflight", "bold"), file=out)
    doc, plans, errors = _load_assessment(Path(args.assessment))
    if errors:
        add(Check("Assessment", "fail", "; ".join(errors)))
    else:
        add(_assessment_check(doc, plans))

    if args.scope:
        scope, guard, errors = load_scope(args.scope)
    else:
        scope, errors = url_scope(args.target)
        guard = ScopeGuard(scope) if scope else None
    target = args.target or (scope or {}).get("base_url")
    if errors:
        add(Check("Scope", "fail", "; ".join(errors)))
    elif not (decision := guard.authorize(target, "target")).allowed:
        add(Check("Scope", "fail", f"{target} is out of scope: {decision.reason}"))
        guard = None
    elif not args.scope:
        add(Check("Scope", "ok", f"no scope file: only {target}'s host and port, read-only"))
    else:
        window = scope.get("window") or {}
        add(Check("Scope", "ok", f"{target} in scope · window until {window.get('until')} · "
                                 f"owner {(scope.get('owner') or {}).get('name')}"))
        if (scope.get("proxy") or {}).get("url"):
            add(_proxy_check(scope, target))

    identities: list[dict] = []
    if not args.identities:
        add(Check("Identities", "info", "none given; only anonymous requests are possible"))
    elif guard is None:
        add(Check("Identities", "info", "not checked without a usable scope"))
    else:
        identities, errors = _check_identities(args.identities, guard, os.environ)
        add(Check("Identities", "fail", "; ".join(errors)) if errors else
            Check("Identities", "ok", f"{', '.join(i['role'] for i in identities)} · environment variables set"))
    plan: list[str] = []
    if not failed(checks):
        plan_check, plan = _preflight_plan(st, doc, plans, scope, identities, target)
        if plan_check:
            add(plan_check)

    host, test_budget = None, None
    try:
        factory, info = _build_planner_factory(args, check_access=not args.offline)
    except ProfileError as exc:
        add(Check("Model", "fail", str(exc)))
    else:
        host = factory.host
        unproven = "quota not checked" if info["check"] == "model metadata accessible" else \
            "server access and quota not checked" + (" (--offline)" if args.offline else "")
        add(Check("Model", "ok", f"{info['profile']} · {info['model']} · {info['runtime']} · {info['auth']} · "
                                 f"{info['check']}; {unproven}"))
        if args.test_model:
            test_budget, problem = _generation_budget(args, info["profile"])
            if problem:
                add(Check("Model test", "fail", problem))

    if failed(checks):
        return _preflight_result(args, checks, out, plan)
    if args.offline:
        add(Check("Target", "info", "not contacted (--offline): reachability and logins not checked"))
    else:
        from .auth import SessionManager
        from .tools import GuardedHttpClient
        from .tools.httpx_transport import transport_from_scope

        via = proxy_for(scope, target)
        print(f"\nThe next checks contact {target}{f' via proxy {via}' if via else ''}: one GET, one login "
              "per identity with a login or token endpoint, one GET per check_url.", file=out)
        conf = confirm_authorization(non_interactive=args.non_interactive, assume_yes=args.yes)
        if not conf.confirmed:
            add(Check("Target", "fail", f"not contacted: {conf.reason}; confirm with --yes, or use --offline"))
        else:
            http = GuardedHttpClient(guard, RunBudget(Limits.load()), transport_from_scope(scope))
            add(check_target(http, target, proxy=via))
            if not failed(checks):
                add(*check_identities(SessionManager(identities, http, env=os.environ), identities, http, target,
                                      scope=scope))
    if test_budget is not None:
        if failed(checks):
            add(Check("Model test", "info", "not run: an earlier check failed"))
        else:
            print(f"\nModel test: one fixed prompt to {host.model}, without target data, findings or credentials; "
                  + (f"limit ${args.cost_limit:.2f}" if args.cost_limit is not None else "one call of the plan"),
                  file=out)
            add(generation_test(host, test_budget, show_costs=args.show_costs or info.get("api_billing", False)))
    return _preflight_result(args, checks, out, plan)


def _preflight_plan(st, doc, plans, scope, identities, target) -> tuple[Check | None, list[str]]:
    """The test plan `verify` would show for these inputs, for every finding and in safe mode
    (VER-008, VER-032): a check line that warns when a finding cannot be tested, and the plan
    itself, which findings it tests and what the others need. Contacts nothing."""
    from .agent import AGENT_CLASSES
    from .tools.browser import BrowserUnavailable, ProofBrowser

    probed = [p for p in plans if p.status == "dynamic" and p.cls in AGENT_CLASSES]
    browser_missing = None
    if any(p.cls == "xss" for p in probed):
        try:
            ProofBrowser.check_available()
        except BrowserUnavailable as exc:
            browser_missing = str(exc)
    listener, _ = _callback_listener(scope, probed)  # validated only; it binds on start()
    from .planning import evidence_id

    blocked = {
        evidence_id(p): need
        for p in probed
        if (
            need := _blocker(
                p,
                identities=identities,
                browser=None if browser_missing else True,
                listener=listener,
                scope=scope,
                safe=True,
            )
        )
    }
    lines = _test_cases(st, probed, blocked, _run_hints(doc, target, browser_missing))
    if not probed:
        return None, lines
    if not blocked:
        return Check("Test plan", "ok", f"{_count(len(probed), 'finding')} can be tested"), lines
    if len(blocked) == len(probed):
        return Check(
            "Test plan",
            "warn",
            "no finding can be tested; verify stops before contacting the target "
            "unless run with --test-all (see below)",
        ), lines
    return Check(
        "Test plan",
        "warn",
        f"{len(probed) - len(blocked)} of {_count(len(probed), 'finding')} can be "
        "tested; the others need what this run does not have (see below)",
    ), lines


def _assessment_check(doc: dict, plans) -> Check:
    counts = {s: sum(p.status == s for p in plans) for s in ("dynamic", "static-only", "input-incomplete")}
    text = (f"{len(plans)} findings: {counts['dynamic']} dynamic, {counts['static-only']} static-only, "
            f"{counts['input-incomplete']} input-incomplete")
    summary = _assessment_summary(doc)
    text = f"{summary} · {text}" if summary else text
    if not counts["dynamic"]:
        return Check("Assessment", "warn", f"{text}; nothing can be verified dynamically")
    return Check("Assessment", "ok", text)


def _proxy_check(scope: dict, target: str) -> Check:
    errors = _check_proxy(scope, os.environ)
    if errors:
        return Check("Proxy", "fail", "; ".join(errors))
    proxy = scope["proxy"]
    via = proxy_for(scope, target)
    if via is None:
        return Check("Proxy", "info", f"declared, but {target} is reached directly (no_proxy)")
    creds = (f"credentials from {proxy['username_env']} and {proxy['password_env']}" if proxy.get("username_env")
             else "without credentials")
    return Check("Proxy", "ok", f"{via} · {creds}")


def _model_test(planner_factory, budget: RunBudget, *, show_costs: bool) -> Check:
    """VER-032 in `verify`: one fixed prompt without target data, findings or
    credentials, counted against the run's own limits, before the first finding."""
    return generation_test(planner_factory.host, budget, show_costs=show_costs)


def _generation_budget(args, profile: str) -> tuple[RunBudget | None, str | None]:
    """The separate limit of --test-model: one call, and for a priced profile an
    explicit cost limit of at least USD 0.01, as in AppSec Analyzer."""
    from .agent import SUBSCRIPTION_PROFILES

    if args.offline:
        return None, "--test-model calls the model, so it cannot run with --offline"
    if profile in SUBSCRIPTION_PROFILES:
        if args.max_calls is None or args.max_calls < 1:
            return None, f"--test-model with {profile} needs --max-calls 1: the test uses one call of the plan"
    elif args.cost_limit is None or args.cost_limit < 0.01:
        return None, "--test-model needs --cost-limit of at least 0.01 (USD) for its one call"
    try:
        return RunBudget(Limits.load({"cost_limit_usd": args.cost_limit, "max_calls": 1})), None
    except ValueError as exc:
        return None, f"invalid limit: {exc}"


def _preflight_result(args, checks: list[Check], out, plan: list[str]) -> int:
    import json

    ok = not failed(checks)
    st = Style.for_stream(out)
    if plan:
        print("\n".join(plan), file=out)
    print("\n" + st(f"preflight {'passed' if ok else 'failed'}; nothing was verified.", "ok" if ok else "critical"),
          file=out)
    if args.json:
        print(json.dumps({"kind": "preflight", "ok": ok, "verification": "not_run",
                          "checks": [c.as_dict() for c in checks]}, sort_keys=True))
    return EXIT_OK if ok else EXIT_BLOCKED


def screenshot_option(value: str) -> str:
    """`--screenshots`: classes from SCREENSHOT_CLASSES, comma-separated, or `none` (VER-035)."""
    from .tools.browser import SCREENSHOT_CLASSES

    names = [v.strip().lower() for v in str(value).split(",") if v.strip()]
    if names == ["none"]:
        return "none"
    unknown = [n for n in names if n not in SCREENSHOT_CLASSES]
    if not names or unknown:
        raise argparse.ArgumentTypeError(f"expected 'none' or classes from {', '.join(SCREENSHOT_CLASSES)}"
                                         + (f"; unknown: {', '.join(unknown)}" if unknown else ""))
    return ",".join(c for c in SCREENSHOT_CLASSES if c in names)


def _screenshot_classes(args) -> frozenset:
    from .tools.browser import SCREENSHOT_CLASSES

    value = getattr(args, "screenshots", None)
    if value is None:
        return frozenset(SCREENSHOT_CLASSES)
    return frozenset() if value == "none" else frozenset(value.split(","))


def _proof_browser(args, http, sel):
    """The proof browser when an XSS finding is selected (VER-009), or a finding
    of a class with screenshots on (VER-035), else None; with a line for the run
    settings and, when it is unavailable, what is missing and how to add it.
    Without it XSS findings stay unconfirmed and nothing gets a screenshot."""
    shots = _screenshot_classes(args)
    xss = any(p.status == "dynamic" and p.cls == "xss" for p in sel)
    shown = any(p.status == "dynamic" and p.cls in shots for p in sel)
    if not (xss or shown):
        return None, None, None
    from .tools.browser import SCREENSHOT_CLASSES, BrowserUnavailable, ProofBrowser

    try:
        ProofBrowser.check_available()
    except BrowserUnavailable as exc:
        lost = "XSS findings cannot be confirmed" if xss else "findings get no screenshot"
        return None, f"unavailable ({exc}); {lost}", str(exc)
    browser = ProofBrowser(http, Path(args.output) / "evidence", headless=not args.headful, screenshots=shots)
    listed = ("all classes" if shots == set(SCREENSHOT_CLASSES)
              else ", ".join(c for c in SCREENSHOT_CLASSES if c in shots) or "none")
    return browser, ("Google Chrome via Playwright" + (", visible" if args.headful else "")
                     + f", started on first use · screenshots: {listed}"), None


def _callback_listener(scope, sel):
    """The SSRF callback listener when an SSRF finding is selected (VER-012), not yet started, else None;
    with a line for the run settings. Without it SSRF findings stay unconfirmed."""
    if not any(p.status == "dynamic" and p.cls == "ssrf" for p in sel):
        return None, None
    from .tools.callback import CallbackListener, CallbackUnavailable

    try:
        listener = CallbackListener(scope.get("callback"))
    except CallbackUnavailable as exc:
        return None, f"unavailable ({exc}); SSRF findings cannot be confirmed"
    return listener, f"will listen on {listener.host}:{listener.port}, reached as {listener.base_url}"


def _marker_note(scope, sel):
    """A line for the run settings when a path-traversal finding is selected. Without the scope's
    marker_file no traversal value is sent, so these findings stay unconfirmed (VER-012). It names
    the path, never the content."""
    if not any(p.status == "dynamic" and p.cls == "path-traversal" for p in sel):
        return None
    path = (scope.get("marker_file") or {}).get("path")
    if not path:
        return "unavailable (no marker_file in the scope); path-traversal findings cannot be confirmed"
    return f"{path} (must exist on the target)"


def _identities_note(identities, sel):
    """A line for the run settings when an access-control finding is selected: its proof contrasts
    identities, so without a test identity it cannot be made (VER-010). It names roles only."""
    if not any(p.status == "dynamic" and p.cls == "access-control" for p in sel):
        return None
    if not identities:
        return "unavailable (no test identity); access-control findings cannot be confirmed"
    return ", ".join(str(i["role"]) for i in identities)


# What a finding this run cannot test needs: its name in the test plan, and how the operator provides it.
# The browser's and the identity's lines are replaced by ones that fit this run (_run_hints).
_NEEDS = {
    "resource": ("test resource", ["add an operator-owned test_resources entry to the scope file, with the "
                                     "finding ID, allowed and denied roles, and a harmless response marker"]),
    "capability": ("test capability", ["the reported variant needs a tool this run does not provide; "
                                        "keep it unresolved or test that variant separately"]),
    "identity": ("test identity", ["create an identities file with two test accounts and pass it with "
                                   "--identities FILE (docs/cli.md, Identities file)"]),
    "browser": ("proof browser", ["install Playwright and Google Chrome"]),
    "marker": ("marker file", ["place a file holding a random token (16 to 128 of A-Z a-z 0-9 _ -) on the "
                               "target and add to a scope file (--scope):",
                               "marker_file: {path: /path/on/the/target/marker.txt, content: TOKEN}",
                               "(docs/cli.md, Scope file)"]),
    "callback": ("callback", ["add to a scope file (--scope):",
                              'callback: {host: 127.0.0.1, port: 8099, base_url: "http://127.0.0.1:8099"}',
                              "(docs/cli.md, Scope file)"]),
    "intrusive": ("intrusive mode", ["run with --allow-intrusive; the scope file needs allow_state_change: true"]),
}


_EXAMPLE_IDENTITIES = "https://github.com/appsec-foundry/appsec-verifier/blob/main/examples/juice-shop/identities.yaml"


def _run_hints(doc: dict, target: str, browser_missing: str | None) -> dict[str, list[str]]:
    """How-tos that fit this run: what the proof browser actually lacks, and for test identities
    the login the assessment names and where an example file is."""
    from .endpoints import login_endpoint

    example = resource_root() / "examples" / "juice-shop" / "identities.yaml"
    login = login_endpoint(doc.get("attack_surface"))
    identity = ["create an identities file with two test accounts and pass it with --identities FILE; it names "
                "the environment variables for user name and password, never the values",
                *([f"login the assessment names: POST {target.rstrip('/')}{login}"] if login else []),
                f"example: {example if example.is_file() else _EXAMPLE_IDENTITIES} (docs/cli.md, Identities file)"]
    return {"identity": identity, **({"browser": [browser_missing]} if browser_missing else {})}


def _blocker(plan, *, identities, browser, listener, scope, safe) -> tuple[str, str] | None:
    """What this run lacks to confirm `plan` (a _NEEDS key and the reason for the
    report), or None when it can try: first what its class's proof needs (VER-009
    to VER-012), then the requests the assessment names (endpoints.py), when all
    of them write in safe mode or all need a login and there is no test identity.
    A finding that names no request is tried."""
    from .endpoints import WRITE_METHODS
    from .verification_context import missing_capabilities

    if plan.cls == "session" and not any(r["finding_id"] == plan.id for r in scope.get("session_checks", [])):
        return "resource", "no operator-identified session cookie in session_checks"
    if plan.cls == "access-control" and not identities:
        return "identity", "no test identity; the proof compares two identities"
    if plan.cls == "access-control" and not any(r["finding_id"] == plan.id for r in scope.get("test_resources", [])):
        return "resource", "no declared test resource with allowed and denied identities"
    if plan.cls == "access-control":
        roles = {i["role"] for i in identities} | {"anonymous"}
        resources = [r for r in scope.get("test_resources", []) if r["finding_id"] == plan.id]
        if not any(set(r["allowed_roles"]) <= roles and set(r["denied_roles"]) <= roles for r in resources):
            return "resource", "a declared test resource names roles unavailable in this run"
    if plan.cls == "xss" and browser is None:
        return "browser", "no proof browser; XSS counts only when the payload executes"
    if plan.cls == "path-traversal" and not (scope.get("marker_file") or {}).get("path"):
        return "marker", "no marker_file in the scope"
    if plan.cls == "ssrf" and listener is None:
        return "callback", "no callback in the scope"
    variants = getattr(plan, "verification_context", {}).get("variants", [])
    missing = [missing_capabilities(v, safe=safe, browser=browser is not None) for v in variants]
    if missing and all(missing):
        needs = sorted({need for row in missing for need in row})
        if needs == ["state-change"]:
            return "intrusive", "safe mode; every declared variant needs a state change"
        return "capability", "declared variants need unavailable capabilities: " + ", ".join(needs)
    requests = [e for e in plan.endpoints if e.method != "PAGE"]
    if requests and safe and all(e.method in WRITE_METHODS for e in requests):
        return "intrusive", "safe mode; every request the assessment names writes"
    if requests and not identities and all(e.login for e in requests):
        return "identity", "no test identity; every request the assessment names requires a login"
    return None


def _wrap_whole(text: str, width: int) -> list[str]:
    """Wrap at spaces only, so a path, command or finding id stays whole and can be copied."""
    return textwrap.wrap(text, width, break_on_hyphens=False, break_long_words=False)


def _test_cases(st, plans, blocked: dict[str, tuple[str, str]], hints: dict[str, list[str]] | None = None) -> list[str]:
    """The test plan before the confirmation: each finding the run tests with the requests the
    assessment names, then those it cannot test, grouped by what they need and how to provide it.
    `hints` replaces a need's how-to with what is actually missing (the browser's cause)."""
    if not plans:
        return []
    from .planning import evidence_id

    tested = [p for p in plans if evidence_id(p) not in blocked]
    head = (
        f"{len(tested)} of {_count(len(plans), 'finding')} will be tested"
        if tested
        else "this run can test none of them"
        if len(plans) > 1
        else "this run cannot test it"
    )
    lines = ["", f"{st('Test plan', 'bold')}     {head}"]
    width = max(len(printable(p.id)) for p in plans)
    for p in tested:
        what = " · ".join(printable(x) for x in (", ".join(map(str, p.endpoints[:2])), p.title or p.cwe) if x)
        lines.append(
            f"  {printable(p.id):<{width}}  {st(f'{printable(p.severity).lower():<8}', 'muted')}  "
            f"{printable(p.cls or ''):<14}  {what}"
        )
        if p.selection_reason:
            lines.append(f"    additionally selected: {printable(p.selection_reason)}")
    if not blocked:
        return lines
    groups: dict[str, list[str]] = {}
    for p in plans:
        if evidence_id(p) in blocked:
            groups.setdefault(blocked[evidence_id(p)][0], []).append(printable(p.id))
    lines += [
        "",
        f"{st('Not testable', 'bold')}  {_count(len(blocked), 'finding')} "
        f"{'needs' if len(blocked) == 1 else 'need'} what this run does not have (--test-all tries anyway)",
    ]
    label_width = max(len(_NEEDS[key][0]) for key in groups)
    indent = 2 + label_width + 2 + 2 + 2
    room = max(columns() - 1 - indent, 30)
    for key, ids in sorted(groups.items(), key=lambda group: -len(group[1])):
        label, how = _NEEDS[key]
        how = [printable(text) for text in (hints or {}).get(key) or how]
        wrapped = _wrap_whole(", ".join(ids), room) or [""]
        lines.append(f"  {st(f'{label:<{label_width}}', 'warn')}  {len(ids):>2}  {wrapped[0]}")
        lines += [" " * indent + piece for piece in wrapped[1:]]
        for n, text in enumerate(how):  # a line to copy stays whole; prose wraps
            pieces = [text] if text.startswith(("marker_file:", "callback:")) else _wrap_whole(text, room - 2)
            lines += [
                " " * indent + st(("→ " if n == 0 and i == 0 else "  ") + piece, "muted")
                for i, piece in enumerate(pieces)
            ]
    return lines


def _verify_settings(st, assessment, target, scope, sel, limits, safe, read_only, contact, agent_info,
                     notes=(), floor=None) -> list[str]:
    dyn = sum(1 for p in sel if p.status == "dynamic")
    from .agent import SUBSCRIPTION_PROFILES

    cost = ("cost not reported (subscription)" if agent_info["profile"] in SUBSCRIPTION_PROFILES
            else f"≤ ${limits.cost_limit_usd:.2f}")
    seconds = int(limits.max_duration_s)
    rate = f"{limits.rate_rps:g} requests/s" if limits.rate_rps else "no rate limit"
    rows = [
        ("Assessment", str(assessment)),
        ("Target", f"{target} ({'will contact' if contact else 'not contacted yet'})"),
        ("Scope", f"{', '.join(scope.get('hosts', []) or [target])} (owner: {(scope.get('owner') or {}).get('name')})"
         if "owner" in scope else f"no scope file: only {target}'s host and port, read-only"),
        ("Selection", " · ".join([_count(len(sel), "finding") + (f", severity {floor} and above" if floor else ""),
                                  f"{dyn} testable against the running app",
                                  *([f"{len(sel) - dyn} code-only"] if len(sel) > dyn else [])])),
        # The profile's own check is not repeated: the pre-flight model test shows whether the model answers.
        ("Profile", " · ".join(v for v in (agent_info.get(k) for k in ("profile", "model", "runtime", "auth")) if v)),
        ("Limits", f"{cost} · ≤ {limits.max_calls} model calls · ≤ {limits.max_requests} requests · ≤ "
                   + (f"{seconds // 60} min" if seconds % 60 == 0 else f"{seconds} s") + f" · {rate}"),
        ("Mode", "safe: only GET, HEAD and OPTIONS" if safe else
         f"intrusive · {'read-only' if read_only else 'state-changing'}", "ok" if safe else "warn"),
    ]
    for key, note in notes:
        if note:
            rows.append((key, note, "warn" if note.startswith(("unavailable", "replaces")) else None))
    return [*_title(st, "verify"), *_facts(st, rows)]


# Seen from the finding: green when the run confirmed it, red when it could not reproduce it or a control
# blocked it (a likely false positive), yellow when the run could not decide.
_VERDICT_MARK = {"confirmed": ("✓", "ok"), "not-reproducible": ("✗", "critical"),
                 "blocked-by-control": ("⊘", "critical"), "inconclusive": ("?", "warn"),
                 "not-attempted": ("·", "muted")}


_VERDICT_ORDER = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")


def _results(st: Style, doc, plans, blocked: dict[str, tuple[str, str]], *, full: bool = False) -> list[str]:
    """The overview at the end (VER-013): per finding its id, severity, class, result and title, and
    under it the reason, confirmed first. A finding this run could not test shows what it needs as
    its result. Only findings testable against the app, unless `full` (--print) lists every finding
    with its whole reason. Text from the assessment and the model passes `printable` before it is
    coloured (VER-005); on a terminal a line is cut to fit."""
    from .loader import _SEVERITY_RANK
    from .verify.report import _VERDICT_LABEL

    severity = {p.id: printable(p.severity).lower() for p in plans}
    rows = [r for r in doc["results"] if full or (r.get("eligibility") or {}).get("status") == "dynamic"]
    if not rows:
        return []
    rows.sort(key=lambda r: (_VERDICT_ORDER.index(r["verdict"]),
                             -_SEVERITY_RANK.get(severity.get(r["finding_ref"].get("id"), ""), 0)))

    def result(r) -> str:
        fid = r["finding_ref"].get("id")
        if r["verdict"] == "not-attempted" and fid in blocked:
            return f"needs {_NEEDS[blocked[fid][0]][0]}"
        return _VERDICT_LABEL[r["verdict"]] + (f" ({printable(r['confidence'])})" if r.get("confidence") else "")

    room = columns() - 1 if st.enabled else 10_000
    id_width = max(len(printable(r["finding_ref"].get("id"))) for r in rows)
    result_width = max(len(result(r)) for r in rows)
    indent = 4                     # the reason starts under the id
    lines = ["", st("Results", "bold")]
    for r in rows:
        fr = r["finding_ref"]
        mark, role = _VERDICT_MARK[r["verdict"]]
        cells = (f"{printable(fr.get('id')):<{id_width}}  {severity.get(fr.get('id'), ''):<8}  "
                 f"{printable(r.get('class') or '-'):<14}  ")
        title = printable(fr.get("title") or fr.get("cwe") or "")
        used = 4 + len(cells) + result_width + 2
        lines.append(f"  {st(mark, role)} {cells}{st(f'{result(r):<{result_width}}', role)}  "
                     + _fit(title, room - used))
        reason = " ".join(printable(r.get("rationale") or "").split())
        if reason and fr.get("id") not in blocked:
            pieces = (textwrap.wrap(reason, max(room - indent, 30)) if full else [_fit(reason, room - indent)])
            lines += [" " * indent + st(piece, "muted") for piece in pieces]
    hidden = len(doc["results"]) - len(rows)
    if hidden:
        lines.append(st(f"  {_count(hidden, 'code-only finding')} not listed (--print lists them)", "muted"))
    return lines


def _fit(text: str, room: int) -> str:
    return text if len(text) <= room else text[: max(room - 1, 10)] + "…"


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" + ("" if n == 1 else "s")


def _run_usage(budget: RunBudget, seconds: float, agent_info: dict, show_costs: bool) -> str:
    """The run's time and what it used: `4m10s · 23 model calls · 41 requests · $0.42 of $5.00`.
    The spend only when the run shows costs; a profile that reports none says so."""
    from .agent import SUBSCRIPTION_PROFILES

    calls = f"{budget.calls} model call" + ("s" if budget.calls != 1 else "")
    requests = f"{budget.requests} request" + ("s" if budget.requests != 1 else "")
    parts = [duration(seconds), calls, requests]
    if show_costs:
        parts.append("cost not reported (subscription)" if agent_info["profile"] in SUBSCRIPTION_PROFILES
                     else spent_text(budget.cost, budget.limits.cost_limit_usd,
                                     api_prices=not agent_info.get("api_billing", False)))
    return " · ".join(parts)


def _verify_summary(st: Style, doc, paths, extra: list[tuple[str, str]]) -> list[str]:
    s = doc["meta"]["summary"]
    code_only = sum(1 for r in doc["results"] if (r.get("eligibility") or {}).get("status") != "dynamic")
    verdicts = ((s["confirmed"], "confirmed", "ok"), (s["not_reproducible"], "not reproducible", "critical"),
                (s["blocked"], "blocked by control", "critical"), (s["inconclusive"], "inconclusive", "warn"),
                (s["not_attempted"] - code_only, "not tested", "muted"), (code_only, "code-only", "muted"))
    evidence = Path(paths["evidence"])
    rows = [
        ("Report", f"{paths['md']} (Markdown)", "bold"),
        ("Data", f"{paths['yaml']} (YAML, for --resume and export)"),
        *([("Evidence", f"{evidence}/")] if evidence.is_dir() and any(evidence.iterdir()) else []),
        *extra,
        ("Verdicts", [(f"{n} {label}", role) for n, label, role in verdicts if n] or [("none", "muted")]),
    ]
    return ["", st("Done", "bold"), *_facts(st, rows)]


def cmd_export(args: argparse.Namespace) -> int:
    doc, errors = read_report(Path(args.verification))
    if errors:
        return _blocked(f"The report {args.verification} cannot be exported", errors)
    ann = build_annotations(doc, verification_report=str(args.verification))
    out = Path(args.output or "analyzer-verification.json")
    if args.fmt == "yaml":
        import yaml
        out.write_text(yaml.safe_dump(ann, sort_keys=False, allow_unicode=True), encoding="utf-8")
    else:
        import json
        out.write_text(json.dumps(ann, indent=2), encoding="utf-8")
    print(f"wrote {len(ann['annotations'])} annotations → {out}")
    return EXIT_OK


_FILES = "--assessment security-assessment.yaml --scope scope.yaml"


def _banner(st: Style) -> str:
    head = (logo(st, version_string(), columns() - 1) if st.enabled else
            [f"AppSec Verifier {version_string()} — verify static assessment findings against a running app."])
    return "\n".join(head) + (
        "\n\n"
        "Guided run:\n"
        "  appsec-verifier ASSESSMENT   asks only what has no default, then verifies\n\n"
        "Commands:\n"
        "  verify     verify selected findings against a target (safe mode by default)\n"
        "  preflight  check assessment, scope, target, logins and model; verifies nothing\n"
        "  scope      resolve and validate an authorisation scope file\n"
        "  export     re-emit verdicts for AppSec Analyzer\n"
        "  update     update a pipx installation of the Verifier, after your yes\n\n"
        "Examples:\n"
        "  appsec-verifier security-assessment.yaml\n"
        f"  appsec-verifier preflight {_FILES} --offline\n"
        f"  appsec-verifier verify {_FILES} \\\n"
        "      --identities identities.yaml --min-severity high --profile claude\n\n"
        "Options and examples of a command: appsec-verifier COMMAND --help, of the guided run:\n"
        "appsec-verifier ASSESSMENT --help. Quick start: README.md. All options: docs/cli.md."
    )


def _wrap(text: str) -> str:
    """A help description, wrapped for an 80-column terminal; the formatter keeps it as written."""
    return textwrap.fill(text, 78)


class _Parser(argparse.ArgumentParser):
    """Help with the description and examples as written. A usage error shows the
    short usage, the error and where to find the examples, not every option.
    Options are taken only as written: an abbreviation such as `--show-cost` is
    an error that names the option meant, not a silent match."""

    def __init__(self, *args, hint: str | None = None, **kwargs):
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)
        self.hint = hint or f"Options and examples: {self.prog} --help"

    def error(self, message):
        if message.startswith("unrecognized arguments: "):
            known = self._option_names()
            meant = [match[0] for arg in message.split(": ", 1)[1].split()
                     if arg.startswith("--") and (match := difflib.get_close_matches(arg.split("=")[0], known, 1))]
            if meant:
                message += f"; did you mean {', '.join(meant)}?"
        self.exit(EXIT_BLOCKED, f"{self.format_usage()}{self.prog}: error: {message}\n{self.hint}\n")

    def _option_names(self) -> list[str]:
        """The long options of this parser and its commands, for the suggestion after an unknown one."""
        names = []
        for action in self._actions:
            names += [name for name in action.option_strings if name.startswith("--")]
            if isinstance(action, argparse._SubParsersAction):
                names += [name for sub in action.choices.values() for name in sub._option_names()]
        return names


_PROFILE_CHOICES = ["claude", "codex-cli", "copilot-cli", "codex", "anthropic-api"]
_PROFILE_HELP = ("claude (Claude CLI, default when interactive), codex-cli (ChatGPT login), copilot-cli "
                 "(Copilot login), codex (OPENAI_API_KEY), anthropic-api (ANTHROPIC_API_KEY)")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="appsec-verifier", add_help=False)
    p.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)   # prints the banner
    p.add_argument("--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="command")

    sc = sub.add_parser(
        "scope", help="resolve and validate an authorisation scope file",
        description="Validates a scope file and prints what may be contacted. Contacts nothing.",
        epilog="Example:\n  appsec-verifier scope --scope scope.yaml --target http://localhost:3000/rest/products")
    sc.add_argument("--scope", metavar="FILE", required=True, help="scope file to validate")
    sc.add_argument("--target", metavar="URL", help="also say whether this URL lies inside the scope")

    vf = sub.add_parser(
        "verify", help="verify selected findings against a target (safe mode by default)",
        usage="appsec-verifier verify --assessment FILE (--scope FILE | --url URL) [options]",
        hint="To be asked for the settings instead: appsec-verifier ASSESSMENT\n"
             "Options and examples: appsec-verifier verify --help",
        description=_wrap("Tests the selected findings against the target and writes a report. Before the first "
                          "request it asks once; --yes confirms without asking."),
        epilog="Examples:\n"
               "  High and Critical findings, with the test accounts of identities.yaml:\n"
               f"    appsec-verifier verify {_FILES} \\\n"
               "      --identities identities.yaml --min-severity high --profile claude\n\n"
               "  Only XSS and IDOR, at most USD 2, without questions (CI):\n"
               f"    appsec-verifier verify {_FILES} \\\n"
               "      --category xss,idor --cost-limit 2 --profile anthropic-api --non-interactive --yes")
    _add_run_options(vf, guided=False)

    pf = sub.add_parser(
        "preflight", help="check assessment, scope, target, logins and model; verifies nothing",
        usage="appsec-verifier preflight --assessment FILE (--scope FILE | --url URL) [options]",
        description=_wrap("Checks the assessment, scope, proxy, identities, target, logins and model, and tests "
                          "no finding. The target and the logins are contacted only after one confirmation."),
        epilog="Examples:\n"
               "  The files only; contacts nothing:\n"
               f"    appsec-verifier preflight {_FILES} \\\n"
               "      --identities identities.yaml --offline\n\n"
               "  Also the target, the logins and the model, after one confirmation:\n"
               f"    appsec-verifier preflight {_FILES} \\\n"
               "      --identities identities.yaml --profile claude")
    pf.add_argument("--assessment", metavar="FILE", required=True, help="security-assessment.yaml to check")
    pf.add_argument("--scope", metavar="FILE", help="scope file; without it, --url alone")
    pf.add_argument("--url", "--target", dest="target", metavar="URL",
                    help="URL to check (default: base_url of the scope); must lie inside the scope")
    pf.add_argument("--identities", metavar="FILE", help="test accounts by role; each login is tried once")
    pf.add_argument("--profile", choices=_PROFILE_CHOICES, metavar="PROFILE", help=f"model profile: {_PROFILE_HELP}")
    pf.add_argument("--model", help="model of the profile (default: the profile's model)")
    pf.add_argument("--offline", action="store_true",
                    help="contact nothing: neither the target, its login endpoints, nor the model provider")
    pf.add_argument("--test-model", action="store_true",
                    help="send one fixed prompt to the model; needs --cost-limit, or --max-calls 1 for "
                         "codex-cli and copilot-cli")
    pf.add_argument("--cost-limit", type=float, metavar="USD", help="with --test-model: spending limit of the call")
    pf.add_argument("--max-calls", type=int, metavar="N", help="with --test-model: call limit (subscription profiles)")
    pf.add_argument("--show-costs", action="store_true",
                    help="with --test-model: show the call's cost even with subscription billing "
                         "(default: API billing only)")
    pf.add_argument("--non-interactive", "--ci", dest="non_interactive", action="store_true",
                    help="no prompts; contacting the target then needs --yes")
    pf.add_argument("--yes", action="store_true", help="confirm contacting the target without a prompt")
    pf.add_argument("--json", action="store_true", help="print the result as JSON on stdout; never prompts")

    ex = sub.add_parser(
        "export", help="re-emit a verification.yaml for AppSec Analyzer",
        description=_wrap("Converts the verdicts of a finished run into a file meant for AppSec Analyzer, "
                          "which does not read it yet. Contacts nothing."),
        epilog="Example:\n  appsec-verifier export --verification verification/verification.yaml")
    ex.add_argument("--verification", metavar="FILE", required=True, help="verification.yaml of a finished run")
    ex.add_argument("--output", metavar="FILE", help="file to write (default: analyzer-verification.json)")
    ex.add_argument("--format", dest="fmt", choices=["json", "yaml"], default="json", help="default: json")

    sub.add_parser("update", help="update a pipx installation of the Verifier, after your yes",
                   description=_wrap("Reinstalls the Verifier with pipx from the source it was installed from, "
                                     "after you confirm."))

    return p


def build_guided_parser() -> argparse.ArgumentParser:
    """`appsec-verifier ASSESSMENT [options]`: the guided run (VER-031). It takes
    the `verify` options; those given replace the defaults and are not asked."""
    p = _Parser(
        prog="appsec-verifier", usage="appsec-verifier ASSESSMENT [options]",
        hint="Options and examples: appsec-verifier ASSESSMENT --help",
        description=_wrap("Guided run: reads the assessment, tests findings of severity high and above with the "
                          "claude profile, asks for the target URL when there is no scope file, then verifies "
                          "after one confirmation. Options given here replace the defaults. Without a terminal, "
                          "or with --non-interactive, nothing is asked."),
        epilog="Examples:\n"
               "  Ask for the target URL, everything else by default:\n"
               "    appsec-verifier security-assessment.yaml\n\n"
               "  This target, medium and above, another model; only the confirmation is asked:\n"
               "    appsec-verifier security-assessment.yaml --target http://localhost:3000 \\\n"
               "      --min-severity medium --profile codex-cli")
    _add_run_options(p, guided=True)
    return p


def _add_run_options(vf: argparse.ArgumentParser, *, guided: bool) -> None:
    """The options of `verify`, shared with the guided run. The guided run takes
    the assessment as its argument and asks for the scope when it is missing."""
    src = vf.add_argument_group("target and input")
    if guided:
        src.add_argument("assessment", metavar="ASSESSMENT", help="security-assessment.yaml from AppSec Analyzer")
        src.add_argument(
            "--scope",
            metavar="FILE",
            help="scope file: what may be contacted, until when, by whom "
            "(default: scope.yaml next to the assessment or here)",
        )
    else:
        src.add_argument(
            "--assessment", metavar="FILE", required=True, help="security-assessment.yaml from AppSec Analyzer"
        )
        src.add_argument("--scope", metavar="FILE", help="scope file: what may be contacted, until when, by whom")
    src.add_argument(
        "--url",
        "--target",
        dest="target",
        metavar="URL",
        help="URL to start from (default: base_url of the scope); must lie inside the scope. "
        "Without --scope, only this URL's host and port are contacted, read-only",
    )
    src.add_argument(
        "--identities", metavar="FILE", help="test accounts by role; their credentials come from environment variables"
    )
    src.add_argument("--source", metavar="DIR", help="checkout of the application's source code, read by the agent")

    sel = vf.add_argument_group(
        "findings to test",
        "Without these, findings of severity high and above."
        if guided
        else "Without these, every finding that can be tested dynamically.",
    )
    sel.add_argument("--category", metavar="LIST", help="classes or techniques, comma-separated, e.g. xss,idor,sqli")
    sel.add_argument("--severity", metavar="LIST", help="exact severities, comma-separated, e.g. critical,high")
    sel.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        metavar="LEVEL",
        help="lowest severity to test: low, medium, high or critical",
    )
    sel.add_argument(
        "--strict-severity",
        action="store_true",
        help="do not add lower-severity management findings or declared prerequisites",
    )
    sel.add_argument(
        "--only", metavar="IDS", help="finding ids, comma-separated, e.g. T-003,T-009; overrides the other selectors"
    )
    sel.add_argument("--class", dest="cls", metavar="LIST", help="(advanced) weakness classes, comma-separated")
    sel.add_argument("--cwe", metavar="LIST", help="(advanced) CWEs, comma-separated, e.g. CWE-79,CWE-639")

    model = vf.add_argument_group("model")
    model.add_argument(
        "--profile",
        choices=_PROFILE_CHOICES,
        metavar="PROFILE",
        help=f"{_PROFILE_HELP}; required with --non-interactive",
    )
    model.add_argument("--model", help="model of the profile (default: the profile's model)")

    lim = vf.add_argument_group("limits", "Without these, the values in data/limits.yaml apply.")
    lim.add_argument("--cost-limit", type=float, metavar="USD", help="spending limit for model calls")
    lim.add_argument("--max-calls", type=int, metavar="N", help="model calls for the run")
    lim.add_argument("--max-requests", type=int, metavar="N", help="requests to the target for the run")
    lim.add_argument("--max-attempts", type=int, metavar="N", help="agent steps per finding")
    lim.add_argument("--max-duration", type=float, metavar="SECONDS", help="run time")
    lim.add_argument("--rate", type=float, metavar="N", help="requests per second; 0 for no rate limit")

    mode = vf.add_argument_group("mode")
    mode.add_argument(
        "--allow-intrusive",
        action="store_true",
        help="also send marked write requests (POST, PUT, PATCH); needs allow_state_change: true "
        "in the scope. Default: GET, HEAD and OPTIONS only",
    )
    mode.add_argument(
        "--read-only",
        action="store_true",
        help="no write requests, even with --allow-intrusive and a scope that allows them",
    )
    mode.add_argument(
        "--non-interactive",
        "--ci",
        dest="non_interactive",
        action="store_true",
        help="ask nothing; every setting comes from the options",
    )
    mode.add_argument("--yes", action="store_true", help="confirm the test without a prompt; the report records it")
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve selection and scope, then stop: writes nothing, contacts nothing",
    )
    mode.add_argument(
        "--test-all",
        action="store_true",
        help="also test findings this run cannot confirm (e.g. a login is needed but no test "
        "identity is given); by default they are listed and not tested",
    )
    mode.add_argument("--headful", action="store_true", help="show the proof browser (local debugging)")

    out = vf.add_argument_group("output")
    out.add_argument(
        "--output",
        metavar="DIR",
        default=None if guided else "./verification",
        help="directory for the report and the evidence (default: ./verification)",
    )
    out.add_argument("--report", action="store_true", help="standalone report (default)")
    out.add_argument(
        "--print", dest="print_results", action="store_true", help="also print the verdict of each finding"
    )
    out.add_argument(
        "--show-costs",
        action="store_true",
        help="show model costs on the console even with subscription billing (default: API billing "
        "only; a subscription CLI reports none). Changes no limit",
    )
    report = out.add_mutually_exclusive_group()
    report.add_argument(
        "--resume",
        action="store_true",
        help="continue the report in the output directory: findings with a verdict keep it, the others are tested",
    )
    report.add_argument(
        "--overwrite",
        action="store_true",
        help="replace a report already in the output directory (without this or --resume, such a report stops the run)",
    )
    out.add_argument(
        "--annotate", action="store_true", help="also write a copy of the assessment with the verdict of each finding"
    )
    out.add_argument(
        "--in-place", action="store_true", help="with --annotate: write the verdicts into the assessment file itself"
    )
    out.add_argument(
        "--screenshots",
        type=screenshot_option,
        metavar="CLASSES",
        help="classes that get screenshots, comma-separated: xss, access-control, injection, "
        "open-redirect, path-traversal, ssrf, session; or none (default: all)",
    )


COMMANDS = ("scope", "verify", "preflight", "export", "update")


def _stdin_is_terminal() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:       # a verify run already handles it and writes its report (runner.py)
        print("\ninterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED


def _main(argv: list[str] | None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and not argv[0].startswith("-") and argv[0] not in COMMANDS:
        from .guided import run_guided
        args = build_guided_parser().parse_args(argv)
        return run_guided(args, interactive=not args.non_interactive and _stdin_is_terminal())
    args = build_parser().parse_args(argv)
    if args.version:
        print(version_string())
        return EXIT_OK
    if args.command == "scope":
        return cmd_scope(args)
    if args.command == "verify":
        return cmd_verify(args)
    if args.command == "preflight":
        return cmd_preflight(args)
    if args.command == "export":
        return cmd_export(args)
    if args.command == "update":
        from .update import UpdateError, update_installation
        try:
            return update_installation()
        except UpdateError as exc:
            print(f"appsec-verifier: error: {exc}", file=sys.stderr)
            return EXIT_BLOCKED
    print(_banner(Style.for_stream(sys.stdout)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
