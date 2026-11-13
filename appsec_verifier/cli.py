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
import shutil
import sys
import textwrap
import time
from collections import ChainMap
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .auth.accounts import FROM_TARGET
from .limits import Limits, RunBudget
from .loader import AssessmentError, plans_from, read_assessment, select
from .preflight import (
    Check,
    check_accounts,
    check_identities,
    check_source,
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
    from .planning import add_quick, dependency_order, severity_order, supplement

    filters = dict(
        categories=_csv(args.category),
        classes=_csv(args.cls),
        severities=_csv(args.severity),
        min_severity=args.min_severity,
        cwes={c.upper() for c in (_csv(args.cwe) or set())} or None,
        ids=_csv(args.only),
    )
    selected = select(plans, **filters)
    strict = getattr(args, "strict_severity", False)
    if args.min_severity and not args.only and not args.severity:
        eligible = select(plans, **{**filters, "min_severity": None})
        selected = supplement(selected, eligible, enabled=not strict)
    if (args.min_severity or args.severity) and not args.only and not strict:
        # The `quick` findings below a severity selection are tested too, within the other selectors.
        selected = add_quick(selected, select(plans, **{**filters, "min_severity": None, "severities": None}))
    return dependency_order(severity_order(selected))


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
        if path.suffix.lower() in (".md", ".markdown"):
            return None, [], ["this is a Markdown report; give the security-assessment.yaml next to it"]
        return None, [], [f"cannot read it as YAML: {type(exc).__name__}"]
    except ValueError as exc:                       # not a mapping at the top level
        return None, [], [str(exc)]
    return doc, plans_from(doc), []


def report_exists(output) -> bool:
    """Whether the output directory already holds a report; only --overwrite replaces it."""
    return any((Path(output) / name).is_file() for name in ("verification.yaml", "verification.md"))


def _default_output(args, doc: dict, assessment: Path, target: str) -> Path:
    """Without --output (VER-058): a new run directory of the assessment's project, or with --resume the newest
    run there whose report is for this assessment and target (VER-037), if there is one."""
    from .run_dirs import data_base, latest_run, new_run, project_name

    project = data_base() / project_name(doc)
    if args.resume:
        from .verify.report import resume_problems
        from .verify.runner import _sha256

        sha = _sha256(assessment)

        def fits(path: Path) -> bool:
            report, errors = read_report(path)
            return not errors and not resume_problems(report, sha, target)

        found = latest_run(project, fits)
        if found:
            return found
    return new_run(project)


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
    whole host; writes only with --allow-intrusive (VER-030). It lasts for this run, so it has no window and
    no owner. The URL comes from the operator, never from the assessment (VER-004)."""
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
    scope = {"schema_version": 1, "base_url": url, "schemes": [scheme]}
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
    forbidden = scope.get("allow_state_change") is False
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
        ("State change", "forbidden" if forbidden else "with --allow-intrusive", "ok" if forbidden else "warn"),
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

_IDENTITY_ENDPOINTS = ("login_url", "token_url", "authorize_url", "device_url", "issuer")


def _check_identities(path: str | None, guard: ScopeGuard, env, *, interactive: bool = False,
                      secrets: dict | None = None, ask_secret=None, doc: dict | None = None
                      ) -> tuple[list[dict], list[str]]:
    """Load the identities file (or take `doc`) and check it before anything is contacted
    (VER-016, VER-025, VER-028, VER-040): schema-valid, every `*_env` variable set, each
    authentication endpoint allowed by the scope for authentication, each
    `target_origin` inside the scope, each `check_url` inside the scope on an
    identity that has credentials (VER-032), each login program found, and a
    sign-in that needs a person only in an interactive run. With `ask_secret`
    (an interactive run) a variable that is not set is asked for hidden once and
    kept in `secrets`, never in the environment. Errors name variables, never values."""
    from .auth.interactive import _loopback
    from .auth.sessions import INTERACTIVE_METHODS, AuthError, header_problem

    if not path and doc is None:
        return [], []
    import yaml
    from jsonschema.validators import validator_for

    if doc is None:
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
    base_dir = Path(path).parent if path else Path.cwd()
    asked: set[str] = set()
    for ident in identities:
        role, method, auth = ident["role"], ident["method"], ident.get("auth") or {}
        if method in INTERACTIVE_METHODS:
            if not interactive:
                errors.append(f"{role}: {method} needs a person to sign in; a run without a terminal can use "
                              "a login program (method command) or client credentials instead")
            if auth.get("username_env") or auth.get("password_env"):
                errors.append(f"{role}: {method} signs in in your browser; remove username_env and password_env")
            try:
                _loopback(auth.get("redirect_uri"))
            except AuthError as exc:
                errors.append(f"{role}: {exc}")
        named = [(key, name) for key, name in auth.items() if key.endswith("_env") and isinstance(name, str) and name]
        named += [(f"headers_env {header}", name) for header, name in (auth.get("headers_env") or {}).items()]
        for key, name in named:
            if env.get(name) or (secrets or {}).get(name):
                continue
            if ask_secret is not None and name not in asked:
                asked.add(name)
                value = ask_secret(f"{role}: {name} ({key}) is not set; enter its value (hidden): ")
                if value:
                    secrets[name] = value
                    continue
            errors.append(f"{role}: environment variable {name} ({key}) is not set")
        for header in auth.get("headers_env") or {}:
            if problem := header_problem(header):
                errors.append(f"{role}: {problem}")
        if method == "command":
            errors += [f"{role}: {problem}" for name in auth.get("headers") or [] if (problem := header_problem(name))]
            program = auth["command"][0]
            found = (base_dir / program).is_file() if "/" in program else shutil.which(program, path=env.get("PATH"))
            if not found:
                errors.append(f"{role}: login program {program!r} not found")
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


def _prepare_accounts(args, doc: dict, scope: dict, guard: ScopeGuard, target: str, secrets: dict, env,
                      interactive: bool, *, passwords: bool = True
                      ) -> tuple[list[dict], dict | None, ScopeGuard, list[str]]:
    """VER-041: the identities for --account and --admin-account, the login endpoint they sign in at, the
    guard (widened by a --login-url host when there is no scope file), and errors. User names go to `secrets`;
    a password not in its variable is asked hidden in an interactive run. Without `passwords` (an offline
    check) passwords are not needed yet. Contacts nothing."""
    from .auth.accounts import PRIVILEGED_ROLE, AccountError, account_identities, resolve_login_url

    normal, privileged =getattr(args, "account", None) or [], getattr(args, "admin_account", None) or []
    if not normal and not privileged:
        return [], None, guard, (["--login-url needs --account or --admin-account"]
                                 if getattr(args, "login_url", None) else [])
    if getattr(args, "identities", None):
        return [], None, guard, ["use either --identities or --account/--admin-account, not both"]
    try:
        login_url, source = resolve_login_url(args.login_url, doc, target)
        identities, users, pending = account_identities(normal, privileged, login_url)
    except AccountError as exc:
        return [], None, guard, [str(exc)]
    if len(set(users.values())) < len(users):
        return [], None, guard, ["the same user name is given twice; an access-control proof needs independent "
                                 "accounts (VER-010)"]
    decision = guard.authorize(login_url, "auth")
    if not decision.allowed:
        if args.scope:
            return [], None, guard, [f"the login endpoint is outside the scope: {decision.reason}; "
                                     "add its host to auth_hosts in the scope file"]
        parts = urlsplit(login_url)      # without a scope file, --login-url names a login host for this run
        port = parts.port or (443 if parts.scheme == "https" else 80)
        scope.setdefault("auth_hosts", []).append(f"{parts.hostname}:{port}")
        if parts.scheme not in scope.setdefault("schemes", []):
            scope["schemes"].append(parts.scheme)
        guard = ScopeGuard(scope)
    secrets.update(users)
    errors = []
    for role, user, variable, named in pending:
        if env.get(variable) or not passwords:
            continue
        if interactive:
            value = _ask_secret(f"Password for {role} ({printable(user)}), hidden: ")
            if value:
                secrets[variable] = value
                continue
        errors.append(f"{role}: environment variable {named} is not set" if named else
                      f"{role}: no password; enter it in a terminal or name its variable with --account USER=VARIABLE")
    if errors:
        return [], None, guard, errors
    # Offline the passwords are not needed yet: the check sees a stand-in, never used to sign in.
    later = {} if passwords else {v: "asked when the run starts" for _, _, v, _ in pending if not env.get(v)}
    _, errors = _check_identities(None, guard, ChainMap(later, env), doc={"identities": identities})
    for ident in identities:          # after the schema check, which knows no such fields
        ident["privileged"] = ident["role"].startswith(f"{PRIVILEGED_ROLE}-")
        if source == FROM_TARGET:
            ident["auth"]["login_from_target"] = True
    return identities, {"url": login_url, "source": source}, guard, errors


def _accounts_note(identities: list[dict], login: dict | None, target: str | None = None) -> str | None:
    """The accounts and their login endpoint, for the settings shown before the confirmation (VER-002, VER-041);
    a login below the target is shown by its path."""
    if not login:
        return None
    roles = ", ".join(i["role"] + (" (privileged, read-only)" if i.get("privileged") else "") for i in identities)
    if login["source"] == FROM_TARGET:
        return f"{roles} · sign in at the login form the target URL leads to"
    url, base = login["url"], (target or "").rstrip("/")
    if base and url.startswith(base + "/"):
        url = url[len(base):]
    return f"{roles} · sign in at POST {url} ({login['source']})"


def _sign_in_accounts(sessions, identities: list[dict], login: dict, host, budget, doc: dict,
                      source_dir) -> list[Check]:
    """VER-041: one model call for the login field names, then each account signs in with at most two
    attempts; a pair that worked is used for the others. A login form found from the target URL names its own
    fields and needs no model call; the check names the page found. A failed login shows in the identity
    checks."""
    from .auth.accounts import AccountError, choose_fields, handler_of
    from .auth.sessions import AuthError
    from .preflight import _REQUEST_ERRORS

    found = login["source"] == FROM_TARGET
    if found:
        pairs = [("username", "password")]     # stand-ins: the form found names its own fields
    else:
        path = urlsplit(login["url"]).path
        handler = handler_of(doc, path) if login["source"] != "--login-url" else None
        excerpt = None
        if handler and source_dir:
            from .agent.source_reader import SourceAccessError, SourceReader

            try:
                excerpt = SourceReader(source_dir).read_window(handler[0], handler[1], context=15)["text"]
            except SourceAccessError:
                excerpt = None
        try:
            pairs = choose_fields(host, budget, endpoint=f"POST {path}",
                                  handler=f"{handler[0]}:{handler[1]}" if handler else None, excerpt=excerpt)
        except AccountError as exc:
            for ident in identities:      # no later login with field names the model did not choose
                sessions.refuse(ident["role"], "no login field names to sign in with")
            return [Check("Login fields", "fail", str(exc))]
    working, refused = None, []
    for ident in identities:
        try:
            working = sessions.sign_in_with_fields(ident["role"], [working] if working else pairs)
        except (AuthError, *_REQUEST_ERRORS):
            refused.append(ident["role"])       # the identity check names the cause; not tried again
    if found:
        page = next((i["auth"]["login_url"] for i in identities if i["role"] not in refused), None)
        where = f"login form found at {printable(urlsplit(page).path or '/')}" if page else \
            "the login form the target URL leads to"
        if not refused:
            return [Check("Login fields", "ok", f"{where}; {working[0]}/{working[1]} worked")]
        return [Check("Login fields", "fail", f"{where}; no session for {', '.join(refused)}. Give the login "
                                              "endpoint with --login-url, or use --identities")]
    shown = ", ".join(f"{u}/{p}" for u, p in pairs)
    if not refused:
        return [Check("Login fields", "ok", f"{shown} proposed by the model; {working[0]}/{working[1]} worked")]
    return [Check("Login fields", "fail", f"{shown} proposed by the model; no session for {', '.join(refused)}, "
                                          "see their lines below. A login the Verifier cannot perform needs "
                                          "--identities")]


def _identities_fix(errors: list[str]) -> str:
    """What to do about the identities errors shown, by their cause."""
    fixes = []
    if any("is not set" in e for e in errors):
        fixes.append("export the variables named above")
    if any("refused for authentication" in e or "outside the scope" in e for e in errors):
        fixes.append("name the login host as the target names it (e.g. localhost, not 127.0.0.1), or list it "
                     "in auth_hosts of a scope file")
    if not fixes:
        fixes.append("correct the identities file")
    return "; ".join(fixes) + ", or start without --identities"


def _ask_secret(prompt: str) -> str:
    """One value typed or pasted without echo; nothing at the end of input."""
    from .auth.paste import ask_hidden

    try:
        return ask_hidden(prompt)
    except EOFError:
        return ""


def _sessions(identities: list[dict], http, env, args, interactive: bool, target: str | None = None):
    """The run's SessionManager: values from `env` (environment plus hidden input), sign-ins that need a
    person only in an interactive run, login programs started from the identities file's directory, HTML form
    logins checked against the target URL (VER-041)."""
    from .auth import SessionManager
    from .auth.interactive import LoginUI

    base_dir = Path(args.identities).parent if getattr(args, "identities", None) else None
    return SessionManager(identities, http, env=env, ui=LoginUI() if interactive else None, base_dir=base_dir,
                          target=target)


def _login_programs(identities: list[dict]) -> str | None:
    """The login programs the run will start, for the settings shown before the confirmation (VER-040)."""
    from .auth.program import describe

    shown = [f"{i['role']}: {describe(i['auth'])}" for i in identities if i.get("method") == "command"]
    return (" · ".join(shown) + " (run with your rights, outside the scope and limits)") if shown else None


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


def cmd_verify(args: argparse.Namespace, invocation: str | None = None, default_yes: bool = False, *,
               secrets: dict | None = None, pasted: list[dict] | None = None) -> int:
    """Verify the selected findings. `invocation`, from the guided run, is the
    equivalent non-interactive command line, shown before the confirmation;
    `default_yes` is set by the guided run only, so Enter at its confirmation
    proceeds (VER-002). `secrets` holds values entered hidden and `pasted` the
    identities whose sessions were pasted, both from the guided run; they live
    only in this process (VER-016). With --console-log, what the run prints
    also goes to console.log in the output directory, once the run writes a
    report there. Without --output the run gets a directory of its own, which
    is removed again when the run wrote nothing into it (VER-058)."""
    fresh = args.output is None
    try:
        if not args.console_log:
            return _verify(args, invocation, default_yes, secrets=secrets, pasted=pasted, console=None)
        from .progress import console_log

        with console_log(plain=args.console_log == "plain") as console:
            return _verify(args, invocation, default_yes, secrets=secrets, pasted=pasted, console=console)
    finally:
        if fresh and args.output:
            from .run_dirs import remove_if_empty

            remove_if_empty(Path(args.output))


def _verify(args: argparse.Namespace, invocation: str | None, default_yes: bool, *,
            secrets: dict | None, pasted: list[dict] | None, console) -> int:
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
    if args.output is None:
        try:
            args.output = str(_default_output(args, doc, assessment, target))
        except OSError as exc:
            return _blocked("The output directory cannot be created", [f"{exc.filename}: {type(exc).__name__}"],
                            "give a directory with --output")
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
    auto_callback = _auto_callback(scope, target, sel)
    if auto_callback:
        guard = ScopeGuard(scope)   # so the listener is never a target
    safe = not args.allow_intrusive
    read_only = safe or args.read_only
    if not read_only and scope.get("allow_state_change") is False:   # an explicit no in the scope file wins
        return _blocked(
            "The scope file forbids write requests (allow_state_change: false)",
            fix="start without --allow-intrusive, add --read-only, or remove allow_state_change: false",
        )

    interactive = not args.non_interactive and _stdin_is_terminal()
    secrets = dict(secrets or {})
    env = ChainMap(secrets, os.environ)
    account_ids, login, guard, account_errors = _prepare_accounts(args, doc, scope, guard, target, secrets, env,
                                                                  interactive)
    if account_errors:
        return _blocked("The accounts cannot be used", account_errors,
                        "see --account, --admin-account and --login-url in `appsec-verifier verify --help`")
    if login:
        identities, id_errors = account_ids, []
    else:
        identities, id_errors = _check_identities(
            None if pasted else args.identities, guard, env, interactive=interactive, secrets=secrets,
            ask_secret=_ask_secret if interactive else None, doc={"identities": pasted} if pasted else None)
    if id_errors:
        return _blocked("The identities cannot be used", id_errors, _identities_fix(id_errors))
    if args.source and (bad := check_source(args.source)).status == "fail":
        return _blocked("The source checkout cannot be read", [bad.message],
                        "give --source a readable checkout of the application, or omit it")
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
    from .tools import GuardedHttpClient
    from .tools.httpx_transport import transport_from_scope

    http = GuardedHttpClient(guard, budget, transport_from_scope(scope))
    sessions = _sessions(identities, http, env, args, interactive, target)
    source = SourceReader(args.source) if args.source else None
    registry = agent_registry(planner_factory, max_steps=limits.max_attempts)
    browser, browser_note, browser_missing = _proof_browser(args, http, sel)
    listener, listener_note = _callback_listener(scope, sel, auto=auto_callback)
    probed = [p for p in sel if p.status == "dynamic" and registry.get(p.cls)]
    blocked = (
        {}
        if args.test_all
        else {
            evidence_id(p): need
            for p in probed
            if (need := _blocker(p, identities=identities, browser=browser, listener=listener, scope=scope, safe=safe,
                                 source=source))
        }
    )
    from .budget_prompt import can_prompt

    # VER-052: in a terminal, the test agent may ask for a write safe mode does not send; an explicit no
    # (--read-only, the scope) asks nothing. A finding whose named requests all write stays untested in safe mode.
    may_ask = safe and not args.read_only and scope.get("allow_state_change") is not False and can_prompt(interactive)
    skipped = {fid: reason for fid, (_, reason) in blocked.items()}
    contact = any(evidence_id(p) not in skipped for p in probed)

    summary = _assessment_summary(doc)
    st = Style.for_stream(sys.stdout)
    out = Path(args.output)
    report_note = resumed or ("replaces " if report_exists(args.output) else "") + str(out / "verification.md")
    notes = (
        ("Accounts", _accounts_note(identities, login, target)),
        ("Identities", None if login else _identities_note(identities, sel)),  # Accounts names the roles
        ("Login programs", _login_programs(identities)),
        ("Browser", browser_note),
        ("Callback", listener_note),
        ("Marker file", _marker_note(scope, sel)),
        ("Report", report_note),
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
                agent_info,
                notes,
                floor=args.min_severity,
                guided=invocation is not None,
            )
        )
    )
    print("\n".join(_test_cases(st, probed, blocked, _run_hints(doc, target, browser_missing), full=False)))
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
        if args.source:  # VER-032: show the source checkout the agent reads from (a fail already stopped above)
            add(check_source(args.source))
        reachable = not failed(checks)
        if reachable and login:
            add(*_sign_in_accounts(sessions, identities, login, planner_factory.host, budget, doc, args.source))
        if reachable:   # also after a failed sign-in: each account's line names its cause
            add(
                *(
                    check_identities(sessions, identities, http, target, scope=scope)
                    if identities
                    else [Check("Identities", "info", "none given; only anonymous requests are possible")]
                )
            )
        if not failed(checks) and (same := check_accounts(sessions)):
            add(*same)
        sessions.end_interactive()      # VER-028: no sign-in that needs a person once findings are tested
        if not failed(checks):
            add(_model_test(planner_factory, budget, show_costs=show_costs))
        if failed(checks):
            return _blocked(
                "A pre-flight check failed; no finding was tested", fix="see the ✗ line under Preflight", contacted=True
            )

    out_dir = Path(args.output)
    if console is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        console.start(out_dir / "console.log", append=existing is not None)
    action_log = progress = write_prompt = None
    started = time.monotonic()
    if contact:
        from .verify.actionlog import ActionLog

        out_dir.mkdir(parents=True, exist_ok=True)
        action_log = ActionLog(out_dir / "agent-log.jsonl", redact=sessions.redact, append=existing is not None)
        priced = show_costs and agent_info["profile"] not in SUBSCRIPTION_PROFILES  # these report no amount
        progress = RunProgress(
            model=agent_info.get("model"),
            runtime=agent_info.get("runtime_name"),
            max_steps=limits.max_attempts,
            roles=[i["role"] for i in identities],
            source=source is not None,
            redact=sessions.redact,
            remaining_time=budget.remaining_time,
            spent=(lambda: budget.cost) if priced else None,
            cost_limit=limits.cost_limit_usd,
            api_prices=not agent_info.get("api_billing", False),
            out_dir=out_dir,
        )
        from .budget_prompt import CeilingPrompt
        from .write_prompt import WritePrompt

        if can_prompt(interactive):     # VER-015: a higher cost ceiling only from what the operator types
            budget.ask_ceiling = CeilingPrompt(progress, api_prices=not agent_info.get("api_billing", False))
        if may_ask:                      # VER-052: a write the test agent asks for, after a question
            write_prompt = WritePrompt(progress)
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
            ask_writes=write_prompt,
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
    import yaml

    try:            # the Analyzer's ratings for the rating after verification (VER-039); the results go out anyway
        source = _load_yaml(assessment)
    except (OSError, yaml.YAMLError):
        source = None
    source = source if isinstance(source, dict) else None
    paths = write_reports(doc, out_dir, source)
    extra = []
    if contact:
        extra.append(("Run", _run_usage(budget, time.monotonic() - started, agent_info, show_costs)))
    if action_log is not None:
        extra.append(("Action log", str(action_log.path)))
    if console is not None:
        extra.append(("Console", str(console.path)))
    if args.annotate and source is None:    # the results above are written; only the copies are missing
        extra.append(("Annotated", f"not written: {assessment.name} could not be read again"))
    elif args.annotate:
        from .verify.annotated_report import write_annotated_report

        annotated = annotate_assessment(source, doc, verification_report=str(paths["yaml"]))
        dest = out_dir / "security-assessment.annotated.yaml"
        write_text_atomically(dest, yaml.safe_dump(annotated, sort_keys=False, allow_unicode=True))
        extra.append(("Annotated", str(dest)))
        extra.append(("Annotated report", write_annotated_report(assessment, annotated, doc, out_dir)))

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
        add(Check("Scope", "ok", f"no scope file: only {target}'s host and port"))
    else:
        window = scope.get("window") or {}
        add(Check("Scope", "ok", f"{target} in scope · window until {window.get('until')} · "
                                 f"owner {(scope.get('owner') or {}).get('name')}"))
        if (scope.get("proxy") or {}).get("url"):
            add(_proxy_check(scope, target))

    identities: list[dict] = []
    interactive = not args.non_interactive and _stdin_is_terminal()
    secrets: dict = {}
    env = ChainMap(secrets, os.environ)
    login = None
    if failed(checks) and (args.account or args.admin_account or args.identities):
        # no password is asked for a run that cannot start anyway
        add(Check("Identities", "info", "not checked: an earlier check failed"))
    elif args.account or args.admin_account or args.login_url:
        if guard is None or doc is None:
            add(Check("Accounts", "info", "not checked without a usable scope and assessment"))
        else:
            identities, login, guard, errors = _prepare_accounts(args, doc, scope, guard, target, secrets, env,
                                                                 interactive, passwords=not args.offline)
            add(Check("Accounts", "fail", "; ".join(errors)) if errors else
                Check("Accounts", "ok", _accounts_note(identities, login)))
    elif not args.identities:
        add(Check("Identities", "info", "none given; only anonymous requests are possible"))
    elif guard is None:
        add(Check("Identities", "info", "not checked without a usable scope"))
    else:
        identities, errors = _check_identities(args.identities, guard, env, interactive=interactive, secrets=secrets,
                                               ask_secret=_ask_secret if interactive and not args.offline else None)
        add(Check("Identities", "fail", "; ".join(errors)) if errors else
            Check("Identities", "ok", f"{', '.join(i['role'] for i in identities)} · credentials available"))
        if not errors and (programs := _login_programs(identities)):
            add(Check("Programs", "info", programs))
    if args.source:
        add(check_source(args.source))
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
        from .tools import GuardedHttpClient
        from .tools.httpx_transport import transport_from_scope

        via = proxy_for(scope, target)
        print(f"\nThe next checks contact {target}{f' via proxy {via}' if via else ''}: one GET, one login "
              "per identity with a login or token endpoint, one GET per check_url"
              + (f"; first one call to {host.model} for the login field names, at most two logins per account"
                 if login and login["source"] != FROM_TARGET else "") + ".", file=out)
        conf = confirm_authorization(non_interactive=args.non_interactive, assume_yes=args.yes)
        if not conf.confirmed:
            add(Check("Target", "fail", f"not contacted: {conf.reason}; confirm with --yes, or use --offline"))
        else:
            http = GuardedHttpClient(guard, RunBudget(Limits.load()), transport_from_scope(scope))
            add(check_target(http, target, proxy=via))
            if not failed(checks):
                sessions = _sessions(identities, http, env, args, interactive, target)
                if login:
                    add(*_sign_in_accounts(sessions, identities, login, host, RunBudget(Limits.load()), doc, None))
                add(*check_identities(sessions, identities, http, target, scope=scope))
                if not failed(checks) and (same := check_accounts(sessions)):
                    add(*same)
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
    _auto_callback(scope, target, probed)
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
    # `probed` holds one entry per variant; the check counts findings, one tested when any variant can be.
    findings = {p.id for p in probed}
    testable = {p.id for p in probed if evidence_id(p) not in blocked}
    if not blocked:
        return Check("Test plan", "ok", f"{_count(len(findings), 'finding')} can be tested"), lines
    if not testable:
        return Check(
            "Test plan",
            "warn",
            "no finding can be tested; verify stops before contacting the target "
            "unless run with --test-all (see below)",
        ), lines
    return Check(
        "Test plan",
        "warn",
        f"{len(testable)} of {_count(len(findings), 'finding')} can be "
        "tested; the others need what this run does not have (see below)",
    ), lines


def _assessment_check(doc: dict, plans) -> Check:
    counts = {s: sum(p.status == s for p in plans) for s in
              ("dynamic", "static-only", "unsupported", "input-incomplete")}
    text = (f"{len(plans)} findings: {counts['dynamic']} dynamic, {counts['unsupported']} unsupported, "
            f"{counts['static-only']} legacy static-only, "
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
    listed = ("screenshots of all classes" if shots == set(SCREENSHOT_CLASSES)
              else "screenshots of " + ", ".join(c for c in SCREENSHOT_CLASSES if c in shots) if shots
              else "no screenshots")
    return browser, "Google Chrome" + (", visible" if args.headful else "") + f", {listed}", None


def _auto_callback(scope: dict, target: str, sel) -> bool:
    """For a target on a loopback address whose scope declares no callback, a listener on a free loopback
    port when an SSRF finding is selected (VER-012). It is added to `scope`, so the guard refuses it as a
    target. A hit there confirms the finding: the application fetched an internal address, so the
    declaration expect_rejected is implied. Returns whether it was added."""
    import socket
    from urllib.parse import urlsplit

    from .scope.guard import is_loopback

    if scope.get("callback") or not any(p.status == "dynamic" and p.cls == "ssrf" for p in sel):
        return False
    try:
        host = urlsplit(target).hostname
    except ValueError:
        return False
    if not is_loopback(host):
        return False
    bind = "::1" if ":" in str(host) else "127.0.0.1"
    try:
        with socket.socket(socket.AF_INET6 if bind == "::1" else socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((bind, 0))
            port = probe.getsockname()[1]
    except OSError:
        return False
    shown = f"[{bind}]" if bind == "::1" else bind
    scope["callback"] = {"host": bind, "port": port, "base_url": f"http://{shown}:{port}", "expect_rejected": True}
    return True


def _callback_listener(scope, sel, *, auto: bool = False):
    """The SSRF callback listener when an SSRF finding is selected (VER-012), not yet started, else None;
    with a line for the run settings. Without it SSRF findings stay unconfirmed."""
    if not any(p.status == "dynamic" and p.cls == "ssrf" for p in sel):
        return None, None
    from .tools.callback import CallbackListener, CallbackUnavailable

    try:
        listener = CallbackListener(scope.get("callback"))
    except CallbackUnavailable as exc:
        return None, f"unavailable ({exc}); SSRF findings cannot be confirmed"
    note = f"{listener.host}:{listener.port}"
    if listener.base_url.rstrip("/") != f"http://{note}":
        note += f", reached as {listener.base_url}"
    if auto:
        note += " (the target must reach this machine's loopback, not via docker -p)"
    return listener, note


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


# What a finding this run cannot test needs: its name in the test plan, what to provide in a few words (`verify`),
# and how to provide it (`preflight`). The browser's and the identity's how-tos are replaced by ones that fit this
# run (_run_hints); the browser's also replaces its few words, since it names the actual cause.
_NEEDS = {
    "resource": ("test resource",
                 "a test_resources entry in a scope file, two --account with --allow-intrusive, or an --admin-account "
                 "for a privileged function",
                 ["add an operator-owned test_resources entry to the scope file, with the finding ID, allowed and "
                  "denied roles, and a harmless response marker",
                  "for IDOR and missing authorisation also: two accounts (--account) with --allow-intrusive, or an "
                  "--admin-account for a privileged function"]),
    "capability": ("test capability", "the reported variant needs a tool this run does not provide",
                   ["the reported variant needs a tool this run does not provide; keep it unresolved or test that "
                    "variant separately"]),
    "identity": ("test identity", "test accounts: --account, or --identities FILE",
                 ["create an identities file with two test accounts and pass it with --identities FILE "
                  "(docs/cli.md, Identities file)"]),
    "browser": ("proof browser", "install Playwright and Google Chrome", ["install Playwright and Google Chrome"]),
    "marker": ("marker file", "a marker_file in a scope file",
               ["place a file holding a random token (16 to 128 of A-Z a-z 0-9 _ -) on the target and add to a "
                "scope file (--scope):",
                "marker_file: {path: /path/on/the/target/marker.txt, content: TOKEN}",
                "(docs/cli.md, Scope file)"]),
    "callback": ("callback", "a callback in a scope file",
                 ["add to a scope file (--scope):",
                  'callback: {host: 127.0.0.1, port: 8099, base_url: "http://127.0.0.1:8099"}',
                  "(docs/cli.md, Scope file)"]),
    "intrusive": ("intrusive mode", "run with --allow-intrusive", ["run with --allow-intrusive"]),
    "contract": ("injection contract", "the finding names no read request, so needs an injection_inputs entry",
                 ["the finding names no GET request for controls to run on; add to a scope file (--scope) the "
                  "input the application must treat as literal data, as a query parameter or a JSON field, not a "
                  "path parameter or a write:",
                  "injection_inputs: [{finding_id: ID, path: /route, input_location: params, input_name: NAME, "
                  "semantics: literal}]",
                  "(docs/cli.md, Scope file)"]),
    "access": ("access request", "a test_resources entry in a scope file",
               ["without a test_resources entry the proof reads the resource with a GET request the finding names, "
                "and an account creates its own resource with a write request the finding names that has no "
                "record identifier in its path, since a write never changes an existing record; a write proof "
                "also needs the finding's write that changes a record by its identifier; declare a test "
                "resource in a scope file (--scope) whose request returns a harmless value only the allowed roles "
                "may see:",
                "test_resources: [{id: NAME, finding_id: ID, path: /route, method: GET, allowed_roles: [ROLE], "
                "denied_roles: [ROLE], pointer: /field, value: VALUE}]",
                "(docs/cli.md, Scope file)"]),
    "route": ("request information", "--source, if the finding's file declares its route",
              ["the assessment names no request for the finding, neither as METHOD /path in its scenario or attack "
               "steps nor as an attack_surface entry whose handler is at its location; with --source, a route "
               "declared in the finding's file up to 40 lines before its location can supply one (docs/cli.md, "
               "Continuous control)"]),
}
# Only an access-control finding can name its request in a scope entry (VER-010); other classes have none for it.
_ACCESS_ROUTE = ("; for access control a test_resources entry",
                 "an access-control finding can name its request in a test_resources entry of a scope file "
                 "(--scope; docs/cli.md, Scope file)")


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


def _blocker(plan, *, identities, browser, listener, scope, safe, source=None) -> tuple[str, str] | None:
    """What this run lacks to confirm `plan` (a _NEEDS key and the reason for the
    report), or None when it can try: first what its class's proof needs (VER-009
    to VER-012; injection also a read request, since its proof repeats controls; access control without a test
    resource a read request and, for a resource an account creates, a write request),
    then the requests the assessment names (endpoints.py), when all of them write
    in safe mode or all need a login and there is no test identity.
    A finding that names no request is tried only with `source`, the run's SourceReader, where a literal
    route near its location can supply one (agent/controller.py); in safe mode not when every route the source
    registers for its handlers writes (VER-008), the routes its test agent would start from (agent/loop.py)."""
    from .agent.experiments import RECORD_CWES, access_methods
    from .endpoints import WRITE_METHODS
    from .verification_context import missing_capabilities, record_segment

    if plan.cls == "session" and not any(r["finding_id"] == plan.id for r in scope.get("session_checks", [])):
        return "resource", "no operator-identified session cookie in session_checks"
    if plan.cls == "access-control" and not identities:
        return "identity", "no test identity; the proof compares two identities"
    if plan.cls == "access-control":
        # VER-010: the operator's test resource first; else one a normal account creates, a privileged reference,
        # or the comparison without credentials (VER-057)
        methods = access_methods(plan.id, plan.cwe, scope, identities, writes=not safe)
        if not methods and access_methods(plan.id, plan.cwe, scope, identities, writes=True):
            return "intrusive", "safe mode; without a declared test resource the Verifier creates one, which writes"
        if not methods and plan.cwe in RECORD_CWES:
            return "resource", ("no declared test resource, and not two normal accounts with --allow-intrusive; a "
                                "privileged account does not prove another account's record")
        if not methods:
            return "resource", ("no declared test resource, and neither two normal accounts with --allow-intrusive "
                                "nor a privileged account")
        roles = {i["role"] for i in identities} | {"anonymous"}
        resources = [r for r in scope.get("test_resources", []) if r["finding_id"] == plan.id]
        if "resource" in methods and not any(
            set(r["allowed_roles"]) <= roles and set(r["denied_roles"]) <= roles for r in resources
        ):
            return "resource", "a declared test resource names roles unavailable in this run"
        # Without one, the comparison reads with a GET request of the finding; an account creates its resource
        # with a write request of the finding that names no existing record (VER-014) and reads it back with a GET
        # of the finding, or, for a write proof, with a GET on the path of the finding's write that changes a
        # record (VER-010; agent/tools.py, routes as agent/controller.py builds them).
        variants = getattr(plan, "verification_context", {}).get("variants", [])
        named = [(v["request"].get("method", "GET"), v["request"].get("path", "")) for v in variants] or [
            *((e.method, e.path) for e in plan.endpoints),
            *((r.get("method", "GET"), r["path"]) for key in ("injection_inputs", "session_checks")
              for r in scope.get(key, []) if r["finding_id"] == plan.id)]
        named += [(e.method, e.path) for e in getattr(plan, "preparation", ())]
        writes = [p for m, p in named if m in ("POST", "PUT", "PATCH", "ALL")]
        reads = any(m in ("GET", "PAGE", "ALL") for m, _ in named)
        creates = any(record_segment(p) is None for p in writes)
        changes = any(record_segment(p) is not None for p in writes)
        if named and not source and "resource" not in methods and not (
                (("reference" in methods or "signed_in" in methods) and reads)
                or ("owner" in methods and creates and (reads or changes))):
            if "owner" in methods and not creates:
                return "access", "no write request that creates a record, one without an identifier in its path"
            return "access", "no GET request to read with" + (
                ", and no write request that changes the record" if "owner" in methods else "")
    if plan.cls == "xss" and browser is None:
        return "browser", "no proof browser; XSS counts only when the payload executes"
    archive = [r for r in scope.get("archive_checks", []) if r["finding_id"] == plan.id]
    if plan.cls == "path-traversal" and archive and (safe or scope.get("allow_state_change") is False):
        return "intrusive", "archive upload proof needs state-change authorization and intrusive mode"
    if plan.cls == "path-traversal" and not archive and not (scope.get("marker_file") or {}).get("path"):
        return "marker", "no marker_file in the scope"
    if plan.cls == "ssrf" and listener is None:
        return "callback", "no callback in the scope"
    variants = getattr(plan, "verification_context", {}).get("variants", [])
    # VER-052: a variant that lists state-change needs the write for its proof, even when its request reads, so
    # safe mode does not test it, with or without the source; --allow-intrusive decides that at the start.
    if safe and variants and all("state-change" in (v.get("required_capabilities") or []) for v in variants):
        return "intrusive", "safe mode; every declared variant needs a state change"
    missing = [missing_capabilities(v, safe=safe, browser=browser is not None, identities=bool(identities))
               for v in variants]
    diagnostic_read = any(v["request"]["method"] in ("GET", "HEAD", "OPTIONS") for v in variants)
    if missing and all(missing) and not (source or diagnostic_read):
        needs = sorted({need for row in missing for need in row})
        if needs == ["state-change"]:
            return "intrusive", "safe mode; every declared variant needs a state change"
        return "capability", "declared variants need unavailable capabilities: " + ", ".join(needs)
    if plan.cls == "injection":
        # VER-011: the proof sends every control twice. For a read request the agent repeats automatically;
        # for a write-only finding the agent sends each control itself in intrusive mode (VER-030).
        contracts = [r for r in scope.get("injection_inputs", []) if r["finding_id"] == plan.id]
        methods = [e.method for e in plan.endpoints if e.method != "PAGE"]
        methods += [v["request"].get("method", "GET") for v in variants]
        methods += ["GET" for r in contracts if r["input_location"] == "params"]
        if methods and all(m in WRITE_METHODS for m in methods) and safe:
            return "intrusive", ("safe mode; every request the finding names writes, and the proof sends each "
                                 "control twice")
        if not methods and not contracts and not source:
            return "contract", "no read request to run controls on, and no injection_inputs entry"
    requests = [e for e in plan.endpoints if e.method != "PAGE"]
    # An injection finding that gets here has a read request, and its proof never writes.
    if requests and safe and plan.cls != "injection" and all(e.method in WRITE_METHODS for e in requests):
        return "intrusive", "safe mode; every request the assessment names writes"
    if requests and not identities and all(e.login for e in requests):
        return "identity", "no test identity; every request the assessment names requires a login"
    declared = any(r["finding_id"] == plan.id for key in ("test_resources", "injection_inputs", "session_checks")
                   for r in scope.get(key, []))
    if safe and hasattr(source, "read_all") and not (variants or plan.endpoints or declared):
        from types import SimpleNamespace

        from .agent.derivation import source_registrations

        registered = source_registrations(SimpleNamespace(source=source, plan=plan, scope=scope))
        if registered and all(r["method"] in WRITE_METHODS for r in registered):
            return "intrusive", "safe mode; every request the source registers for its handlers writes"
    if not (variants or plan.endpoints or declared or source):
        return "route", "the assessment names no request for this finding, and without --source none can be read"
    return None


def _wrap_whole(text: str, width: int) -> list[str]:
    """Wrap at spaces only, so a path, command or finding id stays whole and can be copied."""
    return textwrap.wrap(text, width, break_on_hyphens=False, break_long_words=False)


def _test_cases(st, plans, blocked: dict[str, tuple[str, str]], hints: dict[str, list[str]] | None = None,
                full: bool = True) -> list[str]:
    """The test plan before the confirmation: one line per finding the run tests, with its title and
    the requests the assessment names, those that prepare a test resource marked `(prepares)`. A finding
    whose declared variants differ in request or inputs adds one indented line per variant, naming its own
    request and inputs, and its line names no requests; the runner tries them in that order and stops at
    the first confirmed variant. Variants that do not differ get no lines: the finding's line names their
    request and count. Then the findings the run cannot test, grouped by what they need and how to provide it.
    `hints` replaces a need's how-to with what is actually missing (the browser's cause). Without
    `full` (in `verify`) a line is cut to fit a terminal, and each need gets one row with a few words
    and a pointer to `preflight`, which shows the how-tos."""
    if not plans:
        return []
    from .agent.derivation import page_candidates
    from .planning import evidence_id

    tested = [p for p in plans if evidence_id(p) not in blocked]
    groups: dict[str, list] = {}
    order: list[str] = []
    for p in tested:
        if p.id not in groups:
            order.append(p.id)
        groups.setdefault(p.id, []).append(p)
    # `plans` holds one entry per variant; the head counts findings, and the runs their variants add.
    findings = len({p.id for p in plans})
    runs = f" ({len(tested)} runs with their variants)" if len(tested) > len(groups) else ""
    head = (
        f"{len(groups)} of {_count(findings, 'finding')} will be tested{runs}"
        if tested
        else "this run can test none of them"
        if findings > 1
        else "this run cannot test it"
    )
    lines = ["", f"{st('Test plan', 'bold')}     {head}"]
    id_w, sev_w, cls_w = (max((len(printable(getattr(p, k) or "")) for p in tested), default=0)
                          for k in ("id", "severity", "cls"))
    indent = " " * (2 + id_w + 2 + sev_w + 2 + cls_w + 2)
    width = len(indent)

    def request(endpoint) -> str:      # whether it needs a login is settled: without an account it is not tested
        return printable(str(endpoint)).removesuffix(" (login)")

    def variant_request(p) -> tuple[str, str]:
        """`METHOD path` of the plan's variant and the inputs it names, e.g. `q (query)`."""
        variants = (getattr(p, "verification_context", None) or {}).get("variants") or []
        if not variants:
            return "", ""
        req = (variants[0] or {}).get("request") or {}
        method = printable(req.get("method") or "")
        path = printable(req.get("path") or "")
        inputs = ", ".join(f"{printable(i.get('name') or '')} ({printable(i.get('location') or '')})"
                           for i in req.get("inputs") or [])
        return f"{method} {path}".strip(), inputs

    for fid in order:
        group = groups[fid]
        p = group[0]
        title = printable(p.title or p.cwe or "")
        # Declared variants name their own requests: a row each when they differ, otherwise the shared one here.
        rows = [variant_request(v) for v in group] if any(getattr(v, "variant_id", None) for v in group) else []
        distinct = len(set(rows)) > 1
        if distinct:
            named = []
        elif rows and rows[0][0]:
            named = [rows[0][0]]
        else:
            named = list(map(request, p.endpoints[:2]))
        requests = ", ".join([*named, *(request(e) + " (prepares)" for e in getattr(p, "preparation", ()))])
        tail_parts = [requests, f"{len(group)} variants"] if len(group) > 1 and not distinct else [requests]
        tail = " · ".join(x for x in tail_parts if x) or ("" if distinct else "no request in the assessment" + (
            "; its file path may name one" if page_candidates(p.instance) else ""))       # VER-056
        text = title + ((" · " + tail) if tail else "")
        if st.enabled and not full:
            text = _fit(text, max(columns() - 1 - width, 20))
        rest = text[len(title):]
        lines.append(f"  {printable(p.id):<{id_w}}  {st(f'{printable(p.severity).lower():<{sev_w}}', 'muted')}  "
                     f"{printable(p.cls or ''):<{cls_w}}  {text[:len(title)]}"
                     + (st(rest, "muted") if rest else ""))
        if distinct:
            for n, (vp, (req_text, inputs)) in enumerate(zip(group, rows, strict=True), start=1):
                vid = printable(getattr(vp, "variant_id", None) or f"v{n}")
                body = f"{vid}  {req_text or 'no request declared'}" + (f"  {inputs}" if inputs else "")
                if st.enabled and not full:
                    body = _fit(body, max(columns() - 1 - width, 20))
                lines.append(f"{indent}{st(body, 'muted')}")
        if p.selection_reason:
            lines.append(f"    additionally selected: {printable(p.selection_reason)}")
    if not blocked:
        return lines
    groups: dict[str, list[str]] = {}
    access_route = False
    blocked_ids = set()
    for p in plans:
        if evidence_id(p) in blocked:
            ids = groups.setdefault(blocked[evidence_id(p)][0], [])
            if printable(p.id) not in ids:          # one entry per finding, not per variant
                ids.append(printable(p.id))
            blocked_ids.add(p.id)
            access_route |= blocked[evidence_id(p)][0] == "route" and p.cls == "access-control"
    lines += [
        "",
        f"{st('Not testable', 'bold')}  {_count(len(blocked_ids), 'finding')} "
        f"{'needs' if len(blocked_ids) == 1 else 'need'} what this run does not have (--test-all tries anyway)",
    ]
    widths = [len(_NEEDS[key][0]) for key in groups]
    # a row of its own per need without `full`: a longer label moves only its own row, not every row's column
    label_width = max(widths) if full else max((w for w in widths if w <= 20), default=20)
    indent = 2 + label_width + 2 + (4 if full else 0)
    room = max(columns() - 1 - indent, 30)
    for key, ids in sorted(groups.items(), key=lambda group: -len(group[1])):
        label, brief, how = _NEEDS[key]
        how = (hints or {}).get(key) or how
        if key == "route" and access_route:
            brief, how = brief + _ACCESS_ROUTE[0], [*how, _ACCESS_ROUTE[1]]
        if not full:  # one row: the findings, then what to provide in a few words
            text = printable(how[0] if key == "browser" else brief)
            muted = False
            for i, piece in enumerate(_wrap_whole(f"{', '.join(ids)} → {text}", room)):
                left, arrow, right = ("", "", piece) if muted else piece.partition("→")
                muted = muted or bool(arrow)
                lines.append((f"  {st(f'{label:<{label_width}}', 'warn')}  " if i == 0 else " " * indent)
                             + left + (st(arrow + right, "muted") if arrow + right else ""))
            continue
        how = [printable(text) for text in how]
        wrapped = _wrap_whole(", ".join(ids), room) or [""]
        lines.append(f"  {st(f'{label:<{label_width}}', 'warn')}  {len(ids):>2}  {wrapped[0]}")
        lines += [" " * indent + piece for piece in wrapped[1:]]
        for n, text in enumerate(how):  # a line to copy stays whole; prose wraps
            pieces = [text] if text.startswith(("marker_file:", "callback:")) else _wrap_whole(text, room - 2)
            lines += [
                " " * indent + st(("→ " if n == 0 and i == 0 else "  ") + piece, "muted")
                for i, piece in enumerate(pieces)
            ]
    if not full:
        lines.append("  " + st("how to provide each, with lines to copy: appsec-verifier preflight, or docs/cli.md "
                               "(Scope file)", "muted"))
    return lines


def _verify_settings(st, assessment, target, scope, sel, limits, safe, read_only, agent_info,
                     notes=(), floor=None, guided=False) -> list[str]:
    """The settings before the confirmation (VER-002). The guided run has shown the logo, the assessment and its
    findings already, so they are not repeated there."""
    # `sel` may hold one entry per variant; the settings count findings.
    dyn = len({p.id for p in sel if p.status == "dynamic"})
    selected = len({p.id for p in sel})
    from .agent import SUBSCRIPTION_PROFILES

    cost = ("cost not reported (subscription)" if agent_info["profile"] in SUBSCRIPTION_PROFILES
            else f"≤ ${limits.cost_limit_usd:.2f}")
    seconds = int(limits.max_duration_s)
    rate = f"{limits.rate_rps:g} requests/s" if limits.rate_rps else "no rate limit"
    from .planning import QUICK_REASON

    quick_added = len({p.id for p in sel if p.selection_reason == QUICK_REASON})
    selection = _count(dyn, "finding") + (f", severity {floor} and above" if floor else "")
    if quick_added:
        selection += f", with {quick_added} quick below it"
    if guided and floor:
        selection += " (--min-severity to change)"
    elif not guided and selected > dyn:
        selection += f" (another {selected - dyn} selected cannot be tested at runtime)"
    rows = [
        *([] if guided else [("Assessment", str(assessment))]),
        ("Selection", selection),
        ("Target", f"{target} (scope: {', '.join(scope.get('hosts', []) or [target])}, owner: "
                   f"{(scope.get('owner') or {}).get('name')})" if "owner" in scope
         else f"{target} (no scope file: only this host and port)"),
        ("Mode", "safe: only GET, HEAD and OPTIONS" if safe else
         f"intrusive · {'read-only' if read_only else 'state-changing'}", "ok" if safe else "warn"),
        # The profile's own check is not repeated: the pre-flight model test shows whether the model answers.
        ("Profile", " · ".join(v for v in (agent_info.get(k) for k in ("profile", "model", "runtime", "auth")) if v)),
        ("Limits", f"{cost} · ≤ {limits.max_calls} model calls · ≤ {limits.max_requests} requests · ≤ "
                   + (f"{seconds // 60} min" if seconds % 60 == 0 else f"{seconds} s") + f" · {rate}"),
    ]
    for key, note in notes:
        if note:
            rows.append((key, note, "warn" if note.startswith(("unavailable", "replaces")) else None))
    return [*([] if guided else _title(st, "verify")), *_facts(st, rows)]


# Seen from the finding: green when the run confirmed it, red when it could not reproduce it or a control
# blocked it (a likely false positive), yellow when the run could not decide.
_VERDICT_MARK = {"confirmed": ("✓", "ok"), "not-reproducible": ("✗", "critical"),
                 "blocked-by-control": ("⊘", "critical"), "inconclusive": ("?", "warn"),
                 "not-attempted": ("·", "muted")}


_VERDICT_ORDER = ("confirmed", "not-reproducible", "blocked-by-control", "inconclusive", "not-attempted")


def _results(st: Style, doc, plans, blocked: dict[str, tuple[str, str]], *, full: bool = False) -> list[str]:
    """The overview at the end (VER-013): per finding its id, severity, class, result and title, and
    under it the reason, confirmed first. A finding or variant this run could not test shows what it
    needs as its result and how to provide it as its reason. Only findings testable against the app, unless
    `full` (--print) lists every finding
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

    def need(r) -> str | None:
        """What the run lacked for a finding or variant it did not test, keyed as the test plan keys it
        (planning.evidence_id: the finding id, with a variant's digest)."""
        fr = r["finding_ref"]
        key = str(fr.get("id")) + ("-" + fr["variant_digest"][:16] if fr.get("variant_digest") else "")
        if r["verdict"] != "not-attempted":
            return None
        if key in blocked:
            return blocked[key][0]
        # VER-052: a write the run refused during the test, which --allow-intrusive would send (agent/loop.py).
        return "intrusive" if r.get("limits_hit") == "safe-mode" else None

    def result(r) -> str:
        if need(r):
            return f"needs {_NEEDS[need(r)][0]}"
        return _VERDICT_LABEL[r["verdict"]] + (f" ({printable(r['confidence'])})" if r.get("confidence") else "")

    if not full:
        # A finding one variant confirmed needs nothing more: its untested variants are not listed with what they
        # would need. Variants alike in finding, result and reason share one line that counts them.
        confirmed = {r["finding_ref"].get("id") for r in rows if r["verdict"] == "confirmed"}
        rows = [r for r in rows if r["verdict"] != "not-attempted" or r["finding_ref"].get("id") not in confirmed]
    alike: dict[tuple, list[dict]] = {}
    for r in rows:
        alike.setdefault((r["finding_ref"].get("id"), r["verdict"], need(r) or r.get("rationale")), []).append(r)
    rows = [group[0] for group in alike.values()] if not full else rows
    variants = {id(group[0]): len(group) for group in alike.values()} if not full else {}
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
        # Under a finding the run could not test, how to provide what it needs, e.g. "run with --allow-intrusive".
        reason = _NEEDS[need(r)][1] if need(r) else " ".join(printable(r.get("rationale") or "").split())
        if variants.get(id(r), 1) > 1:
            reason = f"{reason} · {variants[id(r)]} variants" if reason else f"{variants[id(r)]} variants"
        if reason:
            pieces = (textwrap.wrap(reason, max(room - indent, 30)) if full else [_fit(reason, room - indent)])
            lines += [" " * indent + st(piece, "muted") for piece in pieces]
    hidden = len(doc["results"]) - len(rows)
    if hidden:
        lines.append(st(f"  {_count(hidden, 'unsupported or incomplete finding')} not listed (--print lists them)",
                        "muted"))
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
                (s["not_attempted"] - code_only, "not tested", "muted"),
                (code_only, "unsupported or incomplete", "muted"))
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
        description=_wrap("Checks the assessment, scope, proxy, identities, source checkout, target, logins and "
                          "model, and tests no finding. The target and the logins are contacted only after one "
                          "confirmation."),
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
    pf.add_argument("--source", metavar="DIR",
                    help="checkout of the application's source code; checked for readability")
    _add_account_options(pf)
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


def _add_account_options(group) -> None:
    """--account, --admin-account and --login-url (VER-041)."""
    group.add_argument(
        "--account", action="append", metavar="USER[=VAR]",
        help="a test account by user name, instead of --identities; its password comes from the environment "
             "variable VAR or is asked hidden. Repeat for a second account",
    )
    group.add_argument(
        "--admin-account", action="append", metavar="USER[=VAR]",
        help="a privileged test account; it sends only GET, HEAD and OPTIONS, also with --allow-intrusive",
    )
    group.add_argument(
        "--login-url", metavar="URL",
        help="where --account signs in (default: the login entry point the assessment names for the target, "
             "else the login form the target URL leads to)",
    )


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
        "Without --scope, only this URL's host and port are contacted",
    )
    src.add_argument(
        "--identities", metavar="FILE",
        help="test accounts by role; credentials come from environment variables, sign-in in your browser or a "
             "login program",
    )
    _add_account_options(src)
    src.add_argument("--source", metavar="DIR", help="checkout of the application's source code, read by the agent")

    sel = vf.add_argument_group(
        "findings to test",
        "Without these, findings of severity high and above."
        if guided
        else "Without these, every finding that can be tested dynamically.",
    )
    sel.add_argument("--category", metavar="LIST",
                     help="classes or techniques, comma-separated, e.g. xss,idor,sqli; quick for XSS and SQL or "
                          "NoSQL injection a read can reach")
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
        help="do not add lower-severity quick or management findings or declared prerequisites",
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
        help="also send marked write requests (POST, PUT, PATCH), unless the scope file says "
        "allow_state_change: false. Default: GET, HEAD and OPTIONS only",
    )
    mode.add_argument(
        "--read-only",
        action="store_true",
        help="no write requests, even with --allow-intrusive",
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
        help="directory for the report and the evidence (default: a new private directory for each run, on Linux "
        "in ~/.local/share/appsec-verifier/runs/PROJECT/)",
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
        help="continue the report in --output, or without it the newest run for this assessment and target: "
        "findings with a verdict keep it, the others are tested",
    )
    report.add_argument(
        "--overwrite",
        action="store_true",
        help="replace a report already in --output (without this or --resume, such a report stops the run)",
    )
    out.add_argument(
        "--console-log",
        nargs="?",
        const="plain",
        choices=("plain", "color"),
        default=None,
        help="also save the console output as console.log in the output directory, without the status line; "
        "plain leaves out the colour codes (default), color keeps the console's colour",
    )
    out.add_argument(
        "--annotate",
        action="store_true",
        help="also write copies of the assessment and of the Analyzer's Markdown report next to it, with the "
        "verdict, rating after verification and proof of each tested finding; the originals stay unchanged",
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
