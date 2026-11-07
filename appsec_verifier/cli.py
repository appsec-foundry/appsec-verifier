"""appsec-verifier — command-line entry point.

`scope`, `plan` and `export` run offline (no network, no model calls). `verify`
contacts the target through an agent only when model access is configured;
otherwise it reports every selected finding not-attempted. Before the first
model call it runs the pre-flight checks of VER-032; `preflight` runs them alone
and verifies nothing (preflight.py). Called with an
assessment and no command, it starts the guided run of guided.py (VER-031),
which asks for the `verify` settings and then runs `verify`. See docs/cli.md
for the full design.
"""

from __future__ import annotations

import argparse
import os
import sys
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
from .scope import ScopeGuard
from .verify import build_annotations, run_verification, write_reports
from .verify.report import annotate_assessment
from .version_info import resource_root, version_string

EXIT_OK = 0
EXIT_BLOCKED = 2            # run could not start (bad input, unconfirmed, etc.)


def _csv(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {v.strip() for v in value.split(",") if v.strip()}


def _select(args: argparse.Namespace, plans):
    """Apply the selection options of `args` (VER-026)."""
    return select(
        plans,
        categories=_csv(args.category),
        classes=_csv(args.cls),
        severities=_csv(args.severity),
        min_severity=args.min_severity,
        cwes={c.upper() for c in (_csv(args.cwe) or set())} or None,
        ids=_csv(args.only),
    )


def _box(title: str, rows: list[tuple[str, str]]) -> str:
    label_w = max((len(k) for k, _ in rows), default=0)
    width = max(len(title) + 4, max((label_w + 3 + len(v) for _, v in rows), default=0) + 2, 58)
    top = f"┌─ {title} " + "─" * (width - len(title) - 3) + "┐"
    body = [f"│ {k.ljust(label_w)}  {v}".ljust(width + 1) + "│" for k, v in rows]
    bottom = "└" + "─" * width + "┘"
    return "\n".join([top, *body, bottom])


# ── plan ────────────────────────────────────────────────────────────────────

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


def _blocked(header: str, errors: list[str]) -> int:
    print(header, file=sys.stderr)
    for e in errors:
        print(f"  - {printable(e)}", file=sys.stderr)
    return EXIT_BLOCKED


def _assessment_summary(doc: dict) -> str:
    """Project and date from the assessment's meta block, to tell it is the intended one."""
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    return " · ".join(printable(meta[k])[:60] for k in ("project", "generated") if meta.get(k))


def cmd_plan(args: argparse.Namespace) -> int:
    _, plans, errors = _load_assessment(Path(args.assessment))
    if errors:
        return _blocked(f"the assessment {args.assessment} cannot be used:", errors)
    sel = _select(args, plans)
    dyn = [p for p in sel if p.status == "dynamic"]
    static = [p for p in sel if p.status == "static-only"]
    incomplete = [p for p in sel if p.status == "input-incomplete"]
    print(_box("AppSec Verifier · plan", [
        ("assessment", str(args.assessment)),
        ("findings", f"{len(plans)} total · {len(sel)} selected"),
        ("verifiable", f"{len(dyn)} dynamic · {len(static)} static-only · {len(incomplete)} input-incomplete"),
    ]))
    for p in sel:
        mark = {"dynamic": "✓", "static-only": "·", "input-incomplete": "!"}[p.status]
        cls = f"[{p.cls}]" if p.cls else ""
        sev = f"{p.severity}" if p.severity else "?"
        print(f"{mark} {p.id:<8} {p.cwe:<9} {sev:<8} {cls:<16} {p.status}")
        if p.status != "dynamic":
            print(f"    {p.reason}")
    print("\nplan only — nothing was sent to any target.")
    return EXIT_OK


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
    return errors


def cmd_scope(args: argparse.Namespace) -> int:
    scope = _load_yaml(Path(args.scope))
    errors = _validate_scope(scope)
    if errors:
        print("scope file is invalid:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_BLOCKED
    window = scope.get("window", {})
    guard = ScopeGuard(scope)
    win = guard.within_window()
    rows = [
        ("base_url", str(scope.get("base_url"))),
        ("hosts", ", ".join(scope.get("hosts", []) or [scope.get("base_url", "")])),
        ("ports", ", ".join(map(str, scope.get("ports", []) or []))),
        ("networks", ", ".join(map(str, scope.get("networks", []) or []))
         or "— (public addresses, and hosts named by IP or as localhost)"),
        ("path_prefixes", ", ".join(scope.get("path_prefixes", []) or ["/"])),
        ("window", f"{window.get('from')} → {window.get('until')}  [{'ok' if win.allowed else 'EXPIRED/UNOPENED'}]"),
        ("owner", str((scope.get("owner") or {}).get("name"))),
        ("state change", "allowed" if scope.get("allow_state_change") else "read-only"),
        ("auth_hosts", ", ".join(scope.get("auth_hosts", []) or ["—"])),
        ("proxy", (scope.get("proxy") or {}).get("url") or "—"),
    ]
    print(_box("AppSec Verifier · scope", rows))
    if args.target:
        d = guard.authorize(args.target, "target")
        print(f"\ntarget {args.target}: {'INSIDE scope' if d.allowed else 'OUT OF SCOPE — ' + d.reason}")
        if not d.allowed:
            return EXIT_BLOCKED
    print("\nscope only — nothing was contacted.")
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


def cmd_verify(args: argparse.Namespace, invocation: str | None = None) -> int:
    """Verify the selected findings. `invocation`, from the guided run, is the
    equivalent non-interactive command line, shown before the confirmation."""
    assessment = Path(args.assessment)
    if not assessment.is_file():
        print(f"assessment not found: {assessment}", file=sys.stderr)
        return EXIT_BLOCKED
    scope_path = Path(args.scope)
    scope = _load_yaml(scope_path)
    errors = _validate_scope(scope) or _check_proxy(scope, os.environ)
    if errors:
        print("scope file is invalid:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_BLOCKED

    guard = ScopeGuard(scope)
    win = guard.within_window()
    if not win.allowed:
        print(f"authorisation scope is not valid now: {win.reason}", file=sys.stderr)
        return EXIT_BLOCKED
    target = args.target or scope.get("base_url")
    td = guard.authorize(target, "target")
    if not td.allowed:
        print(f"target out of scope: {td.reason}", file=sys.stderr)
        return EXIT_BLOCKED

    doc, plans, errors = _load_assessment(assessment)
    if errors:
        return _blocked(f"the assessment {assessment} cannot be used; nothing was contacted:", errors)
    sel = _select(args, plans)
    if not sel:
        print("empty selection — nothing to verify (refine --category/--severity/--only).", file=sys.stderr)
        return EXIT_BLOCKED

    try:
        limits = Limits.load({
            "cost_limit_usd": args.cost_limit, "max_requests": args.max_requests,
            "max_attempts": args.max_attempts, "max_calls": args.max_calls, "max_duration_s": args.max_duration,
            "rate_rps": args.rate,
        })
    except ValueError as exc:
        print(f"invalid limits: {exc}", file=sys.stderr)
        return EXIT_BLOCKED
    safe = not args.allow_intrusive
    read_only = True if safe else (args.read_only or not scope.get("allow_state_change", False))

    identities, id_errors = _check_identities(args.identities, guard, os.environ)
    if id_errors:
        print("identities are not usable; nothing was contacted:", file=sys.stderr)
        for e in id_errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_BLOCKED
    budget = RunBudget(limits)
    try:
        planner_factory, agent_info = _build_planner_factory(args)
    except ProfileError as exc:
        print(f"model profile unavailable: {exc}", file=sys.stderr)
        return EXIT_BLOCKED
    from .agent import SourceReader, agent_registry
    from .auth import SessionManager
    from .tools import GuardedHttpClient
    from .tools.httpx_transport import transport_from_scope
    http = GuardedHttpClient(guard, budget, transport_from_scope(scope))
    sessions = SessionManager(identities, http, env=os.environ)
    source = SourceReader(args.source) if args.source else None
    registry = agent_registry(planner_factory, max_steps=limits.max_attempts)
    contact = any(p.status == "dynamic" and registry.get(p.cls) for p in sel)
    browser, browser_note = _proof_browser(args, http, sel)
    listener, listener_note = _callback_listener(scope, sel)

    summary = _assessment_summary(doc)
    print(_verify_preflight_box(f"{assessment} · {summary}" if summary else assessment, target, scope, sel, limits,
                                safe, read_only, contact, agent_info, browser_note, listener_note))
    if invocation:
        print(f"\nThe same run without questions, e.g. in CI:\n  {invocation}")

    if contact:
        conf = confirm_authorization(non_interactive=args.non_interactive, assume_yes=args.yes)
        if not conf.confirmed:
            print(f"\nnot authorised to proceed: {conf.reason}", file=sys.stderr)
            return EXIT_BLOCKED
        authorization = {"confirmed": True, "mode": conf.mode,
                         "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    else:
        print("\nNo target-contacting probe is available yet — emitting a report with every "
              "selected finding as not-attempted. Nothing was contacted.")
        authorization = {"confirmed": False, "mode": "ci-flag" if args.non_interactive else "interactive", "at": None}

    if args.dry_run:
        print("\n--dry-run: selection and scope resolved; no report written, nothing contacted.")
        return EXIT_OK

    if contact:   # VER-032: reachability and logins before the first model call
        checks = [check_target(http, target, proxy=proxy_for(scope, target))]
        if not failed(checks):
            checks += check_identities(sessions, identities, http, target, scope=scope)
        print("\nPreflight\n" + render(checks))
        if failed(checks):
            print("\na pre-flight check failed: no finding was tested and no model was asked.", file=sys.stderr)
            return EXIT_BLOCKED

    out_dir = Path(args.output)
    action_log = None
    if contact:
        from .verify.actionlog import ActionLog
        out_dir.mkdir(parents=True, exist_ok=True)
        action_log = ActionLog(out_dir / "agent-log.jsonl", redact=sessions.redact, append=args.append)
    try:
        if listener is not None and contact:
            try:
                listener.start()
            except OSError as exc:
                print(f"callback listener could not start ({type(exc).__name__}: {exc.strerror or exc}); "
                      "SSRF findings cannot be confirmed", file=sys.stderr)
                listener = None
        doc = run_verification(
            assessment_path=assessment, scope=scope, scope_path=scope_path, plans=sel,
            limits=limits, identities=identities, registry=registry, http=http,
            sessions=sessions, source=source, budget=budget,
            verifier_version=version_string(), target_base=target, authorization=authorization,
            safe=safe, read_only=read_only, contacted=contact, agent=agent_info, browser=browser,
            listener=listener if contact else None, log=action_log, evidence_dir=out_dir / "evidence",
        )
    finally:
        if action_log is not None:
            action_log.close()
        if browser is not None:
            browser.close()
        if listener is not None:
            listener.close()

    if args.append:
        existing_path = out_dir / "verification.yaml"
        if existing_path.is_file():
            from .verify import merge_reports
            doc = merge_reports(_load_yaml(existing_path), doc)
    paths = write_reports(doc, out_dir)
    extra: list[str] = [f"action log: {action_log.path}"] if action_log is not None else []
    if args.annotate:
        import yaml
        annotated = annotate_assessment(_load_yaml(assessment), doc)
        dest = assessment if args.in_place else (out_dir / "security-assessment.annotated.yaml")
        with open(dest, "w", encoding="utf-8") as fh:
            yaml.safe_dump(annotated, fh, sort_keys=False, allow_unicode=True)
        extra.append(f"annotated assessment: {dest}" + (" (in place)" if args.in_place else ""))

    if args.print_results:
        _print_results(doc)
    print(_verify_summary_box(doc, paths, extra))
    return 3 if any(r.get("limits_hit") for r in doc["results"]) else EXIT_OK


# ── preflight (VER-032) ───────────────────────────────────────────────────────

def cmd_preflight(args: argparse.Namespace) -> int:
    """The checks of VER-032 without verifying anything. The offline checks come
    first; the target and its logins only after the confirmation of VER-002 and
    not with --offline; --test-model adds one bounded model call. Progress goes
    to stdout, or to stderr with --json, which prints the result on stdout."""
    from .guided import load_scope

    args.non_interactive = args.non_interactive or args.json     # a JSON run never prompts
    out = sys.stderr if args.json else sys.stdout
    checks: list[Check] = []

    def add(*items: Check) -> None:
        checks.extend(items)
        print(render(list(items)), file=out, flush=True)

    print("Preflight", file=out)
    doc, plans, errors = _load_assessment(Path(args.assessment))
    if errors:
        add(Check("Assessment", "fail", "; ".join(errors)))
    else:
        add(_assessment_check(doc, plans))

    scope, guard, errors = load_scope(args.scope)
    target = args.target or (scope or {}).get("base_url")
    if errors:
        add(Check("Scope", "fail", "; ".join(errors)))
    elif not (decision := guard.authorize(target, "target")).allowed:
        add(Check("Scope", "fail", f"{target} is out of scope: {decision.reason}"))
        guard = None
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
        return _preflight_result(args, checks, out)
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
            add(generation_test(host, test_budget))
    return _preflight_result(args, checks, out)


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


def _preflight_result(args, checks: list[Check], out) -> int:
    import json

    ok = not failed(checks)
    print(f"\npreflight {'passed' if ok else 'failed'}; nothing was verified.", file=out)
    if args.json:
        print(json.dumps({"kind": "preflight", "ok": ok, "verification": "not_run",
                          "checks": [c.as_dict() for c in checks]}, sort_keys=True))
    return EXIT_OK if ok else EXIT_BLOCKED


def _proof_browser(args, http, sel):
    """The XSS proof browser when an XSS finding is selected (VER-009), else None;
    with a line for the pre-flight box. Without it XSS findings stay unconfirmed."""
    if not any(p.status == "dynamic" and p.cls == "xss" for p in sel):
        return None, None
    from .tools.browser import BrowserUnavailable, ProofBrowser

    try:
        ProofBrowser.check_available()
    except BrowserUnavailable as exc:
        return None, f"unavailable ({exc}); XSS findings cannot be confirmed"
    browser = ProofBrowser(http, Path(args.output) / "evidence", headless=not args.headful)
    return browser, "Google Chrome via Playwright" + (", visible" if args.headful else "") + ", started on first use"


def _callback_listener(scope, sel):
    """The SSRF callback listener when an SSRF finding is selected (VER-012), not yet started, else None;
    with a line for the pre-flight box. Without it SSRF findings stay unconfirmed."""
    if not any(p.status == "dynamic" and p.cls == "ssrf" for p in sel):
        return None, None
    from .tools.callback import CallbackListener, CallbackUnavailable

    try:
        listener = CallbackListener(scope.get("callback"))
    except CallbackUnavailable as exc:
        return None, f"unavailable ({exc}); SSRF findings cannot be confirmed"
    return listener, f"will listen on {listener.host}:{listener.port}, reached as {listener.base_url}"


def _verify_preflight_box(assessment, target, scope, sel, limits, safe, read_only, contact, agent_info,
                          browser_note=None, listener_note=None) -> str:
    dyn = sum(1 for p in sel if p.status == "dynamic")
    classes = sorted({p.cls for p in sel if p.cls})
    from .agent import SUBSCRIPTION_PROFILES

    cost = ("cost: subscription, not reported" if agent_info["profile"] in SUBSCRIPTION_PROFILES
            else f"cost ≤ ${limits.cost_limit_usd:.2f}")
    rows = [("browser", browser_note)] if browser_note else []
    rows += [("callback", listener_note)] if listener_note else []
    return _box("AppSec Verifier · verify", rows + [
        ("profile", " · ".join(v for v in (agent_info.get(k) for k in ("profile", "model", "runtime", "auth", "check"))
                               if v)),
        ("assessment", str(assessment)),
        ("target", f"{target}  ({'will contact' if contact else 'not contacted yet'})"),
        ("scope", f"{', '.join(scope.get('hosts', []) or [target])}  owner: {(scope.get('owner') or {}).get('name')}"),
        ("selection", f"{len(sel)} findings · {dyn} dynamic · classes: {', '.join(classes) or '—'}"),
        ("boundaries", f"{cost} · ≤ {limits.max_calls} model calls · ≤ {limits.max_requests} req · "
                       f"≤ {int(limits.max_duration_s)}s · {limits.rate_rps} rps"),
        ("mode", f"{'safe' if safe else 'intrusive'} · {'read-only' if read_only else 'state-changing'}"),
    ])


_VERDICT_MARK = {"confirmed": "✓", "not-reproducible": "✗", "blocked-by-control": "⊘",
                 "inconclusive": "?", "not-attempted": "·"}


def _print_results(doc) -> None:
    """Render per-finding verdicts to the console (VER-013)."""
    print("\nResults:")
    for r in doc["results"]:
        fr = r.get("finding_ref", {})
        mark = _VERDICT_MARK.get(r["verdict"], " ")
        conf = f" ({r['confidence']})" if r.get("confidence") else ""
        title = fr.get("title") or fr.get("cwe") or ""
        print(f"{mark} {fr.get('id'):<8} {str(r.get('class') or '-'):<15} {r['verdict']}{conf}  {title}")
        if r.get("rationale"):
            print(f"    {r['rationale']}")


def _verify_summary_box(doc, paths, extra) -> str:
    s = doc["meta"]["summary"]
    rows = [
        ("verified", f"{s['total']} findings"),
        ("verdicts", f"{s['confirmed']} confirmed · {s['not_reproducible']} not-repro · "
                     f"{s['blocked']} blocked · {s['inconclusive']} inconclusive · {s['not_attempted']} not-attempted"),
        ("report", str(paths["md"])),
        ("data", str(paths["yaml"])),
    ]
    rows += [("", line) for line in extra]
    return "\n" + _box("AppSec Verifier · done", rows)


def cmd_export(args: argparse.Namespace) -> int:
    doc = _load_yaml(Path(args.verification))
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


def _banner() -> str:
    return (
        f"AppSec Verifier {version_string()} — verify static assessment findings "
        f"against a running app.\n\n"
        "Guided run:\n"
        "  appsec-verifier ASSESSMENT   asks for the settings with defaults, then verifies\n\n"
        "Commands:\n"
        "  verify     verify selected findings against a target (safe mode by default)\n"
        "  preflight  check assessment, scope, target, logins and model; verifies nothing\n"
        "  plan       list dynamically verifiable findings, offline\n"
        "  scope      resolve and validate an authorisation scope file\n"
        "  export     re-emit verdicts for AppSec Analyzer\n"
        "  update     update a pipx installation of the Verifier, after your yes\n\n"
        "No probe contacts a target yet; see requirements.md and docs/cli.md. "
        "Run a command with --help."
    )


_PROFILE_CHOICES = ["claude", "codex-cli", "copilot-cli", "codex", "anthropic-api"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="appsec-verifier", add_help=True,
                                description="Dynamic verification of static security-assessment findings.",
                                epilog="Guided run: appsec-verifier ASSESSMENT [verify options] asks for the "
                                       "settings with defaults (VER-031).")
    p.add_argument("--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="command")

    pl = sub.add_parser("plan", help="list dynamically verifiable findings (offline)")
    pl.add_argument("--assessment", required=True, help="security-assessment.yaml to read")
    pl.add_argument("--category", help="filter: categories (class or technique), comma-separated")
    pl.add_argument("--severity", help="filter: exact severities, comma-separated")
    pl.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], help="severity floor")
    pl.add_argument("--class", dest="cls", help="(advanced) filter: classes, comma-separated")
    pl.add_argument("--cwe", help="(advanced) filter: CWEs, comma-separated")
    pl.add_argument("--only", help="filter: finding ids, comma-separated")

    sc = sub.add_parser("scope", help="resolve and validate an authorisation scope file")
    sc.add_argument("--scope", required=True, help="scope.yaml to validate")
    sc.add_argument("--target", help="check whether this URL falls inside the scope")

    vf = sub.add_parser("verify", help="verify selected findings against a target (safe mode by default)")
    _add_run_options(vf, guided=False)

    pf = sub.add_parser("preflight", help="check assessment, scope, target, logins and model; verifies nothing")
    pf.add_argument("--assessment", required=True, help="security-assessment.yaml to check")
    pf.add_argument("--scope", required=True, help="authorisation scope file")
    pf.add_argument("--url", "--target", dest="target", help="URL to check (default: scope base_url); must be in scope")
    pf.add_argument("--identities", help="identities.yaml; each login is tried once")
    pf.add_argument("--profile", choices=_PROFILE_CHOICES, help="model profile, as for verify")
    pf.add_argument("--model", help="model for the selected profile")
    pf.add_argument("--offline", action="store_true",
                    help="contact nothing: neither the target, its login endpoints, nor the model provider")
    pf.add_argument("--test-model", action="store_true",
                    help="send one fixed prompt to the model; needs --cost-limit, or --max-calls 1 for "
                         "codex-cli and copilot-cli")
    pf.add_argument("--cost-limit", type=float, help="with --test-model: spending limit of the call, USD")
    pf.add_argument("--max-calls", type=int, help="with --test-model: call limit (subscription profiles)")
    pf.add_argument("--non-interactive", "--ci", dest="non_interactive", action="store_true",
                    help="no prompts; contacting the target then needs --yes")
    pf.add_argument("--yes", action="store_true", help="confirm contacting the target without a prompt")
    pf.add_argument("--json", action="store_true", help="print the result as JSON on stdout; never prompts")

    ex = sub.add_parser("export", help="re-emit a verification.yaml for AppSec Analyzer")
    ex.add_argument("--verification", required=True, help="verification.yaml to export")
    ex.add_argument("--output", help="output path (default: analyzer-verification.json)")
    ex.add_argument("--format", dest="fmt", choices=["json", "yaml"], default="json")

    sub.add_parser("update", help="update a pipx installation of the Verifier, after your yes (VER-033)")

    return p


def build_guided_parser() -> argparse.ArgumentParser:
    """`appsec-verifier ASSESSMENT [options]`: the guided run (VER-031). It takes
    the `verify` options; those given are not asked."""
    p = argparse.ArgumentParser(
        prog="appsec-verifier", usage="appsec-verifier ASSESSMENT [verify options]",
        description="Guided run: reads the assessment, asks for the settings of the run with defaults, "
                    "then verifies after one confirmation. Options given here are not asked. Without a "
                    "terminal, or with --non-interactive, nothing is asked.")
    _add_run_options(p, guided=True)
    return p


def _add_run_options(vf: argparse.ArgumentParser, *, guided: bool) -> None:
    """The options of `verify`, shared with the guided run. The guided run takes
    the assessment as its argument and asks for the scope when it is missing."""
    if guided:
        vf.add_argument("assessment", help="security-assessment.yaml to verify")
        vf.add_argument("--scope", help="authorisation scope file (asked when missing)")
    else:
        vf.add_argument("--assessment", required=True, help="security-assessment.yaml to verify")
        vf.add_argument("--scope", required=True, help="authorisation scope file")
    vf.add_argument("--url", "--target", dest="target",
                    help="start/base URL to test (default: scope base_url); must be in scope")
    vf.add_argument("--identities", help="identities.yaml (roles + env-var credential refs)")
    vf.add_argument("--source", help="read-only checkout of the target repo, to ground the agent (VER-017)")
    vf.add_argument("--output", default=None if guided else "./verification",
                    help="report/evidence directory (default: ./verification)")
    # selection (VER-026)
    vf.add_argument("--category", help="categories, comma-separated: class or technique "
                                       "(e.g. 'idor', 'access-control', 'sqli', 'xss')")
    vf.add_argument("--severity", help="exact severities, comma-separated (e.g. critical,high)")
    vf.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], help="severity floor")
    vf.add_argument("--class", dest="cls", help="(advanced) weakness classes, comma-separated")
    vf.add_argument("--cwe", help="(advanced) CWEs, comma-separated")
    vf.add_argument("--only", help="finding ids, comma-separated")
    # boundaries (VER-015)
    vf.add_argument("--cost-limit", type=float, help="model-spend ceiling, USD")
    vf.add_argument("--max-requests", type=int)
    vf.add_argument("--max-attempts", type=int)
    vf.add_argument("--max-calls", type=int, help="cap on model calls (planning steps) for the run")
    vf.add_argument("--max-duration", type=float, help="run wall-clock ceiling, seconds")
    vf.add_argument("--rate", type=float, help="max requests/second")
    # output mode (VER-020/027) and run mode (VER-002/030)
    vf.add_argument("--report", action="store_true", help="standalone report (default)")
    vf.add_argument("--print", dest="print_results", action="store_true",
                    help="also print per-finding results to the console")
    vf.add_argument("--append", action="store_true",
                    help="extend an existing report in --output instead of overwriting")
    vf.add_argument("--annotate", action="store_true", help="also write an annotated assessment copy")
    vf.add_argument("--in-place", action="store_true", help="with --annotate: modify the assessment file itself")
    vf.add_argument("--non-interactive", "--ci", dest="non_interactive", action="store_true",
                    help="no prompts; selection, scope, and cost come from the invocation")
    vf.add_argument("--yes", action="store_true", help="confirm authorisation without a prompt (recorded)")
    vf.add_argument("--allow-intrusive", action="store_true",
                    help="opt out of safe mode: permit marked state-changing / more thorough probing (VER-030)")
    vf.add_argument("--read-only", action="store_true", help="force read-only even if the scope allows state change")
    vf.add_argument("--dry-run", action="store_true", help="resolve selection + scope, write nothing, contact nothing")
    vf.add_argument("--headful", action="store_true", help="run the proof browser visibly (local debugging)")
    vf.add_argument("--profile", choices=_PROFILE_CHOICES,
                    help="model profile, as in AppSec Analyzer: claude (Claude CLI, login or key; default when "
                         "interactive), codex-cli (ChatGPT login), copilot-cli (Copilot login), codex "
                         "(OPENAI_API_KEY), anthropic-api (ANTHROPIC_API_KEY, no CLI needed). "
                         "Required with --non-interactive")
    vf.add_argument("--model", help="model for the selected profile (default: the profile's model)")


COMMANDS = ("plan", "scope", "verify", "preflight", "export", "update")


def _stdin_is_terminal() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and not argv[0].startswith("-") and argv[0] not in COMMANDS:
        from .guided import run_guided
        args = build_guided_parser().parse_args(argv)
        return run_guided(args, interactive=not args.non_interactive and _stdin_is_terminal())
    args = build_parser().parse_args(argv)
    if args.version:
        print(version_string())
        return EXIT_OK
    if args.command == "plan":
        return cmd_plan(args)
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
    print(_banner())
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
