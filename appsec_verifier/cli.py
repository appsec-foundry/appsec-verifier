"""appsec-verifier — command-line entry point.

Today `scope` and `plan` run (offline, no network, no model calls); `verify` and
`export` are specified in requirements.md / docs/cli.md but not implemented yet
and exit non-zero with that notice. See docs/cli.md for the full design.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .limits import Limits, RunBudget
from .loader import load_plans, select
from .preflight import confirm_authorization
from .scope import ScopeGuard
from .verify import build_annotations, default_registry, run_verification, write_reports
from .verify.report import annotate_assessment
from .version_info import resource_root, version_string

EXIT_OK = 0
EXIT_BLOCKED = 2            # run could not start (bad input, unconfirmed, etc.)


def _csv(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {v.strip() for v in value.split(",") if v.strip()}


def _box(title: str, rows: list[tuple[str, str]]) -> str:
    label_w = max((len(k) for k, _ in rows), default=0)
    width = max(len(title) + 4, max((label_w + 3 + len(v) for _, v in rows), default=0) + 2, 58)
    top = f"┌─ {title} " + "─" * (width - len(title) - 3) + "┐"
    body = [f"│ {k.ljust(label_w)}  {v}".ljust(width + 1) + "│" for k, v in rows]
    bottom = "└" + "─" * width + "┘"
    return "\n".join([top, *body, bottom])


# ── plan ────────────────────────────────────────────────────────────────────

def cmd_plan(args: argparse.Namespace) -> int:
    plans = load_plans(Path(args.assessment))
    sel = select(
        plans,
        classes=_csv(args.cls),
        severities=_csv(args.severity),
        min_severity=args.min_severity,
        cwes={c.upper() for c in (_csv(args.cwe) or set())} or None,
        ids=_csv(args.only),
    )
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
        return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in cls(schema).iter_errors(scope)]
    except ModuleNotFoundError:
        return [f"missing required field: {k}" for k in schema.get("required", []) if k not in scope]


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

def _load_identities(path: str | None) -> list[dict]:
    if not path:
        return []
    return _load_yaml(Path(path)).get("identities", []) or []


def _build_planner_factory(args):
    """A planner factory when model access is available (ANTHROPIC_API_KEY set, or
    --model given), else None — in which case the run stays offline and every
    selected finding is reported not-attempted."""
    if not os.environ.get("ANTHROPIC_API_KEY") and not args.model:
        return None
    from .agent import AnthropicPlanner
    model = args.model or "claude-opus-5-5"
    return lambda: AnthropicPlanner(model=model)


def cmd_verify(args: argparse.Namespace) -> int:
    assessment = Path(args.assessment)
    if not assessment.is_file():
        print(f"assessment not found: {assessment}", file=sys.stderr)
        return EXIT_BLOCKED
    scope_path = Path(args.scope)
    scope = _load_yaml(scope_path)
    errors = _validate_scope(scope)
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

    plans = load_plans(assessment)
    sel = select(
        plans, classes=_csv(args.cls), severities=_csv(args.severity),
        min_severity=args.min_severity,
        cwes={c.upper() for c in (_csv(args.cwe) or set())} or None,
        ids=_csv(args.only),
    )
    if not sel:
        print("empty selection — nothing to verify (refine --class/--severity/--cwe/--only).", file=sys.stderr)
        return EXIT_BLOCKED

    limits = Limits.load({
        "cost_limit_usd": args.cost_limit, "max_requests": args.max_requests,
        "max_attempts": args.max_attempts, "max_duration_s": args.max_duration, "rate_rps": args.rate,
    })
    safe = not args.allow_intrusive
    read_only = True if safe else (args.read_only or not scope.get("allow_state_change", False))

    identities = _load_identities(args.identities)
    budget = RunBudget(limits)
    planner_factory = _build_planner_factory(args)
    http = sessions = source = None
    if planner_factory is not None:
        from .agent import SourceReader, agent_registry
        from .auth import SessionManager
        from .tools import GuardedHttpClient
        from .tools.httpx_transport import transport_from_scope
        http = GuardedHttpClient(guard, budget, transport_from_scope(scope))
        sessions = SessionManager(identities, http, env=os.environ)
        source = SourceReader(args.source) if args.source else None
        registry = agent_registry(planner_factory)
    else:
        registry = default_registry()
    have_probe = any(p.status == "dynamic" and registry.get(p.cls) for p in sel)
    contact = (planner_factory is not None) and have_probe

    print(_verify_preflight_box(assessment, target, scope, sel, limits, safe, read_only, contact))

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

    doc = run_verification(
        assessment_path=assessment, scope=scope, scope_path=scope_path, plans=sel,
        limits=limits, identities=identities, registry=registry, http=http,
        sessions=sessions, source=source, budget=budget,
        verifier_version=version_string(), target_base=target, authorization=authorization,
        safe=safe, read_only=read_only, contacted=contact,
    )

    out_dir = Path(args.output)
    paths = write_reports(doc, out_dir)
    extra: list[str] = []
    if args.annotate:
        import yaml
        annotated = annotate_assessment(_load_yaml(assessment), doc)
        dest = assessment if args.in_place else (out_dir / "security-assessment.annotated.yaml")
        with open(dest, "w", encoding="utf-8") as fh:
            yaml.safe_dump(annotated, fh, sort_keys=False, allow_unicode=True)
        extra.append(f"annotated assessment: {dest}" + (" (in place)" if args.in_place else ""))

    print(_verify_summary_box(doc, paths, extra))
    return 3 if any(r.get("limits_hit") for r in doc["results"]) else EXIT_OK


def _verify_preflight_box(assessment, target, scope, sel, limits, safe, read_only, contact) -> str:
    dyn = sum(1 for p in sel if p.status == "dynamic")
    classes = sorted({p.cls for p in sel if p.cls})
    return _box("AppSec Verifier · verify", [
        ("assessment", str(assessment)),
        ("target", f"{target}  ({'will contact' if contact else 'not contacted yet'})"),
        ("scope", f"{', '.join(scope.get('hosts', []) or [target])}  owner: {(scope.get('owner') or {}).get('name')}"),
        ("selection", f"{len(sel)} findings · {dyn} dynamic · classes: {', '.join(classes) or '—'}"),
        ("boundaries", f"cost ≤ ${limits.cost_limit_usd:.2f} · ≤ {limits.max_requests} req · "
                       f"≤ {int(limits.max_duration_s)}s · {limits.rate_rps} rps"),
        ("mode", f"{'safe' if safe else 'intrusive'} · {'read-only' if read_only else 'state-changing'}"),
    ])


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
        "Commands:\n"
        "  verify   verify selected findings against a target (safe mode by default)\n"
        "  plan     list dynamically verifiable findings, offline\n"
        "  scope    resolve and validate an authorisation scope file\n"
        "  export   re-emit verdicts for AppSec Analyzer\n\n"
        "No probe contacts a target yet; see requirements.md and docs/cli.md. "
        "Run a command with --help."
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="appsec-verifier", add_help=True,
                                description="Dynamic verification of static security-assessment findings.")
    p.add_argument("--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="command")

    pl = sub.add_parser("plan", help="list dynamically verifiable findings (offline)")
    pl.add_argument("--assessment", required=True, help="security-assessment.yaml to read")
    pl.add_argument("--class", dest="cls", help="filter: classes, comma-separated")
    pl.add_argument("--severity", help="filter: exact severities, comma-separated")
    pl.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], help="severity floor")
    pl.add_argument("--cwe", help="filter: CWEs, comma-separated")
    pl.add_argument("--only", help="filter: finding ids, comma-separated")

    sc = sub.add_parser("scope", help="resolve and validate an authorisation scope file")
    sc.add_argument("--scope", required=True, help="scope.yaml to validate")
    sc.add_argument("--target", help="check whether this URL falls inside the scope")

    vf = sub.add_parser("verify", help="verify selected findings against a target (safe mode by default)")
    vf.add_argument("--assessment", required=True, help="security-assessment.yaml to verify")
    vf.add_argument("--scope", required=True, help="authorisation scope file")
    vf.add_argument("--target", help="base URL to test (default: scope base_url); must be in scope")
    vf.add_argument("--identities", help="identities.yaml (roles + env-var credential refs)")
    vf.add_argument("--source", help="read-only checkout of the target repo, to ground the agent (VER-017)")
    vf.add_argument("--output", default="./verification", help="report/evidence directory")
    # selection (VER-026) — same selectors as `plan`
    vf.add_argument("--class", dest="cls", help="classes, comma-separated (e.g. a single class)")
    vf.add_argument("--severity", help="exact severities, comma-separated")
    vf.add_argument("--min-severity", choices=["low", "medium", "high", "critical"])
    vf.add_argument("--cwe", help="CWEs, comma-separated (e.g. CWE-639 for IDOR only)")
    vf.add_argument("--only", help="finding ids, comma-separated")
    # boundaries (VER-015)
    vf.add_argument("--cost-limit", type=float, help="model-spend ceiling, USD")
    vf.add_argument("--max-requests", type=int)
    vf.add_argument("--max-attempts", type=int)
    vf.add_argument("--max-duration", type=float, help="run wall-clock ceiling, seconds")
    vf.add_argument("--rate", type=float, help="max requests/second")
    # output mode (VER-020/027) and run mode (VER-002/030)
    vf.add_argument("--report", action="store_true", help="standalone report (default)")
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
    vf.add_argument("--model", help="reasoning model for the verification agent")

    ex = sub.add_parser("export", help="re-emit a verification.yaml for AppSec Analyzer")
    ex.add_argument("--verification", required=True, help="verification.yaml to export")
    ex.add_argument("--output", help="output path (default: analyzer-verification.json)")
    ex.add_argument("--format", dest="fmt", choices=["json", "yaml"], default="json")

    return p


def main(argv: list[str] | None = None) -> int:
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
    if args.command == "export":
        return cmd_export(args)
    print(_banner())
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
