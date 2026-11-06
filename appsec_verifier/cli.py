"""appsec-verifier — command-line entry point.

Today `scope` and `plan` run (offline, no network, no model calls); `verify` and
`export` are specified in requirements.md / docs/cli.md but not implemented yet
and exit non-zero with that notice. See docs/cli.md for the full design.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .loader import load_plans, select
from .scope import ScopeGuard
from .version_info import resource_root, version_string

EXIT_OK = 0
EXIT_BLOCKED = 2            # run could not start (bad input, unconfirmed, etc.)
EXIT_NOT_IMPLEMENTED = 2


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


# ── not-yet-implemented ───────────────────────────────────────────────────────

def cmd_not_implemented(name: str) -> int:
    print(
        f"`{name}` is specified but not implemented yet (design stage).\n"
        f"See requirements.md and docs/cli.md. `plan` and `scope` run today.",
        file=sys.stderr,
    )
    return EXIT_NOT_IMPLEMENTED


def _banner() -> str:
    return (
        f"AppSec Verifier {version_string()} — verify static assessment findings "
        f"against a running app.\n\n"
        "Commands:\n"
        "  verify   verify selected findings against a target   (not implemented yet)\n"
        "  plan     list dynamically verifiable findings, offline\n"
        "  scope    resolve and validate an authorisation scope file\n"
        "  export   re-emit verdicts for AppSec Analyzer          (not implemented yet)\n\n"
        "Design stage: see requirements.md and docs/cli.md. Run a command with --help."
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

    vf = sub.add_parser("verify", help="verify findings against a target (not implemented yet)")
    vf.add_argument("--assessment")
    vf.add_argument("--scope")

    ex = sub.add_parser("export", help="re-emit verdicts for AppSec Analyzer (not implemented yet)")
    ex.add_argument("--verification")

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
    if args.command in ("verify", "export"):
        return cmd_not_implemented(args.command)
    print(_banner())
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
