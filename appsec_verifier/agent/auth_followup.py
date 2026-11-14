"""Read a declared harmless resource with an injection's artifact only (VER-049/016)."""

from __future__ import annotations

from ..auth.sessions import header_problem
from ..tools.http import same_origin
from .access_observation import matches
from .experiments import pointer_value


def declaration(ctx, login_path):
    checks = [c for c in getattr(ctx, "scope", {}).get("auth_checks", [])
              if c["finding_id"] == ctx.plan.id and c["login_path"] == login_path]
    return checks[0] if len(checks) == 1 else None


def artifact(body, pointer):
    try:
        value = pointer_value(body, pointer)
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        return None
    return value if isinstance(value, str) and 0 < len(value) <= 16384 else None


def followup(tools, body, plan):
    from .tools import ToolError

    ctx = tools.ctx
    check = declaration(ctx, plan["path"])
    if not check or ctx.sessions is None:
        raise ToolError("login-bypass proof needs a unique operator-declared auth_checks resource")
    url = tools._url(check["path"])
    if not same_origin(url, ctx.target_base):
        raise ToolError("login-bypass follow-up must remain on the target origin")
    value = artifact(body, plan.get("pointer"))
    headers = {}
    if value:
        ctx.sessions.remember_secret(value, "login artifact")
        if check.get("artifact_kind", "bearer") == "cookie":
            if any(c in value for c in ';,\r\n\x00'):
                raise ToolError("invalid cookie artifact")
            headers = {"Cookie": check["cookie_name"] + "=" + value}
        else:
            headers = {"Authorization": "Bearer " + value}
        if any(header_problem(k, v) for k, v in headers.items()):
            raise ToolError("invalid authentication artifact")
    ctx.guard.check_window()
    ctx.budget.check_time()
    response = ctx.http.request("GET", url, headers, purpose="target", follow_redirects=False)
    # The follow-up never uses SessionManager.headers_for or renew, and never follows a redirect.
    observed = 200 <= response.status_code < 300 and matches(response.text, check, {"path": check["path"]})
    tools._record(tools._sent(response, "GET", url, headers, None, None), None, headers,
                  omit="body withheld: declared login-bypass resource checked in code (VER-049)")
    return {"path": check["path"], "status": response.status_code, "matched": observed,
            "artifact_supplied": value is not None, "pointer": check["pointer"], "value": check["value"]}
