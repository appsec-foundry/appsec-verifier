"""Value-free session-cookie observations and class-specific proof (VER-013/016/035/062)."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie

from .experiments import latest_plan


def cookie_observations(response, sessions=None):
    headers = getattr(response, "headers", {})
    values = (
        headers.get_list("set-cookie")
        if hasattr(headers, "get_list")
        else [headers.get("Set-Cookie") or headers.get("set-cookie", "")]
    )
    out = []
    for raw in values[:30]:
        if len(raw) > 8192:
            continue
        cookies = SimpleCookie()
        try:
            cookies.load(raw)
        except CookieError:
            continue
        for name, cookie in cookies.items():
            if sessions is not None and cookie.value:
                sessions.remember_secret(cookie.value, "session cookie")
            active = bool(cookie.value)
            try:
                if cookie["max-age"]:
                    active = active and int(cookie["max-age"]) > 0
                elif cookie["expires"]:
                    expires = parsedate_to_datetime(cookie["expires"])
                    active = active and expires > datetime.now(timezone.utc)
            except (ValueError, TypeError, OverflowError):
                active = False
            out.append(
                {
                    "name": name,
                    "secure": bool(cookie["secure"]),
                    "httponly": bool(cookie["httponly"]),
                    "samesite": cookie["samesite"].lower(),
                    "active": active,
                }
            )
    return out


def session_check(ctx, history, cited, *, negative=False):
    start, plan = latest_plan(history)
    resource = next(
        (
            r
            for r in ctx.scope.get("session_checks", [])
            if r["finding_id"] == ctx.plan.id and r["id"] == plan.get("resource")
        ),
        None,
    )
    attribute = {"CWE-614": "secure", "CWE-1004": "httponly", "CWE-1275": "samesite"}.get(ctx.plan.cwe)
    if plan.get("kind") != "session" or not resource or not attribute:
        return "declare a session plan for an operator-identified session cookie"
    if resource.get("source") == "login":
        observations = []
        for n in cited or []:
            h = history[n - 1] if type(n) is int and 0 < n <= len(history) else {}
            if h.get("tool") != "plan_test" or not h.get("result", {}).get("accepted"):
                return "cite the accepted session plan with recorded login observations"
            observations.extend(h["result"].get("login_observations", []))
        unique = {o["observation_id"]: o for o in observations}
        matching = [o for o in unique.values() if o.get("path") == resource["path"]
                    and o.get("role") == resource["role"] and 200 <= o.get("status", 0) < 400]
        if len(matching) < 2:
            return "repeat the configured login cookie observation; fewer than two responses issued the cookie"
        for o in matching:
            cookies = [c for c in o["session_cookies"] if c["name"] == resource["cookie_name"] and c["active"]]
            if len(cookies) != 1:
                return "the declared active session cookie is absent or ambiguous"
            protected = cookies[0][attribute] in ("lax", "strict") if attribute == "samesite" else cookies[0][attribute]
            if protected != negative:
                return "login cookie observations conflict with the proposed attribute verdict"
        return None
    if not isinstance(cited, list) or len(set(cited)) < 2:
        return "repeat the session observation using distinct requests"
    for step in cited:
        if type(step) is not int or not 0 < step <= len(history):
            return f"proof step {step!r} does not exist"
        if negative and step <= start:     # a confirmation may cite earlier observations (VER-043)
            return "session observations must follow the declared plan"
        h = history[step - 1]
        args, result = h.get("args", {}), h.get("result", {})
        if (
            h.get("tool") != "http_request"
            or args.get("path") != resource["path"]
            or args.get("method", "GET") != "GET"
            or args.get("role") != resource.get("role")
            or any(args.get(k) for k in ("params", "json", "form"))
            or not 200 <= result.get("status", 0) < 300
        ):
            return "session proof needs matching successful read-only observations"
        cookies = [c for c in result.get("session_cookies", []) if c["name"] == resource["cookie_name"]]
        if len(cookies) != 1 or not cookies[0]["active"]:
            return "the declared active session cookie is absent or ambiguous"
        protected = cookies[0][attribute] in ("lax", "strict") if attribute == "samesite" else cookies[0][attribute]
        if protected != negative:
            return "the cookie observations do not establish the proposed attribute verdict"
    return None
