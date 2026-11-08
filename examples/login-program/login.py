#!/usr/bin/env python3
"""Example login program for AppSec Verifier (method: command, VER-040).

Logs in to a web application with a classic login form that carries a CSRF
token, and prints the session cookie as JSON on standard output. The user name
and password come from environment variables named after the role, e.g.
VERIFIER_USER_A_USER and VERIFIER_USER_A_PASS for user-a. Messages go to
standard error; standard output holds only the session.

Adapt LOGIN_URL, the form field names and COOKIE to your application. The
program runs with your rights, outside the Verifier's scope and limits, so it
should contact only the application you are authorised to test.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import urllib.parse
import urllib.request

LOGIN_URL = "https://app.staging.example.com/login"     # EDIT: the login form's address
COOKIE = "JSESSIONID"                                    # EDIT: the application's session cookie
CSRF_FIELD = "_csrf"                                     # EDIT: the login form's hidden CSRF field
SESSION_SECONDS = 1800                                   # EDIT: how long a session lasts


def main(role: str) -> int:
    prefix = "VERIFIER_" + role.upper().replace("-", "_")
    user, password = os.environ.get(prefix + "_USER"), os.environ.get(prefix + "_PASS")
    if not user or not password:
        print(f"set {prefix}_USER and {prefix}_PASS", file=sys.stderr)
        return 2
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    page = opener.open(LOGIN_URL, timeout=30).read().decode("utf-8", "replace")
    token = re.search(rf'name="{re.escape(CSRF_FIELD)}"[^>]*value="([^"]+)"', page)
    form = {"username": user, "password": password, **({CSRF_FIELD: token.group(1)} if token else {})}
    opener.open(LOGIN_URL, urllib.parse.urlencode(form).encode(), timeout=30)
    session = next((c for c in jar if c.name == COOKIE), None)
    if session is None:
        print(f"login as {role} failed: no {COOKIE} cookie", file=sys.stderr)
        return 1
    print(json.dumps({"cookies": {COOKIE: session.value}, "expires_in": SESSION_SECONDS}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "user-a"))
