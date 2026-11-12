"""The login form of an HTML page and the cookies a login sets (VER-028, VER-041).

A `form` login whose login URL serves an HTML page with a login form, a form
with exactly one password field, submits that form as a browser does when
Enter is pressed: every named field with its value (hidden fields such as a
CSRF token included), checked boxes, the first submit button, and the user
name and password. The password goes into the form's password field, the user
name into the identity's user name field where the form has one by that name,
else into the form's only text field.

`keep_cookies` keeps the cookies a response sets by name, as a browser keeps
them for one origin. Domain and Path are not used, because the session goes
only to its own origin (VER-018); so a cookie with `Domain=localhost`, which
some cookie libraries drop, is kept. A name or value that is not a valid
cookie is not kept, so no control character reaches a request header.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import http2time

from .program import _COOKIE_NAME, _COOKIE_VALUE

_TEXT_TYPES = ("text", "email", "tel")
_NOT_SENT = ("file", "image", "reset", "button")
_MAX_AGE = re.compile(r"^-?\d{1,12}$")


@dataclass
class LoginForm:
    action: str
    method: str
    fields: list = field(default_factory=list)      # (type, name, value, checked) in document order


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[LoginForm] = []
        self._open: LoginForm | None = None

    def handle_starttag(self, tag, attrs):
        a = {name: value or "" for name, value in attrs}
        if tag == "form":
            self._open = LoginForm(a.get("action", ""), a.get("method", "get").strip().lower())
            self.forms.append(self._open)
        elif self._open is not None and tag in ("input", "button"):
            kind = a.get("type", "text" if tag == "input" else "submit").strip().lower()
            self._open.fields.append((kind, a.get("name", ""), a.get("value", ""), "checked" in a))

    def handle_endtag(self, tag):
        if tag == "form":
            self._open = None


def is_html(resp) -> bool:
    """An answer declared as HTML, or without a type, which a browser reads as HTML too."""
    headers = getattr(resp, "headers", None) or {}
    kind = str(headers.get("content-type") or headers.get("Content-Type") or "").lower()
    return not kind or "html" in kind


def find_form(html: str) -> LoginForm | None:
    """The first form with exactly one password field, or None."""
    parser = _Forms()
    parser.feed(html)
    parser.close()
    return next((f for f in parser.forms if sum(kind == "password" for kind, *_ in f.fields) == 1), None)


def submission(form: LoginForm, user: tuple[str, str], password: tuple[str, str]) -> tuple[dict, str, str]:
    """The fields a browser sends for `form` with the user name and password, each given as (field, value), filled
    in, and the names of the two fields used."""
    texts = [name for kind, name, *_ in form.fields if kind in _TEXT_TYPES and name]
    user_field = texts[0] if len(texts) == 1 and user[0] not in texts else user[0]
    password_field = next(name for kind, name, *_ in form.fields if kind == "password") or password[0]
    data, submitted = {}, False
    for kind, name, value, checked in form.fields:
        if kind == "submit":
            if submitted:
                continue
            submitted = True                      # the default button, sent only when it has a name
        if not name or kind == "password" or kind in _NOT_SENT:
            continue
        if kind in ("checkbox", "radio"):
            if not checked:
                continue
            value = value or "on"
        data.setdefault(name, value)
    data[user_field] = user[1]
    data[password_field] = password[1]
    return data, user_field, password_field


def keep_cookies(resp, cookies: dict, now: float) -> None:
    """Add the cookies `resp` sets to `cookies`; a later value replaces an earlier one, and an expired cookie,
    or one whose name or value is invalid, is removed."""
    headers = getattr(resp, "headers", None) or {}
    if hasattr(headers, "get_list"):              # httpx.Headers: every Set-Cookie line
        lines = headers.get_list("set-cookie")
    else:
        lines = [v for v in (headers.get("Set-Cookie") or headers.get("set-cookie"),) if v]
    for line in lines:
        pair, *attrs = line.split(";")
        name, sep, value = (part.strip() for part in pair.partition("="))
        if not sep or not _COOKIE_NAME.match(name):
            continue
        max_age = expires = None
        for attr in attrs:
            key, _, val = (part.strip() for part in attr.partition("="))
            if key.lower() == "max-age" and _MAX_AGE.match(val):
                max_age = int(val)
            elif key.lower() == "expires":
                expires = http2time(val)
        gone = max_age <= 0 if max_age is not None else expires is not None and expires <= now
        bare = value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
        if gone or not _COOKIE_VALUE.match(bare):
            cookies.pop(name, None)
        else:
            cookies[name] = value
