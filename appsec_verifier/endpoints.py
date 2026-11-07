"""The requests a finding names, read from the assessment (VER-005, VER-008).

An AppSec Analyzer assessment describes a finding in prose: its scenario and
attack steps often name the request (`GET /rest/basket/:id`). Its attack surface
lists each entry point with `auth_required` and the file and line of its
handler. The Verifier joins the two: a request named in the text, matched to an
entry point where one fits, an entry point whose handler sits at one of the
finding's locations, and a browser route (`/#/search`) for client-side findings.

The result is a hint from the input file. It is shown to the operator, decides
whether the run can test a finding at all (a login without a test identity,
only write requests in safe mode), and is given to the agent. That a request
needs a login is known only where the attack surface says `auth_required: true`.
Nothing here contacts the target.
"""

from __future__ import annotations

import re
from typing import NamedTuple

MAX_ENDPOINTS = 4
BRIEF_CAP = 1500
_TEXT_CAP = 4000          # per text field: the input is untrusted, the scan stays bounded
_REQUEST = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/(?:[A-Za-z0-9_\-.:~%/]|<[^<>\s]{1,40}>|\{[^{}\s]{1,40}\})*)")
_PAGE = re.compile(r"/#/[A-Za-z0-9_\-/]+")
_HANDLER = re.compile(r"handler:\s*([^\s;,]+:\d+)")
WRITE_METHODS = frozenset(("POST", "PUT", "PATCH", "DELETE"))


class Endpoint(NamedTuple):
    method: str                 # GET, POST, …, ALL as the attack surface writes it, or PAGE for a browser route
    path: str                   # the attack surface's template where one matched, else as the text names it
    login: bool | None          # True when the attack surface says auth_required; None when it does not say

    def __str__(self) -> str:
        head = f"page {self.path}" if self.method == "PAGE" else f"{self.method} {self.path}"
        return head + (" (login)" if self.login else "")


class _Entry(NamedTuple):
    method: str
    template: str
    login: bool | None
    handler: str | None


def _entries(surface) -> list[_Entry]:
    entries = []
    for item in surface if isinstance(surface, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("entry_point"), str):
            continue
        method, _, template = item["entry_point"].strip().partition(" ")
        if not template.startswith("/"):
            continue
        handler = _HANDLER.search(str(item.get("notes") or "")[:_TEXT_CAP])
        template = re.sub(r"\(.*?\)", "", template.strip())       # Express regex groups: /ftp(?!/quarantine)/:file
        entries.append(_Entry(method.upper(), template, True if item.get("auth_required") is True else None,
                              handler.group(1) if handler else None))
    return entries


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _fits(template: str, path: str) -> bool:
    """`path` is an instance of `template`: same segment count, a template parameter (`:id`) takes any segment."""
    t, p = _segments(template), _segments(path)
    return len(t) == len(p) and all(a == b or a.startswith(":") for a, b in zip(t, p, strict=True))


def _texts(threat: dict) -> list[str]:
    texts = [threat.get("scenario"), *_list(threat.get("attack_steps"))]
    texts += [i.get("scenario") for i in _list(threat.get("instances")) if isinstance(i, dict)]
    return [t[:_TEXT_CAP] for t in texts if isinstance(t, str)]


def _locations(threat: dict) -> set[str]:
    places = [*_list(threat.get("instances"))]
    evidence = threat.get("evidence")
    places += evidence if isinstance(evidence, list) else [evidence]
    return {f"{p.get('file')}:{p.get('line')}" for p in places if isinstance(p, dict) and p.get("file")}


def finding_endpoints(threat: dict, surface) -> tuple[Endpoint, ...]:
    """Up to MAX_ENDPOINTS requests the finding names, the ones in its text first."""
    entries, texts, found = _entries(surface), _texts(threat), []

    def add(endpoint: Endpoint) -> None:      # once, also when the text names an instance of a found template
        if all(e.method != endpoint.method or not (_fits(e.path, endpoint.path) or _fits(endpoint.path, e.path))
               for e in found):
            found.append(endpoint)

    for text in texts:
        for match in _REQUEST.finditer(text):
            method, path = match.group(1), match.group(2).rstrip(".:")
            entry = next((e for e in entries if e.method in (method, "ALL") and _fits(e.template, path)), None)
            add(Endpoint(method, entry.template, entry.login) if entry else Endpoint(method, path, None))
    locations = _locations(threat)
    for entry in entries:
        if entry.handler in locations:
            add(Endpoint(entry.method, entry.template, entry.login))
    for text in texts:
        for match in _PAGE.finditer(text):
            add(Endpoint("PAGE", match.group(0), None))
    return tuple(found[:MAX_ENDPOINTS])


def login_endpoint(surface) -> str | None:
    """The path of the login the attack surface lists (a POST whose path names login), for the
    operator's identities file; None when it lists none."""
    return next((e.template for e in _entries(surface) if e.method == "POST" and "login" in e.template.lower()),
                None)


def finding_brief(threat: dict) -> str:
    """The finding's scenario and attack steps as one line, for the agent; empty without either."""
    scenario = threat.get("scenario")
    if not isinstance(scenario, str) or not scenario.strip():
        scenario = next((i.get("scenario") for i in _list(threat.get("instances"))
                         if isinstance(i, dict) and isinstance(i.get("scenario"), str)), "")
    steps = [s for s in _list(threat.get("attack_steps")) if isinstance(s, str) and s.strip()]
    text = scenario[:_TEXT_CAP] + (" Attack steps: " + " ".join(f"{n}. {s[:_TEXT_CAP]}" for n, s in
                                                                 enumerate(steps, 1)) if steps else "")
    return " ".join(text.split())[:BRIEF_CAP]
