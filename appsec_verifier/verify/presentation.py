"""The test agent's presentation of its proof of concept (VER-059, VER-035, VER-042).

With its verdict the test agent composes how a reader sees the proof: the recorded steps in the order a reader
should follow, each as normal request, attack, outcome or control with a plain label and, where the answer shows
it, an excerpt of that answer; up to three labelled marks; and one sentence on what the attacker sent and obtained,
or, for any other verdict, what the steps show and what is missing. The code decides whether it is used. `assess`
accepts it only if it matches PRESENTATION_SCHEMA, lists every step the proof check relied on, quotes every excerpt
verbatim from the redacted record (whitespace aside) and every mark from the request or excerpt it shows, quotes
nothing of an answer withheld from the model (VER-049, VER-053) or not kept (VER-057), and shows no step as outcome
unless the verdict is confirmed. Otherwise poc.py shows its own presentation and states the reason. `document`
renders an accepted presentation from the record: every value is escaped, the page has no script, and nothing is
sent to the target. `present` renders it again after an evidence review (VER-042).
"""

from __future__ import annotations

import copy
import html
import json
from pathlib import Path
from urllib.parse import unquote, unquote_plus

from jsonschema import Draft202012Validator

# The model is offered this schema with submit_verdict (agent/steps._offered_schema); the verdict itself accepts any
# object there, so a faulty presentation never costs the verdict. It lives here, not in agent/prompts.py, because
# nothing of agent/ may be imported while this module loads (agent.prompts imports verify through agent.proof).
PRESENTATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "steps"],
    "properties": {
        "summary": {"type": "string", "minLength": 10, "maxLength": 400},
        "steps": {
            "type": "array", "minItems": 1, "maxItems": 24,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["step", "role", "label"],
                "properties": {
                    "step": {"type": "integer", "minimum": 1},
                    "role": {"type": "string", "enum": ["normal", "attack", "outcome", "control"]},
                    "label": {"type": "string", "minLength": 3, "maxLength": 120},
                    "excerpt": {"type": "string", "minLength": 1, "maxLength": 600},
                },
            },
        },
        "marks": {
            "type": "array", "maxItems": 3,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["step", "part", "text", "label"],
                "properties": {
                    "step": {"type": "integer", "minimum": 1},
                    "part": {"type": "string", "enum": ["request", "response"]},
                    "text": {"type": "string", "minLength": 1, "maxLength": 200},
                    "label": {"type": "string", "minLength": 3, "maxLength": 80},
                },
            },
        },
    },
}
PRESENTATION_HELP = (
    "Your proof of concept as a reader who does not know this test sees it (VER-059). Ask what the finding says an "
    "attacker gains and show that, not the test's mechanics. steps: every proof step in reading order, role normal "
    "(the application without the attack), attack, outcome (what the attacker obtained; confirmed only) or control "
    "(rules out a coincidence); label: what the step is and what happened, in plain words; excerpt: the part of its "
    "answer that shows it, verbatim from a tool result, at most 12 lines, omitted where the status tells it or the "
    "answer was withheld. A request shows only its answer's start, an experiment or browser check none: read what "
    "you quote with read_response first. "
    "marks: verbatim quotes from a URL-decoded request or an excerpt, labelled with why they "
    "matter. summary: confirmed, what the attacker sent and obtained; otherwise what the steps show and what is "
    "missing. A different page or text alone is no exploit. Every quote and step is checked; a failed check shows "
    "the Verifier's own presentation instead."
)

_VALIDATOR = Draft202012Validator(PRESENTATION_SCHEMA)
_BOUNDS = ("maxLength", "minLength", "maxItems", "minItems", "minimum", "maximum")
MAX_EXCERPT_LINES = 12
_REQUEST_CHARS = 1500
TITLES = {"normal": "Normal request", "attack": "Attack", "outcome": "Outcome", "control": "Control"}
COMPOSED_NOTE = "HTTP evidence composed by the Verifier: "      # an observation, followed by the reason
_CSS = ("section.outcome{border:2px solid #e65100}.outcome h2{background:#fff3e0}.outcome .role{background:#e65100}"
        "header .s{font-size:18px}")

# The same presentation for a structured revision call (VER-042): a strict host needs every property required, so
# an excerpt may be null there instead of omitted; `normalized` drops the nulls again.
REVISION_PRESENTATION = copy.deepcopy(PRESENTATION_SCHEMA)
REVISION_PRESENTATION["required"] = ["summary", "steps", "marks"]
REVISION_PRESENTATION["properties"]["steps"]["items"]["required"] = ["step", "role", "label", "excerpt"]
REVISION_PRESENTATION["properties"]["steps"]["items"]["properties"]["excerpt"] = {
    "type": ["string", "null"], "minLength": 1, "maxLength": 600}


def normalized(presentation):
    """A revision's presentation in the form submit_verdict takes: no null excerpt."""
    if not isinstance(presentation, dict) or not isinstance(presentation.get("steps"), list):
        return presentation
    steps = [{k: v for k, v in s.items() if not (k == "excerpt" and v is None)} if isinstance(s, dict) else s
             for s in presentation["steps"]]
    return {**presentation, "steps": steps}


def _norm(text: str) -> str:
    return " ".join(text.split())


def request_text(e: dict) -> str:
    """A recorded request as a reader reads it: its line URL-decoded, a form body decoded, another body as sent."""
    from .poc import _target

    req = e["request"]
    path, _, query = _target(req["url"]).partition("?")
    line = f"{req['method']} {unquote(path)}{'?' + unquote_plus(query) if query else ''} HTTP/1.1"
    post = req.get("postData") or {}
    body = post.get("text") or ""
    if "x-www-form-urlencoded" in str(post.get("mimeType", "")).lower():
        body = unquote_plus(body)
    return line + ("\n\n" + body[:_REQUEST_CHARS] if body else "")


# Characters a derived form of an answer may show decoded (a page's &lt; as <, a JSON < as <): a quote that only
# a derived form holds must not contain them, or encoded output could be shown as if it were sent unencoded.
_DECODED = {"visible text": set("<>&\"'"), "JSON": set("<>&'")}


def _verbatim(excerpt: str, e: dict) -> bool:
    """Whether `excerpt` is part of the recorded answer, whitespace aside: as recorded, or in the visible text of a
    page or a JSON answer serialised as a tool result shows it, unless it holds a character those forms decode."""
    from .poc import MAX_BODY_CHARS, _text, _VisibleText

    text, quote = _text(e), _norm(excerpt)
    if quote in _norm(text):
        return True
    forms = []
    if "html" in str(e["response"]["content"].get("mimeType", "")).lower():
        parser = _VisibleText()
        parser.feed(text[:MAX_BODY_CHARS])
        forms.append(("visible text", " ".join(parser.parts)))
    try:
        forms.append(("JSON", json.dumps(json.loads(text), ensure_ascii=False)))
    except (ValueError, RecursionError):
        pass
    return any(quote in _norm(form) and not set(quote) & _DECODED[kind] for kind, form in forms)


def _hidden(e: dict, n: int, withheld: set[int]) -> bool:
    """Whether no model has read step `n`'s answer: withheld (VER-049, VER-053) or not kept (VER-057)."""
    return n in withheld or bool(e["response"]["content"].get("_omitted"))


def check(history: list[dict], steps: list[dict], verdict: str, decisive: set[int], presentation) -> tuple:
    """(the presentation, None) if the Verifier may render it, else (None, every reason, so one correction can fix
    them all). A schema error names where and which rule, never the model's text."""
    from .poc import _shown_entry, withheld_steps

    if presentation is None:
        return None, "the test agent composed no presentation"
    error = next(iter(sorted(_VALIDATOR.iter_errors(presentation), key=str)), None)
    if error is not None:
        where = "/".join(map(str, error.absolute_path)) or "its top level"
        # A size rule names its bound, so the next attempt can meet it; the bound is the schema's, not model text.
        bound = f" {error.validator_value}" if error.validator in _BOUNDS else ""
        return None, f"its presentation does not match the schema at {where} (rule {error.validator}{bound})"
    recorded = {s["step"]: e for s in steps if (e := _shown_entry(s)) is not None}
    withheld = withheld_steps(history)
    listed = [item["step"] for item in presentation["steps"]]
    problems = ["its presentation lists a step twice"] if len(set(listed)) != len(listed) else []
    for item in presentation["steps"]:
        n, e = item["step"], recorded.get(item["step"])
        excerpt = item.get("excerpt")
        if e is None:
            problems.append(f"step {n} is not a recorded request")
        elif item["role"] == "outcome" and verdict != "confirmed":
            problems.append(f"step {n} is shown as the outcome, but a verdict that is {verdict} claims no exploit")
        elif excerpt is None:
            continue
        elif _hidden(e, n, withheld):
            problems.append(f"the answer of step {n} is withheld or not kept, so it carries no excerpt")
        elif len(excerpt.splitlines()) > MAX_EXCERPT_LINES:
            problems.append(f"the excerpt of step {n} has more than {MAX_EXCERPT_LINES} lines")
        elif not _verbatim(excerpt, e):
            problems.append(f"the excerpt of step {n} is not a verbatim part of its recorded answer")
    missing = [n for n in sorted(decisive) if n not in listed]
    if missing:
        problems.append(f"step{'s' if len(missing) > 1 else ''} {', '.join(map(str, missing))} the proof relies on "
                        f"{'are' if len(missing) > 1 else 'is'} not listed")
    excerpts = {item["step"]: item.get("excerpt") or "" for item in presentation["steps"]}
    for mark in presentation.get("marks", []):
        n = mark["step"]
        if n not in excerpts or n not in recorded:
            problems.append(f"a mark names step {n}, which the presentation does not list as a recorded request")
        elif mark["part"] == "request" and mark["text"] not in request_text(recorded[n]):
            problems.append(f"a mark is not in the URL-decoded request of step {n}")
        elif mark["part"] == "response" and mark["text"] not in excerpts[n]:
            problems.append(f"a mark on the answer of step {n} is not in the excerpt shown for it")
    return (None, "; ".join(dict.fromkeys(problems))) if problems else (presentation, None)


def assess(ctx, history: list[dict], steps: list[dict], result, cited, presentation) -> tuple:
    """`check` for a finished result: its verdict, the requests among the steps its proof check relied on
    (poc.decisive_steps; a cited source read or plan shows nothing) under the plan they ran under, and the
    presentation redacted as every model text is (VER-016)."""
    from ..agent.experiments import plan_view
    from .poc import _shown_entry, decisive_steps

    cited = (result.proof or {}).get("steps") or cited
    view = plan_view(history, cited)
    requests = {s["step"] for s in steps if _shown_entry(s) is not None}
    decisive = set(decisive_steps(ctx, view, result.verdict, cited)) & requests
    if not decisive:
        return None, "the verdict cites no step"
    sessions = getattr(ctx, "sessions", None)
    if sessions is not None and presentation is not None:
        presentation = sessions.redact(presentation)
    return check(view, steps, result.verdict, decisive, presentation)


def _step(ctx, history, n: int, e: dict, item: dict, marks: list[dict], withheld: set[int]):
    """What one step shows: its request and answer texts, their marks as (label, text), and the Verifier's own
    observation where the proof reads one from the step (poc._proof_observation)."""
    from .poc import _proof_observation

    res = e["response"]
    status = f"HTTP/1.1 {res['status']} {res['statusText']}".rstrip()
    if item.get("excerpt"):
        answer = status + "\n\n" + item["excerpt"]
    elif n in withheld:
        answer = status + "\n\n[answer withheld from models; kept for the operator in the HAR file]"
    elif res["content"].get("_omitted"):
        answer = status + f"\n\n[{res['content']['_omitted']}]"
    else:
        answer = status
    req_marks = [(m["label"], m["text"]) for m in marks if m["step"] == n and m["part"] == "request"]
    res_marks = [(m["label"], m["text"]) for m in marks if m["step"] == n and m["part"] == "response"]
    seen = _proof_observation(ctx, history, n, e)
    facts = [f"Verifier's observation: {_observation(history, seen)}"] if seen else []
    return request_text(e), answer, req_marks, res_marks, facts


def _observation(history: list[dict], seen: tuple) -> str:
    """What the proof check read from a step, in words; a text observation names the text it looked for (VER-055),
    so a reader can tell what 'present' and 'absent' refer to."""
    from ..agent.experiments import latest_plan
    from .poc import _OBSERVATIONS

    label = _OBSERVATIONS[seen[0]][2 if seen[1] else 3]
    text = latest_plan(history)[1].get("text") if seen[0] == "text_present" else None
    if not isinstance(text, str) or not text:
        return label
    text = " ".join(text.split())
    return f'{label}: "{text if len(text) <= 80 else text[:79] + "…"}"'


def report_steps(ctx, history: list[dict], steps: list[dict], presentation: dict) -> list[tuple[int, dict, dict]]:
    """The report's excerpt fields of each step in the presentation's order, as (step, entry, fields), ⟦…⟧ around
    each mark (VER-035)."""
    from .poc import _code_excerpt, _shown_entry, withheld_steps

    recorded = {s["step"]: _shown_entry(s) for s in steps}
    withheld, marks = withheld_steps(history), presentation.get("marks", [])
    out = []
    for item in presentation["steps"]:
        n = item["step"]
        e = recorded[n]
        request, answer, req_marks, res_marks, facts = _step(ctx, history, n, e, item, marks, withheld)
        labels = [f"⟦{text}⟧: {label}" for label, text in (*req_marks, *res_marks)]    # ⟦…⟧ keeps no label
        out.append((n, e, {"role": item["role"], "role_label": item["label"],
                           "request_excerpt": _code_excerpt(request, req_marks),
                           "response_excerpt": _code_excerpt(answer, res_marks), "facts": facts + labels}))
    return out


def document(ctx, history: list[dict], steps: list[dict], presentation: dict, result, har_path) -> tuple[str, int]:
    """The accepted presentation as one HTML page for its screenshot and the number of marks: the code's verdict
    and proof check, the agent's sentence labelled as its own, then each step in its order."""
    from ..planning import _TITLE_LOCATION
    from .poc import _EXCHANGE_CSS, _VERDICT_SENTENCE, _marked, _shown_entry, shown_time, withheld_steps
    from .probes import proof_shown

    recorded = {s["step"]: _shown_entry(s) for s in steps}
    withheld, marks = withheld_steps(history), presentation.get("marks", [])
    verdict, cls = result.verdict, getattr(ctx.plan, "cls", None) or "finding"
    title = _TITLE_LOCATION.sub("", str(getattr(ctx.plan, "title", "") or "")[:300])[:90]
    shown = (proof_shown(result.proof, cls) or (None,))[0] if verdict == "confirmed" else None
    checked = f"accepted: {shown}" if shown else _VERDICT_SENTENCE.get(verdict, "No completed proof.")
    lead = ("What the attacker did and obtained" if verdict == "confirmed"
            else "What the steps show and what is missing")
    first = recorded[presentation["steps"][0]["step"]]
    lines = [f"<b>{html.escape(' · '.join(filter(None, (str(ctx.plan.id), cls, title, verdict))))}</b>",
             f"<span class=s><span class=k>{lead}:</span> {html.escape(presentation['summary'])} "
             "<small>(the test agent's words)</small></span>",
             f"<span class=k>Proof check:</span> {html.escape(checked)}",
             f"<small>AppSec Verifier · steps, excerpts and marks chosen by the test agent and found in the record"
             f"{' in ' + html.escape(har_path) if har_path else ''} captured "
             f"{html.escape(shown_time(first.get('startedDateTime', '')))}; nothing sent again. Requests shown "
             "URL-decoded; yellow marks what a request sent, a red frame what an answer shows.</small>"]
    parts, total = [f"<header>{chr(10).join(lines)}</header>"], 0
    for item in presentation["steps"]:
        n, kind = item["step"], item["role"]
        e = recorded[n]
        request, answer, req_marks, res_marks, facts = _step(ctx, history, n, e, item, marks, withheld)
        req_html, a = _marked(request, req_marks, sent=True)
        res_html, b = _marked(answer, res_marks)
        total += a + b
        who = html.escape(e.get("_role") or "anonymous")
        heading = (f"<h2><span class=role>{html.escape(TITLES[kind])}</span>{html.escape(item['label'])} · Step {n} · "
                   f"{html.escape(e['request']['method'])} as {who} → {e['response']['status']} "
                   f"{html.escape(e['response']['statusText'])}</h2>")
        if "\n" not in answer and not (req_marks or res_marks or facts):
            # Only the status, which the heading names: the request alone, so a repeat takes one short block.
            parts.append(f"<section class={kind}>{heading}<pre>{req_html}</pre></section>")
            continue
        parts.append(f"<section class={kind}>{heading}"
                     + "".join(f"<div class=facts><b>{html.escape(f)}</b></div>" for f in facts)
                     + f"<div class=cols><div><h3>Request</h3><pre>{req_html}</pre></div>"
                     f"<div><h3>Response</h3><pre>{res_html}</pre></div></div></section>")
    page = (f"<!doctype html><html><head><meta charset=utf-8><style>{_EXCHANGE_CSS}{_CSS}</style></head>"
            f"<body>{''.join(parts)}</body></html>")
    return page, total


def screenshots(ctx, history: list[dict], steps: list[dict], presentation: dict, result, har_path) -> list[dict]:
    """The presentation's image (VER-035, VER-059). Its text joins the panels an evidence review reads; the image
    itself is cleared for the reviewer when that text holds no credential value and no marker-file content (VER-012,
    VER-016, VER-042), which a presentation built from the redacted record and quotes the model saw never does."""
    from ..planning import evidence_name
    from .poc import _VisibleText

    page, marked = document(ctx, history, steps, presentation, result, har_path)
    visible = _VisibleText()
    visible.feed(page)
    text = "\n".join(visible.parts)
    ctx.evidence_panels.append({"text": text[:8000], "body_font_px": 16})
    sessions = getattr(ctx, "sessions", None)
    marker = ((getattr(ctx, "scope", None) or {}).get("marker_file") or {}).get("content")
    reviewable = (sessions is None or sessions.redact(text) == text) and not (marker and marker in text)
    try:
        shots = ctx.browser.render_exchanges(html=page, name=evidence_name(ctx.plan), marked=marked)
    except Exception:  # noqa: BLE001 - a screenshot only illustrates; the verdict stands without it
        return []
    return [{**shot, "composed_by": "test-agent", "reviewable": reviewable} for shot in shots]


def _remove(ctx, ev: dict) -> None:
    """Delete one of our own replaced images under evidence/; never a path outside it or a link."""
    directory = getattr(ctx, "evidence_dir", None)
    relative = Path(str(ev.get("path", "")))
    if not directory or len(relative.parts) != 2 or relative.parts[0] != "evidence":
        return
    path = Path(directory).resolve() / relative.name
    if not path.is_symlink() and path.resolve().parent == Path(directory).resolve():
        path.unlink(missing_ok=True)


def shown_steps(ctx, history: list[dict], steps: list[dict], presentation: dict, har_path) -> list[dict]:
    """The report's shown steps (VER-034, VER-035) in the presentation's order: each step's raw request and answer,
    as the evidence review reads them, the answer around the step's excerpt, with the presentation's excerpts and
    labels."""
    from .poc import _focus, _raw_request, _raw_response, _text, withheld_steps

    withheld = withheld_steps(history)
    rows = report_steps(ctx, history, steps, presentation)
    entries = [e for _, e, _ in rows]
    out = []
    for item, (n, e, fields) in zip(presentation["steps"], rows, strict=True):
        at = _text(e).find(item["excerpt"]) if item.get("excerpt") else -1
        focus = at if at >= 0 else _focus(ctx, entries, e)
        out.append({"step": n, "request": _raw_request(e), "elapsed_ms": e.get("time"),
                    "response": _raw_response(e, focus, har_path), **fields,
                    **({"withheld": True} if n in withheld else {})})
    return out


def present(ctx, history: list[dict], steps: list[dict], result, cited, presentation) -> str | None:
    """A revised presentation after an evidence review (VER-042): rendered in place of the finding's HTTP images and
    report excerpts if `assess` accepts it. Returns None when it is used, else why not; then nothing changes."""
    from ..agent.experiments import plan_view

    accepted, why = assess(ctx, history, steps, result, cited, normalized(presentation))
    if accepted is None:
        return why
    view = plan_view(history, (result.proof or {}).get("steps") or cited)
    poc = result.poc or {}
    browser = getattr(ctx, "browser", None)
    if browser is not None and getattr(ctx.plan, "cls", None) in getattr(browser, "screenshots", ()):
        panels = list(ctx.evidence_panels)
        ctx.evidence_panels[:] = []
        shots = screenshots(ctx, view, steps, accepted, result, poc.get("file"))
        if not shots:
            ctx.evidence_panels[:] = panels
            return "its image could not be rendered"
        for ev in [e for e in result.evidence if e.get("composed_by")]:
            _remove(ctx, ev)
        result.evidence[:] = [e for e in result.evidence if not e.get("composed_by")] + shots
    poc["shown"] = shown_steps(ctx, view, steps, accepted, poc.get("file"))
    poc["presentation"] = {"composed_by": "test-agent", "summary": accepted["summary"]}
    result.poc = poc
    result.observations[:] = [o for o in result.observations if not o.startswith(COMPOSED_NOTE)]
    return None
