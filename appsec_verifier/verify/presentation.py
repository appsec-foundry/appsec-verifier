"""The test agent's presentation of its proof of concept (VER-059, VER-035, VER-042).

After its verdict the test agent receives the redacted request and an answer excerpt of each step the verdict rests
on (`repair_context`) and composes how a reader sees the proof: the recorded steps in the order a reader should
follow, each as normal request, attack, outcome or control with a plain label and, where the answer shows it, an
excerpt of that answer; up to three labelled marks; and one sentence on what the attacker sent and obtained, or, for
any other verdict, what the steps show and what is missing. `check` enforces only what keeps the image true: an
excerpt or mark that is not an exact quote from the redacted record (whitespace aside), an excerpt of an answer
withheld from the model (VER-049, VER-053) or not kept (VER-057), and an outcome of a verdict other than confirmed
are left out and named; texts too long are shortened, and the steps the verdict rests on that the presentation does
not show are named. poc.py shows its own presentation instead, with the reason, only when there is none, none
readable as steps with their roles, or none of those steps remains in it. `document` renders a presentation from
the record: every value is escaped, the page has no script, and nothing is sent to the target. `present` renders it
again after an evidence review (VER-042).
"""

from __future__ import annotations

import copy
import html
import json
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote, unquote_plus

# The model is offered this schema with submit_verdict (agent/steps._offered_schema); the verdict itself accepts any
# object there, so a faulty presentation never costs the verdict, and `check` takes what it can of any value. It
# lives here, not in agent/prompts.py, because nothing of agent/ may be imported while this module loads
# (agent.prompts imports verify through agent.proof).
PRESENTATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "steps"],
    "properties": {
        "summary": {"type": "string", "minLength": 10, "maxLength": 400},
        "steps": {
            "type": "array", "minItems": 1, "maxItems": 24,
            "description": "Each step number once; each row shows both its request and response.",
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
    "Your proof of concept as a reader who does not know this test sees it (VER-059). After a verdict that cites "
    "steps you get their recorded_evidence (presentation_request); then submit the same verdict with presentation, "
    "or with remaining_decisions 1 at once. Show what the finding says an attacker gains, not the test's mechanics. "
    "steps: proof steps in reading order, role normal (the application without the attack), attack, outcome (what "
    "the attacker obtained; confirmed only) or control (rules out a coincidence); label: what the step is and what "
    "happened, in plain words; excerpt: the part of its answer body or recorded header that shows it, verbatim from "
    "recorded_evidence, at most 12 lines, omitted where the status tells it or the answer was withheld. marks: "
    "verbatim quotes from a URL-decoded request, displayed response header or an excerpt, labelled with why they "
    "matter. summary: confirmed, what the attacker sent and obtained; otherwise what the steps show and what is "
    "missing. A different page or text alone is no exploit. A quote not in the record is left out."
)

MAX_EXCERPT_LINES = 12
MAX_MARKS = 3
MAX_ROWS = 24
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
    # Header excerpts include their field names; a bare header value must not look like response-body evidence.
    header_lines = [_norm(line) for line in response_head(e).splitlines()]
    quoted_lines = [_norm(line) for line in excerpt.strip().splitlines()]
    header_quote = any(header_lines[i:i + len(quoted_lines)] == quoted_lines for i in range(len(header_lines)))
    if quote in _norm(text) or header_quote:
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


def response_head(e: dict) -> str:
    """The recorded, already redacted response status and headers; never reconstructed model text."""
    res = e["response"]
    return "\n".join([f"HTTP/1.1 {res['status']} {res['statusText']}".rstrip(),
                      *(f"{h['name']}: {h['value']}" for h in res.get("headers", []))])


def _answer(e: dict, excerpt: str, hidden: bool) -> str:
    res = e["response"]
    head = f"HTTP/1.1 {res['status']} {res['statusText']}".rstrip()
    if hidden:
        note = res["content"].get("_omitted") or "answer withheld from models; kept for the operator in the HAR file"
        return head + f"\n\n[{note}]"
    # These protocol properties can decide a proof without a response body. Do not duplicate an exact quote.
    headers = [f"{h['name']}: {h['value']}" for h in res.get("headers", [])
               if h["name"].lower() in ("location", "content-type", "www-authenticate")]
    head = "\n".join([head, *(line for line in headers if line not in excerpt)])
    return head + ("\n\n" + excerpt if excerpt else "")


def _hidden(e: dict, n: int, withheld: set[int]) -> bool:
    """Whether no model has read step `n`'s answer: withheld (VER-049, VER-053) or not kept (VER-057)."""
    return n in withheld or bool(e["response"]["content"].get("_omitted"))


class Checked(NamedTuple):
    """What `check` makes of a presentation (VER-059)."""

    shown: dict | None              # what the Verifier renders, with "left_out" and "not_shown"; None: its own
    why: str | None                 # why it shows its own presentation instead
    left_out: tuple[str, ...] = ()  # what it left out, in words; one correction may restore it


def _short(text: str, limit: int) -> str:
    """A model's own words cut to `limit` characters, marked as cut."""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def check(history: list[dict], steps: list[dict], verdict: str, decisive: set[int], presentation) -> Checked:
    """What the Verifier renders of a presentation (VER-059). It enforces only what keeps the image true and takes
    the rest as the test agent composed it: an excerpt or mark that is not an exact quote from the redacted record,
    an excerpt of an answer no model read, a row that is no recorded request or repeats one, a mark beyond the first
    three or on a step not shown, and an outcome of a verdict other than confirmed (then shown as an attack) are left
    out and named; texts too long are shortened, a quote only at its end. It shows its own presentation instead only
    when there is none, none readable as steps with their roles, or none of the steps the verdict rests on
    (`decisive`) remains in it. What it names holds step numbers and positions, never the model's text."""
    from .poc import _shown_entry, withheld_steps

    if presentation is None:
        return Checked(None, "the test agent composed no presentation")
    items = presentation.get("steps") if isinstance(presentation, dict) else None
    if not isinstance(items, list):
        return Checked(None, "its presentation cannot be read as steps with their roles")
    recorded = {s["step"]: e for s in steps if (e := _shown_entry(s)) is not None}
    withheld = withheld_steps(history)
    left: list[str] = []
    rows: list[dict] = []
    readable = False
    for item in items[:MAX_ROWS]:
        n, role = (item.get("step"), item.get("role")) if isinstance(item, dict) else (None, None)
        if type(n) is not int or role not in TITLES:
            left.append("an entry without a step number and a known role")
            continue
        readable = True
        e = recorded.get(n)
        if e is None:
            left.append(f"step {n}, which is not a recorded request")
            continue
        if any(row["step"] == n for row in rows):
            left.append(f"the second entry of step {n}")
            continue
        if role == "outcome" and verdict != "confirmed":
            left.append(f"the outcome role of step {n}, since the verdict is {verdict}; shown as an attack")
            role = "attack"
        label = item.get("label")
        row = {"step": n, "role": role,
               "label": _short(label, 120) if isinstance(label, str) and label.strip() else TITLES[role]}
        excerpt = item.get("excerpt")
        if isinstance(excerpt, str) and excerpt.strip():
            excerpt = "\n".join(excerpt.splitlines()[:MAX_EXCERPT_LINES])[:600]
            if _hidden(e, n, withheld):
                left.append(f"the excerpt of step {n}, whose answer is withheld or not kept")
            elif not _verbatim(excerpt, e):
                left.append(f"the excerpt of step {n}, which is not an exact quote from its recorded answer")
            else:
                row["excerpt"] = excerpt
        rows.append(row)
    if len(items) > MAX_ROWS:
        left.append(f"the entries after the first {MAX_ROWS}")
    if not readable:
        return Checked(None, "its presentation cannot be read as steps with their roles", tuple(left))
    if not any(row["step"] in decisive for row in rows):
        return Checked(None, "none of the steps the verdict rests on remains in its presentation", tuple(left))
    shown = {row["step"]: row for row in rows}
    marks: list[dict] = []
    given = presentation.get("marks")
    for i, mark in enumerate(given if isinstance(given, list) else [], 1):
        if len(marks) == MAX_MARKS:
            left.append(f"the marks after the first {MAX_MARKS}")
            break
        if not (isinstance(mark, dict) and type(mark.get("step")) is int and mark.get("part") in ("request", "response")
                and isinstance(mark.get("text"), str) and mark["text"]):
            left.append(f"mark {i}, which lacks its step, part or text")
            continue
        n, text, label = mark["step"], mark["text"][:200], mark.get("label")
        row = shown.get(n)
        if row is None:
            left.append(f"mark {i}, on step {n}, which the presentation does not show")
            continue
        e = recorded[n]
        if mark["part"] == "request":
            where, part = request_text(e), "URL-decoded request"
        else:
            where = (response_head(e).split("\n", 1)[0] if _hidden(e, n, withheld)
                     else _answer(e, row.get("excerpt") or "", False))
            part = "answer shown"
        if text not in where:
            left.append(f"mark {i}, which is not in the {part} of step {n}")
            continue
        marks.append({"step": n, "part": mark["part"], "text": text,
                      "label": _short(label, 80) if isinstance(label, str) and label.strip() else "marked"})
    summary = presentation.get("summary")
    if not (isinstance(summary, str) and summary.strip()):
        left.append("its summary sentence")
        summary = ""
    left = list(dict.fromkeys(left))
    return Checked({"summary": _short(summary, 400), "steps": rows, "marks": marks, "left_out": left,
                    "not_shown": sorted(n for n in decisive if n not in shown)}, None, tuple(left))


def assess(ctx, history: list[dict], steps: list[dict], result, cited, presentation) -> Checked:
    """`check` for a finished result: its verdict, the requests among the steps its verdict rests on
    (poc.decisive_steps; a cited source read or plan shows nothing) under the plan they ran under, and the
    presentation redacted as every model text is (VER-016)."""
    from ..agent.experiments import plan_view
    from .poc import _shown_entry, decisive_steps

    cited = (result.proof or {}).get("steps") or cited
    view = plan_view(history, cited)
    requests = {s["step"] for s in steps if _shown_entry(s) is not None}
    decisive = set(decisive_steps(ctx, view, result.verdict, cited)) & requests
    if not decisive:
        return Checked(None, "the verdict cites no step")
    sessions = getattr(ctx, "sessions", None)
    if sessions is not None and presentation is not None:
        presentation = sessions.redact(presentation)
    return check(view, steps, result.verdict, decisive, presentation)


def repair_context(ctx, history: list[dict], steps: list[dict], result, cited) -> dict:
    """The redacted record the test agent composes its presentation from, after its verdict and for a correction
    (VER-059): exact evidence it cannot obtain through another tool call.

    No decorated UI excerpts or synthetic comparison text is quotable. Withheld or omitted responses stay
    withheld, and request values and bodies are masked before taking bounded windows.
    """
    from ..agent.experiments import latest_plan, plan_view
    from ..agent.technical_review import clean
    from .poc import _focus, _shown_entry, _text, decisive_steps, withheld_steps

    cited = (result.proof or {}).get("steps") or cited
    view = plan_view(history, cited)
    decisive = set(decisive_steps(ctx, view, result.verdict, cited))
    withheld = withheld_steps(view)
    observation = clean(ctx, latest_plan(view)[1].get("text"))
    entries = [(s["step"], clean(ctx, e)) for s in steps
               if (e := _shown_entry(s)) is not None and s["step"] in decisive]
    recorded = []
    for n, e in entries[:24]:
        item = {"step": n, "request": request_text(e)[:1500]}
        if _hidden(e, n, withheld):
            item["response_withheld"] = True
        else:
            body = _text(e)
            focus = (body.index(observation) if isinstance(observation, str) and observation and observation in body
                     else _focus(ctx, [entry for _, entry in entries], e))
            start = max(0, min(focus - 150, len(body) - 600))
            item.update(response_head=response_head(e)[:1500], body_excerpt=body[start:start + 600])
        recorded.append(item)
    # Exchanges were redacted on capture; apply the shared model redactor as well, including marker-file content.
    return clean(ctx, {"required_steps": [n for n, _ in entries], "recorded_evidence": recorded})


def _step(ctx, history, n: int, e: dict, item: dict, marks: list[dict], withheld: set[int]):
    """What one step shows: its request and answer texts, their marks as (label, text), and the Verifier's own
    observation where the proof reads one from the step (poc._proof_observation)."""
    from .poc import _proof_observation

    answer = _answer(e, item.get("excerpt") or "", _hidden(e, n, withheld))
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
    """A presentation `check` returned as one HTML page for its screenshot and the number of marks: the code's verdict
    and proof check, the agent's sentence labelled as its own, what the Verifier left out and the steps the verdict
    rests on that the page does not show, then each step in its order."""
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
    left_out, not_shown = presentation.get("left_out") or [], presentation.get("not_shown") or []
    lines = [f"<b>{html.escape(' · '.join(filter(None, (str(ctx.plan.id), cls, title, verdict))))}</b>",
             *([f"<span class=s><span class=k>{lead}:</span> {html.escape(presentation['summary'])} "
                "<small>(the test agent's words)</small></span>"] if presentation.get("summary") else []),
             f"<span class=k>Proof check:</span> {html.escape(checked)}",
             *([f"<small>Left out by the Verifier: {html.escape('; '.join(left_out))}.</small>"] if left_out else []),
             *([f"<small>Also part of the proof, not shown here: step{'s' if len(not_shown) > 1 else ''} "
                f"{', '.join(map(str, not_shown))} (in the report and the HAR file).</small>"] if not_shown else []),
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


def saved(shown: dict) -> dict:
    """What verification.yaml keeps of a presentation of the test agent the Verifier rendered (VER-059)."""
    return {"composed_by": "test-agent", "summary": shown["summary"],
            **({"left_out": shown["left_out"]} if shown["left_out"] else {}),
            **({"not_shown": shown["not_shown"]} if shown["not_shown"] else {})}


def present(ctx, history: list[dict], steps: list[dict], result, cited, presentation) -> str | None:
    """A revised presentation after an evidence review (VER-042): rendered in place of the finding's HTTP images and
    report excerpts unless `assess` shows the Verifier's own instead. Returns None when it is used, else why not;
    then nothing changes."""
    from ..agent.experiments import plan_view
    from .poc import verifier_rows

    accepted, why, _ = assess(ctx, history, steps, result, cited, normalized(presentation))
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
    poc["shown"] = shown_steps(ctx, view, steps, accepted, poc.get("file")) + verifier_rows(
        ctx, view, steps, set(accepted["not_shown"]), poc.get("file"), composed=True)
    poc["presentation"] = saved(accepted)
    result.poc = poc
    result.observations[:] = [o for o in result.observations if not o.startswith(COMPOSED_NOTE)]
    return None
