"""VER-042: the evidence reviewer sees cleared application screenshots, never other images, through every host."""

from __future__ import annotations

import json
import os
import struct
from types import SimpleNamespace

import pytest
from test_evidence_review import CLEAR, issue, pair, revision
from test_host_anthropic import _host as _anthropic_host
from test_host_anthropic import _msg
from test_hosts import (
    CLAUDE_INIT,
    ENV,
    _claude,
    _claude_result,
    _codex,
    _codex_events,
    _copilot,
    _ctx,
    _lines,
    _openai_response,
)

from appsec_verifier.agent.host_openai import OpenAIHost
from appsec_verifier.agent.hosts import HostCallError, HostPlanner, HostReply, png_base64
from appsec_verifier.tools.browser import ProofBrowser
from appsec_verifier.verify.evidence_review import MAX_REVIEW_IMAGES, review_finding
from appsec_verifier.verify.report import _poc_markdown
from appsec_verifier.verify.runner import _private_text


def png(width=640, height=400, tag=b""):
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", width, height) + tag


# ── hosts ─────────────────────────────────────────────────────────────────────

def test_anthropic_sends_images_as_base64_blocks_before_the_text():
    host, client = _anthropic_host([_msg(CLEAR), _msg(CLEAR)])
    host.call("system", "prompt", 10, _ctx().budget, images=(png(),))
    content = client.calls[-1]["messages"][0]["content"]
    assert [b["type"] for b in content] == ["image", "text"]
    assert content[0]["source"] == {"type": "base64", "media_type": "image/png", "data": png_base64(png())}
    host.call("system", "prompt", 10, _ctx().budget)
    assert client.calls[-1]["messages"][0]["content"] == "prompt"


def test_openai_sends_images_as_input_images():
    sent = []

    def post(url, headers, body, timeout):
        sent.append(body)
        return 200, _openai_response(CLEAR)

    host = OpenAIHost.resolve(model=None, environ=ENV, post=post)
    host.call("system", "prompt", 10, _ctx().budget, images=(png(),))
    content = sent[0]["input"][0]["content"]
    assert content[0] == {"type": "input_text", "text": "prompt"}
    assert content[1]["image_url"] == "data:image/png;base64," + png_base64(png())


def test_claude_cli_sends_images_in_one_stream_json_user_message():
    host, run = _claude([_lines(CLAUDE_INIT, _claude_result(CLEAR)), _lines(CLAUDE_INIT, _claude_result(CLEAR))])
    host.call("system", "prompt", 10, _ctx().budget, images=(png(),))
    argv, message = run.calls[0]["argv"], json.loads(run.calls[0]["input"])
    assert argv[argv.index("--input-format") + 1] == "stream-json"
    assert "--tools" in argv and argv[argv.index("--tools") + 1] == ""      # confinement unchanged
    assert message["type"] == "user" and [b["type"] for b in message["message"]["content"]] == ["image", "text"]
    host.call("system", "prompt", 10, _ctx().budget)
    assert "--input-format" not in run.calls[1]["argv"] and run.calls[1]["input"] == "prompt"


def test_codex_cli_attaches_image_files_from_its_empty_directory_before_the_prompt():
    seen = {}

    def inspect(argv, cwd):
        images = [a.split("=", 1)[1] for a in argv if a.startswith("--image=")]
        seen["images"] = [(os.path.dirname(p) == cwd, open(p, "rb").read()) for p in images]
        seen["last"] = argv[-1]

    msg = {"type": "agent_message", "text": json.dumps(CLEAR)}
    host, _ = _codex([_codex_events(msg)], inspect)
    host.call("system", "prompt", 10, _ctx().budget, images=(png(), png(tag=b"2")))
    assert seen["images"] == [(True, png()), (True, png(tag=b"2"))] and seen["last"] == "-"
    assert host.supports_images is False       # only a CLI whose `exec --help` lists --image gets images


def test_copilot_cli_attaches_image_files():
    host, run = _copilot([json.dumps(CLEAR)])
    host.call("system", "prompt", 10, _ctx().budget, images=(png(),))
    argv = run.calls[0]["argv"]
    path = argv[argv.index("--attachment") + 1]
    assert os.path.dirname(path) == run.calls[0]["cwd"] and path.endswith(".png")


def test_only_pngs_are_attached():
    with pytest.raises(ValueError):
        png_base64(b"GIF89a")


class ImageHost:
    label, broken, supports_images = "offline fake", None, True

    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def call(self, system, prompt, timeout, budget, *, schema=None, images=()):
        self.calls.append({"payload": json.loads(prompt), "images": list(images)})
        reply = self.replies.pop(0)
        return reply if isinstance(reply, HostReply) else HostReply(step=reply, usd=0.01)


def test_a_host_without_images_never_gets_them_and_a_refusing_host_gets_text_only_afterwards():
    host = ImageHost([HostReply(error="invalid_request"), CLEAR])
    planner, ctx = HostPlanner(host), pair([])[0]
    with pytest.raises(HostCallError):
        planner.structured(ctx, "s", "{}", {}, images=(png(),))
    assert host.calls[0]["images"] == [png()] and planner.supports_images is False
    planner.structured(ctx, "s", "{}", {}, images=(png(),))
    assert host.calls[1]["images"] == []
    plain = SimpleNamespace(label="x", broken=None, call=lambda *a, **k: pytest.fail("no images expected"))
    assert HostPlanner(plain).supports_images is False


# ── reviewer ──────────────────────────────────────────────────────────────────

def _review(tmp_path, replies, evidence, *, recapture=None):
    ctx, res, *_ = pair([])
    host = ImageHost(replies)
    ctx.evidence_test_planner = HostPlanner(host)
    ctx.evidence_reviewer_factory = lambda: HostPlanner(host)
    ctx.evidence_dir = tmp_path / "evidence"
    ctx.evidence_dir.mkdir()
    ctx.recapture = recapture
    for name, data in evidence.items():
        (ctx.evidence_dir / name).write_bytes(data)
    return ctx, res, host


def shot(name, **extra):
    return {"kind": "screenshot", "path": f"evidence/{name}", **extra}


def test_only_cleared_application_screenshots_reach_the_model_and_the_report_names_them(tmp_path):
    ctx, res, host = _review(tmp_path, [CLEAR], {"app.png": png(), "secret.png": png(tag=b"s"),
                                                 "exchange.png": png(tag=b"x")})
    res.evidence = [shot("app.png", presentation="application", reviewable=True),
                    shot("secret.png", presentation="application", reviewable=False),
                    shot("exchange.png", reviewable=True)]           # an HTTP image is never sent
    review_finding([(ctx, res)])
    assert host.calls[0]["images"] == [png()]
    images = host.calls[0]["payload"]["variants"][0]["images"]
    assert [i["sent_to_model"] for i in images] == [True, False, False]
    assert images[0]["image_index"] == 1 and "image_index" not in images[1]
    review = res.evidence_review
    assert review["visual_review"] == "performed" and review["images_reviewed"] == ["evidence/app.png"]
    assert "1 screenshot reviewed" in review["reason"]
    assert "Screenshots a model reviewed: `evidence/app.png`." in "\n".join(_poc_markdown({"evidence_review": review}))


def test_at_most_three_screenshots_per_review_call(tmp_path):
    names = [f"a{n}.png" for n in range(5)]
    ctx, res, host = _review(tmp_path, [CLEAR], {n: png(tag=n.encode()) for n in names})
    res.evidence = [shot(n, presentation="application", reviewable=True) for n in names]
    review_finding([(ctx, res)])
    assert len(host.calls[0]["images"]) == MAX_REVIEW_IMAGES == 3


def test_a_symlinked_or_foreign_screenshot_is_never_read(tmp_path):
    ctx, res, host = _review(tmp_path, [CLEAR], {})
    outside = tmp_path / "outside.png"
    outside.write_bytes(png())
    (ctx.evidence_dir / "link.png").symlink_to(outside)
    res.evidence = [shot("link.png", presentation="application", reviewable=True),
                    {"kind": "screenshot", "path": "../outside.png", "presentation": "application",
                     "reviewable": True}]
    review_finding([(ctx, res)])
    assert host.calls[0]["images"] == [] and res.evidence_review["visual_review"] == "not-performed"


def test_an_unclear_screenshot_can_be_replaced_by_another_page_once_per_round(tmp_path):
    proposals = []

    def recapture(proposal):
        proposals.append(proposal)
        (ctx.evidence_dir / "better.png").write_bytes(png(tag=b"better"))
        res.evidence[:] = [shot("better.png", presentation="application", reviewable=True)]
        return True

    page = {"path": "/#/basket", "step": 1, "values": ["bob@shop.test"], "role": None}
    ctx, res, host = _review(tmp_path, [issue("screenshot", detail="The marked value is too small to read."),
                                        {**revision(), "page": page}, CLEAR], {"app.png": png()},
                             recapture=recapture)
    res.evidence = [shot("app.png", presentation="application", reviewable=True)]
    review_finding([(ctx, res)])
    assert proposals == [{"path": "/#/basket", "step": 1, "values": ["bob@shop.test"]}]
    assert host.calls[2]["images"] == [png(tag=b"better")]
    assert res.evidence_review["status"] == "clear"
    assert res.evidence_review["images_reviewed"] == ["evidence/app.png", "evidence/better.png"]


def test_a_page_without_a_screenshot_issue_opens_nothing(tmp_path):
    ctx, res, host = _review(tmp_path, [issue("comparison"), {**revision(), "page": {
        "path": "/#/x", "step": 1, "values": ["bob@shop.test"], "role": None}}, CLEAR], {},
        recapture=lambda proposal: pytest.fail("no page expected"))
    review_finding([(ctx, res)])
    assert res.evidence_review["status"] == "clear"


# ── clearing a screenshot when it is taken ────────────────────────────────────

@pytest.mark.parametrize("check, marked, texts, expected", [
    (None, {"text": "page"}, (), False),                                   # no check set: fails closed
    (lambda t: False, {"text": "page"}, ("url",), True),
    (lambda t: "s3cret" in t, {"text": "hello s3cret"}, (), False),
    (lambda t: "s3cret" in t, {"text": "page"}, ("caption s3cret",), False),
    (lambda t: False, {"text": None}, (), False),                          # page text unknown
    (lambda t: False, None, (), False),
    (lambda t: 1 / 0, {"text": "page"}, (), False),                        # a failing check clears nothing
])
def test_a_screenshot_is_cleared_only_when_no_text_on_it_holds_a_secret(tmp_path, check, marked, texts, expected):
    browser = ProofBrowser(None, tmp_path)
    browser.private_text = check
    assert browser._reviewable(marked, *texts) is expected


def test_the_run_check_finds_credential_values_and_marker_file_content():
    sessions = SimpleNamespace(redact=lambda text: text.replace("tok-123", "[redacted]"))
    check = _private_text(sessions, {"marker_file": {"content": "marker-file-content-42"}})
    assert check("Welcome bob") is False
    assert check("token tok-123") is True and check("x marker-file-content-42 y") is True
    assert _private_text(None, {})("anything") is False
