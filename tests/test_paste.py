"""A session pasted from the browser (VER-016, VER-031): a copied cURL request
is split, never run; only Cookie and Authorization of a request to the
identity's origin are kept. The hidden multi-line input reads a pasted command
without echo, also past the 4096-character line limit of a terminal."""

from __future__ import annotations

import os
import sys

import pytest

from appsec_verifier.auth.paste import PasteError, ask_hidden_block, session_from_curl

ORIGIN = "https://app.example.com"

CHROME = r"""curl 'https://app.example.com/rest/basket/6' \
  -H 'accept: application/json, text/plain, */*' \
  -H 'authorization: Bearer eyJhbGciOi.eyJzdWIi.sig' \
  -b 'language=en; token=eyJhbGciOi.eyJzdWIi.sig; continueCode=abc' \
  -H 'user-agent: Mozilla/5.0'"""
FIREFOX = """curl 'https://app.example.com/api/me' --compressed -H 'User-Agent: Mozilla/5.0' \\
  -H 'Cookie: JSESSIONID=1A2B3C4D' -H 'Sec-Fetch-Mode: cors'"""


def test_a_chrome_copy_keeps_only_cookie_and_authorization():
    headers, method, url = session_from_curl(CHROME, ORIGIN)
    assert headers == {"Cookie": "language=en; token=eyJhbGciOi.eyJzdWIi.sig; continueCode=abc",
                       "Authorization": "Bearer eyJhbGciOi.eyJzdWIi.sig"}
    assert (method, url) == ("GET", "https://app.example.com/rest/basket/6")


def test_a_firefox_copy_and_a_post_are_read():
    assert session_from_curl(FIREFOX, ORIGIN)[0] == {"Cookie": "JSESSIONID=1A2B3C4D"}
    post = "curl 'https://app.example.com/api/x' -H 'Cookie: s=1234' --data-raw '{\"a\":1}'"
    assert session_from_curl(post, ORIGIN)[1] == "POST"
    assert session_from_curl("curl -X PUT 'https://app.example.com/a' -b 's=1234'", ORIGIN)[1] == "PUT"


def test_ansi_c_quoting_is_read():
    text = "curl 'https://app.example.com/a' -b $'sid=1234; name=it\\'s; u=\\u00e9\\x21' -H \"Authorization: B x\""
    assert session_from_curl(text, ORIGIN)[0] == {"Cookie": "sid=1234; name=it's; u=\u00e9!",
                                                  "Authorization": "B x"}


@pytest.mark.parametrize("text, problem", [
    (CHROME.replace("app.example.com", "evil.example"), "another site"),
    (CHROME.replace("https://app.example.com", "http://app.example.com"), "another site"),
    ("wget https://app.example.com/", "does not start with curl"),
    ("curl 'https://app.example.com/a", "unbalanced quotes"),
    ("curl 'https://app.example.com/a' -b $'a=1", "unbalanced quotes"),
    ("curl 'https://app.example.com/a' -H 'accept: */*'", "neither a Cookie nor an Authorization"),
    ("curl 'https://app.example.com/a' -b cookies.txt", "from a file"),
    ("curl -H 'Cookie: a=1'", "names no http"),
    ("curl 'https://app.example.com/a' -H $'Cookie: a=1\\x0d\\x0aX-Evil: 1'", "control character"),
    ("curl 'https://app.example.com/a' -b $'a=1\\r\\nX-Evil: 1'", "control character"),
])
def test_unusable_pastes_are_refused_without_their_content(text, problem):
    with pytest.raises(PasteError, match=problem) as exc:
        session_from_curl(text, ORIGIN)
    assert "a=1" not in str(exc.value) and "eyJ" not in str(exc.value)


def test_a_paste_that_is_too_long_is_refused():
    with pytest.raises(PasteError, match="longer than"):
        session_from_curl("curl 'https://app.example.com/' -b 'a=" + "x" * 300_000 + "'", ORIGIN)


@pytest.mark.skipif(not sys.platform.startswith(("linux", "darwin")), reason="needs a pseudo-terminal")
def test_hidden_block_input_reads_a_long_multi_line_paste_without_echo():
    import pty

    master, slave = pty.openpty()
    try:
        long_cookie = "c=" + "x" * 6000                         # longer than a canonical terminal line
        pasted = f"curl 'https://app.example.com/a' \\\n  -b '{long_cookie}' \\\n  -H 'accept: */*'\n"
        import threading

        result = {}
        reader = threading.Thread(target=lambda: result.setdefault("text", ask_hidden_block("Paste: ", fd=slave)))
        reader.start()
        echoed = os.read(master, 100)                           # the prompt: echo is off from here on
        os.write(master, pasted.encode())
        reader.join(5)
        echoed += _drain(master)
        text, echoed = result["text"], echoed.decode()
    finally:
        os.close(master)
        os.close(slave)
    assert text == pasted.strip() and long_cookie in text
    assert echoed.startswith("Paste: ") and "x" * 20 not in echoed          # nothing pasted was echoed


def _drain(fd) -> bytes:
    import select

    data = b""
    while select.select([fd], [], [], 0.2)[0]:
        try:
            chunk = os.read(fd, 100_000)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


@pytest.mark.skipif(not sys.platform.startswith(("linux", "darwin")), reason="needs a pseudo-terminal")
def test_hidden_block_input_with_enter_alone_is_empty():
    import pty

    master, slave = pty.openpty()
    try:
        os.write(master, b"\n")
        assert ask_hidden_block("Paste: ", fd=slave) == ""
    finally:
        os.close(master)
        os.close(slave)
