"""A session pasted from the operator's browser, and hidden input (VER-016, VER-031).

`session_from_curl` reads a request the operator copied with "Copy as cURL" in
the browser's developer tools. The text is split like a shell would, but never
run. Only its URL, method, Cookie and Authorization are kept; everything else
(other headers, the body) is discarded and never logged. The URL must be on the
identity's origin, so a request copied from another site is refused.

`ask_hidden` reads one value without echo; `ask_hidden_block` reads a pasted
multi-line command without echo until a line that does not end with a
backslash. It switches the terminal to non-canonical mode, because the
canonical line buffer holds only 4096 characters and a copied Cookie line is
often longer. Neither keeps what was typed anywhere but in the returned string.
"""

from __future__ import annotations

import getpass
import os
import shlex

from ..tools import same_origin
from .sessions import header_problem

MAX_PASTE_BYTES = 256 * 1024
_VALUE_FLAGS = {
    "-A", "--user-agent", "-e", "--referer", "-o", "--output", "-u", "--user", "-x", "--proxy", "--connect-to",
    "--resolve", "-m", "--max-time", "--connect-timeout", "-w", "--write-out", "--cert", "--key", "--cacert",
    "-E", "-T", "--upload-file", "--data-urlencode",
}
_DATA_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "-F", "--form", "--json"}


class PasteError(ValueError):
    """The pasted text is not a usable copied request. The message never holds its content."""


def session_from_curl(text: str, origin: str) -> tuple[dict, str, str]:
    """(headers, method, url) of a copied cURL request to `origin`: only Cookie and Authorization."""
    if len(text.encode("utf-8", "replace")) > MAX_PASTE_BYTES:
        raise PasteError(f"the pasted text is longer than {MAX_PASTE_BYTES // 1024} KiB")
    joined = _ansi_c_quotes(text.replace("\\\r\n", " ").replace("\\\n", " "))
    try:
        tokens = shlex.split(joined, posix=True)
    except ValueError:
        raise PasteError("the pasted text is not a complete cURL command (unbalanced quotes)") from None
    if not tokens or os.path.basename(tokens[0]).lower() not in ("curl", "curl.exe"):
        raise PasteError("the pasted text does not start with curl; copy the request with 'Copy as cURL (bash)'")
    url, method, has_data = None, None, False
    cookies, authorization = [], None
    i = 1
    while i < len(tokens):
        token = tokens[i]
        value = tokens[i + 1] if i + 1 < len(tokens) else None
        if token in ("-H", "--header") and value is not None:
            name, sep, content = value.partition(":")
            if sep and name.strip().lower() == "cookie":
                cookies.append(content.strip())
            elif sep and name.strip().lower() == "authorization":
                authorization = content.strip()
            i += 2
        elif token in ("-b", "--cookie") and value is not None:
            if "=" not in value:
                raise PasteError("the copied request reads its cookies from a file; copy it again from the browser")
            cookies.append(value.strip())
            i += 2
        elif token in ("-X", "--request") and value is not None:
            method = value.upper()
            i += 2
        elif token == "--url" and value is not None:
            url = value
            i += 2
        elif token in _DATA_FLAGS:
            has_data = True
            i += 2
        elif token in _VALUE_FLAGS:
            i += 2
        elif not token.startswith("-") and url is None:
            url = token
            i += 1
        else:
            i += 1
    if not url or not url.lower().startswith(("http://", "https://")):
        raise PasteError("the pasted command names no http(s) URL")
    if not same_origin(url, origin):
        raise PasteError(f"the copied request goes to another site, not to {origin}")
    headers = {}
    if cookies:
        headers["Cookie"] = "; ".join(c for c in cookies if c)
    if authorization:
        headers["Authorization"] = authorization
    if not headers:
        raise PasteError("the copied request carries neither a Cookie nor an Authorization header; copy a "
                         "request the app sends after you have signed in")
    for name, value in headers.items():
        problem = header_problem(name, value)
        if problem:
            raise PasteError(problem)
    return headers, method or ("POST" if has_data else "GET"), url


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b",
            "e": "\x1b", "f": "\f", "v": "\v", "?": "?"}


def _ansi_c_quotes(text: str) -> str:
    """`text` with each bash `$'...'` string, which 'Copy as cURL (bash)' writes for values with quotes or
    special characters, rewritten as a plain quoted string shlex can read. Escapes are decoded, so an
    encoded line break becomes a real one, which the header check then refuses."""
    out, i, quote = [], 0, None
    while i < len(text):
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"' and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "\\" and i + 1 < len(text):
            out.append(text[i:i + 2])
            i += 1
        elif text.startswith("$'", i):
            value, i = _decode_ansi_c(text, i + 2)
            out.append(shlex.quote(value))
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _decode_ansi_c(text: str, i: int) -> tuple[str, int]:
    value = []
    while i < len(text) and text[i] != "'":
        if text[i] == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in "xuU":
                width = {"x": 2, "u": 4, "U": 8}[nxt]
                digits = "".join(c for c in text[i + 2:i + 2 + width] if c in "0123456789abcdefABCDEF")
                if digits:
                    value.append(chr(int(digits, 16)))
                    i += 2 + len(digits)
                    continue
            value.append(_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
            continue
        value.append(text[i])
        i += 1
    if i >= len(text):
        raise PasteError("the pasted text is not a complete cURL command (unbalanced quotes)")
    return "".join(value), i + 1


def ask_hidden(prompt: str) -> str:
    """One value, typed or pasted without echo."""
    return getpass.getpass(prompt)


def ask_hidden_block(prompt: str, *, fd: int | None = None) -> str:
    """A pasted multi-line command, read without echo up to the first line that does not end with a
    backslash. Falls back to one hidden line where the terminal cannot be switched."""
    try:
        import termios
    except ImportError:
        return ask_hidden(prompt)
    own = fd is None
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY) if own else fd
    except OSError:
        return ask_hidden(prompt)
    try:
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] &= ~(termios.ECHO | termios.ICANON)       # ISIG stays: Ctrl-C still interrupts
        new[6][termios.VMIN], new[6][termios.VTIME] = 1, 0
        termios.tcsetattr(fd, termios.TCSADRAIN, new)    # TCSADRAIN, not TCSAFLUSH: keep what is already pasted
        os.write(fd, prompt.encode())                    # only now: what is pasted after the prompt is not echoed
        try:
            return _read_block(fd)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            os.write(fd, b"\n")
    finally:
        if own:
            os.close(fd)


def _read_block(fd: int) -> str:
    data = bytearray()
    while len(data) <= MAX_PASTE_BYTES:
        chunk = os.read(fd, 65536)
        if not chunk or b"\x04" in chunk:              # end of input, or Ctrl-D
            data += chunk.split(b"\x04", 1)[0]
            break
        data += chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        text = data.decode("utf-8", "replace")
        if text.endswith("\n") and not text.strip():    # Enter alone: nothing pasted
            return ""
        if text.endswith("\n") and not text.rstrip("\n").endswith("\\"):
            break
    return data.decode("utf-8", "replace").strip()
