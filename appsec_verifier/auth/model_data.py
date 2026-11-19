"""Remove recognizable credential material from text intended for a model (VER-016, VER-050)."""

from __future__ import annotations

import re

_MASK = "[credential withheld]"
# Withhold the rest of an incomplete PEM block too, e.g. a source excerpt ending inside it.
_PRIVATE = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?(?:-----END \1-----|\Z)", re.S)
_TOKEN = re.compile(r"\b(?:gh[pousr]_[\w]{16,}|github_pat_[\w]{16,}|sk-(?:[\w-]{16,})|"
                    r"xox[baprs]-[\w-]{12,}|eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+)")
_URL_PASSWORD = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]{0,31}://[^@/\s:]*:)([^@/\s]+)(?=@)")
_HEADER = re.compile(r"(?i)\b(?:bearer|basic)[ \t]+[A-Za-z0-9/+=._~-]{8,}")
_FIELD = (r"(?:[\w-]{1,64}[_-])?(?:(?:client|db|user|session|signing|private|secret|access)[_-]?)?"
          r"(?:password|passwd|secret|api[_-]?key|access[_-]?key|access[_-]?token|"
          r"refresh[_-]?token|auth[_-]?token|token|credential)")
# Quoted assignments in source and JSON, and unquoted single-value environment assignments.
_ASSIGN = re.compile(rf"""(?im)(\b{_FIELD}\b["']?[ \t]*[:=][ \t]*)(["'])((?:\\.|(?!\2)[^\r\n\\])*)(\2|$)""")
_BARE = re.compile(rf"""(?i)(\b{_FIELD}\b\s*=\s*)([^\s,;&"'\[\]{{}}]+)""")
_YAML = re.compile(rf"(?im)^([ \t]*{_FIELD}[ \t]*:[ \t]*)(?![\x22\x27\[{{])([^\s#][^\r\n]*)$")
_BLOCK = re.compile(rf"(?im)^([ \t]*)({_FIELD}[ \t]*:[ \t]*)[|>][0-9+-]*[^\r\n]*"
                    r"(?:\r?\n(?:\1[ \t]+[^\r\n]*|[ \t]*(?=\r?$)))*")
_NUMBER = re.compile(rf"""(?i)(["']{_FIELD}["'][ \t]*:[ \t]*)(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)(?=\s*[,}}])""")
_FIELD_NAME = re.compile(_FIELD, re.I)
_COOKIE_HEADER = re.compile(r"(?im)^((?:set-cookie|cookie):[^\S\n]*)([^\r\n]+)")


def _mask_text(text, remember):
    """Remove recognizable values before excerpts are selected; retain line numbers."""
    text = _PRIVATE.sub(lambda m: _MASK + "\n" * m[0].count("\n"), text)
    text = _TOKEN.sub(_MASK, text)
    text = _URL_PASSWORD.sub(lambda m: m[1] + remember(m[2]), text)
    text = _HEADER.sub(lambda m: remember(m[0].split(None, 1)[1]), text)
    text = _COOKIE_HEADER.sub(lambda m: m[1] + _MASK, text)
    text = _BLOCK.sub(lambda m: m[1] + m[2] + _MASK + "\n" * m[0].count("\n"), text)
    text = _YAML.sub(lambda m: m[1] + remember(m[2]), text)
    text = _NUMBER.sub(lambda m: m[1] + '"' + remember(m[2]) + '"', text)

    def quoted(match):
        prefix, quote, value, closing = match.groups()
        return prefix + quote + remember(value) + closing if value else match[0]

    return _BARE.sub(lambda m: m[1] + remember(m[2]), _ASSIGN.sub(quoted, text))


def credential_text(text: str) -> str:
    return model_data(text)


def model_data(value, sessions=None, *, marker=None):
    """Clean every text field before JSON serialization, including credential-shaped mapping keys."""
    if sessions is not None:
        value = getattr(sessions, "redact_model", sessions.redact)(value)

    found = set()
    oversized = False

    def remember(raw):
        nonlocal oversized
        if isinstance(raw, str | int) and not isinstance(raw, bool):
            raw = str(raw)
            if raw and _MASK not in raw:
                if len(raw) > 4096 or (len(found) >= 64 and raw not in found):
                    oversized = True
                else:
                    found.add(raw)
        return _MASK

    def walk(item, clean_text, *, assignments):
        if isinstance(item, str):
            return clean_text(item)
        if isinstance(item, list | tuple):
            return [walk(v, clean_text, assignments=assignments) for v in item]
        if isinstance(item, dict):
            out = {}
            for key, v in item.items():
                if assignments and isinstance(key, str) and _FIELD_NAME.fullmatch(key) and v is not None:
                    v = v if isinstance(v, bool) else remember(v)
                else:
                    v = walk(v, clean_text, assignments=assignments)
                out[clean_text(key) if isinstance(key, str) else key] = v
            return out
        if not assignments and type(item) is int and (oversized or str(item) in found):
            return _MASK
        return item

    def clean_text(item):
        return _mask_text(item.replace(marker, "[marker-file]") if marker else item, remember)

    cleaned = walk(value, clean_text, assignments=True)
    if oversized:
        # Too many distinct credential values to check echoes within the input budget.
        return walk(cleaned, lambda _: _MASK, assignments=False)
    if found:
        # A short literal such as x can be a credential in its value position.
        # Mask its standalone echoes without rewriting every identifier containing that letter.
        echoes = re.compile("|".join(re.escape(v) if len(v) >= 4 else rf"(?<!\w){re.escape(v)}(?!\w)"
                                     for v in sorted(found, key=len, reverse=True)))
        return walk(cleaned, lambda s: echoes.sub(_MASK, s), assignments=False)
    return cleaned
