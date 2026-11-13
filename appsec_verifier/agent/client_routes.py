"""Literal browser request declarations from recorded source (VER-008, VER-043).

This is a bounded recognizer, not a JavaScript interpreter. It reads fetch calls and XMLHttpRequest.open
calls with literal destinations and methods, constant prefixes and whole dynamic record segments. Unknown
expressions, computed options and ambiguous document bases stay unresolved. Relative URLs use a recorded
document that loads the evidenced script, never its source directory. The caller still checks the source
relationship, route family, scope and write permission.
"""

from __future__ import annotations

import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..tools.http import same_origin

_TOKEN = re.compile(
    r"(?P<skip>//[^\n]*|/\*[\s\S]*?\*/|/(?:\\.|[^/\n\\])+/[a-z]*)"
    r"|(?P<template>`(?:\\.|[^`\\])*`)"
    r"|(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
    r"|(?P<name>[A-Za-z_$][\w$]*)|(?P<punct>[^\s])")
_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}


def _literal(token):
    kind, value, _ = token
    return value[1:-1] if kind == "string" and "\\" not in value else None


def _arguments(tokens, opening):
    """Top-level argument groups and the closing token, or None for an incomplete/mismatched call."""
    stack, groups, start = [], [], opening + 1
    pairs = {")": "(", "]": "[", "}": "{"}
    for i in range(opening, min(len(tokens), opening + 2048)):
        kind, value, _ = tokens[i]
        if kind != "punct":
            continue
        if value in ("(", "[", "{"):
            stack.append(value)
        elif value in pairs:
            if not stack or stack.pop() != pairs[value]:
                return None
            if not stack:
                return [*groups, tokens[start:i]], i
        elif value == "," and len(stack) == 1:
            groups.append(tokens[start:i])
            start = i + 1
    return None


def _object(tokens):
    if not tokens or tokens[0][1] != "{" or tokens[-1][1] != "}":
        return None
    parsed = _arguments(tokens, 0)
    if parsed is None or parsed[1] != len(tokens) - 1:
        return None
    fields = {}
    for group in parsed[0]:
        if not group:
            continue
        key = _literal(group[0]) or (group[0][1] if group[0][0] == "name" else None)
        if key is None or key == "__proto__" or len(group) < 3 or group[1][1] != ":" or key in fields:
            return None
        fields[key] = group[2:]
    return fields


def _url(tokens, constants):
    """Resolve literals and immutable literal prefixes; dynamic values occupy whole path segments only."""
    if len(tokens) == 1 and tokens[0][0] == "template":
        value = tokens[0][1][1:-1]
        if "\\" in value:
            return None
        value = re.sub(r"\$\{([A-Za-z_]\w*)\}", r"{\1}", value)
        if "$" in value:
            return None
    else:
        parts = []
        for i, token in enumerate(tokens):
            if i % 2:
                if token[1] != "+":
                    return None
            else:
                literal = _literal(token)
                if literal is None and token[0] == "name":
                    literal = constants.get(token[1])
                    if literal is None and parts:
                        literal = "{" + token[1] + "}"
                if literal is None:
                    return None
                parts.append(literal)
        if not tokens or len(tokens) % 2 == 0:
            return None
        value = "".join(parts)
    if "{" in value or "}" in value:
        # Never infer a host, prefix, query expression or partial segment from a variable.
        parsed = urlsplit(value)
        if "{" in parsed.netloc or "{" in parsed.query or "{" in parsed.fragment:
            return None
        if not parsed.path.split("{", 1)[0].strip("/"):
            return None
        segments = parsed.path.split("/")
        if not segments or not any(s and "{" not in s for s in segments):
            return None
        if any(("{" in s or "}" in s) and not re.fullmatch(r"\{[A-Za-z_]\w*\}", s) for s in segments):
            return None
    return value


def declarations(text, start_line=1):
    """Recognized method, URL literal, input names and source line, at most 64 calls per source window."""
    tokens = [(m.lastgroup, m[0], m.start()) for m in _TOKEN.finditer(text[:64_000])]
    constants = {}
    bindings = Counter(t[1] for j, t in enumerate(tokens[:-1]) if tokens[j + 1][1] == "=")
    for i in range(len(tokens) - 4):
        if (tokens[i][1] == "const" and tokens[i + 1][0] == "name" and tokens[i + 2][1] == "="
                and tokens[i + 4][1] == ";" and (literal := _literal(tokens[i + 3])) is not None):
            name = tokens[i + 1][1]
            # Reject shadowing/ambiguous bindings, including declarations outside this source window.
            if bindings[name] == 1:
                constants[name] = literal
    xhr = {tokens[i][1] for i in range(len(tokens) - 4)
           if tokens[i][0] == "name" and [t[1] for t in tokens[i + 1:i + 5]] ==
           ["=", "new", "XMLHttpRequest", "("]}
    found = []
    for i, (kind, name, offset) in enumerate(tokens):
        fetch = kind == "name" and name == "fetch" and (i == 0 or tokens[i - 1][1] != ".")
        opened = (kind == "name" and name in xhr and [t[1] for t in tokens[i + 1:i + 4]] == [".", "open", "("])
        opening = i + (1 if fetch else 3)
        if not (fetch or opened) or opening >= len(tokens) or tokens[opening][1] != "(":
            continue
        parsed = _arguments(tokens, opening)
        if parsed is None:
            continue
        args, _ = parsed
        url_arg = 0 if fetch else 1
        if len(args) <= url_arg or (url := _url(args[url_arg], constants)) is None:
            continue
        inputs = [{"location": "query", "name": key} for key, _ in parse_qsl(urlsplit(url).query)]
        inputs += [{"location": "path", "name": key} for key in re.findall(r"\{(\w+)\}", url)]
        if fetch:
            if len(args) > 2:
                continue
            options = _object(args[1]) if len(args) == 2 else {}
            if options is None:
                continue
            method_value = options.get("method")
            method = _literal(method_value[0]) if method_value and len(method_value) == 1 else None
            if method_value is None:
                method = "GET"
            body = options.get("body", [])
            if [t[1] for t in body[:4]] == ["JSON", ".", "stringify", "("] and body[-1][1] == ")":
                fields = _object(body[4:-1])
                if fields is not None:
                    inputs += [{"location": "json", "name": key} for key in fields]
        else:
            method = _literal(args[0][0]) if len(args[0]) == 1 else None
        if method not in _METHODS or not url or any(c in url for c in "\\\r\n\x00"):
            continue
        found.append({"method": method, "literal": url, "inputs": inputs,
                      "source_line": start_line + text.count("\n", 0, offset)})
        if len(found) == 64:
            break
    return found


class _Document(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url, self.base, self.scripts = url, None, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and self.base is None and "href" in attrs:
            self.base = urljoin(self.url, attrs["href"])
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])


def document_bases(ctx, history, source_path, web_roots):
    """Recorded documents loading this source file at its web-root-relative path; ambiguous bases are refused."""
    parts = PurePosixPath(source_path).parts
    root = next((i for i, part in enumerate(parts[:-1]) if part in web_roots), None)
    expected = "/" + "/".join(parts[root + 1:] if root is not None else parts)
    bases = set()
    for n, h in enumerate(history, 1):
        if h.get("tool") != "http_request" or not 200 <= (h.get("result", {}).get("status") or 0) < 300:
            continue
        response = getattr(ctx, "responses", {}).get(n, {})
        if not response.get("complete"):
            continue
        path = h.get("args", {}).get("path", "")
        url = path if urlsplit(path).scheme else ctx.target_base.rstrip("/") + "/" + path.lstrip("/")
        parser = _Document(url)
        parser.feed(response.get("body", "")[:64_000])
        base = parser.base or url
        if not same_origin(base, ctx.target_base):
            continue
        if any(same_origin(urljoin(base, src), ctx.target_base) and urlsplit(urljoin(base, src)).path == expected
               for src in parser.scripts):
            bases.add(base)
    return bases


def candidates(ctx, history, path, text, start_line, web_roots):
    if PurePosixPath(path).suffix not in (".js", ".mjs", ".ts", ".jsx", ".tsx"):
        return []
    bases = document_bases(ctx, history, path, web_roots)
    found = []
    for declaration in declarations(text, start_line):
        literal = declaration["literal"]
        if urlsplit(literal).scheme or literal.startswith("/"):
            urls = {urljoin(ctx.target_base, literal)}
        else:
            urls = {urljoin(base, literal) for base in bases}
        if len(urls) != 1:
            continue
        url = next(iter(urls))
        if not same_origin(url, ctx.target_base) or not ctx.guard.authorize(url, "target").allowed:
            continue
        found.append({**declaration, "path": url, "source_file": path})
    return found
