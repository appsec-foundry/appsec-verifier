"""Evidence-backed request derivation inside a finding (VER-005, VER-008, VER-043, VER-056).

Source declarations and recorded links/forms supply candidates, never authority. A
source declaration is recognised by its form, not its framework: a route literal as
the first argument of a call or annotation that names an HTTP method or a routing
function, joined, where the model asks for it, to a route prefix declared above it
in the same file (a class-level mapping, a prefix argument, a route group). Its
inputs are names its handler's lines contain, or placeholders of its route. A
candidate must stay on the target origin and the original resource's route family;
derived routes cannot become anchors for exploring another resource. When the
assessment names no route, a route another file registers for a handler of the
finding's file can anchor one (`registration_routes`), but only through a literal
import of that file and a handler name the agent read in it. With a source
checkout the Verifier resolves such routes itself before the agent starts, by the
same rule applied to whole files (`source_registrations`). For a page script
without either, a page its file path names can supply it: the file itself, or a
form or link there that carries an input the file names (VER-056). Unknown
framework syntax or relationships stay unresolved. No request is sent here.
"""

from __future__ import annotations

import posixpath
import re
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..tools.http import SAFE_METHODS, same_origin
from ..verification_context import planned_route

MAX_DERIVED = 8
_PLACEHOLDER = re.compile(r":\w+|\{\w+\}|<\w+>|\d+|[0-9a-fA-F-]{36}")
_ROUTE = re.compile(
    r"(?im)^\s*@?(?:(?:app|router|blueprint)\.)?(get|post|put|patch|head|options)"
    r"\(\s*['\"](/[^'\"\s]{0,500})['\"]"
)
_IMPORT = re.compile(r"(?:from\s*|require\(\s*|import\s*)['\"](\.[^'\"\s]{1,200})['\"]")
# A route declaration, whatever the framework: the route literal is the first argument of a call or annotation that
# names an HTTP method or a routing function, e.g. router.get('/x', …), r.GET("/x", …), Route::get('/x', …),
# get '/x' (Rails), @GetMapping("/x"), @RequestMapping(value = "/x", method = …), [HttpGet("x")],
# @app.route('/x', methods=[…]), path('x/', …) (Django), HandleFunc("/x", …) (Go).
_SEGMENT = r"(?:[A-Za-z0-9_.~-]+|:\w+|\{\w+(?::[^{}/'\"]*)?\??\}|<(?:\w+:)?\w+>)"
_ROUTE_TEXT = rf"/?{_SEGMENT}(?:/{_SEGMENT})*/?|/"
_VERBS = "get|post|put|patch|head|options"
_DECLARATION = re.compile(
    rf"""(?:(?<![\w@])(?P<verb>(?i:{_VERBS}))
          |@(?P<annotation>Get|Post|Put|Patch|Request)Mapping
          |\[Http(?P<attribute>Get|Post|Put|Patch|Head|Options)
          |(?P<routing>\.route|(?<![.\w])(?:re_)?path|HandleFunc|\.Handle))
        \s*\(?\s*(?:(?:value|path)\s*=\s*)?(?P<q>['"])(?P<route>{_ROUTE_TEXT})(?P=q)""", re.X)
# A route prefix above a declaration in the same file: a class-level @RequestMapping or [Route(…)], a prefix= or
# prefix(…) argument (url_prefix=, APIRouter(prefix=), Route::prefix(…)), a route Group("…").
_PREFIX = re.compile(rf"""(?:@(?P<mapping>RequestMapping)|\[(?P<attribute>Route)|prefix\s*[(=]|\b[Gg]roup\()
        \s*\(?\s*(?:(?:value|path)\s*=\s*)?(?P<q>['"])(?P<route>{_ROUTE_TEXT})(?P=q)""", re.X)
_METHOD_ARG = re.compile(rf"RequestMethod\.({_VERBS.upper()})\b|methods\s*=\s*[\[(]([^\])]*)[\])]")
_NAME = re.compile(r"""['"]([A-Za-z_][\w-]{0,127})['"]|\b([A-Za-z_]\w{0,127})\b""")
_PLACEHOLDER_NAME = re.compile(r":(\w+)|\{(\w+)\}|<(\w+)>")
MAX_DECLARATIONS = 64   # declarations examined per recorded source window
# VER-056: directly served scripts and pages, whose URL path is their file path below the web root, and the usual
# names of a web root inside a repository.
_PAGE_SUFFIXES = (".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cfm", ".cgi", ".pl", ".html", ".htm")
_WEB_ROOTS = ("public", "public_html", "htdocs", "html", "www", "wwwroot", "web", "webroot", "WebContent", "webapp")
_INDEX = re.compile(r"(?i)(?:index|default)\.\w{2,5}")
_LITERAL = re.compile(r"""['"]([A-Za-z_][\w\[\]-]{0,127})['"]""")
# An alias bound to a module import, e.g. `import * as payment from './routes/payment'` or
# `const payment = require('./routes/payment')`, so a handler reference alias.handler can be resolved to a file.
_ALIAS_IMPORT = re.compile(
    r"""(?:import\s*\*\s*as\s+([A-Za-z_]\w*)\s+from|import\s+([A-Za-z_]\w*)\s+from|"""
    r"""(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*require\()\s*['"](\.[^'"\s]{1,200})['"]"""
)
_HANDLER_REF = re.compile(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\b")
# Handlers bound by name, e.g. `import { getUserProfile } from './routes/userProfile'` or
# `const { a, b: c } = require('./routes/x')`.
_NAMED_IMPORT = re.compile(
    r"""(?:import\s*\{([^}]{1,2000})\}\s*from|(?:const|let|var)\s*\{([^}]{1,2000})\}\s*=\s*require\()"""
    r"""\s*['"](\.[^'"\s]{1,200})['"]"""
)
_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
# Where a registration's handler list ends: the next call on app, router or blueprint, of any method, including
# those never derived (delete, use), so a route is not credited with the next registration's handler.
_NEXT_CALL = re.compile(r"(?im)^\s*@?(?:app|router|blueprint)\.\w+\(")
MAX_REGISTERED = 4   # routes resolved from the source before the agent starts, within MAX_DERIVED
_ROUTES_PER_TEXT = 1000   # registrations examined per text; a whole file is at most 1 MiB (source_reader)


def resolve(ctx, path):
    return path if urlsplit(path).scheme else ctx.target_base.rstrip("/") + "/" + path.lstrip("/")


def original_routes(ctx):
    """Only assessment/operator roots, never routes suggested by target content."""
    routes = [{"method": e.method, "path": e.path} for e in ctx.plan.endpoints]
    routes += [v["request"] for v in ctx.plan.verification_context.get("variants", [])]
    routes += [{"method": e.method, "path": e.path} for e in getattr(ctx.plan, "preparation", ())]
    for key in ("test_resources", "injection_inputs", "session_checks"):
        routes += [r for r in ctx.scope.get(key, []) if r["finding_id"] == ctx.plan.id]
    routes += getattr(ctx, "inferred_route_roots", [])
    return routes


def _parts(path):
    parsed = urlsplit(path)
    # Hash routes identify a different application view even when the HTTP path is identical.
    return tuple(p for p in (urlsplit(parsed.fragment).path if parsed.fragment else parsed.path).split("/") if p)


def related(anchor, candidate):
    """One resource: the same route or its immediate collection, record or view.

    A bare origin, API/version prefix, or placeholder cannot anchor discovery.
    The fixed prefix is never shortened beyond a record's last segment.
    """
    a, b = _parts(anchor), _parts(candidate)
    if a == b:
        return bool(a)
    if a and _PLACEHOLDER.fullmatch(a[-1]):
        a = a[:-1]
    if not a or a[-1].lower() in ("api", "rest", "graphql") or re.fullmatch(r"v\d+", a[-1], re.I):
        return False
    if any(_PLACEHOLDER.fullmatch(p) for p in a):
        return False
    return b[:len(a)] == a and len(a) <= len(b) <= len(a) + 1


class _Forms(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.routes, self.form = base, [], None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            method = (attrs.get("method") or "GET").upper()
            self.form = {"method": method, "path": urljoin(self.base, attrs.get("action") or self.base), "inputs": []}
            self.routes.append(self.form)
        elif tag in ("input", "textarea", "select") and self.form is not None and attrs.get("name"):
            location = "query" if self.form["method"] == "GET" else "form"
            self.form["inputs"].append({"location": location, "name": attrs["name"]})
        elif tag == "a" and attrs.get("href"):
            path = urljoin(self.base, attrs["href"])
            self.routes.append({"method": "GET", "path": path, "inputs": [
                {"location": "query", "name": k} for k, _ in parse_qsl(urlsplit(path).query)]})

    def handle_endtag(self, tag):
        if tag == "form":
            self.form = None


def _source_roots(ctx, history):
    root = (ctx.plan.instance or "").rsplit(":", 1)[0]
    paths = {root}
    # Follow literal local imports only from already related source, with a finite depth.
    for _ in range(3):
        known = set(paths)
        for h in history:
            if h.get("tool") != "read_source" or h.get("args", {}).get("path") not in known:
                continue
            text = h.get("result", {}).get("text", "")
            parent = PurePosixPath(h["args"]["path"]).parent
            for match in list(_IMPORT.finditer(text))[:12]:
                path = posixpath.normpath(str(parent / match[1]))
                # A sibling import may use ..; repository escapes cannot supply evidence.
                if path == ".." or path.startswith(("../", "/")):
                    continue
                paths.update([path, *(path + ext for ext in (".ts", ".js", ".py", "/index.ts", "/index.js"))])
    return paths


def _imports_finding_file(reg_file, text, finding_file):
    """The aliases in `reg_file` that import `finding_file`, so `alias.handler` can be tied to the finding's
    file (VER-008). Resolution is literal and repository-relative; an import that escapes the repo is ignored."""
    parent = PurePosixPath(reg_file).parent
    stem = PurePosixPath(finding_file).with_suffix("")
    aliases = set()
    for m in _ALIAS_IMPORT.finditer(text):
        alias = m.group(1) or m.group(2) or m.group(3)
        target = posixpath.normpath(str(parent / m.group(4)))
        if target == ".." or target.startswith(("../", "/")):
            continue
        if PurePosixPath(target) == stem or target == finding_file:
            aliases.add(alias)
    return aliases


def _named_handlers(reg_file, text, finding_file, finding_text):
    """The local names `reg_file` binds by a named import of `finding_file` to a name that appears in the
    finding's file (VER-008). Resolution is literal and repository-relative, as for _imports_finding_file."""
    parent = PurePosixPath(reg_file).parent
    stem = PurePosixPath(finding_file).with_suffix("")
    names = set()
    for m in _NAMED_IMPORT.finditer(text):
        target = posixpath.normpath(str(parent / m.group(3)))
        if target == ".." or target.startswith(("../", "/")) or (PurePosixPath(target) != stem
                                                                  and target != finding_file):
            continue
        for entry in (m.group(1) or m.group(2)).split(","):
            parts = re.split(r"\s+as\s+|\s*:\s*", entry.strip(), maxsplit=1)   # `a as b` or `a: b`
            original, local = parts[0], parts[-1]
            if (_IDENT.fullmatch(original) and _IDENT.fullmatch(local)
                    and re.search(rf"\b{re.escape(original)}\b", finding_text)):
                names.add(local)
    return names


def registration_routes(ctx, history):
    """Routes another file registers for a handler defined in the finding's file, when the assessment names
    none (VER-008). A route counts only when the registering line names `alias.handler`, `alias` imports the
    finding's file in that file, and `handler` appears in the finding's file as the agent read it. The route's
    provenance is recorded so the plan can show where it came from."""
    finding_file = (ctx.plan.instance or "").rsplit(":", 1)[0]
    if not finding_file:
        return []
    finding_text = "".join(h.get("result", {}).get("text", "") for h in history
                           if h.get("tool") == "read_source" and h.get("args", {}).get("path") == finding_file)
    if not finding_text:
        return []
    routes, seen = [], set()
    for h in history:
        if h.get("tool") != "read_source":
            continue
        reg_file = h.get("args", {}).get("path")
        result = h.get("result", {})
        if not reg_file or reg_file == finding_file:
            continue
        for route in _registered(reg_file, result.get("text", ""), result.get("start_line", 1), finding_file,
                                 finding_text):
            if (route["method"], route["path"]) not in seen:
                seen.add((route["method"], route["path"]))
                routes.append(route)
    return routes


def _registered(reg_file, text, start_line, finding_file, finding_text):
    """The routes `text` of `reg_file` registers for a handler of the finding's file (VER-008): the registering
    call names `alias.handler`, `alias` imports the finding's file in this text, and `handler` appears in the
    finding's file; or it names a handler this text imports by name from the finding's file. The route's own
    path string is not searched for names."""
    aliases = _imports_finding_file(reg_file, text, finding_file)
    named = _named_handlers(reg_file, text, finding_file, finding_text)
    if not aliases and not named:
        return []
    routes = []
    for m in list(_ROUTE.finditer(text))[:_ROUTES_PER_TEXT]:
        ends = [n.start() for n in (_ROUTE.search(text, m.end()), _NEXT_CALL.search(text, m.end())) if n]
        body = text[m.start():min(ends, default=len(text))]
        handlers = text[m.end():min(ends, default=len(text))]
        if any(a in aliases and handler in finding_text
               for a, handler in (ref.groups() for ref in _HANDLER_REF.finditer(body))) or any(
                name in named for name in _IDENT.findall(handlers)):
            routes.append({"method": m[1].upper(), "path": m[2], "inputs": [], "source_file": reg_file,
                           "source_line": start_line + text[:m.start()].count("\n")})
    return routes


def source_registrations(ctx) -> list[dict]:
    """With a source checkout and no route in the assessment, the routes other files register for a handler of
    the finding's file, resolved in code before the agent starts (VER-008): the rule of registration_routes
    applied to whole files, so an import far above its registration counts. Candidate files are those whose lines
    end an import of the finding's module name (`/payment'`); reading stays under the source reader's confinement,
    and only the routes reach the model."""
    reader = getattr(ctx, "source", None)
    finding_file = (ctx.plan.instance or "").rsplit(":", 1)[0]
    if reader is None or not finding_file or original_routes(ctx):
        return []
    from .source_reader import SourceAccessError

    stem = PurePosixPath(finding_file).stem
    try:
        finding_text = reader.read_all(finding_file)
        hits = [h for quote in ("'", '"') for h in reader.search(f"/{stem}{quote}", limit=40)["matches"]]
    except SourceAccessError:
        return []
    routes, seen = [], set()
    for reg_file in dict.fromkeys(h["path"].replace("\\", "/") for h in hits):
        if reg_file == finding_file:
            continue
        try:
            text = reader.read_all(reg_file)
        except SourceAccessError:
            continue
        for route in _registered(reg_file, text, 1, finding_file, finding_text):
            if (route["method"], route["path"]) not in seen:
                seen.add((route["method"], route["path"]))
                routes.append({**route, "evidence_step": None,
                               "reason": f"{reg_file}:{route['source_line']} registers it for a handler of "
                                         f"{finding_file}"})
    return routes[:MAX_REGISTERED]


def _normalise(literal: str) -> str:
    """A route literal in the placeholder spellings route matching knows (`<int:pk>` → `<pk>`, `{id:int}` and
    `{id?}` → `{id}`), with a leading slash."""
    literal = re.sub(r"<\w+:(\w+)>", r"<\1>", literal)
    literal = re.sub(r"\{(\w+)(?::[^{}/]*)?\??\}", r"{\1}", literal)
    return literal if literal.startswith("/") else "/" + literal


def _join(prefix: str, route: str) -> str:
    return prefix if route == "/" else prefix.rstrip("/") + "/" + route.lstrip("/")


def _methods(m, line: str) -> list[str]:
    """The methods a declaration names; a routing function or @RequestMapping without one stands for GET."""
    if m["verb"]:
        return [m["verb"].upper()]
    if m["annotation"] and m["annotation"] != "Request":
        return [m["annotation"].upper()]
    if m["attribute"]:
        return [m["attribute"].upper()]
    named = set()
    for arg in _METHOD_ARG.finditer(line[m.end():]):
        named |= {arg[1]} if arg[1] else {v.upper() for v in re.findall(rf"(?i)\b({_VERBS})\b", arg[2])}
    return sorted(named) or ["GET"]


def _declarations(text: str, start_line: int) -> list[dict]:
    """The route declarations of a source window, one per method. A bare method call such as `x.get('…')` counts
    only with a slash in its literal, so a lookup such as config.get('key') is not taken for a route."""
    found = []
    for i, line in enumerate(text.split("\n")):
        m = _DECLARATION.search(line)
        if not m or (m["verb"] and "/" not in m["route"]):
            continue
        found += [{"method": method, "literal": m["route"], "line": start_line + i} for method in _methods(m, line)]
        if len(found) >= MAX_DECLARATIONS:
            break
    return found


def _prefixes(history, path) -> list[tuple[int, str]]:
    """(line, literal) of the route prefixes the recorded reads of `path` show. A class-level mapping counts only
    with its class declaration within the next three lines; a dotted name without a slash, such as a
    configuration prefix, is no route."""
    found = set()
    for h in history:
        result = h.get("result") or {}
        if h.get("tool") != "read_source" or h.get("args", {}).get("path") != path or result.get("error"):
            continue
        lines = str(result.get("text", "")).split("\n")
        for i, line in enumerate(lines):
            m = _PREFIX.search(line)
            if not m or ("." in m["route"] and "/" not in m["route"]):
                continue
            if (m["mapping"] or m["attribute"]) and not any(re.search(r"\bclass\b", lines[j])
                                                             for j in range(i + 1, min(len(lines), i + 4))):
                continue
            found.add((result.get("start_line", 1) + i, m["route"]))
    return sorted(found)


def _declared(history, path, text, start_line) -> list[dict]:
    """Each declaration of a recorded source window, alone and joined to every prefix declared above it in the same
    file. Its inputs are the names its handler's lines contain, up to the next declaration, and the placeholders of
    its route."""
    prefixes = _prefixes(history, path)
    lines = text.split("\n")
    declarations = _declarations(text, start_line)
    candidates = []
    for n, d in enumerate(declarations):
        following = next((e["line"] for e in declarations[n + 1:] if e["line"] > d["line"]), start_line + len(lines))
        names = {a or b for a, b in _NAME.findall("\n".join(lines[d["line"] - start_line:following - start_line]))}
        route = _normalise(d["literal"])
        for composed in dict.fromkeys([route] + [_join(_normalise(p), route) for line, p in prefixes
                                                 if line < d["line"]]):
            candidates.append({"method": d["method"], "path": composed, "inputs": [], "names": names,
                               "placeholders": {a or b or c for a, b, c in _PLACEHOLDER_NAME.findall(composed)},
                               "source_file": path, "source_line": d["line"]})
    return candidates


def _offers(candidate, item) -> bool:
    """Whether a candidate evidences an input: one it lists, a placeholder of its route for a path input, or a
    name its handler's lines contain for any other input."""
    if item in candidate.get("inputs", []):
        return True
    if item.get("location") == "path":
        return item.get("name") in candidate.get("placeholders", ())
    return item.get("name") in candidate.get("names", ())


def page_candidates(instance) -> list[str]:
    """VER-056: for a finding in a directly served script or page, the URL paths its file path gives below the web
    root: the file itself and up to two directories above it, never the bare root. [] for any other file."""
    file = (instance or "").rsplit(":", 1)[0].replace("\\", "/")
    parts = [p for p in PurePosixPath(file).parts if p not in ("", ".", "/")]
    if not file.lower().endswith(_PAGE_SUFFIXES) or ".." in parts:
        return []
    root = next((i for i, p in enumerate(parts[:-1]) if p in _WEB_ROOTS), None)
    parts = parts[root + 1:] if root is not None else parts
    return ["/" + "/".join(parts)] + ["/" + "/".join(parts[:-depth]) + "/" for depth in (1, 2)
                                      if len(parts) > depth]


def page_source(ctx) -> str | None:
    """VER-056: the evidence file's text where its file path may give the finding's request: a page script, read
    from the source checkout, with no route declaration up to 80 lines before its evidence location; else None."""
    reader, instance = getattr(ctx, "source", None), getattr(ctx.plan, "instance", None)
    file, _, line = (instance or "").rpartition(":")
    if reader is None or not line.isdigit() or not page_candidates(instance):
        return None
    from .source_reader import SourceAccessError

    try:
        text = reader.read_all(file)
    except SourceAccessError:
        return None
    if any(0 <= int(line) - d["line"] <= 80 for d in _declarations(text, 1)):
        return None
    return text


def _page_roots(ctx, h, forms) -> tuple[list[dict], list[dict]]:
    """VER-056: (roots, extra candidates) a recorded GET of one of the finding's page candidates supplies: the
    evidence file itself, with the names it contains as its inputs; or the forms and links of a page above it that
    point into the page's own directory and carry an input the evidence file names as a literal."""
    text = page_source(ctx)
    if text is None or (h.get("args", {}).get("method") or "GET").upper() != "GET":
        return [], []
    pages = page_candidates(ctx.plan.instance)
    sent = urlsplit(resolve(ctx, h.get("args", {}).get("path") or "/")).path

    def requested(page):
        path = urlsplit(resolve(ctx, page)).path
        return sent == path or (page.endswith("/") and posixpath.dirname(sent) + "/" == path
                                and bool(_INDEX.fullmatch(posixpath.basename(sent))))

    page = next((p for p in pages if requested(p)), None)
    if page is None:
        return [], []
    literals = set(_LITERAL.findall(text))
    if page == pages[0]:
        own = {"method": "GET", "path": page, "inputs": [], "names": literals, "placeholders": set()}
        return [own], [own]
    directory = urlsplit(resolve(ctx, page)).path
    return [r for r in forms if same_origin(r["path"], ctx.target_base)
            and urlsplit(r["path"]).path.startswith(directory)
            and any(i["name"] in literals for i in r.get("inputs", []))], []


def _source_candidates(ctx, history, h):
    path = h.get("args", {}).get("path")
    registrations = [r for r in registration_routes(ctx, history) if r["source_file"] == path]
    if path not in _source_roots(ctx, history) and not registrations:
        raise ValueError("the source is not the finding's evidence or a recorded local import from it")
    result = h.get("result", {})
    return list(registrations) + _declared(history, path, result.get("text", ""), result.get("start_line", 1))


def derive(ctx, *, evidence_step, method, path, inputs, reason):
    """Validate a proposal against recorded evidence, not model-provided quotes."""
    history = getattr(ctx, "agent_history", [])
    if type(evidence_step) is not int or not 1 <= evidence_step <= len(history):
        raise ValueError("cite a recorded source or HTTP step of this finding")
    if len(getattr(ctx, "derived_requests", [])) >= MAX_DERIVED:
        raise ValueError("the finding's derived-request allowance is exhausted")
    url = resolve(ctx, path)
    if not same_origin(url, ctx.target_base) or not ctx.guard.authorize(url, "target").allowed:
        raise ValueError("derived request is outside the authorised target")
    if method not in SAFE_METHODS and (ctx.safe or ctx.read_only or ctx.scope.get("allow_state_change") is False):
        raise ValueError("derived writes need intrusive mode and state-change permission")
    h = history[evidence_step - 1]
    if h.get("result", {}).get("error"):
        raise ValueError("a failed action supplies no request evidence")
    source = h.get("tool") == "read_source"
    if source:
        candidates = _source_candidates(ctx, history, h)
    elif h.get("tool") == "http_request":
        response = ctx.responses.get(evidence_step, {})
        if not response.get("complete") or not 200 <= h.get("result", {}).get("status", 0) < 300:
            raise ValueError("request derivation needs a complete successful recorded response")
        parser = _Forms(resolve(ctx, h["args"].get("path", "/")))
        parser.feed(response.get("body", ""))
        candidates = parser.routes
    else:
        raise ValueError("only recorded source declarations and application links or forms supply requests")
    roots = original_routes(ctx)
    # Bootstrap only at the evidenced source location when the assessment has no route.
    if not roots and source:
        file, _, line = (ctx.plan.instance or "").rpartition(":")
        near = [r for r in candidates if r.get("source_file") == file and line.isdigit()
                and 0 <= int(line) - r["source_line"] <= 80]
        # The nearest declaration, with each method it names and each prefix it may carry.
        roots = [r for r in near if r["source_line"] == max(n["source_line"] for n in near)]
        # Or a route another file registers for a handler of the finding's file (VER-008).
        if not roots:
            roots = [r for r in registration_routes(ctx, history)
                     if r["method"] == method and planned_route(resolve(ctx, r["path"]), url)]
    elif not roots:
        # Or, for a page script, a recorded answer of a page its file path gives (VER-056).
        roots, extra = _page_roots(ctx, h, candidates)
        candidates = [*candidates, *extra]
    matching = [r for r in candidates if r["method"] == method
                and planned_route(resolve(ctx, r["path"]), url)
                and all(_offers(r, i) for i in inputs)]
    if not matching or not any(related(resolve(ctx, r["path"]), url) for r in roots):
        raise ValueError("request or inputs lack recorded evidence for the finding's original resource")
    if source:
        # Source paths are relative to the operator's base URL; browser links are already absolute.
        origin = {k: v for k, v in matching[0].items() if k.startswith("source_")}
    else:
        origin = {"response_step": evidence_step}
    request = {"method": method, "path": path, "inputs": inputs, "evidence_step": evidence_step,
               "reason": reason, **origin}
    if not hasattr(ctx, "derived_requests"):
        ctx.derived_requests = []
    if not original_routes(ctx):
        ctx.inferred_route_roots = [{"method": r["method"], "path": r["path"]} for r in roots]
    ctx.derived_requests.append(request)
    return {"accepted": True, "request": request}


def covers(ctx, plan):
    """Whether independently checked derivation covers this plan's route and input."""
    location = {"params": "query"}.get(plan.get("input_location"), plan.get("input_location"))
    return any(r["method"] == plan.get("method", "GET")
               and planned_route(resolve(ctx, r["path"]), resolve(ctx, plan["path"]))
               and (not location or {"location": location, "name": plan.get("input_name")} in r["inputs"])
               for r in getattr(ctx, "derived_requests", []))
