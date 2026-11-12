"""One operator-declared path input, bound without changing route structure (VER-044)."""

from __future__ import annotations

import re
from urllib.parse import quote, urlsplit


def validate_path_input(path, name):
    from .tools import ToolError

    try:
        parsed = urlsplit(path)
    except ValueError as exc:
        raise ToolError("invalid path input template") from exc
    placeholders = re.findall(r":\w+|\{\w+\}|<\w+>", parsed.path)
    if (parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or not path.startswith("/")
            or len(placeholders) != 1 or placeholders[0] not in (":" + name, "{" + name + "}", "<" + name + ">")
            or placeholders[0] not in parsed.path.split("/")):
        # VER-043: name the accepted forms; a model that learned {{predicate}} templates tends to write {{id}}.
        raise ToolError(f"path input needs exactly one whole-segment placeholder with the declared input name, "
                        f"written :{name}, {{{name}}} or <{name}>, e.g. /items/:{name}")
    return placeholders[0]


def bind_path_input(ctx, plan, path, values):
    from .tools import ToolError

    name = plan.get("input_name", "")
    if (ctx.plan.cls != "injection" or plan.get("kind") not in ("boolean", "timing")
            or plan.get("input_location") != "path"):
        # The usual mistake: a placeholder route of another plan, e.g. an access-control plan on /items/:id.
        raise ToolError("path_inputs only carry an accepted injection experiment's declared path input; "
                        "otherwise write the value into path itself, e.g. /items/3 for /items/:id")
    if (path != plan.get("path") or not isinstance(values, dict) or set(values) != {name}
            or not isinstance(values.get(name), str) or len(values[name]) > 4000):
        raise ToolError(f"path input must match the accepted experiment: keep path {plan.get('path')} and give "
                        f"only {name}")
    pinned = [r for r in ctx.scope.get("injection_inputs", []) if r["finding_id"] == ctx.plan.id]
    if pinned and not any(r["path"] == path and r["input_location"] == "path"
               and r["input_name"] == name and r["semantics"] == "literal"
               for r in pinned):
        raise ToolError("path input needs its operator-declared literal input contract")
    placeholder = validate_path_input(path, name)
    return path.replace(placeholder, quote(values[name], safe=""), 1)
