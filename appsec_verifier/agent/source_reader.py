"""Read-only, repository-confined source access for the agent (VER-017).

The agent may read the evidenced code to work out the concrete request, but
only inside the target checkout: a path that resolves outside the repository
root — including via ``..`` or a symlink — is refused, and reads are bounded in
lines and bytes. This tool never writes.
"""

from __future__ import annotations

from pathlib import Path


class SourceAccessError(Exception):
    pass


class SourceReader:
    def __init__(self, repo_root, *, max_bytes: int = 20000, context_lines: int = 40, max_lines: int = 400):
        self.root = Path(repo_root).resolve()
        self.max_bytes = max_bytes
        self.context_lines = context_lines
        self.max_lines = max_lines

    def _resolve(self, relpath: str) -> Path:
        p = (self.root / relpath).resolve()
        try:
            p.relative_to(self.root)
        except ValueError as exc:
            raise SourceAccessError(f"path escapes the repository: {relpath!r}") from exc
        if not p.is_file():
            raise SourceAccessError(f"not a readable file: {relpath!r}")
        return p

    def read_window(self, relpath: str, around_line: int | None = None, context: int | None = None) -> dict:
        p = self._resolve(relpath)
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        ctx = self.context_lines if context is None else context
        if around_line:
            lo = max(0, around_line - 1 - ctx)
            hi = min(len(lines), around_line - 1 + ctx + 1)
            window, start = lines[lo:hi], lo + 1
        else:
            window, start = lines[: self.max_lines], 1
        text = "\n".join(window)[: self.max_bytes]
        return {"path": relpath, "start_line": start, "text": text}
