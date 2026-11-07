"""Read-only, repository-confined source access for the agent (VER-016, VER-017).

The agent may read the evidenced code to work out the concrete request, but
only inside the target checkout: a path that resolves outside the repository
root — including via ``..`` or a symlink — is refused, and reads are bounded in
lines and bytes. Files that hold secrets rather than code (``.env``, private
keys, credential stores) and VCS internals (``.git/``) are refused too, judged
on the resolved path, so their content never reaches the model. This tool
never writes.
"""

from __future__ import annotations

from pathlib import Path

# Matched case-insensitively against every part of the resolved path below the repository root.
_SECRET_DIRS = frozenset({".git", ".hg", ".svn", ".ssh", ".aws", ".gnupg", ".docker", ".kube"})
_SECRET_NAMES = frozenset({".netrc", ".npmrc", ".pypirc", ".pgpass", ".htpasswd", ".git-credentials",
                           "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
_ENV_TEMPLATES = (".example", ".sample", ".template", ".dist")


class SourceAccessError(Exception):
    pass


def _holds_secrets(rel: Path) -> bool:
    parts = [p.lower() for p in rel.parts]
    name = parts[-1]
    if any(p in _SECRET_DIRS for p in parts) or name in _SECRET_NAMES or name.endswith(_SECRET_SUFFIXES):
        return True
    return name == ".env" or (name.startswith(".env.") and not name.endswith(_ENV_TEMPLATES))


class SourceReader:
    def __init__(self, repo_root, *, max_bytes: int = 20000, context_lines: int = 40, max_lines: int = 400):
        self.root = Path(repo_root).resolve()
        self.max_bytes = max_bytes
        self.context_lines = context_lines
        self.max_lines = max_lines

    def _resolve(self, relpath: str) -> Path:
        p = (self.root / relpath).resolve()
        try:
            rel = p.relative_to(self.root)
        except ValueError as exc:
            raise SourceAccessError(f"path escapes the repository: {relpath!r}") from exc
        if rel.parts and _holds_secrets(rel):
            raise SourceAccessError(f"{relpath!r} holds credentials or VCS data and is not read (VER-016)")
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
