"""Read-only, repository-confined source access for the agent (VER-016, VER-017, VER-050).

The agent may read the evidenced code to work out the concrete request, but
only inside the target checkout: a path that resolves outside the repository
root — including via ``..`` or a symlink — is refused, and reads are bounded in
lines and bytes. Files that hold secrets rather than code (``.env``, private
keys, credential stores) and VCS internals (``.git/``) are refused too, judged
on the resolved path, so their content never reaches the model. A path the
file system cannot use, or a file it cannot read, is a SourceAccessError, which
the agent sees as a tool error. This tool never writes.
"""

import os
from pathlib import Path

# Matched case-insensitively against every part of the resolved path below the repository root.
_SECRET_DIRS = frozenset({".git", ".hg", ".svn", ".ssh", ".aws", ".gnupg", ".docker", ".kube"})
_SECRET_NAMES = frozenset({".netrc", ".npmrc", ".pypirc", ".pgpass", ".htpasswd", ".git-credentials",
                           "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
MAX_SOURCE_BYTES = 1_048_576  # total read cap, before decoding or splitting (VER-036)
_ENV_TEMPLATES = (".example", ".sample", ".template", ".dist")
# Walked over but never descended: VCS internals and heavy vendor trees that hold no finding's own source.
_PRUNE_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", ".venv", "venv",
                         "dist", "build", ".next", ".nuxt", "__pycache__", ".tox", ".cache", ".idea", "target"})
_FIND_SCAN_CAP = 200_000  # bounded traversal, so a pathological tree cannot stall a finding (VER-036)
_SEARCH_READ_CAP = 64 * 1_048_576  # total bytes one content search reads (VER-036)
_SEARCH_LINE_CAP = 200  # characters of a matching line returned to the model
_SEARCH_TEXT = (3, 200)  # length bounds of a content-search string


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
        if "\x00" in str(relpath):
            raise SourceAccessError(f"not a file path: {relpath!r}")
        p = (self.root / relpath).resolve()
        try:
            rel = p.relative_to(self.root)
        except ValueError as exc:
            raise SourceAccessError(f"path escapes the repository: {relpath!r}") from exc
        if rel.parts and _holds_secrets(rel):
            raise SourceAccessError(f"{relpath!r} holds credentials or VCS data and is not read (VER-016)")
        try:
            is_file = p.is_file()
        except OSError:                   # e.g. a name too long for the file system
            is_file = False
        if not is_file:
            raise SourceAccessError(f"not a readable file: {relpath!r}")
        return p

    def find(self, query: str, *, limit: int = 40) -> dict:
        """Repo-confined file search (VER-016, VER-017): relative paths whose name or path contains `query`,
        case-insensitive, excluding credential, key and VCS files and heavy vendor directories, bounded in
        traversal and count. Read-only; returns names only, never any file content."""
        if not query or "\x00" in query:
            raise SourceAccessError(f"not a search query: {query!r}")
        needle = query.lower().replace("\\", "/")
        matches, scanned = [], 0
        for dirpath, dirnames, filenames in os.walk(self.root):   # followlinks=False: a symlinked dir is not entered
            dirnames[:] = [d for d in dirnames if d.lower() not in _PRUNE_DIRS]
            for name in filenames:
                scanned += 1
                if scanned > _FIND_SCAN_CAP:
                    return {"query": query, "matches": sorted(matches), "truncated": True}
                try:
                    rel = (Path(dirpath) / name).resolve().relative_to(self.root)
                except (OSError, ValueError):
                    continue
                if _holds_secrets(rel):
                    continue
                if needle in str(rel).replace("\\", "/").lower():
                    matches.append(str(rel))
                    if len(matches) >= limit:
                        return {"query": query, "matches": sorted(matches), "truncated": True}
        matches.sort(key=lambda r: (needle not in Path(r).name.lower(), r))   # name matches before path-only matches
        return {"query": query, "matches": matches, "truncated": False}

    def search(self, text: str, *, limit: int = 40) -> dict:
        """Repo-confined content search (VER-050): the lines that contain `text` as a literal, case-insensitive
        string, as path, line number and the line cut to a fixed length. The same exclusions as `find` apply
        (credential, key and VCS files, heavy vendor directories, symlinks that leave the repository); files
        above the read limit and binary files are skipped, and the traversal and the bytes read are bounded.
        Read-only; the model supplies no pattern, only a string."""
        if not isinstance(text, str) or "\x00" in text or not _SEARCH_TEXT[0] <= len(text.strip()) <= _SEARCH_TEXT[1]:
            raise SourceAccessError(f"a content search needs {_SEARCH_TEXT[0]} to {_SEARCH_TEXT[1]} characters")
        needle = text.lower()
        matches, scanned, read = [], 0, 0

        def done(truncated):
            return {"text": text, "matches": matches, "truncated": truncated}

        for dirpath, dirnames, filenames in os.walk(self.root):   # followlinks=False: a symlinked dir is not entered
            dirnames[:] = sorted(d for d in dirnames if d.lower() not in _PRUNE_DIRS)
            for name in sorted(filenames):
                scanned += 1
                if scanned > _FIND_SCAN_CAP:
                    return done(True)
                try:
                    resolved = (Path(dirpath) / name).resolve()
                    rel = resolved.relative_to(self.root)
                    if _holds_secrets(rel) or not resolved.is_file() or resolved.stat().st_size > MAX_SOURCE_BYTES:
                        continue
                    if read + resolved.stat().st_size > _SEARCH_READ_CAP:
                        return done(True)
                    with resolved.open("rb") as stream:
                        data = stream.read(MAX_SOURCE_BYTES + 1)
                except (OSError, ValueError):
                    continue
                read += len(data)
                if len(data) > MAX_SOURCE_BYTES or b"\x00" in data[:8192]:   # grown since stat, or binary
                    continue
                for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                    if needle in line.lower():
                        matches.append({"path": str(rel), "line": number, "text": line.strip()[:_SEARCH_LINE_CAP]})
                        if len(matches) >= limit:
                            return done(True)
        return done(False)

    def read_window(self, relpath: str, around_line: int | None = None, context: int | None = None) -> dict:
        p = self._resolve(relpath)
        try:
            with p.open("rb") as stream:
                data = stream.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                raise SourceAccessError("source exceeds the 1 MiB read limit")
            lines = data.decode("utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise SourceAccessError(f"cannot read {relpath!r}: {type(exc).__name__}") from exc
        ctx = self.context_lines if context is None else context
        if around_line:
            lo = max(0, around_line - 1 - ctx)
            hi = min(len(lines), around_line - 1 + ctx + 1)
            window, start = lines[lo:hi], lo + 1
        else:
            window, start = lines[: self.max_lines], 1
        text = "\n".join(window)[: self.max_bytes]
        return {"path": relpath, "start_line": start, "text": text}
