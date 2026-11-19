"""Write generated run files without following output links (VER-017, VER-022, VER-058)."""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from pathlib import Path


def check_destination(path: Path) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise OSError(f"symbolic link refused for run output: {path.name}")


@contextlib.contextmanager
def _destination(path: Path):
    check_destination(path)
    if os.name == "nt":
        yield None, path
        return
    # All operations below use this directory even if someone replaces its name.
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield directory, Path(path.name)
    finally:
        os.close(directory)


def open_log(path, append: bool):
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with _destination(Path(path)) as (directory, name):
        fd = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError(f"run log needs a private regular file: {name}")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        if not append:
            os.ftruncate(fd, 0)
        return os.fdopen(fd, "a", encoding="utf-8", buffering=1)
    except BaseException:
        os.close(fd)
        raise


def write_output(path: Path, data: bytes, *, preserve_mode: bool = False) -> None:
    with _destination(path) as (directory, name):
        mode = None
        if preserve_mode:
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(info.st_mode):
                    raise OSError(f"output needs a regular file: {name}")
                mode = stat.S_IMODE(info.st_mode) & 0o777
        temporary = name.with_name(f".output-{secrets.token_hex(12)}")
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                if mode is not None and hasattr(os, "fchmod"):
                    os.fchmod(stream.fileno(), mode)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)
