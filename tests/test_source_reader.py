"""Source access is read-only and confined to the repository (VER-017)."""

from __future__ import annotations

import pytest

from appsec_verifier.agent.source_reader import SourceAccessError, SourceReader


def _repo(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "basket.ts").write_text("\n".join(f"line {i}" for i in range(1, 101)))
    (tmp_path / "secret.txt").write_text("outside-of-routes but inside repo")
    return SourceReader(tmp_path, context_lines=5)


def test_read_window_around_line(tmp_path):
    r = _repo(tmp_path)
    w = r.read_window("routes/basket.ts", around_line=50)
    assert w["start_line"] == 45
    assert "line 50" in w["text"] and "line 44" not in w["text"]


def test_traversal_refused(tmp_path):
    r = _repo(tmp_path)
    with pytest.raises(SourceAccessError):
        r.read_window("../../etc/passwd")


def test_absolute_path_refused(tmp_path):
    r = _repo(tmp_path)
    with pytest.raises(SourceAccessError):
        r.read_window("/etc/passwd")


def test_missing_file_refused(tmp_path):
    r = _repo(tmp_path)
    with pytest.raises(SourceAccessError):
        r.read_window("routes/nope.ts")
