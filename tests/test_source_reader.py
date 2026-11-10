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


@pytest.mark.parametrize("relpath", [".env", ".env.local", "config/.env.production", ".ENV", ".git/config",
                                     "sub/.git/config", ".git", ".aws/credentials", "certs/server.key",
                                     "certs/tls.PEM", ".ssh/id_ed25519", "id_rsa", ".npmrc", ".git-credentials"])
def test_files_holding_secrets_are_refused(tmp_path, relpath):
    """Credential stores and VCS internals never reach the model, though inside the repository (VER-016)."""
    r = _repo(tmp_path)
    target = tmp_path / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.name != ".git":
        target.write_text("DB_PASSWORD=hunter2-real\n")
    else:
        target.write_text("gitdir: /elsewhere\n")
    with pytest.raises(SourceAccessError, match="not read") as exc:
        r.read_window(relpath)
    assert "hunter2" not in str(exc.value)


def test_symlink_to_a_secret_file_is_refused(tmp_path):
    r = _repo(tmp_path)
    (tmp_path / ".env").write_text("DB_PASSWORD=hunter2-real\n")
    (tmp_path / "routes" / "settings.ts").symlink_to(tmp_path / ".env")
    with pytest.raises(SourceAccessError, match="not read"):
        r.read_window("routes/settings.ts")


@pytest.mark.parametrize("relpath", [".env.example", "config/.env.sample", "src/environment.ts", "keys.ts"])
def test_env_templates_and_ordinary_sources_stay_readable(tmp_path, relpath):
    r = _repo(tmp_path)
    (tmp_path / relpath).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / relpath).write_text("API_URL=https://app.example.com\n")
    assert "API_URL" in r.read_window(relpath)["text"]


# ── find: locate files without guessing (VER-050) ─────────────────────────────

def _find_repo(tmp_path):
    for rel in ("routes/feedback.ts", "routes/login.ts", "frontend/feedback.component.ts",
                "feedback/helper.ts", "node_modules/pkg/feedback.ts", "certs/feedback.pem", ".git/feedback-head"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    (tmp_path / ".env").write_text("DB_PASSWORD=hunter2-real\n")
    return SourceReader(tmp_path)


def test_find_locates_files_by_substring_and_ranks_name_matches_first(tmp_path):
    r = _find_repo(tmp_path)
    assert r.find("feedback.ts")["matches"] == ["routes/feedback.ts"]   # not the vendor copy, not the component
    names = r.find("feedback")["matches"]
    assert {"routes/feedback.ts", "frontend/feedback.component.ts", "feedback/helper.ts"} <= set(names)
    assert names[-1] == "feedback/helper.ts"   # "feedback" only in the path, not the name: ranked last


def test_find_excludes_secrets_vendor_and_vcs(tmp_path):
    matches = _find_repo(tmp_path).find("feedback")["matches"]
    assert not any("node_modules" in m or m.endswith(".pem") or ".git" in m for m in matches)


def test_find_stays_in_the_repository(tmp_path):
    outside = tmp_path.parent / "outside_secret.ts"
    outside.write_text("x")
    r = _find_repo(tmp_path)
    (tmp_path / "link.ts").symlink_to(outside)        # a symlinked file resolves outside the repository
    assert "link.ts" not in r.find("link")["matches"]
    assert r.find("outside_secret")["matches"] == []


def test_find_rejects_an_empty_query(tmp_path):
    with pytest.raises(SourceAccessError):
        _find_repo(tmp_path).find("")
