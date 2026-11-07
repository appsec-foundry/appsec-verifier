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
