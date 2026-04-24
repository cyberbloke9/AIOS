"""Tests for aios.project.adopt + install_post_commit_hook (sprint 29)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aios.project import adopt, install_post_commit_hook


def _init_git(path: Path) -> None:
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"],
                   check=True, capture_output=True)


# adopt ------------------------------------------------------------------


def test_adopt_creates_aios_home(tmp_path: Path):
    result = adopt(tmp_path)
    assert (tmp_path / ".aios" / "config.json").exists()
    assert (tmp_path / ".aios" / "events").is_dir()
    assert result.init.profile == "P-Local"


def test_adopt_writes_invariants_template(tmp_path: Path):
    result = adopt(tmp_path)
    inv = tmp_path / ".aios" / "invariants.yaml"
    assert inv.exists()
    assert "invariants:" in inv.read_text(encoding="utf-8")
    assert result.invariants_template_written is True


def test_adopt_does_not_overwrite_existing_invariants(tmp_path: Path):
    (tmp_path / ".aios").mkdir()
    existing = tmp_path / ".aios" / "invariants.yaml"
    existing.write_text("invariants: [{id: INV-1, source: principle, statement: x}]",
                        encoding="utf-8")
    result = adopt(tmp_path, force=True)
    assert result.invariants_template_written is False
    assert "INV-1" in existing.read_text(encoding="utf-8")


def test_adopt_updates_gitignore(tmp_path: Path):
    result = adopt(tmp_path)
    gi = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".aios/events/" in gi
    assert ".aios/projections/" in gi
    assert ".aios/**/log.lock" in gi
    assert result.gitignore_updated is True


def test_adopt_idempotent_on_gitignore(tmp_path: Path):
    adopt(tmp_path)
    first = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    adopt(tmp_path, force=True)  # second run
    second = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    # No duplication of the AIOS block
    assert first.count(".aios/events/") == second.count(".aios/events/") == 1


def test_adopt_preserves_existing_gitignore_content(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("__pycache__/\nnode_modules/\n", encoding="utf-8")
    adopt(tmp_path)
    gi = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert "__pycache__/" in gi
    assert "node_modules/" in gi
    assert ".aios/events/" in gi


def test_adopt_rejects_missing_target(tmp_path: Path):
    with pytest.raises(NotADirectoryError):
        adopt(tmp_path / "does-not-exist")


def test_adopt_rejects_reinit_without_force(tmp_path: Path):
    adopt(tmp_path)
    with pytest.raises(FileExistsError):
        adopt(tmp_path)


def test_adopt_force_reinits(tmp_path: Path):
    adopt(tmp_path)
    result = adopt(tmp_path, force=True)
    assert result.init.profile == "P-Local"


# install_post_commit_hook ------------------------------------------------


def test_hook_installed_in_fresh_repo(tmp_path: Path):
    _init_git(tmp_path)
    hook = install_post_commit_hook(tmp_path)
    assert hook.exists()
    body = hook.read_text(encoding="utf-8")
    assert "aios post-commit hook" in body
    assert "aios append" in body


def test_hook_not_a_git_repo(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="not a git repository"):
        install_post_commit_hook(tmp_path)


def test_hook_idempotent_no_duplicate_block(tmp_path: Path):
    _init_git(tmp_path)
    install_post_commit_hook(tmp_path)
    install_post_commit_hook(tmp_path)
    body = (tmp_path / ".git" / "hooks" / "post-commit").read_text(encoding="utf-8")
    # The begin-marker appears once; the end-marker appears once; both
    # contain the "aios post-commit hook" phrase, so check the full
    # sentinel strings rather than the substring.
    assert body.count(">>> aios post-commit hook >>>") == 1
    assert body.count("<<< aios post-commit hook <<<") == 1


def test_hook_preserves_existing_user_content(tmp_path: Path):
    _init_git(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "post-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(
        "#!/bin/bash\necho 'my existing hook'\n",
        encoding="utf-8",
    )
    install_post_commit_hook(tmp_path)
    body = hook.read_text(encoding="utf-8")
    assert "my existing hook" in body
    assert "aios post-commit hook" in body


def test_hook_updates_aios_block_without_duplicating(tmp_path: Path):
    _init_git(tmp_path)
    install_post_commit_hook(tmp_path)
    body_v1 = (tmp_path / ".git" / "hooks" / "post-commit").read_text(encoding="utf-8")
    # Re-run: the block should be rewritten in place, not duplicated
    install_post_commit_hook(tmp_path)
    body_v2 = (tmp_path / ".git" / "hooks" / "post-commit").read_text(encoding="utf-8")
    assert body_v2.count(">>> aios post-commit hook >>>") == 1
    assert body_v2.count("<<< aios post-commit hook <<<") == 1
