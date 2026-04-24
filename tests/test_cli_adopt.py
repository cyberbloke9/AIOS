"""Tests for `aios adopt` + `aios git-init` CLI (sprint 29)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from aios.cli import main


def test_adopt_cli(tmp_path: Path, capsys):
    rc = main(["adopt", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "adopted AIOS" in out
    assert (tmp_path / ".aios" / "config.json").exists()
    assert (tmp_path / ".gitignore").exists()


def test_adopt_cli_refuses_reinit(tmp_path: Path, capsys):
    main(["adopt", str(tmp_path)])
    capsys.readouterr()
    rc = main(["adopt", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "already" in err.lower()


def test_adopt_cli_force_reinits(tmp_path: Path, capsys):
    main(["adopt", str(tmp_path)])
    capsys.readouterr()
    rc = main(["adopt", str(tmp_path), "--force"])
    assert rc == 0


def test_adopt_cli_bad_target(tmp_path: Path):
    rc = main(["adopt", str(tmp_path / "nope")])
    assert rc == 2


def test_adopt_and_git_init_end_to_end(tmp_path: Path, capsys):
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q", "-b", "main"],
                   check=True, capture_output=True)
    main(["adopt", str(tmp_path)])
    capsys.readouterr()
    rc = main(["git-init", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "post-commit hook" in out
    assert (tmp_path / ".git" / "hooks" / "post-commit").exists()


def test_git_init_without_repo(tmp_path: Path, capsys):
    rc = main(["git-init", str(tmp_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not a git repository" in err


def test_commands_in_help(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "adopt" in out
    assert "git-init" in out
