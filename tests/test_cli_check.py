"""Tests for `aios check` (sprint 30)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from aios.cli import main


def _init_git(path: Path) -> None:
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@e.com"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "T"],
                   check=True, capture_output=True)


def _commit_all(repo: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", message],
                   check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return sha


_INV_TWO = """\
invariants:
  - id: INV-001
    source: principle
    statement: X
  - id: INV-002
    source: security
    statement: Y
"""

_INV_ONE = """\
invariants:
  - id: INV-001
    source: principle
    statement: X
"""


def test_check_refuses_non_adopted_repo(tmp_path: Path, capsys):
    rc = main(["check", "--repo", str(tmp_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "aios adopt" in err


def test_check_clean_repo_passes(tmp_path: Path, capsys):
    main(["adopt", str(tmp_path)])
    capsys.readouterr()
    # No invariants, no ADRs — should pass cleanly.
    rc = main(["check", "--repo", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PROMOTED" in out
    assert "invariants:     0" in out
    assert "ADR structural violations: 0" in out


def test_check_with_invariants_still_passes(tmp_path: Path, capsys):
    main(["adopt", str(tmp_path)])
    (tmp_path / ".aios" / "invariants.yaml").write_text(_INV_TWO, encoding="utf-8")
    capsys.readouterr()
    rc = main(["check", "--repo", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "invariants:     2" in out


def test_check_detects_silent_invariant_removal(tmp_path: Path, capsys):
    _init_git(tmp_path)
    main(["adopt", str(tmp_path)])
    (tmp_path / ".aios" / "invariants.yaml").write_text(_INV_TWO, encoding="utf-8")
    baseline = _commit_all(tmp_path, "baseline")

    # Silently drop INV-002
    (tmp_path / ".aios" / "invariants.yaml").write_text(_INV_ONE, encoding="utf-8")
    _commit_all(tmp_path, "silent drop")

    capsys.readouterr()
    rc = main(["check", "--repo", str(tmp_path),
               "--before", baseline, "--after", "HEAD"])
    assert rc == 4  # Q1 breach -> aborted
    out = capsys.readouterr().out
    assert "ABORTED" in out
    assert "[BREACH]" in out


def test_check_adr_violations_exit_code_6(tmp_path: Path, capsys):
    main(["adopt", str(tmp_path)])
    # Create an ADR that violates structural checks (rejected + removes)
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "0001.md").write_text(
        "---\nid: ADR-0001\nstatus: Rejected\nremoves: [INV-001]\n---\n# bad\n",
        encoding="utf-8",
    )
    capsys.readouterr()
    rc = main(["check", "--repo", str(tmp_path)])
    assert rc == 6  # gate/workflow rejection OR ADR violations
    out = capsys.readouterr().out
    assert "ADR structural violations: 1" in out
    assert "rejected_removes_invariants" in out


def test_check_emits_frames_to_event_log(tmp_path: Path, capsys):
    main(["adopt", str(tmp_path)])
    capsys.readouterr()
    main(["check", "--repo", str(tmp_path)])
    capsys.readouterr()

    rc = main(["replay", "--home", str(tmp_path / ".aios")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "run.started" in out
    assert "gate.evaluated" in out
    assert "artifact.promoted" in out
    assert "skill.evaluated" in out


def test_check_in_help(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "check" in out
    assert "Q1-Q3" in out
