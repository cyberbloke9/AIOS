"""Tests for aios.project.runstate (sprint 24)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aios.project import GitError, runstate_from_project
from aios.verification.conservation_scan import (
    ContextLoad, any_breach, conservation_scan,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")


def _commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.decode().strip()


_INVARIANTS_TWO = """\
invariants:
  - id: INV-001
    source: principle
    statement: Interfaces are frozen.
  - id: INV-002
    source: security
    statement: PII is never logged.
"""

_INVARIANTS_ONE = """\
invariants:
  - id: INV-001
    source: principle
    statement: Interfaces are frozen.
"""

_ADR_ACCEPTED_REMOVES_INV2 = """\
---
id: ADR-0042
status: Accepted
removes: [INV-002]
---
# ADR-0042 — Retire the no-PII invariant (legitimately)
"""


# ---------------------------------------------------------------------------
# Working-tree only (no git diff)
# ---------------------------------------------------------------------------


def test_runstate_from_working_tree_only(tmp_path: Path):
    """No before_ref: before == after, Q1 passes trivially."""
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.yaml").write_text(_INVARIANTS_TWO, encoding="utf-8")

    rs = runstate_from_project(tmp_path)
    ids_before = {i.id for i in rs.invariants_before}
    ids_after = {i.id for i in rs.invariants_after}
    assert ids_before == ids_after == {"INV-001", "INV-002"}
    assert rs.impact == "local"
    assert rs.run_id.endswith(":working")

    ledger = conservation_scan(rs)
    assert ledger["Q1_invariant_integrity"]["status"] == "preserved"
    assert not any_breach(ledger)


def test_runstate_empty_project_returns_empty_sets(tmp_path: Path):
    rs = runstate_from_project(tmp_path)
    assert rs.invariants_after == frozenset()
    assert rs.invariants_before == frozenset()
    assert rs.adr_events == ()


def test_runstate_defaults_produce_passing_scan(tmp_path: Path):
    """A fresh-install user running scan on an empty repo should not get
    spurious breaches."""
    rs = runstate_from_project(tmp_path)
    ledger = conservation_scan(rs)
    assert not any_breach(ledger)


def test_runstate_context_load_auto_populated(tmp_path: Path):
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.yaml").write_text(_INVARIANTS_TWO, encoding="utf-8")
    rs = runstate_from_project(tmp_path)
    assert isinstance(rs.context_load, ContextLoad)
    assert rs.context_load.invariants_required == {"INV-001", "INV-002"}
    assert rs.context_load.budget > 0


# ---------------------------------------------------------------------------
# Git diff (before_ref)
# ---------------------------------------------------------------------------


def test_runstate_detects_silent_removal(tmp_path: Path):
    """Invariant removed between commits with no ADR — Q1 must breach."""
    _init_repo(tmp_path)
    (tmp_path / ".aios").mkdir()
    (tmp_path / ".aios" / "invariants.yaml").write_text(
        _INVARIANTS_TWO, encoding="utf-8"
    )
    baseline = _commit_all(tmp_path, "baseline: two invariants")

    # Silently drop INV-002 (no ADR)
    (tmp_path / ".aios" / "invariants.yaml").write_text(
        _INVARIANTS_ONE, encoding="utf-8"
    )
    _commit_all(tmp_path, "silent: drop INV-002")

    rs = runstate_from_project(tmp_path, before_ref=baseline, after_ref="HEAD")
    ledger = conservation_scan(rs)
    assert ledger["Q1_invariant_integrity"]["status"] == "breached"
    assert "INV-002" in ledger["Q1_invariant_integrity"]["illegitimate_removals"]


def test_runstate_legitimate_removal_preserved(tmp_path: Path):
    """Same removal but with an Accepted ADR retiring INV-002 — Q1 preserved."""
    _init_repo(tmp_path)
    (tmp_path / ".aios").mkdir()
    (tmp_path / ".aios" / "invariants.yaml").write_text(
        _INVARIANTS_TWO, encoding="utf-8"
    )
    baseline = _commit_all(tmp_path, "baseline")

    # Remove INV-002 AND add ADR-0042 authorizing the removal
    (tmp_path / ".aios" / "invariants.yaml").write_text(
        _INVARIANTS_ONE, encoding="utf-8"
    )
    (tmp_path / "adrs").mkdir()
    (tmp_path / "adrs" / "0042-retire.md").write_text(
        _ADR_ACCEPTED_REMOVES_INV2, encoding="utf-8"
    )
    _commit_all(tmp_path, "legitimate: retire INV-002 via ADR-0042")

    rs = runstate_from_project(tmp_path, before_ref=baseline, after_ref="HEAD")
    ledger = conservation_scan(rs)
    assert ledger["Q1_invariant_integrity"]["status"] == "preserved"
    assert rs.adr_events[0].adr_id == "ADR-0042"


def test_runstate_after_ref_working_vs_head(tmp_path: Path):
    """after_ref='working' reads the on-disk state; 'HEAD' reads via git."""
    _init_repo(tmp_path)
    (tmp_path / ".aios").mkdir()
    (tmp_path / ".aios" / "invariants.yaml").write_text(
        _INVARIANTS_TWO, encoding="utf-8"
    )
    _commit_all(tmp_path, "initial")

    # Uncommitted change: drop one invariant (stays in working tree, not HEAD)
    (tmp_path / ".aios" / "invariants.yaml").write_text(
        _INVARIANTS_ONE, encoding="utf-8"
    )
    rs_working = runstate_from_project(tmp_path)  # after_ref='working' default
    rs_head = runstate_from_project(tmp_path, after_ref="HEAD")

    assert {i.id for i in rs_working.invariants_after} == {"INV-001"}
    assert {i.id for i in rs_head.invariants_after} == {"INV-001", "INV-002"}


def test_runstate_unknown_ref_raises_git_error(tmp_path: Path):
    _init_repo(tmp_path)
    (tmp_path / "placeholder.txt").write_text("x")
    _commit_all(tmp_path, "initial")
    with pytest.raises(GitError):
        runstate_from_project(tmp_path, before_ref="does-not-exist-1234567")


def test_runstate_run_id_default_includes_ref(tmp_path: Path):
    rs = runstate_from_project(tmp_path, after_ref="working")
    assert rs.run_id.endswith(":working")
    rs2 = runstate_from_project(tmp_path, run_id="custom")
    assert rs2.run_id == "custom"


def test_runstate_impact_forwarded(tmp_path: Path):
    rs = runstate_from_project(tmp_path, impact="subsystem")
    assert rs.impact == "subsystem"
