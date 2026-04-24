"""Tests for upgrade + migration runner (sprint 57)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.distribution.install import (
    current_version,
    install_package,
)
from aios.distribution.upgrade import (
    UpgradeError,
    upgrade_package,
)


def _mk(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Minor + patch upgrades (same major)
# ---------------------------------------------------------------------------


def test_minor_upgrade_flips_pointer(tmp_path: Path):
    src1 = _mk(tmp_path / "s1", {"a.py": "old"})
    src2 = _mk(tmp_path / "s2", {"a.py": "new"})
    target = tmp_path / "t"
    install_package(src1, target_root=target, version="0.5.0")
    result = upgrade_package(src2, target_root=target, new_version="0.5.1")
    assert result.from_version == "0.5.0"
    assert result.to_version == "0.5.1"
    assert current_version(target) == "0.5.1"


def test_upgrade_refuses_when_not_installed(tmp_path: Path):
    src = _mk(tmp_path / "s", {"a.py": "x"})
    with pytest.raises(UpgradeError, match="no installed version"):
        upgrade_package(src, target_root=tmp_path / "t",
                        new_version="0.5.0")


def test_upgrade_refuses_same_version(tmp_path: Path):
    src = _mk(tmp_path / "s", {"a.py": "x"})
    target = tmp_path / "t"
    install_package(src, target_root=target, version="0.5.0")
    with pytest.raises(UpgradeError, match="already on"):
        upgrade_package(src, target_root=target, new_version="0.5.0")


# ---------------------------------------------------------------------------
# Cross-major requires migration_fn
# ---------------------------------------------------------------------------


def test_cross_major_refuses_without_migration(tmp_path: Path):
    src = _mk(tmp_path / "s", {"a.py": "x"})
    target = tmp_path / "t"
    install_package(src, target_root=target, version="0.5.0")
    with pytest.raises(UpgradeError, match="cross-major"):
        upgrade_package(src, target_root=target, new_version="1.0.0")


def test_cross_major_with_migration_succeeds(tmp_path: Path):
    src1 = _mk(tmp_path / "s1", {"a.py": "old"})
    src2 = _mk(tmp_path / "s2", {"a.py": "new"})
    target = tmp_path / "t"
    install_package(src1, target_root=target, version="0.5.0")

    calls: list[str] = []

    def migrate() -> dict:
        calls.append("ran")
        return {"events_migrated": 100, "schema": "v0.5 -> v1.0"}

    result = upgrade_package(
        src2, target_root=target, new_version="1.0.0",
        migration_fn=migrate,
    )
    assert result.migration_applied is True
    assert result.migration_manifest == {
        "events_migrated": 100, "schema": "v0.5 -> v1.0",
    }
    assert calls == ["ran"]
    assert current_version(target) == "1.0.0"


def test_cross_major_migration_failure_aborts_before_install(tmp_path: Path):
    src1 = _mk(tmp_path / "s1", {"a.py": "old"})
    src2 = _mk(tmp_path / "s2", {"a.py": "new"})
    target = tmp_path / "t"
    install_package(src1, target_root=target, version="0.5.0")

    def bad_migration():
        raise RuntimeError("migration script exploded")

    with pytest.raises(UpgradeError, match="exploded"):
        upgrade_package(
            src2, target_root=target, new_version="1.0.0",
            migration_fn=bad_migration,
        )
    # Pointer NOT flipped
    assert current_version(target) == "0.5.0"


def test_migration_must_return_dict(tmp_path: Path):
    src1 = _mk(tmp_path / "s1", {"a.py": "1"})
    src2 = _mk(tmp_path / "s2", {"a.py": "2"})
    target = tmp_path / "t"
    install_package(src1, target_root=target, version="0.5.0")

    def bad_return():
        return "not a dict"

    with pytest.raises(UpgradeError, match="manifest of transformations"):
        upgrade_package(src2, target_root=target, new_version="1.0.0",
                         migration_fn=bad_return)


# ---------------------------------------------------------------------------
# Q2 scan pre / post
# ---------------------------------------------------------------------------


def test_pre_q2_failure_blocks_upgrade(tmp_path: Path):
    src = _mk(tmp_path / "s", {"a.py": "x"})
    target = tmp_path / "t"
    install_package(src, target_root=target, version="0.5.0")
    with pytest.raises(UpgradeError, match="pre-upgrade Q2"):
        upgrade_package(
            src, target_root=target, new_version="0.5.1",
            q2_scan_fn=lambda: False,
        )
    assert current_version(target) == "0.5.0"


def test_post_q2_failure_rolls_pointer_back(tmp_path: Path):
    src1 = _mk(tmp_path / "s1", {"a.py": "1"})
    src2 = _mk(tmp_path / "s2", {"a.py": "2"})
    target = tmp_path / "t"
    install_package(src1, target_root=target, version="0.5.0")

    # pre=True then post=False
    calls = {"n": 0}

    def scan() -> bool:
        calls["n"] += 1
        return calls["n"] == 1

    with pytest.raises(UpgradeError, match="post-upgrade Q2"):
        upgrade_package(
            src2, target_root=target, new_version="0.5.1",
            q2_scan_fn=scan,
        )
    # Pointer rolled back
    assert current_version(target) == "0.5.0"
    # But the new version's files DID stage (they live under .versions/0.5.1/)
    assert (target / ".versions" / "0.5.1" / "a.py").exists()


def test_successful_upgrade_runs_both_q2_scans(tmp_path: Path):
    src1 = _mk(tmp_path / "s1", {"a.py": "1"})
    src2 = _mk(tmp_path / "s2", {"a.py": "2"})
    target = tmp_path / "t"
    install_package(src1, target_root=target, version="0.5.0")

    calls = {"n": 0}

    def scan() -> bool:
        calls["n"] += 1
        return True

    result = upgrade_package(
        src2, target_root=target, new_version="0.5.1",
        q2_scan_fn=scan,
    )
    assert calls["n"] == 2   # pre + post
    assert result.pre_q2_ok is True
    assert result.post_q2_ok is True


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------


def test_malformed_version_rejected(tmp_path: Path):
    src = _mk(tmp_path / "s", {"a.py": "x"})
    target = tmp_path / "t"
    install_package(src, target_root=target, version="0.5.0")
    with pytest.raises(UpgradeError, match="cannot parse major"):
        upgrade_package(src, target_root=target, new_version="not-a-version")
