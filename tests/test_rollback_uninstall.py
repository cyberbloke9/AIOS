"""Tests for rollback + uninstall (sprint 58)."""
from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from aios.distribution.install import (
    current_version,
    install_package,
    list_installed_versions,
)
from aios.distribution.rollback import (
    RollbackError,
    UninstallError,
    rollback_to,
    uninstall,
)


def _mk(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# rollback_to
# ---------------------------------------------------------------------------


def test_rollback_flips_pointer(tmp_path: Path):
    s1 = _mk(tmp_path / "s1", {"a.py": "v1"})
    s2 = _mk(tmp_path / "s2", {"a.py": "v2"})
    target = tmp_path / "t"
    install_package(s1, target_root=target, version="0.5.0")
    install_package(s2, target_root=target, version="0.6.0")
    assert current_version(target) == "0.6.0"

    result = rollback_to(target, "0.5.0")
    assert result.from_version == "0.6.0"
    assert result.to_version == "0.5.0"
    assert current_version(target) == "0.5.0"
    # .versions/0.6.0 is still on disk
    assert "0.6.0" in list_installed_versions(target)


def test_rollback_refuses_unknown_version(tmp_path: Path):
    s = _mk(tmp_path / "s", {"a.py": "x"})
    target = tmp_path / "t"
    install_package(s, target_root=target, version="0.5.0")
    with pytest.raises(RollbackError, match="not installed"):
        rollback_to(target, "9.9.9")


def test_rollback_refuses_same_version(tmp_path: Path):
    s = _mk(tmp_path / "s", {"a.py": "x"})
    target = tmp_path / "t"
    install_package(s, target_root=target, version="0.5.0")
    with pytest.raises(RollbackError, match="no-op"):
        rollback_to(target, "0.5.0")


def test_rollback_refuses_when_no_install(tmp_path: Path):
    with pytest.raises(RollbackError, match="no current version"):
        rollback_to(tmp_path, "0.5.0")


def test_rollback_then_rollback_forward(tmp_path: Path):
    s1 = _mk(tmp_path / "s1", {"a.py": "v1"})
    s2 = _mk(tmp_path / "s2", {"a.py": "v2"})
    target = tmp_path / "t"
    install_package(s1, target_root=target, version="0.5.0")
    install_package(s2, target_root=target, version="0.6.0")
    rollback_to(target, "0.5.0")
    rollback_to(target, "0.6.0")
    assert current_version(target) == "0.6.0"


# ---------------------------------------------------------------------------
# uninstall — standard (archive)
# ---------------------------------------------------------------------------


def test_uninstall_archives_events_and_config(tmp_path: Path):
    """Simulate a full AIOS home with events + config, then uninstall."""
    target = tmp_path / "home"
    (target / "events").mkdir(parents=True)
    (target / "events" / "segment_0_OPEN.aios").write_bytes(b"fake segment")
    (target / "config.json").write_text('{"profile": "P-Local"}')
    # Minimal marker so the safety check accepts this as an AIOS home
    (target / "current").write_text("0.1.0\n")

    result = uninstall(target)
    assert not target.exists()          # install tree removed
    assert result.archive_path is not None
    assert result.archive_path.exists()
    assert result.purged is False

    # Archive should contain events/ and config.json
    with tarfile.open(result.archive_path, mode="r:gz") as tar:
        names = tar.getnames()
    assert "events" in names or any(n.startswith("events/") for n in names)
    assert "config.json" in names


def test_uninstall_custom_archive_path(tmp_path: Path):
    target = tmp_path / "home"
    (target / "events").mkdir(parents=True)
    (target / "config.json").write_text("{}")
    (target / "current").write_text("0.1.0\n")

    archive = tmp_path / "my-archive.tar.gz"
    result = uninstall(target, archive_path=archive)
    assert result.archive_path == archive.resolve()
    assert archive.exists()


def test_uninstall_omits_versions_dir_from_archive(tmp_path: Path):
    """Versioned code dirs aren't audit trail; they should not bloat the
    archive."""
    target = tmp_path / "home"
    (target / "events").mkdir(parents=True)
    (target / ".versions" / "0.5.0").mkdir(parents=True)
    (target / ".versions" / "0.5.0" / "big.bin").write_bytes(b"x" * 1024)
    (target / "config.json").write_text("{}")
    (target / "current").write_text("0.5.0\n")

    result = uninstall(target)
    with tarfile.open(result.archive_path, mode="r:gz") as tar:
        names = tar.getnames()
    assert not any(".versions" in n for n in names)


# ---------------------------------------------------------------------------
# uninstall — purge
# ---------------------------------------------------------------------------


def test_purge_skips_archive(tmp_path: Path):
    target = tmp_path / "home"
    (target / "events").mkdir(parents=True)
    (target / "config.json").write_text("{}")
    (target / "current").write_text("0.5.0\n")

    result = uninstall(target, force_purge=True)
    assert result.purged is True
    assert result.archive_path is None
    assert not target.exists()


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------


def test_uninstall_refuses_non_aios_directory(tmp_path: Path):
    """A typo like 'uninstall ~/' should not nuke the home dir."""
    not_aios = tmp_path / "home"
    not_aios.mkdir()
    (not_aios / "random.txt").write_text("hello")
    with pytest.raises(UninstallError, match="does not look like"):
        uninstall(not_aios)
    assert not_aios.exists()     # untouched


def test_uninstall_refuses_missing_target(tmp_path: Path):
    with pytest.raises(UninstallError, match="does not exist"):
        uninstall(tmp_path / "nope")


def test_uninstall_accepts_legacy_aios_home(tmp_path: Path):
    """aios init creates events/ + config.json without the pointer file;
    uninstall should still recognize it."""
    target = tmp_path / "legacy"
    (target / "events").mkdir(parents=True)
    (target / "config.json").write_text("{}")
    # No `current` pointer
    result = uninstall(target)
    assert not target.exists()
    assert result.archive_path is not None
