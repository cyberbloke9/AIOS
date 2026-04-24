"""Tests for atomic shadow-dir install (sprint 56)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.distribution.install import (
    InstallError,
    current_version,
    install_package,
    list_installed_versions,
)


def _make_source(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Basic install
# ---------------------------------------------------------------------------


def test_install_creates_version_dir_and_pointer(tmp_path: Path):
    src = _make_source(tmp_path / "src",
                        {"a.py": "A", "pkg/b.py": "B"})
    target = tmp_path / "target"
    result = install_package(src, target_root=target, version="0.5.0")
    assert result.install_dir.is_dir()
    assert (target / ".versions" / "0.5.0" / "a.py").read_text() == "A"
    assert current_version(target) == "0.5.0"
    assert result.previous_version is None


def test_install_records_previous_version(tmp_path: Path):
    src = _make_source(tmp_path / "src", {"a.py": "A"})
    target = tmp_path / "target"
    install_package(src, target_root=target, version="0.5.0")
    result2 = install_package(src, target_root=target, version="0.6.0")
    assert result2.previous_version == "0.5.0"
    assert current_version(target) == "0.6.0"


def test_install_preserves_all_installed_versions(tmp_path: Path):
    """After two installs, both versions remain on disk under .versions/."""
    src1 = _make_source(tmp_path / "s1", {"a.py": "A1"})
    src2 = _make_source(tmp_path / "s2", {"a.py": "A2"})
    target = tmp_path / "target"
    install_package(src1, target_root=target, version="0.5.0")
    install_package(src2, target_root=target, version="0.6.0")
    assert list_installed_versions(target) == ["0.5.0", "0.6.0"]
    # And the non-current version's files are intact
    assert (target / ".versions" / "0.5.0" / "a.py").read_text() == "A1"
    assert (target / ".versions" / "0.6.0" / "a.py").read_text() == "A2"


def test_pointer_is_a_text_file(tmp_path: Path):
    """Using a pointer file (not a symlink) makes this portable on
    Windows without developer mode."""
    src = _make_source(tmp_path / "s", {"a.py": "A"})
    target = tmp_path / "t"
    install_package(src, target_root=target, version="0.5.0")
    pointer = target / "current"
    assert pointer.is_file()
    assert pointer.read_text().strip() == "0.5.0"


def test_current_version_none_on_empty_target(tmp_path: Path):
    assert current_version(tmp_path) is None


def test_list_installed_empty_on_empty_target(tmp_path: Path):
    assert list_installed_versions(tmp_path) == []


# ---------------------------------------------------------------------------
# Failure + force semantics
# ---------------------------------------------------------------------------


def test_install_refuses_duplicate_version_without_force(tmp_path: Path):
    src = _make_source(tmp_path / "s", {"a.py": "A"})
    target = tmp_path / "t"
    install_package(src, target_root=target, version="0.5.0")
    with pytest.raises(InstallError, match="already installed"):
        install_package(src, target_root=target, version="0.5.0")


def test_install_force_overwrites_existing_version(tmp_path: Path):
    v1 = _make_source(tmp_path / "s1", {"a.py": "OLD"})
    target = tmp_path / "t"
    install_package(v1, target_root=target, version="0.5.0")

    v2 = _make_source(tmp_path / "s2", {"a.py": "NEW"})
    install_package(v2, target_root=target, version="0.5.0", force=True)
    assert (target / ".versions" / "0.5.0" / "a.py").read_text() == "NEW"


def test_install_rejects_missing_source(tmp_path: Path):
    with pytest.raises(InstallError, match="not found"):
        install_package(
            tmp_path / "does-not-exist",
            target_root=tmp_path / "t",
            version="0.5.0",
        )


def test_install_accepts_single_file_source(tmp_path: Path):
    f = tmp_path / "solo.py"
    f.write_text("X", encoding="utf-8")
    target = tmp_path / "t"
    result = install_package(f, target_root=target, version="0.5.0")
    assert (result.install_dir / "solo.py").read_text() == "X"


# ---------------------------------------------------------------------------
# Atomicity
# ---------------------------------------------------------------------------


def test_pointer_flip_is_atomic(tmp_path: Path):
    """After a successful install the current pointer is ONE of the
    installed versions — never in a half-written state."""
    src1 = _make_source(tmp_path / "s1", {"a.py": "A1"})
    src2 = _make_source(tmp_path / "s2", {"a.py": "A2"})
    target = tmp_path / "t"
    install_package(src1, target_root=target, version="0.5.0")
    # mid-test, pointer is "0.5.0"
    assert current_version(target) == "0.5.0"
    install_package(src2, target_root=target, version="0.6.0")
    # post-install pointer is exactly "0.6.0" — no tmp file left
    assert current_version(target) == "0.6.0"
    assert not (target / "current.tmp").exists()


def test_staging_dir_cleaned_on_success(tmp_path: Path):
    """After install, no .staging-* directories remain."""
    src = _make_source(tmp_path / "s", {"a.py": "A"})
    target = tmp_path / "t"
    install_package(src, target_root=target, version="0.5.0")
    stragglers = list((target / ".versions").glob(".staging-*"))
    assert stragglers == []
