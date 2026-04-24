"""Atomic shadow-dir install (sprint 56).

Distribution §4.1 install contract + §9 crash consistency:

    Install: atomic symlink to active install; partial install
    directories are discarded.

This module implements the mechanics. A release is staged into a
versioned sub-directory and the top-level pointer is switched to
reference it atomically — if the switch succeeds the install is
committed; if the machine dies mid-install the staging dir is still
there but no consumer sees it.

Why a pointer FILE instead of a symlink:
  Symlinks on Windows typically require developer mode or elevated
  privileges; pointer-file flip (os.replace) is atomic on every OS we
  target (POSIX + Windows) and needs no special privileges. A callable
  extension hook can swap in symlinks for UX where privilege permits,
  but the CORE path must not depend on it.

Layout after install:

    <target_root>/
      .versions/
        0.5.0/
          <installed files>
        0.6.0/
          <installed files>
      current          text file: "0.6.0\\n"

Refuses to re-install a version that already exists unless force=True.
"""
from __future__ import annotations

import dataclasses as dc
import os
import shutil
from pathlib import Path


class InstallError(RuntimeError):
    """Install refused or crashed mid-way."""


@dc.dataclass(frozen=True)
class InstallResult:
    target_root: Path
    version: str
    install_dir: Path         # <target>/.versions/<version>/
    previous_version: str | None


def _pointer_path(target_root: Path) -> Path:
    return target_root / "current"


def current_version(target_root: str | Path) -> str | None:
    """Return the installed-active version, or None if no install yet."""
    target = Path(target_root)
    p = _pointer_path(target)
    if not p.is_file():
        return None
    v = p.read_text(encoding="utf-8").strip()
    return v or None


def list_installed_versions(target_root: str | Path) -> list[str]:
    """List every version present under <target>/.versions/."""
    target = Path(target_root)
    d = target / ".versions"
    if not d.is_dir():
        return []
    return sorted(p.name for p in d.iterdir() if p.is_dir())


def install_package(
    source: str | Path,
    *,
    target_root: str | Path,
    version: str,
    force: bool = False,
) -> InstallResult:
    """Copy `source` into <target>/.versions/<version>/ + flip pointer.

    `source` can be a file tree (most common) or a single file (copied as
    the sole installed file — rare but supported for tests). The copy is
    non-atomic internally, but the pointer flip that makes the install
    VISIBLE is atomic.

    `force=True` reinstalls an existing version; without it, a duplicate
    raises InstallError. The caller must archive the prior install dir
    before calling with force=True if they want rollback later.
    """
    src = Path(source).resolve()
    if not src.exists():
        raise InstallError(f"source not found: {src}")

    target = Path(target_root).resolve()
    target.mkdir(parents=True, exist_ok=True)
    versions_dir = target / ".versions"
    versions_dir.mkdir(parents=True, exist_ok=True)

    install_dir = versions_dir / version
    if install_dir.exists() and not force:
        raise InstallError(
            f"version {version!r} already installed at {install_dir}; "
            f"pass force=True to reinstall (prior content will be wiped)"
        )
    if install_dir.exists() and force:
        shutil.rmtree(install_dir)

    # Stage into a shadow directory — <target>/.staging-<version>/ —
    # so a crash during the copy leaves the live install untouched.
    staging = versions_dir / f".staging-{version}"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        if src.is_dir():
            shutil.copytree(src, staging)
        else:
            staging.mkdir(parents=True)
            shutil.copy2(src, staging / src.name)
    except OSError as e:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise InstallError(f"could not stage {src} -> {staging}: {e}") from e

    # Promote staging -> final install_dir via atomic rename.
    # os.rename is atomic on POSIX and Windows when source + dest on
    # same filesystem; .versions/.staging-V and .versions/V always are.
    os.rename(staging, install_dir)

    _fsync_dir(versions_dir)

    # Flip pointer atomically
    previous = current_version(target)
    pointer = _pointer_path(target)
    pointer_tmp = pointer.with_suffix(".tmp")
    pointer_tmp.write_text(version + "\n", encoding="utf-8")
    # os.replace is atomic across POSIX and Windows.
    os.replace(pointer_tmp, pointer)
    _fsync_dir(target)

    return InstallResult(
        target_root=target,
        version=version,
        install_dir=install_dir,
        previous_version=previous,
    )


def _fsync_dir(path: Path) -> None:
    """POSIX directory fsync — no-op on Windows."""
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass   # best effort; failure here is not install-critical
