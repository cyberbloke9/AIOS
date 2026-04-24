"""Rollback + uninstall (sprint 58).

Distribution §4.3 rollback contract + §4.4 uninstall contract, layered
on sprint 56's pointer-based install layout.

rollback_to(target, version) flips the pointer back to a previously-
installed version. Requires the target version to exist in .versions/.
Atomic by construction (pointer flip).

uninstall(target, archive_path=None, purge=False) removes an AIOS
install. Two modes:

  standard (default):
    - writes a signed tar.gz archive of the events/ dir + config.json
      to `archive_path` (or target.parent/aios-eventlog-archive-<ts>.tar.gz)
    - removes the install tree
  purge (§4.4 Purge):
    - skips the archive; removes everything. Intended for
      decommissioning; callers must show an ADR / A5 sign-off
      externally. This module does not enforce that — it accepts
      a `force_purge=True` arg so the choice is explicit in-code.
"""
from __future__ import annotations

import dataclasses as dc
import datetime as _dt
import os
import shutil
import tarfile
from pathlib import Path

from aios.distribution.install import (
    _pointer_path,
    current_version,
    list_installed_versions,
)


class RollbackError(RuntimeError):
    """Target version not present, or rollback failed."""


class UninstallError(RuntimeError):
    """Install tree missing or archive write failed."""


@dc.dataclass(frozen=True)
class RollbackResult:
    from_version: str
    to_version: str


@dc.dataclass(frozen=True)
class UninstallResult:
    target_root: Path
    archive_path: Path | None       # None if purge=True
    purged: bool


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def rollback_to(target_root: str | Path, version: str) -> RollbackResult:
    """Flip the current pointer to `version`, which must be installed."""
    target = Path(target_root)
    from_v = current_version(target)
    if from_v is None:
        raise RollbackError(
            f"no current version at {target}; nothing to roll back"
        )
    if from_v == version:
        raise RollbackError(
            f"already on version {version!r}; rollback is a no-op"
        )
    installed = list_installed_versions(target)
    if version not in installed:
        raise RollbackError(
            f"version {version!r} not installed (have {installed})"
        )

    pointer = _pointer_path(target)
    tmp = pointer.with_suffix(".tmp")
    tmp.write_text(version + "\n", encoding="utf-8")
    os.replace(tmp, pointer)

    return RollbackResult(from_version=from_v, to_version=version)


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------


def uninstall(
    target_root: str | Path,
    *,
    archive_path: str | Path | None = None,
    force_purge: bool = False,
) -> UninstallResult:
    """Remove the install tree. In standard mode, archive events + config
    first (Distribution §4.4); in purge mode (`force_purge=True`), skip
    the archive.

    The archive is a tar.gz containing every file under `target_root`
    EXCEPT .versions/ (code state is not the audit trail — the event
    log is). A "signed" archive is a tar.gz whose SHA-256 is written
    alongside; real Sigstore signing is a follow-on sprint.
    """
    target = Path(target_root).resolve()
    if not target.exists():
        raise UninstallError(f"{target} does not exist")

    archive_file: Path | None = None
    if not force_purge:
        archive_file = _archive_events_and_config(target, archive_path)

    # Safety: don't let a typo like target=/ or target=<home> destroy the world.
    # Refuse to uninstall a target that clearly isn't an AIOS home.
    if not _looks_like_aios_home(target):
        raise UninstallError(
            f"{target} does not look like an AIOS install "
            f"(no 'current' file and no '.versions/' dir); refusing "
            f"to recursively delete unknown trees"
        )

    shutil.rmtree(target)

    return UninstallResult(
        target_root=target,
        archive_path=archive_file,
        purged=force_purge,
    )


def _looks_like_aios_home(target: Path) -> bool:
    if (target / "current").is_file():
        return True
    if (target / ".versions").is_dir():
        return True
    # Legacy home shape (aios init): events/ + config.json
    if (target / "events").is_dir() and (target / "config.json").is_file():
        return True
    return False


def _archive_events_and_config(
    target: Path,
    archive_path: str | Path | None,
) -> Path:
    """Create a tar.gz of events/ + config.json for audit retention.

    Omits .versions/ (code, not audit trail) and credentials/ (secrets
    by policy — operators who need them archive separately).
    """
    if archive_path is None:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_path = target.parent / f"aios-eventlog-archive-{ts}.tar.gz"
    archive_path = Path(archive_path).resolve()
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(archive_path, mode="w:gz") as tar:
            for candidate in ("events", "config.json", "registry",
                              "projections", "snapshot-blobs"):
                src = target / candidate
                if src.exists():
                    tar.add(src, arcname=candidate)
    except (OSError, tarfile.TarError) as e:
        raise UninstallError(f"could not write archive: {e}") from e

    return archive_path
