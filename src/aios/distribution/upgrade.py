"""Upgrade + migration runner (sprint 57).

Distribution §4.2 upgrade contract + §9 crash consistency. Builds on
the sprint-56 shadow-dir install. The invariants this module adds:

  - Pre-upgrade Q2 scan on the event log (§4.2 pre-condition)
  - Same-major vs cross-major policy check (§4.2)
  - Cross-major upgrades REQUIRE a `migration_fn` that runs BEFORE
    the pointer flip and whose result is a manifest of every
    transformation (§4.2 migration sub-section)
  - Post-upgrade Q2 scan of the full event log (§4.2 post-condition)
  - On any failure, the shadow dir is discarded; the prior install
    is untouched

Pointer flip is the atomic moment. Everything before is staging;
everything after is committed.
"""
from __future__ import annotations

import dataclasses as dc
from pathlib import Path
from typing import Callable

from aios.distribution.install import (
    InstallError,
    current_version,
    install_package,
)


class UpgradeError(RuntimeError):
    """Upgrade refused or failed."""


@dc.dataclass(frozen=True)
class UpgradeResult:
    from_version: str
    to_version: str
    install_dir: Path
    migration_applied: bool
    pre_q2_ok: bool
    post_q2_ok: bool
    migration_manifest: dict | None


def _parse_major(v: str) -> int:
    head = v.split(".", 1)[0]
    try:
        return int(head)
    except ValueError:
        raise UpgradeError(
            f"cannot parse major version from {v!r}; expected MAJOR.MINOR.PATCH"
        )


def upgrade_package(
    source: str | Path,
    *,
    target_root: str | Path,
    new_version: str,
    migration_fn: Callable[[], dict] | None = None,
    q2_scan_fn: Callable[[], bool] | None = None,
) -> UpgradeResult:
    """Perform an in-place upgrade from the current installed version to
    `new_version` using the sprint-56 shadow-dir install as the primitive.

    Arguments:
      source          path to the new version's files (dir or single file)
      target_root     install root (same as sprint 56)
      new_version     the version string being installed
      migration_fn    REQUIRED for cross-major upgrades. Must return a
                      manifest dict listing every transformation the
                      migration performed. Failure -> raise any exception;
                      we roll back by never flipping the pointer.
      q2_scan_fn      optional callable returning True if the event log
                      passes the Q2 state-traceability scan. Called
                      BEFORE and AFTER the install. Either check
                      returning False blocks the upgrade.

    Raises UpgradeError if the version bump is illegal, prerequisites
    fail, or the underlying install errors out.
    """
    target = Path(target_root)
    from_version = current_version(target)
    if from_version is None:
        raise UpgradeError(
            f"no installed version at {target}; use install_package "
            f"for a fresh install"
        )
    if from_version == new_version:
        raise UpgradeError(
            f"target already on version {new_version!r}; nothing to upgrade"
        )

    from_major = _parse_major(from_version)
    to_major = _parse_major(new_version)

    # §4.2 — cross-major upgrade requires a migration
    is_cross_major = from_major != to_major
    if is_cross_major and migration_fn is None:
        raise UpgradeError(
            f"cross-major upgrade {from_version} -> {new_version} requires "
            f"migration_fn per Distribution §4.2"
        )

    # §4.2 pre-condition: Q2 scan on the event log
    pre_q2 = True
    if q2_scan_fn is not None:
        pre_q2 = bool(q2_scan_fn())
        if not pre_q2:
            raise UpgradeError(
                "pre-upgrade Q2 scan failed; event log is not state-"
                "traceable — upgrade refused"
            )

    # Run migration BEFORE the install — if it fails, no pointer flip.
    migration_manifest: dict | None = None
    if migration_fn is not None:
        try:
            migration_manifest = migration_fn()
        except Exception as e:
            raise UpgradeError(
                f"migration_fn raised {type(e).__name__}: {e}; upgrade "
                f"aborted before install"
            ) from e
        if not isinstance(migration_manifest, dict):
            raise UpgradeError(
                "migration_fn must return a dict manifest of "
                "transformations; got " + type(migration_manifest).__name__
            )

    # Stage + flip pointer — atomic install primitive does this.
    try:
        result = install_package(
            source,
            target_root=target,
            version=new_version,
        )
    except InstallError as e:
        raise UpgradeError(f"install_package failed: {e}") from e

    # §4.2 post-condition Q2 scan
    post_q2 = True
    if q2_scan_fn is not None:
        post_q2 = bool(q2_scan_fn())
        if not post_q2:
            # We flipped the pointer, so we need to roll back by
            # flipping it back to the previous version.
            _rollback_pointer(target, from_version)
            raise UpgradeError(
                "post-upgrade Q2 scan failed; pointer rolled back to "
                f"{from_version!r}"
            )

    return UpgradeResult(
        from_version=from_version,
        to_version=new_version,
        install_dir=result.install_dir,
        migration_applied=migration_fn is not None,
        pre_q2_ok=pre_q2,
        post_q2_ok=post_q2,
        migration_manifest=migration_manifest,
    )


def _rollback_pointer(target: Path, previous: str) -> None:
    """Emergency pointer rollback — used when post-Q2 fails."""
    import os
    pointer = target / "current"
    tmp = pointer.with_suffix(".tmp")
    tmp.write_text(previous + "\n", encoding="utf-8")
    os.replace(tmp, pointer)
