"""Root key rotation §6.4 (sprint 66).

Runtime Protocol §6.4:
  "Root key rotation:
     1. The existing root role signs a new root metadata document that
        lists the new root keys alongside the old ones.
     2. The new root metadata is published on all channels.
     3. After a transition period, a subsequent rotation drops the
        old keys.
     4. Existing hosts follow the chain; new hosts bootstrap against
        the latest metadata."

verify_root_rotation(old_root, new_root) implements step 1 checking —
it confirms a new root was signed by the OLD root's threshold (which
proves the rotation was authorized) AND that the new root is
self-consistent under its own declared keys + threshold.

A caller that accepts the rotation then uses the new root's keys for
subsequent verify_tuf_chain calls. §6.3's multi-channel bootstrap
anchor is still the source of trust for the FIRST root metadata; this
module handles successive rotations thereafter.
"""
from __future__ import annotations

import dataclasses as dc

from aios.distribution.tuf import (
    SignedMetadata,
    TufKey,
    TufVerificationError,
    verify_signed_metadata,
)
from aios.distribution.tuf_chain import (
    TufChainError,
    _extract_keys,
    _extract_role_spec,
)


class TufRotationError(TufVerificationError):
    """Root rotation refused — new root not signed by old, or new root
    not self-consistent."""


@dc.dataclass(frozen=True)
class RotationReport:
    old_version: int
    new_version: int
    signed_by_old: int          # signature count from old root keys
    signed_by_new: int          # signature count from new root keys
    new_keys: dict[str, TufKey] # the post-rotation key ring
    added_keyids: tuple[str, ...]
    removed_keyids: tuple[str, ...]


def verify_root_rotation(
    *,
    old_root: SignedMetadata,
    new_root: SignedMetadata,
) -> RotationReport:
    """Verify a §6.4 root rotation from `old_root` to `new_root`.

    Raises TufRotationError on refusal; returns a RotationReport on
    success. The report's `new_keys` is the key ring the caller should
    adopt for subsequent chain walks.
    """
    if old_root.role_type != "root" or new_root.role_type != "root":
        raise TufRotationError(
            "both arguments must be role_type='root' metadata"
        )
    old_version = int(old_root.signed.get("version", 0))
    new_version = int(new_root.signed.get("version", 0))
    if new_version <= old_version:
        raise TufRotationError(
            f"new root version {new_version} must be > old "
            f"version {old_version}"
        )

    # Step 1: verify old root is itself valid under its own declared
    # keys + threshold. The caller should have done this already via
    # the bootstrap anchor, but we re-verify to prevent accepting a
    # fabricated "old root" that was never legitimate.
    old_spec = _extract_role_spec(old_root.signed, "root")
    old_keys = _extract_keys(old_root.signed)
    try:
        verify_signed_metadata(old_root, keys=old_keys, role_spec=old_spec)
    except TufVerificationError as e:
        raise TufRotationError(
            f"old root not self-consistent: {e}"
        ) from e

    # Step 2: new root must carry signatures from the OLD root's keys
    # meeting the OLD threshold — proves the rotation was authorized.
    try:
        count_old = verify_signed_metadata(
            new_root, keys=old_keys, role_spec=old_spec,
        )
    except TufVerificationError as e:
        raise TufRotationError(
            f"new root not signed by old root threshold: {e}"
        ) from e

    # Step 3: new root must ALSO be self-consistent — signatures from
    # the NEW root's keys meeting the NEW threshold. This prevents
    # the old root from signing a document whose NEW keys cannot
    # themselves produce valid signatures (belt-and-braces).
    new_spec = _extract_role_spec(new_root.signed, "root")
    new_keys = _extract_keys(new_root.signed)
    try:
        count_new = verify_signed_metadata(
            new_root, keys=new_keys, role_spec=new_spec,
        )
    except TufVerificationError as e:
        raise TufRotationError(
            f"new root not self-consistent under its own keys: {e}"
        ) from e

    # Report which keyids joined / left
    old_ids = set(old_keys)
    new_ids = set(new_keys)
    added = tuple(sorted(new_ids - old_ids))
    removed = tuple(sorted(old_ids - new_ids))

    return RotationReport(
        old_version=old_version,
        new_version=new_version,
        signed_by_old=count_old,
        signed_by_new=count_new,
        new_keys=new_keys,
        added_keyids=added,
        removed_keyids=removed,
    )
