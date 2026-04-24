"""TUF 4-role chain walk (sprint 64).

Runtime Protocol §6.2 — the four TUF roles form a chain:

    root (threshold of offline-held keys)
      |
      +-- authorizes keys + thresholds for:
             targets, snapshot, timestamp
      |
    targets  — signs concrete artifacts (the release data itself)
    snapshot — commits to the current targets version + hash
    timestamp — commits to the current snapshot version + hash

Sprint 53 gave us SignedMetadata + verify_signed_metadata for a single
role. This module walks the chain: verify root with known keys, extract
per-role TufRoleSpec from root's payload, verify each lower role with
its role-specific keys, and check the cross-references.

Staleness + freshness (sprint 65) layer on top of this module.
"""
from __future__ import annotations

import dataclasses as dc
from typing import Sequence

from aios.distribution.tuf import (
    SignedMetadata,
    TufKey,
    TufRoleSpec,
    TufVerificationError,
    verify_signed_metadata,
)


class TufChainError(TufVerificationError):
    """Chain walk failed — a cross-reference is inconsistent."""


@dc.dataclass(frozen=True)
class TufChainReport:
    """Outcome of a full chain walk."""
    root_ok: bool
    targets_ok: bool
    snapshot_ok: bool
    timestamp_ok: bool
    targets_version: int
    snapshot_version: int
    timestamp_version: int
    targets_in_root: bool
    snapshot_references_targets: bool
    timestamp_references_snapshot: bool


def verify_tuf_chain(
    *,
    root: SignedMetadata,
    targets: SignedMetadata,
    snapshot: SignedMetadata,
    timestamp: SignedMetadata,
    known_root_keys: dict[str, TufKey],
) -> TufChainReport:
    """Verify the 4-role chain using `known_root_keys` as the anchor.

    Raises TufVerificationError (or TufChainError) on any mismatch.
    Returns a report on success.

    Flow:
      1. Verify root signatures against known_root_keys using the
         role spec EMBEDDED in root.signed. This bootstraps trust —
         a caller must have acquired known_root_keys from the §6.3
         multi-channel bootstrap anchor first.
      2. Extract each lower role's authorized keyids + threshold
         from root.signed.roles.
      3. Verify targets/snapshot/timestamp using their role-scoped
         keys + the global `known_root_keys` lookup (keyid -> TufKey).
      4. Check cross-references:
         snapshot.signed.meta['targets.json'].version == targets.version
         timestamp.signed.meta['snapshot.json'].version == snapshot.version
    """
    if root.role_type != "root":
        raise TufChainError(
            f"expected root metadata, got role_type={root.role_type!r}"
        )
    if targets.role_type != "targets":
        raise TufChainError(
            f"expected targets metadata, got {targets.role_type!r}"
        )
    if snapshot.role_type != "snapshot":
        raise TufChainError(
            f"expected snapshot metadata, got {snapshot.role_type!r}"
        )
    if timestamp.role_type != "timestamp":
        raise TufChainError(
            f"expected timestamp metadata, got {timestamp.role_type!r}"
        )

    # --- 1. Root --------------------------------------------------------
    root_spec = _extract_role_spec(root.signed, "root")
    verify_signed_metadata(root, keys=known_root_keys, role_spec=root_spec)

    # --- 2. Parse per-role specs from root's payload --------------------
    targets_spec = _extract_role_spec(root.signed, "targets")
    snapshot_spec = _extract_role_spec(root.signed, "snapshot")
    timestamp_spec = _extract_role_spec(root.signed, "timestamp")

    # Extract the key ring declared by root — keys[].keyid -> TufKey.
    declared_keys = _extract_keys(root.signed)
    # Use declared keys where available; fall back to known_root_keys
    # for root ids. (Real TUF allows root-side keys for root role only;
    # for M6 we accept both.)
    keys: dict[str, TufKey] = {**known_root_keys, **declared_keys}

    # --- 3. Verify lower roles -----------------------------------------
    verify_signed_metadata(targets, keys=keys, role_spec=targets_spec)
    verify_signed_metadata(snapshot, keys=keys, role_spec=snapshot_spec)
    verify_signed_metadata(timestamp, keys=keys, role_spec=timestamp_spec)

    # --- 4. Cross-references -------------------------------------------
    targets_version = int(targets.signed.get("version", 0))
    snapshot_version = int(snapshot.signed.get("version", 0))
    timestamp_version = int(timestamp.signed.get("version", 0))

    snapshot_meta = snapshot.signed.get("meta") or {}
    if not isinstance(snapshot_meta, dict):
        raise TufChainError("snapshot.signed.meta must be a mapping")
    targets_ref = snapshot_meta.get("targets.json") or {}
    snapshot_refs_targets = (
        int(targets_ref.get("version", -1)) == targets_version
        if isinstance(targets_ref, dict)
        else False
    )
    if not snapshot_refs_targets:
        raise TufChainError(
            f"snapshot.meta['targets.json'].version does not match "
            f"targets.version={targets_version}"
        )

    timestamp_meta = timestamp.signed.get("meta") or {}
    if not isinstance(timestamp_meta, dict):
        raise TufChainError("timestamp.signed.meta must be a mapping")
    snapshot_ref = timestamp_meta.get("snapshot.json") or {}
    timestamp_refs_snapshot = (
        int(snapshot_ref.get("version", -1)) == snapshot_version
        if isinstance(snapshot_ref, dict)
        else False
    )
    if not timestamp_refs_snapshot:
        raise TufChainError(
            f"timestamp.meta['snapshot.json'].version does not match "
            f"snapshot.version={snapshot_version}"
        )

    # `targets_in_root` — the root's roles map must declare targets
    targets_in_root = "targets" in (root.signed.get("roles") or {})

    return TufChainReport(
        root_ok=True,
        targets_ok=True,
        snapshot_ok=True,
        timestamp_ok=True,
        targets_version=targets_version,
        snapshot_version=snapshot_version,
        timestamp_version=timestamp_version,
        targets_in_root=targets_in_root,
        snapshot_references_targets=True,
        timestamp_references_snapshot=True,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_role_spec(signed: dict, role: str) -> TufRoleSpec:
    roles = signed.get("roles") or {}
    if role not in roles:
        raise TufChainError(f"root metadata has no '{role}' role entry")
    entry = roles[role]
    keyids = tuple(entry.get("keyids") or ())
    threshold = int(entry.get("threshold", 0))
    if not keyids or threshold < 1:
        raise TufChainError(
            f"role {role!r} has empty keyids or invalid threshold"
        )
    return TufRoleSpec(keyids=keyids, threshold=threshold)


def _extract_keys(signed: dict) -> dict[str, TufKey]:
    keys_raw = signed.get("keys") or {}
    out: dict[str, TufKey] = {}
    for keyid, entry in keys_raw.items():
        if not isinstance(entry, dict):
            continue
        pk_raw = entry.get("public_key")
        if not isinstance(pk_raw, (bytes, bytearray)):
            continue
        try:
            out[keyid] = TufKey(keyid=keyid, public_key=bytes(pk_raw))
        except Exception:
            continue
    return out
