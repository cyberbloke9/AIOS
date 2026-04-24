"""TUF role metadata + threshold signature verification (sprint 53).

Runtime Protocol §6.2 names the four TUF roles and the threshold-
signature model that makes root compromise recoverable below threshold.
This module implements a small, honest subset:

  - Role dataclasses: Root, Targets, Snapshot, Timestamp
  - SignedMetadata carrier with multiple Ed25519 signatures
  - canonical_sign_bytes() produces deterministic CBOR of the `signed`
    payload so signatures are reproducible across implementations
  - verify_signed_metadata() enforces a role-declared threshold of
    authorized keys

What this module does NOT do (belongs to a later sprint):

  - Live network fetch + staleness checks against a TUF repository
  - Snapshot / Timestamp role chaining (present as data structures;
    the verification of the FULL 4-role tree is sprint 55 territory)
  - Key rotation ADR machinery (§6.4)

Runtime Protocol §9.1 still applies: Ed25519 keys, SHA-256 hashes.
`cryptography` is required — this module lives under the `enterprise`
extra's import graph.
"""
from __future__ import annotations

import dataclasses as dc
import hashlib
from typing import Literal

from aios.enterprise.signing import (
    Ed25519Verifier,
    SignatureVerificationError,
    cryptography_available,
)
from aios.runtime.event_log import cbor_encode

RoleType = Literal["root", "targets", "snapshot", "timestamp"]
ROLE_TYPES: tuple[RoleType, ...] = ("root", "targets", "snapshot", "timestamp")


class TufMetadataError(ValueError):
    """Root / role metadata is malformed."""


class TufVerificationError(ValueError):
    """Signed metadata failed threshold signature verification."""


# ---------------------------------------------------------------------------
# Keys + role config
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class TufKey:
    """An Ed25519 public key known to the root role."""
    keyid: str                 # hex of sha256(public_key_bytes), first 16 chars
    public_key: bytes          # 32-byte Ed25519

    @classmethod
    def from_public_bytes(cls, public_key: bytes) -> "TufKey":
        if len(public_key) != 32:
            raise TufMetadataError(
                f"Ed25519 public key must be 32 bytes, got {len(public_key)}"
            )
        keyid = hashlib.sha256(public_key).hexdigest()[:16]
        return cls(keyid=keyid, public_key=public_key)


@dc.dataclass(frozen=True)
class TufRoleSpec:
    """Per-role authorized keys + threshold."""
    keyids: tuple[str, ...]
    threshold: int

    def __post_init__(self):
        if self.threshold < 1:
            raise TufMetadataError(
                f"threshold must be >= 1, got {self.threshold}"
            )
        if self.threshold > len(self.keyids):
            raise TufMetadataError(
                f"threshold={self.threshold} exceeds keyid count "
                f"{len(self.keyids)}"
            )


# ---------------------------------------------------------------------------
# Role content payloads
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class RootContent:
    """§6.2 root role content."""
    spec_version: str
    version: int
    expires_iso: str
    keys: dict[str, TufKey]          # keyid -> TufKey
    roles: dict[RoleType, TufRoleSpec]


@dc.dataclass(frozen=True)
class TargetHash:
    algo: Literal["sha256"]
    hex: str


@dc.dataclass(frozen=True)
class TargetEntry:
    """One signed artifact the Targets role attests."""
    path: str                        # package-relative filename / URL
    length: int
    hashes: tuple[TargetHash, ...]


@dc.dataclass(frozen=True)
class TargetsContent:
    spec_version: str
    version: int
    expires_iso: str
    targets: dict[str, TargetEntry]


@dc.dataclass(frozen=True)
class SnapshotContent:
    spec_version: str
    version: int
    expires_iso: str
    meta: dict[str, dict]   # {"targets.json": {"version": N, "hash": "..."}, ...}


@dc.dataclass(frozen=True)
class TimestampContent:
    spec_version: str
    version: int
    expires_iso: str
    meta: dict[str, dict]   # {"snapshot.json": {"version": N, "hash": "..."}}


# ---------------------------------------------------------------------------
# Signed metadata carrier
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class TufSignature:
    keyid: str
    sig: bytes               # 64-byte Ed25519


@dc.dataclass(frozen=True)
class SignedMetadata:
    role_type: RoleType
    signed: dict             # canonical payload (CBOR-encodable)
    signatures: tuple[TufSignature, ...]

    def canonical_sign_bytes(self) -> bytes:
        """Deterministic bytes the signatures cover.

        Uses the same deterministic-CBOR encoder as the event log so
        cross-implementation signatures are reproducible.
        """
        return cbor_encode({"role": self.role_type, "signed": self.signed})


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_signed_metadata(
    signed: SignedMetadata,
    *,
    keys: dict[str, TufKey],
    role_spec: TufRoleSpec,
) -> int:
    """Verify `signed` against the authorized keys + threshold.

    Returns the number of valid signatures (always >= role_spec.threshold
    on success). Raises TufVerificationError on any failure — threshold
    not met, signatures from unauthorized keys ignored but do not
    count toward the threshold, duplicate keyids count once.

    §6.2 threshold model: compromising the threshold of root keys
    requires compromising `threshold` independent signers. Fewer than
    `threshold` stolen keys cannot produce valid root metadata.
    """
    if not cryptography_available():
        raise TufVerificationError(
            "cryptography package not installed; TUF signature "
            "verification requires the enterprise extra"
        )

    payload = signed.canonical_sign_bytes()
    authorized_ids = set(role_spec.keyids)
    verified: set[str] = set()

    for sig in signed.signatures:
        if sig.keyid not in authorized_ids:
            continue  # not authorized for this role — ignore, don't error
        if sig.keyid in verified:
            continue  # duplicate — counts once
        key = keys.get(sig.keyid)
        if key is None:
            # authorized in the role spec but not in the key ring -
            # ignore (the role spec and the key ring should always agree;
            # disagreement is a root-metadata bug the caller should fix)
            continue
        verifier = Ed25519Verifier(key.public_key)
        try:
            verifier.verify(payload, sig.sig)
        except SignatureVerificationError:
            continue  # bad signature — don't count
        verified.add(sig.keyid)

    if len(verified) < role_spec.threshold:
        raise TufVerificationError(
            f"{signed.role_type} metadata has only {len(verified)} valid "
            f"signature(s); threshold is {role_spec.threshold} "
            f"(authorized keyids: {sorted(authorized_ids)}, "
            f"verified: {sorted(verified)})"
        )
    return len(verified)


def root_metadata_fingerprint(signed_root: SignedMetadata) -> str:
    """SHA-256 of the canonical sign bytes — the fingerprint operators
    publish on multiple channels per §6.3."""
    return hashlib.sha256(signed_root.canonical_sign_bytes()).hexdigest()
