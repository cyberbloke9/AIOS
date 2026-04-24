"""RFC 6962 Merkle tree + §1.5 batch emission (sprint 60).

Runtime Protocol §1.5: "Every N frames (or at segment close), the
appender computes a Merkle tree over the frame hashes in that batch,
and emits a special frame of kind 'merkle.batch' whose payload
contains batch_start_seq, batch_end_seq, leaf_count, merkle_root."

§1.5 also says: "The Merkle structure follows RFC 6962 precisely
(leaves hashed with a 0x00 prefix, internal nodes with a 0x01 prefix;
non-power-of-two trees use RFC 6962's specific padding rule). This
means third-party Merkle clients written against RFC 6962 can verify
AIOS batch roots without AIOS-specific tooling."

This module is the RFC 6962 algorithm — pure, deterministic, stdlib.
EventLog.create_merkle_batch (added here) is the emission path.
"""
from __future__ import annotations

import hashlib
from typing import Sequence

# RFC 6962 §2.1 domain-separation prefixes
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# §1.5 default batch size
DEFAULT_BATCH_SIZE = 1000


class MerkleError(ValueError):
    """Structural error: wrong-width hashes, empty tree where forbidden, etc."""


def leaf_hash(data: bytes) -> bytes:
    """Hash a leaf: SHA-256(0x00 || data). RFC 6962 §2.1."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash an internal node: SHA-256(0x01 || left || right)."""
    if len(left) != 32 or len(right) != 32:
        raise MerkleError(
            f"node children must be 32-byte SHA-256 digests, got "
            f"{len(left)} and {len(right)}"
        )
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    """Compute the RFC 6962 Merkle Tree Hash (MTH) over `leaves`.

    Leaves are the RAW data bytes the MTH hashes (NOT pre-hashed) —
    for frame batches, pass `frame.to_cbor()` or the equivalent.
    An empty list returns the hash of the empty string per RFC 6962.
    """
    n = len(leaves)
    if n == 0:
        # MTH({}) = SHA-256()
        return hashlib.sha256().digest()
    if n == 1:
        return leaf_hash(leaves[0])

    # Split at the largest power of 2 less than n
    k = 1
    while k * 2 < n:
        k *= 2

    left = merkle_tree_hash(leaves[:k])
    right = merkle_tree_hash(leaves[k:])
    return node_hash(left, right)


def merkle_tree_hash_of_hashes(leaf_hashes: Sequence[bytes]) -> bytes:
    """MTH where the leaves are ALREADY the RFC 6962 leaf hashes.

    Frame batches use this path — the caller holds frame_hash() values
    directly and skips the LEAF_PREFIX step.

    For n >= 2 this is equivalent to the recursion over already-hashed
    leaves; for n == 1 it returns that leaf hash as-is; for n == 0 it
    returns SHA-256(empty) (same as merkle_tree_hash).
    """
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256().digest()
    for i, h in enumerate(leaf_hashes):
        if len(h) != 32:
            raise MerkleError(
                f"leaf_hashes[{i}] is {len(h)} bytes, need 32"
            )
    if n == 1:
        return leaf_hashes[0]

    k = 1
    while k * 2 < n:
        k *= 2
    left = merkle_tree_hash_of_hashes(leaf_hashes[:k])
    right = merkle_tree_hash_of_hashes(leaf_hashes[k:])
    return node_hash(left, right)
