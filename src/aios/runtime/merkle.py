"""RFC 6962 Merkle tree + inclusion proofs + §1.5 batch emission.

§1.5 says AIOS uses RFC 6962 "precisely" — so third-party clients
can verify batch roots without AIOS-specific tooling. This module
keeps that contract. Stdlib only.
"""
from __future__ import annotations

import hashlib
from typing import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

DEFAULT_BATCH_SIZE = 1000


class MerkleError(ValueError):
    """Structural error: wrong-width hashes, empty tree, bad index."""


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise MerkleError(
            f"node children must be 32-byte SHA-256 digests, got "
            f"{len(left)} and {len(right)}"
        )
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


# ---------------------------------------------------------------------------
# Merkle Tree Hash (MTH)
# ---------------------------------------------------------------------------


def merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 MTH over raw leaf data."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256().digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_pow2_lt(n)
    return node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def merkle_tree_hash_of_hashes(leaf_hashes: Sequence[bytes]) -> bytes:
    """MTH where leaves are already RFC 6962 leaf-hashed."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256().digest()
    for i, h in enumerate(leaf_hashes):
        if len(h) != 32:
            raise MerkleError(f"leaf_hashes[{i}] is {len(h)} bytes, need 32")
    if n == 1:
        return leaf_hashes[0]
    k = _largest_pow2_lt(n)
    return node_hash(
        merkle_tree_hash_of_hashes(leaf_hashes[:k]),
        merkle_tree_hash_of_hashes(leaf_hashes[k:]),
    )


def _largest_pow2_lt(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


# ---------------------------------------------------------------------------
# Inclusion proofs — RFC 6962 §2.1.1
# ---------------------------------------------------------------------------


def build_inclusion_proof(
    leaf_hashes: Sequence[bytes], index: int,
) -> list[bytes]:
    """PATH(m, D[n]) per RFC 6962 §2.1.1.

    Returns the list of sibling hashes needed to recompute the root
    from leaf_hashes[index]. Leaves are already-hashed. [] for n==1.
    """
    n = len(leaf_hashes)
    if n == 0:
        raise MerkleError("cannot build inclusion proof for empty tree")
    if not 0 <= index < n:
        raise MerkleError(f"index {index} out of range for tree of size {n}")
    for i, h in enumerate(leaf_hashes):
        if len(h) != 32:
            raise MerkleError(f"leaf_hashes[{i}] is {len(h)} bytes, need 32")
    return _path(index, list(leaf_hashes))


def _path(m: int, hashes: list[bytes]) -> list[bytes]:
    n = len(hashes)
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return _path(m, hashes[:k]) + [merkle_tree_hash_of_hashes(hashes[k:])]
    return _path(m - k, hashes[k:]) + [merkle_tree_hash_of_hashes(hashes[:k])]


def verify_inclusion(
    *,
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """RFC 6962 §2.1.1 verification algorithm.

    Returns True iff the reconstructed root equals `root`. Raises
    MerkleError only on STRUCTURAL problems (wrong widths, bad
    index/tree_size, proof-length mismatch). Content mismatch
    returns False.
    """
    if len(leaf_hash) != 32 or len(root) != 32:
        raise MerkleError("leaf_hash and root must be 32 bytes")
    if tree_size <= 0:
        raise MerkleError(f"tree_size must be > 0, got {tree_size}")
    if not 0 <= index < tree_size:
        raise MerkleError(
            f"index {index} out of range for tree of size {tree_size}"
        )
    for i, h in enumerate(proof):
        if len(h) != 32:
            raise MerkleError(
                f"proof element {i} is {len(h)} bytes, need 32"
            )

    # RFC 6962 §2.1.1 audit-path verification
    fn = index                 # current node's index within its level
    sn = tree_size - 1         # last index at current level
    r = leaf_hash

    for p in proof:
        if sn == 0:
            return False       # ran out of levels before proof elements
        if (fn & 1) or (fn == sn):
            # Current node is the RIGHT child (or a right-promoted odd tail)
            r = node_hash(p, r)
            # Skip "pass-through" levels where the right sibling carries
            # up the tree without combining (RFC 6962 non-power-of-2 case)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            # LEFT child — sibling hash is on the right
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1

    # All proof elements consumed; we should be at the root
    return sn == 0 and r == root
