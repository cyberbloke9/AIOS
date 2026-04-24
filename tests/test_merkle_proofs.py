"""Tests for RFC 6962 Merkle inclusion proofs (sprint 61)."""
from __future__ import annotations

import hashlib

import pytest

from aios.runtime.merkle import (
    MerkleError,
    build_inclusion_proof,
    merkle_tree_hash_of_hashes,
    verify_inclusion,
)


def _leaves(n: int) -> list[bytes]:
    return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]


# ---------------------------------------------------------------------------
# build_inclusion_proof
# ---------------------------------------------------------------------------


def test_single_leaf_has_empty_proof():
    leaves = _leaves(1)
    assert build_inclusion_proof(leaves, 0) == []


def test_proof_length_matches_tree_depth():
    # Power-of-two tree of 8 leaves: depth 3 -> proof length 3
    leaves = _leaves(8)
    for i in range(8):
        assert len(build_inclusion_proof(leaves, i)) == 3


def test_proof_length_power_of_two_four():
    leaves = _leaves(4)
    for i in range(4):
        assert len(build_inclusion_proof(leaves, i)) == 2


def test_build_rejects_empty_tree():
    with pytest.raises(MerkleError, match="empty"):
        build_inclusion_proof([], 0)


def test_build_rejects_out_of_range_index():
    leaves = _leaves(4)
    with pytest.raises(MerkleError, match="out of range"):
        build_inclusion_proof(leaves, 4)
    with pytest.raises(MerkleError, match="out of range"):
        build_inclusion_proof(leaves, -1)


def test_build_rejects_non_32_byte_leaf():
    with pytest.raises(MerkleError):
        build_inclusion_proof([b"short"], 0)


# ---------------------------------------------------------------------------
# verify_inclusion — happy paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 11, 16, 100, 257])
def test_round_trip_every_index_every_size(n: int):
    leaves = _leaves(n)
    root = merkle_tree_hash_of_hashes(leaves)
    for i in range(n):
        proof = build_inclusion_proof(leaves, i)
        assert verify_inclusion(
            leaf_hash=leaves[i], index=i, tree_size=n,
            proof=proof, root=root,
        ) is True


# ---------------------------------------------------------------------------
# verify_inclusion — unhappy paths
# ---------------------------------------------------------------------------


def test_tampered_leaf_rejected():
    leaves = _leaves(8)
    root = merkle_tree_hash_of_hashes(leaves)
    proof = build_inclusion_proof(leaves, 3)
    wrong_leaf = hashlib.sha256(b"forged").digest()
    assert verify_inclusion(
        leaf_hash=wrong_leaf, index=3, tree_size=8,
        proof=proof, root=root,
    ) is False


def test_tampered_proof_element_rejected():
    leaves = _leaves(8)
    root = merkle_tree_hash_of_hashes(leaves)
    proof = build_inclusion_proof(leaves, 3)
    bad = bytearray(proof[0])
    bad[0] ^= 0x01
    tampered_proof = [bytes(bad)] + list(proof[1:])
    assert verify_inclusion(
        leaf_hash=leaves[3], index=3, tree_size=8,
        proof=tampered_proof, root=root,
    ) is False


def test_tampered_root_rejected():
    leaves = _leaves(4)
    root = merkle_tree_hash_of_hashes(leaves)
    proof = build_inclusion_proof(leaves, 1)
    bad_root = bytearray(root)
    bad_root[0] ^= 0x01
    assert verify_inclusion(
        leaf_hash=leaves[1], index=1, tree_size=4,
        proof=proof, root=bytes(bad_root),
    ) is False


def test_wrong_index_rejected():
    """Proof for index 3 used at index 2 should fail."""
    leaves = _leaves(8)
    root = merkle_tree_hash_of_hashes(leaves)
    proof = build_inclusion_proof(leaves, 3)
    assert verify_inclusion(
        leaf_hash=leaves[3], index=2, tree_size=8,
        proof=proof, root=root,
    ) is False


def test_verify_rejects_invalid_inputs():
    leaves = _leaves(4)
    root = merkle_tree_hash_of_hashes(leaves)
    proof = build_inclusion_proof(leaves, 0)
    # Leaf hash wrong size
    with pytest.raises(MerkleError):
        verify_inclusion(
            leaf_hash=b"short", index=0, tree_size=4,
            proof=proof, root=root,
        )
    # Root wrong size
    with pytest.raises(MerkleError):
        verify_inclusion(
            leaf_hash=leaves[0], index=0, tree_size=4,
            proof=proof, root=b"short",
        )
    # tree_size <= 0
    with pytest.raises(MerkleError):
        verify_inclusion(
            leaf_hash=leaves[0], index=0, tree_size=0,
            proof=proof, root=root,
        )
    # Index out of range
    with pytest.raises(MerkleError):
        verify_inclusion(
            leaf_hash=leaves[0], index=99, tree_size=4,
            proof=proof, root=root,
        )
    # Proof element wrong size
    with pytest.raises(MerkleError):
        verify_inclusion(
            leaf_hash=leaves[0], index=0, tree_size=4,
            proof=[b"short"], root=root,
        )


def test_proof_from_wrong_tree_rejected():
    leaves_a = _leaves(8)
    leaves_b = [hashlib.sha256(f"other-{i}".encode()).digest() for i in range(8)]
    root_a = merkle_tree_hash_of_hashes(leaves_a)
    proof_b = build_inclusion_proof(leaves_b, 3)
    assert verify_inclusion(
        leaf_hash=leaves_a[3], index=3, tree_size=8,
        proof=proof_b, root=root_a,
    ) is False


def test_empty_proof_works_only_for_single_leaf():
    """Empty proof is valid only when tree_size == 1 and leaf == root."""
    single_leaf = hashlib.sha256(b"only").digest()
    assert verify_inclusion(
        leaf_hash=single_leaf, index=0, tree_size=1,
        proof=[], root=single_leaf,
    ) is True
    # Empty proof on a 4-leaf tree can't recover the root
    leaves = _leaves(4)
    root = merkle_tree_hash_of_hashes(leaves)
    assert verify_inclusion(
        leaf_hash=leaves[0], index=0, tree_size=4,
        proof=[], root=root,
    ) is False
