"""Tests for RFC 6962 Merkle + §1.5 batch emission (sprint 60)."""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from aios.runtime.event_log import EventLog
from aios.runtime.merkle import (
    DEFAULT_BATCH_SIZE,
    LEAF_PREFIX,
    MerkleError,
    NODE_PREFIX,
    leaf_hash,
    merkle_tree_hash,
    merkle_tree_hash_of_hashes,
    node_hash,
)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def test_leaf_hash_known_vector():
    """SHA-256(0x00 || "a") per RFC 6962 §2.1."""
    h = leaf_hash(b"a")
    assert h == hashlib.sha256(b"\x00a").digest()
    assert len(h) == 32


def test_node_hash_known_vector():
    left = hashlib.sha256(b"L").digest()
    right = hashlib.sha256(b"R").digest()
    assert node_hash(left, right) == hashlib.sha256(
        b"\x01" + left + right
    ).digest()


def test_node_hash_rejects_non_32_byte():
    with pytest.raises(MerkleError, match="32-byte"):
        node_hash(b"short", hashlib.sha256(b"r").digest())


# ---------------------------------------------------------------------------
# MTH — RFC 6962 test vectors
# ---------------------------------------------------------------------------


def test_mth_empty_is_sha256_empty():
    """MTH({}) = SHA-256(empty) per RFC 6962 §2.1."""
    assert merkle_tree_hash([]) == hashlib.sha256().digest()


def test_mth_single_leaf_equals_leaf_hash():
    """MTH({d}) = leaf_hash(d)."""
    assert merkle_tree_hash([b"data"]) == leaf_hash(b"data")


def test_mth_two_leaves():
    """MTH({d0, d1}) = node_hash(leaf_hash(d0), leaf_hash(d1))."""
    d0, d1 = b"a", b"b"
    expected = node_hash(leaf_hash(d0), leaf_hash(d1))
    assert merkle_tree_hash([d0, d1]) == expected


def test_mth_three_leaves_splits_at_power_of_2():
    """RFC 6962: split at largest power of 2 less than n.
    For n=3, k=2: tree = node(MTH([d0,d1]), MTH([d2]))."""
    d0, d1, d2 = b"a", b"b", b"c"
    left = merkle_tree_hash([d0, d1])
    right = merkle_tree_hash([d2])
    expected = node_hash(left, right)
    assert merkle_tree_hash([d0, d1, d2]) == expected


def test_mth_four_leaves():
    leaves = [b"a", b"b", b"c", b"d"]
    left = merkle_tree_hash(leaves[:2])
    right = merkle_tree_hash(leaves[2:])
    assert merkle_tree_hash(leaves) == node_hash(left, right)


def test_mth_five_leaves_non_power_of_2():
    """For n=5, k=4: tree = node(MTH([d0..d3]), MTH([d4]))."""
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    left = merkle_tree_hash(leaves[:4])
    right = merkle_tree_hash(leaves[4:])
    expected = node_hash(left, right)
    assert merkle_tree_hash(leaves) == expected


def test_mth_deterministic():
    leaves = [f"leaf-{i}".encode() for i in range(17)]
    a = merkle_tree_hash(leaves)
    b = merkle_tree_hash(leaves)
    assert a == b


def test_mth_of_hashes_matches_mth_for_n_ge_2():
    """merkle_tree_hash_of_hashes pre-hashes the leaves; feeding it
    the leaf_hash(d) of each d produces the same root as feeding
    merkle_tree_hash the raw d."""
    leaves = [f"d{i}".encode() for i in range(5)]
    leaf_hashes = [leaf_hash(d) for d in leaves]
    assert merkle_tree_hash_of_hashes(leaf_hashes) == merkle_tree_hash(leaves)


def test_mth_of_hashes_single_leaf_returns_as_is():
    h = leaf_hash(b"x")
    assert merkle_tree_hash_of_hashes([h]) == h


def test_mth_of_hashes_empty_matches_merkle_tree_hash_empty():
    assert merkle_tree_hash_of_hashes([]) == merkle_tree_hash([])


def test_mth_of_hashes_rejects_non_32_bytes():
    with pytest.raises(MerkleError):
        merkle_tree_hash_of_hashes([b"short", hashlib.sha256(b"x").digest()])


# ---------------------------------------------------------------------------
# EventLog.create_merkle_batch
# ---------------------------------------------------------------------------


def test_create_merkle_batch_emits_frame():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        for i in range(5):
            log.append(kind="x", actor="A1", payload={"i": i})
        batch = log.create_merkle_batch(batch_start_seq=0, batch_end_seq=4)
        assert batch.kind == "merkle.batch"
        assert batch.actor == "A5"
        assert batch.payload["batch_start_seq"] == 0
        assert batch.payload["batch_end_seq"] == 4
        assert batch.payload["leaf_count"] == 5
        assert len(batch.payload["merkle_root"]) == 32
        log.close()


def test_merkle_batch_root_matches_rfc_6962_computation():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        hashes: list[bytes] = []
        for i in range(4):
            f = log.append(kind="x", actor="A1", payload={"i": i})
            hashes.append(f.frame_hash())
        batch = log.create_merkle_batch(batch_start_seq=0, batch_end_seq=3)
        expected = merkle_tree_hash_of_hashes(hashes)
        assert batch.payload["merkle_root"] == expected
        log.close()


def test_merkle_batch_subset_of_range():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        hashes: list[bytes] = []
        for i in range(10):
            f = log.append(kind="x", actor="A1", payload={"i": i})
            hashes.append(f.frame_hash())
        batch = log.create_merkle_batch(batch_start_seq=3, batch_end_seq=7)
        expected = merkle_tree_hash_of_hashes(hashes[3:8])
        assert batch.payload["merkle_root"] == expected
        assert batch.payload["leaf_count"] == 5
        log.close()


def test_merkle_batch_refuses_empty_range():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        try:
            with pytest.raises(ValueError, match="past current head"):
                log.create_merkle_batch(batch_start_seq=5, batch_end_seq=10)
        finally:
            log.close()


def test_merkle_batch_refuses_invalid_range():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        try:
            with pytest.raises(ValueError, match="invalid range"):
                log.create_merkle_batch(batch_start_seq=5, batch_end_seq=2)
        finally:
            log.close()


def test_merkle_batch_refuses_range_beyond_head():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        try:
            with pytest.raises(ValueError, match="past current head"):
                log.create_merkle_batch(batch_start_seq=0, batch_end_seq=999)
        finally:
            log.close()


def test_merkle_batch_participates_in_hash_chain():
    """merkle.batch is just another frame — next frame's prev = batch hash."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        log.append(kind="y", actor="A1", payload={})
        batch = log.create_merkle_batch(batch_start_seq=0, batch_end_seq=1)
        after = log.append(kind="z", actor="A1", payload={})
        assert after.prev == batch.frame_hash()
        log.close()


def test_default_batch_size_constant():
    assert DEFAULT_BATCH_SIZE == 1000
