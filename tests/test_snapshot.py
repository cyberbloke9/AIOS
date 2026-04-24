"""Tests for §1.8 snapshot frame production (sprint 47)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios.runtime.event_log import EventLog, cbor_encode, sha256


def test_create_snapshot_emits_snapshot_frame():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="run.started", actor="A1", payload={"run_id": "r1"})
        log.append(kind="run.completed", actor="A1", payload={"run_id": "r1"})

        frame = log.create_snapshot({"projection_a": {"count": 42}})
        assert frame.kind == "snapshot"
        assert frame.actor == "A5"
        assert "as_of_seq" in frame.payload
        assert "projections" in frame.payload
        log.close()


def test_snapshot_frame_references_content_addressed_blob():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        state = {"users": ["alice", "bob"], "count": 2}
        frame = log.create_snapshot({"user_index": state})
        projections = frame.payload["projections"]
        assert "user_index" in projections
        entry = projections["user_index"]
        # state_hash must match SHA-256 of the CBOR-encoded state
        expected_hash = sha256(cbor_encode(state))
        assert entry["state_hash"] == expected_hash
        # state_ref points to <root>/snapshot-blobs/<name>-<hex>.cbor
        ref = entry["state_ref"]
        assert ref.startswith("snapshot-blobs/user_index-")
        assert ref.endswith(".cbor")
        # And the blob actually exists on disk
        assert (Path(tmp) / ref).is_file()
        log.close()


def test_snapshot_blob_hash_matches_file_bytes():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        state = {"x": [1, 2, 3]}
        frame = log.create_snapshot({"p": state})
        entry = frame.payload["projections"]["p"]
        blob_path = Path(tmp) / entry["state_ref"]
        assert sha256(blob_path.read_bytes()) == entry["state_hash"]
        log.close()


def test_multiple_projections_in_one_snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        frame = log.create_snapshot({
            "a": {"k": 1},
            "b": {"k": 2},
            "c": {"k": 3},
        })
        projs = frame.payload["projections"]
        assert set(projs) == {"a", "b", "c"}
        # Each blob written separately and hashed independently
        hashes = [projs[n]["state_hash"] for n in projs]
        assert len(set(hashes)) == 3
        log.close()


def test_snapshot_appears_in_replay():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        log.create_snapshot({"p": {"count": 5}})
        log.append(kind="y", actor="A1", payload={})
        log.close()

        log2 = EventLog(tmp)
        frames = list(log2.replay())
        log2.close()
        kinds = [f.kind for f in frames]
        assert kinds == ["x", "snapshot", "y"]


def test_snapshot_as_of_seq_points_at_last_preceding_frame():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        # Seq 0, 1, 2
        log.append(kind="a", actor="A1", payload={})
        log.append(kind="b", actor="A1", payload={})
        log.append(kind="c", actor="A1", payload={})
        frame = log.create_snapshot({"p": {"v": 1}})
        # Snapshot is now seq 3, so as_of_seq should be 2
        assert frame.seq == 3
        assert frame.payload["as_of_seq"] == 2
        log.close()


def test_empty_log_snapshot_has_as_of_seq_minus_one():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        frame = log.create_snapshot({"p": {}})
        # First frame — no prior frames — as_of_seq = -1 by convention
        assert frame.seq == 0
        assert frame.payload["as_of_seq"] == -1
        log.close()


def test_snapshot_deterministic_for_identical_state():
    """Same state -> same blob bytes -> same hash -> same filename."""
    state = {"x": 1, "y": [2, 3]}
    hashes: list[bytes] = []
    for _ in range(2):
        with tempfile.TemporaryDirectory() as tmp:
            log = EventLog(tmp)
            frame = log.create_snapshot({"p": state})
            hashes.append(frame.payload["projections"]["p"]["state_hash"])
            log.close()
    assert hashes[0] == hashes[1]


def test_snapshot_hash_chain_intact():
    """Snapshots must chain through the `prev` field like any frame."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        f1 = log.append(kind="x", actor="A1", payload={})
        f2 = log.create_snapshot({"p": {"v": 1}})
        f3 = log.append(kind="y", actor="A1", payload={})
        log.close()

        # f2.prev must equal hash(f1); f3.prev must equal hash(f2)
        assert f2.prev == f1.frame_hash()
        assert f3.prev == f2.frame_hash()


def test_custom_actor_accepted():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        frame = log.create_snapshot({"p": {}}, actor="A4")
        assert frame.actor == "A4"
        log.close()
