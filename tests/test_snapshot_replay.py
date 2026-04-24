"""Tests for snapshot-aware replay §1.8 (sprint 48)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios.runtime.event_log import EventLog, cbor_encode, sha256


# find_latest_snapshot + load_snapshot_state -----------------------------


def test_no_snapshot_returns_none():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        assert log.find_latest_snapshot() is None
        log.close()


def test_finds_most_recent_snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        log.create_snapshot({"p": {"v": 1}})  # seq 1
        log.append(kind="y", actor="A1", payload={})
        log.create_snapshot({"p": {"v": 2}})  # seq 3 — latest
        log.append(kind="z", actor="A1", payload={})
        latest = log.find_latest_snapshot()
        assert latest is not None
        assert latest.seq == 3
        assert latest.payload["as_of_seq"] == 2
        log.close()


def test_load_snapshot_state_returns_decoded_projections():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        snap = log.create_snapshot({
            "users": {"count": 42, "names": ["alice", "bob"]},
            "orders": [1, 2, 3],
        })
        state = log.load_snapshot_state(snap)
        assert state == {
            "users": {"count": 42, "names": ["alice", "bob"]},
            "orders": [1, 2, 3],
        }
        log.close()


def test_load_snapshot_state_detects_blob_tamper():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        snap = log.create_snapshot({"p": {"v": 100}})
        # Corrupt the blob — its hash will no longer match state_hash.
        blob_rel = snap.payload["projections"]["p"]["state_ref"]
        blob_path = Path(tmp) / blob_rel
        raw = bytearray(blob_path.read_bytes())
        raw[-1] ^= 0x01
        blob_path.write_bytes(bytes(raw))
        with pytest.raises(ValueError, match="does not match"):
            log.load_snapshot_state(snap)
        log.close()


def test_load_snapshot_state_detects_missing_blob():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        snap = log.create_snapshot({"p": {"v": 1}})
        (Path(tmp) / snap.payload["projections"]["p"]["state_ref"]).unlink()
        with pytest.raises(ValueError, match="not found"):
            log.load_snapshot_state(snap)
        log.close()


def test_load_snapshot_state_rejects_non_snapshot_frame():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        f = log.append(kind="x", actor="A1", payload={})
        with pytest.raises(ValueError, match="not a snapshot"):
            log.load_snapshot_state(f)
        log.close()


# replay_from_snapshot ---------------------------------------------------


def test_replay_from_snapshot_yields_only_frames_after_as_of():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="a", actor="A1", payload={"i": 0})     # seq 0
        log.append(kind="b", actor="A1", payload={"i": 1})     # seq 1
        snap = log.create_snapshot({"p": {"count": 2}})         # seq 2
        log.append(kind="c", actor="A1", payload={"i": 3})     # seq 3
        log.append(kind="d", actor="A1", payload={"i": 4})     # seq 4
        log.close()

        log2 = EventLog(tmp)
        frames = list(log2.replay_from_snapshot(snap))
        log2.close()
        kinds = [f.kind for f in frames]
        # Snapshot itself is excluded; a/b are <= as_of_seq; c/d yielded
        assert kinds == ["c", "d"]


def test_replay_from_snapshot_at_end_yields_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="a", actor="A1", payload={})
        snap = log.create_snapshot({"p": {"v": 1}})
        log.close()

        log2 = EventLog(tmp)
        frames = list(log2.replay_from_snapshot(snap))
        log2.close()
        assert frames == []


def test_replay_from_snapshot_still_verifies_hash_chain():
    """The snapshot is trustworthy only if the chain up to it is whole.
    Corrupt a pre-snapshot frame and replay_from_snapshot must refuse."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="a", actor="A1", payload={"i": 0})
        log.append(kind="b", actor="A1", payload={"i": 1})
        snap = log.create_snapshot({"p": {"v": 2}})
        log.append(kind="c", actor="A1", payload={"i": 3})
        log.close()

        seg = next(Path(tmp).glob("segment_*.aios"))
        raw = bytearray(seg.read_bytes())
        raw[200] ^= 0x01
        seg.write_bytes(bytes(raw))

        with pytest.raises(ValueError):
            log2 = EventLog(tmp)
            try:
                list(log2.replay_from_snapshot(snap))
            finally:
                log2.close()


def test_snapshot_plus_replay_equals_full_replay_in_state():
    """If you load the snapshot state + apply post-snapshot frames, you
    end up with the same state as applying all frames from genesis.
    This is the §1.8 invariant — the optimization is correct."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)

        def apply_to(state: dict, frame) -> dict:
            if frame.kind == "increment":
                state = {"count": state.get("count", 0) + 1}
            elif frame.kind == "set":
                state = {"count": frame.payload["to"]}
            return state

        log.append(kind="increment", actor="A1", payload={})   # seq 0
        log.append(kind="increment", actor="A1", payload={})   # seq 1
        log.append(kind="set", actor="A1", payload={"to": 10}) # seq 2
        # snapshot captures state at seq 2: count=10
        snap = log.create_snapshot({"counter": {"count": 10}})  # seq 3
        log.append(kind="increment", actor="A1", payload={})   # seq 4
        log.append(kind="increment", actor="A1", payload={})   # seq 5
        log.close()

        # Method 1 — full replay
        log2 = EventLog(tmp)
        full_state: dict = {}
        for f in log2.replay():
            full_state = apply_to(full_state, f)
        log2.close()

        # Method 2 — snapshot + forward replay
        log3 = EventLog(tmp)
        state = log3.load_snapshot_state(snap)["counter"]
        for f in log3.replay_from_snapshot(snap):
            state = apply_to(state, f)
        log3.close()

        assert state == full_state == {"count": 12}
