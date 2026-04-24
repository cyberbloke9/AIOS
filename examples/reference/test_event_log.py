"""
Breach-detection tests for event_log.py.

Each test demonstrates that a specific property of the wire format is
actually enforced by the reference implementation. If a test passes where
it should fail, the implementation is not enforcing what the spec claims.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from event_log import (
    EventLog, Frame, cbor_encode, sha256, crc32c,
    _decode_frame, HEADER_TOTAL_SIZE,
)


# ---------------------------------------------------------------------------
# §3.1 — Deterministic CBOR
# ---------------------------------------------------------------------------

def test_cbor_is_deterministic_across_dict_orderings():
    """Different key insertion orders must produce identical CBOR bytes."""
    a = {"kind": "x", "actor": "A4", "seq": 1}
    b = {"seq": 1, "actor": "A4", "kind": "x"}
    assert cbor_encode(a) == cbor_encode(b), "dict key order must not affect CBOR"


def test_cbor_shortest_integer_form():
    """Per RFC 8949 §4.2, integers use the shortest form."""
    # 23 fits in the head byte alone; 24 requires 1 extra byte
    assert len(cbor_encode(23)) == 1
    assert len(cbor_encode(24)) == 2
    assert len(cbor_encode(255)) == 2
    assert len(cbor_encode(256)) == 3
    assert len(cbor_encode(65535)) == 3
    assert len(cbor_encode(65536)) == 5


def test_cbor_same_bytes_same_hash():
    """Identical content must produce identical frame hashes."""
    f1 = Frame(v=1, seq=0, ts_ns=1000, prev=bytes(32),
               kind="x", actor="A4", payload={"a": 1})
    f2 = Frame(v=1, seq=0, ts_ns=1000, prev=bytes(32),
               kind="x", actor="A4", payload={"a": 1})
    assert f1.frame_hash() == f2.frame_hash()


# ---------------------------------------------------------------------------
# §1 — Event log wire format
# ---------------------------------------------------------------------------

def test_round_trip_single_segment():
    """Write N frames, close, reopen, replay — same hash."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        for i in range(5):
            log.append(kind="test", actor="A4", payload={"i": i})
        head = log.current_head_hash()
        log.close()

        log2 = EventLog(tmp)
        frames = list(log2.replay())
        assert len(frames) == 5
        assert frames[-1].frame_hash() == head
        log2.close()


def test_round_trip_across_rotation():
    """Frames spanning rotation boundaries replay as one continuous chain."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(7):
            log.append(kind="test", actor="A4", payload={"i": i})
        head = log.current_head_hash()
        log.close()

        log2 = EventLog(tmp, rotate_after_frames=2)
        frames = list(log2.replay())
        assert len(frames) == 7
        assert [f.seq for f in frames] == list(range(7))
        assert frames[-1].frame_hash() == head
        log2.close()


def test_tampered_frame_detected():
    """Modifying a byte of a frame's CBOR body must be detected at replay or recovery."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        for i in range(4):
            log.append(kind="test", actor="A4", payload={"i": i})
        log.close()

        # Corrupt one byte inside the active segment (after header)
        seg = next(Path(tmp).glob("segment_*.aios"))
        with open(seg, "r+b") as fh:
            fh.seek(HEADER_TOTAL_SIZE + 10)
            b = fh.read(1)
            fh.seek(HEADER_TOTAL_SIZE + 10)
            fh.write(bytes([b[0] ^ 0x01]))

        # Detection may occur at open (recovery scan) or at replay; either is correct
        try:
            log2 = EventLog(tmp)
            try:
                list(log2.replay())
            finally:
                log2.close()
        except ValueError:
            return
        raise AssertionError("tampered frame was not detected")


def test_truncated_frame_detected():
    """A frame length prefix that promises more bytes than exist must fail."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="test", actor="A4", payload={"i": 0})
        log.close()

        seg = next(Path(tmp).glob("segment_*.aios"))
        full = seg.read_bytes()
        seg.write_bytes(full[:HEADER_TOTAL_SIZE + 8])

        try:
            log2 = EventLog(tmp)
            try:
                list(log2.replay())
            finally:
                log2.close()
        except ValueError:
            return
        raise AssertionError("truncated frame was not detected")


def test_seq_gap_rejected():
    """Construct a segment whose first_seq declares a gap past the prior last_seq.
    Replay must detect the gap and refuse."""
    import struct
    from event_log import (
        HEADER_TOTAL_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION,
        HEADER_FMT_FIXED, _encode_on_disk, cbor_encode,
    )

    with tempfile.TemporaryDirectory() as tmp:
        # Step 1: write a legitimate first segment with frames seq 0..1, then close it
        log = EventLog(tmp, rotate_after_frames=2)  # forces rotation after 2 frames
        log.append(kind="test", actor="A4", payload={"i": 0})
        log.append(kind="test", actor="A4", payload={"i": 1})
        # Rotation just occurred; the newly-opened OPEN segment has first_seq=2
        # Capture the last hash of the closed segment so we can fabricate a
        # *valid-prev but gapped-seq* next segment ourselves
        last_hash_of_closed = log._last_hash
        log.close()

        # Step 2: delete the OPEN segment the library just created
        open_segs = list(Path(tmp).glob("segment_*_OPEN.aios"))
        assert len(open_segs) == 1, f"expected 1 OPEN segment, got {len(open_segs)}"
        open_segs[0].unlink()

        # Step 3: hand-build a replacement segment whose first_seq = 5 (gap!)
        #         but whose prev_hash correctly chains from the closed segment.
        GAPPED_FIRST_SEQ = 5
        now_ns = 1_700_000_000_000_000_000
        fixed = struct.pack(
            HEADER_FMT_FIXED,
            SEGMENT_MAGIC, SEGMENT_VERSION, 0,  # flags=0 open
            GAPPED_FIRST_SEQ, 0xFFFFFFFFFFFFFFFF,
            now_ns,
            last_hash_of_closed,   # correct prev chain
        )
        header = fixed + sha256(fixed)
        gapped_path = Path(tmp) / f"segment_{GAPPED_FIRST_SEQ}_OPEN.aios"
        gapped_path.write_bytes(header)

        # Step 4: append one frame to the gapped segment that claims seq=5
        frame = Frame(
            v=1, seq=GAPPED_FIRST_SEQ, ts_ns=now_ns + 1,
            prev=last_hash_of_closed, kind="test",
            actor="A4", payload={"i": 5},
        )
        on_disk = _encode_on_disk(frame.to_cbor())
        with open(gapped_path, "ab") as fh:
            fh.write(on_disk)

        # Step 5: replay must detect the gap.
        # The library may refuse at open (recovery tries to adopt) or at replay.
        # Either is a genuine gap rejection.
        try:
            log2 = EventLog(tmp, rotate_after_frames=2)
            try:
                list(log2.replay())
            finally:
                log2.close()
        except ValueError as e:
            # Verify the rejection reason mentions seq / first_seq mismatch
            msg = str(e).lower()
            assert "seq" in msg or "first_seq" in msg, f"unexpected rejection reason: {e}"
            return
        raise AssertionError("gapped LSN segment was accepted; should have been rejected")


def test_crc_corruption_detected():
    """Flipping a CRC byte must cause the frame to be rejected."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="test", actor="A4", payload={"i": 0})
        log.close()

        seg = next(Path(tmp).glob("segment_*.aios"))
        raw = bytearray(seg.read_bytes())
        raw[-1] ^= 0x01
        seg.write_bytes(bytes(raw))

        try:
            log2 = EventLog(tmp)
            try:
                list(log2.replay())
            finally:
                log2.close()
        except ValueError:
            return
        raise AssertionError("CRC corruption was not detected")


# ---------------------------------------------------------------------------
# §5 — Replay ordering
# ---------------------------------------------------------------------------

def test_lsn_is_strictly_monotonic():
    """LSN advances by exactly 1 across the log, including across rotations."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(5):
            log.append(kind="test", actor="A4", payload={"i": i})
        log.close()

        log2 = EventLog(tmp, rotate_after_frames=2)
        frames = list(log2.replay())
        log2.close()
        seqs = [f.seq for f in frames]
        assert seqs == list(range(len(seqs)))


def test_prev_hash_chain_unbroken():
    """Every frame's prev is the hash of the previous frame."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(6):
            log.append(kind="test", actor="A4", payload={"i": i})
        log.close()

        log2 = EventLog(tmp, rotate_after_frames=2)
        prev_hash = bytes(32)
        for f in log2.replay():
            assert f.prev == prev_hash
            prev_hash = f.frame_hash()
        log2.close()


# ---------------------------------------------------------------------------
# Helper: frame decode round-trip
# ---------------------------------------------------------------------------

def test_frame_cbor_round_trip():
    f = Frame(v=1, seq=42, ts_ns=12345, prev=bytes(32),
              kind="gate.evaluated", actor="A4",
              payload={"gate_id": "P_Q1_invariant_integrity",
                       "status": "preserved", "count": 3})
    cbor = f.to_cbor()
    g = _decode_frame(cbor)
    assert g.seq == f.seq
    assert g.kind == f.kind
    assert g.actor == f.actor
    assert g.payload == f.payload
    assert g.prev == f.prev


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

TESTS = [
    test_cbor_is_deterministic_across_dict_orderings,
    test_cbor_shortest_integer_form,
    test_cbor_same_bytes_same_hash,
    test_round_trip_single_segment,
    test_round_trip_across_rotation,
    test_tampered_frame_detected,
    test_truncated_frame_detected,
    test_seq_gap_rejected,
    test_crc_corruption_detected,
    test_lsn_is_strictly_monotonic,
    test_prev_hash_chain_unbroken,
    test_frame_cbor_round_trip,
]


if __name__ == "__main__":
    for t in TESTS:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            raise
        except Exception as e:
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
            raise
    print(f"\n{len(TESTS)}/{len(TESTS)} event-log tests passed.")
