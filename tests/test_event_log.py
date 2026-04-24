"""Event-log breach tests (mirrors the 12 reference tests, imports from the package)."""
from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from aios.runtime.event_log import (
    EventLog, Frame, cbor_encode, sha256,
    _decode_frame, HEADER_TOTAL_SIZE,
    HEADER_FMT_FIXED, SEGMENT_MAGIC, SEGMENT_VERSION,
    _encode_on_disk,
)


# §3.1 Deterministic CBOR ---------------------------------------------------


def test_cbor_is_deterministic_across_dict_orderings():
    a = {"kind": "x", "actor": "A4", "seq": 1}
    b = {"seq": 1, "actor": "A4", "kind": "x"}
    assert cbor_encode(a) == cbor_encode(b)


def test_cbor_shortest_integer_form():
    assert len(cbor_encode(23)) == 1
    assert len(cbor_encode(24)) == 2
    assert len(cbor_encode(255)) == 2
    assert len(cbor_encode(256)) == 3
    assert len(cbor_encode(65535)) == 3
    assert len(cbor_encode(65536)) == 5


def test_cbor_same_bytes_same_hash():
    f1 = Frame(v=1, seq=0, ts_ns=1000, prev=bytes(32),
               kind="x", actor="A4", payload={"a": 1})
    f2 = Frame(v=1, seq=0, ts_ns=1000, prev=bytes(32),
               kind="x", actor="A4", payload={"a": 1})
    assert f1.frame_hash() == f2.frame_hash()


# §1 Event-log round trips --------------------------------------------------


def test_round_trip_single_segment():
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
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        for i in range(4):
            log.append(kind="test", actor="A4", payload={"i": i})
        log.close()

        seg = next(Path(tmp).glob("segment_*.aios"))
        with open(seg, "r+b") as fh:
            fh.seek(HEADER_TOTAL_SIZE + 10)
            b = fh.read(1)
            fh.seek(HEADER_TOTAL_SIZE + 10)
            fh.write(bytes([b[0] ^ 0x01]))

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
    """Hand-build a gapped segment declaring first_seq=5 after seq 0..1 closed,
    with a correct prev-chain but a genuine LSN gap. Replay must refuse."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        log.append(kind="test", actor="A4", payload={"i": 0})
        log.append(kind="test", actor="A4", payload={"i": 1})
        last_hash_of_closed = log._last_hash
        log.close()

        open_segs = list(Path(tmp).glob("segment_*_OPEN.aios"))
        assert len(open_segs) == 1
        open_segs[0].unlink()

        GAPPED_FIRST_SEQ = 5
        now_ns = 1_700_000_000_000_000_000
        fixed = struct.pack(
            HEADER_FMT_FIXED,
            SEGMENT_MAGIC, SEGMENT_VERSION, 0,
            GAPPED_FIRST_SEQ, 0xFFFFFFFFFFFFFFFF,
            now_ns,
            last_hash_of_closed,
        )
        header = fixed + sha256(fixed)
        gapped_path = Path(tmp) / f"segment_{GAPPED_FIRST_SEQ}_OPEN.aios"
        gapped_path.write_bytes(header)

        frame = Frame(
            v=1, seq=GAPPED_FIRST_SEQ, ts_ns=now_ns + 1,
            prev=last_hash_of_closed, kind="test",
            actor="A4", payload={"i": 5},
        )
        on_disk = _encode_on_disk(frame.to_cbor())
        with open(gapped_path, "ab") as fh:
            fh.write(on_disk)

        try:
            log2 = EventLog(tmp, rotate_after_frames=2)
            try:
                list(log2.replay())
            finally:
                log2.close()
        except ValueError as e:
            msg = str(e).lower()
            assert "seq" in msg or "first_seq" in msg, f"unexpected rejection: {e}"
            return
        raise AssertionError("gapped LSN segment was accepted")


def test_crc_corruption_detected():
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


# §5 Replay ordering --------------------------------------------------------


def test_lsn_is_strictly_monotonic():
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
