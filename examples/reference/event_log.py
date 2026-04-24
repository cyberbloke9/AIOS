"""
AIOS Runtime Protocol reference implementation — event log wire format.

This file implements a SUBSET of the Runtime Protocol Spec. It is
normative for the clauses listed below and illustrative for the rest.
A production implementation MUST also implement the items in the
"NOT covered" list before claiming full runtime conformance.

NORMATIVELY COVERED (test_event_log.py verifies these):
  §1.2  Frame structure — 8-field CBOR map; field name is `ts_ns` (uint64),
        not `ts` (text). RFC 3339 strings are §3.5 audit-export views only.
  §1.4  Segment headers (96 bytes), trailers (84 bytes), on-disk framing
        (length prefix + CBOR + CRC-32C), rotation.
  §3.1  Deterministic CBOR for the AIOS subset (int, bytes, text, list,
        map, bool, null). Shortest-form integers, byte-lex key ordering.
  §3.4  Byte-lex key ordering (RFC 8949 §4.2.1).
  §4.5  SHA-256 content hashing, CRC-32C frame integrity.
  §5.2  LSN strict monotonicity.
  §5.5  Cross-segment ordering.
  §5.6  Replay procedure with prev-chain and seq verification.

NOT COVERED (production implementation must add):
  §1.5  Merkle batch overlay (required only for P-HighAssurance).
  §1.7  Compaction.
  §1.8  Snapshot production and verification.
  §2    Ed25519 signatures, HMAC caveats, capability-token lifecycle.
  §5.1  POSIX fcntl / Windows LockFileEx single-writer advisory lock.
  §6    TUF client and bootstrap anchor verification.
  §9.2  Frame signatures on Z3→Z4 subsystem+ promotions.

Dependencies: Python standard library only. The deterministic CBOR
encoder is written inline so the file has no external dependencies.

Usage:
    python event_log.py           # demo: write frames, rotate, replay
    python test_event_log.py      # 12 breach tests
"""

from __future__ import annotations

import dataclasses as dc
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# §3.1 Deterministic CBOR (RFC 8949 §4.2)
#
# Minimal encoder supporting: unsigned int, negative int, bytes, text,
# array, map, bool, null. Sufficient for AIOS frames and capability tokens.
# Production should use a full CBOR library; this exists to prove the
# format is self-consistent and implementable from first principles.
# ---------------------------------------------------------------------------


def _cbor_head(major: int, n: int) -> bytes:
    """Encode a CBOR head byte + length prefix in the shortest form."""
    assert 0 <= major <= 7
    assert n >= 0
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise ValueError("integer too large for canonical CBOR encoding")


def cbor_encode(v: Any) -> bytes:
    """Deterministic CBOR per RFC 8949 §4.2 for the subset AIOS needs."""
    # bool MUST be checked before int (bool is a subclass of int in Python)
    if v is True:
        return b"\xf5"                       # major 7, simple value 21
    if v is False:
        return b"\xf4"                       # major 7, simple value 20
    if v is None:
        return b"\xf6"                       # major 7, simple value 22

    if isinstance(v, int):
        if v >= 0:
            return _cbor_head(0, v)
        return _cbor_head(1, -1 - v)

    if isinstance(v, bytes):
        return _cbor_head(2, len(v)) + v

    if isinstance(v, str):
        # §3.3: assume caller passed NFC-normalized UTF-8 text
        encoded = v.encode("utf-8")
        return _cbor_head(3, len(encoded)) + encoded

    if isinstance(v, list):
        return _cbor_head(4, len(v)) + b"".join(cbor_encode(x) for x in v)

    if isinstance(v, dict):
        # §3.4: sort keys by byte-lex of their encoded form
        encoded_pairs = [(cbor_encode(k), cbor_encode(val)) for k, val in v.items()]
        encoded_pairs.sort(key=lambda pair: pair[0])
        return _cbor_head(5, len(encoded_pairs)) + b"".join(
            k + val for k, val in encoded_pairs
        )

    raise TypeError(f"cannot deterministically encode {type(v).__name__}")


# ---------------------------------------------------------------------------
# §4.5 Hash algorithm: SHA-256 only.
# ---------------------------------------------------------------------------


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------------------
# §4.5 CRC-32C (Castagnoli). Pure-Python implementation, table-driven.
# ---------------------------------------------------------------------------

_CRC32C_POLY = 0x82F63B78  # Castagnoli reversed


def _build_crc32c_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (_CRC32C_POLY & -(c & 1))
        table.append(c & 0xFFFFFFFF)
    return table


_CRC32C_TABLE = _build_crc32c_table()


def crc32c(b: bytes) -> int:
    c = 0xFFFFFFFF
    for byte in b:
        c = _CRC32C_TABLE[(c ^ byte) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# §1.2 Frame structure
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class Frame:
    """An event-log frame. See Runtime Protocol Spec §1.2."""

    v: int            # frame format version; MUST be 1 for this spec
    seq: int          # LSN
    ts_ns: int        # nanoseconds since Unix epoch, UTC
    prev: bytes       # 32-byte SHA-256 of prior frame's canonical CBOR
    kind: str
    actor: str
    payload: dict
    sig: bytes | None = None  # 64-byte Ed25519 signature, optional in v1 for within-host frames

    def to_cbor(self) -> bytes:
        """Canonical CBOR encoding per §3.1."""
        m: dict = {
            "v": self.v,
            "seq": self.seq,
            "ts_ns": self.ts_ns,
            "prev": self.prev,
            "kind": self.kind,
            "actor": self.actor,
            "payload": self.payload,
        }
        if self.sig is not None:
            m["sig"] = self.sig
        return cbor_encode(m)

    def frame_hash(self) -> bytes:
        """Content-addressable identifier."""
        return sha256(self.to_cbor())


# ---------------------------------------------------------------------------
# §1.4 Segment file structure
# ---------------------------------------------------------------------------

SEGMENT_MAGIC = b"AIOS"
SEGMENT_VERSION = 1
HEADER_FMT_FIXED = ">4sHH QQ Q 32s"  # magic, version, flags, first_seq, last_seq, created_ts, prev_hash
HEADER_FIXED_SIZE = struct.calcsize(HEADER_FMT_FIXED)
HEADER_TOTAL_SIZE = HEADER_FIXED_SIZE + 32  # + hdr_hash
assert HEADER_TOTAL_SIZE == 96, f"header size must be 96, got {HEADER_TOTAL_SIZE}"

OPEN_LAST_SEQ = 0xFFFFFFFFFFFFFFFF

TRAILER_MAGIC = b"eoSG"
TRAILER_FMT_FIXED = ">4s 32s Q Q"   # magic, last_hash, frame_count, end_ts
TRAILER_FIXED_SIZE = struct.calcsize(TRAILER_FMT_FIXED)
TRAILER_TOTAL_SIZE = TRAILER_FIXED_SIZE + 32
assert TRAILER_TOTAL_SIZE == 84, f"trailer size must be 84, got {TRAILER_TOTAL_SIZE}"


def _segment_name(first_seq: int, last_seq: int | None) -> str:
    end = "OPEN" if last_seq is None else str(last_seq)
    return f"segment_{first_seq}_{end}.aios"


def _pack_header(first_seq: int, last_seq: int, created_ts_ns: int,
                 prev_hash: bytes, flags: int) -> bytes:
    fixed = struct.pack(
        HEADER_FMT_FIXED,
        SEGMENT_MAGIC, SEGMENT_VERSION, flags,
        first_seq, last_seq,
        created_ts_ns,
        prev_hash,
    )
    hdr_hash = sha256(fixed)
    return fixed + hdr_hash


def _unpack_header(raw: bytes) -> dict:
    if len(raw) != HEADER_TOTAL_SIZE:
        raise ValueError("bad header size")
    fixed, hdr_hash = raw[:HEADER_FIXED_SIZE], raw[HEADER_FIXED_SIZE:]
    if sha256(fixed) != hdr_hash:
        raise ValueError("header hash mismatch")
    magic, version, flags, first_seq, last_seq, created_ts, prev_hash = struct.unpack(
        HEADER_FMT_FIXED, fixed
    )
    if magic != SEGMENT_MAGIC:
        raise ValueError("bad segment magic")
    if version != SEGMENT_VERSION:
        raise ValueError(f"unsupported segment version: {version}")
    return {
        "flags": flags, "first_seq": first_seq, "last_seq": last_seq,
        "created_ts_ns": created_ts, "prev_hash": prev_hash,
    }


# ---------------------------------------------------------------------------
# §1.4.3 Frame framing on disk: length prefix + CBOR + CRC32C
# ---------------------------------------------------------------------------


def _encode_on_disk(frame_cbor: bytes) -> bytes:
    length = len(frame_cbor)
    if length > 0xFFFFFFFF:
        raise ValueError("frame too large")
    return struct.pack(">I", length) + frame_cbor + struct.pack(">I", crc32c(frame_cbor))


def _read_on_disk(fh) -> bytes | None:
    """Read one frame's CBOR bytes from an open file handle.
    Returns None at clean EOF; raises on partial/corrupt frame."""
    head = fh.read(4)
    if not head:
        return None
    if len(head) < 4:
        raise ValueError("truncated frame length prefix")
    (length,) = struct.unpack(">I", head)
    cbor = fh.read(length)
    if len(cbor) < length:
        raise ValueError("truncated frame body")
    crc_raw = fh.read(4)
    if len(crc_raw) < 4:
        raise ValueError("truncated frame crc")
    (got_crc,) = struct.unpack(">I", crc_raw)
    if got_crc != crc32c(cbor):
        raise ValueError("frame CRC mismatch")
    return cbor


# ---------------------------------------------------------------------------
# EventLog — single-writer, append-only, hash-chained
# ---------------------------------------------------------------------------


class EventLog:
    """Append-only event log. One writer; many readers.

    §5.1 enforces single-writer via an advisory file lock in production;
    this reference implementation does not implement the lock (stdlib
    portability) but documents where it belongs.
    """

    def __init__(self, root: str | os.PathLike, *,
                 rotate_after_frames: int = 100_000,
                 rotate_after_bytes: int = 64 * 1024 * 1024):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.rotate_after_frames = rotate_after_frames
        self.rotate_after_bytes = rotate_after_bytes

        self._active_path: Path | None = None
        self._active_handle = None
        self._active_first_seq: int | None = None
        self._active_frame_count = 0
        self._active_bytes = 0
        self._next_seq = 0
        self._last_hash = bytes(32)       # genesis prev_hash is 32 zero bytes
        self._active_created_ts_ns = 0

        self._recover_or_init()

    # ----- segment discovery and recovery -----

    def _segment_files(self) -> list[Path]:
        return sorted(self.root.glob("segment_*.aios"),
                      key=lambda p: self._parse_first_seq(p))

    @staticmethod
    def _parse_first_seq(p: Path) -> int:
        name = p.name
        parts = name.removesuffix(".aios").split("_")
        return int(parts[1])

    def _recover_or_init(self):
        segs = self._segment_files()
        if not segs:
            self._open_new_segment(first_seq=0, prev_hash=bytes(32))
            return
        # The last segment is OPEN if its name ends _OPEN.aios
        last = segs[-1]
        if last.name.endswith("_OPEN.aios"):
            self._adopt_open_segment(last)
        else:
            # All closed; open a new segment continuing the chain
            with open(last, "rb") as fh:
                hdr_raw = fh.read(HEADER_TOTAL_SIZE)
                hdr = _unpack_header(hdr_raw)
                # Read frames to find the last hash
                last_hash = hdr["prev_hash"]
                last_seq = hdr["first_seq"] - 1
                while True:
                    pos_before = fh.tell()
                    try:
                        cbor = _read_on_disk(fh)
                    except ValueError:
                        break
                    if cbor is None:
                        break
                    last_hash = sha256(cbor)
                    last_seq += 1
                    # If trailer follows, we've read past frames; stop at trailer magic
                    # A robust reader detects trailer by peeking, but for this ref impl
                    # we stop at EOF; closed segments always end at frames before trailer.
                    # This simplification is acceptable because rotation writes the trailer
                    # at a known offset (see _close_active_segment).
                # NOTE: for simplicity, closed segments have their trailer at fixed offset
                # after all frames; we skip detailed trailer parsing in recovery.
            self._open_new_segment(first_seq=last_seq + 1, prev_hash=last_hash)

    def _adopt_open_segment(self, path: Path):
        with open(path, "rb") as fh:
            hdr_raw = fh.read(HEADER_TOTAL_SIZE)
            hdr = _unpack_header(hdr_raw)
            first_seq = hdr["first_seq"]
            prev_hash = hdr["prev_hash"]
            last_hash = prev_hash
            seq = first_seq - 1
            count = 0
            while True:
                cbor = _read_on_disk(fh)
                if cbor is None:
                    break
                last_hash = sha256(cbor)
                seq += 1
                count += 1
            body_end = fh.tell()
        # Reopen for append
        self._active_path = path
        self._active_handle = open(path, "r+b")
        self._active_handle.seek(body_end)
        self._active_first_seq = first_seq
        self._active_frame_count = count
        self._active_bytes = body_end - HEADER_TOTAL_SIZE
        self._next_seq = seq + 1
        self._last_hash = last_hash
        self._active_created_ts_ns = hdr["created_ts_ns"]

    def _open_new_segment(self, first_seq: int, prev_hash: bytes):
        now_ns = self._now_ns()
        path = self.root / _segment_name(first_seq, None)
        header = _pack_header(first_seq, OPEN_LAST_SEQ, now_ns, prev_hash, flags=0)
        fh = open(path, "wb")
        fh.write(header)
        fh.flush()
        os.fsync(fh.fileno())
        # Directory fsync per §1.6
        dir_fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        self._active_path = path
        self._active_handle = open(path, "r+b")
        self._active_handle.seek(HEADER_TOTAL_SIZE)
        self._active_first_seq = first_seq
        self._active_frame_count = 0
        self._active_bytes = 0
        self._next_seq = first_seq
        self._last_hash = prev_hash
        self._active_created_ts_ns = now_ns

    # ----- append -----

    def append(self, *, kind: str, actor: str, payload: dict,
               sig: bytes | None = None, ts_ns: int | None = None) -> Frame:
        """Append one frame. Returns the constructed Frame."""
        if ts_ns is None:
            ts_ns = self._now_ns()
        frame = Frame(
            v=1,
            seq=self._next_seq,
            ts_ns=ts_ns,
            prev=self._last_hash,
            kind=kind,
            actor=actor,
            payload=payload,
            sig=sig,
        )
        cbor_bytes = frame.to_cbor()
        on_disk = _encode_on_disk(cbor_bytes)
        assert self._active_handle is not None
        self._active_handle.write(on_disk)
        self._active_handle.flush()
        os.fsync(self._active_handle.fileno())

        self._last_hash = sha256(cbor_bytes)
        self._next_seq += 1
        self._active_frame_count += 1
        self._active_bytes += len(on_disk)

        if (self._active_frame_count >= self.rotate_after_frames
                or self._active_bytes >= self.rotate_after_bytes):
            self._rotate()

        return frame

    def _rotate(self):
        """§1.4.4 rotation procedure."""
        assert self._active_handle is not None
        assert self._active_path is not None

        # Write trailer
        trailer_fixed = struct.pack(
            TRAILER_FMT_FIXED,
            TRAILER_MAGIC,
            self._last_hash,
            self._active_frame_count,
            self._now_ns(),
        )
        trailer = trailer_fixed + sha256(trailer_fixed)
        self._active_handle.write(trailer)
        self._active_handle.flush()
        os.fsync(self._active_handle.fileno())
        self._active_handle.close()

        # Rename OPEN -> _<last_seq>
        last_seq = self._next_seq - 1
        closed_name = _segment_name(self._active_first_seq, last_seq)
        closed_path = self.root / closed_name
        os.rename(self._active_path, closed_path)

        dir_fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        # Update closed segment's header in place with last_seq and flags=1 (closed)
        # Rewrite just the header (same size) then re-compute hdr_hash
        new_header = _pack_header(
            self._active_first_seq, last_seq, self._active_created_ts_ns,
            # prev_hash for this segment — read it back from the now-closed file
            self._read_segment_prev_hash(closed_path),
            flags=1,
        )
        with open(closed_path, "r+b") as fh:
            fh.write(new_header)
            fh.flush()
            os.fsync(fh.fileno())

        # Open new active segment continuing the chain
        next_first_seq = last_seq + 1
        self._open_new_segment(first_seq=next_first_seq, prev_hash=self._last_hash)

    @staticmethod
    def _read_segment_prev_hash(path: Path) -> bytes:
        with open(path, "rb") as fh:
            hdr_raw = fh.read(HEADER_TOTAL_SIZE)
            hdr = _unpack_header(hdr_raw)
            return hdr["prev_hash"]

    # ----- read / replay -----

    def replay(self) -> Iterator[Frame]:
        """Yield frames in LSN order across all segments, verifying the hash chain."""
        expected_prev = bytes(32)
        expected_seq = 0
        for seg_path in self._segment_files():
            with open(seg_path, "rb") as fh:
                hdr_raw = fh.read(HEADER_TOTAL_SIZE)
                hdr = _unpack_header(hdr_raw)
                if hdr["prev_hash"] != expected_prev:
                    raise ValueError(
                        f"segment {seg_path.name} prev_hash mismatch: "
                        f"expected {expected_prev.hex()}, got {hdr['prev_hash'].hex()}"
                    )
                if hdr["first_seq"] != expected_seq:
                    raise ValueError(
                        f"segment {seg_path.name} first_seq mismatch: "
                        f"expected {expected_seq}, got {hdr['first_seq']}"
                    )
                while True:
                    pos = fh.tell()
                    # Detect trailer (closed segment): magic is 4 bytes "eoSG"
                    peek = fh.read(4)
                    if len(peek) < 4:
                        break
                    fh.seek(pos)
                    if peek == TRAILER_MAGIC:
                        # consume & verify trailer
                        trailer_raw = fh.read(TRAILER_TOTAL_SIZE)
                        if len(trailer_raw) < TRAILER_TOTAL_SIZE:
                            raise ValueError("truncated trailer")
                        fixed, hsh = trailer_raw[:TRAILER_FIXED_SIZE], trailer_raw[TRAILER_FIXED_SIZE:]
                        if sha256(fixed) != hsh:
                            raise ValueError("trailer hash mismatch")
                        break
                    cbor = _read_on_disk(fh)
                    if cbor is None:
                        break
                    frame_hash = sha256(cbor)
                    # Decode just enough to verify prev chain & seq
                    frame = _decode_frame(cbor)
                    if frame.prev != expected_prev:
                        raise ValueError(
                            f"frame seq={frame.seq} prev mismatch: "
                            f"expected {expected_prev.hex()}, got {frame.prev.hex()}"
                        )
                    if frame.seq != expected_seq:
                        raise ValueError(
                            f"frame seq mismatch: expected {expected_seq}, got {frame.seq}"
                        )
                    expected_prev = frame_hash
                    expected_seq = frame.seq + 1
                    yield frame

    def current_head_hash(self) -> bytes:
        return self._last_hash

    def current_seq(self) -> int:
        return self._next_seq

    def close(self):
        if self._active_handle is not None:
            self._active_handle.close()
            self._active_handle = None

    @staticmethod
    def _now_ns() -> int:
        import time
        return int(time.time() * 1_000_000_000)


# ---------------------------------------------------------------------------
# Minimal deterministic-CBOR decoder, just enough for Frame round-trip.
# This is NOT a full CBOR decoder; it handles the subset our encoder emits.
# ---------------------------------------------------------------------------


class _CborDecoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("CBOR truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def _read_head(self) -> tuple[int, int]:
        head = self._read(1)[0]
        major = head >> 5
        info = head & 0x1F
        if info < 24:
            return major, info
        if info == 24:
            return major, self._read(1)[0]
        if info == 25:
            return major, int.from_bytes(self._read(2), "big")
        if info == 26:
            return major, int.from_bytes(self._read(4), "big")
        if info == 27:
            return major, int.from_bytes(self._read(8), "big")
        raise ValueError(f"unsupported CBOR additional info {info}")

    def decode(self) -> Any:
        if self.pos >= len(self.data):
            raise ValueError("CBOR unexpected end")
        head = self.data[self.pos]
        if head == 0xF5:
            self.pos += 1
            return True
        if head == 0xF4:
            self.pos += 1
            return False
        if head == 0xF6:
            self.pos += 1
            return None
        major, length = self._read_head()
        if major == 0:
            return length
        if major == 1:
            return -1 - length
        if major == 2:
            return self._read(length)
        if major == 3:
            return self._read(length).decode("utf-8")
        if major == 4:
            return [self.decode() for _ in range(length)]
        if major == 5:
            result: dict = {}
            for _ in range(length):
                k = self.decode()
                v = self.decode()
                result[k] = v
            return result
        raise ValueError(f"unsupported CBOR major type {major}")


def _decode_frame(cbor: bytes) -> Frame:
    dec = _CborDecoder(cbor)
    m = dec.decode()
    if not isinstance(m, dict):
        raise ValueError("frame must be CBOR map")
    return Frame(
        v=m["v"],
        seq=m["seq"],
        ts_ns=m["ts_ns"],
        prev=m["prev"],
        kind=m["kind"],
        actor=m["actor"],
        payload=m["payload"],
        sig=m.get("sig"),
    )


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _demo():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=3)  # tight rotation for demo

        # Append several frames spanning multiple segments
        log.append(kind="run.started", actor="A1", payload={"run_id": "r001"})
        log.append(kind="artifact.quarantined", actor="A3",
                   payload={"artifact_ref": "sha256:aa..."})
        log.append(kind="gate.evaluated", actor="A4",
                   payload={"gate_id": "P_Q1_invariant_integrity",
                            "status": "preserved"})
        log.append(kind="gate.evaluated", actor="A4",
                   payload={"gate_id": "P_Q2_state_traceability",
                            "status": "preserved"})
        log.append(kind="artifact.promoted", actor="A5",
                   payload={"artifact_ref": "sha256:aa..."})
        log.append(kind="run.completed", actor="A1",
                   payload={"run_id": "r001", "outcome": "green"})

        head_before_close = log.current_head_hash()
        seq_after = log.current_seq()
        log.close()

        # Reopen, replay, verify
        log2 = EventLog(tmp, rotate_after_frames=3)
        count = 0
        final_hash = bytes(32)
        for frame in log2.replay():
            final_hash = frame.frame_hash()
            count += 1
        log2.close()

        print(f"Wrote {seq_after} frames; replayed {count} frames.")
        print(f"Head hash: {head_before_close.hex()[:16]}...")
        print(f"Replay hash: {final_hash.hex()[:16]}...")
        assert count == seq_after, (count, seq_after)
        assert final_hash == head_before_close, "chain head mismatch on replay"
        print("Replay verification OK.")


if __name__ == "__main__":
    _demo()
