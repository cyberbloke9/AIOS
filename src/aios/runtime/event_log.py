"""AIOS event log — package version (sprint 2).

Port of the v8 reference in examples/reference/event_log.py.

Diff vs reference:
  - _open_new_segment: closes the initial "wb" handle explicitly before
    reopening as "r+b" (fixes WinError 32 at tempdir cleanup on Windows;
    frame hash output unchanged).
  - _dir_fsync: helper that no-ops on Windows (os.fsync on a directory
    file descriptor is not exposed by Python on nt). POSIX behavior
    unchanged — still fsyncs the directory after creation and rename,
    matching Runtime Protocol §1.6 and §1.4.4 step 6.

Everything else is byte-identical to the reference. Passes every
reference test vector in tests/test_event_log.py.
"""
from __future__ import annotations

import dataclasses as dc
import hashlib
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Iterator

from aios.runtime.filelock import FileLock, LockContentionError

# ---------------------------------------------------------------------------
# §3.1 Deterministic CBOR (RFC 8949 §4.2) — AIOS subset
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
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"

    if isinstance(v, int):
        if v >= 0:
            return _cbor_head(0, v)
        return _cbor_head(1, -1 - v)

    if isinstance(v, bytes):
        return _cbor_head(2, len(v)) + v

    if isinstance(v, str):
        encoded = v.encode("utf-8")
        return _cbor_head(3, len(encoded)) + encoded

    if isinstance(v, list):
        return _cbor_head(4, len(v)) + b"".join(cbor_encode(x) for x in v)

    if isinstance(v, dict):
        encoded_pairs = [(cbor_encode(k), cbor_encode(val)) for k, val in v.items()]
        encoded_pairs.sort(key=lambda pair: pair[0])
        return _cbor_head(5, len(encoded_pairs)) + b"".join(
            k + val for k, val in encoded_pairs
        )

    raise TypeError(f"cannot deterministically encode {type(v).__name__}")


# ---------------------------------------------------------------------------
# §4.5 SHA-256 and CRC-32C
# ---------------------------------------------------------------------------


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


_CRC32C_POLY = 0x82F63B78


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
    v: int
    seq: int
    ts_ns: int
    prev: bytes
    kind: str
    actor: str
    payload: dict
    sig: bytes | None = None

    def _as_map(self, include_sig: bool) -> dict:
        m: dict = {
            "v": self.v,
            "seq": self.seq,
            "ts_ns": self.ts_ns,
            "prev": self.prev,
            "kind": self.kind,
            "actor": self.actor,
            "payload": self.payload,
        }
        if include_sig and self.sig is not None:
            m["sig"] = self.sig
        return m

    def unsigned_cbor(self) -> bytes:
        """CBOR of the 7 signature-agnostic fields. This is what an
        Ed25519 signer signs — the sig field is added to the frame
        after signing to avoid the signature-over-signature cycle."""
        return cbor_encode(self._as_map(include_sig=False))

    def to_cbor(self) -> bytes:
        """Canonical CBOR for hash-chain, replay, on-disk framing.

        When `sig` is set, the on-disk form includes it. The frame hash
        (and therefore the `prev` chain) covers `sig` so replaying past
        a tampered signature breaks the next frame's prev verification.
        """
        return cbor_encode(self._as_map(include_sig=True))

    def frame_hash(self) -> bytes:
        return sha256(self.to_cbor())


# ---------------------------------------------------------------------------
# §1.4 Segment file structure
# ---------------------------------------------------------------------------

SEGMENT_MAGIC = b"AIOS"
SEGMENT_VERSION = 1
HEADER_FMT_FIXED = ">4sHH QQ Q 32s"
HEADER_FIXED_SIZE = struct.calcsize(HEADER_FMT_FIXED)
HEADER_TOTAL_SIZE = HEADER_FIXED_SIZE + 32
assert HEADER_TOTAL_SIZE == 96, f"header size must be 96, got {HEADER_TOTAL_SIZE}"

OPEN_LAST_SEQ = 0xFFFFFFFFFFFFFFFF

TRAILER_MAGIC = b"eoSG"
TRAILER_FMT_FIXED = ">4s 32s Q Q"
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


def _encode_on_disk(frame_cbor: bytes) -> bytes:
    length = len(frame_cbor)
    if length > 0xFFFFFFFF:
        raise ValueError("frame too large")
    return struct.pack(">I", length) + frame_cbor + struct.pack(">I", crc32c(frame_cbor))


def _read_on_disk(fh) -> bytes | None:
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


def _dir_fsync(path: Path) -> None:
    """POSIX directory fsync per §1.6. No-op on Windows (not exposed via os.fsync)."""
    if os.name == "nt":
        return
    dir_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


# ---------------------------------------------------------------------------
# EventLog
# ---------------------------------------------------------------------------


class EventLog:
    """Append-only event log. Single writer. Many readers.

    §5.1 advisory file lock is NOT implemented (stdlib portability;
    production must add fcntl.F_SETLK on POSIX and LockFileEx on Windows).
    """

    def __init__(self, root: str | os.PathLike, *,
                 rotate_after_frames: int = 100_000,
                 rotate_after_bytes: int = 64 * 1024 * 1024,
                 signer: Any = None,
                 verifier: Any = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.rotate_after_frames = rotate_after_frames
        self.rotate_after_bytes = rotate_after_bytes
        self._signer = signer
        self._verifier = verifier

        self._active_path: Path | None = None
        self._active_handle = None
        self._active_first_seq: int | None = None
        self._active_frame_count = 0
        self._active_bytes = 0
        self._next_seq = 0
        self._last_hash = bytes(32)
        self._active_created_ts_ns = 0

        # §5.1 single-writer invariant: take the directory-scoped OS lock
        # before touching segment files. Release on close(). A second
        # EventLog constructor on the same root while the first is open
        # raises LockContentionError.
        self._lock = FileLock(self.root / "log.lock")
        self._lock.acquire()
        try:
            self._recover_or_init()
        except Exception:
            self._lock.release()
            raise

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
        last = segs[-1]
        if last.name.endswith("_OPEN.aios"):
            self._adopt_open_segment(last)
        else:
            with open(last, "rb") as fh:
                hdr_raw = fh.read(HEADER_TOTAL_SIZE)
                hdr = _unpack_header(hdr_raw)
                last_hash = hdr["prev_hash"]
                last_seq = hdr["first_seq"] - 1
                while True:
                    try:
                        cbor = _read_on_disk(fh)
                    except ValueError:
                        break
                    if cbor is None:
                        break
                    last_hash = sha256(cbor)
                    last_seq += 1
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

        # Write + fsync header, then CLOSE before reopening for append
        # (reference implementation leaks this handle; Windows refuses deletion).
        with open(path, "wb") as fh:
            fh.write(header)
            fh.flush()
            os.fsync(fh.fileno())

        _dir_fsync(self.root)

        self._active_path = path
        self._active_handle = open(path, "r+b")
        self._active_handle.seek(HEADER_TOTAL_SIZE)
        self._active_first_seq = first_seq
        self._active_frame_count = 0
        self._active_bytes = 0
        self._next_seq = first_seq
        self._last_hash = prev_hash
        self._active_created_ts_ns = now_ns

    def append(self, *, kind: str, actor: str, payload: dict,
               sig: bytes | None = None, ts_ns: int | None = None) -> Frame:
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
        # Auto-sign: if the caller did not supply a sig and this log was
        # constructed with a signer, sign the unsigned-CBOR form now.
        if frame.sig is None and self._signer is not None:
            frame = dc.replace(frame, sig=self._signer.sign(frame.unsigned_cbor()))
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
        assert self._active_handle is not None
        assert self._active_path is not None

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
        self._active_handle = None

        last_seq = self._next_seq - 1
        closed_name = _segment_name(self._active_first_seq, last_seq)
        closed_path = self.root / closed_name
        os.rename(self._active_path, closed_path)

        _dir_fsync(self.root)

        new_header = _pack_header(
            self._active_first_seq, last_seq, self._active_created_ts_ns,
            self._read_segment_prev_hash(closed_path),
            flags=1,
        )
        with open(closed_path, "r+b") as fh:
            fh.write(new_header)
            fh.flush()
            os.fsync(fh.fileno())

        next_first_seq = last_seq + 1
        self._open_new_segment(first_seq=next_first_seq, prev_hash=self._last_hash)

    @staticmethod
    def _read_segment_prev_hash(path: Path) -> bytes:
        with open(path, "rb") as fh:
            hdr_raw = fh.read(HEADER_TOTAL_SIZE)
            hdr = _unpack_header(hdr_raw)
            return hdr["prev_hash"]

    def replay(self) -> Iterator[Frame]:
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
                    peek = fh.read(4)
                    if len(peek) < 4:
                        break
                    fh.seek(pos)
                    if peek == TRAILER_MAGIC:
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
                    # §1.2 / §9.1: if a verifier is configured AND the
                    # frame carries a `sig`, verify it. A verifier is set
                    # but the frame is unsigned, or vice versa, is the
                    # operator's call — neither condition is flagged here.
                    if self._verifier is not None and frame.sig is not None:
                        self._verifier.verify(frame.unsigned_cbor(), frame.sig)
                    expected_prev = frame_hash
                    expected_seq = frame.seq + 1
                    yield frame

    def current_head_hash(self) -> bytes:
        return self._last_hash

    def current_seq(self) -> int:
        return self._next_seq

    # ----- §1.8 snapshot production + replay -----

    def create_snapshot(self, projections: dict[str, Any],
                        *, actor: str = "A5") -> Frame:
        """§1.8 — emit a snapshot frame covering `projections` at the
        current head LSN.

        Each projection value is CBOR-encoded, SHA-256 hashed, and
        written content-addressed to <root>/snapshot-blobs/<name>-<hex>.cbor.
        The snapshot frame's payload references the blob by hash so a
        later reader can verify: read the snapshot frame, read the
        referenced blob, hash the blob, check equality to state_hash.

        Snapshots are appended like any other frame and participate in
        the hash chain. They carry kind="snapshot" and actor=A5 by
        default (Release & Security authority).
        """
        blobs_dir = self.root / "snapshot-blobs"
        blobs_dir.mkdir(parents=True, exist_ok=True)

        projections_meta: dict[str, dict] = {}
        for name, state in projections.items():
            blob_bytes = cbor_encode(state)
            state_hash = sha256(blob_bytes)
            filename = f"{name}-{state_hash.hex()}.cbor"
            (blobs_dir / filename).write_bytes(blob_bytes)
            projections_meta[name] = {
                "state_hash": state_hash,
                "state_ref": f"snapshot-blobs/{filename}",
            }

        as_of_seq = self._next_seq - 1 if self._next_seq > 0 else -1
        # CBOR decode sees integers unchanged; store -1 as a negative int.
        return self.append(
            kind="snapshot",
            actor=actor,
            payload={
                "as_of_seq": as_of_seq,
                "projections": projections_meta,
            },
        )

    def find_latest_snapshot(self) -> Frame | None:
        """Walk the log (verifying the hash chain) and return the most
        recent frame with kind == 'snapshot', or None if none exists."""
        latest: Frame | None = None
        for frame in self.replay():
            if frame.kind == "snapshot":
                latest = frame
        return latest

    def load_snapshot_state(self, snapshot_frame: Frame) -> dict[str, Any]:
        """Load + verify the projection blobs referenced by a snapshot frame.

        Returns {projection_name: decoded_state}. Raises ValueError if
        any referenced blob is missing, is wrong length, or has a hash
        that does not match the snapshot frame's recorded state_hash.
        """
        if snapshot_frame.kind != "snapshot":
            raise ValueError(
                f"frame seq={snapshot_frame.seq} kind="
                f"{snapshot_frame.kind!r} is not a snapshot frame"
            )
        projections = snapshot_frame.payload.get("projections")
        if not isinstance(projections, dict):
            raise ValueError(
                f"snapshot seq={snapshot_frame.seq} has no 'projections' map"
            )

        state: dict[str, Any] = {}
        for name, meta in projections.items():
            ref = meta.get("state_ref")
            expected_hash = meta.get("state_hash")
            if not ref or not isinstance(expected_hash, bytes):
                raise ValueError(
                    f"snapshot projection {name!r} missing state_ref "
                    f"or state_hash"
                )
            blob_path = self.root / ref
            if not blob_path.is_file():
                raise ValueError(
                    f"snapshot blob not found: {blob_path}"
                )
            blob_bytes = blob_path.read_bytes()
            if sha256(blob_bytes) != expected_hash:
                raise ValueError(
                    f"snapshot blob {ref} hash does not match declared "
                    f"state_hash; tampering or corruption"
                )
            state[name] = _CborDecoder(blob_bytes).decode()
        return state

    def replay_from_snapshot(self, snapshot_frame: Frame) -> Iterator[Frame]:
        """Yield every frame in the log with seq > snapshot.as_of_seq.

        The caller pairs this with load_snapshot_state() to get the
        O(snapshot_size + frames_since_snapshot) replay time §1.8
        promises. The hash chain is verified in full during iteration
        (a snapshot cannot be trusted if the chain leading up to it is
        broken — but the snapshot blob itself is trusted via its
        state_hash).
        """
        as_of = snapshot_frame.payload.get("as_of_seq")
        if not isinstance(as_of, int):
            raise ValueError(
                f"snapshot seq={snapshot_frame.seq} has no valid as_of_seq"
            )
        for frame in self.replay():
            if frame.seq > as_of and frame.seq != snapshot_frame.seq:
                yield frame

    def close(self):
        if self._active_handle is not None:
            self._active_handle.close()
            self._active_handle = None
        # Release the writer lock last, after the active-segment handle
        # is closed. Safe to call close() twice.
        self._lock.release()

    @staticmethod
    def _now_ns() -> int:
        import time
        return int(time.time() * 1_000_000_000)


# ---------------------------------------------------------------------------
# Minimal deterministic-CBOR decoder for Frame round-trip.
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
# Demo entry point (kept for parity with the reference file)
# ---------------------------------------------------------------------------


def _demo():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=3)
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

        log2 = EventLog(tmp, rotate_after_frames=3)
        count = 0
        final_hash = bytes(32)
        for frame in log2.replay():
            final_hash = frame.frame_hash()
            count += 1
        log2.close()

        print(f"Wrote {seq_after} frames; replayed {count} frames.")
        assert count == seq_after, (count, seq_after)
        assert final_hash == head_before_close, "chain head mismatch on replay"
        print("Replay verification OK.")


if __name__ == "__main__":
    _demo()
