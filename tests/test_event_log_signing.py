"""Tests for EventLog Ed25519 integration (sprint 15)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios.enterprise.signing import (
    Ed25519Signer, Ed25519Verifier, SignatureVerificationError,
    cryptography_available,
)
from aios.runtime.event_log import EventLog, Frame


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography library not installed",
)


def test_signer_autosigns_appended_frames():
    signer = Ed25519Signer.generate()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        try:
            frame = log.append(kind="t", actor="A1", payload={"x": 1})
            assert frame.sig is not None
            assert len(frame.sig) == 64
        finally:
            log.close()


def test_replay_verifies_signed_frames():
    signer = Ed25519Signer.generate()
    verifier = Ed25519Verifier(signer.public_key())
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        log.append(kind="a", actor="A1", payload={"i": 1})
        log.append(kind="b", actor="A1", payload={"i": 2})
        log.close()

        log2 = EventLog(tmp, verifier=verifier)
        frames = list(log2.replay())
        log2.close()
        assert len(frames) == 2
        for f in frames:
            assert f.sig is not None


def test_replay_refuses_wrong_key():
    signer = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    wrong_verifier = Ed25519Verifier(attacker.public_key())  # different key
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        log.append(kind="x", actor="A1", payload={})
        log.close()

        log2 = EventLog(tmp, verifier=wrong_verifier)
        try:
            with pytest.raises(SignatureVerificationError):
                list(log2.replay())
        finally:
            log2.close()


def test_replay_without_verifier_ignores_sig():
    """A log that was written with a signer can still be replayed by a
    consumer that does not configure a verifier — signatures are
    advisory unless a verifier is provided. This matches §9.1 where
    signatures are MAY in P-Local / SHOULD in P-Enterprise."""
    signer = Ed25519Signer.generate()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        log.append(kind="x", actor="A1", payload={})
        log.close()

        log2 = EventLog(tmp)  # no verifier
        frames = list(log2.replay())
        log2.close()
        assert frames[0].sig is not None


def test_unsigned_log_with_verifier_passes():
    """An unsigned log + verifier is a benign mismatch: verifier is
    present but frames carry no sig, so there is nothing to verify."""
    verifier_key = Ed25519Signer.generate().public_key()
    verifier = Ed25519Verifier(verifier_key)
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        log.close()

        log2 = EventLog(tmp, verifier=verifier)
        frames = list(log2.replay())
        log2.close()
        assert all(f.sig is None for f in frames)


def test_frame_unsigned_cbor_excludes_sig_field():
    f_unsigned = Frame(v=1, seq=0, ts_ns=0, prev=bytes(32),
                       kind="k", actor="A4", payload={})
    f_signed = Frame(v=1, seq=0, ts_ns=0, prev=bytes(32),
                     kind="k", actor="A4", payload={},
                     sig=b"\x00" * 64)
    assert f_unsigned.unsigned_cbor() == f_signed.unsigned_cbor()
    # to_cbor differs: signed frame includes the sig
    assert f_unsigned.to_cbor() != f_signed.to_cbor()


def test_explicit_sig_overrides_auto_signing():
    """Passing --sig to append should not re-sign with the configured signer."""
    signer = Ed25519Signer.generate()
    explicit_sig = b"\xAA" * 64  # obviously not a real signature
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        try:
            frame = log.append(kind="x", actor="A1", payload={},
                               sig=explicit_sig)
            assert frame.sig == explicit_sig
        finally:
            log.close()


def test_signed_frame_tampering_breaks_chain():
    """Modify a byte inside a signed frame's payload after write:
    replay with a verifier must reject."""
    signer = Ed25519Signer.generate()
    verifier = Ed25519Verifier(signer.public_key())
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        log.append(kind="x", actor="A1", payload={"i": 1})
        log.close()

        seg = next(Path(tmp).glob("segment_*.aios"))
        # Flip a byte somewhere in the middle of the segment body
        raw = bytearray(seg.read_bytes())
        raw[-100] ^= 0x01  # before the last 4-byte CRC + other bytes
        seg.write_bytes(bytes(raw))

        # CRC failure may fire at __init__ recovery time OR at replay().
        # Either is a correct detection; catch ValueError either way.
        with pytest.raises(ValueError):
            log2 = EventLog(tmp, verifier=verifier)
            try:
                list(log2.replay())
            finally:
                log2.close()
