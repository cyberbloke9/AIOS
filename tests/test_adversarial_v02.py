"""Adversarial tests for the v0.2.0 surface: Ed25519 signing + writer lock.

Every test constructs a hostile state; the system must refuse. These are
the boundary checks specifically for the new P-Enterprise pieces landed
in sprints 12-16.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from aios.enterprise.signing import (
    Ed25519Signer, Ed25519Verifier, SignatureVerificationError,
    UnimplementedSigner, UnimplementedVerifier, cryptography_available,
)
from aios.runtime.event_log import EventLog, Frame, _encode_on_disk
from aios.runtime.filelock import LockContentionError


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography library not installed",
)


# Signature-level attacks ---------------------------------------------------


def test_forged_signature_from_wrong_key_rejected():
    """Attacker writes a frame whose sig was produced with their own key
    but replay is configured with the legitimate verifier."""
    legit = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    verifier = Ed25519Verifier(legit.public_key())
    with tempfile.TemporaryDirectory() as tmp:
        # Legitimate frame 0
        log = EventLog(tmp, signer=legit)
        log.append(kind="ok", actor="A1", payload={"i": 0})
        log.close()

        # Attacker appends a frame signed with their own key, properly
        # chained to the prior hash. Get the prior state by replay.
        log2 = EventLog(tmp)
        frames = list(log2.replay())
        last = frames[-1]
        log2.close()

        # Build a forged frame with a valid prev but attacker's signature.
        attack_frame = Frame(
            v=1, seq=last.seq + 1, ts_ns=last.ts_ns + 1,
            prev=last.frame_hash(), kind="attack", actor="A1",
            payload={"i": 1},
        )
        # Sign with attacker's key
        attack_sig = attacker.sign(attack_frame.unsigned_cbor())
        import dataclasses as dc
        attack_frame = dc.replace(attack_frame, sig=attack_sig)

        seg = next(Path(tmp).glob("segment_*.aios"))
        with open(seg, "ab") as fh:
            fh.write(_encode_on_disk(attack_frame.to_cbor()))

        # Replay with the legitimate verifier must refuse the attacker frame.
        log3 = EventLog(tmp, verifier=verifier)
        try:
            with pytest.raises(SignatureVerificationError):
                list(log3.replay())
        finally:
            log3.close()


def test_stripped_signature_breaks_chain():
    """Frame originally signed, then its sig field is stripped. The stripped
    frame's hash differs from the signed frame's, breaking the next prev."""
    signer = Ed25519Signer.generate()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        log.append(kind="a", actor="A1", payload={"i": 0})
        log.append(kind="b", actor="A1", payload={"i": 1})
        log.close()

        # Rewrite the active segment body replacing frame 0's on-disk form
        # with its unsigned-cbor variant. Frame 1's prev still points at
        # the SIGNED hash so replay must fail.
        segs = list(Path(tmp).glob("segment_*.aios"))
        assert len(segs) == 1
        seg = segs[0]
        data = seg.read_bytes()

        log2 = EventLog(tmp)
        frames = list(log2.replay())
        log2.close()
        f0 = frames[0]
        assert f0.sig is not None
        unsigned_cbor = f0.unsigned_cbor()
        old_on_disk = _encode_on_disk(f0.to_cbor())
        new_on_disk = _encode_on_disk(unsigned_cbor)
        assert old_on_disk != new_on_disk

        new_data = data.replace(old_on_disk, new_on_disk)
        seg.write_bytes(new_data)

        # Replay must refuse: frame 1 points at the old (signed) hash but
        # frame 0's hash on disk is now the unsigned form.
        log3 = EventLog(tmp)
        try:
            with pytest.raises(ValueError) as exc:
                list(log3.replay())
            assert "prev" in str(exc.value).lower()
        finally:
            log3.close()


def test_unimplemented_verifier_refuses_signed_frame_in_p_local():
    """P-Local ships with UnimplementedVerifier. Attaching it via
    EventLog(verifier=UnimplementedVerifier()) and encountering a signed
    frame at replay must raise — no silent pass."""
    signer = Ed25519Signer.generate()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=signer)
        log.append(kind="x", actor="A1", payload={})
        log.close()

        log2 = EventLog(tmp, verifier=UnimplementedVerifier())
        try:
            with pytest.raises(SignatureVerificationError):
                list(log2.replay())
        finally:
            log2.close()


def test_unimplemented_signer_refuses_to_configure_log():
    """Using the UnimplementedSigner as the configured signer and trying
    to append must raise — operators can't silently skip signing."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, signer=UnimplementedSigner())
        try:
            with pytest.raises(NotImplementedError):
                log.append(kind="x", actor="A1", payload={})
        finally:
            log.close()


# Writer-lock attacks -------------------------------------------------------


def test_concurrent_writer_refused_even_same_user():
    with tempfile.TemporaryDirectory() as tmp:
        first = EventLog(tmp)
        try:
            with pytest.raises(LockContentionError):
                EventLog(tmp)
        finally:
            first.close()


def test_lock_file_sabotage_does_not_release_os_lock():
    """Delete the log.lock file while a writer holds it: the OS-level
    lock is on the fd, not the path, so deletion on POSIX is a no-op
    for enforcement. On Windows, deletion is refused because the file
    is open. Either outcome is correct — a second writer still cannot
    acquire the lock."""
    with tempfile.TemporaryDirectory() as tmp:
        first = EventLog(tmp)
        try:
            lock_path = Path(tmp) / "log.lock"
            # Best-effort delete. On Windows this raises; catch it.
            try:
                lock_path.unlink()
            except (PermissionError, OSError):
                pass
            # Either way, a second EventLog must still refuse.
            with pytest.raises((LockContentionError, FileExistsError, OSError)):
                EventLog(tmp)
        finally:
            first.close()


def test_lock_contention_error_names_pid():
    with tempfile.TemporaryDirectory() as tmp:
        first = EventLog(tmp)
        try:
            try:
                EventLog(tmp)
            except LockContentionError as e:
                assert str(os.getpid()) in str(e)
                return
            raise AssertionError("contention did not raise")
        finally:
            first.close()


def test_writer_lock_released_after_close_allows_new_writer():
    with tempfile.TemporaryDirectory() as tmp:
        log1 = EventLog(tmp)
        log1.close()
        log2 = EventLog(tmp)
        log2.close()
        # success = the lock was actually released
