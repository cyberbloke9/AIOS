"""Tests for the concrete Ed25519 signer / verifier.

Skipped when the `cryptography` library is not installed (e.g., a bare
pip install without the `enterprise` extra).
"""
from __future__ import annotations

import pytest

from aios.enterprise.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    SignatureVerificationError,
    Signer,
    Verifier,
    cryptography_available,
)


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography library not installed (install with .[enterprise])",
)


def test_generate_produces_32_byte_private_key():
    s = Ed25519Signer.generate()
    assert len(s.private_key_bytes()) == 32


def test_signer_public_key_is_32_bytes():
    s = Ed25519Signer.generate()
    assert len(s.public_key()) == 32


def test_signer_sign_produces_64_byte_signature():
    s = Ed25519Signer.generate()
    sig = s.sign(b"some frame CBOR bytes")
    assert len(sig) == 64


def test_sign_verify_round_trip():
    s = Ed25519Signer.generate()
    v = Ed25519Verifier(s.public_key())
    message = b"hello AIOS"
    sig = s.sign(message)
    assert v.verify(message, sig) is True


def test_verifier_rejects_wrong_public_key():
    s1 = Ed25519Signer.generate()
    s2 = Ed25519Signer.generate()
    v = Ed25519Verifier(s2.public_key())  # verifier bound to s2's key
    sig = s1.sign(b"msg")
    with pytest.raises(SignatureVerificationError):
        v.verify(b"msg", sig)


def test_verifier_rejects_tampered_message():
    s = Ed25519Signer.generate()
    v = Ed25519Verifier(s.public_key())
    sig = s.sign(b"original message")
    with pytest.raises(SignatureVerificationError):
        v.verify(b"tampered message", sig)


def test_verifier_rejects_tampered_signature():
    s = Ed25519Signer.generate()
    v = Ed25519Verifier(s.public_key())
    sig = bytearray(s.sign(b"msg"))
    sig[0] ^= 0x01
    with pytest.raises(SignatureVerificationError):
        v.verify(b"msg", bytes(sig))


def test_verifier_rejects_wrong_length_signature():
    s = Ed25519Signer.generate()
    v = Ed25519Verifier(s.public_key())
    with pytest.raises(SignatureVerificationError):
        v.verify(b"msg", b"\x00" * 32)  # 32 bytes, not 64


def test_signer_from_bytes_rejects_wrong_length():
    with pytest.raises(ValueError):
        Ed25519Signer(b"\x00" * 16)


def test_verifier_from_bytes_rejects_wrong_length():
    with pytest.raises(ValueError):
        Ed25519Verifier(b"\x00" * 16)


def test_private_key_round_trip():
    s1 = Ed25519Signer.generate()
    priv = s1.private_key_bytes()
    s2 = Ed25519Signer(priv)
    # s2 was loaded from s1's key material — public keys must match
    assert s2.public_key() == s1.public_key()
    # And a signature made by s2 must verify with s1's (same) public key
    v = Ed25519Verifier(s1.public_key())
    assert v.verify(b"x", s2.sign(b"x"))


def test_concrete_types_satisfy_protocols():
    s = Ed25519Signer.generate()
    v = Ed25519Verifier(s.public_key())
    assert isinstance(s, Signer)
    assert isinstance(v, Verifier)
