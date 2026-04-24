"""Tests for DPoP extension §2.8 (sprint 63)."""
from __future__ import annotations

import time

import pytest

from aios.enterprise.macaroons import (
    MacaroonError,
    TokenVerificationError,
    VerifyContext,
    add_pop_caveat,
    issue_token,
    verify_token,
    verify_with_pop,
)
from aios.enterprise.signing import Ed25519Signer, cryptography_available


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography package not installed",
)


def _base_token():
    issuer = Ed25519Signer.generate()
    token = issue_token(
        issuer_signer=issuer, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=60 * 10**9,
    )
    return issuer, token


def _ctx(now: int | None = None):
    return VerifyContext(
        subject="A3", action="x", scope={},
        now_ns=now or time.time_ns(),
    )


# ---------------------------------------------------------------------------
# add_pop_caveat
# ---------------------------------------------------------------------------


def test_add_pop_caveat_binds_to_key():
    _, token = _base_token()
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())
    assert any(c.type == "pop" for c in bound.caveats)
    pop = next(c for c in bound.caveats if c.type == "pop")
    assert pop.value["pubkey_hex"] == subject.public_key().hex()


def test_add_pop_caveat_rejects_wrong_length_key():
    _, token = _base_token()
    with pytest.raises(MacaroonError, match="32 bytes"):
        add_pop_caveat(token, subject_pubkey=b"\x00" * 16)


# ---------------------------------------------------------------------------
# verify_token must refuse pop-bound tokens
# ---------------------------------------------------------------------------


def test_verify_token_refuses_pop_bound_token():
    """§2.8 — a pop-bound token cannot be verified by the bare flow."""
    issuer, token = _base_token()
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())
    with pytest.raises(TokenVerificationError, match="verify_with_pop"):
        verify_token(bound, issuer_pubkey=issuer.public_key(),
                     context=_ctx())


# ---------------------------------------------------------------------------
# verify_with_pop — happy paths
# ---------------------------------------------------------------------------


def test_verify_with_pop_happy_path():
    issuer, token = _base_token()
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())

    proof_msg = b"timestamp + request hash + ..."
    proof_sig = subject.sign(proof_msg)
    verify_with_pop(
        bound,
        issuer_pubkey=issuer.public_key(),
        context=_ctx(),
        proof_message=proof_msg,
        proof_sig=proof_sig,
    )


def test_verify_with_pop_works_with_additional_caveats():
    """A pop-bound token with scope+audience caveats still verifies."""
    issuer, token = _base_token()
    from aios.enterprise.macaroons import add_caveat
    token = add_caveat(token, caveat_type="audience",
                        value={"aud": "storage-service"})
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())

    proof_msg = b"proof"
    proof_sig = subject.sign(proof_msg)
    ctx = VerifyContext(
        subject="A3", action="x", scope={},
        now_ns=time.time_ns(),
        audience="storage-service",
    )
    verify_with_pop(
        bound, issuer_pubkey=issuer.public_key(),
        context=ctx,
        proof_message=proof_msg, proof_sig=proof_sig,
    )


# ---------------------------------------------------------------------------
# verify_with_pop — unhappy paths
# ---------------------------------------------------------------------------


def test_verify_with_pop_rejects_wrong_key_proof():
    """A proof from a DIFFERENT key than the one bound must fail."""
    issuer, token = _base_token()
    subject = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())

    proof_msg = b"m"
    forged_sig = attacker.sign(proof_msg)
    with pytest.raises(TokenVerificationError,
                       match="proof-of-possession"):
        verify_with_pop(
            bound, issuer_pubkey=issuer.public_key(),
            context=_ctx(),
            proof_message=proof_msg, proof_sig=forged_sig,
        )


def test_verify_with_pop_rejects_tampered_proof_message():
    """Proof was signed for `a` but caller presents `b`."""
    issuer, token = _base_token()
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())

    original_msg = b"original"
    sig_of_original = subject.sign(original_msg)
    with pytest.raises(TokenVerificationError):
        verify_with_pop(
            bound, issuer_pubkey=issuer.public_key(),
            context=_ctx(),
            proof_message=b"tampered",
            proof_sig=sig_of_original,
        )


def test_verify_with_pop_rejects_missing_pop_caveat():
    """verify_with_pop is the wrong path for bare tokens."""
    issuer, token = _base_token()
    subject = Ed25519Signer.generate()
    with pytest.raises(TokenVerificationError, match="no pop caveat"):
        verify_with_pop(
            token,
            issuer_pubkey=issuer.public_key(),
            context=_ctx(),
            proof_message=b"m", proof_sig=subject.sign(b"m"),
        )


def test_verify_with_pop_rejects_wrong_sig_length():
    issuer, token = _base_token()
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())
    with pytest.raises(TokenVerificationError, match="64 bytes"):
        verify_with_pop(
            bound, issuer_pubkey=issuer.public_key(),
            context=_ctx(),
            proof_message=b"m", proof_sig=b"\x00" * 32,
        )


def test_verify_with_pop_rejects_tampered_caveat_chain():
    """Even with a valid proof, a broken MAC chain kills the token."""
    issuer, token = _base_token()
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())
    # Flip a bit in the pop caveat's MAC
    from aios.enterprise.macaroons import Caveat
    tampered_caveats = list(bound.caveats)
    bad = tampered_caveats[0]
    tampered_mac = bytearray(bad.mac)
    tampered_mac[0] ^= 0x01
    tampered_caveats[0] = Caveat(type=bad.type, value=bad.value,
                                  mac=bytes(tampered_mac))
    forged = bound.__class__(
        v=bound.v, tid=bound.tid, iss=bound.iss, sub=bound.sub,
        act=bound.act, scp=bound.scp, nbf_ns=bound.nbf_ns,
        exp_ns=bound.exp_ns, caveats=tuple(tampered_caveats),
        sig=bound.sig,
    )
    proof_msg = b"m"
    proof_sig = subject.sign(proof_msg)
    with pytest.raises(TokenVerificationError, match="MAC chain"):
        verify_with_pop(
            forged, issuer_pubkey=issuer.public_key(),
            context=_ctx(),
            proof_message=proof_msg, proof_sig=proof_sig,
        )


def test_verify_with_pop_rejects_expired_token():
    """pop-bound tokens still expire."""
    issuer = Ed25519Signer.generate()
    past = time.time_ns() - 600 * 10**9     # 10 min ago
    token = issue_token(
        issuer_signer=issuer, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=60 * 10**9, now_ns=past,
    )
    subject = Ed25519Signer.generate()
    bound = add_pop_caveat(token, subject_pubkey=subject.public_key())
    proof_msg = b"m"
    proof_sig = subject.sign(proof_msg)
    with pytest.raises(TokenVerificationError, match="expired"):
        verify_with_pop(
            bound, issuer_pubkey=issuer.public_key(),
            context=_ctx(),
            proof_message=proof_msg, proof_sig=proof_sig,
        )
