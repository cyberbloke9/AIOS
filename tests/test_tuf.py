"""Tests for TUF role metadata + threshold signature verify (sprint 53)."""
from __future__ import annotations

import pytest

from aios.enterprise.signing import Ed25519Signer, cryptography_available
from aios.distribution.tuf import (
    ROLE_TYPES,
    SignedMetadata,
    TufKey,
    TufMetadataError,
    TufRoleSpec,
    TufSignature,
    TufVerificationError,
    root_metadata_fingerprint,
    verify_signed_metadata,
)


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography package not installed",
)


# Key + role spec --------------------------------------------------------


def test_tufkey_from_public_bytes_computes_keyid():
    signer = Ed25519Signer.generate()
    k = TufKey.from_public_bytes(signer.public_key())
    assert len(k.keyid) == 16
    assert k.public_key == signer.public_key()


def test_tufkey_rejects_wrong_length():
    with pytest.raises(TufMetadataError):
        TufKey.from_public_bytes(b"\x00" * 16)


def test_role_spec_rejects_threshold_zero():
    with pytest.raises(TufMetadataError):
        TufRoleSpec(keyids=("a",), threshold=0)


def test_role_spec_rejects_threshold_above_keyids():
    with pytest.raises(TufMetadataError):
        TufRoleSpec(keyids=("a", "b"), threshold=3)


def test_role_spec_threshold_equal_to_keyids_allowed():
    TufRoleSpec(keyids=("a", "b"), threshold=2)


def test_role_types_constant():
    assert ROLE_TYPES == ("root", "targets", "snapshot", "timestamp")


# Canonical sign bytes ---------------------------------------------------


def test_canonical_sign_bytes_deterministic():
    m1 = SignedMetadata(
        role_type="targets",
        signed={"version": 1, "expires": "2027-01-01T00:00:00Z"},
        signatures=(),
    )
    m2 = SignedMetadata(
        role_type="targets",
        signed={"expires": "2027-01-01T00:00:00Z", "version": 1},
        signatures=(),
    )
    # Key order in the dict must not affect canonical bytes
    assert m1.canonical_sign_bytes() == m2.canonical_sign_bytes()


def test_root_metadata_fingerprint_stable():
    m1 = SignedMetadata(
        role_type="root", signed={"v": 1},
        signatures=(),
    )
    m2 = SignedMetadata(
        role_type="root", signed={"v": 1},
        signatures=(TufSignature(keyid="x", sig=b"x" * 64),),
    )
    # Signatures don't affect the fingerprint — only `signed`
    assert root_metadata_fingerprint(m1) == root_metadata_fingerprint(m2)


# Verification happy + unhappy paths ------------------------------------


def _sign_metadata(signers: list[Ed25519Signer], role_type: str, signed: dict):
    keyids = {}
    sigs = []
    payload = SignedMetadata(
        role_type=role_type, signed=signed, signatures=(),
    ).canonical_sign_bytes()
    for s in signers:
        tk = TufKey.from_public_bytes(s.public_key())
        keyids[tk.keyid] = tk
        sigs.append(TufSignature(keyid=tk.keyid, sig=s.sign(payload)))
    return SignedMetadata(
        role_type=role_type, signed=signed, signatures=tuple(sigs),
    ), keyids


def test_threshold_met_with_exact_count():
    s1 = Ed25519Signer.generate()
    s2 = Ed25519Signer.generate()
    s3 = Ed25519Signer.generate()
    signed_meta, keys = _sign_metadata([s1, s2, s3], "root", {"v": 1})
    spec = TufRoleSpec(keyids=tuple(keys.keys()), threshold=3)
    assert verify_signed_metadata(signed_meta, keys=keys, role_spec=spec) == 3


def test_threshold_met_with_extras():
    signers = [Ed25519Signer.generate() for _ in range(5)]
    signed_meta, keys = _sign_metadata(signers, "root", {"v": 1})
    spec = TufRoleSpec(keyids=tuple(keys.keys()), threshold=3)   # 3 of 5
    assert verify_signed_metadata(signed_meta, keys=keys, role_spec=spec) == 5


def test_threshold_not_met_raises():
    signers = [Ed25519Signer.generate() for _ in range(3)]
    signed_meta, keys = _sign_metadata(signers[:1], "root", {"v": 1})
    spec = TufRoleSpec(
        keyids=tuple(TufKey.from_public_bytes(s.public_key()).keyid
                     for s in signers),
        threshold=2,
    )
    # Keys must still be registered for lookup; simulate that.
    all_keys = {TufKey.from_public_bytes(s.public_key()).keyid:
                TufKey.from_public_bytes(s.public_key())
                for s in signers}
    with pytest.raises(TufVerificationError, match="threshold"):
        verify_signed_metadata(signed_meta, keys=all_keys, role_spec=spec)


def test_unauthorized_signature_ignored():
    """A signature from a key not in the role spec is silently dropped
    (not an error, but doesn't count toward threshold)."""
    authorized = [Ed25519Signer.generate() for _ in range(2)]
    rogue = Ed25519Signer.generate()
    signed_meta, keys = _sign_metadata([*authorized, rogue], "root", {"v": 1})
    # Only authorized keys in the spec
    authorized_ids = tuple(
        TufKey.from_public_bytes(s.public_key()).keyid for s in authorized
    )
    spec = TufRoleSpec(keyids=authorized_ids, threshold=2)
    assert verify_signed_metadata(signed_meta, keys=keys, role_spec=spec) == 2


def test_rogue_alone_fails_threshold():
    """If ONLY a rogue key signs, even at threshold=1 it should fail
    because the rogue isn't authorized."""
    authorized = Ed25519Signer.generate()
    rogue = Ed25519Signer.generate()
    signed_meta, _ = _sign_metadata([rogue], "root", {"v": 1})
    authorized_tk = TufKey.from_public_bytes(authorized.public_key())
    rogue_tk = TufKey.from_public_bytes(rogue.public_key())
    spec = TufRoleSpec(keyids=(authorized_tk.keyid,), threshold=1)
    with pytest.raises(TufVerificationError):
        verify_signed_metadata(
            signed_meta,
            keys={authorized_tk.keyid: authorized_tk,
                  rogue_tk.keyid: rogue_tk},
            role_spec=spec,
        )


def test_tampered_payload_breaks_all_signatures():
    signers = [Ed25519Signer.generate() for _ in range(3)]
    signed_meta, keys = _sign_metadata(signers, "root", {"v": 1})
    # Tamper the signed field — signatures no longer cover current bytes
    tampered = SignedMetadata(
        role_type=signed_meta.role_type,
        signed={"v": 999},                     # changed
        signatures=signed_meta.signatures,
    )
    spec = TufRoleSpec(keyids=tuple(keys.keys()), threshold=1)
    with pytest.raises(TufVerificationError):
        verify_signed_metadata(tampered, keys=keys, role_spec=spec)


def test_duplicate_keyids_count_once():
    """Two signatures from the same key collapse to one verified signer."""
    s1 = Ed25519Signer.generate()
    s2 = Ed25519Signer.generate()   # authorized but we won't sign with it
    signed_meta, _ = _sign_metadata([s1], "root", {"v": 1})
    # Duplicate s1's signature so there are TWO sig entries with the same keyid
    dup_meta = SignedMetadata(
        role_type=signed_meta.role_type,
        signed=signed_meta.signed,
        signatures=signed_meta.signatures + signed_meta.signatures,
    )
    k1 = TufKey.from_public_bytes(s1.public_key())
    k2 = TufKey.from_public_bytes(s2.public_key())
    # Threshold 2 with both keyids authorized; only s1 actually signed
    spec = TufRoleSpec(keyids=(k1.keyid, k2.keyid), threshold=2)
    with pytest.raises(TufVerificationError):
        verify_signed_metadata(dup_meta, keys={k1.keyid: k1, k2.keyid: k2},
                                role_spec=spec)


def test_fingerprint_stable_across_signature_changes():
    s = Ed25519Signer.generate()
    meta_unsigned, _ = _sign_metadata([], "root", {"v": 1})
    meta_signed, _ = _sign_metadata([s], "root", {"v": 1})
    assert root_metadata_fingerprint(meta_unsigned) == \
           root_metadata_fingerprint(meta_signed)
