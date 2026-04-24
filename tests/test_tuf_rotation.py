"""Tests for §6.4 TUF root key rotation (sprint 66)."""
from __future__ import annotations

import hashlib

import pytest

from aios.distribution.tuf import SignedMetadata, TufSignature
from aios.distribution.tuf_rotation import (
    TufRotationError,
    verify_root_rotation,
)
from aios.enterprise.signing import Ed25519Signer, cryptography_available


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography package not installed",
)


def _kid(s: Ed25519Signer) -> str:
    return hashlib.sha256(s.public_key()).hexdigest()[:16]


def _sign_root(signed: dict, signers: list[Ed25519Signer]) -> SignedMetadata:
    """Sign a root document with every given signer."""
    tmp = SignedMetadata(role_type="root", signed=signed, signatures=())
    payload = tmp.canonical_sign_bytes()
    sigs = tuple(
        TufSignature(keyid=_kid(s), sig=s.sign(payload))
        for s in signers
    )
    return SignedMetadata(role_type="root", signed=signed, signatures=sigs)


def _root_doc(
    *,
    version: int,
    keys: list[Ed25519Signer],
    threshold: int,
    expires: str = "2030-01-01T00:00:00Z",
) -> dict:
    """A root signed document whose `roles.root` authorizes the given signers."""
    keyids = [_kid(s) for s in keys]
    return {
        "spec_version": "1.0",
        "version": version,
        "expires_iso": expires,
        "roles": {
            "root": {"keyids": keyids, "threshold": threshold},
        },
        "keys": {
            _kid(s): {"public_key": s.public_key()} for s in keys
        },
    }


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_legitimate_rotation_accepted():
    """Old root signs new root; new root authorizes a fresh key set;
    both document lists are internally consistent."""
    old_s = Ed25519Signer.generate()
    new_s = Ed25519Signer.generate()

    old = _sign_root(_root_doc(version=1, keys=[old_s], threshold=1), [old_s])
    new_doc = _root_doc(version=2, keys=[new_s], threshold=1)
    # New root signed by BOTH old (authorization) and new (self-consistency)
    new = _sign_root(new_doc, [old_s, new_s])

    report = verify_root_rotation(old_root=old, new_root=new)
    assert report.old_version == 1
    assert report.new_version == 2
    assert report.signed_by_old == 1
    assert report.signed_by_new == 1
    assert _kid(new_s) in report.added_keyids
    assert _kid(old_s) in report.removed_keyids
    assert report.new_keys[_kid(new_s)].public_key == new_s.public_key()


def test_overlapping_keyset_rotation_accepted():
    """§6.4 allows new root to list OLD+NEW keys together during the
    transition period."""
    old_s = Ed25519Signer.generate()
    add_s = Ed25519Signer.generate()
    # Old root: just old_s at threshold 1
    old = _sign_root(_root_doc(version=1, keys=[old_s], threshold=1), [old_s])
    # New root lists BOTH old_s and add_s; threshold 1 (either can sign)
    new_doc = _root_doc(version=2, keys=[old_s, add_s], threshold=1)
    # Signed by old_s (meets old threshold + new threshold alone)
    new = _sign_root(new_doc, [old_s])

    report = verify_root_rotation(old_root=old, new_root=new)
    assert _kid(add_s) in report.added_keyids
    assert report.removed_keyids == ()   # old_s retained


def test_threshold_rotation_3_of_5():
    """A 3-of-5 root rotation: 3 of 5 OLD keys sign the new root."""
    old_keys = [Ed25519Signer.generate() for _ in range(5)]
    new_keys = [Ed25519Signer.generate() for _ in range(5)]
    old = _sign_root(
        _root_doc(version=1, keys=old_keys, threshold=3), old_keys,
    )
    new_doc = _root_doc(version=2, keys=new_keys, threshold=3)
    # Three old signers + three new signers
    new = _sign_root(new_doc, old_keys[:3] + new_keys[:3])

    report = verify_root_rotation(old_root=old, new_root=new)
    assert report.signed_by_old == 3
    assert report.signed_by_new == 3


# ---------------------------------------------------------------------------
# Unhappy paths
# ---------------------------------------------------------------------------


def test_rotation_without_old_signature_refused():
    """Attacker with new keys only — no old signer — tries to publish
    a v2 root. Must be rejected."""
    old_s = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    old = _sign_root(_root_doc(version=1, keys=[old_s], threshold=1), [old_s])
    forged_doc = _root_doc(version=2, keys=[attacker], threshold=1)
    # Only attacker signed — old threshold not met
    forged = _sign_root(forged_doc, [attacker])

    with pytest.raises(TufRotationError, match="not signed by old"):
        verify_root_rotation(old_root=old, new_root=forged)


def test_rotation_with_non_selfconsistent_new_refused():
    """New root signed by old but new root's declared keys don't
    actually sign it — belt-and-braces check kicks in."""
    old_s = Ed25519Signer.generate()
    new_s = Ed25519Signer.generate()
    old = _sign_root(_root_doc(version=1, keys=[old_s], threshold=1), [old_s])
    new_doc = _root_doc(version=2, keys=[new_s], threshold=1)
    # Signed ONLY by old — new_s didn't co-sign, so new root isn't
    # self-consistent under its declared keys
    new = _sign_root(new_doc, [old_s])

    with pytest.raises(TufRotationError, match="self-consistent"):
        verify_root_rotation(old_root=old, new_root=new)


def test_rotation_with_lower_version_refused():
    old_s = Ed25519Signer.generate()
    new_s = Ed25519Signer.generate()
    old = _sign_root(_root_doc(version=5, keys=[old_s], threshold=1), [old_s])
    new_doc = _root_doc(version=3, keys=[new_s], threshold=1)
    new = _sign_root(new_doc, [old_s, new_s])

    with pytest.raises(TufRotationError, match="version"):
        verify_root_rotation(old_root=old, new_root=new)


def test_rotation_with_equal_version_refused():
    """Same version is NOT a rotation — must strictly increase."""
    old_s = Ed25519Signer.generate()
    new_s = Ed25519Signer.generate()
    old = _sign_root(_root_doc(version=1, keys=[old_s], threshold=1), [old_s])
    new_doc = _root_doc(version=1, keys=[new_s], threshold=1)
    new = _sign_root(new_doc, [old_s, new_s])
    with pytest.raises(TufRotationError, match="version"):
        verify_root_rotation(old_root=old, new_root=new)


def test_non_root_metadata_refused():
    s = Ed25519Signer.generate()
    old = _sign_root(_root_doc(version=1, keys=[s], threshold=1), [s])
    # Pass something that's NOT root
    targets_meta = SignedMetadata(
        role_type="targets", signed={"version": 2}, signatures=(),
    )
    with pytest.raises(TufRotationError, match="role_type"):
        verify_root_rotation(old_root=old, new_root=targets_meta)


def test_old_root_not_self_consistent_refused():
    """If old_root itself doesn't verify under its declared keys (e.g.
    someone fabricated it), the rotation check catches it even before
    the new_root signature check."""
    phantom = Ed25519Signer.generate()
    real = Ed25519Signer.generate()
    # Old root document declares `real` as the only root key but is
    # signed by `phantom` — signature invalid against declared keys
    bogus_old_doc = _root_doc(version=1, keys=[real], threshold=1)
    bogus_old = _sign_root(bogus_old_doc, [phantom])

    new_s = Ed25519Signer.generate()
    new_doc = _root_doc(version=2, keys=[new_s], threshold=1)
    new = _sign_root(new_doc, [real, new_s])

    with pytest.raises(TufRotationError, match="old root"):
        verify_root_rotation(old_root=bogus_old, new_root=new)
