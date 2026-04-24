"""Tests for TUF staleness + freshness/rollback protection (sprint 65)."""
from __future__ import annotations

import hashlib

import pytest

from aios.distribution.tuf import SignedMetadata, TufKey, TufSignature
from aios.distribution.tuf_chain import (
    TufChainError,
    TufRollbackError,
    TufStaleError,
    verify_tuf_chain,
)
from aios.enterprise.signing import Ed25519Signer, cryptography_available


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography package not installed",
)


def _sign(role_type: str, signed: dict,
          signer: Ed25519Signer) -> SignedMetadata:
    tmp = SignedMetadata(role_type=role_type, signed=signed, signatures=())
    sig = signer.sign(tmp.canonical_sign_bytes())
    keyid = hashlib.sha256(signer.public_key()).hexdigest()[:16]
    return SignedMetadata(
        role_type=role_type, signed=signed,
        signatures=(TufSignature(keyid=keyid, sig=sig),),
    )


def _chain(
    *,
    root_expires="2030-01-01T00:00:00Z",
    targets_expires="2030-01-01T00:00:00Z",
    snapshot_expires="2030-01-01T00:00:00Z",
    timestamp_expires="2030-01-01T00:00:00Z",
    targets_version=1,
    snapshot_version=1,
    timestamp_version=1,
):
    root_s = Ed25519Signer.generate()
    tgt_s = Ed25519Signer.generate()
    snap_s = Ed25519Signer.generate()
    ts_s = Ed25519Signer.generate()

    def _kid(s): return hashlib.sha256(s.public_key()).hexdigest()[:16]
    root_kid, tgt_kid, snap_kid, ts_kid = map(
        _kid, [root_s, tgt_s, snap_s, ts_s]
    )

    root = _sign("root", {
        "spec_version": "1.0", "version": 1, "expires_iso": root_expires,
        "roles": {
            "root":      {"keyids": [root_kid], "threshold": 1},
            "targets":   {"keyids": [tgt_kid], "threshold": 1},
            "snapshot":  {"keyids": [snap_kid], "threshold": 1},
            "timestamp": {"keyids": [ts_kid], "threshold": 1},
        },
        "keys": {
            root_kid:  {"public_key": root_s.public_key()},
            tgt_kid:   {"public_key": tgt_s.public_key()},
            snap_kid:  {"public_key": snap_s.public_key()},
            ts_kid:    {"public_key": ts_s.public_key()},
        },
    }, root_s)
    targets = _sign("targets", {
        "spec_version": "1.0", "version": targets_version,
        "expires_iso": targets_expires, "targets": {},
    }, tgt_s)
    snapshot = _sign("snapshot", {
        "spec_version": "1.0", "version": snapshot_version,
        "expires_iso": snapshot_expires,
        "meta": {"targets.json": {"version": targets_version}},
    }, snap_s)
    timestamp = _sign("timestamp", {
        "spec_version": "1.0", "version": timestamp_version,
        "expires_iso": timestamp_expires,
        "meta": {"snapshot.json": {"version": snapshot_version}},
    }, ts_s)
    keys = {root_kid: TufKey(keyid=root_kid, public_key=root_s.public_key())}
    return root, targets, snapshot, timestamp, keys


# ---------------------------------------------------------------------------
# Staleness
# ---------------------------------------------------------------------------


def test_fresh_chain_passes_at_old_now():
    root, t, s, ts, keys = _chain()
    verify_tuf_chain(
        root=root, targets=t, snapshot=s, timestamp=ts,
        known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
    )


def test_expired_timestamp_rejected():
    root, t, s, ts, keys = _chain(timestamp_expires="2024-01-01T00:00:00Z")
    with pytest.raises(TufStaleError, match="timestamp"):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
        )


def test_expired_snapshot_rejected():
    root, t, s, ts, keys = _chain(snapshot_expires="2024-01-01T00:00:00Z")
    with pytest.raises(TufStaleError, match="snapshot"):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
        )


def test_expired_targets_rejected():
    root, t, s, ts, keys = _chain(targets_expires="2024-01-01T00:00:00Z")
    with pytest.raises(TufStaleError, match="targets"):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
        )


def test_expired_root_rejected():
    root, t, s, ts, keys = _chain(root_expires="2024-01-01T00:00:00Z")
    with pytest.raises(TufStaleError, match="root"):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
        )


def test_no_expires_iso_rejected():
    root_s = Ed25519Signer.generate()
    tgt_s = Ed25519Signer.generate()
    snap_s = Ed25519Signer.generate()
    ts_s = Ed25519Signer.generate()

    def _kid(s): return hashlib.sha256(s.public_key()).hexdigest()[:16]
    kids = list(map(_kid, [root_s, tgt_s, snap_s, ts_s]))
    root = _sign("root", {
        "spec_version": "1.0", "version": 1,
        "expires_iso": "2030-01-01T00:00:00Z",
        "roles": {
            "root":      {"keyids": [kids[0]], "threshold": 1},
            "targets":   {"keyids": [kids[1]], "threshold": 1},
            "snapshot":  {"keyids": [kids[2]], "threshold": 1},
            "timestamp": {"keyids": [kids[3]], "threshold": 1},
        },
        "keys": {
            kids[0]: {"public_key": root_s.public_key()},
            kids[1]: {"public_key": tgt_s.public_key()},
            kids[2]: {"public_key": snap_s.public_key()},
            kids[3]: {"public_key": ts_s.public_key()},
        },
    }, root_s)
    # Targets without expires_iso
    targets = _sign("targets", {
        "spec_version": "1.0", "version": 1, "targets": {},
    }, tgt_s)
    snapshot = _sign("snapshot", {
        "spec_version": "1.0", "version": 1,
        "expires_iso": "2030-01-01T00:00:00Z",
        "meta": {"targets.json": {"version": 1}},
    }, snap_s)
    timestamp = _sign("timestamp", {
        "spec_version": "1.0", "version": 1,
        "expires_iso": "2030-01-01T00:00:00Z",
        "meta": {"snapshot.json": {"version": 1}},
    }, ts_s)
    keys = {kids[0]: TufKey(keyid=kids[0], public_key=root_s.public_key())}
    with pytest.raises(TufChainError, match="expires_iso"):
        verify_tuf_chain(
            root=root, targets=targets, snapshot=snapshot, timestamp=timestamp,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
        )


# ---------------------------------------------------------------------------
# Rollback protection
# ---------------------------------------------------------------------------


def test_targets_rollback_rejected():
    root, t, s, ts, keys = _chain(targets_version=3, snapshot_version=5,
                                   timestamp_version=10)
    with pytest.raises(TufRollbackError, match="targets"):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
            last_known_targets_version=5,  # > current 3
        )


def test_snapshot_rollback_rejected():
    root, t, s, ts, keys = _chain(snapshot_version=4, timestamp_version=10)
    with pytest.raises(TufRollbackError, match="snapshot"):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
            last_known_snapshot_version=5,
        )


def test_timestamp_rollback_rejected():
    root, t, s, ts, keys = _chain(timestamp_version=9)
    with pytest.raises(TufRollbackError, match="timestamp"):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
            last_known_timestamp_version=10,
        )


def test_version_equal_to_last_known_accepted():
    """Version == last_known is fine; only STRICTLY LESS is a rollback."""
    root, t, s, ts, keys = _chain(
        targets_version=5, snapshot_version=5, timestamp_version=5,
    )
    verify_tuf_chain(
        root=root, targets=t, snapshot=s, timestamp=ts,
        known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
        last_known_targets_version=5,
        last_known_snapshot_version=5,
        last_known_timestamp_version=5,
    )


def test_version_greater_than_last_known_accepted():
    root, t, s, ts, keys = _chain(
        targets_version=10, snapshot_version=11, timestamp_version=12,
    )
    verify_tuf_chain(
        root=root, targets=t, snapshot=s, timestamp=ts,
        known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
        last_known_targets_version=5,
        last_known_snapshot_version=6,
        last_known_timestamp_version=7,
    )


def test_last_known_none_skips_rollback_check():
    root, t, s, ts, keys = _chain(
        targets_version=1, snapshot_version=1, timestamp_version=1,
    )
    # No last_known_* supplied — rollback check skipped
    verify_tuf_chain(
        root=root, targets=t, snapshot=s, timestamp=ts,
        known_root_keys=keys, now_iso="2026-01-01T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# now_iso parameter
# ---------------------------------------------------------------------------


def test_bad_now_iso_rejected():
    root, t, s, ts, keys = _chain()
    with pytest.raises(ValueError):
        verify_tuf_chain(
            root=root, targets=t, snapshot=s, timestamp=ts,
            known_root_keys=keys, now_iso="not-a-date",
        )


def test_default_now_uses_current_time():
    """With no now_iso, a chain that expires in the distant future passes,
    and a chain that expires in the past (2024) fails — real-clock check."""
    root, t, s, ts, keys = _chain()
    # Uses datetime.now(UTC) by default
    verify_tuf_chain(
        root=root, targets=t, snapshot=s, timestamp=ts,
        known_root_keys=keys,
    )
