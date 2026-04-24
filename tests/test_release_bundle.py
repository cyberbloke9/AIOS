"""Tests for signed release bundle + local verify (sprint 55)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aios.distribution.release import (
    RELEASE_BUNDLE_VERSION,
    ReleaseBundle,
    ReleaseBundleError,
    _infer_kind,
    build_release_bundle,
    verify_release_bundle,
)
from aios.distribution.tuf import TufKey
from aios.enterprise.signing import Ed25519Signer, cryptography_available


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography package not installed",
)


# Helpers ----------------------------------------------------------------


def _mk_artifact(dir: Path, name: str, content: bytes = b"x") -> Path:
    p = dir / name
    p.write_bytes(content)
    return p


# _infer_kind ------------------------------------------------------------


def test_infer_kind_wheel(tmp_path: Path):
    assert _infer_kind(tmp_path / "aios-0.5.0-py3-none-any.whl") == "wheel"


def test_infer_kind_sdist(tmp_path: Path):
    assert _infer_kind(tmp_path / "aios-0.5.0.tar.gz") == "sdist"


def test_infer_kind_sbom_spdx(tmp_path: Path):
    assert _infer_kind(tmp_path / "aios.spdx.json") == "sbom_spdx"


def test_infer_kind_sbom_cyclonedx(tmp_path: Path):
    assert _infer_kind(tmp_path / "aios.cyclonedx.json") == "sbom_cyclonedx"


def test_infer_kind_integrity(tmp_path: Path):
    assert _infer_kind(tmp_path / "integrity.manifest.json") == "integrity_manifest"


def test_infer_kind_other(tmp_path: Path):
    assert _infer_kind(tmp_path / "release-notes.txt") == "other"


# build_release_bundle ---------------------------------------------------


def test_build_unsigned_bundle(tmp_path: Path):
    a = _mk_artifact(tmp_path, "aios-0.5.0.tar.gz", b"sdist bytes")
    b = _mk_artifact(tmp_path, "aios.spdx.json", b"{}")
    bundle = build_release_bundle(
        [a, b], project="aios", version="0.5.0",
    )
    assert bundle.bundle_version == RELEASE_BUNDLE_VERSION
    assert bundle.project == "aios"
    assert len(bundle.artifacts) == 2
    assert bundle.signatures == ()


def test_build_signed_bundle(tmp_path: Path):
    a = _mk_artifact(tmp_path, "aios-0.5.0.tar.gz", b"x")
    signer = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0",
        signers=[signer],
    )
    assert len(bundle.signatures) == 1
    # The sig covers the canonical_sign_bytes
    assert len(bundle.signatures[0].sig) == 64


def test_build_bundle_rejects_missing_artifact(tmp_path: Path):
    with pytest.raises(ReleaseBundleError, match="not found"):
        build_release_bundle(
            [tmp_path / "does-not-exist"],
            project="aios", version="0.5.0",
        )


def test_artifact_hash_matches_file_contents(tmp_path: Path):
    data = b"hello AIOS"
    p = _mk_artifact(tmp_path, "x.tar.gz", data)
    bundle = build_release_bundle([p], project="aios", version="0.5.0")
    assert bundle.artifacts[0].sha256 == hashlib.sha256(data).hexdigest()
    assert bundle.artifacts[0].size == len(data)


def test_artifacts_sorted_by_path(tmp_path: Path):
    b = _mk_artifact(tmp_path, "b.whl")
    a = _mk_artifact(tmp_path, "a.whl")
    bundle = build_release_bundle([b, a], project="aios", version="0.5.0")
    assert [x.path for x in bundle.artifacts] == ["a.whl", "b.whl"]


# JSON round-trip --------------------------------------------------------


def test_bundle_json_round_trip(tmp_path: Path):
    a = _mk_artifact(tmp_path, "a.whl", b"wheel")
    signer = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[signer],
    )
    text = bundle.to_json()
    loaded = ReleaseBundle.from_json(text)
    assert loaded.version == bundle.version
    assert loaded.artifacts[0].sha256 == bundle.artifacts[0].sha256
    assert loaded.signatures[0].keyid == bundle.signatures[0].keyid
    # And the loaded bundle's canonical bytes are identical
    assert loaded.canonical_sign_bytes() == bundle.canonical_sign_bytes()


def test_bundle_rejects_unsupported_version(tmp_path: Path):
    text = json.dumps({
        "bundle_version": "99",
        "project": "aios", "version": "0.5.0",
        "created_iso": "t", "artifacts": [], "signatures": [],
    })
    with pytest.raises(ReleaseBundleError, match="unsupported"):
        ReleaseBundle.from_json(text)


def test_canonical_sign_bytes_excludes_signatures(tmp_path: Path):
    """Signing payload is signature-free — two bundles with same
    content but different signatures must have identical sign bytes."""
    a = _mk_artifact(tmp_path, "a.whl")
    s1 = Ed25519Signer.generate()
    s2 = Ed25519Signer.generate()
    b1 = build_release_bundle([a], project="aios", version="0.5.0", signers=[s1])
    b2 = build_release_bundle([a], project="aios", version="0.5.0", signers=[s2])
    # Timestamps might differ; we care about artifact ordering + content.
    # Instead, sign one bundle then manually create unsigned variant:
    import dataclasses as dc
    unsigned = dc.replace(b1, signatures=())
    alt = dc.replace(b1, signatures=b2.signatures)
    # canonical_sign_bytes doesn't include signatures -> same bytes
    # (with unsigned and signed+alt bundles constructed from b1)
    assert unsigned.canonical_sign_bytes() == alt.canonical_sign_bytes()


# verify_release_bundle --------------------------------------------------


def test_verify_happy_path(tmp_path: Path):
    a = _mk_artifact(tmp_path, "a.whl", b"wheel bytes")
    signer = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[signer],
    )
    tk = TufKey.from_public_bytes(signer.public_key())
    report = verify_release_bundle(
        bundle, keys={tk.keyid: tk}, artifact_root=tmp_path,
    )
    assert report.ok is True
    assert report.signatures_verified == 1
    assert report.artifacts_hashes_checked == 1
    assert report.reasons == ()


def test_verify_without_artifacts_still_checks_signatures(tmp_path: Path):
    a = _mk_artifact(tmp_path, "a.whl")
    signer = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[signer],
    )
    tk = TufKey.from_public_bytes(signer.public_key())
    report = verify_release_bundle(bundle, keys={tk.keyid: tk})
    assert report.ok is True
    assert report.artifacts_hashes_checked == 0


def test_verify_detects_artifact_missing(tmp_path: Path):
    a = _mk_artifact(tmp_path, "a.whl")
    signer = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[signer],
    )
    a.unlink()
    tk = TufKey.from_public_bytes(signer.public_key())
    report = verify_release_bundle(
        bundle, keys={tk.keyid: tk}, artifact_root=tmp_path,
    )
    assert report.ok is False
    assert "a.whl" in report.artifacts_missing


def test_verify_detects_artifact_tamper(tmp_path: Path):
    a = _mk_artifact(tmp_path, "a.whl", b"original")
    signer = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[signer],
    )
    a.write_bytes(b"TAMPERED")
    tk = TufKey.from_public_bytes(signer.public_key())
    report = verify_release_bundle(
        bundle, keys={tk.keyid: tk}, artifact_root=tmp_path,
    )
    assert report.ok is False
    assert "a.whl" in report.artifacts_mismatched


def test_verify_rejects_wrong_key(tmp_path: Path):
    a = _mk_artifact(tmp_path, "a.whl")
    signer = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[signer],
    )
    # Register the ATTACKER's key under the signer's keyid — verify must refuse
    signer_tk = TufKey.from_public_bytes(signer.public_key())
    attacker_tk = TufKey(keyid=signer_tk.keyid, public_key=attacker.public_key())
    report = verify_release_bundle(
        bundle, keys={signer_tk.keyid: attacker_tk}, artifact_root=tmp_path,
    )
    assert report.ok is False
    assert signer_tk.keyid in report.failed_signatures


def test_verify_unknown_keyid_ignored(tmp_path: Path):
    """Signatures from keys not in the `keys` dict are silently dropped."""
    a = _mk_artifact(tmp_path, "a.whl")
    signer = Ed25519Signer.generate()
    rogue = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0",
        signers=[signer, rogue],
    )
    tk = TufKey.from_public_bytes(signer.public_key())
    # Only the legit key registered; rogue's sig has an unknown keyid
    report = verify_release_bundle(bundle, keys={tk.keyid: tk})
    assert report.ok is True
    assert report.signatures_verified == 1


def test_verify_min_signatures_enforced(tmp_path: Path):
    a = _mk_artifact(tmp_path, "a.whl")
    s1 = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[s1],
    )
    tk = TufKey.from_public_bytes(s1.public_key())
    report = verify_release_bundle(
        bundle, keys={tk.keyid: tk}, min_signatures=2,
    )
    assert report.ok is False
    assert any("need >= 2" in r for r in report.reasons)


def test_verify_tampered_bundle_rejected(tmp_path: Path):
    """Changing a field on the bundle after signing invalidates the sig."""
    import dataclasses as dc
    a = _mk_artifact(tmp_path, "a.whl")
    signer = Ed25519Signer.generate()
    bundle = build_release_bundle(
        [a], project="aios", version="0.5.0", signers=[signer],
    )
    tampered = dc.replace(bundle, version="9.9.9")
    tk = TufKey.from_public_bytes(signer.public_key())
    report = verify_release_bundle(
        tampered, keys={tk.keyid: tk},
    )
    assert report.ok is False
    assert tk.keyid in report.failed_signatures
