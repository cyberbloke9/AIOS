"""Signed release bundle (sprint 55).

Distribution §5.1 — every release is signed using a Sigstore-equivalent
mechanism. The artifact hash is signed; the signature is stored alongside
the artifact and (in production) submitted to a tamper-evident
transparency log.

This module builds a self-describing bundle that is Sigstore-compatible
in shape without requiring the Sigstore service at build time. A
downstream integrator can:
  1. Run build_release_bundle() against a directory of artifacts +
     a Targets signer (or signers, for threshold delegation).
  2. Publish the JSON bundle alongside the artifacts.
  3. Operators run verify_release_bundle() + provide the public keys
     (TufKey set). Re-hashes the artifact files if they are present
     on disk, compares to bundle hashes.

Out-of-scope (deferred to a post-M5 sprint):
  - Automatic Rekor transparency-log submission (§5.4)
  - OIDC-bound ephemeral key issuance (Sigstore keyless style)
  - Cross-publisher verification using the TUF root metadata chain —
    this module signs with a single Targets-equivalent key; chaining
    to the TUF root is a caller concern that uses tuf.py (sprint 53)
"""
from __future__ import annotations

import dataclasses as dc
import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Iterable, Literal

from aios.enterprise.signing import (
    Ed25519Verifier,
    SignatureVerificationError,
    Signer,
    cryptography_available,
)
from aios.distribution.tuf import TufKey, TufSignature

ArtifactKind = Literal["wheel", "sdist", "sbom_spdx", "sbom_cyclonedx",
                        "integrity_manifest", "root_metadata", "other"]

RELEASE_BUNDLE_VERSION = "1.0"


class ReleaseBundleError(ValueError):
    """Malformed bundle or failed verification."""


@dc.dataclass(frozen=True)
class ReleaseArtifact:
    path: str
    sha256: str
    size: int
    kind: ArtifactKind


@dc.dataclass(frozen=True)
class ReleaseBundle:
    bundle_version: str
    project: str
    version: str
    created_iso: str
    artifacts: tuple[ReleaseArtifact, ...]
    signatures: tuple[TufSignature, ...]

    def canonical_sign_bytes(self) -> bytes:
        """Deterministic bytes the signatures cover.

        Includes every field EXCEPT signatures (chicken/egg). JSON-
        canonical form with sorted keys + no whitespace so signatures
        are reproducible across implementations.
        """
        payload = {
            "bundle_version": self.bundle_version,
            "project": self.project,
            "version": self.version,
            "created_iso": self.created_iso,
            "artifacts": [
                {"path": a.path, "sha256": a.sha256,
                 "size": a.size, "kind": a.kind}
                for a in sorted(self.artifacts, key=lambda x: x.path)
            ],
        }
        return json.dumps(payload, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def to_json(self) -> str:
        payload = json.loads(self.canonical_sign_bytes())
        payload["signatures"] = [
            {"keyid": s.keyid, "sig_hex": s.sig.hex()}
            for s in self.signatures
        ]
        return json.dumps(payload, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "ReleaseBundle":
        data = json.loads(text)
        if data.get("bundle_version") != RELEASE_BUNDLE_VERSION:
            raise ReleaseBundleError(
                f"unsupported bundle_version: {data.get('bundle_version')}"
            )
        artifacts = tuple(
            ReleaseArtifact(
                path=a["path"],
                sha256=a["sha256"],
                size=int(a["size"]),
                kind=a["kind"],
            )
            for a in data.get("artifacts", [])
        )
        sigs = tuple(
            TufSignature(keyid=s["keyid"], sig=bytes.fromhex(s["sig_hex"]))
            for s in data.get("signatures", [])
        )
        return cls(
            bundle_version=data["bundle_version"],
            project=data["project"],
            version=data["version"],
            created_iso=data["created_iso"],
            artifacts=artifacts,
            signatures=sigs,
        )


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


_KIND_BY_EXT: dict[str, ArtifactKind] = {
    ".whl": "wheel",
    ".tar.gz": "sdist",
    ".cbor": "root_metadata",
}
_KIND_BY_NAME_HINT: tuple[tuple[str, ArtifactKind], ...] = (
    ("spdx", "sbom_spdx"),
    ("cyclonedx", "sbom_cyclonedx"),
    ("integrity", "integrity_manifest"),
    ("root", "root_metadata"),
)


def _infer_kind(path: Path) -> ArtifactKind:
    name = path.name.lower()
    for hint, kind in _KIND_BY_NAME_HINT:
        if hint in name:
            return kind
    for ext, kind in _KIND_BY_EXT.items():
        if name.endswith(ext):
            return kind
    return "other"


def build_release_bundle(
    artifact_paths: Iterable[Path],
    *,
    project: str,
    version: str,
    signers: Iterable[Signer] | None = None,
) -> ReleaseBundle:
    """Hash every artifact, build a ReleaseBundle, sign it.

    `signers` is optional — an unsigned bundle is still well-formed
    (useful for unit tests). Multiple signers produce multiple
    TufSignature entries the verifier can match against a TufRoleSpec
    threshold.
    """
    artifacts: list[ReleaseArtifact] = []
    for p in artifact_paths:
        path = Path(p)
        if not path.is_file():
            raise ReleaseBundleError(f"artifact not found: {path}")
        raw = path.read_bytes()
        artifacts.append(ReleaseArtifact(
            path=path.name,
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
            kind=_infer_kind(path),
        ))

    created = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    unsigned = ReleaseBundle(
        bundle_version=RELEASE_BUNDLE_VERSION,
        project=project,
        version=version,
        created_iso=created,
        artifacts=tuple(sorted(artifacts, key=lambda x: x.path)),
        signatures=(),
    )

    if not signers:
        return unsigned

    payload = unsigned.canonical_sign_bytes()
    sigs: list[TufSignature] = []
    for signer in signers:
        if not cryptography_available():
            raise ReleaseBundleError(
                "signers supplied but cryptography package is not installed"
            )
        pk = signer.public_key()
        keyid = hashlib.sha256(pk).hexdigest()[:16]
        sigs.append(TufSignature(keyid=keyid, sig=signer.sign(payload)))

    return dc.replace(unsigned, signatures=tuple(sigs))


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class ReleaseVerifyReport:
    ok: bool
    signatures_verified: int
    artifacts_hashes_checked: int
    artifacts_missing: tuple[str, ...]
    artifacts_mismatched: tuple[str, ...]
    failed_signatures: tuple[str, ...]
    reasons: tuple[str, ...]


def verify_release_bundle(
    bundle: ReleaseBundle,
    *,
    keys: dict[str, TufKey],
    artifact_root: Path | None = None,
    min_signatures: int = 1,
) -> ReleaseVerifyReport:
    """Verify bundle signatures + (optional) artifact hashes.

    If `artifact_root` is a directory, every artifact.path is re-hashed
    from disk and compared to bundle.sha256. Missing files and hash
    mismatches are reported. Unknown artifact kinds are still hash-checked.

    `keys` maps keyid -> TufKey. Signatures with an unknown keyid are
    ignored; signatures with known keys that fail verification go into
    failed_signatures.

    `min_signatures` must be satisfied by VALID signatures for ok=True.
    """
    if not cryptography_available():
        return ReleaseVerifyReport(
            ok=False,
            signatures_verified=0, artifacts_hashes_checked=0,
            artifacts_missing=(), artifacts_mismatched=(),
            failed_signatures=(),
            reasons=("cryptography package not installed",),
        )

    payload = bundle.canonical_sign_bytes()
    verified: set[str] = set()
    failed: list[str] = []

    for sig in bundle.signatures:
        key = keys.get(sig.keyid)
        if key is None:
            continue  # unknown key — ignore, not an error
        verifier = Ed25519Verifier(key.public_key)
        try:
            verifier.verify(payload, sig.sig)
        except SignatureVerificationError:
            failed.append(sig.keyid)
            continue
        verified.add(sig.keyid)

    missing: list[str] = []
    mismatched: list[str] = []
    checked = 0
    if artifact_root is not None:
        for a in bundle.artifacts:
            file_path = artifact_root / a.path
            if not file_path.is_file():
                missing.append(a.path)
                continue
            raw = file_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != a.sha256 or len(raw) != a.size:
                mismatched.append(a.path)
            checked += 1

    reasons: list[str] = []
    if len(verified) < min_signatures:
        reasons.append(
            f"{len(verified)} valid signature(s), need >= {min_signatures}"
        )
    if failed:
        reasons.append(f"signature verification failed for keyids: {failed}")
    if missing:
        reasons.append(f"artifacts missing on disk: {missing}")
    if mismatched:
        reasons.append(f"artifacts hash-mismatched: {mismatched}")

    ok = not reasons
    return ReleaseVerifyReport(
        ok=ok,
        signatures_verified=len(verified),
        artifacts_hashes_checked=checked,
        artifacts_missing=tuple(missing),
        artifacts_mismatched=tuple(mismatched),
        failed_signatures=tuple(failed),
        reasons=tuple(reasons),
    )
