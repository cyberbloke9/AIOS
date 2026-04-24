"""Distribution subsystem — SBOM, signed releases, TUF bootstrap, install.

See docs/spec/AIOS_Distribution_Spec.md.
"""
from __future__ import annotations

from aios.distribution.integrity import (
    FileEntry,
    IntegrityManifest,
    IntegrityReport,
    build_integrity_manifest,
    verify_install,
)
from aios.distribution.tuf import (
    RootContent,
    SignedMetadata,
    TargetEntry,
    TargetHash,
    TargetsContent,
    TufKey,
    TufMetadataError,
    TufRoleSpec,
    TufSignature,
    TufVerificationError,
    root_metadata_fingerprint,
    verify_signed_metadata,
)
from aios.distribution.sbom_cyclonedx import (
    CycloneDXDocument,
    generate_cyclonedx,
)
from aios.distribution.sbom_spdx import (
    SPDXDocument,
    SPDXPackage,
    generate_spdx,
)

__all__ = [
    "CycloneDXDocument",
    "FileEntry",
    "IntegrityManifest",
    "IntegrityReport",
    "SPDXDocument",
    "SPDXPackage",
    "build_integrity_manifest",
    "generate_cyclonedx",
    "generate_spdx",
    "verify_install",
]
