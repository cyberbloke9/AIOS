"""Distribution subsystem — SBOM, signed releases, TUF bootstrap, install.

See docs/spec/AIOS_Distribution_Spec.md.
"""
from __future__ import annotations

from aios.distribution.bootstrap import (
    BootstrapAnchorError,
    BootstrapVerifyReport,
    Channel,
    load_root_metadata,
    verify_bootstrap_anchor,
)
from aios.distribution.install import (
    InstallError,
    InstallResult,
    current_version,
    install_package,
    list_installed_versions,
)
from aios.distribution.rollback import (
    RollbackError,
    RollbackResult,
    UninstallError,
    UninstallResult,
    rollback_to,
    uninstall,
)
from aios.distribution.upgrade import (
    UpgradeError,
    UpgradeResult,
    upgrade_package,
)
from aios.distribution.integrity import (
    FileEntry,
    IntegrityManifest,
    IntegrityReport,
    build_integrity_manifest,
    verify_install,
)
from aios.distribution.release import (
    ReleaseArtifact,
    ReleaseBundle,
    ReleaseBundleError,
    ReleaseVerifyReport,
    build_release_bundle,
    verify_release_bundle,
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
from aios.distribution.tuf_chain import (
    TufChainError,
    TufChainReport,
    verify_tuf_chain,
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
