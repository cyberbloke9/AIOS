"""Distribution subsystem — SBOM, signed releases, TUF bootstrap, install.

See docs/spec/AIOS_Distribution_Spec.md.
"""
from __future__ import annotations

from aios.distribution.sbom_spdx import (
    SPDXDocument,
    SPDXPackage,
    generate_spdx,
)

__all__ = [
    "SPDXDocument",
    "SPDXPackage",
    "generate_spdx",
]
