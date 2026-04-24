"""CycloneDX 1.5 SBOM generator (sprint 51).

Distribution §5.3 calls for SPDX 2.3 primary + CycloneDX 1.5 secondary.
This module reuses the sbom_spdx scan + emits the CycloneDX 1.5 JSON
shape. Same content, different format — the two are consumer-format
differences, not ground-truth differences.

Emits:
  bomFormat + specVersion + serialNumber + version
  metadata: {timestamp, tools, component} — component = root package
  components[]: libraries with purl (pkg:pypi/<name>@<version>)
  dependencies[]: {ref, dependsOn} graph derived from Requires-Dist
"""
from __future__ import annotations

import dataclasses as dc
import datetime as _dt
import uuid
from typing import Iterable

from aios.distribution.sbom_spdx import SPDXPackage, generate_spdx

CYCLONEDX_SPEC_VERSION = "1.5"
CYCLONEDX_SERIAL_PREFIX = "urn:uuid:"


@dc.dataclass(frozen=True)
class CycloneDXDocument:
    serial_number: str
    timestamp_iso: str
    tool_name: str
    tool_version: str
    root_name: str
    root_version: str
    packages: tuple[SPDXPackage, ...]

    def to_json(self) -> dict:
        # bom-ref scheme: "<name>@<version>" — stable across runs
        def ref(p: SPDXPackage) -> str:
            return f"{p.name}@{p.version}"

        components: list[dict] = []
        dependency_graph: list[dict] = []

        # Root goes in metadata.component; dependencies ref it.
        root_pkg = next(
            (p for p in self.packages
             if p.name.lower() == self.root_name.lower()),
            None,
        )
        root_ref = f"{self.root_name}@{self.root_version}"

        name_to_ref = {p.name.lower(): ref(p) for p in self.packages}

        for p in self.packages:
            if p.name.lower() == self.root_name.lower():
                # Skip root from components; it lives in metadata.component
                continue
            components.append(_package_to_component(p, ref(p)))

        # Dependency graph — one entry per package with outgoing edges
        for p in self.packages:
            outgoing = []
            for dep in p.requires:
                edge = name_to_ref.get(dep.lower())
                if edge is None:
                    continue
                outgoing.append(edge)
            dependency_graph.append({
                "ref": ref(p),
                "dependsOn": outgoing,
            })

        metadata_component: dict = {
            "type": "application",
            "bom-ref": root_ref,
            "name": self.root_name,
            "version": self.root_version,
        }
        if root_pkg:
            if root_pkg.license_declared != "NOASSERTION":
                metadata_component["licenses"] = [{
                    "license": {"name": root_pkg.license_declared}
                }]

        return {
            "bomFormat": "CycloneDX",
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "serialNumber": self.serial_number,
            "version": 1,
            "metadata": {
                "timestamp": self.timestamp_iso,
                "tools": {
                    "components": [{
                        "type": "application",
                        "name": self.tool_name,
                        "version": self.tool_version,
                    }],
                },
                "component": metadata_component,
            },
            "components": components,
            "dependencies": dependency_graph,
        }


def _package_to_component(p: SPDXPackage, bom_ref: str) -> dict:
    component: dict = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": p.name,
        "version": p.version,
        "purl": f"pkg:pypi/{p.name.lower()}@{p.version}",
        "hashes": [{
            "alg": "SHA-256",
            "content": p.checksum_sha256,
        }],
    }
    if p.license_declared and p.license_declared != "NOASSERTION":
        # CycloneDX license object: prefer `id` if the license value
        # looks like an SPDX expression, else `name`. Keep it simple.
        lic = p.license_declared
        component["licenses"] = [{"license": {"name": lic}}]
    if p.homepage and p.homepage != "NOASSERTION":
        component["externalReferences"] = [{
            "type": "website",
            "url": p.homepage,
        }]
    return component


def generate_cyclonedx(
    *,
    root_name: str = "aios",
    root_version: str | None = None,
    tool_name: str = "aios-sbom",
    tool_version: str | None = None,
    serial_number: str | None = None,
    distributions=None,
) -> CycloneDXDocument:
    """Scan the environment + emit a CycloneDX 1.5 document.

    Reuses generate_spdx's package collection so the two formats
    describe identical content.
    """
    # Reuse the SPDX scanner for the package list
    spdx = generate_spdx(
        root_name=root_name,
        root_version=root_version,
        distributions=distributions,
    )
    # The `root_version` we report in CycloneDX matches what SPDX used.
    root_pkg = next(
        (p for p in spdx.packages if p.name.lower() == root_name.lower()),
        None,
    )
    effective_root_version = (
        root_pkg.version if root_pkg else (root_version or "UNKNOWN")
    )

    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = serial_number or f"{CYCLONEDX_SERIAL_PREFIX}{uuid.uuid4()}"

    from aios import __version__ as AIOS_VERSION
    return CycloneDXDocument(
        serial_number=serial,
        timestamp_iso=ts,
        tool_name=tool_name,
        tool_version=tool_version or AIOS_VERSION,
        root_name=root_name,
        root_version=effective_root_version,
        packages=spdx.packages,
    )
