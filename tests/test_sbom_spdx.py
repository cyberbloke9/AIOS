"""Tests for SPDX 2.3 SBOM generator (sprint 50)."""
from __future__ import annotations

import email.message
import json

import pytest

from aios.distribution.sbom_spdx import (
    SPDX_VERSION,
    SPDXDocument,
    SPDXPackage,
    _extract_license,
    _extract_homepage,
    _extract_requires,
    _spdx_id,
    generate_spdx,
)


# ---------------------------------------------------------------------------
# Metadata extraction helpers
# ---------------------------------------------------------------------------


def _fake_meta(fields: dict[str, list[str] | str]) -> email.message.Message:
    """Build an email.message.Message that mimics PackageMetadata."""
    m = email.message.Message()
    for k, v in fields.items():
        if isinstance(v, list):
            for item in v:
                m[k] = item
        else:
            m[k] = v
    return m


def test_license_field_wins():
    meta = _fake_meta({"License": "MIT"})
    assert _extract_license(meta) == "MIT"


def test_license_falls_back_to_osi_classifier():
    meta = _fake_meta({"Classifier": "License :: OSI Approved :: Apache Software License"})
    assert _extract_license(meta) == "Apache Software License"


def test_license_falls_back_to_generic_classifier():
    meta = _fake_meta({"Classifier": "License :: Public Domain"})
    assert _extract_license(meta) == "Public Domain"


def test_license_noassertion_when_absent():
    meta = _fake_meta({})
    assert _extract_license(meta) == "NOASSERTION"


def test_homepage_from_home_page():
    meta = _fake_meta({"Home-page": "https://example.com"})
    assert _extract_homepage(meta) == "https://example.com"


def test_homepage_from_project_url():
    meta = _fake_meta({"Project-URL": "Homepage, https://example.org"})
    assert _extract_homepage(meta) == "https://example.org"


def test_homepage_noassertion_when_unknown():
    meta = _fake_meta({"Home-page": "UNKNOWN"})
    assert _extract_homepage(meta) == "NOASSERTION"


def test_requires_strips_version_specifiers_and_env_markers():
    meta = _fake_meta({"Requires-Dist": [
        "numpy>=1.20",
        "pytest",
        'cryptography>=42.0; python_version>="3.11"',
        "black (==23.3.0)",
        "extras-pkg[toml]",
    ]})
    assert _extract_requires(meta) == (
        "numpy", "pytest", "cryptography", "black", "extras-pkg",
    )


# ---------------------------------------------------------------------------
# SPDX ID normalization
# ---------------------------------------------------------------------------


def test_spdx_id_preserves_allowed_chars():
    assert _spdx_id("aios") == "SPDXRef-Package-aios"
    assert _spdx_id("my-package.v2+") == "SPDXRef-Package-my-package.v2+"


def test_spdx_id_replaces_disallowed_chars():
    assert _spdx_id("my_package") == "SPDXRef-Package-my-package"


# ---------------------------------------------------------------------------
# Document generation
# ---------------------------------------------------------------------------


def test_generate_spdx_returns_valid_shape_for_installed_env():
    doc = generate_spdx(root_name="aios", root_version="0.5.0")
    assert isinstance(doc, SPDXDocument)
    assert doc.document_name == "aios-0.5.0"
    assert len(doc.packages) >= 1
    as_json = doc.to_json()
    assert as_json["spdxVersion"] == SPDX_VERSION
    assert as_json["dataLicense"] == "CC0-1.0"
    assert as_json["SPDXID"] == "SPDXRef-DOCUMENT"
    assert isinstance(as_json["packages"], list)
    # DESCRIBES relationship always present
    describes = [r for r in as_json["relationships"]
                 if r["relationshipType"] == "DESCRIBES"]
    assert len(describes) == 1


def test_generate_spdx_with_root_installed_uses_real_id():
    """aios is installed in this test env; root_id should point at it."""
    doc = generate_spdx(root_name="aios")
    assert doc.root_spdx_id == "SPDXRef-Package-aios"


def test_generate_spdx_with_root_not_installed_emits_placeholder():
    doc = generate_spdx(root_name="definitely-not-installed-pkg",
                        root_version="9.9.9")
    # Root is a placeholder — not in the real distributions list
    assert doc.root_spdx_id.endswith("-definitely-not-installed-pkg")
    assert doc.packages[0].name == "definitely-not-installed-pkg"
    assert doc.packages[0].version == "9.9.9"


def test_document_namespace_defaults_include_version():
    doc = generate_spdx(root_name="aios", root_version="0.5.0")
    assert "aios-0.5.0" in doc.document_namespace


def test_custom_namespace_and_creators():
    doc = generate_spdx(
        root_name="aios", root_version="0.5.0",
        document_namespace="https://internal.example/sbom/aios-0.5.0",
        creators=("Tool: aios-sbom", "Person: ci"),
    )
    j = doc.to_json()
    assert j["documentNamespace"] == "https://internal.example/sbom/aios-0.5.0"
    assert j["creationInfo"]["creators"] == ["Tool: aios-sbom", "Person: ci"]


def test_to_json_is_stable_json_serializable():
    doc = generate_spdx(root_name="aios", root_version="0.5.0")
    text = json.dumps(doc.to_json(), sort_keys=True)
    decoded = json.loads(text)
    assert decoded["spdxVersion"] == SPDX_VERSION


def test_depends_on_relationships_link_to_listed_packages():
    """If pkg A requires pkg B and both are in the doc, there is a
    DEPENDS_ON relationship A -> B."""
    doc = generate_spdx(root_name="aios")
    name_to_id = {p.name.lower(): p.spdx_id for p in doc.packages}
    relationships = doc.to_json()["relationships"]
    for rel in relationships:
        if rel["relationshipType"] != "DEPENDS_ON":
            continue
        # The related element must reference a package actually in the document
        assert rel["relatedSpdxElement"] in name_to_id.values()


def test_checksums_are_sha256():
    doc = generate_spdx(root_name="aios")
    for p in doc.to_json()["packages"]:
        assert p["checksums"][0]["algorithm"] == "SHA256"
        # SHA-256 hex is 64 chars
        assert len(p["checksums"][0]["checksumValue"]) == 64


def test_files_analyzed_false_on_every_package():
    """v0.5 does not unpack wheels; filesAnalyzed is always False."""
    doc = generate_spdx(root_name="aios")
    for p in doc.to_json()["packages"]:
        assert p["filesAnalyzed"] is False
