"""Tests for CycloneDX 1.5 SBOM + aios sbom CLI (sprint 51)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from aios.cli import main
from aios.distribution.sbom_cyclonedx import (
    CYCLONEDX_SPEC_VERSION,
    CycloneDXDocument,
    generate_cyclonedx,
)


# ---------------------------------------------------------------------------
# generate_cyclonedx
# ---------------------------------------------------------------------------


def test_basic_shape():
    doc = generate_cyclonedx(root_name="aios", root_version="0.5.0")
    assert isinstance(doc, CycloneDXDocument)
    j = doc.to_json()
    assert j["bomFormat"] == "CycloneDX"
    assert j["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert j["version"] == 1
    assert j["serialNumber"].startswith("urn:uuid:")


def test_serial_number_is_valid_uuid_urn():
    doc = generate_cyclonedx(root_name="aios")
    urn_re = re.compile(
        r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    assert urn_re.match(doc.to_json()["serialNumber"])


def test_metadata_component_is_root():
    doc = generate_cyclonedx(root_name="aios", root_version="0.5.0")
    j = doc.to_json()
    comp = j["metadata"]["component"]
    assert comp["type"] == "application"
    assert comp["name"] == "aios"
    # bom-ref is <name>@<version>
    assert "@" in comp["bom-ref"]


def test_components_list_excludes_root():
    """Root package lives in metadata.component; it should not also
    appear in components[] (CycloneDX convention)."""
    doc = generate_cyclonedx(root_name="aios")
    j = doc.to_json()
    names = {c["name"] for c in j["components"]}
    assert "aios" not in names


def test_every_component_has_purl():
    doc = generate_cyclonedx(root_name="aios")
    for c in doc.to_json()["components"]:
        assert c["purl"].startswith("pkg:pypi/")
        assert "@" in c["purl"]


def test_every_component_has_sha256_hash():
    doc = generate_cyclonedx(root_name="aios")
    for c in doc.to_json()["components"]:
        assert c["hashes"][0]["alg"] == "SHA-256"
        assert len(c["hashes"][0]["content"]) == 64


def test_dependency_graph_refs_valid_components():
    """Every `ref` in dependencies must match either the root ref or
    a components[].bom-ref."""
    doc = generate_cyclonedx(root_name="aios")
    j = doc.to_json()
    valid_refs = {j["metadata"]["component"]["bom-ref"]}
    valid_refs.update(c["bom-ref"] for c in j["components"])
    for entry in j["dependencies"]:
        # ref may be any pkg we scanned (including root). dependsOn
        # must point at scanned packages.
        for edge in entry["dependsOn"]:
            assert edge in valid_refs


def test_license_surfaces_when_present():
    doc = generate_cyclonedx(root_name="aios")
    for c in doc.to_json()["components"]:
        if "licenses" in c:
            assert isinstance(c["licenses"], list)
            assert "license" in c["licenses"][0]


def test_custom_serial_number_respected():
    custom = "urn:uuid:12345678-1234-1234-1234-123456789abc"
    doc = generate_cyclonedx(root_name="aios", serial_number=custom)
    assert doc.to_json()["serialNumber"] == custom


def test_tool_name_and_version_in_metadata():
    doc = generate_cyclonedx(root_name="aios",
                              tool_name="my-tool", tool_version="9.9")
    tools = doc.to_json()["metadata"]["tools"]["components"]
    assert tools[0]["name"] == "my-tool"
    assert tools[0]["version"] == "9.9"


def test_json_stable_and_parseable():
    doc = generate_cyclonedx(root_name="aios", root_version="0.5.0")
    text = json.dumps(doc.to_json(), sort_keys=True)
    assert json.loads(text)["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# CLI — aios sbom
# ---------------------------------------------------------------------------


def test_cli_sbom_spdx_to_stdout(capsys):
    rc = main(["sbom", "--format", "spdx", "--root", "aios",
               "--root-version", "0.5.0"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["spdxVersion"].startswith("SPDX-")
    assert data["name"] == "aios-0.5.0"


def test_cli_sbom_cyclonedx_to_stdout(capsys):
    rc = main(["sbom", "--format", "cyclonedx", "--root", "aios"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == CYCLONEDX_SPEC_VERSION


def test_cli_sbom_writes_to_file(tmp_path: Path, capsys):
    target = tmp_path / "aios.spdx.json"
    rc = main(["sbom", "--format", "spdx", "--output", str(target)])
    assert rc == 0
    out = capsys.readouterr().out
    assert str(target) in out
    assert target.exists()
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["spdxVersion"].startswith("SPDX-")


def test_cli_sbom_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "sbom" in out
