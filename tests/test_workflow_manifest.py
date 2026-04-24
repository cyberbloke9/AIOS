"""Tests for workflow manifest schema + parser (sprint 18)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.workflow.manifest import (
    ImpactLevel, ManifestError, VALID_IMPACT_LEVELS,
    WorkflowManifest, default_required_gates, parse_manifest,
)


def test_default_gates_local():
    gates = default_required_gates("local")
    assert "P_Q1_invariant_integrity" in gates
    assert "P_Q2_state_traceability" in gates
    assert "P_schema_valid" in gates
    assert "P_Q3_decision_reversibility" not in gates


def test_default_gates_subsystem_extends_local():
    local = set(default_required_gates("local"))
    sub = set(default_required_gates("subsystem"))
    assert local.issubset(sub)
    assert "P_Q3_decision_reversibility" in sub
    assert "P_M4_independence" in sub


def test_default_gates_system_wide_extends_subsystem():
    sub = set(default_required_gates("subsystem"))
    sw = set(default_required_gates("system_wide"))
    assert sub.issubset(sw)


def test_default_gates_invalid_impact_raises():
    with pytest.raises(ManifestError):
        default_required_gates("bogus")  # type: ignore


def test_parse_minimal_json():
    text = json.dumps({
        "id": "test",
        "version": "1.0.0",
        "impact": "local",
    })
    m = parse_manifest(text)
    assert m.id == "test"
    assert m.impact == "local"
    assert m.required_gates == default_required_gates("local")


def test_parse_merges_manifest_gates_with_defaults():
    text = json.dumps({
        "id": "x",
        "version": "1",
        "impact": "subsystem",
        "required_gates": ["P_acceptance_tests"],  # already in subsystem defaults
    })
    m = parse_manifest(text)
    assert m.required_gates.count("P_acceptance_tests") == 1


def test_parse_extras_beyond_defaults_accepted_if_registered():
    text = json.dumps({
        "id": "x", "version": "1", "impact": "local",
        "required_gates": ["P_PI_sentinel"],
    })
    m = parse_manifest(text)
    assert "P_PI_sentinel" in m.required_gates


def test_parse_rejects_unknown_gate():
    text = json.dumps({
        "id": "x", "version": "1", "impact": "local",
        "required_gates": ["P_does_not_exist"],
    })
    with pytest.raises(ManifestError):
        parse_manifest(text)


def test_parse_rejects_invalid_impact():
    text = json.dumps({"id": "x", "version": "1", "impact": "apocalyptic"})
    with pytest.raises(ManifestError):
        parse_manifest(text)


def test_parse_rejects_missing_id():
    text = json.dumps({"version": "1", "impact": "local"})
    with pytest.raises(ManifestError):
        parse_manifest(text)


def test_parse_rejects_non_dict_root():
    text = json.dumps(["not", "a", "mapping"])
    with pytest.raises(ManifestError):
        parse_manifest(text)


def test_parse_required_invariants_forwarded():
    text = json.dumps({
        "id": "x", "version": "1", "impact": "local",
        "required_invariants": ["INV-001", "INV-002"],
    })
    m = parse_manifest(text)
    assert m.required_invariants == ("INV-001", "INV-002")


def test_parse_yaml_if_available():
    pytest.importorskip("yaml")
    text = """\
id: yaml-test
version: 1.0.0
impact: local
description: loaded from yaml
"""
    m = parse_manifest(text, format="yaml")
    assert m.id == "yaml-test"
    assert m.description == "loaded from yaml"


def test_parse_manifest_from_path(tmp_path: Path):
    p = tmp_path / "workflow.json"
    p.write_text(json.dumps({"id": "p", "version": "1", "impact": "local"}))
    m = parse_manifest(p)
    assert m.id == "p"


def test_valid_impact_levels_complete():
    assert set(VALID_IMPACT_LEVELS) == {"local", "subsystem", "system_wide"}
