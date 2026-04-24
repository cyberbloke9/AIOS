"""Tests for P_schema_valid (sprint 25)."""
from __future__ import annotations

from aios.verification.conservation_scan import (
    ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
)
from aios.verification.registry import default_registry
from aios.verification.schema_check import p_schema_valid


def _empty_run() -> RunState:
    inv = Invariant(id="INV-001", source="principle", statement="x")
    events = ({"kind": "e"},)
    return RunState(
        run_id="t",
        invariants_before=frozenset({inv}),
        invariants_after=frozenset({inv}),
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"a"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"b"})),),
        context_load=ContextLoad(0, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact="local",
    )


# Direct-call tests -------------------------------------------------------


def test_valid_artifact_passes():
    schema = {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]}
    result = p_schema_valid(_empty_run(), artifact={"x": 42}, schema=schema)
    assert result["status"] == "preserved"


def test_invalid_artifact_breached():
    schema = {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]}
    result = p_schema_valid(_empty_run(), artifact={"x": "not an int"}, schema=schema)
    assert result["status"] == "breached"
    assert "path" in result


def test_missing_required_property_reports_path():
    schema = {"type": "object", "required": ["foo"]}
    result = p_schema_valid(_empty_run(), artifact={"bar": 1}, schema=schema)
    assert result["status"] == "breached"
    assert "foo" in result["error"]


def test_multiple_errors_reported():
    schema = {
        "type": "object",
        "properties": {
            "x": {"type": "integer"},
            "y": {"type": "string"},
        },
        "required": ["x", "y"],
    }
    artifact = {"x": "bad", "y": 123}
    result = p_schema_valid(_empty_run(), artifact=artifact, schema=schema)
    assert result["status"] == "breached"
    assert result["error_count"] >= 2
    assert len(result["all_errors"]) == result["error_count"]


def test_nothing_supplied_returns_preserved_with_note():
    """Default-call shape (no kwargs): workflows that include the gate
    but don't pass an artifact get a pass-with-note, not a false breach."""
    result = p_schema_valid(_empty_run())
    assert result["status"] == "preserved"
    assert "note" in result


def test_artifact_without_schema_rejected():
    result = p_schema_valid(_empty_run(), artifact={"x": 1})
    assert result["status"] == "breached"
    assert "schema" in result["error"].lower()


def test_schema_without_artifact_rejected():
    result = p_schema_valid(_empty_run(), schema={"type": "object"})
    assert result["status"] == "breached"
    assert "artifact" in result["error"].lower()


def test_malformed_schema_reports_as_invalid_schema():
    """A buggy schema should not masquerade as an artifact failure."""
    bogus_schema = {"type": "not-a-real-type"}
    result = p_schema_valid(_empty_run(), artifact={}, schema=bogus_schema)
    assert result["status"] == "breached"
    assert "invalid JSON Schema" in result["error"]


def test_nested_path_reported():
    schema = {
        "type": "object",
        "properties": {
            "a": {
                "type": "object",
                "properties": {"b": {"type": "integer"}},
                "required": ["b"],
            },
        },
        "required": ["a"],
    }
    artifact = {"a": {"b": "not an int"}}
    result = p_schema_valid(_empty_run(), artifact=artifact, schema=schema)
    assert result["status"] == "breached"
    assert result["path"] == ["a", "b"]


# Registry integration ----------------------------------------------------


def test_registry_evaluates_p_schema_valid():
    """The registry's evaluate() forwards kwargs to the implementation."""
    schema = {"type": "integer"}
    result = default_registry.evaluate(
        "P_schema_valid", _empty_run(),
        artifact=42, schema=schema,
    )
    assert result["status"] == "preserved"


def test_registry_p_schema_valid_no_longer_a_stub():
    """Sprint-4 stubbed this as NotImplementedPredicateError. It's now real."""
    result = default_registry.evaluate("P_schema_valid", _empty_run())
    # No longer raises — returns a dict.
    assert isinstance(result, dict)
    assert result["status"] == "preserved"


def test_p_schema_valid_record_has_implementation():
    rec = default_registry.get("P_schema_valid")
    assert rec.implementation is not None
    assert rec.gate_type == "T3"
    assert rec.failure_level == "major"
