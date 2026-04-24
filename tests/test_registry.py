"""Tests for the gate predicate registry (Verification Spec §1)."""
from __future__ import annotations

import pytest

from aios.verification.conservation_scan import (
    ContextLoad, EventLogRange, Decision, GenerationSlice, Invariant,
    RunState, VerificationSlice, _chain_hash,
)
from aios.verification.registry import (
    NotImplementedPredicateError,
    PredicateRecord,
    Registry,
    UnknownPredicateError,
    default_registry,
)


CORE_IDS = {
    "P_Q1_invariant_integrity",
    "P_Q2_state_traceability",
    "P_Q3_decision_reversibility",
    "P_M4_independence",
    "P_O5_context_sufficiency_hard",
    "P_schema_valid",
    "P_PI_sentinel",
    "P_acceptance_tests",
}


def _sample_run() -> RunState:
    inv = Invariant(id="INV-001", source="principle", statement="X")
    events = ({"kind": "e1"},)
    return RunState(
        run_id="t",
        invariants_before=frozenset({inv}),
        invariants_after=frozenset({inv}),
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"a"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"b"})),),
        context_load=ContextLoad(100, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact="subsystem",
    )


def test_default_registry_contains_core_predicates():
    assert set(default_registry.list_ids()) >= CORE_IDS


def test_registry_get_returns_record():
    rec = default_registry.get("P_Q1_invariant_integrity")
    assert rec.id == "P_Q1_invariant_integrity"
    assert rec.gate_type == "T1"
    assert rec.determinism == "deterministic"
    assert rec.failure_level == "catastrophic"
    assert rec.soundness_class == "Q1"


def test_registry_unknown_predicate_raises():
    with pytest.raises(UnknownPredicateError):
        default_registry.get("P_DOES_NOT_EXIST")


def test_require_registered_refuses_unknown():
    with pytest.raises(UnknownPredicateError):
        default_registry.require_registered([
            "P_Q1_invariant_integrity",
            "P_unregistered_thing",
        ])


def test_require_registered_accepts_all_core():
    default_registry.require_registered(sorted(CORE_IDS))


def test_evaluate_q1_via_registry():
    result = default_registry.evaluate("P_Q1_invariant_integrity", _sample_run())
    assert result["status"] == "preserved"


def test_evaluate_q2_via_registry():
    result = default_registry.evaluate("P_Q2_state_traceability", _sample_run())
    assert result["status"] == "preserved"


def test_evaluate_q3_via_registry():
    result = default_registry.evaluate("P_Q3_decision_reversibility", _sample_run())
    assert result["status"] == "preserved"


def test_evaluate_m4_via_registry():
    result = default_registry.evaluate("P_M4_independence", _sample_run())
    assert result["status"] == "preserved"


def test_evaluate_o5_via_registry():
    result = default_registry.evaluate("P_O5_context_sufficiency_hard", _sample_run())
    assert result["status"] == "preserved"


def test_evaluate_stub_predicate_raises_not_implemented():
    # As of v0.4.0 all §1.2 core predicates are real. Register a
    # throwaway stub on an isolated Registry so the "no silent pass"
    # property stays covered without touching the default registry.
    reg = Registry()
    from aios.verification.registry import PredicateRecord
    stub = PredicateRecord(
        id="P_test_stub", version="0.0.0", owner_authority="A4",
        gate_type="T1", determinism="deterministic", side_effects="read_only",
        input_schema="x", output_schema="y", reference_vectors="z",
        failure_level="minor", soundness_class="other",
        implementation=None,
    )
    reg.register(stub)
    with pytest.raises(NotImplementedPredicateError):
        reg.evaluate("P_test_stub", _sample_run())


def test_evaluate_schema_valid_no_args_returns_preserved_with_note():
    # Sprint 25 promoted P_schema_valid from stub to real jsonschema-backed
    # predicate. With no artifact/schema kwargs, it returns preserved +
    # a note. With invalid content it would return breached.
    result = default_registry.evaluate("P_schema_valid", _sample_run())
    assert result["status"] == "preserved"
    assert "note" in result


def test_registry_double_register_raises():
    reg = Registry()
    rec = default_registry.get("P_Q1_invariant_integrity")
    with pytest.raises(ValueError):
        reg.register(rec)  # P_Q1 is already in the core set


def test_registry_can_register_custom_predicate():
    reg = Registry()
    custom = PredicateRecord(
        id="P_custom_demo",
        version="0.1.0",
        owner_authority="A4",
        gate_type="T3",
        determinism="deterministic",
        side_effects="read_only",
        input_schema="schemas/custom.json",
        output_schema="schemas/custom_out.json",
        reference_vectors="rv/custom.json",
        failure_level="minor",
        soundness_class="other",
        implementation=lambda run: {"status": "preserved"},
    )
    reg.register(custom)
    assert reg.has("P_custom_demo")
    assert reg.evaluate("P_custom_demo", _sample_run())["status"] == "preserved"
