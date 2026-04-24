"""Conservation-scan breach tests — package version.

Mirrors examples/reference/test_conservation_scan.py (v5 reference, 8 tests),
plus two extra tests verifying:
  - M4/Q4 ledger keys both present and identical
  - O5/Q5 ledger keys both present and identical
"""
from __future__ import annotations

from aios.verification.conservation_scan import (
    ADREvent, ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, conservation_scan, _chain_hash,
)


def make_base_run() -> RunState:
    inv_a = Invariant(id="INV-001", source="principle", statement="X")
    events = ({"kind": "e1"}, {"kind": "e2"})
    return RunState(
        run_id="test",
        invariants_before=frozenset({inv_a}),
        invariants_after=frozenset({inv_a}),
        adr_events=(),
        decisions=(Decision(decision_id="D1", rollback_cost="low",
                            irreversibility_adr_id=None),),
        generator_slices=(
            GenerationSlice(actor="A3", inputs_seen=frozenset({"diff", "spec"})),
        ),
        verifier_slices=(
            VerificationSlice(actor="A4", inputs_seen=frozenset({"diff", "adrs"})),
        ),
        context_load=ContextLoad(
            tokens_loaded=1_000, budget=32_000,
            invariants_loaded=frozenset({"INV-001"}),
            invariants_required=frozenset({"INV-001"}),
        ),
        event_log_range=EventLogRange(
            events=events, stored_projection_hash=_chain_hash(events),
        ),
        impact="subsystem",
    )


def test_q1_breaches_on_silent_invariant_removal():
    inv_a = Invariant(id="INV-001", source="principle", statement="X")
    inv_b = Invariant(id="INV-002", source="security", statement="Y")
    run = make_base_run()
    run.invariants_before = frozenset({inv_a, inv_b})
    run.invariants_after = frozenset({inv_a})
    ledger = conservation_scan(run)
    assert ledger["Q1_invariant_integrity"]["status"] == "breached"
    assert "INV-002" in ledger["Q1_invariant_integrity"]["illegitimate_removals"]


def test_q2_breaches_on_hash_mismatch():
    run = make_base_run()
    run.event_log_range = EventLogRange(
        events=run.event_log_range.events,
        stored_projection_hash="0" * 64,
    )
    ledger = conservation_scan(run)
    assert ledger["Q2_state_traceability"]["status"] == "breached"


def test_q3_breaches_on_accidental_irreversible():
    run = make_base_run()
    run.decisions = (
        Decision(decision_id="D1", rollback_cost="low", irreversibility_adr_id=None),
        Decision(decision_id="D2", rollback_cost="irreversible", irreversibility_adr_id=None),
    )
    ledger = conservation_scan(run)
    assert ledger["Q3_decision_reversibility"]["status"] == "breached"
    assert "D2" in ledger["Q3_decision_reversibility"]["accidental_irreversibles"]


def test_q3_preserved_when_irreversibility_is_explicit():
    run = make_base_run()
    run.decisions = (
        Decision(decision_id="D1", rollback_cost="irreversible",
                 irreversibility_adr_id="ADR-0099"),
    )
    ledger = conservation_scan(run)
    assert ledger["Q3_decision_reversibility"]["status"] == "preserved"


def test_m4_breaches_on_high_overlap():
    run = make_base_run()
    run.generator_slices = (
        GenerationSlice(actor="A3",
                        inputs_seen=frozenset({"diff", "spec", "pr_description"})),
    )
    run.verifier_slices = (
        VerificationSlice(actor="A4",
                          inputs_seen=frozenset({"diff", "spec", "pr_description"})),
    )
    ledger = conservation_scan(run, v_min=0.5)
    assert ledger["M4_independence"]["status"] == "breached"
    assert ledger["M4_independence"]["V"] < 0.5


def test_m4_does_not_apply_to_local_impact():
    run = make_base_run()
    run.impact = "local"
    run.generator_slices = (
        GenerationSlice(actor="A3", inputs_seen=frozenset({"diff"})),
    )
    run.verifier_slices = (
        VerificationSlice(actor="A4", inputs_seen=frozenset({"diff"})),
    )
    ledger = conservation_scan(run)
    assert ledger["M4_independence"]["status"] == "preserved"
    assert ledger["M4_independence"]["V"] is None


def test_o5_breaches_on_missing_invariant():
    run = make_base_run()
    run.context_load = ContextLoad(
        tokens_loaded=1_000, budget=32_000,
        invariants_loaded=frozenset(),
        invariants_required=frozenset({"INV-001"}),
    )
    ledger = conservation_scan(run)
    assert ledger["O5_context_sufficiency"]["status"] == "breached"
    assert "INV-001" in ledger["O5_context_sufficiency"]["missing_invariants"]


def test_o5_breaches_on_over_budget():
    run = make_base_run()
    run.context_load = ContextLoad(
        tokens_loaded=50_000, budget=32_000,
        invariants_loaded=frozenset({"INV-001"}),
        invariants_required=frozenset({"INV-001"}),
    )
    ledger = conservation_scan(run)
    assert ledger["O5_context_sufficiency"]["status"] == "breached"
    assert ledger["O5_context_sufficiency"]["over_budget"] is True


# Back-compat: v5 Q4/Q5 keys identical to v7 M4/O5 keys ---------------------


def test_m4_and_q4_ledger_keys_are_identical():
    run = make_base_run()
    ledger = conservation_scan(run)
    assert ledger["M4_independence"] == ledger["Q4_verification_independence"]


def test_o5_and_q5_ledger_keys_are_identical():
    run = make_base_run()
    ledger = conservation_scan(run)
    assert ledger["O5_context_sufficiency"] == ledger["Q5_context_sufficiency"]
