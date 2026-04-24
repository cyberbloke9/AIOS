"""
Failure-case tests for SK-CONSERVATION-SCAN.

Every conservation law should produce a 'breached' status on a constructed
counterexample. If any of these tests pass where they should fail, the scan
is not actually enforcing anything.
"""

from __future__ import annotations

from conservation_scan import (
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
    # Remove an invariant without any ADR authorization
    inv_a = Invariant(id="INV-001", source="principle", statement="X")
    inv_b = Invariant(id="INV-002", source="security", statement="Y")
    run = make_base_run()
    run.invariants_before = frozenset({inv_a, inv_b})
    run.invariants_after = frozenset({inv_a})  # INV-002 silently gone
    # no adr_events removing INV-002
    ledger = conservation_scan(run)
    assert ledger["Q1_invariant_integrity"]["status"] == "breached"
    assert "INV-002" in ledger["Q1_invariant_integrity"]["illegitimate_removals"]


def test_q2_breaches_on_hash_mismatch():
    run = make_base_run()
    run.event_log_range = EventLogRange(
        events=run.event_log_range.events,
        stored_projection_hash="0" * 64,  # deliberately wrong
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


def test_q4_breaches_on_high_overlap():
    run = make_base_run()
    # Generator and verifier see nearly identical inputs => high overlap
    run.generator_slices = (
        GenerationSlice(actor="A3",
                        inputs_seen=frozenset({"diff", "spec", "pr_description"})),
    )
    run.verifier_slices = (
        VerificationSlice(actor="A4",
                          inputs_seen=frozenset({"diff", "spec", "pr_description"})),
    )
    ledger = conservation_scan(run, v_min=0.5)
    assert ledger["Q4_verification_independence"]["status"] == "breached"
    assert ledger["Q4_verification_independence"]["V"] < 0.5


def test_q4_does_not_apply_to_local_impact():
    run = make_base_run()
    run.impact = "local"
    run.generator_slices = (
        GenerationSlice(actor="A3", inputs_seen=frozenset({"diff"})),
    )
    run.verifier_slices = (
        VerificationSlice(actor="A4", inputs_seen=frozenset({"diff"})),
    )
    ledger = conservation_scan(run)
    assert ledger["Q4_verification_independence"]["status"] == "preserved"
    assert ledger["Q4_verification_independence"]["V"] is None


def test_q5_breaches_on_missing_invariant():
    run = make_base_run()
    run.context_load = ContextLoad(
        tokens_loaded=1_000, budget=32_000,
        invariants_loaded=frozenset(),  # nothing loaded
        invariants_required=frozenset({"INV-001"}),
    )
    ledger = conservation_scan(run)
    assert ledger["Q5_context_sufficiency"]["status"] == "breached"
    assert "INV-001" in ledger["Q5_context_sufficiency"]["missing_invariants"]


def test_q5_breaches_on_over_budget():
    run = make_base_run()
    run.context_load = ContextLoad(
        tokens_loaded=50_000, budget=32_000,
        invariants_loaded=frozenset({"INV-001"}),
        invariants_required=frozenset({"INV-001"}),
    )
    ledger = conservation_scan(run)
    assert ledger["Q5_context_sufficiency"]["status"] == "breached"
    assert ledger["Q5_context_sufficiency"]["over_budget"] is True


TESTS = [
    test_q1_breaches_on_silent_invariant_removal,
    test_q2_breaches_on_hash_mismatch,
    test_q3_breaches_on_accidental_irreversible,
    test_q3_preserved_when_irreversibility_is_explicit,
    test_q4_breaches_on_high_overlap,
    test_q4_does_not_apply_to_local_impact,
    test_q5_breaches_on_missing_invariant,
    test_q5_breaches_on_over_budget,
]


if __name__ == "__main__":
    for t in TESTS:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            raise
    print(f"\n{len(TESTS)}/{len(TESTS)} conservation-breach tests passed.")
