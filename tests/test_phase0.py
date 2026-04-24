"""Tests for Phase 0 gate accuracy measurement (sprint 39)."""
from __future__ import annotations

import pytest

from aios.verification.conservation_scan import (
    ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
)
from aios.verification.phase0 import (
    ReferenceCase,
    ReferenceSuite,
    measure_gate_accuracy,
)


# Fixtures ---------------------------------------------------------------


def _good_run(rid: str = "good") -> RunState:
    inv = Invariant(id="INV-001", source="principle", statement="X")
    events = ({"kind": "e"},)
    return RunState(
        run_id=rid,
        invariants_before=frozenset({inv}),
        invariants_after=frozenset({inv}),
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"spec"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"adrs"})),),
        context_load=ContextLoad(100, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact="local",
    )


def _bad_q1_run(rid: str = "bad") -> RunState:
    """A RunState that trips Q1: silent invariant removal."""
    inv_a = Invariant(id="INV-001", source="principle", statement="X")
    inv_b = Invariant(id="INV-002", source="security", statement="Y")
    events = ({"kind": "e"},)
    return RunState(
        run_id=rid,
        invariants_before=frozenset({inv_a, inv_b}),
        invariants_after=frozenset({inv_a}),   # INV-002 silently gone
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"spec"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"adrs"})),),
        context_load=ContextLoad(100, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact="local",
    )


def _build_suite(good: int, bad: int) -> ReferenceSuite:
    cases = []
    for i in range(good):
        cases.append(ReferenceCase(
            run_state=_good_run(f"good-{i}"), label="known_good",
            detail=f"good-{i}",
        ))
    for i in range(bad):
        cases.append(ReferenceCase(
            run_state=_bad_q1_run(f"bad-{i}"), label="known_bad",
            detail=f"bad-{i}",
        ))
    return ReferenceSuite(cases=tuple(cases))


# Tests ------------------------------------------------------------------


def test_p_q1_passes_fp_threshold():
    """100 known-good runs should produce FP rate 0 on Q1."""
    suite = _build_suite(good=100, bad=0)
    report = measure_gate_accuracy("P_Q1_invariant_integrity", suite)
    assert report.fp_rate == 0.0
    assert report.good_count == 100
    assert report.bad_count == 0
    assert not report.insufficient_samples


def test_p_q1_passes_fn_threshold():
    """100 known-bad (silent removal) runs should produce FN rate 0 on Q1."""
    suite = _build_suite(good=100, bad=100)
    report = measure_gate_accuracy("P_Q1_invariant_integrity", suite)
    assert report.fn_rate == 0.0
    assert report.passed_thresholds is True


def test_insufficient_samples_flagged():
    """99 known-good cases fail the §3.1 'at least 100' sample rule."""
    suite = _build_suite(good=99, bad=100)
    report = measure_gate_accuracy("P_Q1_invariant_integrity", suite)
    assert report.insufficient_samples is True
    assert report.passed_thresholds is False  # underscore-sized


def test_threshold_depends_on_failure_level():
    """P_M4_independence is hazardous -> FN threshold 0.20."""
    suite = _build_suite(good=100, bad=50)
    report = measure_gate_accuracy("P_M4_independence", suite)
    assert report.failure_level == "hazardous"
    assert report.fn_threshold == 0.20


def test_catastrophic_gate_has_tighter_fn_threshold():
    suite = _build_suite(good=100, bad=100)
    report = measure_gate_accuracy("P_Q1_invariant_integrity", suite)
    assert report.failure_level == "catastrophic"
    assert report.fn_threshold == 0.10


def test_stub_gate_fails_phase0():
    """P_PI_sentinel is a stub — evaluate raises NotImplementedPredicateError.
    measure_gate_accuracy treats the stub as non-breached on every case,
    which gives fn_rate == 1.0 on a non-empty known_bad suite -> fail."""
    suite = _build_suite(good=100, bad=10)
    report = measure_gate_accuracy("P_PI_sentinel", suite)
    assert report.fn_rate == 1.0
    assert report.passed_thresholds is False


def test_false_positive_details_captured():
    """If a gate wrongly flags a known-good case as breached, its detail is captured."""
    # Use P_Q1 with an adversarial 'good' case that actually tripsQ1
    suite = ReferenceSuite(cases=(
        ReferenceCase(_bad_q1_run("mislabeled-as-good"),
                      label="known_good",
                      detail="mislabeled-as-good"),
    ) + _build_suite(good=99, bad=0).cases)
    report = measure_gate_accuracy("P_Q1_invariant_integrity", suite)
    assert report.fp_rate > 0
    assert "mislabeled-as-good" in report.false_positives


def test_false_negative_details_captured():
    """If a gate wrongly accepts a known-bad case, its detail is captured."""
    # P_Q1 is correct — force a false negative by feeding it a bad case
    # LABELED good and a good case LABELED bad.
    suite = ReferenceSuite(cases=(
        ReferenceCase(_good_run("good-disguised-as-bad"),
                      label="known_bad",
                      detail="good-disguised-as-bad"),
    ) + _build_suite(good=100, bad=0).cases)
    report = measure_gate_accuracy("P_Q1_invariant_integrity", suite)
    assert report.fn_rate > 0
    assert "good-disguised-as-bad" in report.false_negatives


def test_threshold_with_zero_bad_still_requires_fp():
    """A suite with only known-good cases can report FP; FN is trivially 0."""
    suite = _build_suite(good=100, bad=0)
    report = measure_gate_accuracy("P_Q1_invariant_integrity", suite)
    assert report.bad_count == 0
    assert report.fn_rate == 0.0
    assert report.passed_thresholds  # fp_rate is 0 on a correct gate


def test_unknown_gate_raises():
    from aios.verification.registry import UnknownPredicateError
    with pytest.raises(UnknownPredicateError):
        measure_gate_accuracy("P_does_not_exist", _build_suite(1, 1))
