"""Tests for contamination audit + incident backtesting (sprint 40)."""
from __future__ import annotations

import pytest

from aios.verification.backtest import (
    ContaminationAudit,
    ContaminationAuditError,
    Incident,
    contamination_audit,
    incident_backtest,
)
from aios.verification.conservation_scan import (
    ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
)


# Contamination audit ----------------------------------------------------


def test_clean_audit_passes():
    audit = ContaminationAudit(
        benchmark_id="B1",
        benchmark_sample_hashes=frozenset({"a", "b", "c", "d"}),
        training_sample_hashes=frozenset({"x", "y", "z"}),
        method="sha256-exact",
        last_run_iso="2026-04-24T00:00:00Z",
        signer="A4-reviewer",
    )
    report = contamination_audit(audit)
    assert report.overlap == 0.0
    assert report.passed is True


def test_overlap_exactly_5_percent_passes():
    # 1 contaminated out of 20 = 5%
    bench = {f"h{i}" for i in range(20)}
    train = {"h0"}  # 1 overlap
    audit = ContaminationAudit(
        benchmark_id="B2",
        benchmark_sample_hashes=frozenset(bench),
        training_sample_hashes=frozenset(train),
        method="sha256",
        last_run_iso="2026-04-24T00:00:00Z",
        signer="A4",
    )
    report = contamination_audit(audit)
    assert report.overlap == pytest.approx(0.05)
    assert report.passed is True


def test_overlap_above_threshold_fails():
    # 2 contaminated out of 20 = 10%
    bench = {f"h{i}" for i in range(20)}
    train = {"h0", "h1"}
    audit = ContaminationAudit(
        benchmark_id="B3",
        benchmark_sample_hashes=frozenset(bench),
        training_sample_hashes=frozenset(train),
        method="sha256",
        last_run_iso="2026-04-24T00:00:00Z",
        signer="A4",
    )
    report = contamination_audit(audit)
    assert report.overlap == pytest.approx(0.10)
    assert report.passed is False


def test_contamination_tolerant_overrides_threshold():
    """§3.1 escape hatch: a signed declaration of contamination-tolerant
    evaluation accepts any overlap level."""
    bench = {f"h{i}" for i in range(10)}
    train = {f"h{i}" for i in range(5)}   # 50% overlap
    audit = ContaminationAudit(
        benchmark_id="B4",
        benchmark_sample_hashes=frozenset(bench),
        training_sample_hashes=frozenset(train),
        method="sha256",
        last_run_iso="2026-04-24T00:00:00Z",
        signer="A5-author",
        contamination_tolerant=True,
    )
    report = contamination_audit(audit)
    assert report.overlap == pytest.approx(0.5)
    assert report.passed is True
    assert report.contamination_tolerant_declared is True


def test_unsigned_audit_rejected():
    audit = ContaminationAudit(
        benchmark_id="B5",
        benchmark_sample_hashes=frozenset({"a"}),
        training_sample_hashes=frozenset(),
        method="sha256",
        last_run_iso="2026-04-24T00:00:00Z",
        signer="",
    )
    with pytest.raises(ContaminationAuditError, match="signer"):
        contamination_audit(audit)


def test_empty_benchmark_yields_zero_overlap():
    audit = ContaminationAudit(
        benchmark_id="B6",
        benchmark_sample_hashes=frozenset(),
        training_sample_hashes=frozenset({"x"}),
        method="sha256",
        last_run_iso="2026-04-24T00:00:00Z",
        signer="A4",
    )
    assert contamination_audit(audit).overlap == 0.0


# Incident backtesting ---------------------------------------------------


def _q1_breach_run() -> RunState:
    inv_a = Invariant(id="INV-001", source="principle", statement="X")
    inv_b = Invariant(id="INV-002", source="security", statement="Y")
    events = ({"kind": "e"},)
    return RunState(
        run_id="i",
        invariants_before=frozenset({inv_a, inv_b}),
        invariants_after=frozenset({inv_a}),       # silent removal of INV-002
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"spec"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"adrs"})),),
        context_load=ContextLoad(100, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact="local",
    )


def _clean_run() -> RunState:
    inv = Invariant(id="INV-001", source="principle", statement="X")
    events = ({"kind": "e"},)
    return RunState(
        run_id="c",
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


def test_backtest_catches_q1_breach():
    incidents = [Incident(
        incident_id="INC-1",
        run_state=_q1_breach_run(),
        expected_breach_gates=("P_Q1_invariant_integrity",),
        summary="silent removal of security invariant",
    )]
    report = incident_backtest(incidents)
    assert report.incident_count == 1
    assert report.caught_count == 1
    assert report.hit_rate == 1.0
    assert report.results[0].caught is True
    assert "P_Q1_invariant_integrity" in report.results[0].breached_gates


def test_backtest_misses_when_no_gate_fires():
    """Incident expects Q2 to catch it but Q2 verifies — miss recorded."""
    incidents = [Incident(
        incident_id="INC-2",
        run_state=_clean_run(),   # actually clean; Q2 will report preserved
        expected_breach_gates=("P_Q2_state_traceability",),
        summary="clean run mislabeled as an incident",
    )]
    report = incident_backtest(incidents)
    assert report.caught_count == 0
    assert report.hit_rate == 0.0
    assert "INC-2" in report.missed_incident_ids


def test_backtest_mixed_hit_rate():
    incidents = [
        Incident(
            incident_id="INC-HIT-1",
            run_state=_q1_breach_run(),
            expected_breach_gates=("P_Q1_invariant_integrity",),
        ),
        Incident(
            incident_id="INC-HIT-2",
            run_state=_q1_breach_run(),
            expected_breach_gates=("P_Q1_invariant_integrity",),
        ),
        Incident(
            incident_id="INC-MISS",
            run_state=_clean_run(),
            expected_breach_gates=("P_Q1_invariant_integrity",),
        ),
    ]
    report = incident_backtest(incidents)
    assert report.caught_count == 2
    assert report.hit_rate == pytest.approx(2 / 3)
    assert report.missed_incident_ids == ("INC-MISS",)


def test_empty_incident_list_zero_rate():
    report = incident_backtest([])
    assert report.incident_count == 0
    assert report.hit_rate == 0.0


def test_backtest_stub_gate_counts_as_miss():
    """Expected-breach gate is a stub -> never fires -> incident missed."""
    incidents = [Incident(
        incident_id="INC-STUB",
        run_state=_q1_breach_run(),
        expected_breach_gates=("P_PI_sentinel",),   # stub
    )]
    report = incident_backtest(incidents)
    assert report.caught_count == 0
    assert report.hit_rate == 0.0
