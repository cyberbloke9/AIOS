"""Tests for audit protocol + G1-G7 taxonomy (sprint 43)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aios.verification.audit import (
    AuditEvent,
    G_CONTAINMENT,
    compile_audit_report,
    scan_benchmark_gaming,
    scan_oscillation,
    scan_overblocking,
    scan_provenance_overload,
    scan_review_capture,
    scan_stale_contracts,
    scan_underblocking,
)


# Containment table -------------------------------------------------------


def test_containment_covers_all_seven_classes():
    assert set(G_CONTAINMENT) == {"G1", "G2", "G3", "G4", "G5", "G6", "G7"}


# G1 Overblocking ---------------------------------------------------------


def test_g1_fires_on_fp_above_threshold():
    events = scan_overblocking(
        gate_fp_rates={"P_Q1_invariant_integrity": 0.15},
    )
    assert len(events) == 1
    assert events[0].g_class == "G1"


def test_g1_quiet_when_all_gates_under_threshold():
    events = scan_overblocking(
        gate_fp_rates={"P_Q1": 0.05, "P_Q2": 0.07},
    )
    assert events == []


def test_g1_severity_escalates_at_2x_threshold():
    e = scan_overblocking(gate_fp_rates={"P_X": 0.25})[0]
    assert e.severity == "violation"
    e2 = scan_overblocking(gate_fp_rates={"P_X": 0.12})[0]
    assert e2.severity == "warning"


# G2 Underblocking --------------------------------------------------------


def test_g2_fires_on_fn_above_default_threshold():
    events = scan_underblocking(
        gate_fn_rates={"P_Q1": 0.25},
    )
    assert len(events) == 1
    assert events[0].g_class == "G2"


def test_g2_respects_per_gate_threshold():
    # P_Q1 is catastrophic -> 0.10 threshold
    events = scan_underblocking(
        gate_fn_rates={"P_Q1": 0.15},
        fn_threshold_by_gate={"P_Q1": 0.10},
    )
    assert len(events) == 1


def test_g2_quiet_when_under_custom_threshold():
    events = scan_underblocking(
        gate_fn_rates={"P_Q1": 0.05},
        fn_threshold_by_gate={"P_Q1": 0.10},
    )
    assert events == []


# G3 Review capture -------------------------------------------------------


def test_g3_fires_on_dominant_share():
    events = scan_review_capture(
        verifier_merge_counts={"A4-alice": 8, "A4-bob": 2},
    )
    assert len(events) == 1
    assert events[0].g_class == "G3"
    assert "alice" in events[0].subject


def test_g3_quiet_with_balanced_reviewers():
    events = scan_review_capture(
        verifier_merge_counts={"A4-alice": 5, "A4-bob": 5},
    )
    assert events == []


def test_g3_empty_input_is_safe():
    assert scan_review_capture(verifier_merge_counts={}) == []


# G4 Benchmark gaming -----------------------------------------------------


def test_g4_fires_on_divergence():
    events = scan_benchmark_gaming(
        benchmark_score_delta=0.05,
        field_quality_delta=-0.03,
    )
    assert len(events) == 1
    assert events[0].g_class == "G4"


def test_g4_quiet_when_both_moving_same_direction():
    assert scan_benchmark_gaming(
        benchmark_score_delta=0.05, field_quality_delta=0.02,
    ) == []
    assert scan_benchmark_gaming(
        benchmark_score_delta=-0.05, field_quality_delta=-0.02,
    ) == []


# G5 Provenance overload --------------------------------------------------


def test_g5_fires_when_latency_exceeds_budget():
    events = scan_provenance_overload(
        events_per_minute=10_000,
        query_latency_p99_ms=3000,
    )
    assert len(events) == 1
    assert events[0].g_class == "G5"


def test_g5_quiet_when_under_budget():
    assert scan_provenance_overload(
        events_per_minute=10_000,
        query_latency_p99_ms=1000,
    ) == []


# G6 Stale contracts ------------------------------------------------------


def test_g6_fires_on_stale_skill():
    now = datetime.now(timezone.utc)
    events = scan_stale_contracts(
        skill_last_calibration={
            "SK-DEMO": now - timedelta(days=10),
        },
        default_max_age=timedelta(days=7),
        now=now,
    )
    assert len(events) == 1
    assert events[0].g_class == "G6"


def test_g6_quiet_on_fresh_skill():
    now = datetime.now(timezone.utc)
    assert scan_stale_contracts(
        skill_last_calibration={"SK-DEMO": now - timedelta(days=3)},
        default_max_age=timedelta(days=7),
        now=now,
    ) == []


def test_g6_respects_per_skill_schedule():
    now = datetime.now(timezone.utc)
    # SK-MONTHLY uses 30d window
    events = scan_stale_contracts(
        skill_last_calibration={"SK-MONTHLY": now - timedelta(days=20)},
        max_age_by_schedule={"SK-MONTHLY": timedelta(days=30)},
        now=now,
    )
    assert events == []


# G7 Oscillation ----------------------------------------------------------


def test_g7_fires_on_frequent_threshold_changes():
    events = scan_oscillation(
        threshold_changes_in_window={"P_Q1": 5},
        max_changes_per_window=2,
    )
    assert len(events) == 1
    assert events[0].g_class == "G7"


def test_g7_quiet_when_stable():
    assert scan_oscillation(
        threshold_changes_in_window={"P_Q1": 1, "P_Q2": 2},
    ) == []


# Report roll-up ----------------------------------------------------------


def test_compile_audit_report_counts_classes():
    events = [
        AuditEvent(g_class="G1", ts_iso="t", subject="s", detail="d"),
        AuditEvent(g_class="G1", ts_iso="t", subject="s", detail="d"),
        AuditEvent(g_class="G6", ts_iso="t", subject="s", detail="d"),
    ]
    report = compile_audit_report(
        cadence="daily", events=events,
        window_start_iso="2026-04-24T00:00:00Z",
    )
    assert report.counts_by_class == {"G1": 2, "G6": 1}
    assert len(report.events_of_class("G1")) == 2


def test_audit_report_summary_is_human_readable():
    report = compile_audit_report(
        cadence="weekly",
        events=[AuditEvent(g_class="G3", ts_iso="t", subject="s", detail="d")],
        window_start_iso="start",
    )
    text = report.summary()
    assert "weekly" in text
    assert "G3" in text
    assert "debate" in text.lower()  # from G3 containment string


def test_audit_report_empty_events():
    report = compile_audit_report(
        cadence="monthly", events=[],
        window_start_iso="t",
    )
    assert report.counts_by_class == {}
    assert report.events == ()
