"""Audit protocol + G1–G7 taxonomy (sprint 43).

Verification Spec §4 describes the outermost loop — the system watching
itself. This module ships:
  - a typed event for each governance-failure class G1-G7 (§4.3)
  - scan functions for the daily / weekly / monthly audit cadences (§4.2)
  - an AuditReport that summarizes G-class incidence over a window

This is NOT itself an audit oracle; it's the data pipeline the audit
rituals use. Daily/weekly/monthly cadence is operator-driven (§4.7 —
A4 conducts routine audits, A5 for supply-chain implications).

The G taxonomy (§4.3) — each a first-class event type with containment:

  G1 Overblocking             PR throughput falls; catch rate on merged
                              PRs -> 0. Contain: middle-loop recalibrate.
  G2 Underblocking            Production error rate rises while gates
                              pass. Contain: full three-lane + adversarial.
  G3 Review capture           One entity approves a disproportionate
                              share of consequential merges. Contain:
                              rotation policy; force debate.
  G4 Benchmark gaming         Skill score on benchmark rises while
                              field quality falls. Contain: rotate eval
                              suite; SWE-bench-plus-style leak audits.
  G5 Provenance overload      Event log grows faster than queries
                              serve it; projections lag. Contain:
                              scale tier down; archive cold events.
  G6 Stale-contract failure   Skill invoked past calibration refresh
                              window. Contain: auto-quarantine; force
                              recalibrate.
  G7 Oscillation              Gate thresholds change too fast.
                              Contain: freeze thresholds; human override.
"""
from __future__ import annotations

import dataclasses as dc
from datetime import datetime, timedelta, timezone
from typing import Iterable, Literal

GClass = Literal["G1", "G2", "G3", "G4", "G5", "G6", "G7"]

G_CONTAINMENT: dict[GClass, str] = {
    "G1": "middle-loop recalibration",
    "G2": "engage full three-lane verification; adversarial suite",
    "G3": "rotation policy; force debate",
    "G4": "rotate eval suite; SWE-bench-plus-style leak audits",
    "G5": "scale provenance tier down; archive cold events",
    "G6": "auto-quarantine; force recalibration",
    "G7": "freeze thresholds; human override required",
}


@dc.dataclass(frozen=True)
class AuditEvent:
    """One governance-failure observation."""
    g_class: GClass
    ts_iso: str
    subject: str                # entity/gate/workflow involved
    detail: str
    severity: Literal["observation", "warning", "violation"] = "warning"


@dc.dataclass(frozen=True)
class AuditReport:
    window_start_iso: str
    window_end_iso: str
    cadence: Literal["daily", "weekly", "monthly", "quarterly", "ad_hoc"]
    events: tuple[AuditEvent, ...]
    counts_by_class: dict[str, int]

    def events_of_class(self, g: GClass) -> tuple[AuditEvent, ...]:
        return tuple(e for e in self.events if e.g_class == g)

    def summary(self) -> str:
        lines = [
            f"audit cadence: {self.cadence}",
            f"window: {self.window_start_iso} -> {self.window_end_iso}",
            f"events:  {len(self.events)}",
        ]
        for g in ("G1", "G2", "G3", "G4", "G5", "G6", "G7"):
            c = self.counts_by_class.get(g, 0)
            if c:
                lines.append(f"  {g} {c:>3}  {G_CONTAINMENT[g]}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scan primitives — stateless, take observations + produce AuditEvents
# ---------------------------------------------------------------------------


def scan_overblocking(
    *,
    gate_fp_rates: dict[str, float],
    fp_threshold: float = 0.10,
    ts_iso: str | None = None,
) -> list[AuditEvent]:
    """G1: any gate with FP rate > threshold."""
    ts = ts_iso or _iso_now()
    return [
        AuditEvent(
            g_class="G1", ts_iso=ts, subject=gate,
            detail=f"FP rate {rate:.3f} > {fp_threshold:.2f}",
            severity="warning" if rate < 2 * fp_threshold else "violation",
        )
        for gate, rate in gate_fp_rates.items() if rate > fp_threshold
    ]


def scan_underblocking(
    *,
    gate_fn_rates: dict[str, float],
    fn_threshold_by_gate: dict[str, float] | None = None,
    default_fn_threshold: float = 0.20,
    ts_iso: str | None = None,
) -> list[AuditEvent]:
    """G2: any gate with FN rate > its threshold."""
    ts = ts_iso or _iso_now()
    thresholds = fn_threshold_by_gate or {}
    events: list[AuditEvent] = []
    for gate, rate in gate_fn_rates.items():
        threshold = thresholds.get(gate, default_fn_threshold)
        if rate > threshold:
            events.append(AuditEvent(
                g_class="G2", ts_iso=ts, subject=gate,
                detail=f"FN rate {rate:.3f} > {threshold:.2f}",
                severity="violation",
            ))
    return events


def scan_review_capture(
    *,
    verifier_merge_counts: dict[str, int],
    dominant_share_threshold: float = 0.5,
    ts_iso: str | None = None,
) -> list[AuditEvent]:
    """G3: one entity approves > threshold share of consequential merges."""
    ts = ts_iso or _iso_now()
    total = sum(verifier_merge_counts.values())
    if total == 0:
        return []
    events: list[AuditEvent] = []
    for entity, count in verifier_merge_counts.items():
        share = count / total
        if share > dominant_share_threshold:
            events.append(AuditEvent(
                g_class="G3", ts_iso=ts, subject=entity,
                detail=f"approves {count}/{total} ({share:.1%}) of merges",
                severity="violation",
            ))
    return events


def scan_benchmark_gaming(
    *,
    benchmark_score_delta: float,
    field_quality_delta: float,
    subject: str = "benchmark",
    ts_iso: str | None = None,
) -> list[AuditEvent]:
    """G4: benchmark score rising while field quality falling."""
    if benchmark_score_delta > 0 and field_quality_delta < 0:
        return [AuditEvent(
            g_class="G4", ts_iso=ts_iso or _iso_now(), subject=subject,
            detail=(f"benchmark Δ={benchmark_score_delta:+.3f} "
                    f"field Δ={field_quality_delta:+.3f}"),
            severity="violation",
        )]
    return []


def scan_provenance_overload(
    *,
    events_per_minute: float,
    query_latency_p99_ms: float,
    latency_budget_ms: float = 2000.0,
    ts_iso: str | None = None,
) -> list[AuditEvent]:
    """G5: event-log growth outpacing query service."""
    if query_latency_p99_ms > latency_budget_ms:
        return [AuditEvent(
            g_class="G5", ts_iso=ts_iso or _iso_now(),
            subject="event_log",
            detail=(f"p99 query latency {query_latency_p99_ms:.0f}ms > "
                    f"{latency_budget_ms:.0f}ms at "
                    f"{events_per_minute:.0f} events/min"),
            severity="warning",
        )]
    return []


def scan_stale_contracts(
    *,
    skill_last_calibration: dict[str, datetime],
    max_age_by_schedule: dict[str, timedelta] | None = None,
    default_max_age: timedelta = timedelta(days=7),
    ts_iso: str | None = None,
    now: datetime | None = None,
) -> list[AuditEvent]:
    """G6: any skill whose last calibration is older than its window."""
    ts = ts_iso or _iso_now()
    events: list[AuditEvent] = []
    reference_now = now or datetime.now(timezone.utc)
    for skill, last in skill_last_calibration.items():
        max_age = default_max_age
        if max_age_by_schedule:
            max_age = max_age_by_schedule.get(skill, default_max_age)
        age = reference_now - last
        if age > max_age:
            events.append(AuditEvent(
                g_class="G6", ts_iso=ts, subject=skill,
                detail=(f"last calibration {age.days}d ago; "
                        f"window {max_age.days}d"),
                severity="warning",
            ))
    return events


def scan_oscillation(
    *,
    threshold_changes_in_window: dict[str, int],
    max_changes_per_window: int = 2,
    ts_iso: str | None = None,
) -> list[AuditEvent]:
    """G7: gate thresholds changed more than `max_changes_per_window` times."""
    ts = ts_iso or _iso_now()
    return [
        AuditEvent(
            g_class="G7", ts_iso=ts, subject=gate,
            detail=f"{changes} threshold changes in window "
                   f"(max {max_changes_per_window})",
            severity="violation",
        )
        for gate, changes in threshold_changes_in_window.items()
        if changes > max_changes_per_window
    ]


# ---------------------------------------------------------------------------
# Report roll-up
# ---------------------------------------------------------------------------


def compile_audit_report(
    *,
    cadence: Literal["daily", "weekly", "monthly", "quarterly", "ad_hoc"],
    events: Iterable[AuditEvent],
    window_start_iso: str,
    window_end_iso: str | None = None,
) -> AuditReport:
    end = window_end_iso or _iso_now()
    events_tuple = tuple(events)
    counts: dict[str, int] = {}
    for e in events_tuple:
        counts[e.g_class] = counts.get(e.g_class, 0) + 1
    return AuditReport(
        window_start_iso=window_start_iso,
        window_end_iso=end,
        cadence=cadence,
        events=events_tuple,
        counts_by_class=counts,
    )


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
