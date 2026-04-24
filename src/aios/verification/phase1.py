"""Phase 0 → Phase 1 transition (sprint 41).

Verification Spec §3.1 lists five prerequisites that MUST be met before
credentialing can enforce capability. This module collects the reports
from sprints 39 + 40 + sprint 25 schema coverage, decides whether the
transition is allowed, and flips every credential in the ledger to
phase=1 when it is.

Prerequisites (§3.1 table):

    Gate false-positive rates         — sprint 39 AccuracyReport.passed
    Gate false-negative rates         — sprint 39 AccuracyReport.passed
    Benchmark contamination audit     — sprint 40 ContaminationReport.passed
    Incident backtesting              — sprint 40 BacktestReport present
                                        (rate published; no threshold)
    Reference-vector coverage >= 0.80 — explicit coverage map per gate

A4 + A5 co-signing is represented by two signer identifiers on the
transition call. The credentialing_enabled event that §3.1 names is
emitted by the calling layer (aios CLI) so this module stays
event-log-agnostic.
"""
from __future__ import annotations

import dataclasses as dc
from typing import Iterable

from aios.verification.backtest import BacktestReport, ContaminationReport
from aios.verification.credentials import CredentialLedger
from aios.verification.phase0 import AccuracyReport

_REF_VECTOR_COVERAGE_MIN = 0.80


class Phase1NotReadyError(RuntimeError):
    """Attempted to transition when at least one §3.1 prerequisite fails."""


@dc.dataclass(frozen=True)
class Phase1Readiness:
    gate_accuracy_reports: tuple[AccuracyReport, ...]
    contamination_reports: tuple[ContaminationReport, ...]
    backtest_report: BacktestReport | None
    reference_vector_coverage: dict[str, float]
    all_passed: bool
    blockers: tuple[str, ...]


def check_phase1_readiness(
    *,
    gate_accuracy: Iterable[AccuracyReport] = (),
    contamination: Iterable[ContaminationReport] = (),
    backtest: BacktestReport | None = None,
    reference_vector_coverage: dict[str, float] | None = None,
    gate_set: Iterable[str] | None = None,
) -> Phase1Readiness:
    """Produce a Phase1Readiness summary. Does NOT mutate any state.

    `gate_set` (optional) is the list of gate IDs the transition claims
    to certify. When supplied, every ID must have an accuracy report AND
    a reference-vector coverage entry >= 0.80.
    """
    gate_accuracy = tuple(gate_accuracy)
    contamination = tuple(contamination)
    coverage = dict(reference_vector_coverage or {})

    blockers: list[str] = []

    # 1. Gate accuracy — every report must pass its §3.1 thresholds
    for rep in gate_accuracy:
        if rep.insufficient_samples:
            blockers.append(
                f"gate {rep.gate_id}: only {rep.good_count} known-good "
                f"cases (§3.1 requires >= 100)"
            )
        elif not rep.passed_thresholds:
            blockers.append(
                f"gate {rep.gate_id}: FP={rep.fp_rate:.2f} FN={rep.fn_rate:.2f} "
                f"fails §3.1 (FP<={rep.fp_threshold:.2f}, "
                f"FN<={rep.fn_threshold:.2f})"
            )

    # 2. Contamination — every audit must pass (or be contamination_tolerant)
    for report in contamination:
        if not report.passed:
            blockers.append(
                f"benchmark {report.benchmark_id}: overlap "
                f"{report.overlap:.3f} > threshold {report.threshold:.2f} "
                f"(signer {report.signer})"
            )

    # 3. Incident backtesting — must exist; rate published but no hard floor
    if backtest is None:
        blockers.append(
            "no incident backtest report supplied; §3.1 requires one "
            "before credentialing can go live"
        )

    # 4. Reference-vector coverage per gate
    if gate_set is not None:
        for gid in gate_set:
            cov = coverage.get(gid)
            if cov is None:
                blockers.append(
                    f"gate {gid}: no reference-vector coverage reported "
                    f"(§3.1 requires >= {_REF_VECTOR_COVERAGE_MIN})"
                )
            elif cov < _REF_VECTOR_COVERAGE_MIN:
                blockers.append(
                    f"gate {gid}: reference-vector coverage {cov:.2f} < "
                    f"{_REF_VECTOR_COVERAGE_MIN}"
                )
            # Also require an accuracy report per declared gate
            if not any(r.gate_id == gid for r in gate_accuracy):
                blockers.append(
                    f"gate {gid}: no Phase 0 accuracy report supplied"
                )

    return Phase1Readiness(
        gate_accuracy_reports=gate_accuracy,
        contamination_reports=contamination,
        backtest_report=backtest,
        reference_vector_coverage=coverage,
        all_passed=not blockers,
        blockers=tuple(blockers),
    )


def enable_phase1(
    ledger: CredentialLedger,
    readiness: Phase1Readiness,
    *,
    a4_signer: str,
    a5_signer: str,
) -> list[str]:
    """Flip every phase=0 credential in the ledger to phase=1.

    Raises Phase1NotReadyError if any §3.1 prerequisite blocks the
    transition, or if either co-signer identifier is missing. Returns
    the list of entity_ids that were transitioned.

    Writing the credentialing_enabled event to the event log is the
    caller's job — the ledger is event-log-agnostic.
    """
    if not readiness.all_passed:
        raise Phase1NotReadyError(
            "Phase 1 not ready; §3.1 blockers:\n  - "
            + "\n  - ".join(readiness.blockers)
        )
    if not a4_signer or not a4_signer.strip():
        raise Phase1NotReadyError("a4_signer is empty — §3.1 needs A4 co-sign")
    if not a5_signer or not a5_signer.strip():
        raise Phase1NotReadyError("a5_signer is empty — §3.1 needs A5 co-sign")

    transitioned: list[str] = []
    for entity_id in ledger.list_entities():
        rec = ledger.get(entity_id)
        if rec.phase == 0:
            ledger.put(dc.replace(rec, phase=1))
            transitioned.append(entity_id)
    return transitioned
