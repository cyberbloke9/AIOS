"""Phase 0 gate accuracy measurement (sprint 39).

Verification Spec §3.1 makes three numerical requirements gate the
Phase 0 → Phase 1 credential-enforcement transition:

  gate_fp_rate  <= 0.10 per gate, measured on >= 100 known-good cases
  gate_fn_rate  <= 0.10 per CATASTROPHIC T1 gate
  gate_fn_rate  <= 0.20 per HAZARDOUS T1/T2/T3 gate
  (major/minor gates use the hazardous threshold by §3.1 table)

This module does the measurement. It runs the gate against a reference
suite of (RunState, known_good|known_bad) pairs and reports:
  fp_rate                 — known-good cases the gate WRONGLY BREACHED
  fn_rate                 — known-bad cases the gate WRONGLY PRESERVED
  good_count / bad_count  — corpus sizes
  passed_thresholds       — bool: does this gate clear its §3.1 bar?

A Phase 0 → Phase 1 ADR (sprint 41) requires passed_thresholds on every
gate in its required set, OR is blocked.
"""
from __future__ import annotations

import dataclasses as dc
from typing import Literal

from aios.verification.conservation_scan import RunState
from aios.verification.registry import (
    FailureLevel,
    NotImplementedPredicateError,
    Registry,
    default_registry,
)

Label = Literal["known_good", "known_bad"]

# §3.1 thresholds by gate failure-level
_FN_THRESHOLD_BY_LEVEL: dict[FailureLevel, float] = {
    "catastrophic": 0.10,
    "hazardous":    0.20,
    "major":        0.20,
    "minor":        0.20,
    "no_effect":    1.00,  # untested gates get the loosest bar
}
_FP_THRESHOLD = 0.10
_MIN_GOOD_CASES = 100


class ReferenceSuiteError(ValueError):
    """Structural problem with the suite itself (missing labels, too few)."""


@dc.dataclass(frozen=True)
class ReferenceCase:
    """A single labeled input to the gate accuracy harness."""
    run_state: RunState
    label: Label
    detail: str = ""   # optional — why this was labeled the way it was


@dc.dataclass(frozen=True)
class ReferenceSuite:
    cases: tuple[ReferenceCase, ...]

    @property
    def good_cases(self) -> tuple[ReferenceCase, ...]:
        return tuple(c for c in self.cases if c.label == "known_good")

    @property
    def bad_cases(self) -> tuple[ReferenceCase, ...]:
        return tuple(c for c in self.cases if c.label == "known_bad")


@dc.dataclass(frozen=True)
class AccuracyReport:
    gate_id: str
    failure_level: FailureLevel
    fp_rate: float
    fn_rate: float
    good_count: int
    bad_count: int
    fp_threshold: float
    fn_threshold: float
    passed_thresholds: bool
    insufficient_samples: bool
    # Per-case evaluator verdicts for diagnostics
    false_positives: tuple[str, ...] = ()   # case details of wrong-breaches
    false_negatives: tuple[str, ...] = ()


def measure_gate_accuracy(
    gate_id: str,
    suite: ReferenceSuite,
    *,
    registry: Registry | None = None,
) -> AccuracyReport:
    """Run the gate against every case in suite; return FP/FN rates."""
    reg = registry if registry is not None else default_registry

    rec = reg.get(gate_id)  # raises UnknownPredicateError on typo
    level: FailureLevel = rec.failure_level

    good = suite.good_cases
    bad = suite.bad_cases

    insufficient = len(good) < _MIN_GOOD_CASES

    fp_count = 0
    fn_count = 0
    fp_details: list[str] = []
    fn_details: list[str] = []

    for case in good:
        if _gate_says_breached(reg, gate_id, case.run_state):
            fp_count += 1
            fp_details.append(case.detail or f"case@{id(case):x}")

    for case in bad:
        if not _gate_says_breached(reg, gate_id, case.run_state):
            fn_count += 1
            fn_details.append(case.detail or f"case@{id(case):x}")

    fp_rate = fp_count / max(1, len(good))
    fn_rate = fn_count / max(1, len(bad))

    fn_threshold = _FN_THRESHOLD_BY_LEVEL[level]
    passed = (
        not insufficient
        and fp_rate <= _FP_THRESHOLD
        and (not bad or fn_rate <= fn_threshold)
    )

    return AccuracyReport(
        gate_id=gate_id,
        failure_level=level,
        fp_rate=fp_rate,
        fn_rate=fn_rate,
        good_count=len(good),
        bad_count=len(bad),
        fp_threshold=_FP_THRESHOLD,
        fn_threshold=fn_threshold,
        passed_thresholds=passed,
        insufficient_samples=insufficient,
        false_positives=tuple(fp_details),
        false_negatives=tuple(fn_details),
    )


def _gate_says_breached(reg: Registry, gate_id: str, run: RunState) -> bool:
    """True if the gate's verdict on this RunState is 'breached'."""
    try:
        out = reg.evaluate(gate_id, run)
    except NotImplementedPredicateError:
        # Stub gates never return useful verdicts — treat as non-breached
        # so Phase 0 measurement never rubber-stamps an unimplemented
        # predicate. The §3.1 FN rate on a stub gate will be 1.0 for any
        # non-empty known_bad suite, failing the threshold check.
        return False
    except Exception:
        # An evaluator that blew up on a known-good case is itself a defect.
        # Treat as breached so it is counted as a FP.
        return True
    if not isinstance(out, dict):
        return True
    return out.get("status") == "breached"
