"""Verification subsystem: conservation scan + gate registry.

See docs/spec/AIOS_Verification_Spec.md.
"""
from __future__ import annotations

from aios.verification.conservation_scan import (
    ADREvent,
    ContextLoad,
    Decision,
    EventLogRange,
    GenerationSlice,
    Invariant,
    RunState,
    VerificationSlice,
    any_breach,
    conservation_scan,
    jaccard,
    scan_q1_invariant_integrity,
    scan_q2_state_traceability,
    scan_q3_decision_reversibility,
    scan_m4_independence,
    scan_o5_context_sufficiency_hard,
)

__all__ = [
    "ADREvent",
    "ContextLoad",
    "Decision",
    "EventLogRange",
    "GenerationSlice",
    "Invariant",
    "RunState",
    "VerificationSlice",
    "any_breach",
    "conservation_scan",
    "jaccard",
    "scan_q1_invariant_integrity",
    "scan_q2_state_traceability",
    "scan_q3_decision_reversibility",
    "scan_m4_independence",
    "scan_o5_context_sufficiency_hard",
]
