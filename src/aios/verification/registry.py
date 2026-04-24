"""Gate predicate registry (sprint 4).

Implements Verification Spec §1:
  §1.1 predicate record schema
  §1.2 core predicates required for every deployment
  §1.4 predicate lifecycle (proposed / active / deprecated / retired)

The loader MUST refuse to load a workflow manifest that references a
predicate not in the registry (Verification Spec §1, paragraph 2).

This module registers the core predicates only. Individual workflows that
need additional predicates follow the §1.5 activation procedure and call
`Registry.register()` from their own code.
"""
from __future__ import annotations

import dataclasses as dc
from typing import Callable, Literal

from aios.verification.conservation_scan import (
    RunState,
    scan_m4_independence,
    scan_o5_context_sufficiency_hard,
    scan_q1_invariant_integrity,
    scan_q2_state_traceability,
    scan_q3_decision_reversibility,
)

AuthorityId = Literal["A1", "A2", "A3", "A4", "A5"]
GateType = Literal["T1", "T2", "T3", "T4"]
Determinism = Literal["deterministic", "stochastic_bounded", "stochastic_calibrated"]
SideEffects = Literal["read_only", "appends_audit_event", "writes_quarantine"]
FailureLevel = Literal["catastrophic", "hazardous", "major", "minor", "no_effect"]
SoundnessClass = Literal["Q1", "Q2", "Q3", "M4", "O5", "other"]
Lifecycle = Literal["proposed", "active", "deprecated", "retired"]


@dc.dataclass(frozen=True)
class PredicateRecord:
    """Matches the YAML schema in Verification Spec §1.1."""
    id: str
    version: str
    owner_authority: AuthorityId
    gate_type: GateType
    determinism: Determinism
    side_effects: SideEffects
    input_schema: str          # JSON Schema file path (relative to registry root)
    output_schema: str
    reference_vectors: str     # path to reference-vectors file
    failure_level: FailureLevel
    soundness_class: SoundnessClass
    lifecycle: Lifecycle = "active"
    # The callable is optional: stubs in the registry carry None and the
    # loader will surface "not implemented" at evaluate() time.
    implementation: Callable[[RunState], dict] | None = None


class UnknownPredicateError(KeyError):
    """Raised when a workflow references an ID not in the registry."""


class NotImplementedPredicateError(RuntimeError):
    """Raised when a registered predicate has no implementation yet."""


class Registry:
    """Mutable predicate registry. Seeded with the Verification Spec §1.2 core set."""

    def __init__(self) -> None:
        self._by_id: dict[str, PredicateRecord] = {}
        for rec in _core_records():
            self.register(rec)

    def register(self, record: PredicateRecord) -> None:
        if record.id in self._by_id:
            raise ValueError(f"predicate {record.id!r} already registered")
        self._by_id[record.id] = record

    def get(self, predicate_id: str) -> PredicateRecord:
        try:
            return self._by_id[predicate_id]
        except KeyError:
            raise UnknownPredicateError(
                f"predicate {predicate_id!r} not in registry; "
                f"known: {', '.join(sorted(self._by_id))}"
            )

    def has(self, predicate_id: str) -> bool:
        return predicate_id in self._by_id

    def list_ids(self) -> list[str]:
        return sorted(self._by_id)

    def require_registered(self, predicate_ids: list[str]) -> None:
        """Loader-level refusal per Verification Spec §1: refuse any
        manifest that references an unregistered predicate."""
        missing = [pid for pid in predicate_ids if pid not in self._by_id]
        if missing:
            raise UnknownPredicateError(
                f"workflow references unregistered predicate(s): {missing}"
            )

    def evaluate(self, predicate_id: str, run: RunState, **kwargs) -> dict:
        """Invoke the predicate implementation. Raises if only a stub."""
        rec = self.get(predicate_id)
        if rec.implementation is None:
            raise NotImplementedPredicateError(
                f"predicate {predicate_id!r} is registered but has no "
                f"implementation in this build (see docs/coverage.md)"
            )
        return rec.implementation(run, **kwargs)


# ---------------------------------------------------------------------------
# Verification Spec §1.2 core predicate records
# ---------------------------------------------------------------------------


def _core_records() -> list[PredicateRecord]:
    """Verification Spec §1.2 table, with implementations wired where they
    exist in this build and `None` where deferred (see docs/coverage.md)."""
    return [
        PredicateRecord(
            id="P_Q1_invariant_integrity",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T1",
            determinism="deterministic",
            side_effects="read_only",
            input_schema="schemas/P_Q1.input.json",
            output_schema="schemas/P_Q1.output.json",
            reference_vectors="reference_vectors/P_Q1.json",
            failure_level="catastrophic",
            soundness_class="Q1",
            implementation=scan_q1_invariant_integrity,
        ),
        PredicateRecord(
            id="P_Q2_state_traceability",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T1",
            determinism="deterministic",
            side_effects="read_only",
            input_schema="schemas/P_Q2.input.json",
            output_schema="schemas/P_Q2.output.json",
            reference_vectors="reference_vectors/P_Q2.json",
            failure_level="catastrophic",
            soundness_class="Q2",
            implementation=scan_q2_state_traceability,
        ),
        PredicateRecord(
            id="P_Q3_decision_reversibility",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T1",
            determinism="deterministic",
            side_effects="read_only",
            input_schema="schemas/P_Q3.input.json",
            output_schema="schemas/P_Q3.output.json",
            reference_vectors="reference_vectors/P_Q3.json",
            failure_level="catastrophic",
            soundness_class="Q3",
            implementation=scan_q3_decision_reversibility,
        ),
        PredicateRecord(
            id="P_M4_independence",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T1",
            determinism="deterministic",
            side_effects="read_only",
            input_schema="schemas/P_M4.input.json",
            output_schema="schemas/P_M4.output.json",
            reference_vectors="reference_vectors/P_M4.json",
            failure_level="hazardous",
            soundness_class="M4",
            implementation=scan_m4_independence,
        ),
        PredicateRecord(
            id="P_O5_context_sufficiency_hard",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T1",
            determinism="deterministic",
            side_effects="read_only",
            input_schema="schemas/P_O5.input.json",
            output_schema="schemas/P_O5.output.json",
            reference_vectors="reference_vectors/P_O5.json",
            failure_level="hazardous",
            soundness_class="O5",
            implementation=scan_o5_context_sufficiency_hard,
        ),
        # §1.2: generic schema check — deferred. Workflows supply their own.
        PredicateRecord(
            id="P_schema_valid",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T3",
            determinism="deterministic",
            side_effects="read_only",
            input_schema="schemas/P_schema_valid.input.json",
            output_schema="schemas/P_schema_valid.output.json",
            reference_vectors="reference_vectors/P_schema_valid.json",
            failure_level="major",
            soundness_class="other",
            implementation=None,  # requires a concrete target schema per call
        ),
        # §1.2: prompt-injection sentinel — deferred to v2 (requires a
        # calibrated classifier + adversarial corpus).
        PredicateRecord(
            id="P_PI_sentinel",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T1",
            determinism="deterministic",
            side_effects="read_only",
            input_schema="schemas/P_PI_sentinel.input.json",
            output_schema="schemas/P_PI_sentinel.output.json",
            reference_vectors="reference_vectors/P_PI_sentinel.json",
            failure_level="hazardous",
            soundness_class="other",
            implementation=None,
        ),
        # §1.2: named acceptance-test suite — orchestrator-level, not a
        # per-run predicate. Registered so workflows can reference it.
        PredicateRecord(
            id="P_acceptance_tests",
            version="1.0.0",
            owner_authority="A4",
            gate_type="T2",
            determinism="stochastic_bounded",
            side_effects="read_only",
            input_schema="schemas/P_acceptance_tests.input.json",
            output_schema="schemas/P_acceptance_tests.output.json",
            reference_vectors="reference_vectors/P_acceptance_tests.json",
            failure_level="major",
            soundness_class="other",
            implementation=None,
        ),
    ]


# Convenient module-level singleton so callers that want the default core
# set don't need to construct their own.
default_registry = Registry()
