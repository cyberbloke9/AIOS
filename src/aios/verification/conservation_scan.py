"""Conservation scan — package version (sprint 2b).

Ports the v5 reference in examples/reference/conservation_scan.py into the
AIOS v7 Constitution / v8 spec nomenclature:

  Q1, Q2, Q3 are the three Conservation Laws (Constitution Article I).
  M4 (formerly Q4) is the Independence Metric (Constitution §2.1) — a
       governance metric, NOT a conservation law.
  O5 (formerly Q5) is the Context Control Objective (Constitution §2.2) —
       its hard constraint (all required invariants present; within
       budget) is enforced as a T1 predicate per Verification Spec §1.2
       (P_O5_context_sufficiency_hard).

Public scan functions use the M4/O5 names. The v5 `scan_q4_*` / `scan_q5_*`
names are retained as aliases so the reference tests continue to pass
unchanged. Computations are identical to the reference.

Reference-vector compatibility: the ledger dict returned by
`conservation_scan` emits keys under BOTH nomenclatures for the
non-soundness metrics:

  Q1_invariant_integrity
  Q2_state_traceability
  Q3_decision_reversibility
  M4_independence            (== Q4_verification_independence)
  O5_context_sufficiency     (== Q5_context_sufficiency)

This lets pre-v7 code using Q4/Q5 keys, and Verification-Spec-aware code
using M4/O5 keys, both read the same ledger.
"""
from __future__ import annotations

import dataclasses as dc
import hashlib
import json
from typing import Iterable, Literal

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

Status = Literal["preserved", "breached"]


@dc.dataclass(frozen=True)
class Invariant:
    id: str
    source: Literal["principle", "security", "adr", "interface"]
    statement: str

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.id}:{self.source}:{self.statement}".encode()).hexdigest()


@dc.dataclass(frozen=True)
class ADREvent:
    adr_id: str
    status: Literal["Proposed", "Accepted", "Deprecated", "Superseded"]
    removes: frozenset[str]
    deprecates: str | None = None


@dc.dataclass(frozen=True)
class Decision:
    decision_id: str
    rollback_cost: Literal["none", "low", "medium", "high", "irreversible"]
    irreversibility_adr_id: str | None


@dc.dataclass(frozen=True)
class VerificationSlice:
    actor: str
    inputs_seen: frozenset[str]


@dc.dataclass(frozen=True)
class GenerationSlice:
    actor: str
    inputs_seen: frozenset[str]


@dc.dataclass(frozen=True)
class ContextLoad:
    tokens_loaded: int
    budget: int
    invariants_loaded: frozenset[str]
    invariants_required: frozenset[str]


@dc.dataclass(frozen=True)
class EventLogRange:
    events: tuple[dict, ...]
    stored_projection_hash: str


@dc.dataclass
class RunState:
    run_id: str
    invariants_before: frozenset[Invariant]
    invariants_after: frozenset[Invariant]
    adr_events: tuple[ADREvent, ...]
    decisions: tuple[Decision, ...]
    generator_slices: tuple[GenerationSlice, ...]
    verifier_slices: tuple[VerificationSlice, ...]
    context_load: ContextLoad
    event_log_range: EventLogRange
    impact: Literal["local", "subsystem", "system_wide"]


# ---------------------------------------------------------------------------
# Q1 — Invariant Integrity (Constitution §1.1)
# ---------------------------------------------------------------------------


def scan_q1_invariant_integrity(run: RunState) -> dict:
    ids_before = {i.id for i in run.invariants_before}
    ids_after = {i.id for i in run.invariants_after}
    disappeared = ids_before - ids_after

    legitimately_removed: set[str] = set()
    for adr in run.adr_events:
        if adr.status == "Accepted":
            legitimately_removed |= set(adr.removes)

    illegitimate = disappeared - legitimately_removed

    return {
        "status": "preserved" if not illegitimate else "breached",
        "disappeared": sorted(disappeared),
        "legitimately_removed": sorted(legitimately_removed),
        "illegitimate_removals": sorted(illegitimate),
    }


# ---------------------------------------------------------------------------
# Q2 — State Traceability (Constitution §1.2)
# ---------------------------------------------------------------------------


def _chain_hash(events: Iterable[dict]) -> str:
    h = hashlib.sha256(b"")
    for e in events:
        h.update(json.dumps(e, sort_keys=True).encode())
    return h.hexdigest()


def scan_q2_state_traceability(run: RunState) -> dict:
    computed = _chain_hash(run.event_log_range.events)
    ok = computed == run.event_log_range.stored_projection_hash
    return {
        "status": "preserved" if ok else "breached",
        "computed_hash": computed,
        "stored_hash": run.event_log_range.stored_projection_hash,
    }


# ---------------------------------------------------------------------------
# Q3 — Decision Reversibility (Constitution §1.3)
# ---------------------------------------------------------------------------


def scan_q3_decision_reversibility(run: RunState) -> dict:
    accidental_irreversibles = [
        d.decision_id
        for d in run.decisions
        if d.rollback_cost == "irreversible" and not d.irreversibility_adr_id
    ]
    return {
        "status": "preserved" if not accidental_irreversibles else "breached",
        "accidental_irreversibles": accidental_irreversibles,
        "total_decisions": len(run.decisions),
    }


# ---------------------------------------------------------------------------
# M4 — Independence Metric (Constitution §2.1) — governance metric only.
# "preserved" / "breached" here means: independence threshold met / not met.
# A breach here is NOT a soundness breach (Q1-Q3 are the only soundness laws).
# ---------------------------------------------------------------------------


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def scan_m4_independence(run: RunState, v_min: float = 0.5) -> dict:
    if run.impact == "local":
        return {
            "status": "preserved",
            "note": "M4 does not apply to local-impact work",
            "V": None,
        }

    if not run.generator_slices or not run.verifier_slices:
        return {
            "status": "breached",
            "reason": "missing generator or verifier slice metadata",
        }

    max_overlap = max(
        jaccard(g.inputs_seen, v.inputs_seen)
        for g in run.generator_slices
        for v in run.verifier_slices
    )
    V = 1.0 - max_overlap
    return {
        "status": "preserved" if V >= v_min else "breached",
        "V": round(V, 3),
        "v_min": v_min,
        "max_overlap": round(max_overlap, 3),
    }


# ---------------------------------------------------------------------------
# O5 — Context Control Objective hard constraint (Constitution §2.2)
# ---------------------------------------------------------------------------


def scan_o5_context_sufficiency_hard(run: RunState) -> dict:
    missing = run.context_load.invariants_required - run.context_load.invariants_loaded
    over_budget = run.context_load.tokens_loaded > run.context_load.budget
    ok = not missing and not over_budget
    return {
        "status": "preserved" if ok else "breached",
        "missing_invariants": sorted(missing),
        "over_budget": over_budget,
        "tokens_loaded": run.context_load.tokens_loaded,
        "budget": run.context_load.budget,
    }


# Back-compat aliases (v5 nomenclature). Do not remove — the reference
# tests in examples/reference/test_conservation_scan.py still import these.

scan_q4_verification_independence = scan_m4_independence
scan_q5_context_sufficiency = scan_o5_context_sufficiency_hard


# ---------------------------------------------------------------------------
# Top-level scan — ledger carries BOTH Q4/M4 and Q5/O5 keys for compat.
# ---------------------------------------------------------------------------


def conservation_scan(run: RunState, v_min: float = 0.5) -> dict:
    m4 = scan_m4_independence(run, v_min=v_min)
    o5 = scan_o5_context_sufficiency_hard(run)
    return {
        "run_id": run.run_id,
        "Q1_invariant_integrity": scan_q1_invariant_integrity(run),
        "Q2_state_traceability": scan_q2_state_traceability(run),
        "Q3_decision_reversibility": scan_q3_decision_reversibility(run),
        "M4_independence": m4,
        "Q4_verification_independence": m4,
        "O5_context_sufficiency": o5,
        "Q5_context_sufficiency": o5,
    }


def any_breach(ledger: dict) -> bool:
    """Return True if any of Q1/Q2/Q3 is breached.

    M4 and O5 have status fields too, but they are governance metrics;
    breach of those is reported but does NOT halt a run the way Q1-Q3
    breaches do. Per Constitution §1.1-§1.3 vs §2.1-§2.2.
    """
    for key in ("Q1_invariant_integrity", "Q2_state_traceability",
                "Q3_decision_reversibility"):
        if ledger.get(key, {}).get("status") == "breached":
            return True
    return False


def any_soundness_or_governance_breach(ledger: dict) -> bool:
    """Broader check: any of Q1/Q2/Q3/M4/O5 breached."""
    for key in ("Q1_invariant_integrity", "Q2_state_traceability",
                "Q3_decision_reversibility", "M4_independence",
                "O5_context_sufficiency"):
        if ledger.get(key, {}).get("status") == "breached":
            return True
    return False


if __name__ == "__main__":
    # Demo parallel to the reference: one invariant legitimately removed by
    # an Accepted ADR; Q1 preserved; all five scans green.
    inv_a = Invariant(id="INV-001", source="principle", statement="Interfaces are frozen.")
    inv_b = Invariant(id="INV-002", source="adr", statement="Pricing is synchronous.")
    adr_remove_b = ADREvent(adr_id="ADR-0042", status="Accepted", removes=frozenset({"INV-002"}))
    events = (
        {"kind": "intention", "ts": "t1"},
        {"kind": "validation", "ts": "t2"},
        {"kind": "effect", "ts": "t3"},
    )
    run = RunState(
        run_id="demo",
        invariants_before=frozenset({inv_a, inv_b}),
        invariants_after=frozenset({inv_a}),
        adr_events=(adr_remove_b,),
        decisions=(Decision(decision_id="D1", rollback_cost="low", irreversibility_adr_id=None),),
        generator_slices=(GenerationSlice(actor="A3", inputs_seen=frozenset({"spec"})),),
        verifier_slices=(VerificationSlice(actor="A4", inputs_seen=frozenset({"adrs"})),),
        context_load=ContextLoad(
            tokens_loaded=18_000, budget=32_000,
            invariants_loaded=frozenset({"INV-001"}),
            invariants_required=frozenset({"INV-001"}),
        ),
        event_log_range=EventLogRange(events=events, stored_projection_hash=_chain_hash(events)),
        impact="subsystem",
    )
    ledger = conservation_scan(run)
    print(json.dumps(ledger, indent=2, sort_keys=True))
    if any_breach(ledger):
        raise SystemExit("Conservation breach detected; halting.")
    print("\nQ1-Q3 preserved on demo run; M4 and O5 reported.")
