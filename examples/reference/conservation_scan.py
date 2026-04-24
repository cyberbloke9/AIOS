"""
AIOS v5 — SK-CONSERVATION-SCAN reference implementation
======================================================

This is a reference implementation of the five conserved quantities
(Q1 Invariant Integrity, Q2 State Traceability, Q3 Decision Reversibility,
Q4 Verification Independence, Q5 Context Sufficiency).

It is *not* the production implementation. It is the executable
specification of what the production implementation must compute.
Every number in the AIOS v5 spec that claims to be a "conservation check"
must be traceable to a function here.

The purpose of shipping this alongside the spec is to eliminate the
failure mode Codex identified: governance prose that is only enforced
by interpretation rather than by predicates.

Usage:
    python conservation_scan.py --run-id <uuid>

Dependencies: standard library only.
"""

from __future__ import annotations

import dataclasses as dc
import hashlib
import json
from typing import Iterable, Literal


# ---------------------------------------------------------------------------
# Data classes: the minimum structure needed to compute Q1..Q5
# ---------------------------------------------------------------------------

Status = Literal["preserved", "breached"]


@dc.dataclass(frozen=True)
class Invariant:
    """A named invariant from principles, security policy, or an Accepted ADR."""
    id: str
    source: Literal["principle", "security", "adr", "interface"]
    statement: str  # normalized form; hashing uses this

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.id}:{self.source}:{self.statement}".encode()).hexdigest()


@dc.dataclass(frozen=True)
class ADREvent:
    adr_id: str
    status: Literal["Proposed", "Accepted", "Deprecated", "Superseded"]
    removes: frozenset[str]  # invariant ids this ADR legitimately removes
    deprecates: str | None = None


@dc.dataclass(frozen=True)
class Decision:
    decision_id: str
    rollback_cost: Literal["none", "low", "medium", "high", "irreversible"]
    irreversibility_adr_id: str | None  # must be present iff rollback_cost == "irreversible"


@dc.dataclass(frozen=True)
class VerificationSlice:
    """Which sources a verifier was allowed to see."""
    actor: str
    inputs_seen: frozenset[str]


@dc.dataclass(frozen=True)
class GenerationSlice:
    """Which sources the generator was allowed to see."""
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
    events: tuple[dict, ...]  # opaque records, each with sha256 field 'prev_event_hash' and 'hash'
    stored_projection_hash: str  # the hash the projection was stored with


@dc.dataclass
class RunState:
    """Everything the conservation scan needs about a single run."""
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
# Q1 — Invariant Integrity
# ---------------------------------------------------------------------------

def scan_q1_invariant_integrity(run: RunState) -> dict:
    """
    Conservation law:
        I(s) ⊆ I(s')  OR
        the difference I(s) \\ I(s') is the set of invariants legitimately
        removed by an Accepted ADR in the same run.
    """
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
# Q2 — State Traceability
# ---------------------------------------------------------------------------

def _chain_hash(events: Iterable[dict]) -> str:
    h = hashlib.sha256(b"")
    for e in events:
        h.update(json.dumps(e, sort_keys=True).encode())
    return h.hexdigest()


def scan_q2_state_traceability(run: RunState) -> dict:
    """
    Conservation law:
        hash(replay(events_up_to(t))) == stored_hash(projection(t))
    Any mismatch means either tampering or a projection bug.
    """
    computed = _chain_hash(run.event_log_range.events)
    ok = computed == run.event_log_range.stored_projection_hash
    return {
        "status": "preserved" if ok else "breached",
        "computed_hash": computed,
        "stored_hash": run.event_log_range.stored_projection_hash,
    }


# ---------------------------------------------------------------------------
# Q3 — Decision Reversibility
# ---------------------------------------------------------------------------

def scan_q3_decision_reversibility(run: RunState) -> dict:
    """
    Conservation law:
        No decision has rollback_cost == 'irreversible' UNLESS
        it carries an explicit irreversibility_adr_id.
    """
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
# Q4 — Verification Independence
# ---------------------------------------------------------------------------

def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def scan_q4_verification_independence(run: RunState, v_min: float = 0.5) -> dict:
    """
    Conservation law (for impact >= subsystem):
        V(artifact) = 1 - max_jaccard(generator_slice, verifier_slice) >= v_min

    Lower overlap = higher independence. Threshold v_min is [internal policy]
    per the AIOS v5 spec; initial value 0.5.
    """
    if run.impact == "local":
        return {
            "status": "preserved",
            "note": "Q4 does not apply to local-impact work",
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
# Q5 — Context Sufficiency
# ---------------------------------------------------------------------------

def scan_q5_context_sufficiency(run: RunState) -> dict:
    """
    Conservation law:
        All required invariants must be present in the loaded context.
        Tokens loaded must not exceed budget.
    """
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


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------

def conservation_scan(run: RunState, v_min: float = 0.5) -> dict:
    """Run all five scans and return a conservation_ledger record."""
    return {
        "run_id": run.run_id,
        "Q1_invariant_integrity": scan_q1_invariant_integrity(run),
        "Q2_state_traceability": scan_q2_state_traceability(run),
        "Q3_decision_reversibility": scan_q3_decision_reversibility(run),
        "Q4_verification_independence": scan_q4_verification_independence(run, v_min=v_min),
        "Q5_context_sufficiency": scan_q5_context_sufficiency(run),
    }


def any_breach(ledger: dict) -> bool:
    return any(
        v.get("status") == "breached"
        for k, v in ledger.items()
        if k.startswith("Q")
    )


# ---------------------------------------------------------------------------
# Minimal self-test so the file is runnable
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Construct a toy run: an invariant is removed, but the removal is
    # legitimately authorized by an Accepted ADR. Q1 should report preserved.
    inv_a = Invariant(id="INV-001", source="principle", statement="Interfaces are frozen.")
    inv_b = Invariant(id="INV-002", source="adr",       statement="Pricing is synchronous.")
    adr_remove_b = ADREvent(adr_id="ADR-0042", status="Accepted", removes=frozenset({"INV-002"}))

    events = (
        {"kind": "intention",   "ts": "t1"},
        {"kind": "validation",  "ts": "t2"},
        {"kind": "effect",      "ts": "t3"},
    )

    run = RunState(
        run_id="demo",
        invariants_before=frozenset({inv_a, inv_b}),
        invariants_after=frozenset({inv_a}),          # INV-002 gone, legitimately
        adr_events=(adr_remove_b,),
        decisions=(
            Decision(decision_id="D1", rollback_cost="low", irreversibility_adr_id=None),
            Decision(decision_id="D2", rollback_cost="medium", irreversibility_adr_id=None),
        ),
        generator_slices=(
            GenerationSlice(actor="A3", inputs_seen=frozenset({"spec", "principles", "pr_description"})),
        ),
        verifier_slices=(
            VerificationSlice(actor="A4", inputs_seen=frozenset({"diff", "principles", "adrs"})),
        ),
        context_load=ContextLoad(
            tokens_loaded=18_000,
            budget=32_000,
            invariants_loaded=frozenset({"INV-001"}),
            invariants_required=frozenset({"INV-001"}),
        ),
        event_log_range=EventLogRange(
            events=events,
            stored_projection_hash=_chain_hash(events),  # honest hash => Q2 preserved
        ),
        impact="subsystem",
    )

    ledger = conservation_scan(run)
    print(json.dumps(ledger, indent=2, sort_keys=True))
    if any_breach(ledger):
        raise SystemExit("Conservation breach detected; halting.")
    print("\nAll five conservation quantities preserved on the demo run.")
