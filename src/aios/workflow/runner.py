"""Workflow runner — Kernel Spec §2.2 run lifecycle (sprint 19).

    pending --[dispatch]--> running --[gate_sweep]--> verified --[apply]--> applied
                                |                          |                    |
                                +--[abort]--> aborted      +--[reject]--> rejected
                                                                               |
                                                                   +--[rollback]--> rolled_back

The runner:
  1. Emits `run.started` (actor=A1 Router).
  2. Evaluates each gate in manifest.required_gates via the registry.
     - Q1/Q2/Q3 breach -> immediately aborts the run (Kernel §2.2).
     - M4/O5 breach at the declared impact -> gate-level rejection.
     - Stub predicate (NotImplementedPredicateError) -> rejection
       (no silent pass).
  3. Emits a `gate.evaluated` frame per gate with its status.
  4. If all gates pass: `artifact.promoted` (actor=A5).
     Otherwise:    `artifact.rejected` (actor=A4).
  5. Returns a WorkflowResult summarizing outcome + per-gate verdict.

Impact handling: the runner overrides RunState.impact with
manifest.impact so the scan uses the declared level consistently.
"""
from __future__ import annotations

import dataclasses as dc
from typing import Literal

from aios.runtime.event_log import EventLog
from aios.verification.conservation_scan import RunState, any_breach
from aios.verification.registry import (
    NotImplementedPredicateError,
    Registry,
    default_registry,
)
from aios.workflow.manifest import WorkflowManifest

Outcome = Literal["promoted", "rejected", "aborted"]

# Soundness predicates: a breach halts the run (Kernel §2.2 direct abort).
_SOUNDNESS_PREDICATES = frozenset({
    "P_Q1_invariant_integrity",
    "P_Q2_state_traceability",
    "P_Q3_decision_reversibility",
})


@dc.dataclass(frozen=True)
class GateResult:
    predicate_id: str
    status: Literal["preserved", "breached", "not_implemented", "error"]
    detail: dict | str


@dc.dataclass(frozen=True)
class WorkflowResult:
    manifest_id: str
    outcome: Outcome
    gate_results: tuple[GateResult, ...]
    run_started_seq: int
    final_event_seq: int

    def summary(self) -> str:
        lines = [
            f"workflow: {self.manifest_id}",
            f"outcome:  {self.outcome.upper()}",
            f"frames:   seq {self.run_started_seq} .. {self.final_event_seq}",
            "",
        ]
        for g in self.gate_results:
            marker = {
                "preserved": "[ok]",
                "breached": "[BREACH]",
                "not_implemented": "[STUB]",
                "error": "[ERR]",
            }[g.status]
            lines.append(f"  {marker} {g.predicate_id}")
        return "\n".join(lines)


class WorkflowRunner:
    """Executes a WorkflowManifest against a RunState, emitting frames."""

    def __init__(self, registry: Registry | None = None):
        self._registry = registry if registry is not None else default_registry

    def run(self, manifest: WorkflowManifest, runstate: RunState,
            log: EventLog) -> WorkflowResult:
        # Harmonize impact: the manifest is authoritative.
        runstate = dc.replace(runstate, impact=manifest.impact)

        # 1. run.started
        started = log.append(
            kind="run.started",
            actor="A1",
            payload={
                "run_id": runstate.run_id,
                "workflow_id": manifest.id,
                "workflow_version": manifest.version,
                "impact": manifest.impact,
            },
        )

        gate_results: list[GateResult] = []
        soundness_breach: GateResult | None = None
        gate_failed: GateResult | None = None

        # 2-3. Evaluate each gate; emit a gate.evaluated frame per gate.
        for pid in manifest.required_gates:
            result = self._evaluate_gate(pid, runstate)
            gate_results.append(result)
            log.append(
                kind="gate.evaluated",
                actor="A4",
                payload={
                    "gate_id": pid,
                    "status": result.status,
                    "run_id": runstate.run_id,
                },
            )
            # Any soundness-predicate breach aborts (Kernel §2.2).
            if pid in _SOUNDNESS_PREDICATES and result.status == "breached":
                soundness_breach = result
                break
            if result.status in ("breached", "not_implemented", "error") \
                    and gate_failed is None:
                gate_failed = result

        # 4. Emit final verdict frame.
        if soundness_breach is not None:
            final = log.append(
                kind="run.aborted",
                actor="A1",
                payload={
                    "run_id": runstate.run_id,
                    "reason": "soundness_breach",
                    "breached_gate": soundness_breach.predicate_id,
                },
            )
            outcome: Outcome = "aborted"
        elif gate_failed is not None:
            final = log.append(
                kind="artifact.rejected",
                actor="A4",
                payload={
                    "run_id": runstate.run_id,
                    "workflow_id": manifest.id,
                    "failed_gate": gate_failed.predicate_id,
                    "status": gate_failed.status,
                },
            )
            outcome = "rejected"
        else:
            final = log.append(
                kind="artifact.promoted",
                actor="A5",
                payload={
                    "run_id": runstate.run_id,
                    "workflow_id": manifest.id,
                    "gates_passed": list(manifest.required_gates),
                },
            )
            outcome = "promoted"

        return WorkflowResult(
            manifest_id=manifest.id,
            outcome=outcome,
            gate_results=tuple(gate_results),
            run_started_seq=started.seq,
            final_event_seq=final.seq,
        )

    def _evaluate_gate(self, pid: str, runstate: RunState) -> GateResult:
        try:
            out = self._registry.evaluate(pid, runstate)
        except NotImplementedPredicateError as e:
            return GateResult(pid, "not_implemented", str(e))
        except Exception as e:  # noqa: BLE001 — genuinely unknown evaluator failure
            return GateResult(pid, "error", f"{type(e).__name__}: {e}")

        status = out.get("status") if isinstance(out, dict) else None
        if status == "preserved":
            return GateResult(pid, "preserved", out)
        if status == "breached":
            return GateResult(pid, "breached", out)
        return GateResult(pid, "error", f"malformed predicate output: {out!r}")
