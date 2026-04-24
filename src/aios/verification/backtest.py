"""Contamination audit + incident backtesting (sprint 40).

Two of the §3.1 Phase-0 prerequisites:

  Benchmark contamination audit
    For every benchmark used in any T2 gate, audit for overlap with
    training data. Audit must be SIGNED. Overlap <= 0.05 OR an explicit
    contamination-tolerant evaluation declaration.

  Incident backtesting
    Take the last 30 production incidents; replay against the gate set;
    measure gate hit rate (caught vs. missed). Hit rate published;
    no hard threshold — but the number is needed before credentialing.

Both are prerequisites, not gates. They produce reports; sprint 41's
transition-to-Phase-1 function is what refuses to fire if any report
fails its bar.
"""
from __future__ import annotations

import dataclasses as dc
from typing import Literal

from aios.verification.conservation_scan import RunState
from aios.verification.registry import (
    NotImplementedPredicateError,
    Registry,
    default_registry,
)

_CONTAMINATION_THRESHOLD = 0.05


class ContaminationAuditError(ValueError):
    """Contamination audit is malformed (unsigned, missing fields)."""


# ---------------------------------------------------------------------------
# Contamination audit
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class ContaminationAudit:
    benchmark_id: str
    benchmark_sample_hashes: frozenset[str]    # hashes of eval data
    training_sample_hashes: frozenset[str]     # hashes claimed to be in training
    method: str                                # "sha256-exact" | "fuzzy-dedup" | ...
    last_run_iso: str
    signer: str                                # non-empty; A4/A5 identity
    contamination_tolerant: bool = False       # §3.1 escape-hatch declaration

    @property
    def overlap(self) -> float:
        """Fraction of benchmark samples that also appear in training."""
        if not self.benchmark_sample_hashes:
            return 0.0
        intersect = self.benchmark_sample_hashes & self.training_sample_hashes
        return len(intersect) / len(self.benchmark_sample_hashes)


@dc.dataclass(frozen=True)
class ContaminationReport:
    benchmark_id: str
    overlap: float
    threshold: float
    passed: bool
    contamination_tolerant_declared: bool
    signer: str


def contamination_audit(audit: ContaminationAudit) -> ContaminationReport:
    """Evaluate an audit against §3.1's overlap threshold."""
    if not audit.signer or not audit.signer.strip():
        raise ContaminationAuditError(
            "audit.signer is empty; §3.1 requires a signed audit "
            "(attach the auditing authority, e.g. 'A4-<name>')"
        )

    overlap = audit.overlap
    passed = (overlap <= _CONTAMINATION_THRESHOLD) or audit.contamination_tolerant
    return ContaminationReport(
        benchmark_id=audit.benchmark_id,
        overlap=overlap,
        threshold=_CONTAMINATION_THRESHOLD,
        passed=passed,
        contamination_tolerant_declared=audit.contamination_tolerant,
        signer=audit.signer,
    )


# ---------------------------------------------------------------------------
# Incident backtesting
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class Incident:
    incident_id: str
    run_state: RunState
    # Gate IDs that SHOULD have caught the incident. At least one must
    # breach on replay for the incident to be counted as "caught".
    expected_breach_gates: tuple[str, ...]
    summary: str = ""


@dc.dataclass(frozen=True)
class IncidentResult:
    incident_id: str
    caught: bool
    breached_gates: tuple[str, ...]     # which expected gates actually fired
    expected: tuple[str, ...]


@dc.dataclass(frozen=True)
class BacktestReport:
    incident_count: int
    caught_count: int
    hit_rate: float
    results: tuple[IncidentResult, ...]

    @property
    def missed_incident_ids(self) -> tuple[str, ...]:
        return tuple(r.incident_id for r in self.results if not r.caught)


def incident_backtest(
    incidents: list[Incident],
    *,
    registry: Registry | None = None,
) -> BacktestReport:
    """Replay incidents against the registry; report per-incident hit rate.

    §3.1 requires the rate to be published — it does NOT name a minimum
    threshold. The returned BacktestReport holds the number the Phase 0 →
    Phase 1 transition event carries into its payload.
    """
    reg = registry if registry is not None else default_registry

    results: list[IncidentResult] = []
    for incident in incidents:
        breached: list[str] = []
        for gate_id in incident.expected_breach_gates:
            if _gate_breached(reg, gate_id, incident.run_state):
                breached.append(gate_id)
        results.append(IncidentResult(
            incident_id=incident.incident_id,
            caught=bool(breached),
            breached_gates=tuple(breached),
            expected=incident.expected_breach_gates,
        ))

    caught = sum(1 for r in results if r.caught)
    total = len(results)
    rate = caught / total if total else 0.0
    return BacktestReport(
        incident_count=total,
        caught_count=caught,
        hit_rate=rate,
        results=tuple(results),
    )


def _gate_breached(reg: Registry, gate_id: str, run: RunState) -> bool:
    try:
        out = reg.evaluate(gate_id, run)
    except NotImplementedPredicateError:
        return False
    except Exception:
        return False
    if not isinstance(out, dict):
        return False
    return out.get("status") == "breached"
