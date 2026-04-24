"""Phase 1 credential update rule + band capability mapping (sprint 42).

Verification Spec §3.3 update rule:

    Δstanding(band) =
        +α   on a clean green run at the declared impact level
        -β   on a gate failure at the declared impact level
        -γ   on a Q1/Q2/Q3 breach          (γ >> β >> α by design)
        +δ   on contributing to containment of a contained error
        -ε   on recurrence of a previously-contained error class
    constraints:
        standing ∈ [0.0, 1.0]
        standing(system_wide) ≤ standing(subsystem) ≤ standing(local)

Default weights (§3.3 "internal policy"): α=0.01, β=0.05, γ=0.20,
δ=0.02, ε=0.10.

§3.4 band standing → capability mapping:

    < 0.3    quarantined     — not primary author; not verifier
    0.3-0.6  supervised      — verifier must be >= 0.75 for this band
    0.6-0.9  standard        — full authority
    >= 0.9   sole_verifier   — may verify alone

§3.5 restitution on recurrence within 90 days:
    enter restitution -> restitution_budget.remaining = 10
    each clean run decrements the budget
    standing is FROZEN until the budget reaches zero
    recurrence while in restitution: budget doubles + audit event

Phase-0 credentials are untouched by apply_run_outcome — data accumulates
(runs increment) but standing does NOT move. This matches §3.1's
"accumulating" state and the spec's anti-premature-credentialing rule.
"""
from __future__ import annotations

import dataclasses as dc
from datetime import datetime, timedelta, timezone
from typing import Literal

from aios.verification.credentials import (
    Band,
    BandStanding,
    CredentialLedger,
    CredentialRecord,
    RestitutionBudget,
)

Outcome = Literal[
    "clean",                     # +α (or budget decrement in restitution)
    "gate_failure",              # -β
    "conservation_breach",       # -γ
    "contained_recurrence",      # +δ — contributed to containment
    "recurrence",                # -ε — recurrence of contained error
]

Capability = Literal["quarantined", "supervised", "standard", "sole_verifier"]


# §3.3 default weights
DEFAULT_ALPHA = 0.01
DEFAULT_BETA = 0.05
DEFAULT_GAMMA = 0.20
DEFAULT_DELTA = 0.02
DEFAULT_EPSILON = 0.10

# §3.5 restitution policy
_RESTITUTION_WINDOW = timedelta(days=90)
_RESTITUTION_BUDGET_INITIAL = 10


# ---------------------------------------------------------------------------
# §3.4 band -> capability mapping
# ---------------------------------------------------------------------------


def capability_for_band(standing: float) -> Capability:
    if standing < 0.3:
        return "quarantined"
    if standing < 0.6:
        return "supervised"
    if standing < 0.9:
        return "standard"
    return "sole_verifier"


# ---------------------------------------------------------------------------
# §3.3 update rule
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class RunOutcome:
    outcome: Outcome
    band: Band
    error_class: str | None = None    # required for recurrence / containment
    ts_iso: str | None = None


def apply_run_outcome(
    ledger: CredentialLedger,
    entity_id: str,
    run: RunOutcome,
    *,
    alpha: float = DEFAULT_ALPHA,
    beta: float = DEFAULT_BETA,
    gamma: float = DEFAULT_GAMMA,
    delta: float = DEFAULT_DELTA,
    epsilon: float = DEFAULT_EPSILON,
) -> CredentialRecord:
    """Apply a run outcome to `entity_id`'s credential and persist it.

    Returns the updated CredentialRecord. Phase-0 credentials have
    standing untouched — §3.1 anti-premature-credentialing rule.
    """
    rec = ledger.get(entity_id)
    now_iso = run.ts_iso or _iso_now()

    # In-restitution logic — standing frozen, budget mutates.
    if rec.restitution_budget and _in_restitution_window(rec, run):
        if run.outcome == "clean":
            # decrement budget; exit restitution when it reaches zero
            remaining = rec.restitution_budget.remaining - 1
            if remaining <= 0:
                rec = dc.replace(rec, restitution_budget=None)
            else:
                rec = dc.replace(
                    rec,
                    restitution_budget=RestitutionBudget(
                        remaining=remaining,
                        error_class=rec.restitution_budget.error_class,
                    ),
                )
            ledger.put(rec)
            return rec
        if run.outcome == "recurrence":
            # Double the budget — §3.5
            rec = dc.replace(
                rec,
                restitution_budget=RestitutionBudget(
                    remaining=rec.restitution_budget.remaining * 2,
                    error_class=rec.restitution_budget.error_class,
                ),
            )
            ledger.put(rec)
            return rec
        # Other outcomes don't touch budget in restitution
        ledger.put(rec)
        return rec

    # Phase 0: accumulate observational runs but leave standing alone.
    if rec.phase == 0:
        rec = _bump_runs_only(rec, run.band)
        ledger.put(rec)
        return rec

    # Phase 1 enforcement — apply the §3.3 weight.
    band_state = rec.band(run.band)

    if run.outcome == "clean":
        band_state = band_state.with_clean_run(alpha)
    elif run.outcome == "gate_failure":
        band_state = band_state.with_gate_fail(beta)
    elif run.outcome == "conservation_breach":
        band_state = band_state.with_breach(gamma, now_iso)
    elif run.outcome == "contained_recurrence":
        band_state = band_state.with_clean_run(delta)
    elif run.outcome == "recurrence":
        band_state = band_state.with_gate_fail(epsilon)
        # If a previous breach of the same class occurred within the
        # §3.5 window, enter restitution.
        if _should_enter_restitution(rec, run, band_state):
            rec = dc.replace(
                rec.with_band(run.band, band_state),
                restitution_budget=RestitutionBudget(
                    remaining=_RESTITUTION_BUDGET_INITIAL,
                    error_class=run.error_class or "unknown",
                ),
            )
            rec = _enforce_monotone_bands(rec)
            ledger.put(rec)
            return rec
    else:  # pragma: no cover - typing covers this
        raise ValueError(f"unknown outcome {run.outcome!r}")

    rec = rec.with_band(run.band, band_state)
    rec = _enforce_monotone_bands(rec)
    ledger.put(rec)
    return rec


def _enforce_monotone_bands(rec: CredentialRecord) -> CredentialRecord:
    """§3.3 constraint: standing(system_wide) <= standing(subsystem) <= standing(local).

    If higher-impact bands are ABOVE lower-impact bands, clamp them
    down to the lower-impact standing (you cannot trust a wider blast
    radius more than you trust the narrow one).
    """
    bands = dict(rec.competency_bands)
    if bands["subsystem"].standing > bands["local"].standing:
        bands["subsystem"] = dc.replace(
            bands["subsystem"], standing=bands["local"].standing,
        )
    if bands["system_wide"].standing > bands["subsystem"].standing:
        bands["system_wide"] = dc.replace(
            bands["system_wide"], standing=bands["subsystem"].standing,
        )
    return dc.replace(rec, competency_bands=bands)


def _bump_runs_only(rec: CredentialRecord, band: Band) -> CredentialRecord:
    b = rec.band(band)
    return rec.with_band(band, dc.replace(b, runs=b.runs + 1))


def _in_restitution_window(rec: CredentialRecord, run: RunOutcome) -> bool:
    if rec.restitution_budget is None:
        return False
    # A different error class outside restitution does not pause the budget
    if run.error_class and run.error_class != rec.restitution_budget.error_class:
        return False
    return True


def _should_enter_restitution(
    rec: CredentialRecord, run: RunOutcome, new_band: BandStanding
) -> bool:
    """§3.5: enter restitution when an error class recurs within 90 days."""
    if run.error_class is None:
        return False
    prev = rec.band(run.band)
    if prev.last_breach_iso is None:
        return False
    try:
        last = _parse_iso(prev.last_breach_iso)
    except ValueError:
        return False
    now = _parse_iso(run.ts_iso or _iso_now())
    return (now - last) <= _RESTITUTION_WINDOW


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)
