"""Tests for Phase 1 update rule + capability mapping (sprint 42)."""
from __future__ import annotations

import dataclasses as dc
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aios.runtime.init import init_aios_home
from aios.verification.credentials import (
    BandStanding,
    CredentialLedger,
    CredentialRecord,
)
from aios.verification.phase1_update import (
    DEFAULT_ALPHA, DEFAULT_BETA, DEFAULT_GAMMA, DEFAULT_DELTA, DEFAULT_EPSILON,
    RunOutcome,
    apply_run_outcome,
    capability_for_band,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _phase1_ledger(tmp_path: Path, entity: str = "A4") -> CredentialLedger:
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed(entity)
    # Flip to phase=1 directly for unit testing
    rec = ledger.get(entity)
    ledger.put(dc.replace(rec, phase=1))
    return ledger


# §3.4 band -> capability ------------------------------------------------


def test_capability_ranges_match_spec():
    assert capability_for_band(0.0) == "quarantined"
    assert capability_for_band(0.29) == "quarantined"
    assert capability_for_band(0.30) == "supervised"
    assert capability_for_band(0.59) == "supervised"
    assert capability_for_band(0.60) == "standard"
    assert capability_for_band(0.89) == "standard"
    assert capability_for_band(0.90) == "sole_verifier"
    assert capability_for_band(1.00) == "sole_verifier"


# §3.3 update rule -------------------------------------------------------


def test_clean_run_adds_alpha(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="clean", band="local"),
    )
    assert rec.band("local").standing == pytest.approx(0.5 + DEFAULT_ALPHA)
    assert rec.band("local").runs == 1


def test_gate_failure_subtracts_beta(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="gate_failure", band="local"),
    )
    assert rec.band("local").standing == pytest.approx(0.5 - DEFAULT_BETA)
    assert rec.band("local").breaches == 0  # gate failure != breach


def test_conservation_breach_subtracts_gamma(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="conservation_breach", band="local"),
    )
    assert rec.band("local").standing == pytest.approx(0.5 - DEFAULT_GAMMA)
    assert rec.band("local").breaches == 1
    assert rec.band("local").last_breach_iso is not None


def test_contained_recurrence_adds_delta(tmp_path: Path):
    """Apply delta on `local` band — the monotone constraint would
    otherwise clamp subsystem/system_wide to local's standing."""
    ledger = _phase1_ledger(tmp_path)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="contained_recurrence", band="local"),
    )
    assert rec.band("local").standing == pytest.approx(0.5 + DEFAULT_DELTA)


def test_recurrence_subtracts_epsilon(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="recurrence", band="local", error_class="D1"),
    )
    # no prior breach -> doesn't enter restitution, just subtracts epsilon
    assert rec.band("local").standing == pytest.approx(0.5 - DEFAULT_EPSILON)


# Monotone-bands constraint ---------------------------------------------


def test_subsystem_standing_clamped_to_local(tmp_path: Path):
    """standing(subsystem) <= standing(local) — §3.3 constraint."""
    ledger = _phase1_ledger(tmp_path)
    # Drive local down below seeded subsystem standing
    rec = ledger.get("A4")
    rec = rec.with_band("local", BandStanding(standing=0.3))
    ledger.put(rec)
    # Now a clean run on subsystem would push it above 0.3 if not clamped
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="contained_recurrence", band="subsystem"),
    )
    assert rec.band("subsystem").standing <= rec.band("local").standing


def test_system_wide_clamped_to_subsystem(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    rec = ledger.get("A4")
    rec = rec.with_band("subsystem", BandStanding(standing=0.4))
    ledger.put(rec)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="contained_recurrence", band="system_wide"),
    )
    assert rec.band("system_wide").standing <= rec.band("subsystem").standing


# Phase 0 doesn't move standing ------------------------------------------


def test_phase0_accumulates_runs_without_moving_standing(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("pending")   # phase=0 by default
    # Even a breach in phase 0 should not move standing
    rec = apply_run_outcome(
        ledger, "pending",
        RunOutcome(outcome="conservation_breach", band="local"),
    )
    assert rec.band("local").standing == 0.5    # unchanged
    assert rec.band("local").runs == 1
    assert rec.band("local").breaches == 0


# §3.5 restitution -------------------------------------------------------


def test_recurrence_within_90_days_enters_restitution(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    rec = ledger.get("A4")
    # Plant a prior breach 30 days ago on the local band
    b = rec.band("local")
    rec = rec.with_band("local", dc.replace(
        b, breaches=1, last_breach_iso=_iso_days_ago(30),
    ))
    ledger.put(rec)

    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="recurrence", band="local",
                   error_class="D1", ts_iso=_iso_now()),
    )
    assert rec.restitution_budget is not None
    assert rec.restitution_budget.remaining == 10
    assert rec.restitution_budget.error_class == "D1"


def test_recurrence_beyond_90_days_does_not_enter_restitution(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    rec = ledger.get("A4")
    b = rec.band("local")
    rec = rec.with_band("local", dc.replace(
        b, breaches=1, last_breach_iso=_iso_days_ago(120),
    ))
    ledger.put(rec)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="recurrence", band="local",
                   error_class="D1", ts_iso=_iso_now()),
    )
    assert rec.restitution_budget is None   # no restitution entered


def test_restitution_clean_runs_decrement_budget(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    # Enter restitution by planting the state directly
    rec = ledger.get("A4")
    from aios.verification.credentials import RestitutionBudget
    rec = dc.replace(rec, restitution_budget=RestitutionBudget(
        remaining=3, error_class="D1",
    ))
    ledger.put(rec)

    for expected_remaining in (2, 1):
        rec = apply_run_outcome(
            ledger, "A4",
            RunOutcome(outcome="clean", band="local", error_class="D1"),
        )
        assert rec.restitution_budget is not None
        assert rec.restitution_budget.remaining == expected_remaining

    # Final clean run zeroes the budget and exits restitution
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="clean", band="local", error_class="D1"),
    )
    assert rec.restitution_budget is None


def test_restitution_recurrence_doubles_budget(tmp_path: Path):
    ledger = _phase1_ledger(tmp_path)
    from aios.verification.credentials import RestitutionBudget
    rec = ledger.get("A4")
    rec = dc.replace(rec, restitution_budget=RestitutionBudget(
        remaining=10, error_class="D1",
    ))
    ledger.put(rec)

    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="recurrence", band="local", error_class="D1"),
    )
    assert rec.restitution_budget.remaining == 20


def test_restitution_freezes_standing(tmp_path: Path):
    """While in restitution, standing does not move on clean runs —
    only the budget does."""
    ledger = _phase1_ledger(tmp_path)
    from aios.verification.credentials import RestitutionBudget
    rec = ledger.get("A4")
    rec = dc.replace(rec, restitution_budget=RestitutionBudget(
        remaining=5, error_class="D1",
    ))
    ledger.put(rec)
    standing_before = rec.band("local").standing

    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="clean", band="local", error_class="D1"),
    )
    assert rec.band("local").standing == standing_before   # frozen


def test_different_error_class_skips_restitution_gate(tmp_path: Path):
    """An outcome with a different error class should apply normally."""
    ledger = _phase1_ledger(tmp_path)
    from aios.verification.credentials import RestitutionBudget
    rec = ledger.get("A4")
    rec = dc.replace(rec, restitution_budget=RestitutionBudget(
        remaining=5, error_class="D1",
    ))
    ledger.put(rec)
    rec = apply_run_outcome(
        ledger, "A4",
        RunOutcome(outcome="clean", band="local", error_class="D2"),
    )
    # D2 is unrelated -> standing should bump and budget untouched
    assert rec.band("local").standing == pytest.approx(0.5 + DEFAULT_ALPHA)
    assert rec.restitution_budget.remaining == 5
