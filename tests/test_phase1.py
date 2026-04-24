"""Tests for Phase 0 → Phase 1 transition (sprint 41)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.cli import main
from aios.runtime.init import init_aios_home
from aios.verification.backtest import BacktestReport
from aios.verification.credentials import CredentialLedger
from aios.verification.phase0 import AccuracyReport
from aios.verification.phase1 import (
    Phase1NotReadyError,
    check_phase1_readiness,
    enable_phase1,
)


def _good_accuracy(gate_id: str = "P_Q1_invariant_integrity") -> AccuracyReport:
    return AccuracyReport(
        gate_id=gate_id,
        failure_level="catastrophic",
        fp_rate=0.0,
        fn_rate=0.0,
        good_count=200,
        bad_count=100,
        fp_threshold=0.10,
        fn_threshold=0.10,
        passed_thresholds=True,
        insufficient_samples=False,
    )


def _bad_accuracy(gate_id: str = "P_Q1_invariant_integrity") -> AccuracyReport:
    return AccuracyReport(
        gate_id=gate_id,
        failure_level="catastrophic",
        fp_rate=0.30,
        fn_rate=0.25,
        good_count=200,
        bad_count=100,
        fp_threshold=0.10,
        fn_threshold=0.10,
        passed_thresholds=False,
        insufficient_samples=False,
    )


def _empty_backtest() -> BacktestReport:
    return BacktestReport(
        incident_count=30,
        caught_count=28,
        hit_rate=0.933,
        results=(),
    )


# check_phase1_readiness -------------------------------------------------


def test_ready_when_everything_passes():
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy()],
        backtest=_empty_backtest(),
        reference_vector_coverage={"P_Q1_invariant_integrity": 0.9},
        gate_set=["P_Q1_invariant_integrity"],
    )
    assert readiness.all_passed is True
    assert readiness.blockers == ()


def test_blocked_when_accuracy_fails():
    readiness = check_phase1_readiness(
        gate_accuracy=[_bad_accuracy()],
        backtest=_empty_backtest(),
    )
    assert readiness.all_passed is False
    assert any("P_Q1" in b for b in readiness.blockers)


def test_blocked_when_insufficient_samples():
    low_samples = AccuracyReport(
        gate_id="P_Q2_state_traceability",
        failure_level="catastrophic",
        fp_rate=0.0, fn_rate=0.0,
        good_count=50, bad_count=20,
        fp_threshold=0.10, fn_threshold=0.10,
        passed_thresholds=False,
        insufficient_samples=True,
    )
    readiness = check_phase1_readiness(
        gate_accuracy=[low_samples],
        backtest=_empty_backtest(),
    )
    assert not readiness.all_passed
    assert any("known-good cases" in b for b in readiness.blockers)


def test_blocked_when_no_backtest():
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy()],
        backtest=None,
    )
    assert not readiness.all_passed
    assert any("backtest" in b.lower() for b in readiness.blockers)


def test_blocked_on_missing_coverage_entry():
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy()],
        backtest=_empty_backtest(),
        reference_vector_coverage={},   # empty
        gate_set=["P_Q1_invariant_integrity"],
    )
    assert not readiness.all_passed
    assert any("reference-vector" in b for b in readiness.blockers)


def test_blocked_on_low_coverage():
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy()],
        backtest=_empty_backtest(),
        reference_vector_coverage={"P_Q1_invariant_integrity": 0.5},
        gate_set=["P_Q1_invariant_integrity"],
    )
    assert not readiness.all_passed


def test_blocked_when_declared_gate_missing_accuracy_report():
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy("P_Q1_invariant_integrity")],
        backtest=_empty_backtest(),
        reference_vector_coverage={
            "P_Q1_invariant_integrity": 0.9,
            "P_Q2_state_traceability": 0.9,
        },
        gate_set=["P_Q1_invariant_integrity", "P_Q2_state_traceability"],
    )
    assert not readiness.all_passed
    assert any("P_Q2" in b for b in readiness.blockers)


# enable_phase1 ----------------------------------------------------------


def test_enable_phase1_flips_all_credentials(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("A4")
    ledger.seed("SK-ADR-CHECK")
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy()],
        backtest=_empty_backtest(),
    )
    transitioned = enable_phase1(
        ledger, readiness,
        a4_signer="human-alice",
        a5_signer="human-bob",
    )
    assert set(transitioned) == {"A4", "SK-ADR-CHECK"}
    assert ledger.get("A4").phase == 1
    assert ledger.get("SK-ADR-CHECK").phase == 1


def test_enable_phase1_refuses_when_not_ready(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("A4")
    readiness = check_phase1_readiness(
        gate_accuracy=[_bad_accuracy()],
        backtest=_empty_backtest(),
    )
    with pytest.raises(Phase1NotReadyError, match="blockers"):
        enable_phase1(ledger, readiness,
                      a4_signer="a", a5_signer="b")


def test_enable_phase1_refuses_missing_signer(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy()],
        backtest=_empty_backtest(),
    )
    with pytest.raises(Phase1NotReadyError, match="A4"):
        enable_phase1(ledger, readiness, a4_signer="", a5_signer="b")
    with pytest.raises(Phase1NotReadyError, match="A5"):
        enable_phase1(ledger, readiness, a4_signer="a", a5_signer="")


def test_enable_phase1_idempotent_on_already_phase1(tmp_path: Path):
    """Running enable_phase1 twice only transitions phase=0 credentials."""
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("A4")
    readiness = check_phase1_readiness(
        gate_accuracy=[_good_accuracy()],
        backtest=_empty_backtest(),
    )
    first = enable_phase1(ledger, readiness, a4_signer="a", a5_signer="b")
    assert "A4" in first
    second = enable_phase1(ledger, readiness, a4_signer="a", a5_signer="b")
    assert second == []


# CLI --------------------------------------------------------------------


def test_cli_credential_seed_then_status(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    capsys.readouterr()
    rc = main(["credential-seed", "A4", "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "A4" in out

    rc = main(["credential-status", "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "A4" in out
    assert "0.500" in out  # seed standing


def test_cli_credential_status_empty_ledger(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    capsys.readouterr()
    rc = main(["credential-status", "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "no credentials" in out


def test_cli_credential_seed_duplicate_returns_1(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    main(["credential-seed", "A4", "--home", str(home)])
    capsys.readouterr()
    rc = main(["credential-seed", "A4", "--home", str(home)])
    assert rc == 1
