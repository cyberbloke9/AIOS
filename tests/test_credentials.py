"""Tests for credential ledger + record schema (sprint 38)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.runtime.init import init_aios_home
from aios.verification.credentials import (
    BandStanding,
    CredentialError,
    CredentialLedger,
    CredentialRecord,
    RestitutionBudget,
    seed_credential,
)


# Record shape -----------------------------------------------------------


def test_seed_credential_is_phase_0_with_0_5():
    rec = seed_credential("A4-demo")
    assert rec.entity_id == "A4-demo"
    assert rec.phase == 0
    assert set(rec.competency_bands) == {"local", "subsystem", "system_wide"}
    for band in rec.competency_bands.values():
        assert band.standing == 0.5
        assert band.runs == 0
        assert band.breaches == 0


def test_record_standing_is_min_across_bands():
    rec = seed_credential("x")
    rec2 = rec.with_band("subsystem", BandStanding(standing=0.2))
    assert rec2.standing == 0.2


def test_band_with_clean_run_increments_standing():
    b = BandStanding(standing=0.5, runs=3, breaches=0)
    b2 = b.with_clean_run(alpha=0.01)
    assert b2.standing == pytest.approx(0.51)
    assert b2.runs == 4
    assert b2.breaches == 0


def test_band_with_breach_records_timestamp_and_decrements():
    b = BandStanding(standing=0.5, runs=3, breaches=0)
    b2 = b.with_breach(gamma=0.2, now_iso="2026-04-24T00:00:00Z")
    assert b2.standing == pytest.approx(0.3)
    assert b2.breaches == 1
    assert b2.last_breach_iso == "2026-04-24T00:00:00Z"


def test_band_with_gate_fail_runs_increments_no_breach():
    b = BandStanding(standing=0.5, runs=1, breaches=0)
    b2 = b.with_gate_fail(beta=0.05)
    assert b2.standing == pytest.approx(0.45)
    assert b2.runs == 2
    assert b2.breaches == 0  # gate fail != conservation breach


def test_standing_clamps_to_range():
    b = BandStanding(standing=0.99)
    assert b.with_clean_run(alpha=0.5).standing == 1.0
    b2 = BandStanding(standing=0.1)
    assert b2.with_breach(gamma=0.5, now_iso="z").standing == 0.0


def test_serialize_round_trip():
    rec = seed_credential("e1")
    d = rec.to_dict()
    back = CredentialRecord.from_dict(d)
    assert back == rec


def test_serialize_with_restitution_and_calibration():
    rec = CredentialRecord(
        entity_id="e2",
        phase=1,
        competency_bands={"local": BandStanding(standing=0.8)},
        restitution_budget=RestitutionBudget(remaining=5, error_class="D1"),
        linked_calibration="credentials/e2.calibration.json",
    )
    d = rec.to_dict()
    assert d["restitution_budget"]["remaining"] == 5
    back = CredentialRecord.from_dict(d)
    assert back == rec


# Ledger -----------------------------------------------------------------


def test_seed_persists_across_load(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("A4")
    ledger.save()

    reloaded = CredentialLedger(tmp_path)
    assert reloaded.has("A4")
    assert reloaded.get("A4").phase == 0


def test_seed_duplicate_rejected(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("x")
    with pytest.raises(CredentialError, match="already exists"):
        ledger.seed("x")


def test_get_unknown_entity_raises(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    with pytest.raises(CredentialError, match="no credential"):
        ledger.get("SK-MISSING")


def test_list_entities_is_sorted(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("B")
    ledger.seed("A")
    ledger.seed("C")
    assert ledger.list_entities() == ["A", "B", "C"]


def test_put_overwrites_existing_record(tmp_path: Path):
    init_aios_home(tmp_path)
    ledger = CredentialLedger(tmp_path)
    ledger.seed("x")
    rec = ledger.get("x")
    rec2 = rec.with_band("local", BandStanding(standing=0.9))
    ledger.put(rec2)
    ledger.save()
    reloaded = CredentialLedger(tmp_path)
    assert reloaded.get("x").band("local").standing == 0.9


def test_ledger_handles_missing_file_gracefully(tmp_path: Path):
    init_aios_home(tmp_path)
    # No ledger.json yet — constructor should succeed with empty state.
    ledger = CredentialLedger(tmp_path)
    assert ledger.list_entities() == []


def test_ledger_raises_on_malformed_json(tmp_path: Path):
    init_aios_home(tmp_path)
    bad = tmp_path / "credentials" / "ledger.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    with pytest.raises(CredentialError, match="malformed"):
        CredentialLedger(tmp_path)
