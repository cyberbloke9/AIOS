"""Tests for calibration drift + quarantine (sprint 37)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aios.cli import main
from aios.runtime.init import init_aios_home
from aios.verification.calibration_record import save_record
from aios.verification.calibration_status import (
    CalibrationStatusReport,
    check_calibration_status,
    record_calibration_attempt,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _write_record(home: Path, skill_id: str, *, last_fit_iso: str,
                  schedule: str = "weekly"):
    from aios.verification.calibration_record import CalibrationRecord
    rec = CalibrationRecord(
        skill_id=skill_id,
        method="temperature_scaling",
        corpus_path="x", corpus_sha256="0" * 64,
        corpus_size=300,
        corpus_labeling_provenance="human-a",
        corpus_adversarial_share=0.1,
        corpus_recency_policy=schedule,
        corpus_last_refresh_iso=_iso_now(),
        impact="local",
        last_fit_iso=last_fit_iso,
        metrics_brier=0.1,
        metrics_ece=0.05,
        thresholds_brier_max=0.25,
        thresholds_ece_max=0.10,
        model_params={"temperature": 1.0},
        validation_schedule=schedule,
    )
    save_record(home, rec)
    return rec


# check_calibration_status -----------------------------------------------


def test_not_calibrated_when_no_record(tmp_path: Path):
    init_aios_home(tmp_path)
    report = check_calibration_status(tmp_path, "SK-MISSING")
    assert report.state == "not_calibrated"
    assert "no calibration record" in report.reason


def test_current_when_record_is_fresh(tmp_path: Path):
    init_aios_home(tmp_path)
    _write_record(tmp_path, "SK-FRESH",
                  last_fit_iso=_iso_days_ago(2), schedule="weekly")
    report = check_calibration_status(tmp_path, "SK-FRESH")
    assert report.state == "current"
    assert report.age_days < 7
    assert report.window_days == 7


def test_drift_when_past_weekly_window(tmp_path: Path):
    init_aios_home(tmp_path)
    _write_record(tmp_path, "SK-STALE",
                  last_fit_iso=_iso_days_ago(10), schedule="weekly")
    report = check_calibration_status(tmp_path, "SK-STALE")
    assert report.state == "drift"


def test_monthly_window_gives_longer_current(tmp_path: Path):
    init_aios_home(tmp_path)
    _write_record(tmp_path, "SK-MONTHLY",
                  last_fit_iso=_iso_days_ago(20), schedule="monthly")
    report = check_calibration_status(tmp_path, "SK-MONTHLY")
    assert report.state == "current"


def test_quarantined_after_three_failures(tmp_path: Path):
    init_aios_home(tmp_path)
    _write_record(tmp_path, "SK-FLAKY",
                  last_fit_iso=_iso_days_ago(1), schedule="weekly")
    for i in range(3):
        record_calibration_attempt(tmp_path, "SK-FLAKY",
                                    success=False, detail=f"fail {i}")
    report = check_calibration_status(tmp_path, "SK-FLAKY")
    assert report.state == "quarantined"
    assert report.recent_failure_count == 3


def test_quarantine_not_triggered_by_successes(tmp_path: Path):
    init_aios_home(tmp_path)
    _write_record(tmp_path, "SK-OK",
                  last_fit_iso=_iso_days_ago(1), schedule="weekly")
    for _ in range(5):
        record_calibration_attempt(tmp_path, "SK-OK", success=True)
    report = check_calibration_status(tmp_path, "SK-OK")
    assert report.state == "current"


def test_old_failures_beyond_30d_window_do_not_quarantine(tmp_path: Path):
    init_aios_home(tmp_path)
    _write_record(tmp_path, "SK-RECOVERED",
                  last_fit_iso=_iso_days_ago(1), schedule="weekly")
    # Back-date old failure entries directly into the attempts file
    p = tmp_path / "credentials" / "SK-RECOVERED.attempts.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([
        {"ts_iso": _iso_days_ago(60), "success": False, "detail": "old 1"},
        {"ts_iso": _iso_days_ago(45), "success": False, "detail": "old 2"},
        {"ts_iso": _iso_days_ago(40), "success": False, "detail": "old 3"},
    ]))
    report = check_calibration_status(tmp_path, "SK-RECOVERED")
    assert report.state == "current"
    assert report.recent_failure_count == 0


# CLI --------------------------------------------------------------------


def test_cli_calibration_status_not_calibrated(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    capsys.readouterr()
    rc = main(["calibration-status", "SK-X", "--home", str(home)])
    assert rc == 8
    out = capsys.readouterr().out
    assert "NOT_CALIBRATED" in out


def test_cli_calibration_status_current(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    _write_record(home, "SK-OK", last_fit_iso=_iso_days_ago(1))
    capsys.readouterr()
    rc = main(["calibration-status", "SK-OK", "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CURRENT" in out


def test_cli_calibration_status_drift(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    _write_record(home, "SK-STALE", last_fit_iso=_iso_days_ago(10))
    capsys.readouterr()
    rc = main(["calibration-status", "SK-STALE", "--home", str(home)])
    assert rc == 8
    out = capsys.readouterr().out
    assert "DRIFT" in out


def test_cli_calibration_status_quarantined(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    _write_record(home, "SK-Q", last_fit_iso=_iso_days_ago(1))
    for _ in range(3):
        record_calibration_attempt(home, "SK-Q", success=False, detail="flake")
    capsys.readouterr()
    rc = main(["calibration-status", "SK-Q", "--home", str(home)])
    assert rc == 9
    out = capsys.readouterr().out
    assert "QUARANTINED" in out


def test_cli_calibration_status_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "calibration-status" in out
