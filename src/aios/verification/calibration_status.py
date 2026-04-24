"""Calibration drift + recalibration cadence (sprint 37).

Verification Spec §2.5:
  "Weekly validation for skills with weekly schedule; monthly for monthly
   schedule. On any detected drift: immediate recalibration attempt. On
   three failed recalibration attempts in rolling 30 days: the skill is
   quarantined pending audit."

States:
  not_calibrated  — no record found
  current         — record exists, within its validation window
  drift           — record exists, age exceeds its validation window
                    (recalibration attempt required)
  quarantined     — 3+ failed recalibration attempts in the past 30 days
                    (Kernel §3.5 D5 calibration failure)

record_calibration_attempt() appends to a sidecar `<skill>.attempts.json`
so the quarantine logic can count failures in a rolling window without
needing a full event log query.
"""
from __future__ import annotations

import dataclasses as dc
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from aios.verification.calibration_record import (
    has_record,
    load_record,
    record_path,
)

CalibrationState = Literal["not_calibrated", "current", "drift", "quarantined"]

_SCHEDULE_WINDOW = {
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}

_QUARANTINE_FAILURES = 3
_QUARANTINE_WINDOW = timedelta(days=30)


@dc.dataclass(frozen=True)
class CalibrationStatusReport:
    skill_id: str
    state: CalibrationState
    reason: str
    last_fit_iso: str | None
    age_days: float | None
    window_days: int | None
    recent_failure_count: int = 0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def check_calibration_status(
    aios_home: str | Path, skill_id: str
) -> CalibrationStatusReport:
    """Return the current calibration state for `skill_id`."""
    if not has_record(aios_home, skill_id):
        return CalibrationStatusReport(
            skill_id=skill_id,
            state="not_calibrated",
            reason=f"no calibration record at "
                   f"{record_path(aios_home, skill_id)}",
            last_fit_iso=None,
            age_days=None,
            window_days=None,
        )

    # Count failures in the rolling window first — quarantine takes
    # precedence over everything else.
    failures = _recent_failure_count(aios_home, skill_id)
    if failures >= _QUARANTINE_FAILURES:
        record = load_record(aios_home, skill_id)
        return CalibrationStatusReport(
            skill_id=skill_id,
            state="quarantined",
            reason=(f"{failures} failed recalibration attempts in the past "
                    f"{_QUARANTINE_WINDOW.days} days; §2.5 quarantine gate"),
            last_fit_iso=record.last_fit_iso,
            age_days=_age_days(record.last_fit_iso),
            window_days=_SCHEDULE_WINDOW[record.validation_schedule].days,
            recent_failure_count=failures,
        )

    record = load_record(aios_home, skill_id)
    window = _SCHEDULE_WINDOW[record.validation_schedule]
    age_days = _age_days(record.last_fit_iso)
    if age_days <= window.days:
        return CalibrationStatusReport(
            skill_id=skill_id,
            state="current",
            reason=f"last_fit {age_days:.1f}d ago within {window.days}d window",
            last_fit_iso=record.last_fit_iso,
            age_days=age_days,
            window_days=window.days,
            recent_failure_count=failures,
        )
    return CalibrationStatusReport(
        skill_id=skill_id,
        state="drift",
        reason=(f"last_fit {age_days:.1f}d ago exceeds "
                f"{record.validation_schedule} window ({window.days}d); "
                f"recalibration required"),
        last_fit_iso=record.last_fit_iso,
        age_days=age_days,
        window_days=window.days,
        recent_failure_count=failures,
    )


def _age_days(last_fit_iso: str) -> float:
    return (_now() - _parse_iso(last_fit_iso)).total_seconds() / 86400


# ---------------------------------------------------------------------------
# Recalibration attempt log
# ---------------------------------------------------------------------------


def _attempts_path(aios_home: str | Path, skill_id: str) -> Path:
    return Path(aios_home) / "credentials" / f"{skill_id}.attempts.json"


def record_calibration_attempt(
    aios_home: str | Path, skill_id: str, *, success: bool,
    detail: str = "",
) -> None:
    """Append a calibration attempt outcome to the sidecar log.

    The log is read by check_calibration_status to enforce the §2.5
    quarantine rule. Keep the schema stable so future sprints can
    extend (e.g., add a `metrics` field) without migration.
    """
    p = _attempts_path(aios_home, skill_id)
    p.parent.mkdir(parents=True, exist_ok=True)

    entries: list[dict] = []
    if p.exists():
        try:
            entries = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(entries, list):
                entries = []
        except json.JSONDecodeError:
            entries = []

    entries.append({
        "ts_iso": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "success": bool(success),
        "detail": detail,
    })
    p.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")


def _recent_failure_count(aios_home: str | Path, skill_id: str) -> int:
    p = _attempts_path(aios_home, skill_id)
    if not p.exists():
        return 0
    try:
        entries = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return 0
    cutoff = _now() - _QUARANTINE_WINDOW
    count = 0
    for e in entries:
        if e.get("success"):
            continue
        try:
            ts = _parse_iso(e["ts_iso"])
        except (KeyError, ValueError):
            continue
        if ts >= cutoff:
            count += 1
    return count
