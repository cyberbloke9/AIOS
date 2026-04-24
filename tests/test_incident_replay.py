"""Tests for incident replay procedure §4.4 (sprint 44)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from aios.cli import main
from aios.runtime.event_log import EventLog, Frame
from aios.runtime.init import init_aios_home
from aios.verification.incident_replay import (
    IncidentReplayReport,
    replay_incident,
    replay_incident_from_home,
)


# Helpers ----------------------------------------------------------------


def _frame(kind: str, payload: dict, seq: int = 0, actor: str = "A4") -> Frame:
    return Frame(
        v=1, seq=seq, ts_ns=seq * 1_000_000,
        prev=bytes(32), kind=kind, actor=actor,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Pure replay_incident(frames, run_id)
# ---------------------------------------------------------------------------


def test_happy_path_promotion():
    frames = [
        _frame("run.started", {"run_id": "r1", "workflow_id": "wf",
                                "impact": "local"}),
        _frame("gate.evaluated", {"run_id": "r1",
                                    "gate_id": "P_Q1_invariant_integrity",
                                    "status": "preserved"}),
        _frame("gate.evaluated", {"run_id": "r1",
                                    "gate_id": "P_Q2_state_traceability",
                                    "status": "preserved"}),
        _frame("artifact.promoted", {"run_id": "r1"}),
    ]
    report = replay_incident(frames, "r1")
    assert report.run_id == "r1"
    assert report.workflow_id == "wf"
    assert report.impact == "local"
    assert report.outcome == "promoted"
    assert report.frame_count == 4
    assert len(report.gate_verdicts) == 2
    assert report.caught is False   # no breach -> no "catch"
    assert report.attributed_g_class is None


def test_q1_breach_catches_incident():
    frames = [
        _frame("run.started", {"run_id": "r2", "workflow_id": "wf",
                                "impact": "local"}),
        _frame("gate.evaluated", {"run_id": "r2",
                                    "gate_id": "P_Q1_invariant_integrity",
                                    "status": "breached"}),
        _frame("run.aborted", {"run_id": "r2"}),
    ]
    report = replay_incident(frames, "r2")
    assert report.outcome == "aborted"
    assert report.caught is True
    assert "P_Q1_invariant_integrity" in report.q_breaches
    assert report.attributed_g_class is None    # contained -> no G-class


def test_stub_predicate_attributes_g6():
    frames = [
        _frame("run.started", {"run_id": "r3", "workflow_id": "wf",
                                "impact": "local"}),
        _frame("gate.evaluated", {"run_id": "r3",
                                    "gate_id": "P_PI_sentinel",
                                    "status": "not_implemented"}),
        _frame("artifact.rejected", {"run_id": "r3"}),
    ]
    report = replay_incident(frames, "r3")
    assert report.attributed_g_class == "G6"
    assert "recalibration" in report.remediation.lower() or \
           "auto-quarantine" in report.remediation.lower()


def test_missing_gate_evaluations_attributes_g1():
    frames = [
        _frame("run.started", {"run_id": "r4", "workflow_id": "wf",
                                "impact": "local"}),
        _frame("artifact.promoted", {"run_id": "r4"}),  # no gates evaluated!
    ]
    report = replay_incident(frames, "r4")
    assert report.gate_verdicts == ()
    assert report.attributed_g_class == "G1"


def test_filters_by_run_id():
    frames = [
        _frame("run.started", {"run_id": "keeper", "workflow_id": "wf"}),
        _frame("gate.evaluated", {"run_id": "other",
                                    "gate_id": "P_Q1_invariant_integrity",
                                    "status": "breached"}),
        _frame("artifact.promoted", {"run_id": "keeper"}),
    ]
    report = replay_incident(frames, "keeper")
    # Only keeper's frames used; other's breach ignored
    assert report.gate_verdicts == ()
    assert report.q_breaches == ()
    assert report.outcome == "promoted"


def test_empty_frames_produces_empty_report():
    report = replay_incident([], "nope")
    assert report.frame_count == 0
    assert report.outcome is None
    assert report.caught is False


def test_multiple_q_breaches_all_captured():
    frames = [
        _frame("run.started", {"run_id": "rM"}),
        _frame("gate.evaluated", {"run_id": "rM",
                                    "gate_id": "P_Q1_invariant_integrity",
                                    "status": "breached"}),
        _frame("gate.evaluated", {"run_id": "rM",
                                    "gate_id": "P_Q2_state_traceability",
                                    "status": "breached"}),
        _frame("run.aborted", {"run_id": "rM"}),
    ]
    report = replay_incident(frames, "rM")
    assert report.q_breaches == (
        "P_Q1_invariant_integrity",
        "P_Q2_state_traceability",
    )


# ---------------------------------------------------------------------------
# replay_incident_from_home(home, run_id)
# ---------------------------------------------------------------------------


def test_replay_from_home_reads_event_log():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp)
        log = EventLog(Path(tmp) / "events")
        log.append(kind="run.started", actor="A1",
                   payload={"run_id": "live", "workflow_id": "wf",
                            "impact": "local"})
        log.append(kind="gate.evaluated", actor="A4",
                   payload={"run_id": "live",
                            "gate_id": "P_Q1_invariant_integrity",
                            "status": "preserved"})
        log.append(kind="artifact.promoted", actor="A5",
                   payload={"run_id": "live"})
        log.close()

        report = replay_incident_from_home(tmp, "live")
        assert report.run_id == "live"
        assert report.workflow_id == "wf"
        assert report.outcome == "promoted"
        assert report.frame_count == 3


def test_replay_from_home_unknown_run_returns_empty(tmp_path: Path):
    init_aios_home(tmp_path)
    report = replay_incident_from_home(tmp_path, "does-not-exist")
    assert report.frame_count == 0


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_replay_incident_happy(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    main(["append", "--home", str(home),
          "--kind", "run.started", "--actor", "A1",
          "--payload", json.dumps({"run_id": "r1", "workflow_id": "wf"})])
    main(["append", "--home", str(home),
          "--kind", "gate.evaluated", "--actor", "A4",
          "--payload", json.dumps({"run_id": "r1",
                                    "gate_id": "P_Q1_invariant_integrity",
                                    "status": "breached"})])
    main(["append", "--home", str(home),
          "--kind", "run.aborted", "--actor", "A1",
          "--payload", json.dumps({"run_id": "r1"})])
    capsys.readouterr()

    rc = main(["replay-incident", "r1", "--home", str(home)])
    assert rc == 0   # caught
    out = capsys.readouterr().out
    assert "r1" in out
    assert "aborted" in out
    assert "yes" in out


def test_cli_replay_incident_unknown_run(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    capsys.readouterr()
    rc = main(["replay-incident", "nope", "--home", str(home)])
    assert rc == 10
    err = capsys.readouterr().err
    assert "no frames" in err


def test_cli_replay_incident_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "replay-incident" in out
