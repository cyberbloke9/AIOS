"""Tests for `aios run` CLI command (sprint 20)."""
from __future__ import annotations

import dataclasses as dc
import json
import tempfile
from pathlib import Path

import pytest

from aios.cli import main
from aios.verification.registry import default_registry


@pytest.fixture(autouse=True)
def stub_registry_impls():
    """Make stub predicates return preserved for the duration of CLI tests
    so `aios run` with the default manifest can actually promote. Restore
    originals after."""
    stub_ids = ("P_schema_valid", "P_acceptance_tests", "P_PI_sentinel")
    originals = {pid: default_registry.get(pid) for pid in stub_ids}
    try:
        for pid in stub_ids:
            old = originals[pid]
            default_registry._by_id[pid] = dc.replace(
                old, implementation=lambda run, _pid=pid: {"status": "preserved"}
            )
        yield
    finally:
        for pid, rec in originals.items():
            default_registry._by_id[pid] = rec


def _clean_runstate_json() -> dict:
    return {
        "run_id": "cli_promote",
        "invariants_before": [
            {"id": "INV-001", "source": "principle", "statement": "X"},
        ],
        "invariants_after": [
            {"id": "INV-001", "source": "principle", "statement": "X"},
        ],
        "adr_events": [],
        "decisions": [{"decision_id": "D1", "rollback_cost": "low"}],
        "generator_slices": [{"actor": "A3", "inputs_seen": ["spec"]}],
        "verifier_slices": [{"actor": "A4", "inputs_seen": ["adrs"]}],
        "context_load": {
            "tokens_loaded": 100, "budget": 1000,
            "invariants_loaded": ["INV-001"],
            "invariants_required": ["INV-001"],
        },
        "event_log_range": {"events": [{"kind": "e1"}]},
        "impact": "local",
    }


def _breach_runstate_json() -> dict:
    r = _clean_runstate_json()
    r["invariants_before"].append(
        {"id": "INV-002", "source": "security", "statement": "Y"}
    )
    # INV-002 removed silently (no ADR)
    r["run_id"] = "cli_breach"
    return r


def test_run_promotes_with_clean_state(tmp_path: Path, capsys):
    # init
    home = tmp_path / "home"
    main(["init", str(home)])
    capsys.readouterr()

    # manifest
    manifest_path = tmp_path / "wf.json"
    manifest_path.write_text(json.dumps({
        "id": "cli-promote-test", "version": "1.0", "impact": "local",
    }))

    # runstate
    run_json = tmp_path / "run.json"
    run_json.write_text(json.dumps(_clean_runstate_json()))

    rc = main(["run", str(manifest_path),
               "--home", str(home), "--run-json", str(run_json)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PROMOTED" in out
    assert "cli-promote-test" in out


def test_run_aborts_on_q1_breach(tmp_path: Path, capsys):
    home = tmp_path / "home"
    main(["init", str(home)])
    capsys.readouterr()

    manifest_path = tmp_path / "wf.json"
    manifest_path.write_text(json.dumps({
        "id": "cli-breach-test", "version": "1.0", "impact": "local",
    }))

    run_json = tmp_path / "run.json"
    run_json.write_text(json.dumps(_breach_runstate_json()))

    rc = main(["run", str(manifest_path),
               "--home", str(home), "--run-json", str(run_json)])
    assert rc == 4  # Q1 abort
    out = capsys.readouterr().out
    assert "ABORTED" in out


def test_run_bad_manifest_returns_2(tmp_path: Path, capsys):
    home = tmp_path / "home"
    main(["init", str(home)])
    capsys.readouterr()

    manifest_path = tmp_path / "bad.json"
    manifest_path.write_text("{not json}")

    rc = main(["run", str(manifest_path), "--home", str(home)])
    assert rc == 2


def test_run_nonexistent_home_returns_2(tmp_path: Path, capsys):
    manifest_path = tmp_path / "wf.json"
    manifest_path.write_text(json.dumps({
        "id": "x", "version": "1.0", "impact": "local",
    }))
    rc = main(["run", str(manifest_path), "--home", str(tmp_path / "nope")])
    assert rc == 2


def test_run_frames_written_to_event_log(tmp_path: Path, capsys):
    """After `aios run`, the target log must contain the emitted workflow frames."""
    home = tmp_path / "home"
    main(["init", str(home)])
    capsys.readouterr()

    manifest_path = tmp_path / "wf.json"
    manifest_path.write_text(json.dumps({
        "id": "x", "version": "1.0", "impact": "local",
    }))
    run_json = tmp_path / "run.json"
    run_json.write_text(json.dumps(_clean_runstate_json()))

    main(["run", str(manifest_path),
          "--home", str(home), "--run-json", str(run_json)])
    capsys.readouterr()

    rc = main(["replay", "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "run.started" in out
    assert "gate.evaluated" in out
    assert "artifact.promoted" in out


def test_run_appears_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "run" in capsys.readouterr().out
