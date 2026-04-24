"""Tests for aios.cli — CLI entry points."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from aios.cli import main


def test_help_prints(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "aios" in out.lower()
    assert "init" in out
    assert "append" in out
    assert "replay" in out
    assert "scan" in out
    assert "check-profile" in out


def test_version_flag(capsys):
    rc = main(["--version"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "aios" in out
    assert "constitution" in out
    assert "runtime_protocol" in out


def test_init_default_profile(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        rc = main(["init", str(home)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "P-Local" in out
        assert (home / "config.json").exists()


def test_init_refuses_reinit_without_force(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        rc = main(["init", str(home)])
        assert rc == 1


def test_init_force_reinits():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        rc = main(["init", str(home), "--profile", "P-Local", "--force"])
        assert rc == 0


def test_append_and_replay(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        capsys.readouterr()  # drain

        rc = main(["append", "--home", str(home),
                   "--kind", "run.started", "--actor", "A1",
                   "--payload", '{"run_id":"r001"}'])
        assert rc == 0
        out = capsys.readouterr().out
        assert "seq=2" in out  # after genesis install+profile
        assert "run.started" in out

        rc = main(["replay", "--home", str(home)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "install.complete" in out
        assert "profile.declared" in out
        assert "run.started" in out
        assert "3 frame(s)" in out


def test_replay_json_format(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        capsys.readouterr()
        rc = main(["replay", "--home", str(home), "--format", "json"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 2
        assert data[0]["kind"] == "install.complete"
        assert data[1]["kind"] == "profile.declared"


def test_scan_demo_passes(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        capsys.readouterr()
        rc = main(["scan", "--home", str(home)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Q1_invariant_integrity" in out
        assert "preserved" in out


def test_scan_with_run_json_breach(capsys):
    """Feed a RunState that silently removes an invariant; expect breach exit."""
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        capsys.readouterr()

        run_json = Path(tmp) / "run.json"
        run_json.write_text(json.dumps({
            "run_id": "cli_breach",
            "invariants_before": [
                {"id": "INV-001", "source": "principle", "statement": "X"},
                {"id": "INV-002", "source": "security", "statement": "Y"},
            ],
            "invariants_after": [
                {"id": "INV-001", "source": "principle", "statement": "X"},
            ],
            "adr_events": [],
            "decisions": [],
            "generator_slices": [],
            "verifier_slices": [],
            "context_load": {
                "tokens_loaded": 100, "budget": 1000,
                "invariants_loaded": ["INV-001"],
                "invariants_required": ["INV-001"],
            },
            "event_log_range": {"events": [{"kind": "e1"}]},
            "impact": "local",
        }))

        rc = main(["scan", "--home", str(home), "--run-json", str(run_json)])
        assert rc == 4  # breach exit code


def test_info_command(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        capsys.readouterr()
        rc = main(["info", "--home", str(home)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "P-Local" in out
        assert "frames:" in out
        assert "head_seq:" in out


def test_check_profile_p_local_ok(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home), "--profile", "P-Local"])
        capsys.readouterr()
        rc = main(["check-profile", "--home", str(home)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "PASS" in out


def test_check_profile_p_enterprise_fails(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home), "--profile", "P-Enterprise"])
        capsys.readouterr()
        rc = main(["check-profile", "--home", str(home)])
        assert rc == 5
        out = capsys.readouterr().out
        assert "P-Enterprise" in out
        assert "FAIL" in out


def test_unknown_home_errors(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        rc = main(["replay", "--home", str(Path(tmp) / "nowhere")])
        assert rc == 2
        err = capsys.readouterr().err
        assert "no AIOS home" in err


def test_bad_json_payload_rejected(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "h"
        main(["init", str(home)])
        capsys.readouterr()
        rc = main(["append", "--home", str(home), "--kind", "x",
                   "--actor", "A1", "--payload", "{not json}"])
        assert rc == 2


def test_no_subcommand_prints_help(capsys):
    rc = main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "init" in out
    assert "append" in out
