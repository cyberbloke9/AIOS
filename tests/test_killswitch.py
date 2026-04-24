"""Tests for Kernel §5 kill switch (sprint 67)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios.cli import main
from aios.runtime.event_log import EventLog
from aios.runtime.killswitch import (
    KillState,
    KillSwitch,
    KillSwitchError,
    apply_kill_switch,
    is_killed,
    lift_kill_switch,
    read_only_mode,
)


# ---------------------------------------------------------------------------
# Authorization (§5.2)
# ---------------------------------------------------------------------------


def test_global_kill_accepts_a5():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="global", subject="*",
                reason="emergency", authority="A5",
            ))
        finally:
            log.close()


def test_global_kill_accepts_a4():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="global", subject="*",
                reason="investigation", authority="A4",
            ))
        finally:
            log.close()


def test_global_kill_accepts_operator():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="global", subject="*",
                reason="fire drill", authority="operator",
            ))
        finally:
            log.close()


def test_authority_kill_requires_a5():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            with pytest.raises(KillSwitchError, match="not allowed"):
                apply_kill_switch(log, KillSwitch(
                    scope="authority", subject="A3",
                    reason="misbehavior", authority="A4",
                ))
        finally:
            log.close()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="authority", subject="A3",
                reason="misbehavior", authority="A5",
            ))
        finally:
            log.close()


def test_workflow_kill_accepts_a4_or_a5():
    for auth in ("A4", "A5"):
        with tempfile.TemporaryDirectory() as tmp:
            log = EventLog(tmp)
            try:
                apply_kill_switch(log, KillSwitch(
                    scope="workflow", subject="pricing-refactor",
                    reason="bad deploy", authority=auth,
                ))
            finally:
                log.close()


def test_skill_kill_accepts_skill_owner():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="skill", subject="SK-ADR-CHECK",
                reason="false positives", authority="skill_owner:alice",
            ))
        finally:
            log.close()


def test_unauthorized_authority_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            with pytest.raises(KillSwitchError):
                apply_kill_switch(log, KillSwitch(
                    scope="global", subject="*",
                    reason="x", authority="A1",
                ))
        finally:
            log.close()


def test_global_subject_must_be_star():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            with pytest.raises(KillSwitchError, match="must be"):
                apply_kill_switch(log, KillSwitch(
                    scope="global", subject="specific",
                    reason="x", authority="A5",
                ))
        finally:
            log.close()


def test_non_global_requires_subject():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            with pytest.raises(KillSwitchError, match="non-empty subject"):
                apply_kill_switch(log, KillSwitch(
                    scope="workflow", subject="",
                    reason="x", authority="A5",
                ))
        finally:
            log.close()


# ---------------------------------------------------------------------------
# is_killed + read_only_mode
# ---------------------------------------------------------------------------


def test_is_killed_reflects_applied_kill():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="skill", subject="SK-X",
                reason="flake", authority="A5",
            ))
        finally:
            log.close()
        log2 = EventLog(tmp)
        try:
            state = is_killed(log2, scope="skill", subject="SK-X")
        finally:
            log2.close()
        assert state.active is True
        assert state.applied_authority == "A5"
        assert state.reason == "flake"


def test_is_killed_false_for_untouched_scope():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.close()
        log2 = EventLog(tmp)
        try:
            assert is_killed(log2, scope="workflow", subject="any").active is False
        finally:
            log2.close()


def test_lift_clears_kill():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="workflow", subject="wf1",
                reason="x", authority="A5",
            ))
            lift_kill_switch(log, KillSwitch(
                scope="workflow", subject="wf1",
                reason="resolved", authority="A5",
            ))
        finally:
            log.close()
        log2 = EventLog(tmp)
        try:
            state = is_killed(log2, scope="workflow", subject="wf1")
        finally:
            log2.close()
        assert state.active is False


def test_re_kill_after_lift_active_again():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="skill", subject="SK-X",
                reason="first", authority="A5",
            ))
            lift_kill_switch(log, KillSwitch(
                scope="skill", subject="SK-X",
                reason="ok", authority="A5",
            ))
            apply_kill_switch(log, KillSwitch(
                scope="skill", subject="SK-X",
                reason="second", authority="A5",
            ))
        finally:
            log.close()
        log2 = EventLog(tmp)
        try:
            state = is_killed(log2, scope="skill", subject="SK-X")
        finally:
            log2.close()
        assert state.active is True
        assert state.reason == "second"


def test_is_killed_subject_isolation():
    """Killing one subject doesn't affect another."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="skill", subject="SK-A",
                reason="x", authority="A5",
            ))
        finally:
            log.close()
        log2 = EventLog(tmp)
        try:
            assert is_killed(log2, scope="skill", subject="SK-A").active is True
            assert is_killed(log2, scope="skill", subject="SK-B").active is False
        finally:
            log2.close()


def test_read_only_mode_true_after_global_kill():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            apply_kill_switch(log, KillSwitch(
                scope="global", subject="*",
                reason="maintenance", authority="A5",
            ))
        finally:
            log.close()
        log2 = EventLog(tmp)
        try:
            assert read_only_mode(log2) is True
        finally:
            log2.close()


def test_read_only_mode_false_without_kill():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.close()
        log2 = EventLog(tmp)
        try:
            assert read_only_mode(log2) is False
        finally:
            log2.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_kill_global_happy_path(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    capsys.readouterr()
    rc = main([
        "kill", "--scope", "global", "--reason", "test",
        "--authority", "A5", "--home", str(home),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "kill applied" in out
    assert "read-only mode" in out


def test_cli_kill_unauthorized_exits_14(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    capsys.readouterr()
    rc = main([
        "kill", "--scope", "authority", "--subject", "A3",
        "--reason", "r", "--authority", "A4",
        "--home", str(home),
    ])
    assert rc == 14


def test_cli_kill_status_reports_active(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    main(["kill", "--scope", "workflow", "--subject", "wf1",
          "--reason", "x", "--authority", "A5",
          "--home", str(home)])
    capsys.readouterr()
    rc = main(["kill-status", "--scope", "workflow", "--subject", "wf1",
               "--home", str(home)])
    assert rc == 15
    out = capsys.readouterr().out
    assert "active:    True" in out


def test_cli_kill_lift_then_status_clear(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    main(["kill", "--scope", "skill", "--subject", "SK-X",
          "--reason", "x", "--authority", "A5", "--home", str(home)])
    main(["kill-lift", "--scope", "skill", "--subject", "SK-X",
          "--reason", "resolved", "--authority", "A5", "--home", str(home)])
    capsys.readouterr()
    rc = main(["kill-status", "--scope", "skill", "--subject", "SK-X",
               "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "active:    False" in out


def test_cli_kill_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "kill" in out
    assert "kill-lift" in out
    assert "kill-status" in out
