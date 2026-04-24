"""Tests for P_acceptance_tests pytest wrapper (sprint 46)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.verification.acceptance_tests import (
    _parse_summary,
    p_acceptance_tests,
)
from aios.verification.conservation_scan import (
    ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
)


def _empty_run() -> RunState:
    inv = Invariant(id="INV-001", source="principle", statement="x")
    events = ({"kind": "e"},)
    return RunState(
        run_id="t",
        invariants_before=frozenset({inv}),
        invariants_after=frozenset({inv}),
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"a"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"b"})),),
        context_load=ContextLoad(0, 1000, frozenset({"INV-001"}),
                                  frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact="local",
    )


# Summary parsing (pure) -------------------------------------------------


def test_parse_summary_all_passed():
    text = "============== 142 passed in 4.56s =============="
    counts = _parse_summary(text)
    assert counts == {"passed": 142}


def test_parse_summary_mixed():
    text = "============== 140 passed, 2 failed, 1 skipped in 5.0s =============="
    counts = _parse_summary(text)
    assert counts["passed"] == 140
    assert counts["failed"] == 2
    assert counts["skipped"] == 1


def test_parse_summary_handles_errors_plural():
    text = "==== 1 error, 2 errors in 1s ===="
    counts = _parse_summary(text)
    assert counts.get("error", 0) == 2  # "2 errors" overwrites "1 error" (both normalize)


def test_parse_summary_empty():
    assert _parse_summary("no pytest ran here") == {}


# Default-call shape ------------------------------------------------------


def test_no_suite_path_returns_preserved_note():
    result = p_acceptance_tests(_empty_run())
    assert result["status"] == "preserved"
    assert "note" in result


# Real subprocess — use pytest on a mini fixture --------------------------


def _write_passing_suite(tmp_path: Path) -> Path:
    suite = tmp_path / "test_passing.py"
    suite.write_text(
        "def test_trivially_true():\n    assert 1 + 1 == 2\n",
        encoding="utf-8",
    )
    return suite


def _write_failing_suite(tmp_path: Path) -> Path:
    suite = tmp_path / "test_failing.py"
    suite.write_text(
        "def test_always_fails():\n    assert False\n",
        encoding="utf-8",
    )
    return suite


def test_passing_suite_marked_preserved(tmp_path: Path):
    suite = _write_passing_suite(tmp_path)
    result = p_acceptance_tests(_empty_run(), suite_path=suite)
    assert result["status"] == "preserved"
    assert result["exit_code"] == 0
    assert result["passed"] >= 1
    assert result["failed"] == 0
    assert result["duration_seconds"] > 0


def test_failing_suite_marked_breached(tmp_path: Path):
    suite = _write_failing_suite(tmp_path)
    result = p_acceptance_tests(_empty_run(), suite_path=suite)
    assert result["status"] == "breached"
    assert result.get("status_reason") == "tests_failed"
    assert result["failed"] >= 1


def test_no_tests_collected_is_preserved(tmp_path: Path):
    # Empty file with no test_* functions triggers exit code 5
    empty = tmp_path / "test_empty.py"
    empty.write_text("# no tests here\n", encoding="utf-8")
    result = p_acceptance_tests(_empty_run(), suite_path=empty)
    assert result["status"] == "preserved"
    assert result.get("status_reason") == "no_tests_collected"


def test_timeout_fires_breach(tmp_path: Path):
    """A test that sleeps longer than the timeout should breach with
    status_reason='timeout'."""
    suite = tmp_path / "test_slow.py"
    suite.write_text(
        "import time\n"
        "def test_slow():\n"
        "    time.sleep(10)\n",
        encoding="utf-8",
    )
    result = p_acceptance_tests(
        _empty_run(), suite_path=suite, timeout_seconds=1.0,
    )
    assert result["status"] == "breached"
    assert result["status_reason"] == "timeout"


def test_custom_pytest_args_forwarded(tmp_path: Path):
    """-k filter should select a subset. Passing a filter that matches
    nothing triggers exit 5 (no tests collected) → preserved."""
    suite = _write_passing_suite(tmp_path)
    result = p_acceptance_tests(
        _empty_run(), suite_path=suite,
        pytest_args=["-k", "nothing-matches-this-filter", "-q"],
    )
    assert result["status"] == "preserved"
    assert result.get("status_reason") == "no_tests_collected"


# Registry integration ---------------------------------------------------


def test_registry_no_longer_stub():
    from aios.verification.registry import default_registry
    result = default_registry.evaluate(
        "P_acceptance_tests", _empty_run(),
    )
    # With no kwargs -> preserved + note (the non-stub path)
    assert result["status"] == "preserved"
    assert isinstance(result, dict)


def test_registry_record_has_implementation():
    from aios.verification.registry import default_registry
    rec = default_registry.get("P_acceptance_tests")
    assert rec.implementation is not None
    assert rec.gate_type == "T2"
    assert rec.determinism == "stochastic_bounded"


def test_registry_forwards_suite_path_kwarg(tmp_path: Path):
    from aios.verification.registry import default_registry
    suite = _write_passing_suite(tmp_path)
    result = default_registry.evaluate(
        "P_acceptance_tests", _empty_run(),
        suite_path=suite,
    )
    assert result["status"] == "preserved"
    assert result["passed"] >= 1
