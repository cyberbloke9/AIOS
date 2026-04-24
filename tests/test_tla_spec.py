"""Structural tests for the TLA+ spec (sprint 71).

These tests verify the SHAPE of docs/spec/AIOS_EventLog.tla — they
don't run TLC. Running the model checker is the operator's job
(documented in the file itself). What we enforce here:

  - the file exists + parses as a TLA+ module (has MODULE header)
  - it declares the expected CONSTANTS + VARIABLES
  - it defines Init, Next, Spec
  - it declares the five invariants the spec §5 promises
  - a companion .cfg file exists so a reviewer can run TLC out of box

Spec correctness is only verified by TLC; these are unit tests for
spec-file shape, not proofs.
"""
from __future__ import annotations

from pathlib import Path

import pytest

SPEC = Path(__file__).parent.parent / "docs" / "spec" / "AIOS_EventLog.tla"
CFG = Path(__file__).parent.parent / "docs" / "spec" / "AIOS_EventLog.cfg"


@pytest.fixture(scope="module")
def spec_text() -> str:
    return SPEC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def cfg_text() -> str:
    return CFG.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# File presence + header
# ---------------------------------------------------------------------------


def test_spec_file_exists():
    assert SPEC.is_file(), f"{SPEC} missing — sprint 71 deliverable"


def test_cfg_file_exists():
    assert CFG.is_file(), f"{CFG} missing — reviewer can't run TLC"


def test_module_header_present(spec_text: str):
    assert "MODULE AIOS_EventLog" in spec_text


def test_extends_expected_modules(spec_text: str):
    """Naturals + Sequences cover the log-length arithmetic; TLC gives
    us Cardinality and Assert."""
    assert "EXTENDS Naturals, Sequences, TLC" in spec_text


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------


def test_constants_declared(spec_text: str):
    assert "CONSTANTS" in spec_text
    for c in ("Writers", "MaxSeq", "HashSpace"):
        assert c in spec_text, f"constant {c} missing"


def test_variables_declared(spec_text: str):
    assert "VARIABLES" in spec_text
    for v in ("log", "activeWriter", "nextSeq"):
        assert v in spec_text, f"variable {v} missing"


def test_init_next_spec_defined(spec_text: str):
    for name in ("Init ==", "Next ==", "Spec =="):
        assert name in spec_text, f"{name.rstrip(' =')} missing"


# ---------------------------------------------------------------------------
# Invariants §5 promises
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("invariant", [
    "SingleWriter",      # §5.1
    "LSN_Monotonic",     # §5.2
    "LSN_NoGap",         # §5.2 — advance by exactly 1
    "ChainLinked",       # §1.2 prev chain
    "UniqueHashes",      # content addressing
])
def test_invariant_defined(spec_text: str, invariant: str):
    assert f"{invariant} ==" in spec_text, \
        f"invariant {invariant} not defined"


def test_append_only_temporal_property(spec_text: str):
    assert "AppendOnly ==" in spec_text


# ---------------------------------------------------------------------------
# CFG contents
# ---------------------------------------------------------------------------


def test_cfg_binds_constants(cfg_text: str):
    for c in ("Writers", "MaxSeq", "HashSpace"):
        assert c in cfg_text, f"cfg missing constant binding: {c}"


def test_cfg_lists_every_invariant(cfg_text: str):
    for inv in ("SingleWriter", "LSN_Monotonic", "LSN_NoGap",
                "ChainLinked", "UniqueHashes"):
        assert inv in cfg_text, f"cfg missing INVARIANT: {inv}"


def test_cfg_sets_init_next(cfg_text: str):
    assert "INIT Init" in cfg_text
    assert "NEXT Next" in cfg_text


def test_cfg_sets_temporal_property(cfg_text: str):
    assert "PROPERTIES" in cfg_text
    assert "AppendOnly" in cfg_text


# ---------------------------------------------------------------------------
# Spec boundary
# ---------------------------------------------------------------------------


def test_spec_has_module_terminator(spec_text: str):
    """TLA+ modules end with '='×80. Forgetting the terminator makes
    some tools refuse to parse the file."""
    assert "================================================================================" in spec_text


def test_cfg_runnable_comment_present(cfg_text: str):
    """The cfg should instruct a reviewer how to run it."""
    assert "tlc" in cfg_text.lower()
