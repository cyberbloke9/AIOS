"""Tests for P-HighAssurance loader checks (sprint 72)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios.enterprise.signing import cryptography_available
from aios.runtime.event_log import EventLog
from aios.runtime.init import init_aios_home
from aios.runtime.profile import check_profile


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography package not installed",
)


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def test_p_ha_without_merkle_fails():
    """A fresh P-HA-declared home has no merkle.batch yet — must fail."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        result = check_profile(tmp)
    assert result.profile == "P-HighAssurance"
    assert not result.passed
    merkle_checks = [c for c in result.checks
                     if c.name == "p_highassurance.merkle_batch_present"]
    assert merkle_checks
    assert merkle_checks[0].status == "fail"


def test_p_ha_with_merkle_batch_passes_core_checks():
    """Add a merkle.batch frame; the compiled-in features all report OK.
    Remaining unimplemented items surface as warnings, not fails."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        log = EventLog(Path(tmp) / "events")
        try:
            log.append(kind="x", actor="A1", payload={"i": 0})
            log.append(kind="x", actor="A1", payload={"i": 1})
            log.create_merkle_batch(batch_start_seq=0, batch_end_seq=1)
        finally:
            log.close()

        result = check_profile(tmp)

    merkle = _check_named(result, "p_highassurance.merkle_batch_present")
    assert merkle.status == "pass"

    # All 4 module-import checks present and passing
    for mod in ("macaroons", "tuf_chain", "tuf_rotation", "killswitch"):
        chk = _check_named(result, f"p_highassurance.{mod}_available")
        assert chk.status == "pass"


def test_p_ha_tla_check_reports_warn_or_pass():
    """The TLA+ spec lives under docs/ which may not ship with an
    installed wheel. The check tolerates absence as a 'warn', not a
    fail — deployment packages it alongside the release bundle."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        log = EventLog(Path(tmp) / "events")
        try:
            log.append(kind="x", actor="A1", payload={})
            log.create_merkle_batch(batch_start_seq=0, batch_end_seq=0)
        finally:
            log.close()
        result = check_profile(tmp)
    tla = _check_named(result, "p_highassurance.tla_spec_present")
    assert tla.status in ("pass", "warn")


def test_p_ha_remaining_items_are_warns_not_fails():
    """Sigstore/Rekor network, reproducible builds, TPM hooks — these
    are operator homework, not v0.6.0 bugs. They appear as warnings."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        log = EventLog(Path(tmp) / "events")
        try:
            log.append(kind="x", actor="A1", payload={})
            log.create_merkle_batch(batch_start_seq=0, batch_end_seq=0)
        finally:
            log.close()
        result = check_profile(tmp)
    remaining = [c for c in result.checks
                 if c.name == "p_highassurance.remaining"]
    assert remaining
    assert all(c.status == "warn" for c in remaining)


def test_p_ha_overall_passes_when_merkle_present():
    """Assemble a clean P-HA home + one merkle batch; overall PASS."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        log = EventLog(Path(tmp) / "events")
        try:
            log.append(kind="x", actor="A1", payload={})
            log.create_merkle_batch(batch_start_seq=0, batch_end_seq=0)
        finally:
            log.close()
        result = check_profile(tmp)
    failing = [c for c in result.checks if c.status == "fail"]
    assert failing == [], f"failing checks: {[c.name for c in failing]}"
    assert result.passed is True


def test_p_ha_inherits_p_local_checks():
    """Events.replay_ok, events.dir_present etc. must be in the P-HA
    check list — P-HA is a superset of P-Enterprise is a superset of
    P-Local."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        log = EventLog(Path(tmp) / "events")
        try:
            log.append(kind="x", actor="A1", payload={})
            log.create_merkle_batch(batch_start_seq=0, batch_end_seq=0)
        finally:
            log.close()
        result = check_profile(tmp)
    names = {c.name for c in result.checks}
    # P-Local baseline
    assert "events.dir_present" in names
    assert "events.replay_ok" in names
    # P-Enterprise layer
    assert "p_enterprise.ed25519_available" in names
    assert "p_enterprise.writer_lock_active" in names
    # P-HA layer
    assert "p_highassurance.merkle_batch_present" in names


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_named(result, name):
    hits = [c for c in result.checks if c.name == name]
    assert hits, f"no check named {name!r}; got {[c.name for c in result.checks]}"
    return hits[0]
