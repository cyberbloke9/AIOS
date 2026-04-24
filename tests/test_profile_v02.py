"""Tests for updated v0.2.0 profile checks (sprint 16).

Covers the changes to `runtime.profile.check_profile`:
  - P-Enterprise now runs _run_p_enterprise_checks with richer output
  - cryptography availability is reported
  - writer-lock active is reported
  - remaining unimplemented features named individually
  - P-Local still refuses signed frames (no verifier configured)
  - P-Enterprise accepts signed frames as expected (§9.2)
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios.enterprise.signing import (
    Ed25519Signer, cryptography_available,
)
from aios.runtime.event_log import EventLog
from aios.runtime.init import init_aios_home
from aios.runtime.profile import check_profile


def test_p_enterprise_runs_richer_checks():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Enterprise")
        result = check_profile(tmp)
        names = [c.name for c in result.checks]
        assert "p_enterprise.writer_lock_active" in names
        assert "p_enterprise.ed25519_available" in names
        assert "p_enterprise.unimplemented" in names


def test_p_enterprise_reports_ed25519_available():
    if not cryptography_available():
        pytest.skip("cryptography not installed")
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Enterprise")
        result = check_profile(tmp)
        ed = [c for c in result.checks
              if c.name == "p_enterprise.ed25519_available"]
        assert ed and ed[0].status == "pass"


def test_p_enterprise_still_fails_overall_due_to_tuf_etc():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Enterprise")
        result = check_profile(tmp)
        assert not result.passed
        unimplemented = [c for c in result.checks
                         if c.name == "p_enterprise.unimplemented"]
        assert len(unimplemented) >= 5  # TUF, credentialing x2, calibration, audit, SBOM
        details = " ".join(c.detail for c in unimplemented)
        assert "TUF" in details
        assert "Credentialing" in details
        assert "Calibration" in details


def test_p_enterprise_unimplemented_list_no_longer_contains_ed25519():
    """v0.2.0 shipped Ed25519 — should no longer appear as missing."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Enterprise")
        result = check_profile(tmp)
        unimplemented = [c for c in result.checks
                         if c.name == "p_enterprise.unimplemented"]
        details = " ".join(c.detail for c in unimplemented)
        assert "Ed25519 capability tokens" not in details


def test_p_enterprise_accepts_signed_frames():
    if not cryptography_available():
        pytest.skip("cryptography not installed")
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Enterprise")
        signer = Ed25519Signer.generate()
        log = EventLog(Path(tmp) / "events", signer=signer)
        log.append(kind="artifact.promoted", actor="A5",
                   payload={"artifact_ref": "sha256:abc"})
        log.close()

        result = check_profile(tmp)
        sig_check = [c for c in result.checks
                     if c.name == "events.signatures_allowed"]
        assert sig_check and sig_check[0].status == "pass"


def test_p_local_still_refuses_signed_frames():
    if not cryptography_available():
        pytest.skip("cryptography not installed")
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        signer = Ed25519Signer.generate()
        log = EventLog(Path(tmp) / "events", signer=signer)
        log.append(kind="x", actor="A3", payload={})
        log.close()

        result = check_profile(tmp)
        assert not result.passed
        bad = [c for c in result.checks
               if c.name == "p_local.no_capability_tokens"]
        assert bad and bad[0].status == "fail"


def test_p_highassurance_refuses_without_merkle_batch():
    """v0.6.0 made P-HA pass when merkle.batch frames exist. Without one,
    the loader still refuses with a Merkle-specific failure."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        result = check_profile(tmp)
        assert not result.passed
        details = " ".join(c.detail for c in result.checks if c.status == "fail")
        assert "merkle" in details.lower()


def test_p_airgap_still_refused():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Airgap")
        result = check_profile(tmp)
        assert not result.passed
        details = " ".join(c.detail for c in result.checks if c.status == "fail")
        assert "TUF" in details
