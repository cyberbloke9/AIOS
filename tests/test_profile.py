"""Tests for profile loader (Runtime Protocol §10.6)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from aios.runtime.event_log import EventLog
from aios.runtime.init import init_aios_home
from aios.runtime.profile import check_profile


def test_p_local_fresh_init_passes():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        result = check_profile(tmp)
        assert result.profile == "P-Local"
        assert result.passed, result.format_report()
        # Every individual check passed
        for c in result.checks:
            assert c.status == "pass", f"{c.name} {c.status}: {c.detail}"


def test_missing_config_fails():
    with tempfile.TemporaryDirectory() as tmp:
        result = check_profile(tmp)
        assert not result.passed
        assert any(c.name == "config.present" and c.status == "fail"
                   for c in result.checks)


def test_p_enterprise_declaration_fails_loader():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Enterprise")
        result = check_profile(tmp)
        assert result.profile == "P-Enterprise"
        assert not result.passed
        failing = [c for c in result.checks if c.status == "fail"]
        # Must name specific missing features
        assert any("Ed25519" in c.detail or "TUF" in c.detail for c in failing)


def test_p_airgap_declaration_fails_loader():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Airgap")
        result = check_profile(tmp)
        assert result.profile == "P-Airgap"
        assert not result.passed


def test_p_highassurance_declaration_fails_loader():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-HighAssurance")
        result = check_profile(tmp)
        assert result.profile == "P-HighAssurance"
        assert not result.passed
        failing = [c for c in result.checks if c.status == "fail"]
        details = " ".join(c.detail for c in failing)
        assert "Merkle" in details  # §1.5


def test_events_dir_missing_fails():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        # Delete the events directory after init
        import shutil
        shutil.rmtree(Path(tmp) / "events")
        result = check_profile(tmp)
        assert not result.passed
        assert any(c.name == "events.dir_present" and c.status == "fail"
                   for c in result.checks)


def test_spec_version_mismatch_fails():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        # Poison the config with a wrong spec version
        cfg_path = Path(tmp) / "config.json"
        config = json.loads(cfg_path.read_text())
        config["spec_versions"]["constitution"] = "99.0.0"
        cfg_path.write_text(json.dumps(config))
        result = check_profile(tmp)
        assert not result.passed
        assert any(c.name == "config.spec_versions" and c.status == "fail"
                   for c in result.checks)


def test_unsigned_p_local_log_passes_no_cap_token_check():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        # Add a normal (unsigned) frame
        log = EventLog(Path(tmp) / "events")
        log.append(kind="demo", actor="A3", payload={"x": 1})
        log.close()
        result = check_profile(tmp)
        assert result.passed, result.format_report()


def test_signed_frame_breaks_p_local():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        # Inject a frame carrying a `sig` field: P-Local does not verify
        # signatures in v0.1.0, so presence indicates an incorrect profile.
        log = EventLog(Path(tmp) / "events")
        log.append(kind="demo", actor="A3", payload={"x": 1},
                   sig=b"\x00" * 64)
        log.close()
        result = check_profile(tmp)
        assert not result.passed
        assert any(c.name == "p_local.no_capability_tokens"
                   and c.status == "fail" for c in result.checks)


def test_report_format_human_readable():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        result = check_profile(tmp)
        text = result.format_report()
        assert "P-Local" in text
        assert "PASS" in text
        assert "[ok]" in text
