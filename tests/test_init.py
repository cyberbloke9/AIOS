"""Tests for aios.runtime.init — AIOS home directory initialization."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios import __version__
from aios.runtime.event_log import EventLog
from aios.runtime.init import (
    DEFAULT_PROFILE, VALID_PROFILES,
    init_aios_home, is_initialized, read_config,
)


def test_init_creates_layout():
    with tempfile.TemporaryDirectory() as tmp:
        result = init_aios_home(tmp)
        for sub in ("events", "registry", "projections", "credentials"):
            assert (Path(tmp) / sub).is_dir(), f"{sub} missing"
        assert result.config_path.exists()
        assert result.profile == DEFAULT_PROFILE
        assert result.install_seq == 0
        assert result.profile_seq == 1


def test_init_writes_config_with_spec_versions():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp)
        config = read_config(tmp)
        assert config["aios_version"] == __version__
        assert config["profile"] == "P-Local"
        assert config["spec_versions"]["constitution"] == "1.0.0"
        assert config["spec_versions"]["runtime_protocol"] == "1.0.0"


def test_init_writes_genesis_and_profile_events():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        log = EventLog(Path(tmp) / "events")
        frames = list(log.replay())
        log.close()
        assert len(frames) == 2
        assert frames[0].kind == "install.complete"
        assert frames[0].actor == "A5"
        assert frames[0].seq == 0
        assert frames[1].kind == "profile.declared"
        assert frames[1].payload["profile"] == "P-Local"
        assert frames[1].seq == 1


def test_init_refuses_reinit_without_force():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp)
        with pytest.raises(FileExistsError):
            init_aios_home(tmp)


def test_init_force_reinitializes():
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        # Re-init as P-Enterprise (the loader will refuse later, but init
        # itself must accept any valid profile declaration).
        result = init_aios_home(tmp, profile="P-Enterprise", force=True)
        config = read_config(tmp)
        assert config["profile"] == "P-Enterprise"
        assert result.install_seq >= 2  # new install event past old chain


def test_init_rejects_unknown_profile():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(ValueError):
            init_aios_home(tmp, profile="P-Bogus")


def test_valid_profiles_complete():
    assert set(VALID_PROFILES) == {
        "P-Local", "P-Enterprise", "P-Airgap", "P-HighAssurance",
    }


def test_is_initialized_false_for_empty_dir():
    with tempfile.TemporaryDirectory() as tmp:
        assert not is_initialized(tmp)
        init_aios_home(tmp)
        assert is_initialized(tmp)
