"""Tests for P_acceptance_tests sandbox mode (sprint 68).

Keep these tests fast (no subprocess pytest runs) so they don't
duplicate the ~2-minute test_acceptance_tests suite. Tests here
focus on the sandbox-specific pieces: env scrubbing + preexec_fn
selection + 'sandbox' flag propagation into the report.
"""
from __future__ import annotations

import os

import pytest

from aios.verification.acceptance_tests import (
    _build_preexec_fn,
    scrub_env,
)


# ---------------------------------------------------------------------------
# scrub_env
# ---------------------------------------------------------------------------


def test_scrub_keeps_normal_vars():
    kept = scrub_env({"PATH": "/usr/bin", "HOME": "/home/user",
                      "LANG": "en_US.UTF-8"})
    assert kept == {"PATH": "/usr/bin", "HOME": "/home/user",
                    "LANG": "en_US.UTF-8"}


def test_scrub_strips_tokens():
    kept = scrub_env({
        "GITHUB_TOKEN": "ghp_xxx",
        "SLACK_BOT_TOKEN": "xoxb_xxx",
        "PATH": "/bin",
    })
    assert "GITHUB_TOKEN" not in kept
    assert "SLACK_BOT_TOKEN" not in kept
    assert kept["PATH"] == "/bin"


def test_scrub_strips_api_keys():
    kept = scrub_env({
        "OPENAI_API_KEY": "sk-xxx",
        "ANTHROPIC_API_KEY": "sk-ant-xxx",
        "MY_CUSTOM_API_KEY": "sk-custom",
        "PATH": "/bin",
    })
    assert "OPENAI_API_KEY" not in kept
    assert "ANTHROPIC_API_KEY" not in kept
    assert "MY_CUSTOM_API_KEY" not in kept


def test_scrub_strips_secrets():
    kept = scrub_env({
        "AWS_SECRET_ACCESS_KEY": "xxx",
        "SOMETHING_SECRET": "xxx",
        "JWT_SIGNING_KEY": "xxx",
        "DB_PASSWORD": "xxx",
        "PATH": "/bin",
    })
    for removed in ("AWS_SECRET_ACCESS_KEY", "SOMETHING_SECRET",
                    "JWT_SIGNING_KEY", "DB_PASSWORD"):
        assert removed not in kept
    assert "PATH" in kept


def test_scrub_strips_database_url():
    kept = scrub_env({"DATABASE_URL": "postgres://x", "PATH": "/bin"})
    assert "DATABASE_URL" not in kept


def test_scrub_case_insensitive():
    """Variables with unusual casing still caught."""
    kept = scrub_env({
        "my_token": "x",
        "Some_Private_Key": "x",
        "path": "/bin",
    })
    assert "my_token" not in kept
    assert "Some_Private_Key" not in kept
    assert "path" in kept


def test_scrub_empty_env_is_empty():
    assert scrub_env({}) == {}


def test_scrub_is_pure():
    """scrub_env must not mutate the input."""
    original = {"GITHUB_TOKEN": "x", "PATH": "/bin"}
    copy = dict(original)
    scrub_env(original)
    assert original == copy   # unchanged


# ---------------------------------------------------------------------------
# _build_preexec_fn
# ---------------------------------------------------------------------------


def test_preexec_none_on_windows():
    """On Windows, preexec_fn is always None (POSIX-only)."""
    if os.name != "nt":
        pytest.skip("this assertion is Windows-only")
    assert _build_preexec_fn(512) is None


def test_preexec_none_when_no_memory_limit():
    assert _build_preexec_fn(None) is None


def test_preexec_posix_returns_callable():
    """POSIX returns a callable that setrlimit's the memory limit."""
    if os.name == "nt":
        pytest.skip("POSIX-only behavior")
    fn = _build_preexec_fn(256)
    assert callable(fn)
    # Don't actually call it — would affect this process's RLIMIT_AS


# ---------------------------------------------------------------------------
# Report flag
# ---------------------------------------------------------------------------


def test_sandbox_flag_in_report(tmp_path):
    """A passing sandboxed run carries sandbox=True in the output."""
    from aios.verification.acceptance_tests import p_acceptance_tests

    class _Run:  # minimal RunState stand-in since p_acceptance_tests
        pass     # doesn't inspect it

    suite = tmp_path / "test_pass.py"
    suite.write_text("def test_a(): assert True\n", encoding="utf-8")
    result = p_acceptance_tests(_Run(), suite_path=suite, sandbox=True)
    assert result.get("sandbox") is True
    assert result["status"] == "preserved"


def test_sandbox_scrubs_token_from_subprocess(tmp_path, monkeypatch):
    """With sandbox=True, a FAKE_TOKEN in this process's env is NOT
    visible inside pytest. The test inside the spawned suite asserts
    os.environ does not contain FAKE_TOKEN."""
    from aios.verification.acceptance_tests import p_acceptance_tests

    class _Run:
        pass

    monkeypatch.setenv("FAKE_TOKEN", "s3cr3t")
    suite = tmp_path / "test_check.py"
    suite.write_text(
        "import os\n"
        "def test_scrubbed():\n"
        "    assert 'FAKE_TOKEN' not in os.environ\n",
        encoding="utf-8",
    )
    result = p_acceptance_tests(_Run(), suite_path=suite, sandbox=True)
    assert result["status"] == "preserved"


def test_without_sandbox_token_leaks_through(tmp_path, monkeypatch):
    """Baseline: without sandbox, the token IS visible."""
    from aios.verification.acceptance_tests import p_acceptance_tests

    class _Run:
        pass

    monkeypatch.setenv("FAKE_TOKEN", "s3cr3t")
    suite = tmp_path / "test_check.py"
    suite.write_text(
        "import os\n"
        "def test_visible():\n"
        "    assert os.environ.get('FAKE_TOKEN') == 's3cr3t'\n",
        encoding="utf-8",
    )
    result = p_acceptance_tests(_Run(), suite_path=suite, sandbox=False)
    assert result["status"] == "preserved"
