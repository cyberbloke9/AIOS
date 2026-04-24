"""Tests for multi-channel bootstrap anchor verification (sprint 54)."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aios.cli import main
from aios.distribution.bootstrap import (
    BootstrapAnchorError,
    Channel,
    load_root_metadata,
    verify_bootstrap_anchor,
)


def _fp(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# verify_bootstrap_anchor
# ---------------------------------------------------------------------------


def test_two_channels_agree_passes():
    root = b"root-metadata-bytes"
    fp = _fp(root)
    report = verify_bootstrap_anchor(
        [Channel("website", fp), Channel("git", fp)],
        root_metadata_bytes=root,
    )
    assert report.ok is True
    assert report.agreed_fingerprint == fp
    assert report.root_metadata_sha256 == fp


def test_three_channels_agree_passes():
    root = b"stuff"
    fp = _fp(root)
    report = verify_bootstrap_anchor(
        [Channel("website", fp), Channel("git", fp), Channel("rekor", fp)],
        root_metadata_bytes=root,
    )
    assert report.ok is True


def test_single_channel_fails():
    root = b"stuff"
    fp = _fp(root)
    report = verify_bootstrap_anchor(
        [Channel("website", fp)],
        root_metadata_bytes=root,
    )
    assert report.ok is False
    assert any("channels" in r for r in report.reasons)


def test_disagreeing_channels_fail():
    root = b"stuff"
    fp = _fp(root)
    wrong_fp = _fp(b"different bytes")
    report = verify_bootstrap_anchor(
        [Channel("website", fp), Channel("git", wrong_fp)],
        root_metadata_bytes=root,
    )
    assert report.ok is False
    assert any("disagree" in r for r in report.reasons)


def test_root_metadata_mismatch_fails():
    fp = _fp(b"claimed bytes")
    actual_root = b"something else entirely"
    report = verify_bootstrap_anchor(
        [Channel("website", fp), Channel("git", fp)],
        root_metadata_bytes=actual_root,
    )
    assert report.ok is False
    assert any("does not match" in r for r in report.reasons)


def test_without_root_metadata_accepts_if_channels_agree():
    fp = _fp(b"whatever")
    report = verify_bootstrap_anchor(
        [Channel("a", fp), Channel("b", fp)],
        root_metadata_bytes=None,   # operator verifies separately
    )
    assert report.ok is True
    assert report.root_metadata_sha256 is None


def test_min_channels_parameter():
    """Raising the bar to 3 rejects a 2-channel agreement."""
    fp = _fp(b"x")
    report = verify_bootstrap_anchor(
        [Channel("a", fp), Channel("b", fp)],
        min_channels=3,
    )
    assert report.ok is False


def test_fingerprint_case_normalization():
    root = b"a"
    fp = _fp(root)
    # Channels advertise with mixed case — normalizer lowercases them
    report = verify_bootstrap_anchor(
        [Channel("a", fp.upper()), Channel("b", fp)],
        root_metadata_bytes=root,
    )
    assert report.ok is True
    assert report.agreed_fingerprint == fp.lower()


def test_invalid_fingerprint_length_raises():
    with pytest.raises(BootstrapAnchorError, match="SHA-256"):
        verify_bootstrap_anchor(
            [Channel("a", "tooshort"), Channel("b", "tooshort")],
        )


def test_invalid_fingerprint_non_hex_raises():
    with pytest.raises(BootstrapAnchorError):
        verify_bootstrap_anchor(
            [Channel("a", "z" * 64), Channel("b", "z" * 64)],
        )


# load_root_metadata helper ----------------------------------------------


def test_load_root_metadata_returns_bytes(tmp_path: Path):
    p = tmp_path / "root.cbor"
    p.write_bytes(b"\xde\xad\xbe\xef")
    assert load_root_metadata(p) == b"\xde\xad\xbe\xef"


# ---------------------------------------------------------------------------
# CLI — aios bootstrap-verify
# ---------------------------------------------------------------------------


def test_cli_happy_path(tmp_path: Path, capsys):
    root = tmp_path / "root.cbor"
    root.write_bytes(b"the-root-metadata")
    fp = _fp(b"the-root-metadata")

    rc = main([
        "bootstrap-verify",
        "--channel", f"website={fp}",
        "--channel", f"git={fp}",
        "--root-metadata", str(root),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK" in out
    assert fp in out


def test_cli_disagreement_exits_13(tmp_path: Path, capsys):
    fp_a = "a" * 64
    fp_b = "b" * 64
    rc = main([
        "bootstrap-verify",
        "--channel", f"website={fp_a}",
        "--channel", f"git={fp_b}",
    ])
    assert rc == 13
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "disagree" in out


def test_cli_root_mismatch_exits_13(tmp_path: Path, capsys):
    root = tmp_path / "root.cbor"
    root.write_bytes(b"actual bytes")
    claimed_fp = _fp(b"claimed bytes")
    rc = main([
        "bootstrap-verify",
        "--channel", f"website={claimed_fp}",
        "--channel", f"git={claimed_fp}",
        "--root-metadata", str(root),
    ])
    assert rc == 13


def test_cli_bad_channel_format_exits_2(tmp_path: Path, capsys):
    rc = main([
        "bootstrap-verify",
        "--channel", "no-equals-sign-here",
        "--channel", "x=" + ("0" * 64),
    ])
    assert rc == 2


def test_cli_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "bootstrap-verify" in out
