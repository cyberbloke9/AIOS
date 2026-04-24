"""Tests for package integrity manifest + verifier (sprint 52)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.cli import main
from aios.distribution.integrity import (
    IntegrityManifest,
    build_integrity_manifest,
    verify_install,
)


# Helpers ----------------------------------------------------------------


def _make_tree(root: Path, files: dict[str, str]) -> None:
    """Write `files` = {relative_path: content}."""
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


# build_integrity_manifest -----------------------------------------------


def test_manifest_covers_every_source_file(tmp_path: Path):
    _make_tree(tmp_path, {
        "a.py": "print('a')\n",
        "pkg/__init__.py": "",
        "pkg/util.py": "def f(): return 1\n",
    })
    m = build_integrity_manifest(tmp_path)
    paths = sorted(f.path for f in m.files)
    assert paths == ["a.py", "pkg/__init__.py", "pkg/util.py"]


def test_manifest_file_entry_fields():
    """Each FileEntry has path, sha256, and size; sha256 is 64 hex chars."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _make_tree(root, {"x.py": "hello"})
        m = build_integrity_manifest(root)
        entry = next(f for f in m.files if f.path == "x.py")
        assert len(entry.sha256) == 64
        assert entry.size == len("hello")


def test_manifest_excludes_pycache_and_git(tmp_path: Path):
    _make_tree(tmp_path, {
        "real.py": "x",
        "__pycache__/real.cpython-312.pyc": "compiled",
        ".git/HEAD": "ref: refs/heads/main",
    })
    m = build_integrity_manifest(tmp_path)
    paths = {f.path for f in m.files}
    assert "real.py" in paths
    assert "__pycache__/real.cpython-312.pyc" not in paths
    assert ".git/HEAD" not in paths


def test_manifest_extension_filter(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "x", "b.pyc": "compiled", "c.md": "docs"})
    m = build_integrity_manifest(tmp_path, include_extensions=(".py",))
    paths = {f.path for f in m.files}
    assert paths == {"a.py"}


def test_manifest_tree_sha_deterministic(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1", "b.py": "2"})
    m1 = build_integrity_manifest(tmp_path)
    m2 = build_integrity_manifest(tmp_path)
    assert m1.tree_sha256 == m2.tree_sha256


def test_manifest_tree_sha_changes_when_file_changes(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1"})
    before = build_integrity_manifest(tmp_path).tree_sha256
    _make_tree(tmp_path, {"a.py": "2"})
    after = build_integrity_manifest(tmp_path).tree_sha256
    assert before != after


def test_manifest_rejects_missing_root(tmp_path: Path):
    with pytest.raises(NotADirectoryError):
        build_integrity_manifest(tmp_path / "nope")


# JSON round-trip --------------------------------------------------------


def test_manifest_json_round_trip(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1", "b.py": "2"})
    m = build_integrity_manifest(tmp_path)
    path = tmp_path / "m.json"
    m.to_json_path(path)
    loaded = IntegrityManifest.from_json_path(path)
    assert loaded.tree_sha256 == m.tree_sha256
    assert len(loaded.files) == len(m.files)


def test_manifest_rejects_unsupported_version(tmp_path: Path):
    data = {
        "manifest_version": "99.0",
        "root": "x",
        "generated_iso": "t",
        "files": [],
    }
    (tmp_path / "m.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unsupported"):
        IntegrityManifest.from_json_path(tmp_path / "m.json")


# verify_install ---------------------------------------------------------


def test_verify_clean_install_is_ok(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1", "pkg/b.py": "2"})
    m = build_integrity_manifest(tmp_path)
    report = verify_install(tmp_path, m)
    assert report.ok is True
    assert report.missing == ()
    assert report.mismatched == ()
    assert report.extra == ()


def test_verify_detects_missing_file(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1", "b.py": "2"})
    m = build_integrity_manifest(tmp_path)
    (tmp_path / "b.py").unlink()
    report = verify_install(tmp_path, m)
    assert report.ok is False
    assert "b.py" in report.missing


def test_verify_detects_modified_file(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1"})
    m = build_integrity_manifest(tmp_path)
    (tmp_path / "a.py").write_text("CHANGED", encoding="utf-8")
    report = verify_install(tmp_path, m)
    assert report.ok is False
    assert "a.py" in report.mismatched


def test_verify_detects_extra_file(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1"})
    m = build_integrity_manifest(tmp_path)
    (tmp_path / "extra.py").write_text("new", encoding="utf-8")
    report = verify_install(tmp_path, m)
    assert report.ok is False
    assert "extra.py" in report.extra


def test_verify_allow_extras_ignores_new_files(tmp_path: Path):
    _make_tree(tmp_path, {"a.py": "1"})
    m = build_integrity_manifest(tmp_path)
    (tmp_path / "extra.py").write_text("new", encoding="utf-8")
    report = verify_install(tmp_path, m, check_extras=False)
    assert report.ok is True
    assert report.extra == ()


# CLI --------------------------------------------------------------------


def test_cli_integrity_manifest_to_file(tmp_path: Path, capsys):
    src = tmp_path / "src"
    _make_tree(src, {"a.py": "1"})
    manifest_path = tmp_path / "m.json"
    rc = main(["integrity-manifest", str(src), "--output", str(manifest_path)])
    assert rc == 0
    assert manifest_path.exists()
    out = capsys.readouterr().out
    assert "tree_sha256" in out


def test_cli_verify_install_ok(tmp_path: Path, capsys):
    src = tmp_path / "pkg"
    _make_tree(src, {"a.py": "1", "b.py": "2"})
    manifest_path = tmp_path / "m.json"
    main(["integrity-manifest", str(src), "--output", str(manifest_path)])
    capsys.readouterr()

    rc = main(["verify-install", str(src), "--manifest", str(manifest_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK" in out


def test_cli_verify_install_fail_exit_12(tmp_path: Path, capsys):
    src = tmp_path / "pkg"
    _make_tree(src, {"a.py": "1"})
    manifest_path = tmp_path / "m.json"
    main(["integrity-manifest", str(src), "--output", str(manifest_path)])
    capsys.readouterr()

    # Tamper
    (src / "a.py").write_text("CHANGED", encoding="utf-8")
    rc = main(["verify-install", str(src), "--manifest", str(manifest_path)])
    assert rc == 12
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "a.py" in out


def test_cli_verify_install_bad_manifest_exit_2(tmp_path: Path, capsys):
    rc = main(["verify-install", str(tmp_path), "--manifest", str(tmp_path / "nope.json")])
    assert rc == 2


def test_cli_integrity_commands_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "integrity-manifest" in out
    assert "verify-install" in out
