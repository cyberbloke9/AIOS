"""Smoke-test the shipped demo project (sprint 31)."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from aios.cli import main
from aios.project import read_adrs, read_invariants


def _copy_demo_to(tmp_path: Path) -> Path:
    """Copy examples/demo-project into tmp_path so tests don't pollute it."""
    repo_root = Path(__file__).resolve().parent.parent
    src = repo_root / "examples" / "demo-project"
    dst = tmp_path / "demo-project"
    shutil.copytree(src, dst)
    return dst


def test_demo_project_has_three_invariants(tmp_path: Path):
    demo = _copy_demo_to(tmp_path)
    invs = read_invariants(demo)
    assert len(invs) == 3
    assert {i.id for i in invs} == {"INV-001", "INV-002", "INV-003"}


def test_demo_project_has_two_adrs(tmp_path: Path):
    demo = _copy_demo_to(tmp_path)
    adrs = read_adrs(demo)
    assert len(adrs) == 2
    assert {a.adr_id for a in adrs} == {"ADR-0001", "ADR-0002"}
    assert all(a.status == "Accepted" for a in adrs)


def test_demo_adopt_and_check_clean(tmp_path: Path, capsys):
    demo = _copy_demo_to(tmp_path)
    main(["adopt", str(demo)])
    capsys.readouterr()
    rc = main(["check", "--repo", str(demo)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PROMOTED" in out
    assert "invariants:     3" in out
    assert "ADRs:           2" in out
    assert "ADR structural violations: 0" in out


def test_demo_catches_silent_removal(tmp_path: Path, capsys):
    """End-to-end replay of the demo.md walkthrough: commit baseline,
    silently drop INV-003, then aios check --before HEAD~1 catches it."""
    demo = _copy_demo_to(tmp_path)
    subprocess.run(["git", "-C", str(demo), "init", "-q", "-b", "main"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(demo), "config", "user.email", "t@e.com"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(demo), "config", "user.name", "T"],
                   check=True, capture_output=True)

    main(["adopt", str(demo)])
    capsys.readouterr()

    subprocess.run(["git", "-C", str(demo), "add",
                    ".aios/invariants.yaml", "adrs/", "README.md"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(demo), "commit", "-q", "-m", "baseline"],
                   check=True, capture_output=True)

    # Silently drop INV-003
    inv_yaml = demo / ".aios" / "invariants.yaml"
    text = inv_yaml.read_text(encoding="utf-8")
    # Cut everything from the INV-003 block (- id: INV-003) through the
    # end of its statement line.
    lines = text.splitlines(keepends=True)
    kept = []
    skip = False
    for line in lines:
        if skip:
            if line.startswith("  - id:") or not line.startswith("  "):
                skip = False
            else:
                continue
        if line.strip().startswith("- id: INV-003"):
            # Drop the "  - id:" line and its following statement/source lines
            skip = True
            continue
        kept.append(line)
    inv_yaml.write_text("".join(kept), encoding="utf-8")

    subprocess.run(["git", "-C", str(demo), "commit", "-qam", "drop INV-003"],
                   check=True, capture_output=True)

    capsys.readouterr()
    rc = main(["check", "--repo", str(demo),
               "--before", "HEAD~1", "--after", "HEAD"])
    assert rc == 4
    out = capsys.readouterr().out
    assert "ABORTED" in out
    assert "[BREACH] P_Q1_invariant_integrity" in out
