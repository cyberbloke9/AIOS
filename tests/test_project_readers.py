"""Tests for aios.project.readers (sprint 23)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.project import (
    ADRParseError, InvariantParseError,
    read_adrs, read_invariants,
)
from aios.verification.conservation_scan import ADREvent, Invariant


# Invariants ---------------------------------------------------------------


def test_read_invariants_yaml(tmp_path: Path):
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.yaml").write_text(
        "invariants:\n"
        "  - id: INV-001\n"
        "    source: principle\n"
        "    statement: Interfaces are frozen.\n"
        "  - id: INV-002\n"
        "    source: security\n"
        "    statement: PII is never logged.\n",
        encoding="utf-8",
    )
    invs = read_invariants(tmp_path)
    assert len(invs) == 2
    ids = {inv.id for inv in invs}
    assert ids == {"INV-001", "INV-002"}


def test_read_invariants_json(tmp_path: Path):
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.json").write_text(json.dumps({
        "invariants": [
            {"id": "INV-001", "source": "principle", "statement": "X"},
        ],
    }))
    invs = read_invariants(tmp_path)
    assert len(invs) == 1
    (first,) = invs
    assert isinstance(first, Invariant)
    assert first.id == "INV-001"


def test_read_invariants_missing_file_returns_empty(tmp_path: Path):
    # No .aios/ dir at all
    assert read_invariants(tmp_path) == frozenset()


def test_read_invariants_empty_aios_dir_returns_empty(tmp_path: Path):
    (tmp_path / ".aios").mkdir()
    assert read_invariants(tmp_path) == frozenset()


def test_read_invariants_duplicate_id_rejected(tmp_path: Path):
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.json").write_text(json.dumps({
        "invariants": [
            {"id": "INV-001", "source": "principle", "statement": "A"},
            {"id": "INV-001", "source": "security", "statement": "B"},
        ],
    }))
    with pytest.raises(InvariantParseError, match="duplicate"):
        read_invariants(tmp_path)


def test_read_invariants_invalid_source_rejected(tmp_path: Path):
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.json").write_text(json.dumps({
        "invariants": [
            {"id": "INV-001", "source": "imaginary", "statement": "X"},
        ],
    }))
    with pytest.raises(InvariantParseError, match="source"):
        read_invariants(tmp_path)


def test_read_invariants_missing_top_level_key(tmp_path: Path):
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.json").write_text(json.dumps({"nope": []}))
    with pytest.raises(InvariantParseError, match="invariants"):
        read_invariants(tmp_path)


def test_read_invariants_non_mapping_root(tmp_path: Path):
    aios = tmp_path / ".aios"
    aios.mkdir()
    (aios / "invariants.json").write_text(json.dumps(["not", "a", "mapping"]))
    with pytest.raises(InvariantParseError, match="mapping"):
        read_invariants(tmp_path)


# ADRs ---------------------------------------------------------------------


_ADR_ACCEPTED = """\
---
id: ADR-0001
status: Accepted
date: 2026-03-15
---
# ADR-0001 — Accept pricing synchronicity
Context, decision, consequences.
"""

_ADR_WITH_REMOVES = """\
---
id: ADR-0042
status: Accepted
removes: [INV-002]
---
# ADR-0042 — Retire pricing synchronicity
"""

_ADR_SUPERSEDES = """\
---
id: ADR-0101
status: Accepted
deprecates: ADR-0001
---
# ADR-0101 — New pricing architecture
"""


def test_read_adrs_basic(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "0001-accept.md").write_text(_ADR_ACCEPTED, encoding="utf-8")
    adrs = read_adrs(tmp_path)
    assert len(adrs) == 1
    a = adrs[0]
    assert isinstance(a, ADREvent)
    assert a.adr_id == "ADR-0001"
    assert a.status == "Accepted"
    assert a.removes == frozenset()


def test_read_adrs_with_removes(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "0042-retire.md").write_text(_ADR_WITH_REMOVES, encoding="utf-8")
    adrs = read_adrs(tmp_path)
    assert adrs[0].removes == frozenset({"INV-002"})


def test_read_adrs_deprecates(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "0101-supersede.md").write_text(_ADR_SUPERSEDES, encoding="utf-8")
    adrs = read_adrs(tmp_path)
    assert adrs[0].deprecates == "ADR-0001"


def test_read_adrs_accepts_docs_adr_path(tmp_path: Path):
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0001.md").write_text(_ADR_ACCEPTED, encoding="utf-8")
    adrs = read_adrs(tmp_path)
    assert len(adrs) == 1


def test_read_adrs_missing_dir_returns_empty(tmp_path: Path):
    assert read_adrs(tmp_path) == tuple()


def test_read_adrs_ignores_non_adr_markdown(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "README.md").write_text("# This is just a README.\n", encoding="utf-8")
    (adr_dir / "0001-adr.md").write_text(_ADR_ACCEPTED, encoding="utf-8")
    adrs = read_adrs(tmp_path)
    assert len(adrs) == 1
    assert adrs[0].adr_id == "ADR-0001"


def test_read_adrs_missing_id_rejected(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "bad.md").write_text(
        "---\nstatus: Accepted\n---\n# no id\n", encoding="utf-8"
    )
    with pytest.raises(ADRParseError, match="id"):
        read_adrs(tmp_path)


def test_read_adrs_invalid_status_rejected(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "bad.md").write_text(
        "---\nid: ADR-1\nstatus: Maybe\n---\n# bad status\n", encoding="utf-8"
    )
    with pytest.raises(ADRParseError, match="status"):
        read_adrs(tmp_path)


def test_read_adrs_duplicate_id_rejected(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "a.md").write_text(_ADR_ACCEPTED, encoding="utf-8")
    (adr_dir / "b.md").write_text(_ADR_ACCEPTED, encoding="utf-8")  # same id
    with pytest.raises(ADRParseError, match="duplicate"):
        read_adrs(tmp_path)


def test_read_adrs_unclosed_front_matter_rejected(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "bad.md").write_text(
        "---\nid: ADR-9\nstatus: Accepted\n# never closed\n",
        encoding="utf-8",
    )
    with pytest.raises(ADRParseError, match="never closed"):
        read_adrs(tmp_path)


def test_read_adrs_ordered_by_filename(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    adr_dir.mkdir()
    (adr_dir / "0002.md").write_text(
        "---\nid: ADR-2\nstatus: Accepted\n---\n", encoding="utf-8"
    )
    (adr_dir / "0001.md").write_text(
        "---\nid: ADR-1\nstatus: Accepted\n---\n", encoding="utf-8"
    )
    adrs = read_adrs(tmp_path)
    assert [a.adr_id for a in adrs] == ["ADR-1", "ADR-2"]
