"""Tests for SK-ADR-CHECK (sprint 27)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.skills import default_skill_registry
from aios.skills.adr_check import SKILL_ID, sk_adr_check


def _write_adr(adr_dir: Path, filename: str, front_matter: str, body: str = "# adr\n") -> None:
    adr_dir.mkdir(parents=True, exist_ok=True)
    (adr_dir / filename).write_text(f"---\n{front_matter}\n---\n{body}", encoding="utf-8")


# Direct-call tests -------------------------------------------------------


def test_skill_registered():
    assert default_skill_registry.has(SKILL_ID)
    contract = default_skill_registry.get(SKILL_ID)
    assert contract.owner_authority == "A2"
    assert contract.implementation is not None


def test_no_adrs_means_no_violations(tmp_path: Path):
    result = sk_adr_check({"root": str(tmp_path)})
    assert result == {"count": 0, "violations": []}


def test_clean_adr_set_no_violations(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "id: ADR-0001\nstatus: Accepted")
    _write_adr(adr_dir, "0002.md", "id: ADR-0002\nstatus: Proposed")
    result = sk_adr_check({"root": str(tmp_path)})
    assert result["count"] == 0


def test_dangling_deprecates_flagged(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(
        adr_dir, "0101.md",
        "id: ADR-0101\nstatus: Accepted\ndeprecates: ADR-9999",
    )
    result = sk_adr_check({"root": str(tmp_path)})
    assert result["count"] == 1
    v = result["violations"][0]
    assert v["adr_id"] == "ADR-0101"
    assert v["kind"] == "dangling_deprecates"
    assert "ADR-9999" in v["detail"]


def test_deprecates_rejected_target_flagged(tmp_path: Path):
    """Can't deprecate a Rejected ADR — it was never law."""
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "id: ADR-0001\nstatus: Rejected")
    _write_adr(
        adr_dir, "0002.md",
        "id: ADR-0002\nstatus: Accepted\ndeprecates: ADR-0001",
    )
    result = sk_adr_check({"root": str(tmp_path)})
    assert result["count"] == 1
    v = result["violations"][0]
    assert v["adr_id"] == "ADR-0002"
    assert v["kind"] == "invalid_deprecation_target"
    assert "Rejected" in v["detail"]


def test_deprecates_proposed_target_flagged(tmp_path: Path):
    """Can't deprecate a not-yet-Accepted ADR."""
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "id: ADR-0001\nstatus: Proposed")
    _write_adr(
        adr_dir, "0002.md",
        "id: ADR-0002\nstatus: Accepted\ndeprecates: ADR-0001",
    )
    result = sk_adr_check({"root": str(tmp_path)})
    assert result["count"] == 1
    assert result["violations"][0]["kind"] == "invalid_deprecation_target"


def test_deprecates_accepted_target_ok(tmp_path: Path):
    """Deprecating an Accepted ADR is the happy path."""
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "id: ADR-0001\nstatus: Accepted")
    _write_adr(
        adr_dir, "0002.md",
        "id: ADR-0002\nstatus: Accepted\ndeprecates: ADR-0001",
    )
    result = sk_adr_check({"root": str(tmp_path)})
    assert result["count"] == 0


def test_rejected_removes_invariants_flagged(tmp_path: Path):
    """A Rejected ADR cannot authorize invariant removal."""
    adr_dir = tmp_path / "adrs"
    _write_adr(
        adr_dir, "0001.md",
        "id: ADR-0001\nstatus: Rejected\nremoves: [INV-001]",
    )
    result = sk_adr_check({"root": str(tmp_path)})
    assert result["count"] == 1
    v = result["violations"][0]
    assert v["kind"] == "rejected_removes_invariants"
    assert "INV-001" in v["detail"]


def test_multiple_violations_all_reported(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(
        adr_dir, "0001.md",
        "id: ADR-0001\nstatus: Rejected\nremoves: [INV-001]",
    )
    _write_adr(
        adr_dir, "0002.md",
        "id: ADR-0002\nstatus: Accepted\ndeprecates: ADR-DOES-NOT-EXIST",
    )
    result = sk_adr_check({"root": str(tmp_path)})
    assert result["count"] == 2
    kinds = {v["kind"] for v in result["violations"]}
    assert kinds == {"rejected_removes_invariants", "dangling_deprecates"}


# Registry invocation -----------------------------------------------------


def test_invoke_via_registry_round_trip(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "id: ADR-0001\nstatus: Accepted")
    result = default_skill_registry.invoke(SKILL_ID, {"root": str(tmp_path)})
    assert result == {"count": 0, "violations": []}


def test_invoke_rejects_missing_root():
    from aios.skills.base import SkillInputError
    with pytest.raises(SkillInputError, match="root"):
        default_skill_registry.invoke(SKILL_ID, {})


def test_invoke_rejects_extra_keys(tmp_path: Path):
    """additionalProperties: false on input_schema."""
    from aios.skills.base import SkillInputError
    with pytest.raises(SkillInputError):
        default_skill_registry.invoke(
            SKILL_ID, {"root": str(tmp_path), "surprise": 42}
        )
