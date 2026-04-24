"""Tests for SK-PRECEDENT-MATCH (sprint 28)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.skills import default_skill_registry
from aios.skills.precedent_match import SKILL_ID, sk_precedent_match


def _write_adr(adr_dir: Path, filename: str, adr_id: str, status: str, body: str) -> None:
    adr_dir.mkdir(parents=True, exist_ok=True)
    (adr_dir / filename).write_text(
        f"---\nid: {adr_id}\nstatus: {status}\n---\n{body}\n",
        encoding="utf-8",
    )


# ------------------------------------------------------------------------


def test_skill_registered():
    assert default_skill_registry.has(SKILL_ID)


def test_no_adrs_returns_empty(tmp_path: Path):
    result = sk_precedent_match({"root": str(tmp_path), "query": "anything"})
    assert result == {"total_adrs": 0, "matches": []}


def test_exact_match_scores_high(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "ADR-0001", "Accepted",
               "Pricing must be synchronous. Latency budget is 50ms.")
    _write_adr(adr_dir, "0002.md", "ADR-0002", "Accepted",
               "Logging format is JSON lines with structured fields.")

    result = sk_precedent_match({
        "root": str(tmp_path),
        "query": "pricing latency synchronous",
    })
    assert result["total_adrs"] == 2
    assert len(result["matches"]) >= 1
    # ADR-0001 should win on this query.
    assert result["matches"][0]["adr_id"] == "ADR-0001"
    assert result["matches"][0]["score"] > 0.0


def test_unrelated_query_returns_below_threshold(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "ADR-0001", "Accepted", "Pricing synchronous latency.")
    result = sk_precedent_match({
        "root": str(tmp_path),
        "query": "quantum unicorn typography",
        "min_score": 0.5,
    })
    assert result["matches"] == []


def test_top_k_respected(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    for i in range(5):
        _write_adr(
            adr_dir, f"{i:04d}.md", f"ADR-{i:04d}", "Accepted",
            f"Synchronous pricing option {i}.",
        )
    result = sk_precedent_match({
        "root": str(tmp_path),
        "query": "synchronous pricing",
        "top_k": 2,
    })
    assert len(result["matches"]) == 2


def test_matches_ordered_by_score(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "ADR-0001", "Accepted",
               "Pricing pricing pricing synchronous.")
    _write_adr(adr_dir, "0002.md", "ADR-0002", "Accepted",
               "Logging structure.")
    _write_adr(adr_dir, "0003.md", "ADR-0003", "Accepted",
               "Pricing synchronous once.")
    result = sk_precedent_match({
        "root": str(tmp_path),
        "query": "pricing synchronous",
        "min_score": 0.01,
    })
    scores = [m["score"] for m in result["matches"]]
    assert scores == sorted(scores, reverse=True)


def test_snippet_trimmed(tmp_path: Path):
    long_body = "synchronous " * 200
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "ADR-0001", "Accepted", long_body)
    result = sk_precedent_match({
        "root": str(tmp_path),
        "query": "synchronous",
    })
    snippet = result["matches"][0]["snippet"]
    assert len(snippet) <= 200


def test_invoke_via_registry(tmp_path: Path):
    adr_dir = tmp_path / "adrs"
    _write_adr(adr_dir, "0001.md", "ADR-0001", "Accepted", "Pricing synchronous.")
    result = default_skill_registry.invoke(
        SKILL_ID, {"root": str(tmp_path), "query": "pricing"},
    )
    assert result["total_adrs"] == 1
    assert result["matches"]


def test_missing_query_rejected(tmp_path: Path):
    from aios.skills.base import SkillInputError
    with pytest.raises(SkillInputError, match="query"):
        default_skill_registry.invoke(SKILL_ID, {"root": str(tmp_path)})


def test_empty_query_rejected(tmp_path: Path):
    """min_length=1 on the query schema."""
    from aios.skills.base import SkillInputError
    with pytest.raises(SkillInputError):
        default_skill_registry.invoke(SKILL_ID,
                                      {"root": str(tmp_path), "query": ""})
