"""Tests for calibration corpus quality rules (sprint 34)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aios.verification.corpus import (
    CorpusExample,
    CorpusQualityError,
    CorpusSpec,
    IndependenceAudit,
    validate_corpus,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _good_audit() -> IndependenceAudit:
    return IndependenceAudit(
        method="sha256-leak-check",
        last_run_iso=_iso_now(),
        overlap_detected=False,
        signer="human-verifier",
    )


def _make_corpus(
    *,
    size: int = 300,
    adversarial_count: int = 30,          # 10% of 300 (>= 5% required)
    provenance: str = "human-labeler",
    audit: IndependenceAudit | None = None,
    recency_policy: str = "weekly",
    last_refresh_iso: str | None = None,
    class_imbalance: dict | None = None,
) -> CorpusSpec:
    examples = []
    for i in range(size):
        examples.append(CorpusExample(
            input={"x": i},
            label=i % 2,
            provenance=provenance,
            is_adversarial=i < adversarial_count,
        ))
    declared_adv = adversarial_count / size if size else 0.0
    return CorpusSpec(
        path="corpus.jsonl",
        sha256="0" * 64,
        examples=tuple(examples),
        independence_audit=audit or _good_audit(),
        recency_policy=recency_policy,  # type: ignore[arg-type]
        last_refresh_iso=last_refresh_iso or _iso_now(),
        declared_adversarial_share=declared_adv,
        class_imbalance=class_imbalance,
    )


# Rule 1 — minimum size --------------------------------------------------


def test_local_requires_300():
    with pytest.raises(CorpusQualityError) as exc:
        validate_corpus(_make_corpus(size=299), impact="local")
    assert exc.value.rule == "minimum_size"


def test_local_exactly_300_passes():
    validate_corpus(_make_corpus(size=300), impact="local")


def test_subsystem_requires_1000():
    with pytest.raises(CorpusQualityError, match="1000"):
        validate_corpus(_make_corpus(size=999), impact="subsystem")


def test_system_wide_requires_3000():
    with pytest.raises(CorpusQualityError, match="3000"):
        validate_corpus(_make_corpus(size=2999), impact="system_wide")


def test_system_wide_3000_passes():
    validate_corpus(_make_corpus(size=3000, adversarial_count=300),
                    impact="system_wide")


# Rule 2 — labeling provenance -------------------------------------------


def test_empty_provenance_rejected():
    with pytest.raises(CorpusQualityError) as exc:
        validate_corpus(_make_corpus(provenance=""), impact="local")
    assert exc.value.rule == "labeling_provenance"


def test_provenance_must_start_with_human_or_oracle():
    with pytest.raises(CorpusQualityError, match="human"):
        validate_corpus(_make_corpus(provenance="machine-rng"), impact="local")


def test_oracle_prefix_accepted():
    validate_corpus(_make_corpus(provenance="oracle-regex"), impact="local")


# Rule 3 — independence audit --------------------------------------------


def test_unsigned_audit_rejected():
    bad = IndependenceAudit(
        method="x", last_run_iso=_iso_now(),
        overlap_detected=False, signer="",
    )
    with pytest.raises(CorpusQualityError) as exc:
        validate_corpus(_make_corpus(audit=bad), impact="local")
    assert exc.value.rule == "independence"


def test_overlap_detected_rejected():
    bad = IndependenceAudit(
        method="sha256", last_run_iso=_iso_now(),
        overlap_detected=True, signer="human-x",
    )
    with pytest.raises(CorpusQualityError, match="overlap"):
        validate_corpus(_make_corpus(audit=bad), impact="local")


# Rule 4 — recency -------------------------------------------------------


def test_stale_weekly_corpus_rejected():
    with pytest.raises(CorpusQualityError) as exc:
        validate_corpus(
            _make_corpus(recency_policy="weekly",
                         last_refresh_iso=_iso_days_ago(10)),
            impact="local",
        )
    assert exc.value.rule == "recency"


def test_fresh_weekly_corpus_accepted():
    validate_corpus(
        _make_corpus(recency_policy="weekly",
                     last_refresh_iso=_iso_days_ago(3)),
        impact="local",
    )


def test_monthly_accepts_older_than_weekly():
    validate_corpus(
        _make_corpus(recency_policy="monthly",
                     last_refresh_iso=_iso_days_ago(20)),
        impact="local",
    )


def test_stale_monthly_corpus_rejected():
    with pytest.raises(CorpusQualityError, match="recency"):
        validate_corpus(
            _make_corpus(recency_policy="monthly",
                         last_refresh_iso=_iso_days_ago(45)),
            impact="local",
        )


def test_bad_iso_date_rejected():
    with pytest.raises(CorpusQualityError, match="ISO 8601"):
        validate_corpus(
            _make_corpus(last_refresh_iso="nonsense"),
            impact="local",
        )


# Rule 5 — distribution --------------------------------------------------


def test_declared_imbalance_must_match_actual():
    # Actual is 50/50; declaring 90/10 should be rejected
    bad = {"class_0": 0.9, "class_1": 0.1}
    with pytest.raises(CorpusQualityError) as exc:
        validate_corpus(_make_corpus(class_imbalance=bad), impact="local")
    assert exc.value.rule == "distribution"


def test_honest_imbalance_accepted():
    good = {"class_0": 0.5, "class_1": 0.5}
    validate_corpus(_make_corpus(class_imbalance=good), impact="local")


# Rule 6 — adversarial coverage ------------------------------------------


def test_below_5_percent_adversarial_rejected():
    # 10 adversarial out of 300 = 3.3%
    with pytest.raises(CorpusQualityError) as exc:
        validate_corpus(_make_corpus(adversarial_count=10), impact="local")
    assert exc.value.rule == "adversarial_coverage"


def test_exactly_5_percent_accepted():
    validate_corpus(_make_corpus(size=300, adversarial_count=15), impact="local")


def test_declared_adversarial_must_match_actual():
    # Build a corpus where declared share lies about actual
    c = _make_corpus(size=300, adversarial_count=30)
    fraud = CorpusSpec(**{**c.__dict__, "declared_adversarial_share": 0.25})
    with pytest.raises(CorpusQualityError, match="declarations must match"):
        validate_corpus(fraud, impact="local")
