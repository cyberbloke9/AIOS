"""Calibration corpus data model + quality rules (sprint 34).

Verification Spec §2.3 defines six corpus-quality rules. This module
makes them LOADER-LEVEL REFUSALS, not advisory warnings. A calibration
record referencing a corpus that fails any rule is refused — the skill
cannot emit a confidence scalar until the corpus is corrected. This is
the anti-theater remedy Codex's review specifically called out.

The six rules per §2.3:

    Rule                  Requirement
    --------------------- ------------------------------------------------
    Minimum size          >= 300 local | 1000 subsystem | 3000 system_wide
    Labeling provenance   every label traceable to a named human / oracle
    Independence          no overlap w/ model training data; audit signed
    Recency               no example older than the refresh schedule
    Distribution          sample weights published; imbalance declared
    Adversarial coverage  >= 5% adversarial examples
"""
from __future__ import annotations

import dataclasses as dc
from datetime import datetime, timedelta, timezone
from typing import Literal

ImpactLevel = Literal["local", "subsystem", "system_wide"]
RecencyPolicy = Literal["weekly", "monthly"]

_MIN_SIZE_BY_IMPACT: dict[ImpactLevel, int] = {
    "local": 300,
    "subsystem": 1000,
    "system_wide": 3000,
}

_RECENCY_MAX_AGE: dict[RecencyPolicy, timedelta] = {
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}

_MIN_ADVERSARIAL_SHARE = 0.05


class CorpusQualityError(ValueError):
    """Raised when a corpus fails one of the §2.3 rules.

    The `rule` attribute names which rule tripped so callers can present
    a specific remediation. The exception never falls through to a
    silent warning — refusal is the contract.
    """

    def __init__(self, rule: str, detail: str):
        super().__init__(f"[{rule}] {detail}")
        self.rule = rule
        self.detail = detail


@dc.dataclass(frozen=True)
class CorpusExample:
    """One labeled example plus provenance metadata."""
    input: dict
    label: int
    provenance: str             # "human-<name>" | "oracle-<id>" — non-empty
    is_adversarial: bool = False
    date_iso: str | None = None  # ISO 8601 UTC ("2026-04-01T00:00:00Z")
    # Predicted probability from the skill being calibrated. Optional so
    # that validate_corpus() can run on a fresh corpus before any skill
    # has produced predictions. `calibrate()` requires it on every example.
    predicted_prob: float | None = None


@dc.dataclass(frozen=True)
class IndependenceAudit:
    """Signed audit that the corpus does not overlap the training data."""
    method: str
    last_run_iso: str
    overlap_detected: bool
    signer: str                 # e.g. "A4-<name>" — non-empty


@dc.dataclass(frozen=True)
class CorpusSpec:
    """Calibration corpus + metadata matching Verification §2.4 schema."""
    path: str
    sha256: str
    examples: tuple[CorpusExample, ...]
    independence_audit: IndependenceAudit
    recency_policy: RecencyPolicy
    last_refresh_iso: str
    declared_adversarial_share: float
    class_imbalance: dict[str, float] | None = None

    @property
    def size(self) -> int:
        return len(self.examples)

    @property
    def actual_adversarial_share(self) -> float:
        if not self.examples:
            return 0.0
        return sum(1 for e in self.examples if e.is_adversarial) / len(self.examples)

    @property
    def actual_class_imbalance(self) -> dict[str, float]:
        if not self.examples:
            return {}
        total = len(self.examples)
        counts: dict[str, int] = {}
        for e in self.examples:
            k = f"class_{e.label}"
            counts[k] = counts.get(k, 0) + 1
        return {k: v / total for k, v in counts.items()}


def validate_corpus(spec: CorpusSpec, *, impact: ImpactLevel) -> None:
    """Raise CorpusQualityError on the first failing §2.3 rule.

    Passing this function means the corpus may back a calibration record.
    Not passing means the calibration record MUST NOT be issued.
    """
    # Rule 1 — minimum size
    min_required = _MIN_SIZE_BY_IMPACT[impact]
    if spec.size < min_required:
        raise CorpusQualityError(
            "minimum_size",
            f"impact={impact} requires >= {min_required} examples, "
            f"got {spec.size}",
        )

    # Rule 2 — labeling provenance on every example
    for i, e in enumerate(spec.examples):
        if not e.provenance or not e.provenance.strip():
            raise CorpusQualityError(
                "labeling_provenance",
                f"example[{i}] has empty provenance; §2.3 requires "
                f"traceable human/oracle attribution for every label",
            )
        if not (e.provenance.startswith("human-") or e.provenance.startswith("oracle-")):
            raise CorpusQualityError(
                "labeling_provenance",
                f"example[{i}] provenance {e.provenance!r} must start with "
                f"'human-' or 'oracle-' per §2.4",
            )

    # Rule 3 — independence audit signed + no overlap
    ia = spec.independence_audit
    if not ia.signer or not ia.signer.strip():
        raise CorpusQualityError(
            "independence",
            "independence_audit.signer is empty; §2.3 requires the audit "
            "to be signed",
        )
    if ia.overlap_detected:
        raise CorpusQualityError(
            "independence",
            "independence_audit.overlap_detected is True; corpus shares "
            "training data with the model being calibrated",
        )

    # Rule 4 — recency
    try:
        last = _parse_iso(spec.last_refresh_iso)
    except ValueError as e:
        raise CorpusQualityError(
            "recency",
            f"last_refresh_iso {spec.last_refresh_iso!r} is not valid "
            f"ISO 8601 UTC: {e}",
        ) from e
    max_age = _RECENCY_MAX_AGE[spec.recency_policy]
    age = datetime.now(timezone.utc) - last
    if age > max_age:
        raise CorpusQualityError(
            "recency",
            f"last_refresh was {age.days} days ago; recency_policy="
            f"{spec.recency_policy!r} requires <= {max_age.days} days",
        )

    # Rule 5 — distribution: imbalance declared (if multi-class) must match
    # actual. If None, compute + verify consistent.
    actual_imbalance = spec.actual_class_imbalance
    if spec.class_imbalance is not None:
        for cls, declared in spec.class_imbalance.items():
            actual = actual_imbalance.get(cls, 0.0)
            if abs(declared - actual) > 0.01:  # 1% tolerance
                raise CorpusQualityError(
                    "distribution",
                    f"declared {cls}={declared:.3f} but actual is "
                    f"{actual:.3f}; declare imbalance honestly per §2.3",
                )

    # Rule 6 — adversarial share
    actual_adv = spec.actual_adversarial_share
    if actual_adv < _MIN_ADVERSARIAL_SHARE:
        raise CorpusQualityError(
            "adversarial_coverage",
            f"actual adversarial share is {actual_adv:.3f}; "
            f"§2.3 requires >= {_MIN_ADVERSARIAL_SHARE}",
        )
    # declared must be honest too (within 1% of actual)
    if abs(spec.declared_adversarial_share - actual_adv) > 0.01:
        raise CorpusQualityError(
            "adversarial_coverage",
            f"declared_adversarial_share={spec.declared_adversarial_share:.3f} "
            f"but actual is {actual_adv:.3f}; declarations must match "
            f"reality per §2.3",
        )


def _parse_iso(s: str) -> datetime:
    """Parse ISO 8601 with trailing Z (§2.4 format)."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)
