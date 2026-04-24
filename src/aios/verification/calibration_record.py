"""Calibration record per §2.4 schema + fit + persistence (sprint 36).

calibrate(skill_id, corpus, method, impact) performs the full §2 flow:
  1. validate_corpus(spec, impact) -> raises if §2.3 rules fail
  2. extract (probs, labels) from corpus.examples
  3. fit the named method
  4. compute Brier + ECE on the calibrated probabilities
  5. check against the method's §2.2 thresholds; refuse if breached
  6. return a CalibrationRecord ready to serialize to the credentials dir

The function raises CalibrationQualityError if the record would claim
calibration on a corpus that genuinely cannot calibrate the skill.
"""
from __future__ import annotations

import dataclasses as dc
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from aios.verification.calibration import (
    PlattModel,
    TemperatureModel,
    platt_fit,
    temperature_fit,
)
from aios.verification.calibration_metrics import (
    brier_score,
    expected_calibration_error,
)
from aios.verification.corpus import (
    CorpusQualityError,
    CorpusSpec,
    ImpactLevel,
    validate_corpus,
)

Method = Literal["temperature_scaling", "platt_scaling"]

# §2.2 thresholds
_THRESHOLDS = {
    "temperature_scaling": {"brier_max": 0.25, "ece_max": 0.10},
    "platt_scaling":       {"brier_max": 0.25, "ece_max": 0.10},
}


class CalibrationQualityError(ValueError):
    """Brier/ECE exceeded §2.2 thresholds, or corpus lacks predictions."""


@dc.dataclass(frozen=True)
class CalibrationRecord:
    """Matches the YAML schema in Verification §2.4."""
    skill_id: str
    method: Method
    corpus_path: str
    corpus_sha256: str
    corpus_size: int
    corpus_labeling_provenance: str
    corpus_adversarial_share: float
    corpus_recency_policy: str
    corpus_last_refresh_iso: str
    impact: ImpactLevel
    last_fit_iso: str
    metrics_brier: float
    metrics_ece: float
    thresholds_brier_max: float
    thresholds_ece_max: float
    model_params: dict[str, float]  # serialized TemperatureModel or PlattModel
    validation_schedule: str

    def to_json(self) -> str:
        return json.dumps(dc.asdict(self), sort_keys=True, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "CalibrationRecord":
        data = json.loads(text)
        return cls(**data)


def calibrate(
    skill_id: str,
    corpus: CorpusSpec,
    *,
    method: Method = "temperature_scaling",
    impact: ImpactLevel = "local",
) -> CalibrationRecord:
    """Fit a calibrator and return the §2.4-shaped record.

    Raises:
      CorpusQualityError — corpus fails §2.3 rules
      CalibrationQualityError — missing predicted_prob on any example,
        or Brier/ECE exceed §2.2 thresholds for the chosen method
    """
    # §2.3 corpus quality (refuses before any fitting)
    validate_corpus(corpus, impact=impact)

    # Extract predictions
    probs: list[float] = []
    labels: list[int] = []
    for i, e in enumerate(corpus.examples):
        if e.predicted_prob is None:
            raise CalibrationQualityError(
                f"example[{i}] has no predicted_prob; run the skill on "
                f"every example and store the raw probability before "
                f"calling calibrate()"
            )
        probs.append(float(e.predicted_prob))
        labels.append(int(e.label))

    # Fit
    if method == "temperature_scaling":
        model: Any = temperature_fit(probs, labels)
        calibrated = model.apply(probs)
        params = dc.asdict(model)
    elif method == "platt_scaling":
        model = platt_fit(probs, labels)
        calibrated = model.apply(probs)
        params = dc.asdict(model)
    else:
        raise ValueError(f"unknown method {method!r}")

    # Evaluate on the (same) corpus — the record reports the post-fit
    # numbers so the operator sees what the calibrator achieved.
    b = brier_score(calibrated, labels)
    ece = expected_calibration_error(calibrated, labels)

    thresholds = _THRESHOLDS[method]
    if b > thresholds["brier_max"]:
        raise CalibrationQualityError(
            f"Brier={b:.4f} exceeds {method} threshold "
            f"{thresholds['brier_max']:.2f}; corpus cannot calibrate this skill"
        )
    if ece > thresholds["ece_max"]:
        raise CalibrationQualityError(
            f"ECE={ece:.4f} exceeds {method} threshold "
            f"{thresholds['ece_max']:.2f}; corpus cannot calibrate this skill"
        )

    return CalibrationRecord(
        skill_id=skill_id,
        method=method,
        corpus_path=corpus.path,
        corpus_sha256=corpus.sha256,
        corpus_size=corpus.size,
        corpus_labeling_provenance=corpus.independence_audit.signer,
        corpus_adversarial_share=corpus.actual_adversarial_share,
        corpus_recency_policy=corpus.recency_policy,
        corpus_last_refresh_iso=corpus.last_refresh_iso,
        impact=impact,
        last_fit_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        metrics_brier=b,
        metrics_ece=ece,
        thresholds_brier_max=thresholds["brier_max"],
        thresholds_ece_max=thresholds["ece_max"],
        model_params=params,
        validation_schedule=corpus.recency_policy,
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def record_path(aios_home: str | Path, skill_id: str) -> Path:
    return Path(aios_home) / "credentials" / f"{skill_id}.calibration.json"


def save_record(aios_home: str | Path, record: CalibrationRecord) -> Path:
    p = record_path(aios_home, record.skill_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(record.to_json() + "\n", encoding="utf-8")
    return p


def load_record(aios_home: str | Path, skill_id: str) -> CalibrationRecord:
    p = record_path(aios_home, skill_id)
    return CalibrationRecord.from_json(p.read_text(encoding="utf-8"))


def has_record(aios_home: str | Path, skill_id: str) -> bool:
    return record_path(aios_home, skill_id).exists()


# ---------------------------------------------------------------------------
# Corpus JSON loader — used by aios calibrate CLI
# ---------------------------------------------------------------------------


def load_corpus_from_json(path: str | Path) -> CorpusSpec:
    """Load a CorpusSpec from a JSON file matching the CorpusSpec shape.

    Schema:
        {
          "path": str,              # relative corpus identifier, not used
          "recency_policy": "weekly" | "monthly",
          "last_refresh_iso": ISO,
          "declared_adversarial_share": float,
          "independence_audit": {method, last_run_iso, overlap_detected, signer},
          "class_imbalance": {class_X: float, ...} | null,
          "examples": [
            {input, label, provenance, is_adversarial, date_iso, predicted_prob},
            ...
          ]
        }

    The file is hashed automatically; the caller does not supply sha256.
    """
    from aios.verification.corpus import (
        CorpusExample,
        IndependenceAudit,
    )
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    data = json.loads(raw)
    return CorpusSpec(
        path=data.get("path", str(p)),
        sha256=sha,
        examples=tuple(
            CorpusExample(
                input=e["input"],
                label=int(e["label"]),
                provenance=str(e["provenance"]),
                is_adversarial=bool(e.get("is_adversarial", False)),
                date_iso=e.get("date_iso"),
                predicted_prob=(float(e["predicted_prob"])
                                if e.get("predicted_prob") is not None
                                else None),
            )
            for e in data["examples"]
        ),
        independence_audit=IndependenceAudit(
            method=data["independence_audit"]["method"],
            last_run_iso=data["independence_audit"]["last_run_iso"],
            overlap_detected=bool(
                data["independence_audit"]["overlap_detected"]
            ),
            signer=data["independence_audit"]["signer"],
        ),
        recency_policy=data["recency_policy"],
        last_refresh_iso=data["last_refresh_iso"],
        declared_adversarial_share=float(data["declared_adversarial_share"]),
        class_imbalance=data.get("class_imbalance"),
    )
