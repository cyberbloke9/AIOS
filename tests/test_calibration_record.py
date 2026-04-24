"""Tests for calibration record + persistence + CLI (sprint 36)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aios.cli import main
from aios.runtime.init import init_aios_home
from aios.verification.calibration_record import (
    CalibrationQualityError,
    CalibrationRecord,
    calibrate,
    has_record,
    load_corpus_from_json,
    load_record,
    save_record,
)
from aios.verification.corpus import (
    CorpusExample,
    CorpusQualityError,
    CorpusSpec,
    IndependenceAudit,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _good_corpus(size: int = 300, predicted_fn=None) -> CorpusSpec:
    """A corpus that passes §2.3 rules. Default predictions are
    reasonably calibrated so calibrate() also passes thresholds."""
    if predicted_fn is None:
        # Predict ~label with small noise so calibration is trivial.
        predicted_fn = lambda i: 0.9 if (i % 2 == 1) else 0.1
    examples = []
    for i in range(size):
        examples.append(CorpusExample(
            input={"x": i},
            label=i % 2,
            provenance="human-alice",
            is_adversarial=(i < size // 10),  # 10% adversarial
            predicted_prob=predicted_fn(i),
        ))
    return CorpusSpec(
        path="c.jsonl",
        sha256="0" * 64,
        examples=tuple(examples),
        independence_audit=IndependenceAudit(
            method="sha256",
            last_run_iso=_iso_now(),
            overlap_detected=False,
            signer="human-auditor",
        ),
        recency_policy="weekly",
        last_refresh_iso=_iso_now(),
        declared_adversarial_share=0.1,
        class_imbalance={"class_0": 0.5, "class_1": 0.5},
    )


# calibrate() ------------------------------------------------------------


def test_calibrate_produces_valid_record():
    rec = calibrate("SK-DEMO", _good_corpus(), method="temperature_scaling")
    assert rec.skill_id == "SK-DEMO"
    assert rec.method == "temperature_scaling"
    assert rec.corpus_size == 300
    assert rec.metrics_brier <= 0.25
    assert rec.metrics_ece <= 0.10
    assert "temperature" in rec.model_params


def test_calibrate_platt_method():
    rec = calibrate("SK-PLATT", _good_corpus(), method="platt_scaling")
    assert rec.method == "platt_scaling"
    assert rec.model_params.keys() == {"A", "B"}


def test_calibrate_refuses_corpus_that_fails_quality():
    # undersized corpus (local requires 300)
    small = _good_corpus(size=299)
    with pytest.raises(CorpusQualityError):
        calibrate("SK-DEMO", small)


def test_calibrate_requires_predictions_on_every_example():
    # One example with predicted_prob=None
    c = _good_corpus()
    bad = list(c.examples)
    bad[0] = CorpusExample(
        input={}, label=0, provenance="human-alice",
        is_adversarial=False, predicted_prob=None,
    )
    # Replace the first 30 to include this one + keep size >= 300
    broken = CorpusSpec(**{**c.__dict__, "examples": tuple(bad)})
    with pytest.raises(CalibrationQualityError, match="predicted_prob"):
        calibrate("SK-DEMO", broken)


def test_calibrate_refuses_when_brier_too_high():
    """A corpus where predictions are 0.5 on a balanced set gives Brier ~0.25
    (the threshold). Push predictions away from correct and watch it refuse."""
    # Predict 0.9 for all examples, but only ~50% are label=1 -> high Brier.
    c = _good_corpus(predicted_fn=lambda i: 0.99)
    with pytest.raises(CalibrationQualityError):
        calibrate("SK-DEMO", c, method="temperature_scaling")


# Persistence ------------------------------------------------------------


def test_save_and_load_record(tmp_path: Path):
    init_aios_home(tmp_path, profile="P-Local")
    rec = calibrate("SK-A", _good_corpus())
    path = save_record(tmp_path, rec)
    assert path.exists()
    assert has_record(tmp_path, "SK-A")
    loaded = load_record(tmp_path, "SK-A")
    assert loaded == rec


def test_record_is_json_serialisable(tmp_path: Path):
    rec = calibrate("SK-B", _good_corpus())
    text = rec.to_json()
    data = json.loads(text)
    assert data["skill_id"] == "SK-B"
    assert data["metrics_brier"] == rec.metrics_brier


def test_load_corpus_from_json_hashes_file(tmp_path: Path):
    corpus_path = tmp_path / "c.json"
    corpus_path.write_text(json.dumps({
        "path": "c.json",
        "recency_policy": "weekly",
        "last_refresh_iso": _iso_now(),
        "declared_adversarial_share": 0.1,
        "independence_audit": {
            "method": "sha256", "last_run_iso": _iso_now(),
            "overlap_detected": False, "signer": "human-a",
        },
        "examples": [
            {"input": {"i": i}, "label": i % 2,
             "provenance": "human-a",
             "is_adversarial": i < 30,
             "predicted_prob": 0.9 if i % 2 else 0.1}
            for i in range(300)
        ],
    }))
    spec = load_corpus_from_json(corpus_path)
    assert spec.size == 300
    assert len(spec.sha256) == 64


# CLI --------------------------------------------------------------------


def _write_corpus_file(tmp_path: Path) -> Path:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps({
        "path": str(p),
        "recency_policy": "weekly",
        "last_refresh_iso": _iso_now(),
        "declared_adversarial_share": 0.1,
        "independence_audit": {
            "method": "sha256", "last_run_iso": _iso_now(),
            "overlap_detected": False, "signer": "human-a",
        },
        "examples": [
            {"input": {"i": i}, "label": i % 2,
             "provenance": "human-a",
             "is_adversarial": i < 30,
             "predicted_prob": 0.9 if i % 2 else 0.1}
            for i in range(300)
        ],
    }))
    return p


def test_cli_calibrate_happy_path(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    corpus_path = _write_corpus_file(tmp_path)
    capsys.readouterr()
    rc = main([
        "calibrate", "SK-DEMO",
        "--corpus", str(corpus_path),
        "--method", "temperature_scaling",
        "--home", str(home),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "calibrated SK-DEMO" in out
    assert "brier:" in out
    assert "ece:" in out
    assert (home / "credentials" / "SK-DEMO.calibration.json").exists()


def test_cli_calibrate_rejects_bad_corpus(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    corpus_path = tmp_path / "c.json"
    corpus_path.write_text(json.dumps({
        "path": str(corpus_path),
        "recency_policy": "weekly",
        "last_refresh_iso": _iso_now(),
        "declared_adversarial_share": 0.1,
        "independence_audit": {
            "method": "sha256", "last_run_iso": _iso_now(),
            "overlap_detected": False, "signer": "human-a",
        },
        "examples": [   # Only 50 — fails §2.3 min-size rule
            {"input": {"i": i}, "label": i % 2,
             "provenance": "human-a",
             "is_adversarial": i < 5,
             "predicted_prob": 0.5}
            for i in range(50)
        ],
    }))
    capsys.readouterr()
    rc = main([
        "calibrate", "SK-DEMO",
        "--corpus", str(corpus_path),
        "--home", str(home),
    ])
    assert rc == 7   # corpus rejected
    err = capsys.readouterr().err
    assert "minimum_size" in err or "corpus rejected" in err


def test_cli_calibrate_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "calibrate" in out
