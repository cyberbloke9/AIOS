"""Tests for Brier + ECE (sprint 33)."""
from __future__ import annotations

import pytest

from aios.verification.calibration_metrics import (
    CalibrationMetricError,
    brier_score,
    expected_calibration_error,
)


# Brier ------------------------------------------------------------------


def test_brier_perfect_classifier():
    # Predictions exactly match labels → Brier == 0
    predictions = [0.0, 1.0, 0.0, 1.0]
    labels = [0, 1, 0, 1]
    assert brier_score(predictions, labels) == 0.0


def test_brier_always_wrong_classifier():
    predictions = [1.0, 0.0, 1.0, 0.0]
    labels = [0, 1, 0, 1]
    assert brier_score(predictions, labels) == 1.0


def test_brier_uniform_half():
    """Always predict 0.5 → Brier = 0.25 regardless of labels."""
    predictions = [0.5] * 100
    labels = [i % 2 for i in range(100)]
    assert brier_score(predictions, labels) == 0.25


def test_brier_known_value():
    predictions = [0.9, 0.2, 0.8, 0.3]
    labels = [1, 0, 1, 0]
    # (0.1^2 + 0.2^2 + 0.2^2 + 0.3^2) / 4 = (0.01+0.04+0.04+0.09)/4 = 0.045
    assert brier_score(predictions, labels) == pytest.approx(0.045, abs=1e-10)


def test_brier_length_mismatch():
    with pytest.raises(CalibrationMetricError, match="length mismatch"):
        brier_score([0.5], [0, 1])


def test_brier_empty_rejected():
    with pytest.raises(CalibrationMetricError, match="empty"):
        brier_score([], [])


def test_brier_out_of_range_prediction():
    with pytest.raises(CalibrationMetricError, match="not in"):
        brier_score([1.5], [1])


def test_brier_non_binary_label():
    with pytest.raises(CalibrationMetricError, match="not 0 or 1"):
        brier_score([0.5], [2])


# ECE --------------------------------------------------------------------


def test_ece_perfectly_calibrated_extremes():
    """All predictions are 0.0 or 1.0 and exactly match labels → ECE == 0."""
    predictions = [0.0] * 50 + [1.0] * 50
    labels = [0] * 50 + [1] * 50
    assert expected_calibration_error(predictions, labels) == pytest.approx(0.0)


def test_ece_overconfident_classifier():
    """Predicts 0.9 every time but only half are right → ECE ~ 0.4"""
    predictions = [0.9] * 100
    labels = [1] * 50 + [0] * 50  # actual accuracy 50%
    # Single bin occupied (the 0.9 bin); |0.5 - 0.9| * 1.0 = 0.4
    assert expected_calibration_error(predictions, labels) == pytest.approx(0.4, abs=1e-10)


def test_ece_uniform_half_on_balanced_labels():
    """Predicts 0.5 on a 50/50 label mix → ECE == 0 (bin is perfectly calibrated)."""
    predictions = [0.5] * 100
    labels = [i % 2 for i in range(100)]
    assert expected_calibration_error(predictions, labels) == pytest.approx(0.0)


def test_ece_low_for_reasonable_predictions():
    """Mixed predictions that track the labels reasonably → ECE < 0.2."""
    predictions = [0.1, 0.2, 0.9, 0.8, 0.95, 0.05, 0.85, 0.15, 0.7, 0.3]
    labels =      [0,   0,   1,   1,   1,    0,    1,    0,    1,   0]
    ece = expected_calibration_error(predictions, labels, n_bins=5)
    assert 0.0 <= ece < 0.2


def test_ece_bin_count_parameter():
    """More bins can increase granularity but shouldn't break the function."""
    predictions = [i / 20 for i in range(1, 20)]
    labels = [0 if p < 0.5 else 1 for p in predictions]
    ece_10 = expected_calibration_error(predictions, labels, n_bins=10)
    ece_2 = expected_calibration_error(predictions, labels, n_bins=2)
    assert ece_10 >= 0
    assert ece_2 >= 0


def test_ece_invalid_n_bins():
    with pytest.raises(CalibrationMetricError, match="n_bins"):
        expected_calibration_error([0.5], [1], n_bins=0)


def test_ece_prediction_of_one_lands_in_final_bin():
    """p == 1.0 must not overflow bin index (n_bins index = n_bins)."""
    predictions = [1.0, 1.0, 1.0]
    labels = [1, 1, 1]
    ece = expected_calibration_error(predictions, labels, n_bins=10)
    assert ece == pytest.approx(0.0)


def test_ece_matches_verification_spec_threshold():
    """Well-calibrated classifier should have ECE <= 0.10 per §2.2."""
    # Simulated: predictions at 0.1, 0.3, 0.5, 0.7, 0.9 with matching frequencies
    predictions = []
    labels = []
    for bucket, count_1 in [(0.1, 1), (0.3, 3), (0.5, 5), (0.7, 7), (0.9, 9)]:
        # 10 samples per bucket, count_1 positives (matching the confidence)
        predictions.extend([bucket] * 10)
        labels.extend([1] * count_1 + [0] * (10 - count_1))
    ece = expected_calibration_error(predictions, labels)
    assert ece <= 0.10
