"""Calibration metrics — Brier score + Expected Calibration Error (sprint 33).

Verification Spec §2.2 names four calibration methods with thresholds:
    method              Brier <=   ECE <=
    temperature          0.25       0.10
    platt                0.25       0.10
    linear_probe         0.25       0.10
    self_consistency     0.25       0.15

These are the measurement primitives. They take predicted probabilities +
ground-truth labels and return scalar metrics. Stdlib-only (no numpy /
scipy) so they run in P-Local without extras.

Binary classification only for v0.4.0. Multi-class Brier is trivial to
add when a confidence-emitting skill needs it; no skills require it in
the current build.
"""
from __future__ import annotations

from typing import Sequence


class CalibrationMetricError(ValueError):
    """Bad inputs: length mismatch, out-of-range probabilities, etc."""


def _validate(predictions: Sequence[float], labels: Sequence[int]) -> None:
    if len(predictions) != len(labels):
        raise CalibrationMetricError(
            f"length mismatch: {len(predictions)} predictions vs {len(labels)} labels"
        )
    if not predictions:
        raise CalibrationMetricError("empty predictions")
    for i, p in enumerate(predictions):
        if not 0.0 <= p <= 1.0:
            raise CalibrationMetricError(
                f"prediction[{i}]={p!r} not in [0, 1]"
            )
    for i, y in enumerate(labels):
        if y not in (0, 1):
            raise CalibrationMetricError(
                f"label[{i}]={y!r} is not 0 or 1 (binary only)"
            )


def brier_score(predictions: Sequence[float], labels: Sequence[int]) -> float:
    """Binary Brier score: mean squared error between prediction and label.

    Lower is better; range [0, 1]. A perfect classifier scores 0;
    always-predict-0.5 scores 0.25.
    """
    _validate(predictions, labels)
    return sum((float(p) - y) ** 2 for p, y in zip(predictions, labels)) / len(predictions)


def expected_calibration_error(
    predictions: Sequence[float],
    labels: Sequence[int],
    *,
    n_bins: int = 10,
) -> float:
    """Expected Calibration Error with equal-width bins over [0, 1].

    For each bin, computes |accuracy - avg_confidence|, weighted by the
    fraction of predictions in the bin. Sum across all bins = ECE.

    n_bins default 10 matches the original Guo et al. "On Calibration of
    Modern Neural Networks" convention.
    """
    _validate(predictions, labels)
    if n_bins < 1:
        raise CalibrationMetricError(f"n_bins must be >= 1, got {n_bins}")

    n = len(predictions)
    # bin i covers [i/n_bins, (i+1)/n_bins); the last bin is closed on the right
    # so predictions of exactly 1.0 land in the final bin.
    bins_conf_sum: list[float] = [0.0] * n_bins
    bins_acc_sum: list[int] = [0] * n_bins
    bins_count: list[int] = [0] * n_bins

    for p, y in zip(predictions, labels):
        idx = int(p * n_bins)
        if idx == n_bins:  # p == 1.0
            idx = n_bins - 1
        bins_conf_sum[idx] += float(p)
        bins_acc_sum[idx] += y
        bins_count[idx] += 1

    ece = 0.0
    for k in range(n_bins):
        if bins_count[k] == 0:
            continue
        avg_conf = bins_conf_sum[k] / bins_count[k]
        acc = bins_acc_sum[k] / bins_count[k]
        weight = bins_count[k] / n
        ece += abs(acc - avg_conf) * weight
    return ece
