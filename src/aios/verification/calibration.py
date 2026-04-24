"""Calibration methods — temperature + Platt scaling (sprint 35).

Verification Spec §2.2 names four calibration methods. This module
implements two of them — temperature scaling and Platt scaling — as
stdlib-only fit + apply functions. The other two (linear probe,
self-consistency) require either extra libs or model access and are
deferred.

Temperature scaling:
    p_cal = sigmoid(logit(p_raw) / T)
    Fit: find T that minimizes NLL on (p_raw, y) pairs.
    One scalar to fit; cheap and extremely robust. Default choice
    unless the raw scores are systematically biased (where Platt wins).

Platt scaling:
    p_cal = sigmoid(A * p_raw + B)
    Fit: gradient descent on the two-parameter logistic regression.
    Corrects systematic over/under-confidence AND bias.

Both functions are deterministic given identical inputs (no random init
for T; Platt starts from A=1, B=0 always). This matches §2.2's
"deterministic | stochastic_bounded | stochastic_calibrated" taxonomy —
calibration itself stays deterministic.
"""
from __future__ import annotations

import dataclasses as dc
import math
from typing import Sequence


_EPS = 1e-7


class CalibrationFitError(ValueError):
    """Raised when inputs to fit are malformed."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sigmoid(z: float) -> float:
    # Numerically-stable sigmoid.
    if z >= 0:
        e = math.exp(-z)
        return 1.0 / (1.0 + e)
    e = math.exp(z)
    return e / (1.0 + e)


def _logit(p: float) -> float:
    p = max(_EPS, min(1.0 - _EPS, p))
    return math.log(p / (1.0 - p))


def _nll_binary(probs_cal: Sequence[float], labels: Sequence[int]) -> float:
    """Negative log-likelihood of calibrated probabilities."""
    total = 0.0
    for p, y in zip(probs_cal, labels):
        p_clamped = max(_EPS, min(1.0 - _EPS, p))
        if y == 1:
            total -= math.log(p_clamped)
        else:
            total -= math.log(1.0 - p_clamped)
    return total / len(probs_cal)


def _validate_fit(probs: Sequence[float], labels: Sequence[int]) -> None:
    if len(probs) != len(labels):
        raise CalibrationFitError(
            f"length mismatch: {len(probs)} probs vs {len(labels)} labels"
        )
    if len(probs) < 2:
        raise CalibrationFitError("need at least 2 examples to fit a calibrator")
    for i, p in enumerate(probs):
        if not 0.0 <= p <= 1.0:
            raise CalibrationFitError(f"probs[{i}]={p!r} not in [0, 1]")
    for i, y in enumerate(labels):
        if y not in (0, 1):
            raise CalibrationFitError(f"labels[{i}]={y!r} must be 0 or 1")


# ---------------------------------------------------------------------------
# Temperature scaling
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class TemperatureModel:
    """Fitted temperature-scaling model. Apply via temperature_apply(...)."""
    temperature: float

    def apply(self, probs: Sequence[float]) -> list[float]:
        return temperature_apply(probs, self.temperature)


def temperature_fit(probs: Sequence[float], labels: Sequence[int],
                    *, t_min: float = 0.05, t_max: float = 10.0,
                    coarse_steps: int = 100, fine_steps: int = 100) -> TemperatureModel:
    """Grid + local refinement to find T that minimizes NLL.

    Coarse scan across [t_min, t_max], then a fine scan in a window
    around the best coarse candidate. Deterministic and cheap for
    corpora up to ~1e5.
    """
    _validate_fit(probs, labels)
    if t_min <= 0:
        raise CalibrationFitError(f"t_min must be > 0, got {t_min}")
    if t_max <= t_min:
        raise CalibrationFitError(f"t_max must be > t_min")

    best_T, best_nll = _scan_T(probs, labels, t_min, t_max, coarse_steps)

    # Fine scan in a window around best_T
    step = (t_max - t_min) / (coarse_steps - 1) if coarse_steps > 1 else 0.1
    window = step * 4
    fine_T, fine_nll = _scan_T(
        probs, labels,
        max(t_min, best_T - window),
        min(t_max, best_T + window),
        fine_steps,
    )
    if fine_nll < best_nll:
        best_T = fine_T

    return TemperatureModel(temperature=best_T)


def _scan_T(probs, labels, t_min, t_max, steps) -> tuple[float, float]:
    best_T = t_min
    best_nll = float("inf")
    for i in range(steps):
        if steps == 1:
            T = t_min
        else:
            T = t_min + (t_max - t_min) * i / (steps - 1)
        calibrated = temperature_apply(probs, T)
        nll = _nll_binary(calibrated, labels)
        if nll < best_nll:
            best_nll = nll
            best_T = T
    return best_T, best_nll


def temperature_apply(probs: Sequence[float], temperature: float) -> list[float]:
    """Apply p_cal = sigmoid(logit(p) / T)."""
    if temperature <= 0:
        raise CalibrationFitError(f"temperature must be > 0, got {temperature}")
    return [_sigmoid(_logit(p) / temperature) for p in probs]


# ---------------------------------------------------------------------------
# Platt scaling
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class PlattModel:
    A: float
    B: float

    def apply(self, probs: Sequence[float]) -> list[float]:
        return platt_apply(probs, self.A, self.B)


def platt_fit(probs: Sequence[float], labels: Sequence[int],
              *, lr: float = 0.5, epochs: int = 400,
              tol: float = 1e-7) -> PlattModel:
    """Gradient descent on NLL with early stop when loss plateau.

    Starts at A=1, B=0 (i.e., identity on logits) and descends. Uses
    the classic logistic loss derivative; no regularization (Platt's
    original formulation). Deterministic init makes this stable across
    re-runs of the same corpus.
    """
    _validate_fit(probs, labels)

    A, B = 1.0, 0.0
    prev_loss = float("inf")
    n = len(probs)
    for _ in range(epochs):
        dA = 0.0
        dB = 0.0
        loss = 0.0
        for p, y in zip(probs, labels):
            z = A * p + B
            pred = _sigmoid(z)
            err = pred - y
            dA += err * p
            dB += err
            p_clamped = max(_EPS, min(1.0 - _EPS, pred))
            loss -= y * math.log(p_clamped) + (1 - y) * math.log(1.0 - p_clamped)
        A -= lr * dA / n
        B -= lr * dB / n
        loss /= n
        if abs(prev_loss - loss) < tol:
            break
        prev_loss = loss

    return PlattModel(A=A, B=B)


def platt_apply(probs: Sequence[float], A: float, B: float) -> list[float]:
    return [_sigmoid(A * p + B) for p in probs]
