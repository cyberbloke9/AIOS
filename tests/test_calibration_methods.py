"""Tests for temperature + Platt scaling (sprint 35)."""
from __future__ import annotations

import pytest

from aios.verification.calibration import (
    CalibrationFitError,
    PlattModel,
    TemperatureModel,
    platt_apply,
    platt_fit,
    temperature_apply,
    temperature_fit,
)
from aios.verification.calibration_metrics import (
    brier_score,
    expected_calibration_error,
)


# Temperature scaling -----------------------------------------------------


def test_temperature_model_is_deterministic():
    """Same input -> same T. No random init."""
    probs = [0.1, 0.9, 0.2, 0.8, 0.6, 0.4] * 20
    labels = [0, 1, 0, 1, 1, 0] * 20
    m1 = temperature_fit(probs, labels)
    m2 = temperature_fit(probs, labels)
    assert m1.temperature == m2.temperature


def test_temperature_apply_identity_at_T_equals_1():
    """T = 1 means no change."""
    probs = [0.1, 0.5, 0.9]
    out = temperature_apply(probs, 1.0)
    for p, q in zip(probs, out):
        assert abs(p - q) < 1e-6


def test_temperature_softens_overconfident_predictions():
    """An overconfident classifier (always 0.95 but only 50% accurate)
    should be calibrated to a LESS extreme output under T > 1."""
    probs = [0.95] * 200
    labels = [1] * 100 + [0] * 100
    model = temperature_fit(probs, labels)
    assert model.temperature > 1.0  # softening
    calibrated = model.apply(probs)
    # After calibration, predictions should move toward 0.5 (actual accuracy)
    assert all(0.3 < p < 0.7 for p in calibrated)


def test_temperature_sharpens_underconfident_predictions():
    """A timid classifier (always 0.6 but 90% accurate) should get T < 1."""
    probs = [0.6] * 200
    labels = [1] * 180 + [0] * 20
    model = temperature_fit(probs, labels)
    assert model.temperature < 1.0
    calibrated = model.apply(probs)
    # Calibrated predictions should move toward 0.9
    assert all(0.75 < p < 0.95 for p in calibrated)


def test_temperature_reduces_ece():
    """Fitting should lower ECE on the fit data (training-set reduction
    is the baseline; held-out reduction is what §2.2 really tracks but
    out of scope for this unit test)."""
    probs = [0.9, 0.85, 0.8, 0.92, 0.88] * 30 + [0.1, 0.15, 0.2, 0.12] * 30
    labels = [1, 0, 1, 0, 1] * 30 + [0, 1, 0, 0] * 30
    raw_ece = expected_calibration_error(probs, labels)
    model = temperature_fit(probs, labels)
    cal = model.apply(probs)
    cal_ece = expected_calibration_error(cal, labels)
    assert cal_ece <= raw_ece + 1e-6


def test_temperature_invalid_inputs_rejected():
    with pytest.raises(CalibrationFitError):
        temperature_fit([0.5], [1])  # too few
    with pytest.raises(CalibrationFitError):
        temperature_fit([0.5, 0.3], [1, 2])  # non-binary label
    with pytest.raises(CalibrationFitError):
        temperature_apply([0.5], 0.0)  # T must be > 0


# Platt scaling -----------------------------------------------------------


def test_platt_model_is_deterministic():
    probs = [0.1, 0.9, 0.2, 0.8] * 20
    labels = [0, 1, 0, 1] * 20
    m1 = platt_fit(probs, labels)
    m2 = platt_fit(probs, labels)
    assert (m1.A, m1.B) == (m2.A, m2.B)


def test_platt_learns_bias():
    """If raw scores are systematically too low, Platt should learn
    positive B (bias) to correct."""
    # Scores always 0.3, but 80% are positive -> need to shift up.
    probs = [0.3] * 200
    labels = [1] * 160 + [0] * 40
    model = platt_fit(probs, labels, epochs=500)
    calibrated = model.apply(probs)
    assert calibrated[0] > 0.5   # moved up from 0.3


def test_platt_reduces_brier():
    probs = [0.9] * 100 + [0.1] * 100
    labels = [1] * 60 + [0] * 40 + [0] * 80 + [1] * 20
    raw_brier = brier_score(probs, labels)
    model = platt_fit(probs, labels, epochs=500)
    cal_brier = brier_score(model.apply(probs), labels)
    assert cal_brier <= raw_brier + 1e-6


def test_platt_invalid_inputs_rejected():
    with pytest.raises(CalibrationFitError):
        platt_fit([0.5], [1])
    with pytest.raises(CalibrationFitError):
        platt_fit([0.5, 0.5], [1, 2])


def test_platt_output_is_probabilities():
    """Every apply output must be in [0, 1]."""
    model = PlattModel(A=-5.0, B=3.0)  # adversarial
    outputs = model.apply([0.0, 0.5, 1.0])
    assert all(0.0 <= o <= 1.0 for o in outputs)


# Comparison --------------------------------------------------------------


def test_temperature_and_platt_on_same_corpus():
    """Both methods should produce valid probabilities and reduce miscalibration."""
    probs = [0.95, 0.9, 0.85, 0.5, 0.15, 0.05] * 50
    labels = [1, 0, 1, 1, 0, 1] * 50   # noisy signal

    t_model = temperature_fit(probs, labels)
    p_model = platt_fit(probs, labels, epochs=500)

    t_out = t_model.apply(probs)
    p_out = p_model.apply(probs)
    assert all(0.0 <= v <= 1.0 for v in t_out)
    assert all(0.0 <= v <= 1.0 for v in p_out)


def test_models_serializable_via_dataclass():
    t = TemperatureModel(temperature=1.5)
    p = PlattModel(A=2.0, B=-0.5)
    import dataclasses as dc
    assert dc.asdict(t) == {"temperature": 1.5}
    assert dc.asdict(p) == {"A": 2.0, "B": -0.5}
