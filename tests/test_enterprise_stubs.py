"""Tests for the P-Enterprise extension stubs (sprint 10)."""
from __future__ import annotations

import json

import pytest

from aios.enterprise import (
    JCSEncodingError,
    Signer,
    SignatureVerificationError,
    UnimplementedSigner,
    UnimplementedVerifier,
    Verifier,
    jcs_encode,
)


# JCS subset ---------------------------------------------------------------


def test_jcs_encode_sorts_keys():
    a = jcs_encode({"b": 1, "a": 2})
    b = jcs_encode({"a": 2, "b": 1})
    assert a == b
    # Canonical output uses sorted keys and compact separators
    assert a == b'{"a":2,"b":1}'


def test_jcs_encode_rejects_nan_and_inf():
    with pytest.raises(JCSEncodingError):
        jcs_encode(float("nan"))
    with pytest.raises(JCSEncodingError):
        jcs_encode(float("inf"))


def test_jcs_encode_rejects_non_jsonable():
    with pytest.raises(JCSEncodingError):
        jcs_encode({"bytes": b"\x01\x02"})


def test_jcs_encode_round_trips_through_json():
    value = {"gate": "P_Q1", "status": "preserved", "count": 3}
    encoded = jcs_encode(value)
    assert json.loads(encoded.decode("utf-8")) == value


# Signer / Verifier protocols ---------------------------------------------


def test_unimplemented_signer_refuses_to_sign():
    s = UnimplementedSigner()
    with pytest.raises(NotImplementedError):
        s.sign(b"any bytes")


def test_unimplemented_signer_refuses_public_key():
    s = UnimplementedSigner()
    with pytest.raises(NotImplementedError):
        s.public_key()


def test_unimplemented_verifier_refuses_signed_frame():
    v = UnimplementedVerifier()
    with pytest.raises(SignatureVerificationError):
        v.verify(b"frame", b"\x00" * 64)


def test_unimplemented_signer_satisfies_signer_protocol():
    """Protocol adherence — not adherence to the implementation."""
    assert isinstance(UnimplementedSigner(), Signer)


def test_unimplemented_verifier_satisfies_verifier_protocol():
    assert isinstance(UnimplementedVerifier(), Verifier)
