"""Tests for SK-DEBATE-N3 (sprint 70)."""
from __future__ import annotations

import dataclasses as dc

import pytest

from aios.skills import default_skill_registry
from aios.skills.base import (
    SkillContract,
    SkillInputError,
    SkillOutputError,
)
from aios.skills.debate_n3 import SKILL_ID, sk_debate_n3


# ---------------------------------------------------------------------------
# Fixture: register fake skills that return deterministic verdicts
# ---------------------------------------------------------------------------


def _register_fake(skill_id: str, status: str):
    """Register a fake skill returning {status: <status>}."""
    if default_skill_registry.has(skill_id):
        default_skill_registry._by_id.pop(skill_id)

    def _impl(inputs):
        return {"status": status}

    contract = SkillContract(
        id=skill_id, version="0.0.0", owner_authority="A4",
        description="test fake",
        input_schema={"type": "object"},
        output_schema={"type": "object", "properties": {
            "status": {"type": "string"},
        }, "required": ["status"]},
        implementation=_impl,
    )
    default_skill_registry.register(contract)


def _register_faking_skill(skill_id: str, raises: type[Exception]):
    if default_skill_registry.has(skill_id):
        default_skill_registry._by_id.pop(skill_id)

    def _impl(inputs):
        raise raises("simulated failure")

    contract = SkillContract(
        id=skill_id, version="0.0.0", owner_authority="A4",
        description="test fake that raises",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        implementation=_impl,
    )
    default_skill_registry.register(contract)


def _cleanup_fakes(*ids):
    for sid in ids:
        if default_skill_registry.has(sid):
            default_skill_registry._by_id.pop(sid)


# ---------------------------------------------------------------------------
# Skill registered
# ---------------------------------------------------------------------------


def test_skill_registered():
    assert default_skill_registry.has(SKILL_ID)


# ---------------------------------------------------------------------------
# Majority logic
# ---------------------------------------------------------------------------


def test_unanimous_preserved():
    _register_fake("TEST-A", "preserved")
    _register_fake("TEST-B", "preserved")
    _register_fake("TEST-C", "preserved")
    try:
        r = sk_debate_n3({"skill_ids": ["TEST-A", "TEST-B", "TEST-C"]})
        assert r["verdict"] == "preserved"
        assert r["majority_count"] == 3
        assert r["skill_count"] == 3
        assert r["agreement_score"] == 1.0
        assert r["dissenters"] == []
    finally:
        _cleanup_fakes("TEST-A", "TEST-B", "TEST-C")


def test_unanimous_breached():
    _register_fake("TEST-A", "breached")
    _register_fake("TEST-B", "breached")
    _register_fake("TEST-C", "breached")
    try:
        r = sk_debate_n3({"skill_ids": ["TEST-A", "TEST-B", "TEST-C"]})
        assert r["verdict"] == "breached"
        assert r["agreement_score"] == 1.0
    finally:
        _cleanup_fakes("TEST-A", "TEST-B", "TEST-C")


def test_majority_2_of_3_preserved():
    _register_fake("TEST-A", "preserved")
    _register_fake("TEST-B", "preserved")
    _register_fake("TEST-C", "breached")
    try:
        r = sk_debate_n3({"skill_ids": ["TEST-A", "TEST-B", "TEST-C"]})
        assert r["verdict"] == "preserved"
        assert r["majority_count"] == 2
        assert r["dissenters"] == ["TEST-C"]
        assert round(r["agreement_score"], 3) == 0.667
    finally:
        _cleanup_fakes("TEST-A", "TEST-B", "TEST-C")


def test_even_split_4_skills_is_mixed():
    """2 preserved + 2 breached — no strict majority."""
    _register_fake("TEST-A", "preserved")
    _register_fake("TEST-B", "preserved")
    _register_fake("TEST-C", "breached")
    _register_fake("TEST-D", "breached")
    try:
        r = sk_debate_n3({
            "skill_ids": ["TEST-A", "TEST-B", "TEST-C", "TEST-D"],
            "min_skills": 2,
        })
        assert r["verdict"] == "mixed"
        assert r["majority_count"] == 0
    finally:
        _cleanup_fakes("TEST-A", "TEST-B", "TEST-C", "TEST-D")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def test_error_counts_as_error_not_as_breach():
    _register_fake("TEST-A", "preserved")
    _register_fake("TEST-B", "preserved")
    _register_faking_skill("TEST-ERR", ValueError)
    try:
        r = sk_debate_n3({
            "skill_ids": ["TEST-A", "TEST-B", "TEST-ERR"],
        })
        # Two preserved + one error — majority preserved
        assert r["verdict"] == "preserved"
        errs = [v for v in r["verdicts"] if v["status"] == "error"]
        assert len(errs) == 1
        assert errs[0]["skill_id"] == "TEST-ERR"
    finally:
        _cleanup_fakes("TEST-A", "TEST-B", "TEST-ERR")


def test_strict_mode_aborts_on_error():
    _register_fake("TEST-A", "preserved")
    _register_faking_skill("TEST-ERR", RuntimeError)
    _register_fake("TEST-B", "preserved")
    try:
        with pytest.raises(SkillOutputError, match="TEST-ERR"):
            sk_debate_n3({
                "skill_ids": ["TEST-A", "TEST-B", "TEST-ERR"],
                "strict": True,
            })
    finally:
        _cleanup_fakes("TEST-A", "TEST-B", "TEST-ERR")


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_refuses_fewer_than_min_skills():
    _register_fake("TEST-A", "preserved")
    _register_fake("TEST-B", "preserved")
    try:
        with pytest.raises(SkillInputError, match=">= 3"):
            sk_debate_n3({"skill_ids": ["TEST-A", "TEST-B"]})
    finally:
        _cleanup_fakes("TEST-A", "TEST-B")


def test_min_skills_param_overrides_default():
    _register_fake("TEST-A", "preserved")
    _register_fake("TEST-B", "preserved")
    try:
        r = sk_debate_n3({
            "skill_ids": ["TEST-A", "TEST-B"],
            "min_skills": 2,
        })
        assert r["verdict"] == "preserved"
    finally:
        _cleanup_fakes("TEST-A", "TEST-B")


def test_refuses_duplicate_skill_ids():
    _register_fake("TEST-A", "preserved")
    _register_fake("TEST-B", "preserved")
    try:
        with pytest.raises(SkillInputError, match="duplicate"):
            sk_debate_n3({"skill_ids": ["TEST-A", "TEST-A", "TEST-B"]})
    finally:
        _cleanup_fakes("TEST-A", "TEST-B")


# ---------------------------------------------------------------------------
# Per-skill input overrides
# ---------------------------------------------------------------------------


def test_shared_inputs_delivered_to_each_skill():
    captured: dict[str, dict] = {}

    def _capturer(name):
        def _impl(inputs):
            captured[name] = dict(inputs)
            return {"status": "preserved"}
        return _impl

    for name in ("CAP-A", "CAP-B", "CAP-C"):
        if default_skill_registry.has(name):
            default_skill_registry._by_id.pop(name)
        contract = SkillContract(
            id=name, version="0.0.0", owner_authority="A4",
            description="capturing fake",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            implementation=_capturer(name),
        )
        default_skill_registry.register(contract)
    try:
        sk_debate_n3({
            "skill_ids": ["CAP-A", "CAP-B", "CAP-C"],
            "shared_inputs": {"x": 1, "y": "z"},
            "per_skill_inputs": {"CAP-B": {"x": 999}},
        })
        assert captured["CAP-A"] == {"x": 1, "y": "z"}
        assert captured["CAP-B"] == {"x": 999, "y": "z"}
        assert captured["CAP-C"] == {"x": 1, "y": "z"}
    finally:
        _cleanup_fakes("CAP-A", "CAP-B", "CAP-C")


# ---------------------------------------------------------------------------
# Registry invocation with schema validation
# ---------------------------------------------------------------------------


def test_invoke_via_registry_validates_schema():
    with pytest.raises(SkillInputError):
        default_skill_registry.invoke(SKILL_ID, {"oops": True})
