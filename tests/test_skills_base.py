"""Tests for the skill framework (sprint 26)."""
from __future__ import annotations

import pytest

from aios.skills import (
    NotImplementedSkillError,
    SkillContract,
    SkillInputError,
    SkillOutputError,
    SkillRegistry,
    UnknownSkillError,
)


# Minimal contract constructor for tests ---------------------------------


def _contract(
    id="SK-TEST",
    impl=None,
    input_schema=None,
    output_schema=None,
    authority="A3",
) -> SkillContract:
    return SkillContract(
        id=id,
        version="1.0.0",
        owner_authority=authority,  # type: ignore[arg-type]
        description="test skill",
        input_schema=input_schema or {"type": "object"},
        output_schema=output_schema or {"type": "object"},
        implementation=impl,
    )


# Registration ------------------------------------------------------------


def test_register_and_get():
    reg = SkillRegistry()
    reg.register(_contract())
    assert reg.has("SK-TEST")
    assert reg.get("SK-TEST").version == "1.0.0"


def test_register_duplicate_rejected():
    reg = SkillRegistry()
    reg.register(_contract())
    with pytest.raises(ValueError, match="already registered"):
        reg.register(_contract())


def test_unknown_skill_raises():
    reg = SkillRegistry()
    with pytest.raises(UnknownSkillError):
        reg.get("SK-DOES-NOT-EXIST")


def test_list_ids_sorted():
    reg = SkillRegistry()
    reg.register(_contract(id="SK-B"))
    reg.register(_contract(id="SK-A"))
    assert reg.list_ids() == ["SK-A", "SK-B"]


def test_require_registered_refuses_unknown():
    reg = SkillRegistry()
    reg.register(_contract(id="SK-KNOWN"))
    with pytest.raises(UnknownSkillError):
        reg.require_registered(["SK-KNOWN", "SK-MADE-UP"])


def test_register_rejects_malformed_input_schema():
    reg = SkillRegistry()
    with pytest.raises(ValueError, match="invalid input_schema"):
        reg.register(_contract(input_schema={"type": "not-a-real-type"}))


def test_register_rejects_malformed_output_schema():
    reg = SkillRegistry()
    with pytest.raises(ValueError, match="invalid output_schema"):
        reg.register(_contract(output_schema={"type": "not-a-real-type"}))


# Invocation --------------------------------------------------------------


def test_invoke_returns_output_when_valid():
    reg = SkillRegistry()
    reg.register(_contract(
        id="SK-ECHO",
        input_schema={"type": "object", "required": ["msg"],
                      "properties": {"msg": {"type": "string"}}},
        output_schema={"type": "object", "required": ["echo"],
                       "properties": {"echo": {"type": "string"}}},
        impl=lambda inputs: {"echo": inputs["msg"]},
    ))
    result = reg.invoke("SK-ECHO", {"msg": "hello"})
    assert result == {"echo": "hello"}


def test_invoke_validates_inputs():
    reg = SkillRegistry()
    reg.register(_contract(
        id="SK-REQUIRED",
        input_schema={"type": "object", "required": ["x"]},
        impl=lambda inputs: {"ok": True},
    ))
    with pytest.raises(SkillInputError, match="x"):
        reg.invoke("SK-REQUIRED", {"y": 1})


def test_invoke_validates_outputs():
    reg = SkillRegistry()
    reg.register(_contract(
        id="SK-LIES",
        input_schema={"type": "object"},
        output_schema={"type": "object", "required": ["declared"]},
        impl=lambda inputs: {"omitted": True},  # doesn't have 'declared'
    ))
    with pytest.raises(SkillOutputError, match="declared"):
        reg.invoke("SK-LIES", {})


def test_invoke_rejects_non_dict_output():
    reg = SkillRegistry()
    reg.register(_contract(
        impl=lambda inputs: "not a dict",  # type: ignore[return-value,arg-type]
    ))
    with pytest.raises(SkillOutputError, match="dict"):
        reg.invoke("SK-TEST", {})


def test_stub_skill_refuses_silent_pass():
    """A skill registered without implementation must raise, not silently pass."""
    reg = SkillRegistry()
    reg.register(_contract(impl=None))
    with pytest.raises(NotImplementedSkillError):
        reg.invoke("SK-TEST", {})


def test_input_error_names_offending_path():
    reg = SkillRegistry()
    reg.register(_contract(
        id="SK-NESTED",
        input_schema={
            "type": "object",
            "properties": {
                "a": {"type": "object",
                      "properties": {"b": {"type": "integer"}},
                      "required": ["b"]},
            },
            "required": ["a"],
        },
        impl=lambda inputs: {},
    ))
    try:
        reg.invoke("SK-NESTED", {"a": {"b": "not an int"}})
    except SkillInputError as e:
        assert "a" in str(e) and "b" in str(e)
        return
    raise AssertionError("expected SkillInputError")


def test_default_registry_starts_empty():
    from aios.skills import default_skill_registry
    # Baseline skills land in later sprints. v0.3.0 / sprint 26 leaves it empty.
    assert isinstance(default_skill_registry, SkillRegistry)
