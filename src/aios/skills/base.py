"""Skill contract + registry (sprint 26).

A skill is a deterministic Z1 function with a declared input/output schema.
Authorities (A2-A5) invoke skills to produce or verify artifacts. Every
skill invocation:

  1. Validates inputs against `input_schema` (T3 pre-check)
  2. Runs the implementation
  3. Validates outputs against `output_schema` (T3 post-check)

Any schema violation raises a SkillInputError or SkillOutputError; the
caller never sees a silently-malformed output. This is Kernel §1.1 Z1's
"outputs are schema-checked" promise encoded as the default invocation
path.
"""
from __future__ import annotations

import dataclasses as dc
from typing import Any, Callable, Literal

import jsonschema
from jsonschema import Draft202012Validator

AuthorityId = Literal["A1", "A2", "A3", "A4", "A5"]
Lifecycle = Literal["proposed", "active", "deprecated", "retired"]


class UnknownSkillError(KeyError):
    """Skill id not in the registry."""


class NotImplementedSkillError(RuntimeError):
    """Skill is registered but has no implementation yet."""


class SkillInputError(ValueError):
    """Invocation inputs failed `input_schema` validation."""


class SkillOutputError(ValueError):
    """Implementation output failed `output_schema` validation —
    this is always a bug in the skill, not in the caller."""


@dc.dataclass(frozen=True)
class SkillContract:
    """Kernel §1.1 Z1 contract for a deterministic skill."""
    id: str
    version: str
    owner_authority: AuthorityId
    description: str
    input_schema: dict                    # JSON Schema (Draft 2020-12)
    output_schema: dict                   # JSON Schema (Draft 2020-12)
    implementation: Callable[[dict], dict] | None = None
    lifecycle: Lifecycle = "active"
    # `calibration` is a forward-compat field; v0.3.0 skills are all
    # deterministic, so it stays None. M4 will populate for stochastic
    # confidence-emitting skills.
    calibration: Any = None


class SkillRegistry:
    """Mutable registry parallel to verification.Registry but for skills."""

    def __init__(self) -> None:
        self._by_id: dict[str, SkillContract] = {}

    def register(self, skill: SkillContract) -> None:
        if skill.id in self._by_id:
            raise ValueError(f"skill {skill.id!r} already registered")
        # Validate schemas themselves up front so a broken skill contract
        # fails at registration, not at first invocation.
        try:
            Draft202012Validator.check_schema(skill.input_schema)
        except jsonschema.SchemaError as e:
            raise ValueError(f"{skill.id}: invalid input_schema: {e.message}") from e
        try:
            Draft202012Validator.check_schema(skill.output_schema)
        except jsonschema.SchemaError as e:
            raise ValueError(f"{skill.id}: invalid output_schema: {e.message}") from e

        self._by_id[skill.id] = skill

    def get(self, skill_id: str) -> SkillContract:
        try:
            return self._by_id[skill_id]
        except KeyError:
            raise UnknownSkillError(
                f"skill {skill_id!r} not in registry; known: "
                f"{', '.join(sorted(self._by_id)) or '<empty>'}"
            )

    def has(self, skill_id: str) -> bool:
        return skill_id in self._by_id

    def list_ids(self) -> list[str]:
        return sorted(self._by_id)

    def require_registered(self, skill_ids: list[str]) -> None:
        """Refuse any workflow manifest referencing an unregistered skill.
        Parallel to Registry.require_registered for gates."""
        missing = [sid for sid in skill_ids if sid not in self._by_id]
        if missing:
            raise UnknownSkillError(
                f"workflow references unregistered skill(s): {missing}"
            )

    def invoke(self, skill_id: str, inputs: dict) -> dict:
        """Validate inputs -> run implementation -> validate outputs."""
        skill = self.get(skill_id)
        if skill.implementation is None:
            raise NotImplementedSkillError(
                f"skill {skill_id!r} is registered but not implemented "
                f"in this build"
            )

        input_errors = sorted(
            Draft202012Validator(skill.input_schema).iter_errors(inputs),
            key=lambda e: list(e.absolute_path),
        )
        if input_errors:
            raise SkillInputError(
                f"{skill_id}: input validation failed: "
                f"{input_errors[0].message} "
                f"(path {list(input_errors[0].absolute_path)})"
            )

        output = skill.implementation(inputs)
        if not isinstance(output, dict):
            raise SkillOutputError(
                f"{skill_id}: implementation returned {type(output).__name__}, "
                f"expected dict"
            )

        output_errors = sorted(
            Draft202012Validator(skill.output_schema).iter_errors(output),
            key=lambda e: list(e.absolute_path),
        )
        if output_errors:
            raise SkillOutputError(
                f"{skill_id}: implementation output failed its own "
                f"output_schema: {output_errors[0].message} "
                f"(path {list(output_errors[0].absolute_path)})"
            )

        return output


# Module-level default registry. Baseline skills (SK-ADR-CHECK etc) will
# register themselves at import time in later sprints.
default_skill_registry = SkillRegistry()
