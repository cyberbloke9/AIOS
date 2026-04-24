"""Skills — deterministic Z1 scripts invoked by authorities A2-A5.

Constitution Article III:
  A2 Architect     -> proposes structural change, authors ADRs
  A3 Implementer   -> produces artifacts
  A4 Verifier      -> evaluates gates, accepts or rejects artifacts
  A5 Release/Sec   -> signs releases, operates kill switches

Kernel §1.1:
  Z1 Trusted deterministic skills | pure, schema-validated | outputs are
                                     schema-checked

This module defines the contract every skill must satisfy, a registry
parallel to the gate `verification.registry.Registry`, and the invocation
protocol that validates inputs/outputs against the skill's declared
schemas. Baseline skills (SK-ADR-CHECK, SK-PRECEDENT-MATCH, ...) live in
sibling modules and register themselves at import.
"""
from __future__ import annotations

from aios.skills.base import (
    NotImplementedSkillError,
    SkillContract,
    SkillInputError,
    SkillOutputError,
    SkillRegistry,
    UnknownSkillError,
    default_skill_registry,
)

# Baseline skills self-register on import.
from aios.skills import adr_check as _adr_check  # noqa: F401,E402
from aios.skills import precedent_match as _precedent_match  # noqa: F401,E402
from aios.skills import threat_model as _threat_model  # noqa: F401,E402

__all__ = [
    "NotImplementedSkillError",
    "SkillContract",
    "SkillInputError",
    "SkillOutputError",
    "SkillRegistry",
    "UnknownSkillError",
    "default_skill_registry",
]
