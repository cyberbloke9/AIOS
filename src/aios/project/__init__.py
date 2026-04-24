"""Project integration: read invariants and ADRs from a real repo.

See docs/integration.md for the `.aios/invariants.yaml` and ADR front-matter
formats this module understands.
"""
from __future__ import annotations

from aios.project.readers import (
    ADRParseError,
    InvariantParseError,
    ProjectReadError,
    read_adrs,
    read_invariants,
)
from aios.project.runstate import (
    GitError,
    runstate_from_project,
)

__all__ = [
    "ADRParseError",
    "InvariantParseError",
    "ProjectReadError",
    "GitError",
    "read_adrs",
    "read_invariants",
    "runstate_from_project",
]
