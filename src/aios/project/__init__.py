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

__all__ = [
    "ADRParseError",
    "InvariantParseError",
    "ProjectReadError",
    "read_adrs",
    "read_invariants",
]
