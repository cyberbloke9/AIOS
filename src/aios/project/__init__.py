"""Project integration: read invariants and ADRs from a real repo.

See docs/integration.md for the `.aios/invariants.yaml` and ADR front-matter
formats this module understands.
"""
from __future__ import annotations

from aios.project.adopt import (
    AdoptResult,
    adopt,
    install_post_commit_hook,
)
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
    "AdoptResult",
    "InvariantParseError",
    "ProjectReadError",
    "GitError",
    "adopt",
    "install_post_commit_hook",
    "read_adrs",
    "read_invariants",
    "runstate_from_project",
]
