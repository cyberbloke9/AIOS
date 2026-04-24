"""Build a RunState from a real project directory (sprint 24).

`runstate_from_project(root, before_ref=...)` turns a repo into the
RunState shape the conservation scan and workflow runner consume.
Invariants and ADRs are read via `aios.project.readers`. When
`before_ref` is provided, the "before" set is reconstructed from git
(via `git show`) so `aios scan` / `aios run` / `aios check` can detect
silent invariant removals between two commits.

Minimal decisions / slices / context_load are synthesized from defaults
so a first-install user does not need to hand-build those fields. An
operator can override by providing the respective arguments.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from aios.project.readers import read_adrs, read_invariants
from aios.verification.conservation_scan import (
    ADREvent,
    ContextLoad,
    Decision,
    EventLogRange,
    GenerationSlice,
    Invariant,
    RunState,
    VerificationSlice,
    _chain_hash,
)

_DEFAULT_CONTEXT_BUDGET = 32_000


class GitError(RuntimeError):
    """Raised when a git command fails or the target is not a git repo."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def runstate_from_project(
    root: str | Path,
    *,
    before_ref: str | None = None,
    after_ref: str = "working",
    run_id: str | None = None,
    impact: str = "local",
    decisions: tuple[Decision, ...] = (),
    generator_slices: tuple[GenerationSlice, ...] = (),
    verifier_slices: tuple[VerificationSlice, ...] = (),
    context_load: ContextLoad | None = None,
) -> RunState:
    """Assemble a RunState from the current project directory.

    Parameters:
      root         the project root (must contain `.aios/` and/or an ADR dir).
      before_ref   git ref to read the pre-change invariant set from. If
                   None, the "before" set equals the "after" set (no diff;
                   useful for initial scans that establish a baseline).
      after_ref    git ref for the post-change state. The literal
                   "working" (default) means the on-disk working tree —
                   no git call required. Any other value is passed to git.
      run_id       run identifier written into the frame. Defaults to
                   "<root_name>:<after_ref>".
      impact       "local" | "subsystem" | "system_wide".
      decisions / generator_slices / verifier_slices / context_load
                   override the defaults. The defaults produce a RunState
                   that passes Q1-Q3 on a clean repo (no decisions, no
                   overlap, within budget).
    """
    root_path = Path(root).resolve()

    if after_ref == "working":
        invs_after = read_invariants(root_path)
        adrs = read_adrs(root_path)
    else:
        invs_after, adrs = _state_at_ref(root_path, after_ref)

    if before_ref is None:
        invs_before = invs_after
    else:
        invs_before, _ = _state_at_ref(root_path, before_ref)

    if run_id is None:
        run_id = f"{root_path.name}:{after_ref}"

    if context_load is None:
        required_ids = frozenset(i.id for i in invs_after)
        context_load = ContextLoad(
            tokens_loaded=0,
            budget=_DEFAULT_CONTEXT_BUDGET,
            invariants_loaded=required_ids,
            invariants_required=required_ids,
        )

    return RunState(
        run_id=run_id,
        invariants_before=invs_before,
        invariants_after=invs_after,
        adr_events=adrs,
        decisions=decisions,
        generator_slices=generator_slices,
        verifier_slices=verifier_slices,
        context_load=context_load,
        event_log_range=EventLogRange((), _chain_hash(())),
        impact=impact,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _state_at_ref(root: Path, ref: str) -> tuple[frozenset[Invariant], tuple[ADREvent, ...]]:
    """Materialize the invariants + ADRs at `ref` into a tempdir and read."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Invariants file (first match wins)
        for candidate in ("invariants.yaml", "invariants.yml", "invariants.json"):
            rel = f".aios/{candidate}"
            content = _git_show(root, ref, rel)
            if content is not None:
                target = tmp_path / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                break

        # ADR directory (first match wins)
        for adr_dir in ("adrs", "docs/adr", "doc/adr", "docs/adrs"):
            entries = _git_ls_tree(root, ref, adr_dir)
            if entries:
                for relpath in entries:
                    content = _git_show(root, ref, relpath)
                    if content is not None:
                        target = tmp_path / relpath
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(content)
                break

        return read_invariants(tmp_path), read_adrs(tmp_path)


def _git_show(root: Path, ref: str, relpath: str) -> bytes | None:
    """Return the bytes of <root>:<ref>:<relpath>, or None if absent."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "show", f"{ref}:{relpath}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        raise GitError("git executable not found on PATH") from e

    if result.returncode == 0:
        return result.stdout
    # Distinguish "file not in this ref" (exit 128) from "not a git repo" etc.
    err = result.stderr.decode("utf-8", errors="replace").lower()
    if "not a git repository" in err:
        raise GitError(f"{root} is not a git repository")
    if "does not exist" in err or "exists on disk, but not in" in err or "bad revision" in err:
        if "bad revision" in err:
            raise GitError(f"unknown ref {ref!r} in {root}")
        return None
    # Unknown git error
    raise GitError(f"git show {ref}:{relpath} failed: {err.strip() or 'no stderr'}")


def _git_ls_tree(root: Path, ref: str, dir_relpath: str) -> list[str]:
    """List blob paths under <ref>:<dir> matching *.md. Returns [] if dir absent."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-r", "--name-only", ref, dir_relpath],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        raise GitError("git executable not found on PATH") from e

    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace").lower()
        if "not a git repository" in err:
            raise GitError(f"{root} is not a git repository")
        return []

    files = result.stdout.decode("utf-8", errors="replace").strip().splitlines()
    return [f for f in files if f.endswith(".md")]
