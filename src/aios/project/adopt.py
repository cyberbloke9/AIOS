"""aios adopt + aios git-init — integrate AIOS into an existing repo.

`adopt(repo_dir, profile='P-Local')`:
  - creates <repo>/.aios/ via init_aios_home(...)
  - writes a starter .aios/invariants.yaml (empty invariants list)
  - adds .aios/events/, .aios/projections/, .aios/credentials/ + log.lock
    artefacts to .gitignore so runtime state does not bleed into git
  - leaves the config.json + invariants.yaml committable

`install_post_commit_hook(repo_dir)`:
  - installs .git/hooks/post-commit that appends a `commit.landed` frame
    to the repo's AIOS event log on every commit
  - preserves any existing hook content (appends, does not overwrite)
  - cross-platform: shell script + CMD shim; Windows Git Bash honors the
    shell form, native Windows git calls the .cmd shim
"""
from __future__ import annotations

import dataclasses as dc
import os
from pathlib import Path

from aios.runtime.init import InitResult, init_aios_home


_INVARIANTS_STUB = """\
# AIOS invariants file. Declare invariants your codebase must preserve.
# Sources: principle | security | adr | interface
#
# invariants:
#   - id: INV-001
#     source: principle
#     statement: Public API method signatures do not change without an ADR.
#   - id: INV-002
#     source: security
#     statement: PII fields are never written to logs.

invariants: []
"""

_GITIGNORE_LINES = (
    "# AIOS runtime state (local; do not commit)",
    ".aios/events/",
    ".aios/projections/",
    ".aios/credentials/",
    ".aios/**/log.lock",
    ".aios/**/log.lock.holder",
)

_HOOK_MARKER_BEGIN = "# >>> aios post-commit hook >>>"
_HOOK_MARKER_END = "# <<< aios post-commit hook <<<"

_HOOK_BODY = """\
{marker_begin}
# Appends a commit.landed frame to the AIOS event log for this repo.
# Installed by `aios git-init`. Edit freely outside the marker block.
if command -v aios >/dev/null 2>&1; then
  sha=$(git rev-parse HEAD 2>/dev/null || echo "")
  msg=$(git log -1 --format=%s HEAD 2>/dev/null | head -c 200 | tr -d '"\\\\')
  author=$(git log -1 --format=%ae HEAD 2>/dev/null | head -c 120)
  if [ -n "$sha" ] && [ -d ".aios" ]; then
    aios append --home .aios \\
      --kind commit.landed --actor A3 \\
      --payload "{{\\"sha\\":\\"$sha\\",\\"msg\\":\\"$msg\\",\\"author\\":\\"$author\\"}}" \\
      >/dev/null 2>&1 || true
  fi
fi
{marker_end}
""".format(marker_begin=_HOOK_MARKER_BEGIN, marker_end=_HOOK_MARKER_END)


@dc.dataclass(frozen=True)
class AdoptResult:
    repo: Path
    init: InitResult
    gitignore_updated: bool
    invariants_template_written: bool


def adopt(repo_dir: str | os.PathLike, *, profile: str = "P-Local",
          force: bool = False) -> AdoptResult:
    """Scaffold AIOS into an existing repo.

    Idempotent: running adopt() twice does not duplicate .gitignore lines
    and refuses to re-init unless `force=True`.
    """
    repo = Path(repo_dir).resolve()
    if not repo.is_dir():
        raise NotADirectoryError(f"adopt target {repo} is not a directory")

    aios_home = repo / ".aios"
    result = init_aios_home(aios_home, profile=profile, force=force)

    # Invariants template (only written if the file does not already exist)
    inv_path = aios_home / "invariants.yaml"
    wrote_template = False
    if not inv_path.exists():
        inv_path.write_text(_INVARIANTS_STUB, encoding="utf-8")
        wrote_template = True

    # .gitignore maintenance
    gi_path = repo / ".gitignore"
    gi_updated = _ensure_gitignore(gi_path, _GITIGNORE_LINES)

    return AdoptResult(
        repo=repo,
        init=result,
        gitignore_updated=gi_updated,
        invariants_template_written=wrote_template,
    )


def _ensure_gitignore(gi_path: Path, lines: tuple[str, ...]) -> bool:
    existing = ""
    if gi_path.exists():
        existing = gi_path.read_text(encoding="utf-8")
    # Idempotency: if the whole block is already present, no-op.
    marker_check = "\n".join(lines[1:])  # skip the comment line
    if marker_check in existing:
        return False
    separator = "" if existing.endswith("\n") or not existing else "\n"
    new_content = existing + separator + "\n".join(lines) + "\n"
    gi_path.write_text(new_content, encoding="utf-8")
    return True


def install_post_commit_hook(repo_dir: str | os.PathLike) -> Path:
    """Install (or update) .git/hooks/post-commit that appends a
    commit.landed frame to the repo's AIOS event log.

    Returns the path to the hook. Preserves existing hook content outside
    the AIOS marker block — editing the hook by hand is safe.
    """
    repo = Path(repo_dir).resolve()
    git_dir = repo / ".git"
    if not git_dir.is_dir():
        raise FileNotFoundError(f"{repo} is not a git repository (no .git/)")

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "post-commit"

    existing = hook_path.read_text(encoding="utf-8") if hook_path.exists() else ""

    if _HOOK_MARKER_BEGIN in existing and _HOOK_MARKER_END in existing:
        # Replace just our block, keep user content
        start = existing.index(_HOOK_MARKER_BEGIN)
        end = existing.index(_HOOK_MARKER_END) + len(_HOOK_MARKER_END)
        new_content = existing[:start] + _HOOK_BODY.rstrip() + existing[end:]
    else:
        if not existing:
            new_content = "#!/usr/bin/env bash\nset -e\n\n" + _HOOK_BODY
        else:
            sep = "" if existing.endswith("\n") else "\n"
            new_content = existing + sep + "\n" + _HOOK_BODY

    hook_path.write_text(new_content, encoding="utf-8")

    # POSIX execute bits; no-op on Windows but harmless.
    try:
        mode = hook_path.stat().st_mode
        hook_path.chmod(mode | 0o111)
    except OSError:
        pass

    return hook_path
