"""Project state readers (sprint 23).

Build `Invariant` and `ADREvent` sets from a real project directory so
the conservation scan and workflow runner can be driven by actual repo
state, not hand-crafted JSON.

Conventions:

  <repo>/
    .aios/
      invariants.yaml          (or .json)   — the declared invariant set
    adrs/ | docs/adr/ | doc/adr/             — directory of ADRs
      0001-title.md            markdown with YAML front matter
      0002-*.md
      ...

Invariants file (YAML or JSON; both accepted):

    invariants:
      - id: INV-001
        source: principle       # principle | security | adr | interface
        statement: Interfaces are frozen.
      - id: INV-002
        source: security
        statement: PII is never logged.

ADR front matter (Nygard-style, YAML between `---` fences):

    ---
    id: ADR-0042
    status: Accepted            # Proposed | Accepted | Rejected | Deprecated | Superseded
    date: 2026-03-15
    removes: [INV-002]          # optional — invariant IDs this ADR retires
    deprecates: ADR-0001        # optional — ADR ID this one replaces
    ---
    # ADR-0042 — Title

    Body...

PyYAML is used when available (from the `enterprise` extra). A small
stdlib-only fallback parser covers the restricted front-matter subset
above so P-Local installs without extras still work for the common case.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from aios.verification.conservation_scan import ADREvent, Invariant

INVARIANT_FILENAMES = ("invariants.yaml", "invariants.yml", "invariants.json")
ADR_DIRS = ("adrs", "docs/adr", "doc/adr", "docs/adrs")

VALID_INV_SOURCES = ("principle", "security", "adr", "interface")
VALID_ADR_STATUSES = ("Proposed", "Accepted", "Rejected", "Deprecated", "Superseded")


class ProjectReadError(ValueError):
    """Base class for project-read failures."""


class InvariantParseError(ProjectReadError):
    """Malformed invariants file."""


class ADRParseError(ProjectReadError):
    """Malformed ADR file or directory."""


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def read_invariants(root: str | Path) -> frozenset[Invariant]:
    """Read invariants from `<root>/.aios/invariants.{yaml,yml,json}`.

    Returns an empty set when no file is present — an uninitialized repo
    is not an error. Raises InvariantParseError on malformed content.
    """
    root_path = Path(root)
    aios_dir = root_path / ".aios"
    path = _find_first_existing(aios_dir, INVARIANT_FILENAMES)
    if path is None:
        return frozenset()

    try:
        raw = _load_structured(path)
    except Exception as e:
        raise InvariantParseError(f"could not parse {path}: {e}") from e

    if not isinstance(raw, dict):
        raise InvariantParseError(
            f"{path}: top-level must be a mapping with an `invariants:` key"
        )

    items = raw.get("invariants")
    if items is None:
        raise InvariantParseError(f"{path}: missing top-level key `invariants`")
    if not isinstance(items, list):
        raise InvariantParseError(f"{path}: `invariants` must be a list")

    seen_ids: set[str] = set()
    out: list[Invariant] = []
    for i, entry in enumerate(items):
        where = f"{path} invariant #{i}"
        if not isinstance(entry, dict):
            raise InvariantParseError(f"{where}: must be a mapping, got {type(entry).__name__}")
        for key in ("id", "source", "statement"):
            if key not in entry:
                raise InvariantParseError(f"{where}: missing required key `{key}`")
        if entry["source"] not in VALID_INV_SOURCES:
            raise InvariantParseError(
                f"{where}: source must be one of {VALID_INV_SOURCES}, got {entry['source']!r}"
            )
        if entry["id"] in seen_ids:
            raise InvariantParseError(f"{where}: duplicate invariant id {entry['id']!r}")
        seen_ids.add(entry["id"])
        out.append(Invariant(
            id=entry["id"],
            source=entry["source"],
            statement=str(entry["statement"]),
        ))
    return frozenset(out)


# ---------------------------------------------------------------------------
# ADRs
# ---------------------------------------------------------------------------


def read_adrs(root: str | Path) -> tuple[ADREvent, ...]:
    """Read ADRs from `<root>/adrs/` or `<root>/docs/adr/` (first found).

    Returns an empty tuple when no ADR directory is present. Files
    without YAML front matter are ignored with a silent skip (they
    may be drafts or READMEs). Files with malformed front matter
    raise ADRParseError.
    """
    root_path = Path(root)
    adr_dir = _find_first_adr_dir(root_path)
    if adr_dir is None:
        return tuple()

    adrs: list[ADREvent] = []
    seen_ids: set[str] = set()
    for md_path in sorted(adr_dir.glob("*.md")):
        front = _read_front_matter(md_path)
        if front is None:
            continue  # no front matter; probably a README

        for key in ("id", "status"):
            if key not in front:
                raise ADRParseError(f"{md_path}: front matter missing `{key}`")

        adr_id = str(front["id"])
        status = str(front["status"])
        if status not in VALID_ADR_STATUSES:
            raise ADRParseError(
                f"{md_path}: status must be one of {VALID_ADR_STATUSES}, got {status!r}"
            )

        if adr_id in seen_ids:
            raise ADRParseError(f"duplicate ADR id {adr_id!r} in {md_path}")
        seen_ids.add(adr_id)

        removes_raw = front.get("removes", [])
        if removes_raw in (None, ""):
            removes: Iterable[str] = ()
        elif isinstance(removes_raw, list):
            removes = [str(x) for x in removes_raw]
        elif isinstance(removes_raw, str):
            removes = [removes_raw]
        else:
            raise ADRParseError(
                f"{md_path}: `removes` must be list or string, got {type(removes_raw).__name__}"
            )

        deprecates = front.get("deprecates")
        if deprecates is not None and not isinstance(deprecates, str):
            raise ADRParseError(
                f"{md_path}: `deprecates` must be a string, got {type(deprecates).__name__}"
            )

        adrs.append(ADREvent(
            adr_id=adr_id,
            status=status,  # type: ignore[arg-type]
            removes=frozenset(removes),
            deprecates=deprecates,
        ))

    return tuple(adrs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_first_existing(parent: Path, names: Iterable[str]) -> Path | None:
    for name in names:
        p = parent / name
        if p.is_file():
            return p
    return None


def _find_first_adr_dir(root: Path) -> Path | None:
    for rel in ADR_DIRS:
        p = root / rel
        if p.is_dir():
            return p
    return None


def _load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(text)
    # yaml or yml
    return _parse_yaml_or_fallback(text, str(path))


def _parse_yaml_or_fallback(text: str, source: str):
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        # Minimal stdlib-only parser for the restricted subset we document.
        return _parse_yaml_minimal(text, source)


def _parse_yaml_minimal(text: str, source: str):
    """Parse the restricted YAML subset documented at module top.

    Supports:
      key: value                       string (quotes stripped if paired)
      key: [a, b, c]                   inline list of strings
      key:                             empty -> None
      invariants: (block list)
        - id: ...
          source: ...
          statement: ...

    Not supported: nested mappings inside inline lists, multi-line strings,
    folded/literal blocks, references. Those require PyYAML.
    """
    out: dict = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if line.startswith((" ", "\t")):
            # Stray indented line at top level; most often a continuation the
            # fallback parser can't handle. Surface a clear error.
            raise InvariantParseError(
                f"{source}: stdlib-only YAML fallback cannot parse indented "
                f"line {i+1!r}; install aios[enterprise] for full YAML support"
            )
        if ":" not in stripped:
            raise InvariantParseError(f"{source}: line {i+1}: expected `key: value`")
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if not value:
            # Block list follows
            items: list = []
            i += 1
            current: dict | None = None
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip() or nxt.strip().startswith("#"):
                    i += 1
                    continue
                if not nxt.startswith((" ", "\t")):
                    break
                inner = nxt.strip()
                if inner.startswith("- "):
                    current = {}
                    items.append(current)
                    inner = inner[2:].strip()
                if ":" in inner and current is not None:
                    k, _, v = inner.partition(":")
                    current[k.strip()] = _coerce_scalar(v.strip())
                i += 1
            out[key] = items
            continue
        out[key] = _coerce_scalar(value)
        i += 1
    return out


def _coerce_scalar(value: str) -> Any:
    """Turn a raw scalar into str / list per the documented mini-YAML subset."""
    if value == "" or value.lower() == "null" or value == "~":
        return None
    if value.startswith("[") and value.endswith("]"):
        inside = value[1:-1].strip()
        if not inside:
            return []
        return [_strip_quotes(x.strip()) for x in inside.split(",")]
    return _strip_quotes(value)


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _read_front_matter(md_path: Path) -> dict | None:
    """Return the parsed YAML front-matter mapping, or None if absent."""
    lines = md_path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        raise ADRParseError(f"{md_path}: front matter opened but never closed")

    front_text = "\n".join(lines[1:end])
    try:
        parsed = _parse_yaml_or_fallback(front_text, str(md_path))
    except InvariantParseError as e:
        # Re-raise as ADR-domain error
        raise ADRParseError(str(e)) from e
    except Exception as e:
        raise ADRParseError(f"{md_path}: front matter parse failed: {e}") from e

    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ADRParseError(
            f"{md_path}: front matter must be a mapping, got {type(parsed).__name__}"
        )
    return parsed
