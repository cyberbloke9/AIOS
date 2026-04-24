"""Workflow manifest schema + parser (sprint 18).

Kernel Spec §1.2 defines the impact-level → required-gate-set mapping:

  local        -> P_Q1_invariant_integrity,
                  P_Q2_state_traceability,
                  schema checks on outputs
  subsystem    -> local set +
                  P_Q3_decision_reversibility,
                  P_M4_independence >= 0.5,
                  acceptance tests
  system_wide  -> subsystem set +
                  adversarial injection suite,
                  drift regression,
                  containment regression

A workflow manifest declares the impact level and MAY add workflow-specific
gates. The runner expands the declared gates to the per-impact default set
before execution; extra gates are additive, never subtractive (the manifest
cannot OPT OUT of required gates).

Manifest format (YAML or JSON):

  id: pricing-refactor
  version: 1.0.0
  impact: subsystem                 # local | subsystem | system_wide
  description: migrate pricing...   # optional
  required_gates:                   # optional; merged with impact defaults
    - P_acceptance_tests
  required_invariants:              # optional; forwarded to the run's context
    - INV-001
    - INV-pricing-sync

All listed predicate IDs MUST be registered with the gate registry at
parse time; unknown IDs raise ManifestError.
"""
from __future__ import annotations

import dataclasses as dc
import json
from pathlib import Path
from typing import Literal

from aios.verification.registry import Registry, default_registry

ImpactLevel = Literal["local", "subsystem", "system_wide"]

VALID_IMPACT_LEVELS: tuple[ImpactLevel, ...] = ("local", "subsystem", "system_wide")


class ManifestError(ValueError):
    """Raised when a workflow manifest is malformed or references unknown gates."""


# ---------------------------------------------------------------------------
# Per-impact default gate sets (Kernel §1.2)
# ---------------------------------------------------------------------------

_LOCAL_DEFAULTS: tuple[str, ...] = (
    "P_Q1_invariant_integrity",
    "P_Q2_state_traceability",
    "P_schema_valid",
)

_SUBSYSTEM_DEFAULTS: tuple[str, ...] = _LOCAL_DEFAULTS + (
    "P_Q3_decision_reversibility",
    "P_M4_independence",
    "P_acceptance_tests",
)

# system_wide adds adversarial injection, drift regression, containment
# regression. None of those three have stub IDs in this build yet — they
# are workflow-specific test suites. We add P_PI_sentinel as the nearest
# registered stand-in; a production deployment must expand.
_SYSTEM_WIDE_DEFAULTS: tuple[str, ...] = _SUBSYSTEM_DEFAULTS + (
    "P_PI_sentinel",
)


def default_required_gates(impact: ImpactLevel) -> tuple[str, ...]:
    """Return the Kernel §1.2 default gate set for the given impact level."""
    if impact == "local":
        return _LOCAL_DEFAULTS
    if impact == "subsystem":
        return _SUBSYSTEM_DEFAULTS
    if impact == "system_wide":
        return _SYSTEM_WIDE_DEFAULTS
    raise ManifestError(f"invalid impact level: {impact!r}")


# ---------------------------------------------------------------------------
# WorkflowManifest
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class WorkflowManifest:
    id: str
    version: str
    impact: ImpactLevel
    required_gates: tuple[str, ...]  # union of impact defaults + manifest-specified
    required_invariants: tuple[str, ...]
    description: str = ""

    @property
    def gate_set(self) -> tuple[str, ...]:
        """Alias for required_gates for readability in runner code."""
        return self.required_gates


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_manifest(source: str | bytes | Path, *,
                   format: Literal["auto", "yaml", "json"] = "auto",
                   registry: Registry | None = None) -> WorkflowManifest:
    """Parse a manifest from a file path, raw text, or bytes.

    `format='auto'` detects by file extension when source is a Path, or
    tries JSON first then YAML when source is a string / bytes.

    The loader validates:
      - required top-level keys (`id`, `version`, `impact`)
      - impact is one of local / subsystem / system_wide
      - `required_gates` (if present) is a list of strings
      - every predicate ID (defaults + manifest-specified) is registered

    Returns a frozen WorkflowManifest with required_gates = union of
    impact defaults and manifest-specified gates (deduped, ordered).
    """
    reg = registry if registry is not None else default_registry

    # Normalize source to text + resolved format
    text, fmt = _resolve_source(source, format)

    raw = _parse_text(text, fmt)

    if not isinstance(raw, dict):
        raise ManifestError(f"manifest must be a mapping, got {type(raw).__name__}")

    _require(raw, "id", str)
    _require(raw, "version", str)
    _require(raw, "impact", str)

    if raw["impact"] not in VALID_IMPACT_LEVELS:
        raise ManifestError(
            f"impact must be one of {VALID_IMPACT_LEVELS}, got {raw['impact']!r}"
        )

    # Combine impact defaults + manifest-specified gates, preserving order
    defaults = default_required_gates(raw["impact"])
    extras = raw.get("required_gates", []) or []
    if not isinstance(extras, list) or not all(isinstance(x, str) for x in extras):
        raise ManifestError("required_gates must be a list of strings")

    combined: list[str] = []
    seen: set[str] = set()
    for pid in tuple(defaults) + tuple(extras):
        if pid not in seen:
            combined.append(pid)
            seen.add(pid)

    # All predicate IDs must be registered (Verification §1)
    try:
        reg.require_registered(combined)
    except Exception as e:
        raise ManifestError(str(e)) from e

    invariants = raw.get("required_invariants", []) or []
    if not isinstance(invariants, list) or not all(isinstance(x, str) for x in invariants):
        raise ManifestError("required_invariants must be a list of strings")

    return WorkflowManifest(
        id=raw["id"],
        version=raw["version"],
        impact=raw["impact"],
        required_gates=tuple(combined),
        required_invariants=tuple(invariants),
        description=raw.get("description", "") or "",
    )


def _resolve_source(source, format):
    if isinstance(source, Path):
        text = source.read_text(encoding="utf-8")
        if format == "auto":
            suffix = source.suffix.lower()
            if suffix in (".yml", ".yaml"):
                fmt = "yaml"
            elif suffix == ".json":
                fmt = "json"
            else:
                fmt = "auto"  # fall through to content sniff
        else:
            fmt = format
    else:
        if isinstance(source, bytes):
            text = source.decode("utf-8")
        else:
            text = source
        fmt = format

    return text, fmt


def _parse_text(text: str, fmt: str):
    if fmt == "json":
        return json.loads(text)
    if fmt == "yaml":
        return _parse_yaml(text)
    # auto: try JSON, then YAML
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return _parse_yaml(text)
        except ImportError:
            raise ManifestError(
                "manifest is not valid JSON and PyYAML is not installed; "
                "install with `pip install aios[enterprise]` or supply JSON"
            )


def _parse_yaml(text: str):
    try:
        import yaml
    except ImportError:
        raise
    return yaml.safe_load(text)


def _require(d: dict, key: str, typ):
    if key not in d:
        raise ManifestError(f"manifest missing required key: {key!r}")
    if not isinstance(d[key], typ):
        raise ManifestError(
            f"manifest key {key!r} must be {typ.__name__}, got {type(d[key]).__name__}"
        )
