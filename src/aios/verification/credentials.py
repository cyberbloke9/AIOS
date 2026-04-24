"""Credential ledger + record schema (sprint 38).

Verification Spec §3.2 credential record schema:

    credential:
      entity_id: A4 | SK-ADR-CHECK | ...
      phase: 0 | 1
      standing: <float, [0.0, 1.0]>
      competency_bands:
        local:       {standing, runs, breaches, last_breach}
        subsystem:   {...}
        system_wide: {...}
      restitution_budget:
        remaining: <int>
        class: <error class triggering restitution>
      linked_calibration: <path | null>

Seeding (§3.1): when a credential is created it is Phase 0 with
standing=0.5 across all bands. Phase 0 is inert — credentials
accumulate observational data but do not gate capability. The
Phase 0 → Phase 1 transition is a separate event (sprint 41) that
requires the §3.1 prerequisites to be met.

This sprint handles the data model + ledger persistence. Update
rule and band-capability mapping are sprints 41-42.
"""
from __future__ import annotations

import dataclasses as dc
import json
from pathlib import Path
from typing import Literal

Phase = Literal[0, 1]
Band = Literal["local", "subsystem", "system_wide"]

_SEED_STANDING = 0.5
_BANDS: tuple[Band, ...] = ("local", "subsystem", "system_wide")


class CredentialError(ValueError):
    """Base for credential-ledger errors."""


@dc.dataclass(frozen=True)
class BandStanding:
    """Per-band competency track."""
    standing: float
    runs: int = 0
    breaches: int = 0
    last_breach_iso: str | None = None

    def with_clean_run(self, alpha: float) -> "BandStanding":
        return dc.replace(
            self,
            standing=_clamp(self.standing + alpha),
            runs=self.runs + 1,
        )

    def with_breach(self, gamma: float, now_iso: str) -> "BandStanding":
        return dc.replace(
            self,
            standing=_clamp(self.standing - gamma),
            runs=self.runs + 1,
            breaches=self.breaches + 1,
            last_breach_iso=now_iso,
        )

    def with_gate_fail(self, beta: float) -> "BandStanding":
        return dc.replace(
            self,
            standing=_clamp(self.standing - beta),
            runs=self.runs + 1,
        )


@dc.dataclass(frozen=True)
class RestitutionBudget:
    """Recurrence restitution per §3.5."""
    remaining: int
    error_class: str


@dc.dataclass(frozen=True)
class CredentialRecord:
    """§3.2 credential record."""
    entity_id: str
    phase: Phase
    competency_bands: dict[str, BandStanding]
    restitution_budget: RestitutionBudget | None = None
    linked_calibration: str | None = None

    @property
    def standing(self) -> float:
        """Overall standing = min of band standings (most-restrictive band)."""
        if not self.competency_bands:
            return _SEED_STANDING
        return min(b.standing for b in self.competency_bands.values())

    def band(self, name: Band) -> BandStanding:
        return self.competency_bands[name]

    def with_band(self, name: Band, value: BandStanding) -> "CredentialRecord":
        new_bands = dict(self.competency_bands)
        new_bands[name] = value
        return dc.replace(self, competency_bands=new_bands)

    # --- serialization ---

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "phase": self.phase,
            "competency_bands": {
                k: dc.asdict(v) for k, v in self.competency_bands.items()
            },
            "restitution_budget": (
                dc.asdict(self.restitution_budget)
                if self.restitution_budget else None
            ),
            "linked_calibration": self.linked_calibration,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CredentialRecord":
        bands = {
            k: BandStanding(**v) for k, v in data["competency_bands"].items()
        }
        rb_raw = data.get("restitution_budget")
        rb = RestitutionBudget(**rb_raw) if rb_raw else None
        return cls(
            entity_id=data["entity_id"],
            phase=data["phase"],
            competency_bands=bands,
            restitution_budget=rb,
            linked_calibration=data.get("linked_calibration"),
        )


def seed_credential(entity_id: str, *,
                    linked_calibration: str | None = None) -> CredentialRecord:
    """Create a new Phase-0 credential seeded at 0.5 across all bands."""
    return CredentialRecord(
        entity_id=entity_id,
        phase=0,
        competency_bands={b: BandStanding(standing=_SEED_STANDING) for b in _BANDS},
        linked_calibration=linked_calibration,
    )


# ---------------------------------------------------------------------------
# Ledger — one JSON file per AIOS home
# ---------------------------------------------------------------------------


def _ledger_path(aios_home: str | Path) -> Path:
    return Path(aios_home) / "credentials" / "ledger.json"


class CredentialLedger:
    """Collection of CredentialRecord keyed by entity_id.

    All mutations go through methods so callers cannot skew standing
    without leaving a trail of BandStanding updates.
    """

    def __init__(self, aios_home: str | Path):
        self._home = Path(aios_home)
        self._records: dict[str, CredentialRecord] = {}
        self._load()

    def _load(self) -> None:
        p = _ledger_path(self._home)
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise CredentialError(f"ledger {p} is malformed: {e}") from e
        for entity_id, rec in data.items():
            self._records[entity_id] = CredentialRecord.from_dict(rec)

    def save(self) -> Path:
        p = _ledger_path(self._home)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {eid: rec.to_dict() for eid, rec in self._records.items()}
        p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                     encoding="utf-8")
        return p

    def has(self, entity_id: str) -> bool:
        return entity_id in self._records

    def get(self, entity_id: str) -> CredentialRecord:
        try:
            return self._records[entity_id]
        except KeyError:
            raise CredentialError(
                f"no credential for {entity_id!r}; seed one via "
                f"ledger.seed({entity_id!r})"
            )

    def seed(self, entity_id: str, *,
             linked_calibration: str | None = None) -> CredentialRecord:
        if entity_id in self._records:
            raise CredentialError(
                f"credential for {entity_id!r} already exists; use "
                f"ledger.get({entity_id!r}) to read it"
            )
        rec = seed_credential(entity_id, linked_calibration=linked_calibration)
        self._records[entity_id] = rec
        return rec

    def put(self, record: CredentialRecord) -> None:
        self._records[record.entity_id] = record

    def list_entities(self) -> list[str]:
        return sorted(self._records)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clamp(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x
