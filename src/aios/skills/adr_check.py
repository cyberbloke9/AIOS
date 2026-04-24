"""SK-ADR-CHECK — validate ADR lifecycle + references (sprint 27).

Enforces Kernel Spec §2.4 ADR lifecycle plus reference integrity on a
directory of ADRs. Returns a structured list of violations so the
caller can decide whether any are blocking.

Violation kinds:
  dangling_deprecates         : `deprecates` points at a non-existent ADR
  invalid_deprecation_target  : `deprecates` target is Rejected / Proposed
                                / Superseded (not reachable by §2.4)
  rejected_removes_invariants : a Rejected ADR carries `removes` — it has
                                no authority to remove anything per
                                Constitution §1.1
  status_not_in_lifecycle     : sanity — not raised by this implementation
                                because the reader rejects bad statuses
                                at parse time; documented for callers

Input schema:
  {root: string}            path to the project dir containing the ADR folder

Output schema:
  {count: int, violations: [{adr_id, kind, detail}]}

Registered on import with aios.skills.default_skill_registry.
"""
from __future__ import annotations

from pathlib import Path

from aios.project.readers import read_adrs
from aios.skills.base import SkillContract, default_skill_registry

SKILL_ID = "SK-ADR-CHECK"


_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "root": {"type": "string", "minLength": 1},
    },
    "required": ["root"],
    "additionalProperties": False,
}

_VIOLATION_KINDS = (
    "dangling_deprecates",
    "invalid_deprecation_target",
    "rejected_removes_invariants",
)

_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "count": {"type": "integer", "minimum": 0},
        "violations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "adr_id": {"type": "string"},
                    "kind": {"enum": list(_VIOLATION_KINDS)},
                    "detail": {"type": "string"},
                },
                "required": ["adr_id", "kind", "detail"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["count", "violations"],
    "additionalProperties": False,
}


def sk_adr_check(inputs: dict) -> dict:
    root = Path(inputs["root"])
    adrs = read_adrs(root)
    by_id = {a.adr_id: a for a in adrs}

    violations: list[dict] = []

    for adr in adrs:
        if adr.deprecates:
            target = by_id.get(adr.deprecates)
            if target is None:
                violations.append({
                    "adr_id": adr.adr_id,
                    "kind": "dangling_deprecates",
                    "detail": (
                        f"deprecates {adr.deprecates} which is not in the "
                        f"ADR set"
                    ),
                })
            elif target.status not in ("Accepted", "Deprecated"):
                # §2.4: the successor of Accepted is Deprecated; Deprecated
                # -> Superseded. A Proposed/Rejected/Superseded target means
                # the current ADR's lifecycle claim is broken.
                violations.append({
                    "adr_id": adr.adr_id,
                    "kind": "invalid_deprecation_target",
                    "detail": (
                        f"deprecates {adr.deprecates} but target status is "
                        f"{target.status!r}; §2.4 requires Accepted or "
                        f"already-Deprecated"
                    ),
                })

        if adr.status == "Rejected" and adr.removes:
            # Constitution §1.1: only an Accepted ADR authorizes invariant
            # removal. A Rejected ADR holding a non-empty `removes` list is
            # a governance anomaly — either the status or the removes list
            # is wrong.
            violations.append({
                "adr_id": adr.adr_id,
                "kind": "rejected_removes_invariants",
                "detail": (
                    f"Rejected but declares removes={sorted(adr.removes)}; "
                    f"Constitution §1.1 requires Accepted status to remove "
                    f"invariants"
                ),
            })

    return {"count": len(violations), "violations": violations}


_CONTRACT = SkillContract(
    id=SKILL_ID,
    version="1.0.0",
    owner_authority="A2",   # Architect authors ADRs; Verifier checks
    description="Validate ADR lifecycle and reference integrity "
                "(Kernel §2.4, Constitution §1.1).",
    input_schema=_INPUT_SCHEMA,
    output_schema=_OUTPUT_SCHEMA,
    implementation=sk_adr_check,
)


default_skill_registry.register(_CONTRACT)
