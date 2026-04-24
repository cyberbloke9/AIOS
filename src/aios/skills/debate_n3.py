"""SK-DEBATE-N3 — multi-skill concurrence aggregator (sprint 70).

Distribution §1.1 names debate-N3 as a baseline skill. Runtime §7.6
budgets three-skill concurrence at p95 ≤ 90s. The mechanism: run N
skills on the same input, compute a majority verdict + agreement
score, report dissenters.

The DEBATE loop is not a model-call debate here — this is the
concurrence ORCHESTRATOR. Individual skills in the default registry
provide their own verdicts; debate_n3 aggregates. A later sprint can
add adversarial re-evaluation rounds (the "debate" part); v0.6
ships the concurrence primitive.

Input schema:
  {
    "skill_ids": ["SK-A", "SK-B", "SK-C"],      # 2+ skills
    "shared_inputs": {...},                      # merged into each call
    "per_skill_inputs": {"SK-A": {...}},         # optional per-skill overrides
    "min_skills": 2                              # default from §7.6: 3
  }

Output:
  {
    "verdict": "preserved" | "breached" | "mixed",
    "majority_count": int,
    "skill_count": int,
    "agreement_score": float (0..1),             # majority / N
    "verdicts": [{"skill_id", "status", "output"}],
    "dissenters": ["SK-X", ...]                  # skills that disagreed
  }

When a skill raises (missing impl, bad inputs, etc.), its verdict
becomes status='error' and it counts as a dissenter regardless of
the others. With strict=True, ANY error aborts aggregation with
a SkillOutputError.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from aios.skills.base import (
    SkillContract,
    SkillInputError,
    SkillOutputError,
    default_skill_registry,
)

SKILL_ID = "SK-DEBATE-N3"


_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "skill_ids": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
        },
        "shared_inputs": {"type": "object"},
        "per_skill_inputs": {
            "type": "object",
            "additionalProperties": {"type": "object"},
        },
        "min_skills": {"type": "integer", "minimum": 2, "default": 3},
        "strict": {"type": "boolean", "default": False},
    },
    "required": ["skill_ids"],
    "additionalProperties": False,
}


_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"enum": ["preserved", "breached", "mixed"]},
        "majority_count": {"type": "integer", "minimum": 0},
        "skill_count": {"type": "integer", "minimum": 0},
        "agreement_score": {"type": "number", "minimum": 0, "maximum": 1},
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "skill_id": {"type": "string"},
                    "status": {"type": "string"},
                    "output": {"type": "object"},
                },
                "required": ["skill_id", "status", "output"],
                "additionalProperties": False,
            },
        },
        "dissenters": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["verdict", "majority_count", "skill_count",
                  "agreement_score", "verdicts", "dissenters"],
    "additionalProperties": False,
}


def sk_debate_n3(inputs: dict) -> dict:
    skill_ids: list[str] = list(inputs["skill_ids"])
    shared: dict = dict(inputs.get("shared_inputs") or {})
    per_skill: dict[str, dict] = dict(inputs.get("per_skill_inputs") or {})
    min_skills = int(inputs.get("min_skills", 3))
    strict = bool(inputs.get("strict", False))

    if len(skill_ids) < min_skills:
        raise SkillInputError(
            f"debate requires >= {min_skills} skills, got {len(skill_ids)}"
        )
    if len(set(skill_ids)) != len(skill_ids):
        raise SkillInputError(
            f"debate refuses duplicate skill_ids: {skill_ids}"
        )

    verdicts: list[dict] = []
    for sid in skill_ids:
        call_inputs = {**shared, **per_skill.get(sid, {})}
        try:
            output = default_skill_registry.invoke(sid, call_inputs)
            status = _extract_status(output)
            verdicts.append({
                "skill_id": sid,
                "status": status,
                "output": output if isinstance(output, dict) else {"raw": output},
            })
        except Exception as e:
            if strict:
                raise SkillOutputError(
                    f"skill {sid!r} raised {type(e).__name__}: {e}"
                ) from e
            verdicts.append({
                "skill_id": sid,
                "status": "error",
                "output": {"error_type": type(e).__name__, "error": str(e)},
            })

    status_counts = Counter(v["status"] for v in verdicts)
    # Majority on preserved/breached only — error votes never win
    votable = [s for s in ("preserved", "breached")]
    best_status = max(votable, key=lambda s: status_counts.get(s, 0),
                       default="mixed")
    best_count = status_counts.get(best_status, 0)
    n = len(verdicts)
    if best_count * 2 <= n:   # strict majority required (more than half)
        verdict = "mixed"
    else:
        verdict = best_status
    dissenters = [
        v["skill_id"] for v in verdicts if v["status"] != verdict
    ] if verdict != "mixed" else [
        v["skill_id"] for v in verdicts if v["status"] == "error"
    ]

    return {
        "verdict": verdict,
        "majority_count": best_count if verdict != "mixed" else 0,
        "skill_count": n,
        "agreement_score": round(best_count / n, 3) if n else 0.0,
        "verdicts": verdicts,
        "dissenters": sorted(dissenters),
    }


def _extract_status(output: Any) -> str:
    """Pull a status string from the skill's output dict. Unknown
    shapes become 'error' so aggregation always has a string to count."""
    if isinstance(output, dict) and "status" in output:
        s = output["status"]
        if s in ("preserved", "breached"):
            return s
    return "error"


_CONTRACT = SkillContract(
    id=SKILL_ID,
    version="1.0.0",
    owner_authority="A4",
    description="Multi-skill concurrence. Runs N >= 3 skills on the same "
                "input, aggregates to a strict-majority verdict + agreement "
                "score + dissenter list. Skills that raise count as 'error' "
                "and dissenters. `strict=True` makes any error abort.",
    input_schema=_INPUT_SCHEMA,
    output_schema=_OUTPUT_SCHEMA,
    implementation=sk_debate_n3,
)


default_skill_registry.register(_CONTRACT)
