"""P_schema_valid implementation (sprint 25).

Runtime shape per the Verification Spec §1.2 T3 predicate:

  input:  a CBOR/JSON-compatible artifact + a JSON Schema (dict or ref)
  output: {status: preserved|breached, ...}

Called via the registry:

    default_registry.evaluate(
        "P_schema_valid",
        runstate,
        artifact={"x": 1},
        schema={"type": "object", "required": ["x"]},
    )

If artifact + schema are both None (the runner has no per-artifact context
to pass), the predicate returns `preserved` with a `note` — there is
literally nothing to validate at this invocation layer. A workflow that
wants strict validation supplies the pair. This matches Kernel §1.2's
intent: schema checks are ON OUTPUTS, not on an empty set.
"""
from __future__ import annotations

from typing import Any

import jsonschema
from jsonschema import Draft202012Validator

from aios.verification.conservation_scan import RunState


def p_schema_valid(
    run: RunState,
    *,
    artifact: Any = None,
    schema: dict | None = None,
    validator_cls=Draft202012Validator,
) -> dict:
    """T3 schema-check predicate."""
    if artifact is None and schema is None:
        return {
            "status": "preserved",
            "note": "no artifact/schema supplied; nothing to validate",
        }
    if schema is None:
        return {
            "status": "breached",
            "error": "artifact supplied without schema",
        }
    if artifact is None:
        return {
            "status": "breached",
            "error": "schema supplied without artifact",
        }

    # Sanity-check the schema itself first so schema bugs don't masquerade
    # as artifact failures.
    try:
        validator_cls.check_schema(schema)
    except jsonschema.SchemaError as e:
        return {
            "status": "breached",
            "error": f"invalid JSON Schema: {e.message}",
            "path": list(e.absolute_path),
        }

    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(artifact), key=lambda e: list(e.absolute_path))
    if not errors:
        return {"status": "preserved"}

    return {
        "status": "breached",
        "error": errors[0].message,
        "path": list(errors[0].absolute_path),
        "error_count": len(errors),
        "all_errors": [
            {"message": e.message, "path": list(e.absolute_path)}
            for e in errors
        ],
    }
