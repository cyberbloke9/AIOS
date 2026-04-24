"""JCS (RFC 8785 JSON Canonicalization Scheme) audit-export stub.

Runtime Protocol §3.2: "For audit exports, JCS per RFC 8785 is acceptable.
JCS and CBOR are not byte-compatible (JCS sorts UTF-16 code units; CBOR
sorts bytes of UTF-8)."

Runtime Protocol §9.2: JCS audit exports are REQUIRED for P-Enterprise
when audit reports cross system boundaries.

This module sketches the boundary: `jcs_encode` accepts JSON-compatible
values and returns bytes that are intended to be RFC 8785 canonical JSON.
The implementation is a *conservative subset* — bytes round-trip for the
frame shape AIOS actually emits (maps of ASCII-keyed string/int values)
but a production P-Enterprise implementation MUST validate against an
RFC 8785 test suite before relying on this for cross-org audit.

Known non-conformances in this v0.1.0 subset:
  - Floats are stringified with Python `repr`, not the RFC 8785
    shortest-round-trip algorithm.
  - Non-ASCII keys sort by UTF-8 bytes (CBOR rule), not UTF-16 code
    units (JCS rule). For ASCII-only keys the two orderings coincide.
  - Unicode normalization (NFC) is not applied.

Callers that need strict RFC 8785 MUST use an audited JCS library.
"""
from __future__ import annotations

import json
from typing import Any


class JCSEncodingError(ValueError):
    """Input contained something this subset cannot canonicalize."""


def jcs_encode(value: Any) -> bytes:
    """Conservative JCS subset. See module docstring for caveats."""
    try:
        # `sort_keys=True` gives byte-wise ASCII key ordering which matches
        # JCS for ASCII-only keys. Compact separators per RFC 8785 §3.1.
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as e:
        raise JCSEncodingError(str(e)) from e
    return text.encode("utf-8")
