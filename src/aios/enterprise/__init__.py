"""P-Enterprise extensions — interface definitions only (sprint 10).

This subpackage defines the **shape** of the features that Runtime
Protocol §10.2 requires beyond P-Local. None of them are functional in
v0.1.0; calling any operation raises `NotImplementedError` or the
type-specific subclass. The loader in `runtime.profile` refuses the
P-Enterprise profile until these stubs are replaced with real
implementations.

The reason interfaces ship while implementations do not:
  1. A v1 port to another language (Rust, Go, TypeScript) has a target
     shape to match.
  2. A would-be implementer sees the exact signatures needed to turn
     P-Enterprise from a refused declaration into a supported one.
  3. The gap between "interface exists" and "feature works" is auditable.

See docs/coverage.md for the full not-implemented list.
"""
from __future__ import annotations

from aios.enterprise.jcs import jcs_encode, JCSEncodingError
from aios.enterprise.signing import (
    Signer,
    Verifier,
    UnimplementedSigner,
    UnimplementedVerifier,
    SignatureVerificationError,
)

__all__ = [
    "jcs_encode",
    "JCSEncodingError",
    "Signer",
    "Verifier",
    "UnimplementedSigner",
    "UnimplementedVerifier",
    "SignatureVerificationError",
]
