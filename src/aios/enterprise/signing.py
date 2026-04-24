"""Frame-signing interface (sprint 10 stub).

Runtime Protocol §1.2: the frame `sig` field carries an Ed25519
signature over the frame's canonical-CBOR encoding. REQUIRED on frames
that cross trust zones (Z3→Z4) in P-Enterprise and above.

This module defines the Signer and Verifier protocols. No actual
Ed25519 backend is shipped with v0.1.0. An implementer provides a
concrete class conforming to these protocols (typically backed by
`cryptography.hazmat.primitives.asymmetric.ed25519`) and registers it
before declaring any profile above P-Local.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


class SignatureVerificationError(ValueError):
    """Raised when a frame's `sig` does not verify against the issuer key."""


@runtime_checkable
class Signer(Protocol):
    """Produces a 64-byte Ed25519 signature over a frame's CBOR bytes."""

    def sign(self, frame_cbor: bytes) -> bytes:  # pragma: no cover - interface
        """Return a 64-byte signature."""
        ...

    def public_key(self) -> bytes:  # pragma: no cover - interface
        """Return the 32-byte Ed25519 public key identifying this signer."""
        ...


@runtime_checkable
class Verifier(Protocol):
    """Verifies a 64-byte Ed25519 signature over frame CBOR bytes."""

    def verify(self, frame_cbor: bytes, signature: bytes) -> bool:  # pragma: no cover
        """Return True iff the signature is valid. Never suppress exceptions."""
        ...


class UnimplementedSigner:
    """Default signer — always refuses. Registered so frames with a
    declared signer never silently pass without one."""

    def sign(self, frame_cbor: bytes) -> bytes:
        raise NotImplementedError(
            "Ed25519 signing is not implemented in v0.1.0. P-Local does "
            "not require it. Provide a concrete Signer to declare a "
            "higher profile (see src/aios/enterprise/signing.py)."
        )

    def public_key(self) -> bytes:
        raise NotImplementedError(
            "public_key not available: no concrete Signer is registered."
        )


class UnimplementedVerifier:
    """Default verifier — always refuses a signed frame."""

    def verify(self, frame_cbor: bytes, signature: bytes) -> bool:
        raise SignatureVerificationError(
            "Ed25519 verification is not implemented in v0.1.0. A frame "
            "carrying a `sig` field cannot be cleared by this build. "
            "P-Local accepts only unsigned frames."
        )
