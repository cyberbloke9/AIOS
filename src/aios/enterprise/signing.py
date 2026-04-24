"""Frame-signing interface + concrete Ed25519 implementation.

Runtime Protocol §1.2: the frame `sig` field carries an Ed25519
signature over the frame's canonical-CBOR encoding. REQUIRED on frames
that cross trust zones (Z3→Z4) in P-Enterprise and above.

Runtime Protocol §9.1: "Ed25519 signatures on capability tokens ...
Non-forgeability is the definition of a capability."

This module defines:
  - `Signer` / `Verifier` — the protocol a backend must satisfy.
  - `UnimplementedSigner` / `UnimplementedVerifier` — the default
    no-op implementations that refuse loudly (P-Local ships with these).
  - `Ed25519Signer` / `Ed25519Verifier` — real implementations backed
    by `cryptography.hazmat.primitives.asymmetric.ed25519`. Import is
    deferred so packages without the `enterprise` extra still import
    the module fine — they just cannot construct the concrete classes.

Install the enterprise extra to use Ed25519:
    pip install -e .[enterprise]
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


class SignatureVerificationError(ValueError):
    """Raised when a frame's `sig` does not verify against the issuer key."""


class CryptographyNotInstalledError(RuntimeError):
    """The `cryptography` package is required for Ed25519 but is missing."""


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


# ---------------------------------------------------------------------------
# Default no-op implementations (shipped with P-Local)
# ---------------------------------------------------------------------------


class UnimplementedSigner:
    """Default signer — always refuses."""

    def sign(self, frame_cbor: bytes) -> bytes:
        raise NotImplementedError(
            "Ed25519 signing is not configured in this build. P-Local does "
            "not require it. Install with `pip install aios[enterprise]` and "
            "construct Ed25519Signer() to declare a higher profile."
        )

    def public_key(self) -> bytes:
        raise NotImplementedError(
            "public_key not available: no concrete Signer is registered."
        )


class UnimplementedVerifier:
    """Default verifier — always refuses a signed frame."""

    def verify(self, frame_cbor: bytes, signature: bytes) -> bool:
        raise SignatureVerificationError(
            "Ed25519 verification is not configured in this build. Install "
            "the `enterprise` extra and construct an Ed25519Verifier(pubkey) "
            "to verify signed frames."
        )


# ---------------------------------------------------------------------------
# Concrete Ed25519 implementations (require `cryptography`)
# ---------------------------------------------------------------------------


def _require_cryptography():
    """Import cryptography lazily with a helpful error message."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
        from cryptography.exceptions import InvalidSignature as _InvalidSignature
    except ImportError as e:
        raise CryptographyNotInstalledError(
            "The `cryptography` package is required for Ed25519. "
            "Install with `pip install aios[enterprise]`."
        ) from e
    return _ed25519, _InvalidSignature


class Ed25519Signer:
    """Concrete Ed25519 signer backed by `cryptography`.

    Two constructors:
      Ed25519Signer.generate()       -> a fresh keypair
      Ed25519Signer(private_bytes)   -> load an existing 32-byte private key
    """

    def __init__(self, private_key_bytes: bytes):
        ed25519, _ = _require_cryptography()
        if len(private_key_bytes) != 32:
            raise ValueError(
                f"Ed25519 private key must be 32 bytes, got {len(private_key_bytes)}"
            )
        self._private = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self._private_bytes = private_key_bytes

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        ed25519, _ = _require_cryptography()
        priv = ed25519.Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cls(raw)

    def sign(self, frame_cbor: bytes) -> bytes:
        return self._private.sign(frame_cbor)

    def public_key(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_key_bytes(self) -> bytes:
        """Expose the 32-byte private key so callers can persist it.

        WARNING: treat this like any Ed25519 secret — never log it, never
        write it into a frame payload. Operator responsibility.
        """
        return self._private_bytes


class Ed25519Verifier:
    """Concrete Ed25519 verifier bound to one public key."""

    def __init__(self, public_key_bytes: bytes):
        ed25519, _ = _require_cryptography()
        if len(public_key_bytes) != 32:
            raise ValueError(
                f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}"
            )
        self._public = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        self._public_bytes = public_key_bytes

    def verify(self, frame_cbor: bytes, signature: bytes) -> bool:
        _, InvalidSignature = _require_cryptography()
        if len(signature) != 64:
            raise SignatureVerificationError(
                f"Ed25519 signatures are 64 bytes, got {len(signature)}"
            )
        try:
            self._public.verify(signature, frame_cbor)
        except InvalidSignature as e:
            raise SignatureVerificationError(
                f"signature does not verify against the configured public key"
            ) from e
        return True

    def public_key(self) -> bytes:
        return self._public_bytes


def cryptography_available() -> bool:
    """Return True iff Ed25519*() classes can be constructed in this environment."""
    try:
        _require_cryptography()
    except CryptographyNotInstalledError:
        return False
    return True
