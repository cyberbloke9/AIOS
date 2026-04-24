"""Macaroon-style capability tokens (sprint 62).

Runtime Protocol §2.2 token structure + §2.3 caveat chain. Implements
the cryptographic shape the spec names:

  - Base token: v / tid / iss / sub / act / scp / nbf / exp / sig
  - sig = Ed25519(issuer_sk, canonical_cbor(base_without_sig))
  - Caveat: {type, value, mac}
  - MAC chain: mac_i = HMAC-SHA256(prior_mac, canonical_cbor(caveat_i_without_mac))
    where prior_mac for the FIRST caveat is the Ed25519 signature bytes.

Key property (Macaroon paper):
  A holder can add (narrowing) caveats without returning to the issuer.
  The verifier still accepts the token because the MAC chain remains
  intact. The holder cannot REMOVE caveats — any attempt breaks the
  chain.

Caveat types supported:
  time       value = {nbf_ns, exp_ns}  — narrower than base nbf/exp
  scope      value = dict               — must be a sub-scope of base scp
  predicate  value = {"name": str, "arg": any}  — caller supplies predicate fn
  audience   value = {"aud": str}       — must match context.audience

Anything else in the caveat list is an unknown caveat and raises a
verification failure (deny by default).
"""
from __future__ import annotations

import dataclasses as dc
import hashlib
import hmac
import os
import time
from typing import Any, Callable, Literal

from aios.enterprise.signing import (
    Ed25519Verifier,
    SignatureVerificationError,
    Signer,
    cryptography_available,
)
from aios.runtime.event_log import cbor_encode

CaveatType = Literal["time", "scope", "predicate", "audience"]
TOKEN_VERSION = 1

# §2.5 default skew tolerance
_DEFAULT_CLOCK_SKEW_NS = 30 * 10**9   # 30 seconds


class MacaroonError(ValueError):
    """Base class for capability-token errors."""


class TokenVerificationError(MacaroonError):
    """Verification failed — base sig bad, caveat chain broken, or
    caveat rejected the context."""


@dc.dataclass(frozen=True)
class Caveat:
    type: CaveatType
    value: dict | str | int
    mac: bytes                  # 32-byte HMAC-SHA256

    def payload_bytes(self) -> bytes:
        """The bytes covered by this caveat's MAC — type + value."""
        return cbor_encode({"type": self.type, "value": self.value})


@dc.dataclass(frozen=True)
class CapabilityToken:
    """§2.2 base token + §2.3 caveat chain."""
    v: int
    tid: bytes                  # 16-byte random nonce
    iss: str
    sub: str
    act: str
    scp: dict
    nbf_ns: int
    exp_ns: int
    caveats: tuple[Caveat, ...]
    sig: bytes                  # 64-byte Ed25519 signature

    def base_bytes(self) -> bytes:
        """Canonical CBOR of the signature-covered base fields."""
        return cbor_encode({
            "v": self.v,
            "tid": self.tid,
            "iss": self.iss,
            "sub": self.sub,
            "act": self.act,
            "scp": self.scp,
            "nbf_ns": self.nbf_ns,
            "exp_ns": self.exp_ns,
        })


# ---------------------------------------------------------------------------
# Issuance + delegation
# ---------------------------------------------------------------------------


def issue_token(
    *,
    issuer_signer: Signer,
    issuer_id: str,
    subject: str,
    action: str,
    scope: dict,
    ttl_ns: int,
    now_ns: int | None = None,
    tid: bytes | None = None,
) -> CapabilityToken:
    """Issue a new capability token, Ed25519-signed by the issuer."""
    if not cryptography_available():
        raise MacaroonError(
            "cryptography package required to issue tokens; install "
            "aios[enterprise]"
        )
    if ttl_ns <= 0:
        raise MacaroonError(f"ttl_ns must be > 0, got {ttl_ns}")

    now = now_ns if now_ns is not None else time.time_ns()
    nonce = tid or os.urandom(16)
    if len(nonce) != 16:
        raise MacaroonError(f"tid must be 16 bytes, got {len(nonce)}")

    unsigned = CapabilityToken(
        v=TOKEN_VERSION,
        tid=nonce,
        iss=issuer_id,
        sub=subject,
        act=action,
        scp=dict(scope),
        nbf_ns=now,
        exp_ns=now + ttl_ns,
        caveats=(),
        sig=b"",
    )
    sig = issuer_signer.sign(unsigned.base_bytes())
    return dc.replace(unsigned, sig=sig)


def add_caveat(
    token: CapabilityToken,
    *,
    caveat_type: CaveatType,
    value: Any,
) -> CapabilityToken:
    """Return a new token with an extra caveat appended.

    The new caveat's MAC chains from the prior caveat's MAC (or from
    the Ed25519 signature if this is the first caveat). The holder
    cannot REMOVE caveats without breaking the chain, so this only
    narrows authority.
    """
    if caveat_type not in ("time", "scope", "predicate", "audience"):
        raise MacaroonError(f"unknown caveat type {caveat_type!r}")

    prior_mac = token.caveats[-1].mac if token.caveats else token.sig
    payload = cbor_encode({"type": caveat_type, "value": value})
    mac = hmac.new(prior_mac, payload, hashlib.sha256).digest()

    new_caveat = Caveat(type=caveat_type, value=value, mac=mac)
    return dc.replace(token, caveats=token.caveats + (new_caveat,))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dc.dataclass(frozen=True)
class VerifyContext:
    """What the caller presents to verify the token against."""
    subject: str
    action: str
    scope: dict
    now_ns: int
    audience: str | None = None
    predicates: dict[str, Callable[[Any, "VerifyContext"], bool]] = dc.field(
        default_factory=dict,
    )


def verify_token(
    token: CapabilityToken,
    *,
    issuer_pubkey: bytes,
    context: VerifyContext,
    clock_skew_ns: int = _DEFAULT_CLOCK_SKEW_NS,
) -> None:
    """Verify a capability token against a context.

    Raises TokenVerificationError on any failure. Returns None on
    success — in spec-ese, an absent exception is the capability.
    """
    if not cryptography_available():
        raise TokenVerificationError(
            "cryptography package required to verify tokens"
        )
    if token.v != TOKEN_VERSION:
        raise TokenVerificationError(
            f"unsupported token version: {token.v}"
        )

    # 1. Ed25519 signature over base
    verifier = Ed25519Verifier(issuer_pubkey)
    try:
        verifier.verify(token.base_bytes(), token.sig)
    except SignatureVerificationError as e:
        raise TokenVerificationError(f"base signature invalid: {e}") from e

    # 2. Caveat MAC chain
    prior_mac = token.sig
    for i, cav in enumerate(token.caveats):
        expected = hmac.new(prior_mac, cav.payload_bytes(),
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, cav.mac):
            raise TokenVerificationError(
                f"caveat[{i}] MAC chain broken"
            )
        prior_mac = cav.mac

    # 3. Subject / action / scope checks against BASE token
    if token.sub != context.subject:
        raise TokenVerificationError(
            f"subject mismatch: token.sub={token.sub!r} "
            f"context.subject={context.subject!r}"
        )
    if token.act != context.action:
        raise TokenVerificationError(
            f"action mismatch: token.act={token.act!r} "
            f"context.action={context.action!r}"
        )
    if not _scope_covers(token.scp, context.scope):
        raise TokenVerificationError(
            f"scope does not cover context: token.scp={token.scp} "
            f"context.scope={context.scope}"
        )

    # 4. Base time window (with skew tolerance)
    if context.now_ns + clock_skew_ns < token.nbf_ns:
        raise TokenVerificationError("token not yet valid (nbf in future)")
    if context.now_ns - clock_skew_ns > token.exp_ns:
        raise TokenVerificationError("token expired")

    # 5. Caveats (narrowing)
    for i, cav in enumerate(token.caveats):
        _apply_caveat(cav, context, clock_skew_ns, index=i)


def _apply_caveat(cav: Caveat, ctx: VerifyContext,
                  skew_ns: int, *, index: int) -> None:
    if cav.type == "time":
        if not isinstance(cav.value, dict):
            raise TokenVerificationError(
                f"caveat[{index}]: time value must be a dict"
            )
        nbf = cav.value.get("nbf_ns")
        exp = cav.value.get("exp_ns")
        if isinstance(nbf, int) and ctx.now_ns + skew_ns < nbf:
            raise TokenVerificationError(
                f"caveat[{index}]: time nbf in future"
            )
        if isinstance(exp, int) and ctx.now_ns - skew_ns > exp:
            raise TokenVerificationError(
                f"caveat[{index}]: time expired"
            )
    elif cav.type == "scope":
        if not isinstance(cav.value, dict):
            raise TokenVerificationError(
                f"caveat[{index}]: scope value must be a dict"
            )
        if not _scope_covers(cav.value, ctx.scope):
            raise TokenVerificationError(
                f"caveat[{index}]: scope does not cover context"
            )
    elif cav.type == "audience":
        expected = cav.value if isinstance(cav.value, str) else (
            cav.value.get("aud") if isinstance(cav.value, dict) else None
        )
        if ctx.audience != expected:
            raise TokenVerificationError(
                f"caveat[{index}]: audience mismatch "
                f"(token={expected!r} context={ctx.audience!r})"
            )
    elif cav.type == "predicate":
        if not isinstance(cav.value, dict):
            raise TokenVerificationError(
                f"caveat[{index}]: predicate value must be a dict"
            )
        name = cav.value.get("name")
        fn = ctx.predicates.get(name) if isinstance(name, str) else None
        if fn is None:
            raise TokenVerificationError(
                f"caveat[{index}]: predicate {name!r} has no evaluator "
                f"in VerifyContext.predicates"
            )
        if not fn(cav.value.get("arg"), ctx):
            raise TokenVerificationError(
                f"caveat[{index}]: predicate {name!r} returned False"
            )
    else:
        # Unknown caveat type — deny by default per §2.3 safety rule
        raise TokenVerificationError(
            f"caveat[{index}]: unknown type {cav.type!r}"
        )


def _scope_covers(scope: dict, ctx_scope: dict) -> bool:
    """scope COVERS ctx_scope iff every (k, v) in ctx_scope is also in scope
    at the same key, with equal value OR scope[k] is a list containing v."""
    for k, v in ctx_scope.items():
        if k not in scope:
            return False
        allowed = scope[k]
        if isinstance(allowed, list):
            if v not in allowed:
                return False
        else:
            if allowed != v:
                return False
    return True
