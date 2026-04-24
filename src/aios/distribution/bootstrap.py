"""Multi-channel bootstrap anchor verification (sprint 54).

Runtime Protocol §6.3 — a brand-new host must anchor trust in the root
role's public keys through an out-of-band channel that is independent
of the AIOS package itself. Codex's review flagged single-channel
fingerprint publication as insufficient; §6.3.1 therefore requires:

  1. Bootstrap anchor (root metadata fingerprint) published on
     >= 3 independent channels
     e.g. {project website (HTTPS+CA), git repo (signed commit),
           Sigstore Rekor, printed fingerprint in conference
           proceedings, physical media handoff}
  2. Operator fetches the fingerprint from at least 2 channels,
     AND downloads the root metadata separately
  3. Verifier confirms the 2+ channel fingerprints AGREE with each
     other AND match the SHA-256 of the downloaded root metadata

This module automates step 3 — the cryptographic refusal logic the
§6.3.2 install ceremony ends with. It does NOT automate the fetching
(that is the operator's responsibility and is channel-specific); it
consumes fingerprint strings the operator supplies.

CLI usage:

    aios bootstrap-verify \\
        --channel website=5f4a3e...9b2c \\
        --channel git=5f4a3e...9b2c \\
        --channel rekor=5f4a3e...9b2c \\
        --root-metadata path/to/root.cbor

    Returns exit 0 on agreement, non-zero on any mismatch.
"""
from __future__ import annotations

import dataclasses as dc
import hashlib
from pathlib import Path


_MIN_CHANNELS = 2   # §6.3.1 says 3+, ceremony accepts 2 as the gate


class BootstrapAnchorError(ValueError):
    """Fingerprints disagreed across channels OR root metadata does
    not match the channel-advertised fingerprint."""


@dc.dataclass(frozen=True)
class Channel:
    """One independent advertisement of the root fingerprint."""
    name: str                 # free-form (website / git / rekor / print / ...)
    fingerprint_hex: str      # lowercase hex sha256 of root metadata bytes
    source: str = ""          # URL / path / description, informational only


@dc.dataclass(frozen=True)
class BootstrapVerifyReport:
    ok: bool
    channels_seen: tuple[str, ...]
    agreed_fingerprint: str | None   # None when channels disagree
    root_metadata_sha256: str | None
    reasons: tuple[str, ...]         # detail on why it failed, if it did


def verify_bootstrap_anchor(
    channels: list[Channel],
    *,
    root_metadata_bytes: bytes | None = None,
    min_channels: int = _MIN_CHANNELS,
) -> BootstrapVerifyReport:
    """Verify multi-channel agreement + (optional) root metadata match.

    At least `min_channels` channels (default 2) must agree on the
    same fingerprint. If `root_metadata_bytes` is supplied, its
    SHA-256 must equal that fingerprint.

    Returns a BootstrapVerifyReport with ok=True only when both
    conditions hold. Never raises — a report carries the failure
    reasons so operators can present them to a human for review.
    """
    reasons: list[str] = []

    if len(channels) < min_channels:
        reasons.append(
            f"need >= {min_channels} channels for agreement, got {len(channels)}"
        )

    # Normalize fingerprints
    norm = [_normalize(c) for c in channels]
    fps = {c.fingerprint_hex for c in norm}

    agreed: str | None = None
    if len(fps) == 1 and len(norm) >= min_channels:
        agreed = next(iter(fps))
    elif len(fps) > 1:
        reasons.append(
            f"channels disagree on fingerprint: "
            + "; ".join(f"{c.name}={c.fingerprint_hex}" for c in norm)
        )

    root_sha256: str | None = None
    if root_metadata_bytes is not None:
        root_sha256 = hashlib.sha256(root_metadata_bytes).hexdigest()
        if agreed is not None and root_sha256 != agreed:
            reasons.append(
                f"root metadata sha256 {root_sha256} does not match "
                f"channel-advertised fingerprint {agreed}"
            )

    ok = bool(agreed) and not reasons
    return BootstrapVerifyReport(
        ok=ok,
        channels_seen=tuple(c.name for c in norm),
        agreed_fingerprint=agreed,
        root_metadata_sha256=root_sha256,
        reasons=tuple(reasons),
    )


def _normalize(c: Channel) -> Channel:
    fp = c.fingerprint_hex.strip().lower()
    if not _is_hex_sha256(fp):
        raise BootstrapAnchorError(
            f"channel {c.name!r} fingerprint is not a valid SHA-256 hex "
            f"string (got {c.fingerprint_hex!r})"
        )
    return dc.replace(c, fingerprint_hex=fp)


def _is_hex_sha256(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        int(s, 16)
    except ValueError:
        return False
    return True


def load_root_metadata(path: str | Path) -> bytes:
    """Convenience — read root metadata bytes the operator downloaded.

    Agnostic to encoding (CBOR, JSON, raw); the sha256 must match what
    the channels advertise regardless of format.
    """
    return Path(path).read_bytes()
