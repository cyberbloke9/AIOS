"""Profile loader and enforcement (sprint 5).

Runtime Protocol §10.6: "Each profile's required-clause set is a loader
check: at system start, the loader verifies each required mechanism is
present and functional. A deployment that declares P-HighAssurance but
lacks Merkle batch frames fails at loader time. This is the
ANti-'checkbox compliance' rule: profiles are not flags; they are
enforceable constraints."

This v0.1.0 build implements the P-Local profile only (Runtime §10.1).
Declaring any other profile causes `check_profile` to return failed with
an explicit list of features this build does not yet implement.

P-Local MUST (Runtime §10.1):
  - Constitution I-VII (enforced by any_breach() on Q1-Q3)
  - Runtime Protocol §§1, 3, 4, 5 as covered by event_log.py
  - §9.1 cryptographic core — SHA-256 + CRC-32C + deterministic CBOR
    are present; Ed25519/HMAC token chain is deferred (see below)
  - Kernel Spec §§1-3 (trust zones, state machines, failure domains)
  - Verification Spec §1 (gate registry)
  - Distribution §1 (package identity) and §4.1 (install contract)

Deferrals documented in docs/coverage.md. The loader refuses
non-P-Local profiles rather than silently accepting them.
"""
from __future__ import annotations

import dataclasses as dc
from pathlib import Path
from typing import Literal

from aios import __spec_versions__
from aios.runtime.event_log import EventLog
from aios.runtime.init import VALID_PROFILES, read_config
from aios.verification.registry import default_registry

CheckStatus = Literal["pass", "fail", "warn"]

_REQUIRED_CORE_PREDICATES = (
    "P_Q1_invariant_integrity",
    "P_Q2_state_traceability",
    "P_Q3_decision_reversibility",
    "P_M4_independence",
    "P_O5_context_sufficiency_hard",
)

# Features this build does not implement but Runtime Protocol §10.2/§10.3/§10.4
# require for non-P-Local profiles. Returned verbatim when the loader refuses.
_UNIMPLEMENTED_IN_V1 = {
    "P-Enterprise": [
        "Ed25519 capability tokens (§2)",
        "TUF role separation + bootstrap (§6)",
        "JCS audit export for cross-system reports (§3.2)",
        "Credentialing Phase 0 + Phase 1 (Verification Spec §3)",
        "Calibration protocol with anti-theater corpus checks (Verification §2)",
    ],
    "P-Airgap": [
        "Ed25519 capability tokens (§2)",
        "TUF offline root setup (§6.2)",
        "Air-gapped signed-bundle install path (Distribution §3.4 / §6.2)",
        "Zero-telemetry enforcement at loader level",
    ],
    "P-HighAssurance": [
        "Ed25519 capability tokens (§2)",
        "Merkle batch overlay (§1.5)",
        "DPoP proof-of-possession on every token (§2.8)",
        "External Sigstore/Rekor transparency log publication (§1.5 / Distribution §5.4)",
        "Reproducible builds with diverse-builder attestation (Distribution §5.2)",
        "Hardware-root-of-trust hooks (TPM/TEE attestation for bootstrap)",
    ],
}


@dc.dataclass(frozen=True)
class Check:
    name: str
    status: CheckStatus
    detail: str


@dc.dataclass(frozen=True)
class ProfileCheckResult:
    profile: str
    passed: bool
    checks: tuple[Check, ...]

    def format_report(self) -> str:
        lines = [f"AIOS profile: {self.profile}",
                 f"Overall: {'PASS' if self.passed else 'FAIL'}",
                 ""]
        for c in self.checks:
            marker = {"pass": "[ok]", "fail": "[FAIL]", "warn": "[warn]"}[c.status]
            lines.append(f"  {marker} {c.name}: {c.detail}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Loader entry point
# ---------------------------------------------------------------------------


def check_profile(aios_home: str | Path) -> ProfileCheckResult:
    """Run the profile-enforcement checks for an initialized AIOS home."""
    root = Path(aios_home).resolve()

    config_checks = list(_run_config_checks(root))
    profile = _extract_declared_profile(root)

    if profile is None:
        return ProfileCheckResult(profile="<unknown>", passed=False,
                                  checks=tuple(config_checks))

    if profile == "P-Local":
        profile_checks = list(_run_p_local_checks(root))
    elif profile in _UNIMPLEMENTED_IN_V1:
        profile_checks = list(_run_unsupported_checks(profile))
    else:
        profile_checks = [Check("profile.recognized", "fail",
                                f"{profile!r} is not a known profile; "
                                f"expected one of {VALID_PROFILES}")]

    all_checks = tuple(config_checks) + tuple(profile_checks)
    passed = all(c.status != "fail" for c in all_checks)
    return ProfileCheckResult(profile=profile, passed=passed, checks=all_checks)


# ---------------------------------------------------------------------------
# Individual check groups
# ---------------------------------------------------------------------------


def _run_config_checks(root: Path):
    config_path = root / "config.json"
    if not config_path.exists():
        yield Check("config.present", "fail",
                    f"no config.json at {config_path} "
                    f"(run `aios init` first)")
        return

    yield Check("config.present", "pass", str(config_path))

    try:
        config = read_config(root)
    except Exception as e:
        yield Check("config.readable", "fail", f"{type(e).__name__}: {e}")
        return

    yield Check("config.readable", "pass", "config.json parsed")

    expected = __spec_versions__
    actual = config.get("spec_versions", {})
    mismatches = [f"{k}: config={actual.get(k)} pkg={v}"
                  for k, v in expected.items() if actual.get(k) != v]
    if mismatches:
        yield Check("config.spec_versions", "fail",
                    "spec version mismatch: " + ", ".join(mismatches))
    else:
        yield Check("config.spec_versions", "pass",
                    f"all {len(expected)} spec versions match package")

    profile = config.get("profile")
    if profile in VALID_PROFILES:
        yield Check("config.profile_declared", "pass", profile)
    else:
        yield Check("config.profile_declared", "fail",
                    f"invalid profile {profile!r}")


def _extract_declared_profile(root: Path) -> str | None:
    try:
        config = read_config(root)
    except Exception:
        return None
    p = config.get("profile")
    if p in VALID_PROFILES:
        return p
    return None


def _run_p_local_checks(root: Path):
    events_dir = root / "events"
    if not events_dir.is_dir():
        yield Check("events.dir_present", "fail", f"{events_dir} missing")
        return
    yield Check("events.dir_present", "pass", str(events_dir))

    try:
        log = EventLog(events_dir)
    except Exception as e:
        yield Check("events.log_openable", "fail", f"{type(e).__name__}: {e}")
        return

    try:
        frames = list(log.replay())
    except Exception as e:
        log.close()
        yield Check("events.replay_ok", "fail",
                    f"replay refused: {type(e).__name__}: {e}")
        return
    finally:
        log.close()

    yield Check("events.replay_ok", "pass",
                f"{len(frames)} frame(s) replay with unbroken hash chain")

    # §10.5 profile.declared must be present in the log
    declared = [f for f in frames if f.kind == "profile.declared"]
    if not declared:
        yield Check("events.profile_declared_event", "fail",
                    "no profile.declared event found")
    else:
        latest = declared[-1]
        yield Check("events.profile_declared_event", "pass",
                    f"seq={latest.seq} profile={latest.payload.get('profile')}")

    # P-Local MUST NOT use capability tokens (Ed25519 not implemented).
    signed = [f for f in frames if f.sig is not None]
    if signed:
        yield Check("p_local.no_capability_tokens", "fail",
                    f"{len(signed)} frame(s) carry `sig` bytes; P-Local v0.1.0 "
                    f"does not implement Ed25519 token verification")
    else:
        yield Check("p_local.no_capability_tokens", "pass",
                    "no frames carry capability-token signatures")

    # Gate registry must have the five core Q/M/O predicates (Verification §1.2).
    missing = [pid for pid in _REQUIRED_CORE_PREDICATES
               if not default_registry.has(pid)]
    if missing:
        yield Check("verification.core_predicates", "fail",
                    f"missing from registry: {missing}")
    else:
        yield Check("verification.core_predicates", "pass",
                    f"{len(_REQUIRED_CORE_PREDICATES)} core predicates registered")


def _run_unsupported_checks(profile: str):
    missing = _UNIMPLEMENTED_IN_V1[profile]
    yield Check(
        f"{profile.lower()}.feature_coverage",
        "fail",
        f"{profile} declared but v0.1.0 does not implement: "
        + "; ".join(missing) + ". Reinitialize with --profile P-Local "
        "or wait for a build that ships these features.",
    )
