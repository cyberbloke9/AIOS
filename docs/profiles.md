# Profiles

> Summary of Runtime Protocol §10 as enforced by v0.1.0 of this package.

A deployment declares exactly one profile. The loader refuses to start
when the declared profile requires mechanisms this build does not
implement. Declaring a profile you cannot support is a loader-time
failure, not a checkbox.

## The four profiles

| Profile | Target | v0.1.0 of `aios` |
|---|---|---|
| **P-Local**        | single developer, one project   | ✅ fully supported |
| **P-Enterprise**   | organization with audit         | ❌ refused at loader |
| **P-Airgap**       | offline / sovereign             | ❌ refused at loader |
| **P-HighAssurance**| hostile-review-grade            | ❌ refused at loader |

## P-Local (supported)

```
aios init ./my-home --profile P-Local
aios check-profile --home ./my-home
```

### MUST

- Constitution I–VII — enforced by `conservation_scan.any_breach` on Q1-Q3
- Runtime Protocol §§1, 3, 4, 5 — implemented in `runtime/event_log.py`
- Runtime Protocol §9.1 cryptographic core:
  - deterministic CBOR ✅
  - SHA-256 ✅
  - CRC-32C ✅
  - Ed25519 on capability tokens — capability tokens not used in v0.1.0;
    enforced by `p_local.no_capability_tokens` loader check (frames with
    `sig` bytes cause P-Local to fail)
  - HMAC-SHA256 caveat chain — not used
  - TUF role separation — distribution out of scope for P-Local; use
    `pip install` against a local package
  - Multi-channel bootstrap — operator procedure
- Kernel Spec §§1–3 — documented; runtime enforcement via frame kinds
- Verification Spec §1 gate registry — implemented
- Verification Spec §2 calibration — P-Local explicitly opts out;
  skills that emit confidence must carry `calibration: not_established`
- Distribution Spec §1 (manifest), §4.1 (install contract) — implemented

### MAY omit

- Sigstore/Rekor transparency log
- Credentialing (Verification §3)
- Multi-agent debate
- SBOM production
- Merkle batch overlay (§1.5)
- DPoP proof-of-possession on tokens

## Unsupported profiles (refused at loader)

Declaring one of these produces a `FAIL` in `aios check-profile` with
an explicit list of missing mechanisms, per this table.

### P-Enterprise

Missing in v0.1.0:
- Ed25519 capability tokens (§2)
- TUF role separation + bootstrap (§6)
- JCS audit export for cross-system reports (§3.2)
- Credentialing Phase 0 + Phase 1 (Verification §3)
- Calibration protocol with anti-theater corpus checks (Verification §2)

### P-Airgap

Missing in v0.1.0:
- Ed25519 capability tokens (§2)
- TUF offline root setup (§6.2)
- Air-gapped signed-bundle install path (Distribution §3.4 / §6.2)
- Zero-telemetry enforcement at loader level
  (the package makes no network calls by default — but this is convention
  in v0.1.0, not an enforced check)

### P-HighAssurance

Missing in v0.1.0:
- Ed25519 capability tokens (§2)
- Merkle batch overlay (§1.5)
- DPoP proof-of-possession on every token (§2.8)
- External Sigstore/Rekor transparency log publication (§1.5 / Distribution §5.4)
- Reproducible builds with diverse-builder attestation (Distribution §5.2)
- Hardware-root-of-trust hooks (TPM/TEE for bootstrap)

## Profile declaration event

Per Runtime Protocol §10.5, the declaration is an event of kind
`profile.declared` written once at install time. `aios init` writes both:

```
seq=0  kind=install.complete   actor=A5
seq=1  kind=profile.declared   actor=A5  payload.profile=<declared>
```

Changing the profile after init is a governance act (Constitution
Article VI — requires an ADR in a real deployment). The v0.1.0 CLI
supports `--force` on `aios init` to overwrite the declaration; the
first post-force event records the change.
