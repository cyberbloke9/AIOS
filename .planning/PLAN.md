# AIOS — implementation plan (first build, P-Local)

## Strategy

Short sprints, one commit per atomic unit. The reference Python implementations
(`event_log.py`, `conservation_scan.py`) are normative for their clauses — we
vendor them unchanged in sprint 1, then build the package, directory init,
registry, loader, CLI, and tests around them. No architectural invention.

## Target: first accepted build

Per the brief:

- installs locally
- runs tests
- initializes an AIOS directory
- appends frames
- rotates segments
- replays logs
- detects corruption
- detects seq gaps
- runs conservation scan
- enforces P-Local loader checks
- exposes a CLI with `--help`
- documents exactly what is not implemented yet

## Sprints

| # | Sprint | Commit |
|---|---|---|
| 0 | Bootstrap repo (LICENSE, .gitignore, README stub, pyproject, plan) | 1 |
| 1 | Vendor reference Python + specs (docs/spec/, tests pass stand-alone) | 2 |
| 2 | Package src/aios: runtime.event_log, verification.conservation_scan | 3 |
| 3 | AIOS directory init + profile.declared genesis frame | 4 |
| 4 | Gate registry (P_Q1/Q2/Q3/M4/O5, P_schema_valid, P_PI_sentinel stub) | 5 |
| 5 | P-Local loader: verify required mechanisms, refuse on missing | 6 |
| 6 | CLI (argparse): init, append, replay, scan, info, check-profile, --help | 7 |
| 7 | Adversarial tests (tamper, prev-lie, over-budget, profile downgrade) | 8 |
| 8 | Docs: coverage matrix, profiles guide, CHANGELOG | 9 |
| 9 | Verify install + push | 10 |
| 10 | P-Enterprise hook stubs (JCS export, signature hook, loader refusal) | 11 |

## Conformance scope

This build claims P-Local ONLY. Per Runtime Protocol §10.1:

**MUST:** Constitution I–VII; Runtime Protocol §§1/3/4/5 as covered by
`event_log.py`; §9.1 crypto core (SHA-256, deterministic CBOR, CRC-32C);
Kernel Spec §§1–3; Verification Spec §1 (gate registry) and §2 (calibration or
explicit no-calibration declaration); Distribution §1 (package identity) and
§4.1 (install contract).

**MAY omit:** Sigstore/Rekor; credentialing Phase 1; multi-agent debate; SBOM.

## Failure conditions (brief §: stop and report)

- spec contradiction
- TypeScript cannot reproduce Python reference hashes → **not in scope v1**
- deterministic CBOR cannot be made cross-platform → **not in scope v1**
- P-Local depends on deferred feature → stop, escalate
- security shortcut needed → stop, escalate

No contradictions discovered while reading v6/v7/v8. `ts_ns` used consistently
across the v8 spec and `event_log.py`. Proceeding.
