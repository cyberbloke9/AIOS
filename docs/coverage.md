# Coverage matrix

> What the current build implements and what it deliberately does not.
> Living document updated per release. Current: **v0.5.0** (M5 —
> "make it deployable").
> The authoritative source is Runtime Protocol §8.1 (normative covered
> vs. not-covered for `event_log.py`). This document extends §8.1 to
> the whole package.

## Legend

- ✅ implemented in v0.1.0 and covered by tests
- 🟡 implemented as a stub — registered / accepted but raises
  `NotImplementedPredicateError` or returns `fail` at loader time
- ❌ deliberately deferred; documented here so a reviewer cannot mistake
  absence for oversight

## Constitution (v1.0)

| Article | Status |
|---|---|
| I  Conservation Laws Q1/Q2/Q3 | ✅ `conservation_scan.scan_q1/q2/q3_*` |
| II Governance Metrics M4/O5   | ✅ `scan_m4_independence`, `scan_o5_context_sufficiency_hard` |
| III Authorities A1-A5         | ✅ enforced by schema: `--actor` CLI flag, PredicateRecord.owner_authority |
| IV Trust Zones Z0-Z4          | ✅ Z0 = pkg; Z1 = user code; Z2-Z4 carried in frame `kind` |
| V  Gate Types T1-T4           | ✅ PredicateRecord.gate_type; loader refuses untyped gates |
| VI Amendment                  | 🟡 prose; emergency amendment path not automated |
| VII Severability / Precedence | ✅ docs |

## Kernel Spec (v1.0)

| Section | Status |
|---|---|
| §1 Trust zones                      | ✅ documented; runtime enforcement is by kind-registry-in-frame |
| §2 State machines                   | 🟡 enforced for run/ADR/credential (lifecycle fields); artifact pipeline requires workflow orchestrator (v2) |
| §3 Failure domains D1-D8            | ✅ D7 (event-log corruption) enforced at replay |
| §4 Crash consistency (fsync + WAL)  | ✅ per-frame fsync; POSIX directory fsync; Windows uses default disk semantics |
| §5 Kill switch scopes               | ❌ operator process discipline only in v0.1.0 (no daemon) |
| §6 Mode U / Mode D / Mode A         | ❌ requires a live model-serving layer |
| §7 Kernel invariants KI-1 .. KI-7   | ✅ KI-1,2,3,5 by event_log; KI-4 by registry.evaluate; KI-6 by loader refusal; KI-7 by frame.actor requirement |

## Runtime Protocol (v1.0)

Mirrors §8.1 of the spec.

### Normatively covered by `src/aios/runtime/event_log.py`

| Clause | Section | Package evidence |
|---|---|---|
| Deterministic CBOR (AIOS subset)         | §3.1, §3.4 | `cbor_encode`, tests `test_cbor_*` |
| Frame structure 8-field CBOR map, `ts_ns`| §1.2       | `Frame` dataclass, `to_cbor`, `frame_hash` |
| Hash-chain linkage via `prev`            | §1.2, §5.6 | `test_prev_hash_chain_unbroken`, `test_tampered_frame_detected` |
| Segment header (96 bytes)                | §1.4.2     | `_pack_header`, `_unpack_header` |
| Segment trailer (84 bytes)               | §1.4.5     | `_rotate` writes trailer; replay verifies |
| Length-prefix + CBOR + CRC-32C framing   | §1.4.3     | `_encode_on_disk`, `_read_on_disk`; `test_crc_*`, `test_truncated_*` |
| Segment rotation + atomic rename + dir fsync | §1.4.4 | `_rotate` + `_dir_fsync` (POSIX) |
| LSN strict monotonicity across segments  | §5.2, §5.5 | `test_lsn_is_strictly_monotonic`, `test_seq_gap_rejected` |
| Replay with prev-chain + seq verification| §5.6       | `EventLog.replay` |

### NOT covered — deferred per P-Local profile §10.1

| Clause | Section | Status | Reason |
|---|---|---|---|
| Advisory file lock single-writer enforcement | §5.1      | ❌ | stdlib portability; needs `fcntl.F_SETLK` / `LockFileEx` |
| Merkle batch overlay                         | §1.5      | ❌ | Optional in P-Local; required only in P-HighAssurance |
| Ed25519 signature generation + verification  | §1.2, §2  | 🟡 | `sig` field accepted on frames; loader rejects for P-Local; no crypto lib yet |
| Capability token issuance + caveat chain     | §2        | ❌ | Ed25519 + HMAC-SHA256 libraries needed |
| Snapshot production + verification           | §1.8      | ❌ | Full replay sufficient in P-Local |
| Compaction                                   | §1.7      | ❌ | Operator-initiated; deferred |
| Capability revocation log consultation       | §2.6      | ❌ | Requires live A5 path |
| Full CBOR decoder (all major types + tags)   | §3.1      | 🟡 | AIOS subset only |
| Clock-skew handling for tokens               | §2.5      | ❌ | No tokens in v0.1.0 |
| TUF client (fetch, verify, rotate)           | §6        | ❌ | Use official TUF client, do not reimplement |
| Multi-channel bootstrap anchor verification  | §6.3      | ❌ | Operator procedure, not runtime code |
| Sigstore/Rekor transparency-log client       | §1.5, Dist §5.4 | ❌ | Optional per §10; P-HighAssurance only |
| JCS audit export                             | §3.2      | 🟡 | Sprint 10 stub planned |

## Verification Spec (v1.0)

| Section | Status |
|---|---|
| §1 Gate registry + PredicateRecord schema        | ✅ |
| §1.2 Core predicates Q1/Q2/Q3/M4/O5              | ✅ |
| §1.2 P_schema_valid (T3 jsonschema-backed)       | ✅ (v0.3.0) |
| §1.2 P_PI_sentinel / P_acceptance_tests          | 🟡 stubs refuse silent pass |
| §2 Calibration protocol (anti-theater)           | ❌ P-Local explicitly declares no-calibration |
| §3 Credential protocol (Phase 0 / Phase 1)       | ❌ |
| §4 Audit protocol + G1-G7 taxonomy               | ❌ |

## Skills (Kernel §1.1 Z1 + Distribution §1.1 baseline)

| Skill | Status |
|---|---|
| SK-ADR-CHECK (ADR lifecycle + reference integrity) | ✅ (v0.3.0) |
| SK-PRECEDENT-MATCH (TF-IDF cosine over ADRs)       | ✅ (v0.3.0) |
| SK-THREAT-MODEL                                     | ❌ |
| SK-DEBATE-N3 (multi-skill concurrence)              | ❌ |

## Project integration (v0.3.0)

| Feature | Status |
|---|---|
| `aios adopt <repo>` scaffolds .aios/                       | ✅ |
| `aios git-init` installs post-commit hook                  | ✅ |
| `aios check` one-shot RunState-from-repo scan              | ✅ |
| `.aios/invariants.yaml` declarative schema                 | ✅ |
| ADR front-matter reader (adrs/ or docs/adr/)               | ✅ |
| RunState adapter with git before/after diff                | ✅ |
| GitHub PR check composite action                           | ❌ M4 |

## Distribution Spec (v1.0)

| Section | Status |
|---|---|
| §1 Package identity + manifest (`aios` block)    | 🟡 this package uses `aios` (Python) — the `@aios-core/*` npm namespace is reserved for a future JS/TS port |
| §2 Semver                                        | ✅ |
| §3 Supported runtimes                            | ✅ Python 3.11+ |
| §3.4 Air-gapped variant                          | ❌ P-Airgap profile refused at loader |
| §4.1 Install contract                            | ✅ `aios init` implements the post-conditions |
| §4.2/3/4 Upgrade, rollback, uninstall            | ❌ use `pip install --upgrade`; no atomic shadow dir in v0.1.0 |
| §5 Signed releases + SBOM + Rekor                | ❌ |
| §6 Telemetry default (zero)                      | ✅ no network calls |
| §7 Dependency policy                             | ✅ zero runtime deps |
| §8 Corruption recovery                           | ✅ replay detects corruption; manual recovery |

## Tests

```
$ pytest
...................
279 passed
```

Breakdown (v0.3.0):
- tests/test_event_log.py              12 (§1, §3, §5)
- tests/test_event_log_lock.py          6 (§5.1 writer lock)
- tests/test_event_log_signing.py       8 (Ed25519 + §1.2 sig)
- tests/test_conservation_scan.py      10 (Ver §1.2 core + compat)
- tests/test_registry.py               14 (Ver §1.1, §1.2, §1.5)
- tests/test_schema_check.py           12 (real P_schema_valid, §1.2 T3)
- tests/test_skills_base.py            14 (SkillContract + SkillRegistry)
- tests/test_skill_adr_check.py        12 (SK-ADR-CHECK)
- tests/test_skill_precedent_match.py  10 (SK-PRECEDENT-MATCH)
- tests/test_init.py                    8 (Dist §4.1)
- tests/test_project_readers.py        19 (invariants.yaml + ADR readers)
- tests/test_project_runstate.py       10 (RunState adapter + git diff)
- tests/test_project_adopt.py          13 (adopt + post-commit hook)
- tests/test_profile.py                10 (Runtime §10.6)
- tests/test_profile_v02.py             8 (P-Enterprise partial)
- tests/test_filelock.py               10 (§5.1 POSIX + Windows)
- tests/test_workflow_manifest.py      15 (Kernel §1.2 defaults + parse)
- tests/test_workflow_runner.py         8 (Kernel §2.2 lifecycle)
- tests/test_cli.py                    15 (core UX + exit codes)
- tests/test_cli_run.py                 6 (`aios run`)
- tests/test_cli_adopt.py               7 (`aios adopt` / `git-init`)
- tests/test_cli_check.py               7 (`aios check`)
- tests/test_demo_project.py            4 (examples/demo-project end-to-end)
- tests/test_adversarial.py            11 (security boundary — substrate)
- tests/test_adversarial_v02.py         8 (security boundary — Ed25519 + lock)
- tests/test_enterprise_stubs.py        9 (JCS + Signer/Verifier protocol)
- tests/test_ed25519.py                12 (concrete Ed25519 round-trip)
