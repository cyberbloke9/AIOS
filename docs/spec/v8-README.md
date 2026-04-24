# AIOS v8 — Closure Pass

**Date:** 2026-04-23
**Supersedes:** v7 (five-document stack with runtime protocol).
**Scope.** Codex's five closure items. No new architecture. No new philosophy. Only defects and clarifications.

---

## What changed from v7

v7 was the first bundle a serious systems group could implement against. Codex's third review said so, and then listed five items that disqualified it from immediate "global standard" status. v8 closes those five items. Nothing more, nothing less.

### Codex's five closure items, mapped to v8 changes

| Closure item | What v8 does |
|---|---|
| 1. Internal contradictions (starting with `ts` vs `ts_ns`) | Runtime Protocol §1.2 now names the field `ts_ns` (uint64 nanoseconds). §3.5 states RFC 3339 text is an audit-export rendering only. The reference implementation was already using `ts_ns`; the spec's own §1.2 table is now consistent with §3.5 and the code. |
| 2. `test_seq_gap_rejected` overclaims what it proves | Rewritten to hand-build a second segment declaring `first_seq=5` after a prior segment ending at `seq=1`, with a correct prev-hash chain but a genuine LSN gap. The test verifies replay refuses with a seq/first_seq mismatch error. This is now an adversarial test, not a sanity check. |
| 3. Which Runtime Protocol clauses are covered by `event_log.py` and which are not | Runtime Protocol §8.1 adds an explicit two-table coverage matrix: "normatively covered" (9 clauses, each mapped to the test that verifies it) and "NOT covered" (12 clauses with reason for deferral). The reference file's docstring repeats the same mapping. The README's earlier overclaim is retracted. |
| 4. Cryptographic surface too broad for v1 | Runtime Protocol §9 adds a Cryptographic Surface Policy: §9.1 v1 core (7 mechanisms, each with a "why indispensable now" justification); §9.2 v1 strongly recommended (2 mechanisms); §9.3 v1 deferred to v2 (5 mechanisms, each with a reason for deferral including Sigstore/Rekor, Merkle batch overlay, DPoP, hardware attestation, geo-distributed append). §9.4 states the interrogation rule: no v2 feature enters v1 without a concrete containment gap, implementation feasibility, and explicit migration. |
| 5. Conformance Profiles missing | Runtime Protocol §10 adds four profiles: P-Local (single-developer), P-Enterprise (organizational), P-Airgap (sovereign/offline), P-HighAssurance (hostile-review-grade). Each profile names its required, optional, and forbidden mechanisms. §10.5 requires a profile declaration at install; §10.6 requires the loader to enforce it. |

---

## Why v8 exists as a discrete version

v6 fixed conceptual overreach. v7 added the missing runtime substrate. v8 is not architectural work; it is **closure** of the residual defects in v7. Codex was explicit: "you are now past the 'big architecture' phase. Another 30x increase in abstract sophistication would be a mistake." v8 respects that and does only what closure requires.

The temptation to add more to a spec that is already good is the failure mode; the discipline of stopping when the remaining work is closure, not architecture, is the success mode. v8 is the discipline.

---

## What v8 does NOT change

- Constitution Articles I–VII — unchanged. The only edit was adding Runtime Protocol Spec items to the "what this Constitution does NOT contain" list and placing it in the precedence order (§VII).
- Kernel Spec — unchanged.
- Distribution Spec — unchanged.
- Verification Spec — unchanged.
- Runtime Protocol Spec §§1–7 — substantive content unchanged. Only §1.2 timestamp-field clarification, §3.5 tightening, and a new §§8.1–10 appended.
- Conservation scan reference implementation — unchanged.
- Event log reference implementation — docstring updated to state coverage; code is byte-identical where behavior is unchanged.

---

## Five-document structure (still)

| Document | Cadence | Role |
|---|---|---|
| `AIOS_Constitution.md` | Quarterly at most | Irreducible laws |
| `AIOS_Kernel_Spec.md` | Minor bumps | Runtime: zones, state machines, failure domains |
| `AIOS_Distribution_Spec.md` | Minor bumps | Package: namespace, semver, signed releases |
| `AIOS_Verification_Spec.md` | Minor bumps | Gates, calibration, credentialing, audit |
| `AIOS_Runtime_Protocol.md` | Minor bumps | Wire format, ordering, determinism, bootstrap, SLOs, **profiles** |

---

## Reference implementations

Both reference implementations carry forward unchanged except for the `event_log.py` docstring (now states coverage explicitly) and the rewritten seq-gap test.

```
python conservation_scan.py           # demo: Q1-Q3 preserved on a toy run
python test_conservation_scan.py      # 8 breach cases, all detected
python event_log.py                   # demo: 6 frames across 2 segments, replay verified
python test_event_log.py              # 12 tests including genuine seq-gap adversarial test
```

Combined status: **20 of 20 tests passing.**

The earlier "stdlib-only Python in under 600 LOC" framing is retracted where it overclaimed. The accurate statement: the reference implementations normatively cover the substrate clauses listed in Runtime Protocol §8.1, and a production implementation must add the items listed there as "NOT covered" before claiming full runtime conformance.

---

## Conformance Profiles at a glance

| Profile | When to use | v1 crypto core | Merkle | Rekor | DPoP | Air-gap | Credentialing |
|---|---|---|---|---|---|---|---|
| **P-Local** | Single developer | required | may omit | may omit | may omit | may omit | may omit |
| **P-Enterprise** | Organization with audit | required | may omit | may omit | may omit | may omit | required |
| **P-Airgap** | Offline / sovereign | required | may omit | forbidden | may omit | required | recommended |
| **P-HighAssurance** | Hostile-review grade | required | required | required | required | may omit | required |

A deployment declares its profile in its root AIOS configuration. Profile changes require an ADR.

---

## Contents

```
AIOS_Constitution.md           Governing document. Short. Rigid. Boring.
AIOS_Kernel_Spec.md            Runtime law.
AIOS_Distribution_Spec.md      Package law.
AIOS_Verification_Spec.md      Verification law.
AIOS_Runtime_Protocol.md       Wire-level machine contract (now with §§8.1, 9, 10).
conservation_scan.py           Reference impl: Q1-Q3, M4, O5.
test_conservation_scan.py      Reference vectors for the above (8 tests).
event_log.py                   Reference impl: CBOR, frames, segments, replay.
test_event_log.py              Reference vectors (12 tests, with genuine seq-gap test).
README.md                      This file.
```

---

## For a reviewer

The question to ask on v8 is not "what else should this system do?" but "is every item on Codex's closure list actually closed?" The answers, with line-pointable evidence:

| Closure item | Evidence of closure |
|---|---|
| Timestamp field contradiction | Runtime Protocol §1.2 line defining `ts_ns`; §3.5 stating CBOR wire form; `event_log.py` `Frame` class field `ts_ns`. All three consistent. |
| Weak seq-gap test | `test_event_log.py` `test_seq_gap_rejected` — hand-built gapped segment, 45 lines including setup; verifies `ValueError` with "seq" or "first_seq" in message. Passes. |
| Reference coverage scope | Runtime Protocol §8.1 with two tables totaling 21 clauses each marked covered or not-covered with reason. |
| Crypto surface | Runtime Protocol §9.1 (7 indispensable), §9.2 (2 recommended), §9.3 (5 deferred with reasons). §9.4 interrogation rule. |
| Conformance profiles | Runtime Protocol §10: four named profiles (P-Local, P-Enterprise, P-Airgap, P-HighAssurance) with MUST / SHOULD / MAY / MUST NOT per profile. §10.5 declaration requirement. §10.6 loader enforcement. |

A reviewer who finds any of these claims not substantiated by the cited section has found a residual defect, and the bundle is not yet closed. A reviewer who finds all five substantiated has confirmed the closure pass is complete.

---

## What v8 does not pretend to be

v8 is not "millions-of-installs ready." Codex already said so, and that stance has not changed. v8 is closure-pass complete, not production-scale attested.

The gap between closure-pass complete and production-scale attested is work that cannot be done by spec alone:

- Incident backtesting against real production history (Verification Spec §3.1 Phase 0 prerequisites).
- Field-tuned performance budgets (Runtime Protocol §7, currently all `[internal policy]`).
- Cross-language conformance suite beyond the Python reference.
- TLA+ formal model of §5 ordering (Runtime Protocol §11 future work).
- Red-team review of a running deployment, not just a document.

Those are engineering activities, not specification activities. v8 is the last specification pass before engineering begins.
