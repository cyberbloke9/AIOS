# AIOS Kernel Spec

*Runtime law: trust zones, state transitions, failure domains, crash consistency.*

**Status.** Normative. Subordinate to the AIOS Constitution.
**Version.** 1.0.0, aligned with Constitution v1.0.
**Scope.** Everything that runs. If it executes, it is governed here.

---

## §0 — Orientation

This document answers the runtime questions a reviewer will ask first:

- What code is trusted?
- What code is not?
- How does an artifact move between those states?
- What happens when something breaks?
- What happens when the model is unavailable?
- What does "crash consistent" mean for AIOS?
- What is the kill switch and who can pull it?

The Constitution stated the trust zones and the conservation laws. This spec makes them executable. The intended reader is Claude Code or an equivalent implementation agent.

Two precedents carry most of the weight here:

1. **seL4 microkernel** — capability-based trust; privilege transitions require explicit capability possession; the only OS kernel with formal functional-correctness proofs.
2. **Erlang/OTP supervisor trees** — "let it crash" with explicit supervisor hierarchy for failure containment; failure is a first-class event, not an exception.

---

## §1 — Trust Zones

### §1.1 The five zones

| Zone | Name | Contents | Writable by |
|---|---|---|---|
| Z0 | Trusted kernel | Conservation-scan predicates (Q1–Q3), zone-transition logic, event-log append path, signature verification | Release & Security (A5) only, via signed Distribution release |
| Z1 | Trusted deterministic skills | Pure-function skill scripts; schema-validated I/O; no network | Skill maintainers + A5 co-sign |
| Z2 | Untrusted model output | Raw model generations, model-produced prose, model-produced code before any check | Model, by construction |
| Z3 | Quarantined generated artifacts | Artifacts in flight through a workflow; not yet past required gates | Workflow-local, ephemeral |
| Z4 | Promoted verified artifacts | Artifacts that have passed the full gate set for their impact level | Append-only from Z3 via verified promotion |

### §1.2 Zone transition rules

Every zone transition is an event. The event carries `(from_zone, to_zone, artifact_id, authority, capability_token, gate_set_passed)`. Missing any field is a load-time error for downstream consumers.

**Z2 → Z3 (admission).** Raw model output enters quarantine only after:

- Schema check on the output shape (T3 gate).
- Prompt-injection sentinel scan on any instruction-like content (predicate `P_PI_sentinel`, defined in Verification Spec §1).
- Provenance stamp: which model, which prompt hash, which tool results were in context.

**Z3 → Z4 (promotion).** Quarantined artifacts are promoted only after the full gate set for their declared impact level passes. The gate set is:

| Impact | Required gates (by ID, defined in Verification Spec §1) |
|---|---|
| local | `P_Q1_invariant_integrity`, `P_Q2_state_traceability`, schema checks on outputs |
| subsystem | local set + `P_Q3_decision_reversibility`, `P_M4_independence ≥ 0.5`, acceptance tests |
| system_wide | subsystem set + adversarial injection suite, drift regression, containment regression |

**Z4 → Z3 (demotion).** A Z4 artifact that fails a post-merge check (e.g., production incident traced to the artifact) is demoted back to Z3, not silently patched. Demotion emits an event and triggers the audit protocol.

**Anywhere → Z0 (prohibited).** No runtime path promotes anything into Z0. Z0 changes only through the Distribution Spec's signed-release path (§4 of that spec). This is the hard boundary.

### §1.3 Capability tokens

A capability token is a short-lived signed object: `{ subject, action, scope, nonce, expiry }`. Tokens are issued by A5 (Release & Security) to authorities A1–A4 at workflow start and are consumed on action. Tokens are non-transferable. Forgery is a Z0 concern and falls under the kernel signature-verification path.

The precedent is seL4's approach: capabilities are explicit, unforgeable, and non-ambient. A process cannot escalate its privileges by convincing another process to act; it must possess the capability token itself.

---

## §2 — State Machines

Every stateful entity in AIOS has a typed state machine. The loader refuses entities whose declared transitions do not match this table.

### §2.1 Artifact lifecycle

```
  draft --[admission]--> quarantined --[gate_set_pass]--> verified --[promote]--> promoted
                              |                               |                        |
                              +--[gate_fail]--> rejected      +--[demote]--> quarantined
                                                                             (post-merge failure)
                                                  promoted --[retire_adr]--> retired
```

Allowed transitions:

- `draft → quarantined` (admission; must carry Z2→Z3 event)
- `quarantined → verified` (all gates pass)
- `quarantined → rejected` (any required gate fails)
- `verified → promoted` (Z3→Z4 with all capability tokens)
- `promoted → quarantined` (demotion from post-merge failure)
- `promoted → retired` (explicit retirement ADR)

Forbidden transitions: `draft → verified`, `draft → promoted`, `rejected → anything`, `retired → anything`.

### §2.2 Run lifecycle

```
  pending --[dispatch]--> running --[gate_sweep]--> verified --[apply]--> applied
                             |                          |                     |
                             +--[abort]--> aborted      +--[reject]--> rejected
                                                                              |
                                                                   +--[rollback]--> rolled_back
```

A run that violates Q1, Q2, or Q3 transitions directly to `aborted` regardless of the gate sweep outcome. Conservation violations are soundness failures; they preempt ordinary gate logic.

### §2.3 Skill lifecycle

```
  proposed --[contract_accepted]--> contracted --[calibrated]--> active
                                                                    |
                                                                    +--[calibration_drift]--> quarantined_for_band
                                                                    +--[deprecation_adr]--> deprecated --[removed]--> retired
```

A skill cannot transition to `active` without a calibration record that passes the thresholds in Verification Spec §2. A skill whose calibration drifts past thresholds moves to `quarantined_for_band` for the affected impact band (not for all bands simultaneously).

### §2.4 ADR lifecycle

```
  proposed --[accepted]--> accepted --[deprecated]--> deprecated --[superseded]--> superseded
                              |
                              +--[rejected]--> rejected
```

`Accepted` is the only status that authorizes Q1 invariant removal (per Constitution §1.1).

### §2.5 Credential lifecycle

Credentials live in Phase 0 or Phase 1 (see Verification Spec §3 for the phase gate).

```
  seeded --[phase_0_complete]--> accumulating
              |
  accumulating --[breach]--> restitution --[N_green_runs]--> accumulating
              |
  accumulating --[band_standing<0.3]--> quarantined_for_band
```

A credential in Phase 0 is seeded but not enforced. It becomes enforceable only after the Verification Spec's phase-gate prerequisites are met (gate FP/FN rates measured, benchmark contamination audited, incident backtesting completed). This is the anti-premature-credentialing rule.

---

## §3 — Failure-Domain Model

Failure is a first-class event, not an exception. For each failure domain, the spec defines how the runtime *contains* the failure (prevents spread), *degrades* (reduces functionality safely), *recovers* (returns to a good state), and *rolls back* (undoes side effects where feasible). The precedent is Erlang/OTP supervisor trees, where every process has a supervisor and every failure has a named recovery strategy.

The eight domains:

### §3.1 D1 — Local artifact failure

*Scope:* A single artifact in Z3 fails a gate.

- **Contain.** Quarantine persists; artifact cannot leave Z3.
- **Degrade.** The run continues with a rejection event; other artifacts in the same run proceed if they do not depend on the rejected one.
- **Recover.** Implementer (A3) produces a revised artifact; new quarantine, new gate sweep.
- **Rollback.** None required; nothing was applied.

### §3.2 D2 — Workflow failure

*Scope:* A workflow fails to progress (timeout, deadlock, uncaught condition).

- **Contain.** Workflow supervisor kills the run; emits `workflow_aborted` event.
- **Degrade.** The authority that dispatched the workflow falls back to the defined fallback (usually: human hold or escalation to A4 for adjudication).
- **Recover.** Rerun with fresh state after diagnosis; diagnosis is logged as an audit event.
- **Rollback.** Any in-flight Z3 artifacts discarded; no Z4 changes possible because no promotion occurred.

### §3.3 D3 — Agent failure

*Scope:* An authority (A1–A5) becomes unresponsive or produces malformed output.

- **Contain.** Other authorities continue; the failing authority's decisions are held, not decided by fallback.
- **Degrade.** Router (A1) marks the authority unavailable; affected workflows fail D2.
- **Recover.** Restart the authority; health check must pass before it re-enters rotation.
- **Rollback.** Capability tokens held by the failed authority expire at the token expiry time; no explicit revocation required.

### §3.4 D4 — Projection failure

*Scope:* A projection's stored hash does not match replay of the event log (Q2 breach detected).

- **Contain.** The projection is quarantined; downstream readers receive `unavailable`, not stale data. Silent stale data is the failure mode being prevented.
- **Degrade.** Consumers that can tolerate staleness explicitly opt in; consumers that cannot stop.
- **Recover.** Rebuild the projection from the event log; verify hash; publish.
- **Rollback.** Not applicable; projections are derived views, not sources of truth.

### §3.5 D5 — Calibration failure

*Scope:* A skill's calibration metrics breach thresholds.

- **Contain.** Skill marked `calibration_drift`; skill loses authority over low-confidence routing decisions for the affected band.
- **Degrade.** Queries that would have routed via the skill's confidence are routed via multi-skill concurrence instead.
- **Recover.** Recalibrate from fresh data; if still out-of-bounds, skill enters `quarantined_for_band`.
- **Rollback.** If calibration failure is traced to a corpus update, revert to the prior corpus and re-run.

### §3.6 D6 — Registry corruption

*Scope:* The skill or workflow registry fails integrity check (hash mismatch, schema violation).

- **Contain.** Registry marked `corrupted`; all workflow loads fail with explicit error.
- **Degrade.** Only previously-loaded workflows continue; new runs blocked.
- **Recover.** Restore from the last signed release (Distribution Spec §5); replay post-release events if any.
- **Rollback.** Not applicable for registry itself; any artifacts loaded during the corruption window require re-verification.

### §3.7 D7 — Event-log corruption

*Scope:* The event log's hash chain breaks.

- **Contain.** Append path halts immediately. No new events accepted. This is the most severe failure.
- **Degrade.** System enters read-only mode. Read operations on projections continue; writes blocked.
- **Recover.** Identify the break point; restore from the most recent signed snapshot; replay incremental events from that point if they survive individual verification.
- **Rollback.** Any changes applied after the break point are subject to case-by-case review.

This is the one failure the kernel cannot silently route around. A broken event log means Q2 cannot be established, and therefore no subsequent operation can be trusted until recovery completes.

### §3.8 D8 — External dependency failure

*Scope:* Model API unavailable, network partition, DNS failure, dependency registry down.

- **Contain.** Per §6 (degraded-mode behavior).
- **Degrade.** See §6.
- **Recover.** Retry with bounded backoff; after N attempts, escalate to D3 (agent unavailability).
- **Rollback.** Not applicable; no state change occurred.

### §3.9 Failure-domain summary matrix

| Domain | Contain | Degrade | Recover | Rollback |
|---|---|---|---|---|
| D1 Local artifact | Z3 quarantine | Other artifacts proceed | A3 revises | N/A |
| D2 Workflow | Supervisor kill | Fallback or escalation | Rerun with diagnosis | Discard Z3 artifacts |
| D3 Agent | Mark unavailable | Affected workflows fail D2 | Restart + health check | Token expiry |
| D4 Projection | Quarantine projection | Consumers choose | Rebuild + verify | N/A |
| D5 Calibration | Mark skill drift | Multi-skill concurrence | Recalibrate | Revert corpus |
| D6 Registry | Halt loads | Previously-loaded continue | Restore from signed release | Re-verify loaded artifacts |
| D7 Event log | Halt append | Read-only mode | Restore + replay | Case-by-case |
| D8 External dep | Per §6 | Per §6 | Backoff + escalate | N/A |

---

## §4 — Crash Consistency

### §4.1 The durability contract

AIOS's event log is the source of truth. The durability contract is modeled on SQLite WAL-mode semantics with explicit fsync boundaries:

- **Durability point.** An event is durable iff it has been fsync'd to the event-log file, its hash linked to the prior event's hash, and acknowledged by the append path.
- **Visibility lag.** Projections may lag the event log. Readers that require strict consistency must address the event log directly; readers that can tolerate lag read projections with explicit staleness bounds.
- **Torn writes.** The append path writes the event frame and the hash-chain linkage in a single atomic operation. Torn writes are prevented by appending to a new page and updating the tail pointer as the final step (the WAL pattern).

### §4.2 What survives a crash

- All events that reached `fsync`'d state are recoverable.
- All events that were in the append buffer but not yet `fsync`'d may be lost; the caller is informed they are not durable until acknowledged.
- All projections can be rebuilt from the durable event log.

### §4.3 What does not survive a crash

- In-flight Z3 artifacts without corresponding events. Z3 is deliberately transient; a crash rolls back the workflow to its last durable event (D2 recovery).
- Capability tokens are not re-issued automatically. Workflows restart with fresh tokens.

### §4.4 Consistency check cadence

- Per-append: hash-chain linkage verified atomically.
- Hourly: random sample of projections spot-checked against replay.
- Daily: full Q2 scan of hot projections.
- Weekly: full Q2 scan of warm projections.
- On demand: cold projections verified when next read.

---

## §5 — Kill Switch

Kill switches are the constitutional equivalent of a circuit breaker. They exist so that a human operator can stop the system without diagnosing the cause.

### §5.1 Scopes

Kill switches operate at four scopes, from largest to smallest:

| Scope | Effect |
|---|---|
| Global | All Z1–Z4 activity halts. Z0 predicates continue so Q1–Q3 violations remain detectable. Event-log append allowed only for shutdown events. |
| Authority | One of A1–A5 halts; others continue. Dependent workflows fail D3. |
| Workflow | One named workflow halts; other workflows continue. |
| Skill | One named skill halts; workflows that depend on it fail on the next skill invocation. |

### §5.2 Authorization

- **Global kill.** Any A5 holder, or two concurrent A4 holders, or the designated human operator.
- **Authority kill.** A5 unilaterally.
- **Workflow kill.** A5 or A4.
- **Skill kill.** A5 or the skill owner plus A4.

Every kill is an event with authority, scope, reason, and (where applicable) restart-authorization requirement.

### §5.3 Read-only mode

A global kill automatically transitions the system to read-only mode: projections can be read, event log can be queried, but no new events are appended. Read-only mode is the default degraded state for any D7 recovery.

---

## §6 — Model Unavailability, Degradation, and Adversarial Modes

The kernel cannot assume the model is available, fast, or honest. Three named modes:

### §6.1 Mode U — Model Unavailable

*Trigger:* Model API returns unavailable, times out, or loses connectivity beyond retry budget.

*Behavior:*
- Workflows that require model inference halt with `D8_external_dep`.
- Workflows that are purely deterministic (Z1 skills only) continue.
- A5 may choose to enter global read-only mode for extended outages.
- No fallback to a "best-guess" alternative model without explicit A5 authorization and a corresponding ADR, because silently swapping the model violates calibration assumptions (D5) for every calibrated skill downstream.

### §6.2 Mode D — Model Degraded

*Trigger:* Model responds but calibration metrics on a monitoring corpus drift past thresholds within a rolling window.

*Behavior:*
- The model is flagged `degraded` in the skill registry.
- All skills that use the model lose low-confidence routing authority.
- Workflows fall back to multi-skill concurrence or human hold.
- A5 may issue a workflow-scope kill for the most impact-sensitive workflows.
- Recovery requires either model replacement (Distribution Spec process) or demonstrated calibration restoration.

### §6.3 Mode A — Adversarial

*Trigger:* Prompt-injection sentinel (`P_PI_sentinel`) fires above rate threshold, OR multiple skills report out-of-distribution inputs simultaneously, OR a peer-reviewed disclosure indicates a new class of model attack applicable to the deployment.

*Behavior:*
- Heightened scrutiny: all Z2 → Z3 transitions require the adversarial-injection suite (Verification Spec §1), not just the standard admission check.
- Human hold triggers more liberally: A4 is authorized to downgrade T1/T2/T3 gates to T4 temporarily for affected workflows.
- A5 may issue global read-only.
- Recovery requires a named mitigation: either input filter, prompt rewrite, model update, or workflow deprecation.

### §6.4 Mode selection

The modes are not exclusive: U+A is possible (model down during an active adversarial window) and requires both sets of precautions. Mode transitions are events; the current mode is visible in the audit dashboard at all times.

---

## §7 — Kernel Invariants (what never changes)

A small set of kernel invariants are relied on by the Constitution and every subordinate spec. These cannot change through ordinary amendment; changing them is a new major version of the Kernel Spec and forces a Distribution major bump.

- KI-1: Every state transition produces exactly one event in the log.
- KI-2: Hash-chain linkage is verified on every append.
- KI-3: Zone promotions require capability tokens; tokens are short-lived and non-transferable.
- KI-4: Q1–Q3 scans run synchronously before any Z3→Z4 promotion; they cannot be bypassed.
- KI-5: The event log is append-only. Compaction produces a new log segment; it does not modify existing segments.
- KI-6: Read-only mode is the default degraded state for any Z0 or D7 failure.
- KI-7: No authority may act without leaving its identifier in the event record.

---

## §8 — What this spec does NOT contain

By design:

- Gate predicate registry → **Verification Spec §1**
- Calibration thresholds and methods → **Verification Spec §2**
- Credential update rules → **Verification Spec §3**
- Governance-failure taxonomy → **Verification Spec §4**
- Package identity, semver, install mechanics → **Distribution Spec**
- Signed-release infrastructure → **Distribution Spec §5**

---

*End of Kernel Spec.*
