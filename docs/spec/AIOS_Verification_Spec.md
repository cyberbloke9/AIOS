# AIOS Verification Spec

*Gate registry, calibration protocol, credential protocol, audit protocol.*

**Status.** Normative. Subordinate to the AIOS Constitution.
**Version.** 1.0.0, aligned with Constitution v1.0 and Kernel Spec v1.0.
**Scope.** How AIOS establishes that Q1, Q2, Q3 hold; how M4 and O5 are measured; how agents and skills earn and lose authority.

---

## §0 — Orientation

The Constitution names three conservation laws, four gate types, and one independence metric, one context control objective. This spec makes each of them measurable.

Three precedents govern the design:

1. **RFC 2119** — the IETF vocabulary MUST / SHOULD / MAY. Every predicate specification in §1 uses these words with their RFC 2119 meanings.
2. **DO-178C aviation software levels** — failure consequence (catastrophic, hazardous, major, minor, no-effect) drives the required rigor. Not every gate needs formal verification; gates for system-wide-impact artifacts do.
3. **CS-25 airworthiness requirements vs. Acceptable Means of Compliance** — the Constitution is CS-25 (what must hold). This spec is AMC (how to demonstrate it). AMC can evolve without the airworthiness requirement changing.

**Codex's direct critique, addressed here:**

- *Credentialing is clever but underspecified enough to be gamed.* — Answered by §3.1, the Phase 0 prerequisite. Credentialing does not go live until gate FP/FN rates have been measured on a reference incident suite.
- *Calibration theater.* — Answered by §2.3, the corpus-quality rules. A calibration record against a weak corpus is refused, not merely warned.
- *"Compiled gates" still rely on semantic predicates not formally specified.* — Answered by §1, the formal gate registry with explicit schemas and reference vectors for every predicate.

---

## §1 — Formal Gate Registry

Every gate predicate that any workflow invokes MUST be registered here with the following fields. The loader refuses to load a workflow manifest that references a predicate not in the registry.

### §1.1 Predicate record schema

```yaml
predicate:
  id:                <globally unique identifier, e.g. P_Q1_invariant_integrity>
  version:           <semver>
  owner_authority:   A1 | A2 | A3 | A4 | A5
  gate_type:         T1 | T2 | T3 | T4            # per Constitution Article V
  determinism:       deterministic | stochastic_bounded | stochastic_calibrated
  side_effects:      read_only | appends_audit_event | writes_quarantine
  input_schema:      <JSON Schema file path>
  output_schema:     <JSON Schema file path>
  reference_vectors: <path to reference-vectors file>
  failure_level:     catastrophic | hazardous | major | minor | no_effect
  soundness_class:   Q1 | Q2 | Q3 | M4 | O5 | other
```

Rules:

- `determinism: deterministic` means: given identical inputs, output is bit-identical. Required for T1 and T3 predicates.
- `determinism: stochastic_bounded` means: output variance is bounded by a declared statistic. Permitted for T2.
- `determinism: stochastic_calibrated` means: output is a probability that has a calibration record per §2. Permitted for predicates that emit confidence.
- `side_effects: read_only` predicates MUST NOT modify any state, including the event log (other than the gate's own result event, which is written by the orchestrator, not the predicate).
- `failure_level` maps to `impact` in Kernel Spec §1.2: `catastrophic` predicates are required for `system_wide` impact artifacts; `hazardous` for `subsystem`; `major` for `local`.

### §1.2 Core predicates (required for every deployment)

| ID | Type | Soundness | Determinism | Failure level | Purpose |
|---|---|---|---|---|---|
| `P_Q1_invariant_integrity` | T1 | Q1 | deterministic | catastrophic | Conservation Law 1 enforcement |
| `P_Q2_state_traceability` | T1 | Q2 | deterministic | catastrophic | Conservation Law 2 enforcement |
| `P_Q3_decision_reversibility` | T1 | Q3 | deterministic | catastrophic | Conservation Law 3 enforcement |
| `P_M4_independence` | T1 | M4 | deterministic | hazardous | Independence metric (non-soundness) |
| `P_O5_context_sufficiency_hard` | T1 | O5 | deterministic | hazardous | O5 hard constraint (all required invariants present; within budget) |
| `P_schema_valid` | T3 | other | deterministic | major | Generic schema conformance |
| `P_PI_sentinel` | T1 | other | deterministic | hazardous | Prompt-injection sentinel on Z2→Z3 admission |
| `P_acceptance_tests` | T2 | other | stochastic_bounded | major to catastrophic | Declared test suite pass |

Each predicate has a reference-vector file: a JSON file with input/expected-output pairs used to validate predicate implementations. A new implementation of a predicate MUST pass every reference vector. Reference vectors are versioned with the predicate; a reference-vector change is at minimum a minor predicate version bump.

### §1.3 Reference vectors: the executable spec

For `P_Q1_invariant_integrity` through `P_O5_context_sufficiency_hard`, the reference implementation is the `conservation_scan.py` module delivered with this spec. The eight tests in `test_conservation_scan.py` are the minimum reference-vector set. Every compliant implementation MUST pass them.

A deployment that replaces the reference implementation with an alternate one (e.g., a native implementation for performance) MUST:

- Publish its implementation against the reference vectors.
- Preserve deterministic output for deterministic predicates.
- Include the implementation hash in the SBOM (Distribution Spec §5.3).

### §1.4 Predicate lifecycle

- `proposed` — predicate defined but not yet accepted.
- `active` — in use by one or more workflows.
- `deprecated` — superseded by another predicate; workflows SHOULD migrate.
- `retired` — removed from the registry; referencing workflows fail to load.

Retirement of a core predicate (Q1–Q3) requires a constitutional amendment, because those predicates are named in the Constitution.

### §1.5 Adding a new predicate

The path from `proposed` to `active`:

1. Draft the predicate record.
2. Produce the input and output schemas.
3. Produce reference vectors covering at minimum: one positive case, one negative case per distinct failure mode.
4. Implement and test.
5. A4 reviews; A5 co-signs if the predicate is T1 catastrophic.
6. The new predicate is added to the registry with an activation event.

---

## §2 — Calibration Protocol

The Constitution recognizes that O5 and M4 are metrics, not conservation laws. The calibration protocol here applies to any predicate or skill emitting a confidence or probability. The anti-theater rule is the load-bearing one: a calibration record against a weak corpus is refused, not warned.

### §2.1 What requires calibration

- Every skill that emits a `confidence` field in its output.
- Every predicate with `determinism: stochastic_calibrated`.
- Every authority that uses a confidence scalar to route or abstain.

### §2.2 Supported calibration methods

Each method is the one named in the peer-reviewed literature:

| Method | When applicable | Thresholds |
|---|---|---|
| Temperature scaling | Single scalar on logits pre-softmax; works for classifier-shaped outputs | Brier ≤ 0.25, ECE ≤ 0.10 |
| Platt scaling | Logistic regression on validation outputs; calibrates scores to probabilities | Brier ≤ 0.25, ECE ≤ 0.10 |
| Linear probe | Recent method reported to deliver calibrated uncertainty with ~10x computational savings and better generalization to unseen domains | Brier ≤ 0.25, ECE ≤ 0.10 |
| Self-consistency | Consistency across perturbed-neighbor queries; established as a valid calibration approach | Brier ≤ 0.25, ECE ≤ 0.15 |

Thresholds are `[internal policy]` defaults. A deployment may set tighter thresholds; loosening them requires an ADR naming the rationale.

### §2.3 Corpus-quality rules (anti-theater)

A calibration corpus MUST satisfy:

| Rule | Requirement |
|---|---|
| Minimum size | ≥ 300 examples for predicates operating at local impact; ≥ 1000 for subsystem; ≥ 3000 for system-wide |
| Labeling provenance | Every label traceable to a named human adjudicator or a deterministic oracle |
| Independence | No overlap with the training data of the model or skill being calibrated; overlap audit performed and signed |
| Recency | No example older than the calibration refresh schedule (weekly, monthly) |
| Distribution | Sample weights published; class imbalance declared |
| Adversarial coverage | ≥ 5% of examples are adversarial (OOD, prompt-injection attempts, edge cases) |

**Refusal.** A calibration record referencing a corpus that fails any of these rules is refused. The skill emits `calibration: not_established` in its contract; the skill cannot emit confidence scalars to downstream consumers until the corpus is corrected.

This is the specific remedy for Codex's "calibration theater" critique. Corpus-quality rules are not aspirational; they are loader-level refusals.

### §2.4 Calibration record schema (in a SKILL.md contract)

```yaml
calibration:
  method: temperature_scaling | platt_scaling | linear_probe | self_consistency
  corpus:
    path: <relative path to corpus file>
    hash: <SHA256>
    size: <int, must meet §2.3 minimum for declared impact>
    labeling_provenance: <"human-<name>" | "oracle-<oracle_id>">
    independence_audit:
      method: <string>
      last_run: <ISO8601>
      overlap_detected: false | true
    recency_policy: weekly | monthly
    adversarial_share: <float, must be >= 0.05>
  last_fit: <ISO8601>
  metrics:
    brier_score: <float>
    expected_calibration_error: <float>
    reliability_diagram: <path to plot>
  validation_schedule: weekly | monthly
  thresholds:
    brier_max: <float, from §2.2>
    ece_max: <float, from §2.2>
```

### §2.5 Recalibration cadence

- Weekly validation for skills with weekly schedule; monthly for monthly schedule.
- On any detected drift: immediate recalibration attempt.
- On three failed recalibration attempts in rolling 30 days: the skill is quarantined (Kernel Spec §2.3) pending audit.

### §2.6 Calibration failure is a D5 event

Per Kernel Spec §3.5. Containment, degradation, recovery, and rollback are specified there.

---

## §3 — Credential Protocol

Codex's critique: credentialing cannot start on day 31 because gate quality has not yet been measured on day 31. Accepted. The credential protocol has a Phase 0 that must complete before any credential update takes effect.

### §3.1 Phase 0 — Prerequisites for credentialing

Credentialing is disabled until all of the following are measured:

| Prerequisite | Measurement | Acceptance threshold |
|---|---|---|
| Gate false-positive rates | Run each T1/T2/T3 gate against a reference suite of known-good artifacts; measure rate of incorrect rejections | FP rate ≤ 0.10 per gate, measured on ≥ 100 cases |
| Gate false-negative rates | Run each gate against a reference suite of known-bad artifacts (seeded defects); measure rate of incorrect acceptances | FN rate ≤ 0.10 per catastrophic gate, ≤ 0.20 per hazardous |
| Benchmark contamination audit | For every benchmark used in any T2 gate, audit for overlap with training data; audit must be signed | Overlap ≤ 0.05 OR explicit contamination-tolerant evaluation declared |
| Incident backtesting | Take the last 30 production incidents; replay against the gate set; measure gate hit rate (caught vs. missed) | Hit rate published; no threshold — but the number is needed before credentialing |
| Reference-vector coverage | Every predicate has reference vectors for positive, negative, and edge cases | Coverage ≥ 0.80 for each gate |

**Phase 0 → Phase 1 transition.** When all prerequisites are met, A4 and A5 co-sign a `credentialing_enabled` event. Credentialing updates begin from that event forward, not retroactively.

Until Phase 0 completes, credential records are seeded at 0.5 standing across all bands and updated only by observation (i.e., they accumulate data about gate performance); the standing value is not used to gate capability. The credential lifecycle in Kernel Spec §2.5 begins its enforced behavior at the Phase 0 → Phase 1 transition.

### §3.2 Credential record (active in Phase 1)

```yaml
credential:
  entity_id: A4 | SK-ADR-CHECK | ...
  phase: 0 | 1
  standing: <float, [0.0, 1.0]>
  competency_bands:
    local:       {standing: <float>, runs: <int>, breaches: <int>, last_breach: <ISO8601 | null>}
    subsystem:   {standing: <float>, runs: <int>, breaches: <int>, last_breach: <ISO8601 | null>}
    system_wide: {standing: <float>, runs: <int>, breaches: <int>, last_breach: <ISO8601 | null>}
  restitution_budget:
    remaining: <int>
    class: <error class triggering restitution>
  linked_calibration: <path to calibration record, if applicable>
```

### §3.3 Update rule (Phase 1)

Per run that concludes with an outcome:

```
Δstanding(band) =
    +α   on a clean green run at the declared impact level
    -β   on a gate failure at the declared impact level
    -γ   on a Q1/Q2/Q3 breach          (γ >> β >> α by design)
    +δ   on contributing to containment of a contained error
    -ε   on recurrence of a previously-contained error class
constraints:
    standing ∈ [0.0, 1.0]
    standing(system_wide) ≤ standing(subsystem) ≤ standing(local)
```

`[internal policy]` default weights: α=0.01, β=0.05, γ=0.20, δ=0.02, ε=0.10. Weights are reviewed under the audit protocol §4.

### §3.4 Standing-to-capability mapping

| Band standing | Capability |
|---|---|
| < 0.3 | Quarantined for this band; cannot be primary author; cannot verify |
| 0.3 – 0.6 | Participating under supervision; verifier for this band must be ≥ 0.75 |
| 0.6 – 0.9 | Standard authority |
| ≥ 0.9 | Sole verifier permitted for this band |

### §3.5 Restitution for recurrence

When an error of class C in subsystem S occurs twice within 90 days and the same entity was involved in both:

- The entity enters `restitution` for class C.
- `restitution_budget.remaining` is set to N (default 10).
- Each subsequent run decrements the budget on clean completion.
- Standing is frozen until the budget reaches zero.
- A recurrence during restitution doubles the budget and triggers an audit event.

### §3.6 Gaming defenses

The concern: an entity learns that clean runs raise standing and defines "clean" leniently, or seeks out low-risk work to farm standing.

Defenses:

- The asymmetric weights (γ >> β > α) mean a single breach wipes out many clean runs.
- Standing is per-band; farming local standing does not earn subsystem or system-wide authority.
- The audit protocol §4 watches for unusually clean streaks and flags them for review.
- External review via the audit protocol monitors the FP rate of gates that contribute to standing.

---

## §4 — Audit Protocol

The audit protocol is the outermost loop. It watches the system watching itself.

### §4.1 What is audited

- Gate performance: FP/FN rates over rolling windows.
- Credential distributions: suspicious streaks, low-risk farming patterns.
- Calibration performance: drift and recovery.
- Governance-failure taxonomy incidence (G1–G7, §4.3).
- Constitutional compliance: are amendments following Article VI?

### §4.2 Audit cadence

| Window | Audit |
|---|---|
| Per-run | Conservation ledger entries for Q1–Q3 |
| Daily | Q2 scan of hot projections; event-log hash-chain check |
| Weekly | Calibration validation for weekly-schedule skills; credential summary |
| Monthly | Calibration validation for monthly-schedule skills; full credential distribution review |
| Quarterly | Constitutional health review: Articles I–V compliance; governance-failure distribution; amendment retrospective |

### §4.3 Governance-failure taxonomy

| Class | Name | Symptom | Primary containment |
|---|---|---|---|
| G1 | Overblocking | PR throughput falls; gate catch rate on merged PRs → 0 | Middle-loop recalibration |
| G2 | Underblocking | Production error rate rises while gates pass | Engage full three-lane verification; adversarial suite |
| G3 | Review capture | One entity approves a disproportionate share of consequential merges | Rotation policy; force debate |
| G4 | Benchmark gaming | Skill scores on benchmark rise while field quality falls | Rotate eval suite; SWE-bench-plus-style leak audits |
| G5 | Provenance overload | Event log grows faster than queries serve it; projections lag | Scale provenance tier down; archive cold events |
| G6 | Stale-contract failure | Skill invoked past its calibration refresh window | Auto-quarantine; force recalibration |
| G7 | Oscillation | Gate thresholds change too fast | Freeze thresholds; human override required |

Each class is a first-class event type in the audit log. The quarterly constitutional health review reports per-class incidence.

### §4.4 Incident replay procedure

When a production incident is traced to AIOS behavior:

1. Identify the event-log range covering the incident.
2. Run `conservation_scan` on the range; record Q1–Q3 status.
3. Reconstruct the workflow, the skills invoked, the gates evaluated, and the credentials in effect.
4. Determine whether the incident was caught by any gate, and if not, why.
5. Attribute to a governance-failure class (G1–G7) if applicable.
6. Produce an incident report with a remediation plan.
7. Incident reports feed the calibration corpora (§2.3 adversarial share).

### §4.5 External review (non-adjudicatory)

Per the Constitution's Article VI, external references are informative, not adjudicatory. The audit protocol MAY invoke external-style review as a diagnostic technique — for example, running a Codex-style physics/machine-code critique on a new subsystem before it enters production. Results of such review are audit evidence, not constitutional votes.

The three informative reviewers named for use in this diagnostic:

- **Codex-style review** — first-principles critique of the design.
- **OpenAI *Practical Guide to Building Agents*** — consulted for agent design patterns; evals-first discipline; multi-agent splitting criteria.
- **GPT-style agentic prompting conventions** — Scope Discipline, CTCO framing, Plan-then-Execute separation.

These are methodologies AIOS teams apply to their own designs. They do not vote. This preserves the separation Codex identified: external advisory guidance does not belong in the constitutional review loop.

### §4.6 Audit artifacts

Each audit produces:

- A signed audit report in a stable format.
- Entries in the audit log.
- Updates to the dashboard of governance-failure class incidence.
- Recommendations with a named recipient (authority or committee).

### §4.7 Audit authority

A4 (Verifier) conducts routine audits. A5 (Release & Security) conducts audits with potential supply-chain or trust-zone implications. Constitutional health reviews (quarterly) require A2 + A4 + A5 concurrence.

---

## §5 — Reference Implementation Commitments

To prevent the spec from being "boxes and arrows" with no executable substance, the following reference implementations ship alongside this spec and are the executable specification for their respective predicates:

| Module | Specification of |
|---|---|
| `conservation_scan.py` | P_Q1_invariant_integrity, P_Q2_state_traceability, P_Q3_decision_reversibility, P_M4_independence, P_O5_context_sufficiency_hard |
| `test_conservation_scan.py` | Reference vectors for all five above |

Any alternative implementation MUST pass these reference vectors. Additional reference implementations for `P_PI_sentinel`, `P_acceptance_tests`, and skill-specific predicates are produced per the predicate-addition procedure in §1.5.

---

## §6 — What this spec does NOT contain

- Trust-zone rules → **Kernel Spec §1**
- State machines → **Kernel Spec §2**
- Failure-domain behaviors → **Kernel Spec §3**
- Package identity, semver, signed-release mechanics → **Distribution Spec**
- Kill-switch specification → **Kernel Spec §5**

---

*End of Verification Spec.*
