# The AIOS Constitution

*Irreducible laws for agentic software engineering.*

**Status.** Normative. Adopted 2026-04-22.
**Supersedes.** AIOS v5 (now archived as the constitutional draft).
**Companion specs.** Kernel Spec, Distribution Spec, Verification Spec.

---

## Preamble

This document is the constitutional kernel of AIOS. It is short by design. Everything that is not stated here is delegated to the three companion specs. The precedent is the Linux kernel's stability contract with userspace — the kernel ABI is rigid, slow-changing, and boring so that the ecosystem above it can evolve quickly without breaking. The Constitution is the ABI. The Kernel Spec, Distribution Spec, and Verification Spec are the equivalent of the reference implementation, the packaging contract, and the conformance suite.

Amendments follow Article VI. External guides (OpenAI's *Practical Guide to Building Agents*, peer-reviewed literature cited below, Codex-style review) are informative references only; they are not constitutional adjudicators. Making external guidance a voting member of a standards process creates version drift, interpretive ambiguity, and dependency on documents we do not control. Those three hazards are sufficient to disqualify external documents from constitutional authority regardless of their merit as references.

---

## Article I — Conservation Laws

Three quantities are conserved under every legitimate state transition. A run that violates any of these halts at the boundary where the violation is detected. These are the soundness properties of AIOS in the Rust sense of *sound* — a bright line, not a guideline.

### §1.1 Q1 — Invariant Integrity

**Law.** For any state transition `s → s'` and any declared invariant set `I`:

> `I(s) ⊆ I(s')` ∨ `∃ adr ∈ events(s → s') : adr.status = Accepted ∧ adr.removes ⊇ I(s) \ I(s')`

Plain English: an invariant may only disappear when an Accepted ADR explicitly authorizes its removal. A diff that silently weakens an invariant is a soundness breach.

**Enforcement.** See Verification Spec §1 predicate `P_Q1_invariant_integrity`.

### §1.2 Q2 — State Traceability

**Law.** For every projection `p` at time `t`:

> `hash(replay(events_up_to(t))) = stored_projection_hash(p, t)`

Plain English: the state visible to the system must be reproducible by replaying the event log. If replay does not match the stored hash, something in the chain has been tampered with or corrupted.

**Enforcement.** See Verification Spec §1 predicate `P_Q2_state_traceability`. The accounting precedent is double-entry bookkeeping: the ledger equation is genuinely conserved; any imbalance is a real defect, not a stylistic preference.

### §1.3 Q3 — Decision Reversibility

**Law.** For every decision `d` accepted by the system:

> `d.rollback_cost = irreversible ⇒ ∃ adr : adr.irreversibility_of = d ∧ adr.status = Accepted`

Plain English: a decision that cannot be undone must be declared irreversible explicitly, with an Accepted ADR acknowledging it. Accidental irreversibility is a soundness breach.

**Enforcement.** See Verification Spec §1 predicate `P_Q3_decision_reversibility`.

---

## Article II — Governance Metrics (Non-Conservation)

These quantities are named and measured, but they are not conservation laws. Treating them as such would be a category error. They inform routing and control; they do not define soundness.

### §2.1 M4 — Independence Metric

**Definition.** `M4(artifact) = 1 − max_Jaccard(inputs(generator), inputs(verifier))`.

**Role.** M4 is one input to the Verifier's decision whether to accept the verification path. Low M4 is a signal, not a soundness failure. A reviewer was correct to point out that context-set overlap is a heuristic: two agents with zero input overlap can still share model family, training priors, and benchmark leakage. M4 does not claim to measure independence in the full sense; it measures one necessary condition.

**Threshold.** `[internal policy]` initial `M4 ≥ 0.5` for subsystem- and system-wide-impact artifacts. Tuned under the Verification Spec's audit protocol.

### §2.2 O5 — Context Control Objective

**Definition.** For every query with required invariants `I_req` and loaded invariants `I_loaded`:

> Hard constraint: `I_req ⊆ I_loaded` and `tokens_loaded ≤ budget`  
> Soft objective: minimize `tokens_loaded` subject to the hard constraint

**Role.** O5 is a control objective, not a conserved quantity. The λ-penalty scoring from v5 is a control-theoretic trade-off, not a physical conservation law. Naming matters: calling a control objective a conservation law corrodes the conceptual rigor of the other three laws.

**Enforcement.** The hard constraint is a loader-level refusal; the soft objective is an input to the Token Economist described in the Kernel Spec.

---

## Article III — Authorities

AIOS recognizes five authorities. Their decision rights are non-overlapping, and every decision event carries the authority identifier. Merging authorities, splitting an authority, or creating a sixth authority is a constitutional amendment.

| ID | Authority | Decision rights (irreducible) |
|---|---|---|
| A1 | Router | Classify query; select workflow; dispatch to authorities A2–A5 |
| A2 | Architect | Propose structural change; author ADRs; declare invariants |
| A3 | Implementer | Produce artifacts conforming to ADRs and contracts |
| A4 | Verifier | Evaluate gates; adjudicate Q1–Q3 and M4; accept or reject artifacts |
| A5 | Release & Security | Sign releases; enforce trust-zone promotion; operate kill switches |

No authority may grant itself the decision rights of another. No authority may act without leaving an event record in the log. A4 and A5 together constitute the amendment quorum described in Article VI.

---

## Article IV — Trust Zones

AIOS distinguishes five trust zones. Artifacts and instructions move between zones only through capability-gated transitions. The zone taxonomy is stated here; transition rules and state machines live in the Kernel Spec §1–§2.

| Zone | Name | Contents |
|---|---|---|
| Z0 | Trusted kernel | Constitutional code, conservation-scan predicates, zone-transition logic |
| Z1 | Trusted deterministic skills | Pure, schema-validated skill scripts; outputs are schema-checked |
| Z2 | Untrusted model output | Raw generations; assumed adversarial until promoted |
| Z3 | Quarantined generated artifacts | Output that has entered workflow but not yet passed required gates |
| Z4 | Promoted verified artifacts | Artifacts that have passed all required gates and entered the repository |

**Law.** Promotion from Z_n to Z_(n+1) requires the gate set associated with that transition (defined in the Verification Spec). Downgrade (e.g., a Z4 artifact that fails a post-merge check) returns the artifact to Z3 and emits a demotion event; it does not silently persist.

The precedent is seL4's capability-gated design: the only OS kernel with formal functional correctness proofs, built on the principle that privilege transitions require explicit capability possession, not ambient authority.

---

## Article V — Gate Types

Every gate in every workflow compiles to exactly one of four types:

| Type | Name | Executable form |
|---|---|---|
| T1 | Deterministic predicate | Pure function, returns bool |
| T2 | Test suite | Named suite, pass/fail criterion |
| T3 | Schema check | JSON Schema validation of an upstream artifact |
| T4 | Human hold | Named approver role, time limit, escalation |

**Law.** The workflow loader refuses to load any manifest with an uncompiled or untyped gate. There is no fifth type and no mixed type. Semantic prose gates are either compiled into T1/T2/T3 or reclassified as T4 with a named approver.

The full gate registry — predicate IDs, input and output schemas, determinism requirements, side-effect rules, reference test vectors — lives in the Verification Spec §1.

---

## Article VI — Amendment

**Who.** An amendment to this Constitution requires the concurrence of A4 (Verifier) and A5 (Release & Security), plus one of: A2 (Architect) for amendments to Articles I–V, or the designated constitutional review committee for amendments to this article itself.

**How.** Every amendment proposal must produce:

1. A diff against the current Constitution.
2. An impact analysis against the Kernel Spec, Distribution Spec, and Verification Spec.
3. A conservation ledger covering the preceding 90 days, demonstrating Q1–Q3 preservation rates.
4. A migration plan for any in-flight work.
5. An informative review against the references named in §VI.3.

**External references (non-normative).** The following guides are consulted as informative references during amendment review. They do not vote. They cannot veto. Their authority is persuasive, not adjudicatory. This is the correction to v5's mistake of elevating external documents to constitutional-lane status.

- OpenAI, *A practical guide to building agents* — agent design patterns.
- Codex-style first-principles review — physics/machine-code critique methodology.
- Peer-reviewed references listed in §VI.4.
- GPT-style agentic prompting conventions (Scope Discipline, CTCO framing, Plan-then-Execute separation) — prompt-engineering hygiene.

**Cadence.** Constitutional amendments are rare by design. The expected cadence is at most quarterly. An emergency amendment path exists for discovered soundness violations and requires A4 + A5 sign-off within 72 hours.

### §VI.4 Peer-reviewed informative references

Cited in the subordinate specs where load-bearing:

- Liu et al., *Lost in the Middle: How Language Models Use Long Contexts* (TACL 2024) — long-context position effects.
- Kamoi et al., *Self-correction critical survey* (TACL 2024).
- Li et al., *Evaluating the Instruction-Following Robustness of LLMs to Prompt Injection* (EMNLP 2024).
- Du et al., *Improving Factuality and Reasoning via Multi-Agent Debate* (ICML 2024).
- Li et al., *Improving Multi-Agent Debate with Sparse Communication Topology* (EMNLP Findings 2024).
- Jimenez et al., *SWE-bench* (ICLR 2024); Aleithan et al., *SWE-Bench+* benchmark audit.
- He, Treude, Lo, *LMA for SE systematic review* (ACM TOSEM 2025).
- Seltzer, *Primer on Provenance* (CACM / ACM Queue).
- Masud et al., *Reward Engineering for Reinforcement Learning in Software Tasks* (2026 survey).
- Uncertainty quantification and calibration surveys for LLMs (temperature scaling, Platt, linear probes, self-consistency).

---

## Article VII — Severability and Precedence

If any clause of this Constitution is found unsound under a subsequent review, that clause is suspended; the remainder stands. Suspension triggers the emergency amendment path.

**Precedence.** In any conflict between documents:

1. This Constitution governs.
2. Verification Spec governs soundness checks.
3. Runtime Protocol Spec governs wire formats, ordering, and bootstrap trust.
4. Kernel Spec governs runtime behavior.
5. Distribution Spec governs packaging and deployment.
6. Skill contracts govern individual skill behavior.
7. Workflow manifests govern specific runs.

A conflict that reaches this Constitution and cannot be resolved by amendment indicates a constitutional defect and triggers the emergency amendment path.

---

## What this Constitution does NOT contain

By design, the following are delegated to the subordinate specs. A reviewer looking for these topics in the Constitution will not find them, and that absence is intentional:

- Runtime state machines and transition semantics → **Kernel Spec §2**
- Failure-domain matrix (8 domains × 4 verbs) → **Kernel Spec §3**
- Crash-consistency guarantees → **Kernel Spec §4**
- Kill-switch specification → **Kernel Spec §5**
- Model-unavailability / degraded / adversarial modes → **Kernel Spec §6**
- Package namespace, semver policy, supported runtimes → **Distribution Spec §1–3**
- Install / upgrade / rollback / uninstall semantics → **Distribution Spec §4**
- Signed release + SBOM + transparency log → **Distribution Spec §5**
- Formal gate registry with schemas → **Verification Spec §1**
- Calibration protocol (anti-theater rules) → **Verification Spec §2**
- Credential protocol (Phase 0 prerequisites) → **Verification Spec §3**
- Audit protocol and governance-failure taxonomy → **Verification Spec §4**
- Event-log wire format and concurrency law → **Runtime Protocol Spec §1, §5**
- Capability-token protocol → **Runtime Protocol Spec §2**
- Canonical serialization and cross-platform determinism → **Runtime Protocol Spec §3, §4**
- First-install bootstrap trust ceremony → **Runtime Protocol Spec §6**
- Performance budgets (SLOs per operation class) → **Runtime Protocol Spec §7**

---

*End of Constitution.*
