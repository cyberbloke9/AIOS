# AIOS Distribution Spec

*Package, sign, install, upgrade, rollback, uninstall.*

**Status.** Normative. Subordinate to the AIOS Constitution.
**Version.** 1.0.0, aligned with Constitution v1.0 and Kernel Spec v1.0.
**Scope.** How AIOS reaches a host and how it leaves cleanly.

---

## §0 — Orientation

This spec answers the questions Codex's second review correctly insisted on:

- What is the package boundary?
- What is the install contract?
- What is the upgrade contract?
- What is the rollback contract?
- What is the uninstall contract?
- What is the supply-chain model?
- What does the system do offline, air-gapped, and under corrupted state?

The precedents carrying most of the weight:

1. **Debian Policy Manual** — separation of policy from individual packages; "essential" packages as the irreducible core.
2. **Sigstore / cosign / Rekor** — modern signed-release tooling with a tamper-evident public transparency log.
3. **Reproducible Builds** project — deterministic builds producing bit-identical outputs as the foundation for signature meaningfulness.
4. **SPDX** and **CycloneDX** — standardized SBOM formats for supply-chain accountability.
5. **npm's lockfile + semver** conventions for dependency pinning.

---

## §1 — Package Identity and Namespace

### §1.1 Top-level packages

AIOS is distributed as a set of packages under a reserved npm namespace. The boundary is explicit: the `@aios-core/*` namespace is the trusted distribution; packages outside it are community contributions and are never loaded into Z0 or Z1 without an explicit trust-promotion ADR.

| Package | Role | Zone |
|---|---|---|
| `@aios-core/kernel` | Conservation-scan predicates (Q1–Q3); zone-transition logic; event-log append path | Z0 |
| `@aios-core/verification` | Gate registry; calibration runner; credential ledger; audit runner | Z0 with Z1 extension points |
| `@aios-core/distribution` | Package manifest tools; signed-release verifier; SBOM tooling | Z0 |
| `@aios-core/skills-baseline` | The initial skill set (ADR-check, precedent-match, threat-model, debate-N3, etc.) | Z1 |
| `@aios-core/cli` | Operator CLI: load workflow, run, audit, kill | Outside zones; invokes zone APIs |

### §1.2 Package manifest requirements

Every `@aios-core/*` package must declare in its `package.json`:

```json
{
  "name": "@aios-core/<name>",
  "version": "X.Y.Z",
  "aios": {
    "zone": "Z0 | Z1 | Z1+Z0 extensions",
    "constitution_version": "1.0.0",
    "kernel_spec_version": "1.0.0",
    "verification_spec_version": "1.0.0",
    "distribution_spec_version": "1.0.0",
    "sbom": "./sbom.spdx.json",
    "signature": "./signature.cosign"
  },
  "engines": { "node": ">=20.0.0" }
}
```

A package without an `aios` block is not an AIOS package and is refused by the loader.

### §1.3 Subpackage policy

Subpackages (`@aios-core/skills-baseline/adr-check`, etc.) are permitted but each must satisfy §1.2 independently. Monorepo structure does not exempt subpackages from the manifest requirement.

---

## §2 — Semantic Versioning Rules

AIOS uses strict semver with domain-specific interpretation. The bright-line rule: changes to the Constitution's Articles I–V (soundness-critical) force a major version bump on every AIOS package that references them.

### §2.1 Major version (`X`)

A major bump is required when any of the following occur:

- Any of Articles I–V of the Constitution changes.
- KI-1 through KI-7 (Kernel Invariants) change.
- Any gate predicate's input schema changes in a non-additive way.
- The trust-zone taxonomy changes.
- The event-log schema changes in a non-additive way.

### §2.2 Minor version (`Y`)

A minor bump is required when:

- A new gate predicate is added.
- A new skill is added to the baseline.
- A new failure domain is added.
- A new calibration method is supported.
- Any schema is extended additively.

### §2.3 Patch version (`Z`)

A patch bump is permitted for:

- Bug fixes that preserve all public interfaces.
- Performance improvements.
- Documentation updates.
- Reference-test additions.

### §2.4 Deprecation policy

A public interface marked deprecated remains available for at least one full major version. Removal requires:

- An Accepted ADR naming the deprecation and the rationale.
- A migration guide for consumers.
- A minimum of 90 days between deprecation notice and removal.

### §2.5 Downgrade policy

Downgrades are supported within the same major version. Cross-major downgrades are not supported automatically; they require an explicit migration plan and are executed via uninstall followed by install of the prior major version. The event log survives this process (§4.4).

---

## §3 — Supported Runtime Matrix

AIOS targets stable, long-supported runtimes. The matrix is constrained to reduce compatibility surface.

### §3.1 Node.js

- Supported: active LTS and maintenance LTS lines of Node.js at release time.
- Minimum: Node.js 20.x.
- Not supported: odd-numbered (development) Node.js lines; node versions past end-of-life.

### §3.2 Operating systems

- Supported: Linux (glibc ≥ 2.31), macOS (≥ 14), Windows (≥ 10) via WSL2 for Linux-primary functionality.
- Native Windows: supported for CLI and event-log reader functions; kernel runtime runs in WSL2 by default.
- Supported CPU architectures: x86-64, arm64.

### §3.3 Python (for Z1 skill scripts)

- Minimum: CPython 3.11 for skills that require numerical tooling (calibration, etc.).
- Skills that do not require Python declare so in their contract; they are loadable on hosts without Python.

### §3.4 Offline / air-gapped variant

AIOS supports a fully offline variant:

- All packages downloadable as a signed bundle.
- No runtime network calls from Z0 or Z1.
- Calibration corpora pre-shipped; no cloud corpus fetch.
- Model inference via a local inference endpoint; Distribution Spec does not mandate the endpoint but specifies its interface (`aios_model_endpoint` schema).

### §3.5 Runtime capability detection

On install (§4.1), the install hook runs a capability probe:

- Node version, Python version.
- Filesystem writability for event-log path.
- Filesystem atomicity (fsync behavior).
- Network reachability if not air-gapped.
- Clock skew vs. distribution time authority (for signature validity windows).

Probe results are logged. A capability failure blocks install.

---

## §4 — Install, Upgrade, Rollback, Uninstall

This section defines contracts, not implementations. The Kernel Spec's state machines are the execution model; this spec states the pre- and post-conditions.

### §4.1 Install contract

**Pre-conditions.**

- The install target (a directory path) is writable.
- No prior AIOS install exists at the target, OR the prior install is the same major version and upgrade path is requested.
- Runtime capability probe (§3.5) passes.
- The signed-release bundle passes signature verification against the Distribution Spec's known root of trust (§5.1).

**Post-install state.**

- `@aios-core/kernel` installed; conservation-scan predicates loadable.
- Event log initialized at the configured path with a genesis event.
- Constitution, Kernel Spec, Distribution Spec, Verification Spec installed as reference documents in a read-only directory.
- Registry (`.registry/`) initialized with the baseline skills and workflows.
- Install hook writes an `install_complete` event.

**What the install hook may not do.**

- No network calls if air-gapped mode is selected.
- No writes outside the install target directory.
- No modifications to the host system's package manager state.
- No environment-variable changes outside the AIOS process.
- No telemetry transmission; telemetry is disabled by default (§6.1).

The precedent here is Debian's strict separation of `postinst` scripts from host-level side effects.

### §4.2 Upgrade contract

**Pre-conditions.**

- A prior install exists.
- The upgrade target version is ≥ the current version within the same major version, OR the upgrade is a documented cross-major migration with an explicit migration plan.
- The signed-release bundle for the new version passes signature verification.
- The current event log passes a Q2 scan (Kernel Spec §4.4).

**During upgrade.**

- The system enters a read-only window for the duration of the upgrade.
- Event-log append is suspended; reads continue.
- The upgrade is staged in a shadow directory; the switch to the new version is atomic (symlink flip or equivalent).
- On failure during staging, the shadow directory is discarded; the prior install is unchanged.

**Post-upgrade state.**

- New version installed; prior version archived in `.versions/X.Y.Z/` for rollback (§4.3).
- Event log continues without interruption; the upgrade writes an `upgrade_complete` event with the prior and new versions.
- Q1–Q3 scans run on the full event log before the read-only window is lifted.

**Migration.** A cross-major upgrade runs the migration script from the prior major to the new major. The script:

- Reads from the current event log.
- Writes to a new event log using the new schema.
- Must produce a manifest listing every transformation.
- Fails the upgrade if any event cannot be migrated without loss.

### §4.3 Rollback contract

Rollback restores the state immediately prior to an upgrade.

**Pre-conditions.**

- A prior version exists in `.versions/`.
- The current event log has not accumulated events past the upgrade boundary that depend on features only in the new version. If it has, rollback requires explicit `--accept-data-loss` with a named authority and an event recording the loss.

**Rollback procedure.**

- Read-only window enters.
- Current version's install directory is archived under `.versions/<current>/`.
- The chosen prior version is restored as the active install (atomic switch).
- Event log is truncated to the upgrade-boundary event if `--accept-data-loss` was given, else the rollback is refused.
- A `rollback_complete` event is written.

**What rollback preserves.**

- The event log up to the truncation point.
- Registry entries valid under the restored version.
- Calibration corpora.

**What rollback discards.**

- Events that depended on the new version only (if `--accept-data-loss`).
- Registry entries for skills or workflows introduced in the new version.

### §4.4 Uninstall contract

Uninstall is different from rollback: rollback goes to a prior version; uninstall removes AIOS from the host.

**Standard uninstall.**

- System enters read-only mode; all workflows halted.
- Install directory removed.
- Event log archived to a user-specified path as a signed, self-contained archive (`aios-eventlog-archive-<timestamp>.tar.gz.sig`). This archive is sufficient to reconstruct the full history independently of AIOS.
- Configuration files removed except those explicitly marked preserve-on-uninstall.
- A final `uninstall_complete` event is written to the archive (the archive is closed after this event).

**Purge uninstall (explicit `--purge` flag).**

- Same as standard, plus: the event-log archive is not written; calibration corpora and configuration are removed.
- Requires authority A5 sign-off and an ADR recording the purge rationale.
- Discouraged except for decommissioning compliance reasons.

### §4.5 Install hooks (postinstall behavior)

The permitted surface of install hooks is narrow:

- Runtime capability probe (§3.5).
- Signature verification of the bundle.
- Creation of directories under the install target.
- Write of the genesis event.
- Refusal to install if any prerequisite fails.

The following are prohibited in install hooks:

- Fetching additional code from the network (air-gapped mode requires this; non-air-gapped mode should not).
- Executing arbitrary host commands.
- Modifying shell profiles, cron entries, or service definitions.
- Requesting elevated privileges.

A hook that violates these constraints is treated as a supply-chain incident and fails the install.

---

## §5 — Signed Releases, SBOM, Transparency Log

### §5.1 Signing model

Every release is signed using a Sigstore-equivalent mechanism:

- Release artifacts (tarballs, signed hashes) are produced by the reproducible-build pipeline.
- Signatures are stored alongside artifacts and also submitted to a tamper-evident transparency log.
- Verification requires: the artifact's hash matches the signed hash, the signature verifies against the known root of trust, and the signature entry is present in the transparency log.

**Root of trust.** The root-of-trust public key is shipped as part of the prior release; it can be rotated via an explicit root-rotation release. Users verify a first install against a published root-of-trust fingerprint distributed through the Constitution's amendment channel.

### §5.2 Reproducible builds

All `@aios-core/*` packages build reproducibly. Build inputs (source, dependency lockfile, build tooling versions) produce bit-identical outputs across hosts. The build artifact includes:

- The source archive hash.
- The dependency lockfile hash.
- The build-tooling manifest hash.
- The output artifact hash.

A release whose rebuilds do not match is refused.

### §5.3 SBOM requirements

Every release ships an SBOM in SPDX 2.3 format (primary) and CycloneDX 1.5 format (secondary). The SBOM lists:

- Every direct and transitive dependency.
- Every dependency's version and hash.
- Every dependency's license.
- The provenance of the build environment.

The SBOM is signed alongside the release artifacts. Verification of an install checks SBOM presence and signature.

### §5.4 Transparency log

Release entries are recorded in a Rekor-equivalent transparency log. Each entry contains the artifact hash, the signature, the SBOM hash, and a monotonic index. The transparency log is append-only and independently verifiable.

A release whose transparency-log entry is missing, or whose entry's artifact hash differs from the local artifact, fails verification.

### §5.5 Supply-chain threats explicitly considered

This spec assumes the following threat model:

- **Dependency typosquatting.** Mitigated by namespace reservation and strict lockfile pinning (§7).
- **Compromised upstream maintainer.** Mitigated by reproducible builds (§5.2) and SBOM audits (§5.3).
- **Stolen signing key.** Mitigated by transparency log (§5.4); a compromised key can be detected by comparing local beliefs to the log.
- **Benchmark contamination.** Mitigated by the calibration-corpus rules in Verification Spec §2.3.
- **Model supply-chain attack.** Treated under Kernel Spec §6.3 (Mode A — Adversarial).

---

## §6 — Offline, Air-gapped, Telemetry, Data Residency

### §6.1 Telemetry defaults

Default is zero telemetry. AIOS does not transmit data from the host unless the operator has explicitly enabled a named telemetry channel and authorized the destination. This is non-negotiable: telemetry is opt-in by explicit config, never opt-out.

### §6.2 Air-gapped mode

Air-gapped mode is a first-class deployment target. Requirements:

- No outbound network calls from Z0 or Z1.
- Signed-release verification performed against locally-present transparency log segments.
- Calibration corpora pre-shipped in the bundle.
- Model endpoint is a local deployment, reached via a Unix socket or localhost port only.
- Registry updates via offline bundles signed by A5.

### §6.3 Data residency

The event log and all projections remain on the install host's filesystem unless an operator explicitly configures a replication target. AIOS does not replicate, sync, or mirror data to external destinations by default. An operator who configures replication is responsible for the legal framework of that replication (GDPR, regional requirements, etc.); AIOS records the configuration as an event for audit.

### §6.4 Logs that leave the host

Operator-initiated export of audit reports is supported. Exports include:

- The audit report itself.
- The event-log range underlying the report.
- The signatures and transparency-log entries that allow independent verification.

Exports are never automatic. They require explicit operator command and are logged as events.

---

## §7 — Dependency Policy

### §7.1 Dependency surface

`@aios-core/kernel` has the smallest possible dependency surface: cryptographic libraries (for signing and hashing), serialization (JSON), and storage (filesystem primitives). New kernel dependencies require A5 sign-off and an ADR.

Other `@aios-core/*` packages may have broader dependencies subject to the audit rules in §7.3.

### §7.2 Lockfile and pinning

- Every `@aios-core/*` package ships a lockfile (`package-lock.json`) pinning exact versions of every direct and transitive dependency.
- Lockfile updates are reviewed as if they were code changes.
- Unplanned lockfile drift between `package.json` and `package-lock.json` fails CI.

### §7.3 Dependency audit cadence

- At every minor release: full SBOM diff against the prior release; any added dependency is named in the release notes.
- Monthly: known-CVE scan against the current lockfile; CVE discovery triggers a patch release unless the CVE is non-applicable.
- Quarterly: manual review of the top-level dependency list for abandonment and maintenance signals.

### §7.4 Dynamic dependency loading

Prohibited. AIOS does not fetch, require, or eval code that was not present at install time. The only exception is signed-release upgrades via §4.2, which are explicit operator actions.

---

## §8 — Corruption Recovery

This section specifies behavior when something is wrong and must be healed. The precedent is SQLite's recovery-on-open behavior: on open, the database checks its integrity and takes defined steps before allowing writes.

### §8.1 Corruption detection

- **On install:** signature + SBOM check (§5).
- **On load:** registry hash check (Kernel Spec §3.6 trigger).
- **Continuous:** event-log hash-chain linkage (Kernel Spec §4.1).
- **Periodic:** Q2 scans (Kernel Spec §4.4).

### §8.2 Recovery procedures

| Corruption | Procedure | Authority |
|---|---|---|
| Signature mismatch at install | Refuse install; report to operator | Automatic |
| SBOM mismatch at install | Refuse install; report to operator | Automatic |
| Registry hash mismatch | Halt loads; restore from last signed release; replay post-release events | A5 |
| Event-log hash-chain break | Halt append; enter read-only; restore from most recent snapshot; replay verifiable events after snapshot | A5 + operator |
| Projection hash mismatch | Quarantine projection; rebuild from event log; verify | A4 |
| Calibration corpus hash mismatch | Revert to last-known-good corpus; trigger recalibration | A4 |

### §8.3 Snapshots

AIOS may produce signed snapshots of the event log at operator-configured intervals. A snapshot is:

- A sealed archive of the event log at a named event index.
- Signed by A5.
- Recorded in the transparency log.
- Usable as a restoration starting point for D7 recovery.

Snapshots are optional; deployments may rely on reverse replay for recovery. Recommended for deployments with large event logs.

### §8.4 What cannot be recovered

- Events never fsync'd (Kernel Spec §4.2).
- Events in a hash-chain range where the chain is broken and no snapshot exists prior to the break. Such deployments require operator adjudication.

These cases are rare and represent genuine data loss; the spec does not pretend otherwise.

---

## §9 — Crash Consistency Across Install/Upgrade/Rollback

- Install: atomic symlink to active install; partial install directories are discarded.
- Upgrade: shadow directory + atomic switch; prior install preserved under `.versions/`.
- Rollback: atomic switch back to prior install; event log handled per §4.3.
- Uninstall: event-log archive written before install directory removal; archive is self-contained.

A crash during any of these produces a recoverable state: either the prior install is unchanged, or the new install is complete. There is no in-between state that requires manual surgery.

---

## §10 — What this spec does NOT contain

- Runtime state machines → **Kernel Spec §2**
- Failure-domain behaviors → **Kernel Spec §3**
- Gate registry and predicates → **Verification Spec §1**
- Calibration protocol → **Verification Spec §2**
- Credential protocol → **Verification Spec §3**
- Audit and governance-failure taxonomy → **Verification Spec §4**

---

*End of Distribution Spec.*
