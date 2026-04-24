# Changelog

All notable changes to this project will be documented here.

## [0.4.0] — unreleased (M4: make it safe)

Verification §§2, 3, 4 implemented. Every §1.2 core predicate is now
real. Skills that emit confidence scalars can be calibrated against
rules that refuse weak corpora; credentialing has a §3.1-gated Phase
0 → Phase 1 transition; audit G1–G7 scans + incident replay exist.

### Added

- **Calibration metrics** (`verification.calibration_metrics`) — Brier
  score + Expected Calibration Error, stdlib-only. §2.2 thresholds
  (Brier ≤ 0.25, ECE ≤ 0.10) encoded as default parameters.
- **Corpus quality rules** (`verification.corpus`) — six §2.3 checks
  enforced as loader-level refusals. `CorpusQualityError` names the
  failing rule. Honesty enforced: declared adversarial share + class
  imbalance must match computed values ±1%.
- **Calibration methods** — `temperature_scaling` (grid + local refine)
  and `platt_scaling` (gradient descent, deterministic init) in
  `verification.calibration`. Linear-probe and self-consistency stay
  deferred.
- **CalibrationRecord + persistence** — §2.4 schema with to_json /
  from_json. `aios calibrate <SK-ID> --corpus ... --method ...`
  CLI saves the record; any threshold failure exits 7 and records the
  attempt in the sidecar.
- **Calibration drift + quarantine** — weekly/monthly windows,
  `<skill>.attempts.json` sidecar, three-failures-in-30d → quarantined.
  `aios calibration-status` CLI with exit codes 0 / 8 / 9.
- **Credential ledger** — `verification.credentials` + §3.2 schema.
  `BandStanding` encapsulates +α/-β/-γ/+δ/-ε transitions; ledger
  persists to `<home>/credentials/ledger.json`. `aios credential-seed`
  / `aios credential-status` CLI.
- **Phase 0 gate accuracy** — `verification.phase0.measure_gate_accuracy`
  with §3.1 thresholds by failure level. Stubs count as FN 1.0 — no
  sneak-through for unimplemented predicates.
- **Contamination audit + incident backtesting** — `verification.backtest`
  with §3.1 overlap threshold 0.05 and contamination-tolerant escape
  hatch. Backtest surfaces hit_rate + missed_incident_ids.
- **Phase 0 → Phase 1 transition** — `verification.phase1.check_phase1_
  readiness` aggregates all §3.1 prerequisites; `enable_phase1` flips
  every phase=0 credential after verifying readiness AND A4 + A5
  co-signers. Idempotent.
- **Phase 1 update rule** — `verification.phase1_update.apply_run_
  outcome` applies §3.3 weights with monotone-bands constraint
  (system_wide ≤ subsystem ≤ local). §3.5 restitution: 90-day window,
  budget 10, frozen standing while in restitution, doubled budget
  on recurrence.
- **Band capability mapping** — `capability_for_band(standing)` →
  quarantined / supervised / standard / sole_verifier per §3.4.
- **Audit protocol** — `verification.audit` with seven `scan_*`
  primitives producing AuditEvents for G1–G7 classes. `AuditReport`
  rolls up by class; `.summary()` includes containment strategy per
  §4.3.
- **Incident replay** — `verification.incident_replay.replay_incident`
  reconstructs workflow from frames, attributes G-class (G1 for zero
  gate.evaluated, G2 for uncaught Q-breach, G6 for stub encountered).
  `aios replay-incident <run_id>` CLI, exit codes 0 / 10 / 11.
- **Real P_PI_sentinel** — pattern-based deterministic detector for
  role_escape / system_prompt_leak / identity_hijack / tool_hijack /
  delimiter_smuggle. Registered via default_registry; retires the
  sprint-4 stub.
- **Real P_acceptance_tests** — subprocess pytest wrapper with
  timeout + exit-code mapping + summary-line parser. Retires the
  last §1.2 core-predicate stub.

### Test count

495/495 pass with the enterprise extra installed.

### Deferred (remaining for M5/M6)

- TUF client + multi-channel bootstrap anchor (§6)
- Merkle batch overlay (§1.5) — P-HighAssurance only
- Snapshots + compaction (§1.7, §1.8)
- Sigstore/Rekor signed releases + SBOM (Distribution §5)
- Install/upgrade/rollback/uninstall atomic shadow dir (Dist §4.2-4.4)
- DPoP proof-of-possession (§2.8)
- Kill switch daemon (Kernel §5)
- SK-THREAT-MODEL / SK-DEBATE-N3 skills
- Subprocess sandboxing for P_acceptance_tests
- TLA+ formal model of §5 ordering

## [0.3.0] — unreleased (M3: make it usable)

The first build a real developer can point at their repo and have
governance. Closes the integration gap between "spec demonstrator" and
"works on my project."

### Added

- **Project-state readers** (`aios.project.readers`) —
  `read_invariants()` parses `.aios/invariants.yaml|.json` into
  `frozenset[Invariant]`. `read_adrs()` walks the ADR directory
  (first found of `adrs/`, `docs/adr/`, `doc/adr/`, `docs/adrs/`) and
  parses YAML front matter into `tuple[ADREvent]`. Stdlib-only
  mini-YAML fallback when PyYAML is absent.
- **RunState adapter** (`aios.project.runstate_from_project`) —
  builds a RunState from a real repo, optionally diffing two git refs
  via `git show` + temp reconstruction. The "before" invariant set is
  recovered from history so Q1 silent-removal detection works across
  commits.
- **Real P_schema_valid** backed by `jsonschema>=4.20` (Draft 2020-12).
  Added as a core dependency. Retires the sprint-4 stub; returns
  structured errors with absolute_path for downstream tooling.
- **Skill framework** (`aios.skills`) — `SkillContract` frozen
  dataclass + `SkillRegistry` parallel to the gate Registry. Invoke
  path validates inputs and outputs against JSON Schema. Stubs raise
  `NotImplementedSkillError` — no silent pass.
- **SK-ADR-CHECK** — validates ADR lifecycle (Kernel §2.4) + reference
  integrity + Constitution §1.1 `removes` requires Accepted status.
  Registered on import.
- **SK-PRECEDENT-MATCH** — stdlib TF-IDF over ADR bodies. Ranks prior
  ADRs against a query string so authors see related precedents.
- **`aios adopt <repo>`** — scaffolds `.aios/` into an existing repo,
  writes starter `invariants.yaml`, adds runtime state to `.gitignore`.
- **`aios git-init`** — installs `.git/hooks/post-commit` that appends
  `commit.landed` frames. Idempotent + preserves user hook content.
- **`aios check`** — the "it works on my repo" command. Builds a
  RunState from the project, runs SK-ADR-CHECK + Q1/Q2/Q3 gates,
  emits all the usual workflow frames.
- **Demo project** — `examples/demo-project/` + `examples/demo.md`
  walkthrough showing the silent-invariant-removal scenario
  end-to-end.
- **Docs** — `docs/integration.md` with the full `.aios/` layout,
  schemas, and CI recipe. README reshuffled to foreground the
  adopt-then-check flow.

### Test count

279/279 pass with the enterprise extra installed.

### Still deferred (see docs/coverage.md)

- TUF client + bootstrap anchor verification (§6)
- Merkle batch overlay (§1.5) — P-HighAssurance only
- Snapshots + compaction (§1.7, §1.8)
- Credentialing Phase 0 and Phase 1 (Verification §3)
- Calibration protocol with corpus-quality rules (Verification §2)
- Audit protocol + G1-G7 taxonomy (Verification §4)
- SBOM production + Sigstore/Rekor signed releases (Distribution §5)
- DPoP proof-of-possession (§2.8)
- SK-THREAT-MODEL / SK-DEBATE-N3 skills

## [0.2.0] — unreleased (Option 1 + 2 + 3: P-Enterprise partial + workflow orchestrator + CI/release)

### Added

- **Ed25519 frame signing** (`aios.enterprise.signing.Ed25519Signer/Verifier`).
  `pip install aios[enterprise]` brings `cryptography` and `PyYAML`.
  `EventLog(signer=..., verifier=...)` auto-signs on append and verifies
  on replay. `Frame.unsigned_cbor()` is the signature target to avoid
  signature-over-signature cycles.
- **Single-writer file lock** (`aios.runtime.filelock.FileLock`).
  POSIX `fcntl.flock` / Windows `msvcrt.locking`. `EventLog.__init__`
  acquires `<root>/log.lock`; second opener raises `LockContentionError`.
  Runtime Protocol §5.1 is now enforced, not just asserted.
- **P-Enterprise partial loader support**. `aios check-profile` with
  `profile=P-Enterprise` no longer uniformly refuses; it runs richer
  checks (`ed25519_available`, `writer_lock_active`) and names the
  remaining unimplemented features (TUF, credentialing, calibration,
  audit, SBOM) individually.
- **Workflow manifest schema** (`aios.workflow.manifest.WorkflowManifest`).
  YAML or JSON. Kernel §1.2 impact-level default gate sets. Validates
  every gate against the registry.
- **Workflow runner** (`aios.workflow.runner.WorkflowRunner`). Kernel §2.2
  lifecycle: emits run.started / gate.evaluated* / (run.aborted |
  artifact.rejected | artifact.promoted). Q1-Q3 breach aborts
  immediately; stubs cause rejection (no silent pass).
- **`aios run <manifest>`** CLI subcommand. Exit 0 promoted / 4
  soundness-breach / 6 other rejection.
- **GitHub Actions CI** (.github/workflows/ci.yml) — 3 OS × 2 Python
  matrix with enterprise extras, plus a stdlib-only minimal job.
  End-to-end CLI smoke test on every run.
- **Release workflow** (.github/workflows/release.yml) — tag-triggered
  build + test + PyPI trusted publishing + GitHub Release.

### Test count

170/170 pass on the enterprise install.

### Known limitations still deferred (see docs/coverage.md)

- TUF client + bootstrap anchor verification (§6)
- Merkle batch overlay (§1.5) — required only for P-HighAssurance
- DPoP proof-of-possession on tokens (§2.8)
- Snapshots and compaction (§1.7, §1.8)
- Credentialing Phase 0 and Phase 1 (Verification §3)
- Calibration protocol with corpus-quality rules (Verification §2)
- Audit protocol and G1-G7 taxonomy (Verification §4)
- SBOM production + Sigstore/Rekor signed releases (Distribution §5)

## [0.1.0] — 2026-04-24 (P-Local first build)

First build per the v8 closure-pass success criteria:

- installs locally (`pip install -e .`)
- runs tests (80 passing)
- initializes an AIOS directory (`aios init`)
- appends, rotates, replays frames (Runtime §§1, 3, 4, 5)
- detects corruption (CRC, hash chain, trailer, header)
- detects seq gaps (hand-built adversarial test)
- runs conservation scan (Q1, Q2, Q3, M4, O5)
- enforces P-Local loader checks (Runtime §10.6)
- exposes a CLI with `--help` (`aios init/append/replay/scan/info/check-profile/version`)
- documents exactly what is not implemented (`docs/coverage.md`)

### Added

- `src/aios/runtime/event_log.py` — deterministic CBOR, frame struct,
  segment header/trailer, length+CBOR+CRC-32C framing, rotation, replay,
  hash-chain verification. Fixes a Windows file-handle leak in the
  reference `_open_new_segment`; frame hashes unchanged.
- `src/aios/verification/conservation_scan.py` — Q1/Q2/Q3 conservation
  laws, M4 independence metric, O5 context sufficiency. Renamed from
  v5 Q4/Q5 per Constitution Article II; Q4/Q5 retained as aliases.
- `src/aios/verification/registry.py` — PredicateRecord schema + the
  eight Verification Spec §1.2 core records. Unregistered-predicate
  refusal; stub-evaluation refusal (no silent pass).
- `src/aios/runtime/init.py` — creates events/, registry/, projections/,
  credentials/ layout and writes install.complete + profile.declared
  genesis frames per Runtime §10.5 and Distribution §4.1.
- `src/aios/runtime/profile.py` — `check_profile()` per Runtime §10.6.
  P-Local checks pass cleanly; P-Enterprise/P-Airgap/P-HighAssurance
  fail with an explicit list of unimplemented features.
- `src/aios/cli.py` — `aios` entry point registered in pyproject.toml.
- `docs/spec/` — vendored v7/v8 Constitution, Kernel, Verification,
  Distribution, Runtime Protocol specs (unmodified).
- `docs/coverage.md` — full covered / deferred matrix per §8.1.
- `docs/profiles.md` — the four profiles and what v0.1.0 refuses.
- `examples/reference/` — verbatim v5/v8 reference Python implementations
  for diff against the package version.

### Known limitations (see docs/coverage.md)

- Ed25519 capability tokens (§2) — deferred
- Merkle batch overlay (§1.5) — deferred (P-HighAssurance only)
- TUF client + bootstrap anchor verification (§6) — deferred
- POSIX fcntl / Windows LockFileEx single-writer lock (§5.1) — deferred
- Snapshots and compaction (§1.7, §1.8) — deferred
- Full CBOR decoder — subset only (sufficient for Frame round-trip)
- Signed-release infrastructure (Distribution §5) — deferred
