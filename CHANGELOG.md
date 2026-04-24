# Changelog

All notable changes to this project will be documented here.

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
