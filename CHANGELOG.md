# Changelog

All notable changes to this project will be documented here.

## [0.1.0] — unreleased (P-Local first build)

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
