# AIOS — first build (P-Local)

> Reference Python implementation of the AIOS v8 closure-pass specification,
> scoped to the **P-Local** conformance profile (single-developer, single-host).

**Status.** Bootstrapping — see `.planning/PLAN.md`.
**Specs in this repo.** Constitution v1.0, Kernel v1.0, Verification v1.0,
Distribution v1.0, Runtime Protocol v1.0 (all vendored in `docs/spec/`).

## What this is

The five-document AIOS stack is a machine contract, not prose. This package
is the first executable build:

- event log (append, rotate, replay, verify, detect corruption and seq gaps)
- conservation scan (Q1, Q2, Q3, M4, O5 per Verification Spec §1)
- gate registry (§1.2 core predicates)
- CLI with `--help`
- P-Local loader enforcement (Runtime Protocol §10.1, §10.6)
- coverage matrix explicitly stating what is **not** implemented

See `docs/coverage.md` for the full normative / not-covered breakdown.

## Requirements

- Python 3.11+
- Standard library only (no runtime deps for v1 core)

## Install

```
pip install -e .
```

## Quickstart

```
aios --help
aios init ./my-aios-home --profile P-Local
aios append --kind run.started --actor A1 --payload '{"run_id":"r001"}'
aios replay
aios scan --run-id r001
aios check-profile
```

## Not implemented in this build

Follows Runtime Protocol §8.1 "NOT covered" table. Highlights:

- Ed25519 frame signatures, capability tokens (§2)
- POSIX fcntl / Windows LockFileEx writer lock (§5.1)
- Merkle batch overlay (§1.5 — optional per P-Local)
- TUF client + bootstrap anchor verification (§6)
- Snapshots, compaction (§1.7, §1.8)
- Full CBOR decoder (ref decoder handles the AIOS subset)

These are deliberately deferred per §10.1. `aios check-profile` will refuse
to start if you declare P-Enterprise / P-HighAssurance / P-Airgap against
this build — the loader enforces the profile, not the flag.

## License

MIT — see `LICENSE`.
