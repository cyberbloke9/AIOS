# Integrating AIOS into your project

> How to take an existing repo and turn it into something AIOS can govern.
> Companion to `examples/demo.md` and the sprint-29/30 CLI.

## One-time setup

```bash
# From inside your project's root
aios adopt .
aios git-init
```

After this:

- `.aios/config.json` exists with profile declaration and the five spec
  versions. **Commit it.**
- `.aios/invariants.yaml` holds a stub you fill in with your real
  invariants. **Commit it.**
- `.aios/events/`, `.aios/projections/`, `.aios/credentials/`, and the
  `log.lock` files are added to `.gitignore` — they are local runtime
  state, not declarative state.
- `.git/hooks/post-commit` now appends a `commit.landed` frame to the
  event log on every commit. User-authored hook content is preserved.

## The `.aios/` directory

```
.aios/
├── config.json        committed — profile + spec versions (Distribution §4.1)
├── invariants.yaml    committed — the declared invariant set (Constitution §1.1)
├── events/            gitignored — append-only event log (Runtime §1)
├── projections/       gitignored — derived views (Kernel §3.4)
└── credentials/       gitignored — Phase 0/1 credential records (Ver §3)
```

## invariants.yaml schema

```yaml
invariants:
  - id: INV-001                       # required, must be unique
    source: principle                 # principle | security | adr | interface
    statement: |
      What must hold. Free text. Keep it declarative.
```

Duplicate IDs and unknown `source` values are rejected at read time —
malformed files fail `aios check` with an explicit line pointer.

## ADR format

AIOS understands Nygard/adr-tools-style markdown with YAML front matter.
Drop files into any of:

- `adrs/`
- `docs/adr/`
- `doc/adr/`
- `docs/adrs/`

The first directory found wins.

```markdown
---
id: ADR-0042                         # required, unique
status: Accepted                     # Proposed | Accepted | Rejected |
                                     # Deprecated | Superseded
date: 2026-03-15
removes: [INV-002]                   # optional — invariants this ADR retires
deprecates: ADR-0001                 # optional — the ADR this one replaces
---
# ADR-0042 — Title

## Context

...

## Decision

...

## Consequences

...
```

### Lifecycle rules enforced by SK-ADR-CHECK

- `deprecates` must point to an existing ADR.
- The deprecation target must be Accepted or already-Deprecated
  (Kernel §2.4).
- A Rejected ADR cannot have a non-empty `removes` list
  (Constitution §1.1 — only Accepted ADRs may remove invariants).

## The inner loop

```bash
# Make a change, commit it
git commit -am "refactor pricing"

# The post-commit hook has already logged a commit.landed frame.
# Now run the governance sweep:
aios check --before HEAD~1 --after HEAD
```

Exit codes are wired so `aios check` is CI-friendly:

| Code | Meaning |
|---|---|
| 0 | promoted — all gates green, no ADR violations |
| 2 | bad input — repo not adopted, bad refs, etc. |
| 4 | Q1/Q2/Q3 soundness breach — run aborted |
| 6 | workflow rejection OR ADR violations |

Drop this into your CI:

```yaml
- run: aios check --before $BASE_REF --after HEAD --impact subsystem
```

## Impact levels

`--impact local` (default) runs the Q1/Q2/Q3 substrate. Higher impact
pulls in more gates per Kernel §1.2 (subsystem adds M4 + O5 + acceptance
tests; system_wide adds adversarial injection). For a service PR
touching cross-service contracts, pass `--impact subsystem`. For a
kernel-adjacent change, `--impact system_wide`.

## What you still need

- **Real invariants.** The stub `aios adopt` ships has `invariants: []` —
  that's intentional. You write the invariants that matter for your
  system. Start small: 3-5 principle-level invariants covering what
  MUST hold.
- **ADR discipline.** Every time a new invariant lands, ship an ADR
  declaring it. Every time one is retired, ship an ADR removing it.
  This is governance, not automation — AIOS enforces the bookkeeping,
  not the judgment.
- **A review protocol for confidence-emitting skills.** v0.3.0 doesn't
  do that yet (Verification §2 calibration lands in M4). Don't let
  skills emit a `confidence` scalar until calibration goes live.
