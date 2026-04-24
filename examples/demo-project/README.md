# AIOS demo project

A toy project laid out exactly the way `aios adopt` expects:

```
demo-project/
├── .aios/
│   ├── config.json           ← written by aios adopt
│   ├── invariants.yaml       ← the three invariants this project defends
│   └── events/               ← runtime state (gitignored in a real repo)
├── adrs/
│   ├── 0001-pii-logging-policy.md
│   └── 0002-append-only-log.md
└── README.md
```

See `../demo.md` for the walkthrough showing `aios check` catching a silent
Q1 breach.

## Prerequisites

```
pip install -e "../..[enterprise,dev]"     # from the AIOS repo root
```

## Quick tour

```
cd examples/demo-project
aios adopt .                      # creates .aios/config.json + genesis events
aios check                        # should pass cleanly: 3 invariants, 2 ADRs
```

Then see `../demo.md` for the "catch the breach" exercise.
