# Demo — catching a Q1 breach end-to-end

This walkthrough uses `examples/demo-project/`. It shows the full loop a user
gets once they run `aios adopt` on their repo: a silent invariant removal is
caught by `aios check`, prints a diagnostic, and exits non-zero.

## 1. Adopt the project

```
cd examples/demo-project
aios adopt .
```

Output:

```
adopted AIOS into repo .../examples/demo-project
  profile:         P-Local
  aios home:       .../.aios
  invariants.yaml: existing          ← we shipped one; adopt did not overwrite
  .gitignore:      updated
```

## 2. Baseline check — clean pass

```
aios check
```

Output (abbreviated):

```
aios check — .../examples/demo-project
  invariants:     3
  ADRs:           2

  ADR structural violations: 0

workflow: aios-check
outcome:  PROMOTED
  [ok] P_Q1_invariant_integrity
  [ok] P_Q2_state_traceability
  [ok] P_Q3_decision_reversibility
```

Exit code 0. All three invariants present, both ADRs well-formed.

## 3. Commit the baseline and introduce a silent breach

```
git init -q -b main
git add .aios/invariants.yaml adrs/ README.md
git commit -q -m "baseline: 3 invariants, 2 ADRs"
```

Now edit `.aios/invariants.yaml` and delete the INV-003 entry entirely —
no ADR, no justification, nothing. Commit the change:

```
git commit -qam "drop INV-003"
```

## 4. Run aios check against the previous commit

```
aios check --before HEAD~1 --after HEAD
```

Output (abbreviated):

```
aios check — .../examples/demo-project
  before_ref:     HEAD~1
  after_ref:      HEAD
  invariants:     2
  ADRs:           2

  ADR structural violations: 0

workflow: aios-check
outcome:  ABORTED
  [BREACH] P_Q1_invariant_integrity
```

Exit code **4** (Q1/Q2/Q3 soundness breach). The run was aborted before
Q2 or Q3 even got a chance to evaluate — this matches Kernel Spec §2.2:
a conservation breach transitions the run directly to aborted.

## 5. The fix — add an ADR authorizing the removal

Create `adrs/0003-retire-append-only.md`:

```
---
id: ADR-0003
status: Accepted
date: 2026-04-24
removes: [INV-003]
---
# ADR-0003 — Retire the append-only invariant

(Hypothetical, for demo purposes.)
```

```
git add adrs/0003-retire-append-only.md
git commit -qam "legitimize INV-003 removal via ADR-0003"
```

Now re-run:

```
aios check --before HEAD~2 --after HEAD
```

Q1 preserves: the disappearance of INV-003 is authorized by an Accepted
ADR whose `removes` list contains `INV-003`, so the Constitution's
§1.1 escape clause applies.

Exit code 0 again. The whole loop: one command to adopt, one command to
check, automatic frame logging into `.aios/events/`, and Q1-Q3 catch the
thing that mattered.
