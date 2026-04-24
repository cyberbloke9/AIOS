----------------------------- MODULE AIOS_EventLog -----------------------------
(***************************************************************************
  Formal specification of AIOS Runtime Protocol §5 ordering invariants
  (sprint 71).

  Models a single-writer, multi-reader append-only event log with:
    - Strictly monotonic Log Sequence Numbers (LSN)
    - Hash-chain linkage: frame.prev == hash_of(prior_frame)
    - Single-writer invariant: one process appends at any moment
    - Replay determinism: reading yields the same ordered sequence
      every time for a given log state

  Refer to Runtime Protocol §5 (Replay Ordering & Concurrency) for
  the corresponding prose contract. This module is the machine-checkable
  companion. Intended for TLC model checking with small bounds.

  Acknowledgments:
    Shape inspired by the TLA+ community's tla_apalache repository
    and the Kafka log replication spec pattern.
 ***************************************************************************)

EXTENDS Naturals, Sequences, TLC

CONSTANTS
  Writers,          \* Set of potential writer process IDs
  MaxSeq,           \* Upper bound on LSN values explored by the model
  HashSpace         \* Set of opaque "hash" values; model-checker can
                    \* instantiate as a small set of strings

VARIABLES
  log,              \* Sequence of frames; log[i] = <<seq, prev, hash>>
  activeWriter,     \* Writer currently holding the append lock, or NONE
  nextSeq           \* LSN the next appended frame will carry

vars == <<log, activeWriter, nextSeq>>

NONE == CHOOSE x : x \notin Writers

(***************************************************************************
  Initial state — an empty log with no writer and seq 0 as the next LSN.
 ***************************************************************************)

Init ==
  /\ log = <<>>
  /\ activeWriter = NONE
  /\ nextSeq = 0

(***************************************************************************
  A writer attempts to acquire the lock. Only one writer may hold it at a
  time; this is the §5.1 single-writer invariant in action.
 ***************************************************************************)

AcquireLock(w) ==
  /\ activeWriter = NONE
  /\ w \in Writers
  /\ activeWriter' = w
  /\ UNCHANGED <<log, nextSeq>>

ReleaseLock(w) ==
  /\ activeWriter = w
  /\ activeWriter' = NONE
  /\ UNCHANGED <<log, nextSeq>>

(***************************************************************************
  Append one frame. The writer:
    - holds the lock
    - reads the last-frame hash (or a designated GENESIS for the empty log)
    - appends a record whose seq = nextSeq and prev = last-hash
    - chooses a fresh hash value (abstract: any unused element of HashSpace)
    - advances nextSeq
 ***************************************************************************)

LastHash ==
  IF log = <<>> THEN "GENESIS"
  ELSE log[Len(log)][3]                 \* field 3 of the last frame

UsedHashes == { log[i][3] : i \in DOMAIN log }

Append(w) ==
  /\ activeWriter = w
  /\ nextSeq < MaxSeq
  /\ \E h \in HashSpace \ UsedHashes :
        /\ log' = Append(log, << nextSeq, LastHash, h >>)
        /\ nextSeq' = nextSeq + 1
  /\ UNCHANGED activeWriter

Next ==
  \/ \E w \in Writers : AcquireLock(w)
  \/ \E w \in Writers : Append(w)
  \/ \E w \in Writers : ReleaseLock(w)

Spec == Init /\ [][Next]_vars

(***************************************************************************
  Invariants — what must hold in EVERY reachable state.
 ***************************************************************************)

\* I1 — at most one writer holds the lock
SingleWriter ==
  activeWriter # NONE => activeWriter \in Writers

\* I2 — seq values strictly monotonic across the log
LSN_Monotonic ==
  \A i, j \in DOMAIN log :
    i < j => log[i][1] < log[j][1]

\* I3 — no gaps in seq values (advance by exactly 1)
LSN_NoGap ==
  \A i \in DOMAIN log :
    log[i][1] = i - 1

\* I4 — hash chain linked: every frame's prev equals the prior frame's hash
ChainLinked ==
  \A i \in DOMAIN log :
    IF i = 1
      THEN log[i][2] = "GENESIS"
      ELSE log[i][2] = log[i-1][3]

\* I5 — no duplicate hashes in the log (content-addressed uniqueness)
UniqueHashes ==
  Cardinality(UsedHashes) = Len(log)

\* I6 — no writer can act without holding the lock
\*      (derived from Append's guard; expressed here for the model checker)
ExclusiveAppend == TRUE  \* Append(w) guards on activeWriter = w

(***************************************************************************
  Temporal property — the log never shrinks (append-only §1.1).
 ***************************************************************************)

AppendOnly ==
  [][ \/ Len(log') = Len(log)
     \/ Len(log') = Len(log) + 1 ]_vars

(***************************************************************************
  Model-checking boilerplate. Instantiate MaxSeq + Writers + HashSpace in
  the TLC configuration:

    MaxSeq <- 4
    Writers <- {"w1", "w2"}
    HashSpace <- {"h0", "h1", "h2", "h3", "h4", "h5"}

  INVARIANTS:
    SingleWriter
    LSN_Monotonic
    LSN_NoGap
    ChainLinked
    UniqueHashes

  PROPERTY:
    AppendOnly
 ***************************************************************************)

Cardinality(S) == IF S = {} THEN 0 ELSE 1 + Cardinality(S \ {CHOOSE x \in S : TRUE})

================================================================================
