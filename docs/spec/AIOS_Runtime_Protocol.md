# AIOS Runtime Protocol Spec

*Wire-level machine contract: event-log format, capability tokens, canonical serialization, cross-platform determinism, replay ordering, first-install bootstrap trust, performance budgets.*

**Status.** Normative. Subordinate to the AIOS Constitution.
**Version.** 1.0.0. Aligned with Constitution v1.0, Kernel Spec v1.0, Distribution Spec v1.0, Verification Spec v1.0.
**Scope.** Everything above the operating system and below the Constitution. If a hostile reviewer asks "what exact bytes?" this document answers.

---

## §0 — Orientation

The Constitution, Kernel Spec, Distribution Spec, and Verification Spec together define *what* AIOS guarantees and *who* has authority to do what. Codex's third review was correct that they did not define *how the bits are laid out*. Elite constitution, incomplete machine contract. This document is the machine contract.

### §0.1 Design principle

Reuse battle-tested protocols. Do not invent primitives where a peer-reviewed or IETF-specified one exists. Where AIOS needs a specific behavior that a standard does not provide, name the extension explicitly and cite the closest standard behavior. The protocols carrying weight here:

- **Certificate Transparency (RFC 6962)** — append-only tamper-evident log with Merkle-tree overlay.
- **SQLite WAL format** — the most-deployed crash-consistent append log.
- **Kafka log segments** — segment rotation, LSN addressing, compaction at scale.
- **CBOR deterministic encoding (RFC 8949 §4.2)** — canonical binary serialization.
- **JCS — JSON Canonicalization Scheme (RFC 8785)** — canonical JSON for audit export.
- **Macaroons (Birgisson et al., NDSS 2014)** — capability tokens with HMAC-chained caveats; peer-reviewed.
- **Paseto** — cryptographic suite chosen to fix JWT's `alg:none` and `alg` confusion attacks; Ed25519 + XChaCha20-Poly1305 only.
- **TUF — The Update Framework (Samuel et al., ACM CCS 2010)** — peer-reviewed secure software update framework that survives individual key compromise via role separation and threshold signatures.
- **Sigstore / Rekor** — already cited in the Distribution Spec; uses TUF underneath.
- **WASM deterministic execution** — the clean reference environment for cross-platform bit-identity.
- **Google SRE error-budget methodology** — SLO/SLI discipline for performance targets.

### §0.2 What this document contains, by section

| Section | Underdone item from Codex's review |
|---|---|
| §1 Event-log wire format | Item 1 |
| §2 Capability-token protocol | Item 2 |
| §3 Canonical serialization | Item 4 |
| §4 Cross-platform determinism | Item 4 |
| §5 Replay ordering & concurrency | Item 1 |
| §6 First-install bootstrap trust | Item 3 |
| §7 Performance budgets | Item 5 |
| §8 Delegation + reference-implementation coverage | Boundary clarity |
| §9 Cryptographic surface policy for v1 | Anti-maximalism / Codex's "too ambitious for v1" critique |
| §10 Conformance profiles (Local / Enterprise / Airgap / HighAssurance) | Operational deployability |

### §0.3 RFC 2119 keywords

This document uses MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY with their RFC 2119 meanings.

---

## §1 — Event-Log Wire Format

### §1.1 Design axioms

The event log is:

- **Append-only.** No in-place modification. Compaction produces a new segment; it does not edit existing segments.
- **Hash-chained.** Every frame's hash covers the previous frame's hash. Any tampering propagates forward and is detected on replay (Verification Spec P_Q2_state_traceability).
- **Content-addressed.** The frame hash is the frame's canonical identifier.
- **Segmented.** The log is a sequence of segment files, not a single unbounded file. Segments rotate on size or time boundary (§1.4).
- **Single-writer per segment.** One process appends to the active segment at any time. Multi-writer coordination is achieved via consensus above this layer, not by relaxing the append invariant (§5).
- **Merkle-overlaid for external verification.** A CT-style Merkle tree over frame hashes allows third parties to verify log consistency without reading the full log (§1.5).

### §1.2 Frame structure

A frame is a CBOR map (RFC 8949) with exactly the fields below, encoded under §3 deterministic rules. Additional fields are a wire-format error and MUST be rejected by compliant readers.

| Field | CBOR type | Semantics |
|---|---|---|
| `v` | unsigned int | Frame format version. v1.0 of this spec uses `v = 1`. |
| `seq` | unsigned int (uint64) | Log Sequence Number. Strictly monotonic across the entire log. |
| `ts_ns` | unsigned int (uint64) | Wall-clock timestamp at append time, nanoseconds since Unix epoch (UTC). Advisory, not authoritative for ordering. Integer form only; RFC 3339 text is the audit-export rendering per §3.5, never the on-wire form. |
| `prev` | byte string (32 bytes) | SHA-256 of the prior frame's canonical encoding. For seq=0 (genesis), 32 zero bytes. |
| `kind` | text | Event kind (e.g. `"artifact.promoted"`, `"gate.evaluated"`). Enumerated in a kind registry. |
| `actor` | text | Authority identifier: one of `A1`..`A5`, or a named skill/script. Mirrors Constitution Article III. |
| `payload` | any (CBOR) | Event-specific payload. Schema determined by `kind`. |
| `sig` | byte string (64 bytes), OPTIONAL | Ed25519 signature over the frame, signed by the actor's capability token issuer. REQUIRED for frames that cross trust zones (Z3→Z4 transitions). |

The frame's own hash is SHA-256 of the frame's canonical-CBOR encoding as specified in §3.1. This hash MUST NOT be included as a field inside the frame; it is computed by the reader and is the content identifier of the frame.

Example (annotated CBOR, not on-wire bytes):

```
{
  "actor": "A4",
  "kind": "gate.evaluated",
  "payload": {
    "gate_id": "P_Q1_invariant_integrity",
    "status": "preserved",
    "artifact_ref": "sha256:abc123..."
  },
  "prev": h'0f4e...a9',         // 32-byte SHA-256 of prior frame
  "seq": 4271,
  "sig": h'c5d2...8b',          // 64-byte Ed25519 signature
  "ts_ns": 1745337540123456789, // uint64 ns since Unix epoch UTC
  "v": 1
}
```

The canonical CBOR byte-lex ordering of keys yields: `actor, kind, payload, prev, seq, sig, ts_ns, v`.

### §1.3 Serialization

- **Primary form: deterministic CBOR** per RFC 8949 §4.2 and §3 below. All on-disk frames are deterministic CBOR.
- **Export form: JCS** per RFC 8785. Audit reports and cross-system exports MAY use JCS. When a frame is exported as JCS, the original CBOR bytes SHOULD be archived alongside the JCS rendering so the frame hash remains verifiable; the JCS rendering is a view, not a replacement.

Frame hashes are always computed over the CBOR form. An implementation that stores frames only in JSON internally is non-conforming.

### §1.4 Segment file structure

#### §1.4.1 Naming

Segments are files named `segment_<lsn_start>_<lsn_end>.aios` in the log directory. `lsn_start` is the seq of the first frame; `lsn_end` is the seq of the last frame or `OPEN` for the currently-active segment.

Example:
```
segment_0_999.aios
segment_1000_1999.aios
segment_2000_OPEN.aios      # active
```

#### §1.4.2 Segment header

Every segment begins with a header:

```
magic       4 bytes    "AIOS"
version     2 bytes    uint16 BE, = 1
flags       2 bytes    bit 0: closed; bit 1: compacted; bits 2..15: reserved 0
first_seq   8 bytes    uint64 BE
last_seq    8 bytes    uint64 BE      # OPEN segment: 0xFFFFFFFFFFFFFFFF
created_ts  8 bytes    uint64 BE nanoseconds since Unix epoch
prev_hash   32 bytes   SHA-256 of last frame of prior segment; genesis: 32 zero bytes
hdr_hash    32 bytes   SHA-256 of the above 64 bytes
```

Total header: 96 bytes. Fixed layout, big-endian, no padding.

#### §1.4.3 Frame framing on disk

Each frame on disk is:

```
frame_len   4 bytes    uint32 BE   # length of CBOR frame bytes
frame_bytes N bytes    deterministic CBOR (§1.2)
frame_crc   4 bytes    uint32 BE CRC-32C over frame_bytes
```

The CRC provides fast corruption detection independent of the hash chain. The hash chain provides tamper evidence; the CRC provides corruption detection. They are not redundant.

#### §1.4.4 Rotation

A segment rotates when any of:
- Size: `[internal policy]` default 64 MiB.
- Frame count: `[internal policy]` default 100,000 frames.
- Time: `[internal policy]` default 24 hours since segment creation.
- Operator command.

Rotation procedure:
1. Compute the hash of the last frame in the active segment.
2. Write a trailer to the active segment (§1.4.5).
3. `fsync` the active segment.
4. Create the next segment with `prev_hash` = hash of the last frame of the rotated segment.
5. Rename the rotated file from `segment_<n>_OPEN.aios` to `segment_<n>_<m>.aios`.
6. `fsync` the directory.

Steps 2–5 MUST succeed as a unit. A crash between steps may leave the active segment with or without a trailer; §4.6 of the Kernel Spec's WAL recovery rules apply.

#### §1.4.5 Segment trailer

```
magic       4 bytes    "eoSG"
last_hash   32 bytes   SHA-256 of the last frame's canonical CBOR
frame_count 8 bytes    uint64 BE
end_ts      8 bytes    uint64 BE nanoseconds since Unix epoch
trl_hash    32 bytes   SHA-256 of the above 52 bytes
```

Total trailer: 84 bytes.

### §1.5 Merkle tree overlay

Every `[internal policy]` N=1000 frames (or at segment close, whichever first), the appender computes a Merkle tree over the frame hashes in that batch, and emits a special frame of kind `"merkle.batch"` whose payload contains:

- `batch_start_seq`, `batch_end_seq`
- `leaf_count`
- `merkle_root` (SHA-256, 32 bytes)

The Merkle structure follows RFC 6962 precisely (leaves hashed with a 0x00 prefix, internal nodes with a 0x01 prefix; non-power-of-two trees use RFC 6962's specific padding rule). This means third-party Merkle clients written against RFC 6962 can verify AIOS batch roots without AIOS-specific tooling.

Merkle roots are periodically signed by A5 and published to an external transparency log (Sigstore Rekor or operator-chosen equivalent; see Distribution Spec §5.4). A Merkle root present in the external log that does not match the local computation is a D7 event-log-corruption incident.

### §1.6 Durability

The durability contract restates Kernel Spec §4 with exact semantics:

- `write(frame)` is not durable until `fsync` returns.
- `fsync` is invoked at minimum once per `[internal policy]` 100ms or per 64 frames, whichever first. Producers MAY request immediate fsync for high-assurance frames.
- `fdatasync` is not sufficient; full `fsync` is required because segment metadata matters for recovery.
- Directory `fsync` is required after file creation and rename (§1.4.4 step 6). Precedent: the `ext4` metadata crash behavior that motivated `fsync(dirfd)` as a distinct operation.
- Torn writes are prevented by the `frame_len + frame_bytes + frame_crc` triplet: a partial write leaves `frame_len` indicating a frame that is not actually present, or `frame_crc` failing. Either case is detected on recovery and the partial frame is truncated.

### §1.7 Compaction

Compaction produces a *new* segment. It never edits existing segments. The compaction target is specified by an ADR (Verifier A4 + Release/Security A5 concurrence) and typically covers events older than the retention window.

Compaction procedure:
1. Identify the source segment range to compact.
2. Produce a `snapshot` frame (§1.8) covering the compacted range's end state.
3. Write a new segment containing the snapshot frame + any post-compaction frames.
4. Mark the source segments as `compacted` via the header flags bit (requires rewriting just the header; the bit flip is atomic and does not alter frame content).
5. Archive the source segments per Distribution Spec §5.3 (signed and SBOM'd).

Retention: source segments SHOULD NOT be deleted. They SHOULD be archived. A deployment that deletes source segments loses the ability to audit events from that range; this is operator choice and requires an ADR.

### §1.8 Snapshots

A snapshot is a frame whose payload contains the materialized state of one or more projections at a specific LSN.

```
{
  "v": 1,
  "seq": N,
  "kind": "snapshot",
  "actor": "A5",
  "payload": {
    "as_of_seq": N-1,
    "projections": {
      "<projection_name>": {
        "state_hash": h'...',
        "state_ref": "snapshot-blobs/<projection>-<hash>.cbor"
      }
    },
    "merkle_root_at_seq": h'...'
  },
  "sig": h'...'
}
```

Snapshot blobs are content-addressed files stored alongside the segment. The snapshot frame's payload references them by hash, so snapshot verification is: read the snapshot frame, read the referenced blob, hash the blob, check equality to `state_hash`.

Snapshots are optional. A deployment without snapshots relies on full replay for recovery. A deployment with snapshots can recover in O(snapshot_size + frames_since_snapshot) time instead of O(all frames).

---

## §2 — Capability-Token Protocol

### §2.1 Design axioms

Capability tokens are:

- **Non-forgeable.** Cryptographically signed by the issuer (Release & Security authority A5).
- **Short-lived.** Default TTL `[internal policy]` 5 minutes; maximum 15 minutes. Long-lived capability is a security anti-pattern.
- **Non-transferable.** A token includes the subject (the authority it was issued to). Use by a different subject fails verification.
- **Delegatable with caveats.** A subject MAY issue a derived token to another subject, narrowing (never widening) the scope. This is the Macaroon primitive.
- **Non-persistent.** Tokens live in process memory. They MUST NOT be written to the event log, to disk, or to any channel outside the issuing host.

### §2.2 Token structure (v1 suite)

Version 1 of the token format uses:

- **Signature algorithm:** Ed25519 (RFC 8032). Ed25519 is deterministic, has small signature and key sizes, and fast verification. Precedent: Paseto v4 uses Ed25519 for the same reasons.
- **Caveat chaining MAC:** HMAC-SHA256. Precedent: the original Macaroon paper.

A token is a deterministic-CBOR map:

```
{
  "v": 1,
  "tid": <16-byte random nonce>,
  "iss": <issuer identifier, text>,
  "sub": <subject, text, e.g., "A3">,
  "act": <action, text, e.g., "promote_artifact">,
  "scp": <scope, map with fields like {workflow_id, artifact_ref, ...}>,
  "nbf": <uint64, ns since Unix epoch, not-before>,
  "exp": <uint64, ns since Unix epoch, expiry>,
  "caveats": [<list of caveats, see §2.3>],
  "sig": <64-byte Ed25519 signature>
}
```

`tid` is the token ID. It is logged (when a token is used, the consuming process records `tid` in the frame's payload) but the token itself is not logged. This lets audit reconstruct *which* token authorized an action without the token's confidential material being written to disk.

### §2.3 Caveats

A caveat is a further restriction. The Macaroon paper's peer-reviewed result: caveats let a token holder voluntarily weaken their own token without going back to the issuer, and verification remains O(caveat count). AIOS uses this for safe delegation.

A caveat is a CBOR map:

```
{
  "type": "time" | "scope" | "predicate" | "audience",
  "value": <type-specific>,
  "mac": <32-byte HMAC-SHA256>
}
```

The MAC chain is computed exactly as in §3 of the Macaroon paper: each caveat's MAC is HMAC(prior_MAC, canonical_encoding(caveat_without_mac)). The root MAC is the Ed25519 signature on the base token.

Verification procedure:
1. Verify Ed25519 signature on the base token using the issuer's public key (A5's signing key per §6).
2. Walk the caveat list in order, verifying each caveat's MAC chain.
3. Apply each caveat to the authorization context. A caveat that rejects the context fails the whole token.
4. Check `sub` equals the presenting subject.
5. Check `nbf ≤ now ≤ exp`.
6. Check `act` covers the requested action.
7. Check `scp` covers the requested scope.

Any failure rejects the token.

### §2.4 Wire format

Tokens travel as deterministic CBOR bytes with a single-byte envelope tag:

```
0x01 <uvarint length> <CBOR bytes>
```

The leading byte identifies the token format version. Future versions use `0x02`, etc. A receiver that does not recognize the version MUST reject the token; the system never silently downgrades.

### §2.5 Clock skew tolerance

- `nbf` and `exp` comparisons allow skew of `[internal policy]` ±30 seconds.
- Frames that reference a token MUST carry the verifying host's clock at use-time (`ts` field of the consuming frame).
- Clock skew beyond the tolerance is a D8 external-dependency-failure event (NTP unavailable or host clock drift). The Kernel Spec's recovery rules apply.

### §2.6 Revocation

Short TTL is the primary revocation mechanism. Explicit revocation supplements it:

- A5 maintains a revocation log (`kind: "capability.revoked"`) with the `tid` of any token revoked before its natural expiry.
- Every token verification consults the revocation log for the token's `tid`. Because revocations are rare and the log can be bloom-filtered by `tid` prefix, the check is O(1) amortized.
- A deployment configured for offline operation relies on TTL only; explicit revocation is unavailable without a live path to A5.

### §2.7 Storage rules

- Tokens MUST live only in process memory for the TTL window.
- Tokens MUST NOT be logged, written to stdout/stderr, or included in error messages by trusted code. A leaked token is valid until expiry; this is the reason for short TTL.
- On process exit, any in-flight tokens are discarded. A restarting process requests fresh tokens.

### §2.8 Proof-of-possession (extension)

For environments that support it, A5 MAY issue `dpop`-style proof-of-possession tokens (RFC 9449). In this mode, the token binds to a subject-held key; each use requires a signed proof that the subject possesses the key. This defends against token theft (an interceptor without the key cannot use the stolen token).

Proof-of-possession is optional in v1 of this protocol. Its presence is declared by a caveat of type `pop` with the subject key fingerprint.

---

## §3 — Canonical Serialization

### §3.1 Deterministic CBOR

All event-log frames, all capability tokens, all predicates emitting content-hashed output MUST use deterministic CBOR per RFC 8949 §4.2:

- Integers in shortest possible form (1, 2, 4, or 8 bytes beyond the initial byte).
- Maps with keys sorted by byte-lex of their canonical encoding. Duplicate keys are forbidden.
- Arrays and maps use definite-length encoding. Indefinite-length is forbidden.
- Floating-point values MUST NOT appear in any frame or token that participates in the conservation laws Q1–Q3 (§4 elaborates).
- Byte strings and text strings use the shortest form.

A reader that encounters a non-canonical encoding on an input that requires canonicality MUST reject the input as malformed.

### §3.2 JCS fallback for audit exports

For audit exports, JCS per RFC 8785 is acceptable. JCS and CBOR are not byte-compatible (JCS sorts UTF-16 code units; CBOR sorts bytes of UTF-8). They are structurally compatible: the canonical form of a given logical value round-trips through either encoding without information loss.

Rule: frame hashes are computed over the CBOR form. JCS is a viewing format, not a substrate. An AIOS implementation that tries to compute frame hashes over JCS bytes is non-conforming.

### §3.3 Text rules

- All text is UTF-8.
- All text participating in frame content is NFC-normalized (Unicode Normalization Form C, Unicode Standard Annex #15). NFC is the normalization form used by most modern systems; it composes precomposed characters where possible.
- Case folding uses byte-level case folding for ASCII only. Locale-sensitive case folding is forbidden in AIOS-critical paths.
- String comparison uses byte-wise equality of NFC UTF-8.

### §3.4 Key ordering

CBOR form: byte-lex of the key's canonical encoding. This is RFC 8949 §4.2.1's rule.

### §3.5 Timestamps

- On wire, in CBOR: **unsigned integer nanoseconds since Unix epoch (UTC)**. The CBOR major type is 0 (unsigned int). This avoids timezone ambiguity and has nanosecond precision. The frame field name is `ts_ns` (see §1.2); no alternative integer representation is permitted on wire.
- In JCS exports: RFC 3339 UTC string with nanosecond precision (`2026-04-23T10:00:00.123456789Z`), derived from the integer `ts_ns` at export time. The `Z` suffix is required; `+00:00` is non-canonical. Export strings are views, not substrates: frame hashes are computed over the CBOR form only (§3.2).
- Leap seconds are represented per POSIX: the timestamp does not include leap seconds. This matches the common Unix-epoch interpretation and is what every major system logs already do.

### §3.6 Numeric handling

- Integer values are represented in CBOR as major type 0 (unsigned) or major type 1 (negative). Never as a float.
- Integer widths on wire are determined by value, not by language type. A protocol field documented as `uint64` uses CBOR major type 0 and a value in range [0, 2^64-1].
- Rational quantities are represented as pairs of integers `{n, d}` with `d > 0` and `gcd(n, d) == 1`. Floating-point approximations of rationals are non-canonical.
- When a floating-point value is necessary (e.g., a reported Brier score), it appears in payloads only (never in frame-structural fields) and is serialized in CBOR as IEEE 754 binary64, with the signaling-NaN-forbidden rule from RFC 8949 §4.2.2.

---

## §4 — Cross-Platform Determinism

### §4.1 Determinism classes

Three classes, derived from the gate typing in Constitution Article V:

| Class | Requirement | Applies to |
|---|---|---|
| Bit-identical | Given identical inputs, bit-identical output across every conforming implementation and host | T1 catastrophic predicates (Q1–Q3) |
| Rationally-equivalent | Given identical inputs, equal as rational values; byte representation MAY differ | T1 hazardous predicates (M4), T3 schema checks |
| Bounded-variance | Output variance bounded by a declared statistic; used where probabilistic methods are required | T2 test suites, stochastic calibrated predicates |

The Verification Spec §1.1's `determinism` field names which class applies. The loader enforces it.

### §4.2 Forbidden operations in catastrophic T1 predicates

The following MUST NOT appear in any T1 predicate at catastrophic failure level:

- IEEE 754 floating-point arithmetic (addition, multiplication, etc. whose results depend on rounding mode or libm implementation).
- Transcendental functions (`sin`, `cos`, `exp`, `log`, etc.) from the host libm. These differ across libc implementations and across CPU architectures even at the same nominal precision.
- Locale-sensitive string operations.
- Reliance on system time beyond the frame timestamp.
- Any non-deterministic source (random, thread-scheduling-dependent operations).
- Integer overflow in languages where overflow is undefined behavior (C, C++). Use checked arithmetic or a language with defined overflow semantics.

[Inference] These constraints make the T1 catastrophic predicates implementable in WASM, in the Rust `core` crate without `std::f64`, in pure Python (Python `int` is arbitrary precision and deterministic), and in Java with `strictfp`. This portability is the test: if a predicate cannot be expressed in that constrained subset, it is not a catastrophic T1 predicate.

### §4.3 Integer arithmetic rules

- Integer values MUST have a declared width in the predicate's input schema (`uint64`, `int32`, etc.).
- Arithmetic operations use checked semantics: overflow is an error, not a silent wrap.
- Division is integer division; remainders are explicit.
- Arbitrary-precision integers are permitted in intermediate computation but final outputs fit within declared widths.

### §4.4 String comparison and sorting rules

- String equality: byte-wise equality of NFC UTF-8 (§3.3).
- String ordering: byte-lex of NFC UTF-8 (not Unicode code-point order, not locale-sensitive collation). For ASCII-only strings the three orderings coincide; for strings containing non-ASCII characters, byte-lex is the deterministic one.
- Sorts: any sort used in a catastrophic T1 predicate MUST be stable. Merge sort and Timsort satisfy this; quicksort does not unless explicitly stabilized.

### §4.5 Hash algorithm whitelist

- **SHA-256** is the default content hash. Used for frame hashes, Merkle tree nodes, projection hashes, SBOM references.
- **SHA3-256** is an acceptable alternative but MUST be declared per-predicate; mixed use within one log is forbidden.
- **HMAC-SHA256** for capability-token caveat chaining (§2.3).
- **BLAKE2/BLAKE3** are not used in v1 to minimize the cryptographic surface; a future version MAY add them with explicit migration.

### §4.6 WASM as a reference execution target

A T1 catastrophic predicate SHOULD be specified such that it can be compiled to WebAssembly core (no host-imported functions that would introduce non-determinism). WASM's deterministic execution model is then the cross-platform reference: if the predicate produces result R under a conforming WASM engine, every conforming AIOS implementation must produce R.

This is not a requirement to actually ship WASM in production. It is a specification technique: if the predicate cannot be expressed in WASM-deterministic-subset form, the predicate is under-specified.

---

## §5 — Replay Ordering & Concurrency

### §5.1 Single-writer invariant

At any moment, at most one process holds the active-segment write lock. Enforcement:

- Active segment file carries a POSIX advisory exclusive lock (fcntl F_SETLK) or equivalent Windows file lock.
- A lock file `log.lock` in the log directory contains the PID and start time of the current writer.
- A process that finds an existing lock and determines the holder is dead (PID gone, lock file older than threshold) MAY recover the lock after verifying the active segment's last-frame hash and any torn tail.

### §5.2 LSN (Log Sequence Number)

- LSN (the `seq` field) is a uint64 strictly monotonic across the entire log.
- LSN 0 is the genesis frame; its `prev` field is 32 zero bytes.
- LSN advances by exactly 1 per frame. A gap in LSN is a corruption signal.
- LSN is the canonical order. Wall-clock timestamps (`ts`) are advisory. Reasoning about event order uses LSN, not `ts`, because `ts` is subject to clock skew.

### §5.3 Reader semantics

- Readers open segment files read-only, with no lock.
- A reader observes a consistent prefix: the reader sees frames up to some LSN N with N ≤ the current appender's acknowledged LSN. The reader never sees a partial frame; the frame length prefix and CRC filter torn tails.
- A reader that needs the latest state polls the active segment's size or subscribes to a host-provided change notification (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows).
- A reader computing a projection MUST read frames in strict LSN order.

### §5.4 Multi-process coordination

- Writers coordinate via the lock file. Contention is resolved by queueing or erroring, not by racing.
- Readers do not coordinate; multiple readers are always safe.
- Reader-writer conflicts do not exist because writers append; they never modify prior bytes.

### §5.5 Cross-segment ordering

- Each segment's header carries `first_seq`. The sequence of segments partitions the log by LSN ranges without gaps.
- Replay across segments is: segment by LSN-range, then frames by LSN within segment. Both are strictly monotonic.

### §5.6 Replay procedure

```
initialize state from snapshot-at-LSN-K (if any; otherwise genesis state, K = -1)
for each frame F in segments covering LSN K+1 through target_LSN, in LSN order:
    verify F.prev == hash_of_frame_at(F.seq - 1)
    verify F.crc (per §1.4.3)
    verify F.sig if present (per §2)
    apply F to state
    record hash_of_frame_at(F.seq) for the next iteration's verification
verify hash_of_frame_at(target_LSN) == expected_hash   # e.g., stored projection hash
return state
```

Any verification failure aborts replay. The abort is a Q2 breach (Constitution §1.2).

### §5.7 Partial-replay safety

A replay may be interrupted (process crash, operator cancel). No state is persisted mid-replay. The next replay attempt starts from the last verified snapshot and proceeds as above. The event log is unaffected.

### §5.8 Ordering notes [Inference]

AIOS's single-writer + LSN model is the simplest correct design. It does not scale to geo-distributed append. A deployment that requires geo-distributed append adds a consensus layer (Raft, multi-Paxos) above the log; the consensus layer produces an ordered stream of commands that the single writer consumes and appends locally. That consensus layer is out of scope for this spec; the single-writer invariant on each log remains.

---

## §6 — First-Install Bootstrap Trust

### §6.1 The problem

A brand-new host with no prior AIOS state downloads the first AIOS package. It must verify the package is genuine. The root-of-trust public key it verifies against is itself data; how is that key trusted?

Codex's third review named this the "first-install trust ceremony" and said v6's single-channel fingerprint description was insufficient.

### §6.2 TUF roles

AIOS uses TUF (The Update Framework) for signing infrastructure. Per the peer-reviewed TUF paper:

- **Root role.** Holds the root public keys. Signed by a threshold (e.g., 3 of 5) of offline-held keys. Compromising the root requires compromising the threshold.
- **Targets role.** Signs the concrete package artifacts (tarballs, hashes). Lives online for day-to-day signing.
- **Snapshot role.** Signs the current set of targets to prevent mix-and-match and rollback attacks.
- **Timestamp role.** Freshness attestation; prevents freeze attacks by asserting the current snapshot is recent.

Role separation means: a compromised online signing key (Targets or Timestamp) is a recoverable incident; the offline Root keys sign a new Targets key.

### §6.3 Bootstrap anchor

The bootstrap anchor is the root role's public keys. A brand-new host must acquire them through an out-of-band channel that is independent of the AIOS package itself.

#### §6.3.1 Multi-channel publication

The bootstrap anchor MUST be published on at least three independent channels:

1. The project's primary website, under HTTPS with a CA-issued certificate (TLS trust).
2. The project's git repository, in a file signed by the root-role keys' own fingerprints (circular but useful: a reader who has any prior version of the repo can verify continuity).
3. A public transparency log entry (Sigstore Rekor or equivalent).
4. (Optional fourth) A printed fingerprint in published conference proceedings or a physical book.

Each channel lists the same fingerprint (SHA-256 of the TUF root metadata). A new host verifies by comparing the fingerprint from 2+ channels and refusing the install if any disagree.

#### §6.3.2 First-install ceremony

The operator on a new host performs:

1. Download the AIOS bootstrap package (signed by Targets role).
2. Fetch the root role metadata from the distribution channel.
3. Fetch the root role fingerprint from the project website AND from a second independent channel (git, Rekor, or printed source).
4. Verify the fingerprints match each other.
5. Verify the root metadata matches the fingerprint.
6. Verify the bootstrap package's signature chains to the root.
7. Install.

The ceremony is documented and MAY be automated once the root fingerprint is known. The first-time verification is unavoidably a human act because the host has no prior state against which to verify.

Precedent: Qubes OS, Tails, and Tor Browser publish their signing keys on multiple independent channels and explicitly document the verification ceremony. The practice is standard in hostile-environment secure bootstrap.

### §6.4 Key rotation

Root key rotation:
1. The existing root role signs a new root metadata document that lists the new root keys alongside the old ones.
2. The new root metadata is published on all channels.
3. After a transition period, a subsequent rotation drops the old keys.
4. Existing hosts follow the chain; new hosts bootstrap against the latest metadata.

Targets key rotation is unilateral: the root role signs a new targets key. This is the common case and is how routine security response works.

### §6.5 Recovery after compromise

- **Targets key compromised:** Root signs a new Targets key; all prior targets-signed metadata older than the rotation is invalidated; affected packages are re-signed and re-published. No end-host action is required beyond a normal update cycle.
- **Snapshot or Timestamp key compromised:** Rotate that role's key at the root level; clients detect the change via the chain.
- **Root key compromised below threshold:** Irrecoverable without human action. Each end-host must verify a new root fingerprint via the multi-channel ceremony (§6.3.2). This is the worst case and the reason for the threshold.
- **Root key compromised at or above threshold:** Cryptographic catastrophe. The project issues a new root via an announcement channel that predates the compromise; end-hosts must cold-restart trust.

The TUF paper's peer-reviewed result is that role separation and threshold signatures make all but the last case recoverable without manual end-host intervention. AIOS inherits this property.

---

## §7 — Performance Budgets

### §7.1 Methodology

Performance budgets are SLO-style ceilings, not guarantees. Each budget is:

- **Expressed as a percentile + threshold + window** (e.g., p99 ≤ 50ms over 1-hour windows), following standard SRE practice.
- **Measured by the audit protocol** (Verification Spec §4.2) on a declared corpus.
- **Tuned under the audit protocol** with explicit ADRs for threshold changes.
- **An input to Kernel Spec §3.2 (workflow-failure D2)** when exceeded persistently.

All numbers below are `[internal policy]` initial values. They set starting points and tuning targets; they are not ground truth.

### §7.2 Event-log growth

| Metric | Target | Rationale |
|---|---|---|
| Frames per run (local impact) | p99 ≤ 50 | One run produces intentions, validations, effects; ~10 for simple, ~50 for complex |
| Frames per run (subsystem impact) | p99 ≤ 200 | More gates, more Merkle batch frames |
| Frames per run (system-wide impact) | p99 ≤ 500 | Full three-lane verification contributes frames |
| Bytes per frame | p99 ≤ 4 KiB | Canonical CBOR is compact; payloads beyond this belong in content-addressed blobs referenced by hash |
| Segment size | 64 MiB default | Rotation target; balances file-handle count against replay latency |
| Daily log growth (per 1000 runs/day) | p99 ≤ 2 GiB/day | At 200 avg frames × 1 KiB avg / 1000 runs |

Hosts with retention windows >90 days MUST provision storage accordingly or configure compaction.

### §7.3 Projection rebuild

Rebuild time matters because a D4 (projection corruption) event requires reconstructing the projection from the event log.

| Metric | Target |
|---|---|
| Hot projection rebuild (last 7 days of events) | p95 ≤ 30 seconds |
| Warm projection rebuild (last 90 days) | p95 ≤ 5 minutes |
| Cold projection rebuild (all history from snapshot) | p95 ≤ 30 minutes |

Deployments that exceed these require either snapshots (§1.8) or a wider retention-compaction policy.

### §7.4 Calibration run cost

| Metric | Target |
|---|---|
| Weekly validation run for one skill (corpus size 300–1000) | p95 ≤ 5 minutes wall-clock |
| Monthly validation run for one skill (corpus size 1000–3000) | p95 ≤ 30 minutes |
| Full recalibration after drift detection | p95 ≤ 1 hour |

Exceeding these triggers a G-class governance-failure event (G5 if due to provenance overload, G6 if due to stale contracts).

### §7.5 Gate latency

Per the gate-type taxonomy in Constitution Article V:

| Gate type | Target p99 (local impact) | Target p99 (subsystem) | Target p99 (system-wide) |
|---|---|---|---|
| T1 deterministic predicate | ≤ 100 ms | ≤ 500 ms | ≤ 2 seconds |
| T2 test suite | ≤ 2 minutes | ≤ 10 minutes | ≤ 30 minutes |
| T3 schema check | ≤ 50 ms | ≤ 100 ms | ≤ 250 ms |
| T4 human hold | N/A (time-limited by approver SLA) | | |

T1 predicates exceeding their budget are a strong signal that they have crept into per-frame processing when they should be per-run or per-segment. Review and optimization take precedence over threshold relaxation.

### §7.6 Debate latency

Multi-skill concurrence (formerly SK-DEBATE-N3) is expensive. Budget:

| Metric | Target |
|---|---|
| Three-skill concurrence evaluation | p95 ≤ 90 seconds |
| Full debate with disagreement resolution | p95 ≤ 5 minutes |

Debate invocation rate is itself a dashboard metric (Verification Spec §4). Rate > `[internal policy]` 10% of runs is a signal that the debate trigger is mis-calibrated, not that the debate is too slow.

### §7.7 Upgrade window

Upgrades require a read-only window during which appending halts. Budget:

| Metric | Target |
|---|---|
| Minor version upgrade read-only window | p95 ≤ 60 seconds |
| Major version upgrade read-only window | p95 ≤ 10 minutes |
| Cross-major migration read-only window | p95 ≤ 1 hour; documented in the migration guide |

Upgrades that exceed these budgets SHOULD be staged over multiple shorter windows using the snapshot mechanism (§1.8) to reduce replay scope.

### §7.8 What is not budgeted

- Creative work (drafting prose, producing ADRs): bounded by authority time, not spec.
- External model latency: bounded by the external provider; tracked for D8 escalation but not owned by AIOS.
- Human-hold response time: bounded by operator SLA, not AIOS.

These exclusions are not loopholes; they are honest acknowledgments that AIOS cannot control what is not inside AIOS. [Inference] A deployment can, however, track them as first-class operational metrics even though the spec does not fix them.

---

## §8 — What this spec does NOT contain

- Soundness laws and authorities → **Constitution Articles I, III**
- Trust zones and state machines → **Kernel Spec §§1–2**
- Failure-domain model → **Kernel Spec §3**
- Kill switches, degraded modes → **Kernel Spec §§5–6**
- Package namespace, semver, install/upgrade/rollback/uninstall mechanics → **Distribution Spec §§1–4**
- Signed-release infrastructure (Sigstore, SBOM, transparency log) → **Distribution Spec §5**
- Gate predicate registry → **Verification Spec §1**
- Calibration protocol → **Verification Spec §2**
- Credential protocol → **Verification Spec §3**
- Audit protocol and G1–G7 taxonomy → **Verification Spec §4**

### §8.1 Reference-implementation coverage

The `event_log.py` module is **normative** for the clauses below and **illustrative** for the rest. A conforming production implementation in any language MUST pass `test_event_log.py` for the normative clauses; it MUST independently implement the illustrative ones.

**Normatively covered by `event_log.py`:**

| Clause | Section | Evidence |
|---|---|---|
| Deterministic CBOR for the AIOS subset | §3.1, §3.4 | 40-line encoder; `test_cbor_is_deterministic_across_dict_orderings`, `test_cbor_shortest_integer_form` |
| Frame structure (8-field CBOR map; `ts_ns` integer, not `ts` text) | §1.2 | `Frame` dataclass; `to_cbor()` and `frame_hash()` |
| Frame hash-chain linkage via `prev` | §1.2, §5.6 | `test_prev_hash_chain_unbroken`, `test_tampered_frame_detected` |
| Segment header format (96 bytes: magic, version, flags, first_seq, last_seq, created_ts, prev_hash, hdr_hash) | §1.4.2 | `_pack_header`, `_unpack_header` |
| Segment trailer format (84 bytes) | §1.4.5 | `_rotate` writes trailer; replay verifies |
| On-disk frame framing: length prefix + CBOR + CRC-32C | §1.4.3 | `_encode_on_disk`, `_read_on_disk`; `test_crc_corruption_detected`, `test_truncated_frame_detected` |
| Segment rotation with atomic rename + directory fsync | §1.4.4 | `_rotate`; `test_round_trip_across_rotation` |
| LSN strict monotonicity across segments | §5.2, §5.5 | `test_lsn_is_strictly_monotonic`, `test_seq_gap_rejected` |
| Replay procedure with prev-chain and seq verification | §5.6 | `replay()`; `test_round_trip_single_segment`, `test_round_trip_across_rotation` |

**NOT covered by `event_log.py` (MUST be added by a production implementation):**

| Clause | Section | Why deferred |
|---|---|---|
| Advisory file lock for single-writer enforcement | §5.1 | stdlib portability across POSIX/Windows; production must use `fcntl.F_SETLK` on POSIX, `LockFileEx` on Windows |
| Merkle batch frames (every N frames, at segment close) | §1.5 | Optional per the v1 conformance profile; required only for P-HighAssurance (see §10) |
| Ed25519 signature generation and verification on frames | §1.2 `sig`, §2 | Requires `cryptography` library or equivalent; not stdlib-only |
| Capability token issuance, verification, caveat chain walking | §2 | Requires Ed25519 + HMAC-SHA256 libraries |
| Snapshot production and verification | §1.8 | Optional; deployments without snapshots rely on full replay |
| Compaction procedure | §1.7 | Operator-initiated; deferred until retention requirements force it |
| Capability revocation log consultation | §2.6 | Requires live A5 path or cached revocation list |
| Full CBOR decoder (all major types, tagged values, floating-point) | §3.1 | The reference decoder handles the frame/token subset only |
| Clock skew handling for token verification | §2.5 | Requires integration with NTP or equivalent time source |
| TUF client (metadata fetch, verification, rotation) | §6 | Use the official TUF client implementation; do not re-implement |
| Bootstrap anchor multi-channel verification | §6.3 | Operator procedure, not runtime code |
| Sigstore/Rekor transparency log client | §1.5, Distribution Spec §5.4 | Optional per §10; deferred to v2 for non-HighAssurance profiles |

**Consequence.** A language-port of AIOS that passes `test_event_log.py` has demonstrated substrate-level conformance. It has **not** demonstrated full runtime conformance; that requires implementing the second table and passing a production test suite the reference does not yet contain. The v7 README's claim that the system is "implementable from first principles with stdlib-only Python in under 600 LOC" refers to the normative substrate only — not to the full runtime.

---

## §9 — Cryptographic Surface Policy for v1

Codex's review flagged the v1 cryptographic surface as too broad for a first deployment. This section is the interrogation: for each piece, is it indispensable **now** or deferrable to v2?

### §9.1 v1 core (indispensable)

These MUST be present in every conforming v1 deployment.

| Mechanism | Why indispensable for v1 |
|---|---|
| Deterministic CBOR (§3.1) | Without a canonical wire form, frame hashes are not reproducible and Q2 cannot be verified across implementations. The entire soundness story rests on this. |
| SHA-256 content hashing (§4.5) | The hash chain is the Q2 mechanism. Nothing below it is safe without it. |
| CRC-32C per frame (§1.4.3) | Distinguishes corruption from tampering. Cheap to compute; expensive to omit. |
| Ed25519 signatures on capability tokens (§2.2) | Non-forgeability is the definition of a capability. A token without a signature is not a capability; it is a hint. |
| HMAC-SHA256 for Macaroon caveat chain (§2.3) | Caveats must chain unforgeably. Without the MAC chain, a holder could forge caveats that look authorized. This is the peer-reviewed Macaroon result. |
| TUF role separation for signing (§6.2) | Without role separation, a compromised online key compromises the whole system. The recoverable-compromise property requires TUF. |
| Multi-channel bootstrap anchor publication (§6.3.1) | The one place where a brand-new host must anchor trust without prior state. Any single channel is defeatable by an adversary who controls it. |

### §9.2 v1 strongly recommended (SHOULD)

Present in every deployment except explicit exemption.

| Mechanism | Condition |
|---|---|
| JCS for audit exports (§3.2) | Required whenever audit reports cross system boundaries; omit only if all audit consumption is within a single host that reads CBOR directly. |
| Frame signatures on Z3→Z4 promotion (§1.2 `sig`) | Required for subsystem- and system-wide-impact promotions; optional for local-impact single-author runs. |

### §9.3 v1 deferred to v2 (MAY but SHOULD NOT)

These are useful and documented here so the protocol has room to grow, but a v1 deployment is not required to implement them. A v1 that adds them early inherits their complexity.

| Mechanism | Reason for deferral |
|---|---|
| External Sigstore/Rekor transparency log integration | TUF signatures already cover release verification; external transparency is an add-on for cross-organization auditability. Required only in the P-HighAssurance profile (§10). |
| Merkle batch overlay (§1.5) | The frame hash chain already provides local tamper evidence. Merkle batches enable external third-party verification without reading the full log; this matters for external auditors but not for an internal team. Required only in P-HighAssurance. |
| DPoP-style proof-of-possession on capability tokens (§2.8) | Short TTL (5-15 min) plus non-transferability already defeats most token-theft scenarios. DPoP adds robustness against in-process interception; required only in P-HighAssurance. |
| Hardware-root-of-trust attestation (TPM/TEE) | Useful for bootstrap in adversarial environments; out of v1 scope. |
| Geo-distributed append via external consensus (§5.8) | Single-writer per log is correct; multi-site deployment uses a consensus layer above the log. Out of v1 scope. |

### §9.4 The interrogation rule

If a v2 feature creeps into v1, the proposer MUST demonstrate in writing:

1. A specific incident class that v1 cannot contain without the feature, and
2. That the feature is implementable within the cryptographic-library constraints of the target conformance profile (§10), and
3. An explicit migration for existing v1 deployments.

Without all three, the feature stays in v2. This is the anti-maximalism rule.

---

## §10 — Conformance Profiles

A conforming AIOS deployment declares one profile. The profile determines which clauses are required, recommended, or out-of-scope. Profiles exist so that a sovereign-air-gapped deployment does not pretend to satisfy clauses that assume external network connectivity, and so that a single-developer local install does not carry costs that only a production organization needs.

### §10.1 P-Local — minimal local profile

**Target.** A developer's laptop running AIOS against a single project. One writer, possibly no human operator other than the developer.

**Required (MUST):**
- Constitution Articles I–VII in full (soundness is not negotiable).
- Runtime Protocol §1 (event log), §3 (canonical serialization), §4 (cross-platform determinism), §5 (replay ordering) as covered by `event_log.py`.
- Runtime Protocol §9.1 cryptographic core.
- Kernel Spec §§1–3 (trust zones, state machines, failure domains).
- Verification Spec §1 (gate registry) and §2 (calibration, or explicit declaration of no-calibration with a ceiling on what confidence-emitting skills may do).
- Distribution Spec §1 (package identity) and §4.1 (install contract).

**Optional (MAY omit):**
- Signed-release infrastructure via Sigstore (§1.5 Merkle, Distribution §5.4 Rekor) — developer builds can be self-signed.
- Credentialing (Verification §3) — Phase 0 never completes, credentials accumulate data but never enforce.
- Multi-agent debate — local deployments typically run with one author and one verifier.
- SBOM production — required for published releases, not for local work.

**Rationale.** Local deployments prioritize iteration speed. Soundness (Q1–Q3) is still enforced because those are constitutional; governance overhead (credentialing, debate) is not.

### §10.2 P-Enterprise — standard organizational profile

**Target.** A team deploying AIOS across multiple developers and projects within one organization. External network access available; signed releases required; audits performed.

**Required (MUST):**
- Everything required by P-Local.
- Distribution Spec §§2–5 in full (semver, supported runtimes, install/upgrade/rollback/uninstall, signed releases, SBOM, transparency log — but see §10.4 for the transparency-log exception).
- Verification Spec §§2–4 (calibration, credentialing Phase 0 and Phase 1, audit).
- Runtime Protocol §9.2 (JCS audit exports, frame signatures on subsystem+ promotions).
- TUF root-role setup per §6.2.

**Optional (MAY omit):**
- Merkle batch frames (§1.5) — the hash chain is sufficient for internal audit.
- DPoP on tokens (§2.8) — short TTL is sufficient in a trusted internal network.
- Air-gapped mode (Distribution §3.4) — assumes connectivity.

**Rationale.** Enterprise deployments have resources for proper governance (credentialing, audit) but do not need the cross-organization verification story of external transparency logs. They SHOULD use external transparency if they publish software to third parties; they MAY omit it for internal-only tools.

### §10.3 P-Airgap — sovereign air-gapped profile

**Target.** A deployment with no outbound network connectivity: offline labs, classified environments, regulated industries with strict data-egress policies.

**Required (MUST):**
- Everything required by P-Local.
- Distribution Spec §3.4 (air-gapped mode) in full.
- Distribution Spec §6.2 (air-gapped mode operational rules): no outbound calls from Z0/Z1, signature verification against locally-present transparency log segments, pre-shipped calibration corpora, local model endpoint only.
- TUF bootstrap (§6.2) with offline-held root keys and signed-bundle-only updates.
- Distribution Spec §6.1 zero telemetry (already the default; explicit in this profile).

**Forbidden (MUST NOT):**
- Outbound network calls from Z0 or Z1.
- Automatic Sigstore/Rekor log submission.
- Cloud-hosted calibration corpora.
- Any telemetry channel to an external destination.

**Optional (MAY omit):**
- External transparency log (§1.5 Merkle) — it cannot be published from an airgapped network.
- Rekor integration (Distribution §5.4) — same reason.
- DPoP — short TTL is sufficient in controlled physical environments.

**Rationale.** P-Airgap is not a reduced profile; it is a different threat model. External transparency is replaced by physical-handoff of signed release bundles, and bootstrap verification is performed by operators consulting printed fingerprints and physically-delivered media.

### §10.4 P-HighAssurance — full-stack verified profile

**Target.** Deployments that must survive adversarial review, third-party audit, or regulatory scrutiny. Publishing software to untrusted consumers; regulated industries under continuous attestation.

**Required (MUST):**
- Everything required by P-Enterprise.
- Runtime Protocol §1.5 Merkle batch frames.
- Distribution Spec §5.4 external transparency log publication (Sigstore Rekor or equivalent).
- Runtime Protocol §2.8 DPoP on all capability tokens.
- Reproducible builds (Distribution §5.2) with published diverse-builder attestations.
- Hardware-root-of-trust hooks where available (TPM/TEE attestation for bootstrap).
- Frame signatures on every Z3→Z4 promotion regardless of impact level.
- Credentialing Phase 1 active with all audit protocol cadences at their stated intervals.

**Rationale.** This is the profile that has to survive a hostile review by an independent standards body. Every optional mechanism from §9.3 is on. The cost is real; the benefit is external verifiability.

### §10.5 Profile declaration

A conforming deployment MUST declare its profile in its root AIOS configuration. The declaration is an event (`kind: "profile.declared"`, written once at install). Profile changes require an ADR and emit a `profile.changed` event.

### §10.6 Profile enforcement

Each profile's required-clause set is a loader check: at system start, the loader verifies each required mechanism is present and functional. A deployment that declares P-HighAssurance but lacks Merkle batch frames fails at loader time. This is the ANti-"checkbox compliance" rule: profiles are not flags; they are enforceable constraints.

---

## §11 — Future Work (non-normative)

- **TLA+ specification of §5 ordering and concurrency rules.** The single-writer / multi-reader / LSN model is amenable to formal specification. [Inference] A TLA+ model would make the invariants checkable by model checking, not just by inspection.
- **BLAKE3 migration.** The hash-algorithm whitelist in §4.5 is deliberately conservative. A future version MAY add BLAKE3 for performance-critical paths with explicit migration tooling.
- **Geo-distributed append.** §5.8's consensus-layer extension. Out of scope for v1.
- **Full v2 cryptographic surface.** The mechanisms deferred in §9.3 become required in whatever profile succeeds P-HighAssurance (a putative P-Regulated or equivalent). v2 of this protocol makes them first-class.

---

*End of Runtime Protocol Spec.*
