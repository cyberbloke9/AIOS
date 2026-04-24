---
id: ADR-0002
status: Accepted
date: 2026-04-01
---
# ADR-0002 — Event log is append-only

## Context

Audit investigations require reconstructing who did what and when. A mutable
event log breaks replay hashing and therefore Q2 state traceability.

## Decision

Establish INV-003: The event log is append-only. Compaction produces a new
segment; it does not edit existing segments.

## Consequences

Any future feature that wants to "clean up" old events must do so via a new
segment with a snapshot frame, per Runtime Protocol §1.7, not by editing.
