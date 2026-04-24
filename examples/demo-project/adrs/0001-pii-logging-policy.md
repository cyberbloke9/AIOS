---
id: ADR-0001
status: Accepted
date: 2026-03-15
---
# ADR-0001 — PII logging policy

## Context

The service logs request and response bodies for debugging. Regulatory review
flagged that request bodies sometimes contain user email addresses and other
PII, which end up in our log aggregator with a 90-day retention window.

## Decision

Introduce INV-002: PII fields are never written to logs. Applied at the HTTP
middleware layer via an allow-list of loggable field names. Any new field
must explicitly opt in.

## Consequences

- Debug velocity takes a small hit; engineers must log IDs and look up records
  via tooling rather than inspecting full payloads.
- Legal risk from ambient PII-in-logs is eliminated at the source.
