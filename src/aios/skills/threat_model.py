"""SK-THREAT-MODEL — STRIDE-style pattern detector (sprint 69).

Distribution Spec §1.1 names threat-model as a baseline skill.
This implementation is deterministic — pattern rules over a system
description (components + data flows), no model call.

STRIDE categories checked:

  S   Spoofing identity
  T   Tampering with data
  R   Repudiation
  I   Information disclosure
  D   Denial of service
  E   Elevation of privilege

Input schema (simplified model — sufficient for code-review hygiene;
a real threat model needs a data-flow diagram review by a human):

  {
    "components": [
      {"name": str,
       "type": "service"|"datastore"|"external"|"browser",
       "handles_pii": bool,
       "exposed": bool,       # reachable from the untrusted side
       "authenticates_clients": bool,
       "audit_logged": bool,
       "rate_limited": bool,
       "validates_privilege": bool},
      ...
    ],
    "data_flows": [
      {"from": str, "to": str,
       "authenticated": bool,
       "encrypted": bool,
       "crosses_trust_boundary": bool,
       "carries_pii": bool},
      ...
    ]
  }

Output: {threats: [{category, subject, description, mitigation_hint}],
         count, categories_fired}
"""
from __future__ import annotations

from aios.skills.base import SkillContract, default_skill_registry

SKILL_ID = "SK-THREAT-MODEL"


_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "type": {"enum": ["service", "datastore", "external", "browser"]},
                    "handles_pii": {"type": "boolean"},
                    "exposed": {"type": "boolean"},
                    "authenticates_clients": {"type": "boolean"},
                    "audit_logged": {"type": "boolean"},
                    "rate_limited": {"type": "boolean"},
                    "validates_privilege": {"type": "boolean"},
                },
                "required": ["name", "type"],
            },
        },
        "data_flows": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "authenticated": {"type": "boolean"},
                    "encrypted": {"type": "boolean"},
                    "crosses_trust_boundary": {"type": "boolean"},
                    "carries_pii": {"type": "boolean"},
                },
                "required": ["from", "to"],
            },
        },
    },
    "required": ["components", "data_flows"],
    "additionalProperties": False,
}


_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "count": {"type": "integer", "minimum": 0},
        "categories_fired": {
            "type": "array",
            "items": {"enum": ["S", "T", "R", "I", "D", "E"]},
        },
        "threats": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"enum": ["S", "T", "R", "I", "D", "E"]},
                    "subject": {"type": "string"},
                    "description": {"type": "string"},
                    "mitigation_hint": {"type": "string"},
                },
                "required": ["category", "subject", "description",
                              "mitigation_hint"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["count", "categories_fired", "threats"],
    "additionalProperties": False,
}


def sk_threat_model(inputs: dict) -> dict:
    components = inputs.get("components", [])
    flows = inputs.get("data_flows", [])
    threats: list[dict] = []

    # Per-component rules
    for comp in components:
        name = comp["name"]
        typ = comp["type"]

        # S — exposed + unauthenticated
        if comp.get("exposed") and not comp.get("authenticates_clients", False):
            threats.append({
                "category": "S", "subject": name,
                "description": (
                    f"Exposed {typ} {name!r} does not authenticate its "
                    f"clients; spoofing trivial."
                ),
                "mitigation_hint": (
                    "require mTLS or a cryptographic token on every "
                    "inbound request"
                ),
            })

        # R — not audit-logged (services especially)
        if typ == "service" and not comp.get("audit_logged", False):
            threats.append({
                "category": "R", "subject": name,
                "description": (
                    f"Service {name!r} is not audit-logged; actions "
                    f"cannot be attributed after the fact."
                ),
                "mitigation_hint": (
                    "emit structured access logs with actor identity "
                    "to the AIOS event log or equivalent tamper-evident sink"
                ),
            })

        # D — exposed service without rate limiting
        if comp.get("exposed") and typ == "service" \
                and not comp.get("rate_limited", False):
            threats.append({
                "category": "D", "subject": name,
                "description": (
                    f"Exposed service {name!r} has no rate limiting; "
                    f"one adversary can exhaust capacity."
                ),
                "mitigation_hint": (
                    "add per-principal token-bucket at the ingress "
                    "and global quota enforcement upstream"
                ),
            })

        # E — privileged operations without validation
        if typ == "service" and not comp.get("validates_privilege", False):
            threats.append({
                "category": "E", "subject": name,
                "description": (
                    f"Service {name!r} does not validate the caller's "
                    f"privilege on each operation; escalation possible."
                ),
                "mitigation_hint": (
                    "enforce per-request authorization against a "
                    "capability token; reject on ambient-authority use"
                ),
            })

        # I — datastore with PII exposed
        if typ == "datastore" and comp.get("handles_pii") and comp.get("exposed"):
            threats.append({
                "category": "I", "subject": name,
                "description": (
                    f"Datastore {name!r} holds PII and is exposed; "
                    f"a direct-read attack leaks PII."
                ),
                "mitigation_hint": (
                    "place the datastore behind a service boundary; "
                    "never expose primary PII stores directly"
                ),
            })

    # Per-flow rules
    for flow in flows:
        edge = f"{flow['from']} -> {flow['to']}"

        # I + T — unencrypted cross-boundary
        if flow.get("crosses_trust_boundary") and not flow.get("encrypted", False):
            threats.append({
                "category": "I", "subject": edge,
                "description": (
                    f"Flow {edge} crosses a trust boundary without "
                    f"encryption; eavesdropping exposes payload."
                ),
                "mitigation_hint": (
                    "use TLS 1.3 or equivalent channel encryption on "
                    "every trust-boundary crossing"
                ),
            })
            threats.append({
                "category": "T", "subject": edge,
                "description": (
                    f"Flow {edge} crosses a trust boundary without "
                    f"encryption; a MITM can tamper in transit."
                ),
                "mitigation_hint": (
                    "pair TLS with message authentication (HMAC or "
                    "signed envelope) so integrity survives even if "
                    "channel auth is stripped"
                ),
            })

        # I — PII in an unencrypted flow, regardless of boundary
        if flow.get("carries_pii") and not flow.get("encrypted", False):
            threats.append({
                "category": "I", "subject": edge,
                "description": (
                    f"Flow {edge} carries PII without encryption."
                ),
                "mitigation_hint": (
                    "encrypt in transit AND redact PII from logs / "
                    "traces along the path"
                ),
            })

        # S — authenticated flows missing their claim
        if flow.get("crosses_trust_boundary") and \
                not flow.get("authenticated", False):
            threats.append({
                "category": "S", "subject": edge,
                "description": (
                    f"Flow {edge} crosses a trust boundary unauthenticated; "
                    f"source can be spoofed."
                ),
                "mitigation_hint": (
                    "require a capability token or mutual auth on the "
                    "receiving side; drop unauthenticated traffic"
                ),
            })

    categories = sorted({t["category"] for t in threats})
    return {
        "count": len(threats),
        "categories_fired": categories,
        "threats": threats,
    }


_CONTRACT = SkillContract(
    id=SKILL_ID,
    version="1.0.0",
    owner_authority="A4",
    description="STRIDE-style pattern detector over a system description. "
                "Deterministic; returns plausible threats + mitigation "
                "hints per component and data flow.",
    input_schema=_INPUT_SCHEMA,
    output_schema=_OUTPUT_SCHEMA,
    implementation=sk_threat_model,
)


default_skill_registry.register(_CONTRACT)
