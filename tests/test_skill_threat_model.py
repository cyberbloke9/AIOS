"""Tests for SK-THREAT-MODEL (sprint 69)."""
from __future__ import annotations

import pytest

from aios.skills import default_skill_registry
from aios.skills.threat_model import SKILL_ID, sk_threat_model


def test_skill_registered():
    assert default_skill_registry.has(SKILL_ID)
    c = default_skill_registry.get(SKILL_ID)
    assert c.owner_authority == "A4"


def test_clean_system_has_no_threats():
    """All components authenticated, logged, rate-limited; all flows
    encrypted + authed."""
    result = sk_threat_model({
        "components": [{
            "name": "api", "type": "service",
            "exposed": True, "authenticates_clients": True,
            "audit_logged": True, "rate_limited": True,
            "validates_privilege": True,
        }],
        "data_flows": [{
            "from": "client", "to": "api",
            "authenticated": True, "encrypted": True,
            "crosses_trust_boundary": True,
        }],
    })
    assert result["count"] == 0
    assert result["threats"] == []
    assert result["categories_fired"] == []


def test_spoofing_on_unauthenticated_exposed_component():
    result = sk_threat_model({
        "components": [{
            "name": "api", "type": "service",
            "exposed": True, "authenticates_clients": False,
            "audit_logged": True, "rate_limited": True,
            "validates_privilege": True,
        }],
        "data_flows": [],
    })
    assert "S" in result["categories_fired"]
    s_threats = [t for t in result["threats"] if t["category"] == "S"]
    assert any(t["subject"] == "api" for t in s_threats)


def test_repudiation_for_service_without_audit_log():
    result = sk_threat_model({
        "components": [{
            "name": "payments", "type": "service",
            "audit_logged": False, "authenticates_clients": True,
            "rate_limited": True, "validates_privilege": True,
        }],
        "data_flows": [],
    })
    r_threats = [t for t in result["threats"] if t["category"] == "R"]
    assert any(t["subject"] == "payments" for t in r_threats)


def test_denial_of_service_on_exposed_unrated_service():
    result = sk_threat_model({
        "components": [{
            "name": "api", "type": "service",
            "exposed": True, "authenticates_clients": True,
            "audit_logged": True, "rate_limited": False,
            "validates_privilege": True,
        }],
        "data_flows": [],
    })
    d_threats = [t for t in result["threats"] if t["category"] == "D"]
    assert any(t["subject"] == "api" for t in d_threats)


def test_elevation_on_service_without_privilege_check():
    result = sk_threat_model({
        "components": [{
            "name": "admin", "type": "service",
            "audit_logged": True, "rate_limited": True,
            "authenticates_clients": True,
            "validates_privilege": False,
        }],
        "data_flows": [],
    })
    e_threats = [t for t in result["threats"] if t["category"] == "E"]
    assert any(t["subject"] == "admin" for t in e_threats)


def test_information_disclosure_on_exposed_pii_datastore():
    result = sk_threat_model({
        "components": [{
            "name": "user_db", "type": "datastore",
            "handles_pii": True, "exposed": True,
        }],
        "data_flows": [],
    })
    i_threats = [t for t in result["threats"] if t["category"] == "I"]
    assert any(t["subject"] == "user_db" for t in i_threats)


def test_unencrypted_boundary_flow_fires_info_disclosure_and_tampering():
    result = sk_threat_model({
        "components": [],
        "data_flows": [{
            "from": "client", "to": "api",
            "authenticated": True, "encrypted": False,
            "crosses_trust_boundary": True,
        }],
    })
    cats = set(result["categories_fired"])
    assert "I" in cats
    assert "T" in cats


def test_pii_in_unencrypted_flow_fires_info_disclosure_even_within_boundary():
    result = sk_threat_model({
        "components": [],
        "data_flows": [{
            "from": "svc-a", "to": "svc-b",
            "authenticated": True, "encrypted": False,
            "crosses_trust_boundary": False,
            "carries_pii": True,
        }],
    })
    assert "I" in result["categories_fired"]


def test_unauthed_boundary_flow_fires_spoofing():
    result = sk_threat_model({
        "components": [],
        "data_flows": [{
            "from": "client", "to": "api",
            "authenticated": False, "encrypted": True,
            "crosses_trust_boundary": True,
        }],
    })
    assert "S" in result["categories_fired"]


def test_every_threat_has_mitigation_hint():
    result = sk_threat_model({
        "components": [{
            "name": "svc", "type": "service",
            "exposed": True, "authenticates_clients": False,
            "audit_logged": False, "rate_limited": False,
            "validates_privilege": False,
        }],
        "data_flows": [{
            "from": "x", "to": "y",
            "encrypted": False,
            "crosses_trust_boundary": True,
        }],
    })
    assert result["count"] > 0
    for t in result["threats"]:
        assert t["mitigation_hint"]


def test_invoke_via_registry_validates_schemas():
    """Wrong input shape must be refused by the Registry's schema check."""
    from aios.skills.base import SkillInputError
    with pytest.raises(SkillInputError):
        default_skill_registry.invoke(SKILL_ID, {"oops": True})


def test_deterministic_output_for_same_input():
    inputs = {
        "components": [{
            "name": "svc", "type": "service",
            "exposed": True, "authenticates_clients": False,
            "audit_logged": True, "rate_limited": True,
            "validates_privilege": True,
        }],
        "data_flows": [],
    }
    a = sk_threat_model(inputs)
    b = sk_threat_model(inputs)
    assert a == b


def test_empty_system_is_threat_free():
    result = sk_threat_model({"components": [], "data_flows": []})
    assert result == {"count": 0, "categories_fired": [], "threats": []}
