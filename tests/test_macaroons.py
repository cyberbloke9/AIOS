"""Tests for Macaroon-style capability tokens (sprint 62)."""
from __future__ import annotations

import time

import pytest

from aios.enterprise.macaroons import (
    CapabilityToken,
    MacaroonError,
    TokenVerificationError,
    VerifyContext,
    add_caveat,
    issue_token,
    verify_token,
)
from aios.enterprise.signing import Ed25519Signer, cryptography_available


pytestmark = pytest.mark.skipif(
    not cryptography_available(),
    reason="cryptography package not installed",
)


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------


def _issuer():
    return Ed25519Signer.generate()


def test_issue_returns_signed_token():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="promote_artifact", scope={"workflow": "wf1"},
        ttl_ns=60 * 10**9,
    )
    assert t.v == 1
    assert len(t.tid) == 16
    assert t.iss == "A5"
    assert t.sub == "A3"
    assert t.act == "promote_artifact"
    assert t.scp == {"workflow": "wf1"}
    assert len(t.sig) == 64
    assert t.caveats == ()


def test_issue_refuses_zero_ttl():
    s = _issuer()
    with pytest.raises(MacaroonError, match="ttl_ns"):
        issue_token(
            issuer_signer=s, issuer_id="A5", subject="A3",
            action="x", scope={}, ttl_ns=0,
        )


def test_issue_refuses_bad_tid_length():
    s = _issuer()
    with pytest.raises(MacaroonError, match="tid"):
        issue_token(
            issuer_signer=s, issuer_id="A5", subject="A3",
            action="x", scope={}, ttl_ns=10**9,
            tid=b"too short",
        )


# ---------------------------------------------------------------------------
# Base verification
# ---------------------------------------------------------------------------


def _now_ns() -> int:
    return time.time_ns()


def _ctx(now: int = None, **overrides):
    base = dict(
        subject="A3", action="promote_artifact",
        scope={"workflow": "wf1"},
        now_ns=now if now is not None else _now_ns(),
    )
    base.update(overrides)
    return VerifyContext(**base)


def test_verify_valid_token_passes():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="promote_artifact", scope={"workflow": "wf1"},
        ttl_ns=60 * 10**9,
    )
    verify_token(t, issuer_pubkey=s.public_key(), context=_ctx())


def test_verify_rejects_wrong_subject():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**9,
    )
    with pytest.raises(TokenVerificationError, match="subject"):
        verify_token(t, issuer_pubkey=s.public_key(),
                     context=_ctx(subject="A4", action="x", scope={}))


def test_verify_rejects_wrong_action():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="promote_artifact", scope={}, ttl_ns=10**9,
    )
    with pytest.raises(TokenVerificationError, match="action"):
        verify_token(t, issuer_pubkey=s.public_key(),
                     context=_ctx(action="delete_artifact", scope={}))


def test_verify_rejects_missing_scope_key():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={"workflow": "wf1"}, ttl_ns=10**9,
    )
    with pytest.raises(TokenVerificationError, match="scope"):
        verify_token(t, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x",
                                   scope={"workflow": "wf2"}))


def test_verify_accepts_scope_with_list_allowed():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={"workflow": ["wf1", "wf2"]},
        ttl_ns=10**9,
    )
    verify_token(t, issuer_pubkey=s.public_key(),
                 context=_ctx(action="x", scope={"workflow": "wf2"}))


def test_verify_rejects_wrong_key():
    s1 = _issuer()
    s2 = _issuer()
    t = issue_token(
        issuer_signer=s1, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**9,
    )
    with pytest.raises(TokenVerificationError, match="signature"):
        verify_token(t, issuer_pubkey=s2.public_key(),
                     context=_ctx(action="x", scope={}))


def test_verify_rejects_expired_token():
    s = _issuer()
    past = _now_ns() - 10**11
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**9, now_ns=past,
    )
    with pytest.raises(TokenVerificationError, match="expired"):
        verify_token(t, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={}))


def test_verify_rejects_not_yet_valid():
    s = _issuer()
    future = _now_ns() + 10**11
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**9, now_ns=future,
    )
    with pytest.raises(TokenVerificationError, match="not yet"):
        verify_token(t, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={}))


# ---------------------------------------------------------------------------
# Caveats — narrowing
# ---------------------------------------------------------------------------


def test_caveat_time_narrows_expiry():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=60 * 10**9,
    )
    # 10 minutes in the past — beyond the 30-second skew tolerance
    past = _now_ns() - 600 * 10**9
    narrow = add_caveat(t, caveat_type="time",
                         value={"exp_ns": past})
    with pytest.raises(TokenVerificationError, match="time expired"):
        verify_token(narrow, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={}))


def test_caveat_scope_narrows():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={"workflow": ["wf1", "wf2"]},
        ttl_ns=10**10,
    )
    narrow = add_caveat(t, caveat_type="scope",
                         value={"workflow": "wf1"})
    # Narrowed to wf1 — passes for wf1
    verify_token(narrow, issuer_pubkey=s.public_key(),
                 context=_ctx(action="x", scope={"workflow": "wf1"}))
    # But NOT wf2
    with pytest.raises(TokenVerificationError):
        verify_token(narrow, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={"workflow": "wf2"}))


def test_caveat_audience_required():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**10,
    )
    bound = add_caveat(t, caveat_type="audience",
                        value={"aud": "storage-service"})
    # Wrong audience
    with pytest.raises(TokenVerificationError, match="audience"):
        verify_token(bound, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={},
                                   audience="web-service"))
    # Right audience
    verify_token(bound, issuer_pubkey=s.public_key(),
                 context=_ctx(action="x", scope={},
                               audience="storage-service"))


def test_caveat_predicate_applied():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**10,
    )
    narrow = add_caveat(t, caveat_type="predicate",
                         value={"name": "ip_in_range",
                                "arg": "10.0.0.0/8"})
    # Predicate rejects
    ctx_bad = VerifyContext(
        subject="A3", action="x", scope={}, now_ns=_now_ns(),
        predicates={"ip_in_range": lambda arg, ctx: False},
    )
    with pytest.raises(TokenVerificationError, match="predicate"):
        verify_token(narrow, issuer_pubkey=s.public_key(), context=ctx_bad)
    # Predicate accepts
    ctx_ok = VerifyContext(
        subject="A3", action="x", scope={}, now_ns=_now_ns(),
        predicates={"ip_in_range": lambda arg, ctx: True},
    )
    verify_token(narrow, issuer_pubkey=s.public_key(), context=ctx_ok)


def test_predicate_with_no_evaluator_rejects():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**10,
    )
    narrow = add_caveat(t, caveat_type="predicate",
                         value={"name": "unknown_check"})
    with pytest.raises(TokenVerificationError, match="no evaluator"):
        verify_token(narrow, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={}))


# ---------------------------------------------------------------------------
# Caveat chain integrity
# ---------------------------------------------------------------------------


def test_caveat_chain_detects_reorder():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**11,
    )
    t = add_caveat(t, caveat_type="scope", value={"k": "v1"})
    t = add_caveat(t, caveat_type="audience", value={"aud": "x"})
    # Swap the caveat order — MAC chain breaks
    reordered = t.__class__(
        v=t.v, tid=t.tid, iss=t.iss, sub=t.sub, act=t.act,
        scp=t.scp, nbf_ns=t.nbf_ns, exp_ns=t.exp_ns,
        caveats=(t.caveats[1], t.caveats[0]),
        sig=t.sig,
    )
    with pytest.raises(TokenVerificationError, match="MAC chain"):
        verify_token(reordered, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={}, audience="x"))


def test_caveat_chain_detects_tampered_value():
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**11,
    )
    t = add_caveat(t, caveat_type="audience", value={"aud": "x"})
    # Tamper with the caveat value while keeping the MAC — MAC chain breaks
    from aios.enterprise.macaroons import Caveat
    tampered_caveat = Caveat(
        type="audience", value={"aud": "attacker"},
        mac=t.caveats[0].mac,
    )
    tampered = t.__class__(
        v=t.v, tid=t.tid, iss=t.iss, sub=t.sub, act=t.act,
        scp=t.scp, nbf_ns=t.nbf_ns, exp_ns=t.exp_ns,
        caveats=(tampered_caveat,),
        sig=t.sig,
    )
    with pytest.raises(TokenVerificationError, match="MAC chain"):
        verify_token(tampered, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={},
                                   audience="attacker"))


def test_caveat_cannot_be_removed_without_breaking_chain():
    """Removing a caveat that was chained after another changes the
    effective prior_mac for the rest."""
    s = _issuer()
    t = issue_token(
        issuer_signer=s, issuer_id="A5", subject="A3",
        action="x", scope={}, ttl_ns=10**11,
    )
    t = add_caveat(t, caveat_type="scope", value={"k": "v1"})
    t = add_caveat(t, caveat_type="audience", value={"aud": "x"})
    # Drop the first caveat, keep the second — second's MAC was
    # chained from first's, so removing first breaks it.
    stripped = t.__class__(
        v=t.v, tid=t.tid, iss=t.iss, sub=t.sub, act=t.act,
        scp=t.scp, nbf_ns=t.nbf_ns, exp_ns=t.exp_ns,
        caveats=(t.caveats[1],),
        sig=t.sig,
    )
    with pytest.raises(TokenVerificationError, match="MAC chain"):
        verify_token(stripped, issuer_pubkey=s.public_key(),
                     context=_ctx(action="x", scope={}, audience="x"))
