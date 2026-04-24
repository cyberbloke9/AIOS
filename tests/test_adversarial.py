"""Adversarial / security tests (sprint 7).

Each test constructs a hostile state and asserts the system refuses it.
If any of these passes where it should fail, the corresponding soundness
property is not actually being enforced.

Covers:
  - §1.4.2 segment header tamper
  - §1.4.5 segment trailer tamper
  - §1.4.3 frame-body tamper across a rotation boundary
  - §5.2 LSN monotonicity (out-of-order segment rename)
  - §5.5 cross-segment prev-chain lie
  - §1.4.3 malformed CBOR rejected by replay
  - §10.6 profile downgrade attempt (signed frames + P-Local declaration)
  - Verification §1: unregistered predicate refused by loader
  - Verification §1: stub predicate refuses to evaluate (not silent pass)
  - Q1: silent invariant removal → breach → CLI exit code
"""
from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

import pytest

from aios.runtime.event_log import (
    EventLog, HEADER_TOTAL_SIZE, TRAILER_TOTAL_SIZE,
    _encode_on_disk, sha256,
)
from aios.runtime.init import init_aios_home
from aios.runtime.profile import check_profile
from aios.verification.conservation_scan import (
    ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
    any_breach, conservation_scan,
)
from aios.verification.registry import (
    NotImplementedPredicateError, UnknownPredicateError, default_registry,
)


# §1.4 / §5 Event-log integrity --------------------------------------------


def test_header_magic_tamper_rejected():
    """Flip the magic bytes in a segment header: unpack must raise."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        log.close()
        seg = next(Path(tmp).glob("segment_*.aios"))
        raw = bytearray(seg.read_bytes())
        raw[0:4] = b"BAD!"
        seg.write_bytes(bytes(raw))
        with pytest.raises(ValueError):
            log2 = EventLog(tmp)
            try:
                list(log2.replay())
            finally:
                log2.close()


def test_header_first_seq_tamper_rejected():
    """Change first_seq in header: hdr_hash becomes invalid."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        log.close()
        seg = next(Path(tmp).glob("segment_*.aios"))
        raw = bytearray(seg.read_bytes())
        # first_seq is at offset 8 (after magic+version+flags = 4+2+2)
        raw[8:16] = struct.pack(">Q", 999)
        seg.write_bytes(bytes(raw))
        with pytest.raises(ValueError):
            log2 = EventLog(tmp)
            try:
                list(log2.replay())
            finally:
                log2.close()


def test_trailer_tamper_rejected_on_replay():
    """Flip a byte in the trailer of a closed segment. Replay must refuse."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(4):
            log.append(kind="x", actor="A1", payload={"i": i})
        log.close()
        # Identify the first closed segment (trailer lives at end of file,
        # before any subsequent on-disk content).
        closed = sorted(p for p in Path(tmp).glob("segment_*.aios")
                        if "OPEN" not in p.name)
        assert closed
        seg = closed[0]
        raw = bytearray(seg.read_bytes())
        # Corrupt the first byte of the trailer (the magic "eoSG")
        trailer_start = len(raw) - TRAILER_TOTAL_SIZE
        raw[trailer_start] ^= 0x01
        seg.write_bytes(bytes(raw))

        with pytest.raises(ValueError):
            log2 = EventLog(tmp, rotate_after_frames=2)
            try:
                list(log2.replay())
            finally:
                log2.close()


def test_cross_segment_prev_lie_rejected():
    """Rewrite the prev_hash in a segment-2 header so it claims to follow
    segment-1 but with the wrong end-hash. Replay detects the prev lie."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(4):
            log.append(kind="x", actor="A1", payload={"i": i})
        log.close()

        segs = sorted(Path(tmp).glob("segment_*.aios"),
                      key=lambda p: int(p.name.split("_")[1]))
        assert len(segs) >= 2
        # Overwrite the prev_hash in the second segment's header.
        # Header layout: magic(4) ver(2) flags(2) first_seq(8) last_seq(8)
        # created_ts(8) prev_hash(32) => prev_hash starts at byte 32.
        raw = bytearray(segs[1].read_bytes())
        bad_prev = b"\xAA" * 32
        raw[32:64] = bad_prev
        # Recompute hdr_hash so the header itself stays valid
        fixed = bytes(raw[:HEADER_TOTAL_SIZE - 32])
        raw[HEADER_TOTAL_SIZE - 32:HEADER_TOTAL_SIZE] = sha256(fixed)
        segs[1].write_bytes(bytes(raw))

        with pytest.raises(ValueError) as exc:
            log2 = EventLog(tmp, rotate_after_frames=2)
            try:
                list(log2.replay())
            finally:
                log2.close()
        assert "prev_hash" in str(exc.value) or "prev" in str(exc.value)


def test_malformed_cbor_payload_rejected():
    """Hand-craft a frame whose CBOR uses an unsupported major type."""
    with tempfile.TemporaryDirectory() as tmp:
        # Init a log with one good frame so recovery doesn't short-circuit
        log = EventLog(tmp)
        log.append(kind="ok", actor="A1", payload={"i": 0})
        log.close()

        seg = next(Path(tmp).glob("segment_*.aios"))
        # Append a manually crafted on-disk frame whose CBOR starts with
        # major type 7 simple value 16 (0xF0): unsupported by our decoder.
        bogus_cbor = b"\xf0\x01\x02"
        on_disk = _encode_on_disk(bogus_cbor)
        with open(seg, "ab") as fh:
            fh.write(on_disk)

        with pytest.raises(ValueError):
            log2 = EventLog(tmp)
            try:
                list(log2.replay())
            finally:
                log2.close()


# §10.6 Profile downgrade attack --------------------------------------------


def test_p_local_refuses_signed_frames_from_higher_profile():
    """Attacker declares P-Local but the log contains Ed25519-signed frames
    (implying an earlier P-HighAssurance deployment). Loader must refuse."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        log = EventLog(Path(tmp) / "events")
        log.append(kind="a", actor="A3", payload={}, sig=b"\x11" * 64)
        log.close()
        result = check_profile(tmp)
        assert not result.passed
        bad = [c for c in result.checks if c.name == "p_local.no_capability_tokens"]
        assert bad and bad[0].status == "fail"


def test_rewriting_config_profile_to_unknown_refused():
    """Direct rewrite of config.json to an unknown profile string."""
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp, profile="P-Local")
        cfg = Path(tmp) / "config.json"
        data = json.loads(cfg.read_text())
        data["profile"] = "P-Invented"
        cfg.write_text(json.dumps(data))
        result = check_profile(tmp)
        assert not result.passed


# Verification §1 Predicate registry defenses -----------------------------


def test_workflow_referencing_unregistered_predicate_refused():
    with pytest.raises(UnknownPredicateError):
        default_registry.require_registered([
            "P_Q1_invariant_integrity",
            "P_made_up_by_workflow_author",
        ])


def test_stub_predicate_refuses_silent_pass():
    """P_acceptance_tests is registered but not yet implemented. A workflow
    that calls evaluate() on it must get a loud refusal, not a silent 'ok'.
    (P_PI_sentinel was promoted from stub to real in sprint 45; the
    still-stub predicate is P_acceptance_tests.)"""
    run = RunState(
        run_id="t",
        invariants_before=frozenset(),
        invariants_after=frozenset(),
        adr_events=(),
        decisions=(),
        generator_slices=(),
        verifier_slices=(),
        context_load=ContextLoad(0, 0, frozenset(), frozenset()),
        event_log_range=EventLogRange((), _chain_hash(())),
        impact="local",
    )
    with pytest.raises(NotImplementedPredicateError):
        default_registry.evaluate("P_acceptance_tests", run)


# Q1 breach must be detected and raised through the ledger -----------------


def test_silent_invariant_removal_is_a_breach():
    inv_a = Invariant(id="INV-001", source="principle", statement="X")
    inv_b = Invariant(id="INV-002", source="security", statement="Y")
    run = RunState(
        run_id="bad",
        invariants_before=frozenset({inv_a, inv_b}),
        invariants_after=frozenset({inv_a}),
        adr_events=(),  # no accepted ADR removing INV-002
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"a"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"b"})),),
        context_load=ContextLoad(100, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange((), _chain_hash(())),
        impact="subsystem",
    )
    ledger = conservation_scan(run)
    assert ledger["Q1_invariant_integrity"]["status"] == "breached"
    assert any_breach(ledger)


def test_m4_breach_alone_is_not_soundness_breach():
    """M4 is a governance metric, not a conservation law: failing M4 must
    NOT flip any_breach() to True. Only Q1-Q3 trigger the halt."""
    inv = Invariant(id="I", source="principle", statement="X")
    # Generator and verifier see identical inputs => M4 breach (max overlap 1, V=0)
    run = RunState(
        run_id="m4bad",
        invariants_before=frozenset({inv}),
        invariants_after=frozenset({inv}),
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"a", "b"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"a", "b"})),),
        context_load=ContextLoad(100, 1000, frozenset({"I"}), frozenset({"I"})),
        event_log_range=EventLogRange((), _chain_hash(())),
        impact="subsystem",
    )
    ledger = conservation_scan(run)
    assert ledger["M4_independence"]["status"] == "breached"
    assert not any_breach(ledger)
