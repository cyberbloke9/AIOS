"""Tests for the workflow runner (sprint 19)."""
from __future__ import annotations

import dataclasses as dc
import json
import tempfile

from aios.runtime.event_log import EventLog
from aios.verification.conservation_scan import (
    ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
)
from aios.verification.registry import Registry
from aios.workflow import (
    WorkflowRunner, parse_manifest,
)


def _registry_with_stubs_as_preserved() -> Registry:
    """Test registry where P_schema_valid / P_acceptance_tests / P_PI_sentinel
    return preserved instead of NotImplementedPredicateError. Lets the
    runner tests cover the promote path without needing those predicates
    to be production-ready."""
    reg = Registry()
    stub_ids = ("P_schema_valid", "P_acceptance_tests", "P_PI_sentinel")
    for pid in stub_ids:
        old = reg.get(pid)
        reg._by_id[pid] = dc.replace(
            old, implementation=lambda run, _pid=pid: {
                "status": "preserved", "note": f"{_pid} test stub"}
        )
    return reg


def _clean_run(run_id: str = "r1", impact: str = "local") -> RunState:
    inv = Invariant(id="INV-001", source="principle", statement="X")
    events = ({"kind": "e1"},)
    return RunState(
        run_id=run_id,
        invariants_before=frozenset({inv}),
        invariants_after=frozenset({inv}),
        adr_events=(),
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"spec"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"adrs"})),),
        context_load=ContextLoad(100, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact=impact,
    )


def _q1_breach_run() -> RunState:
    inv_a = Invariant(id="INV-001", source="principle", statement="X")
    inv_b = Invariant(id="INV-002", source="security", statement="Y")
    events = ({"kind": "e1"},)
    return RunState(
        run_id="breach",
        invariants_before=frozenset({inv_a, inv_b}),
        invariants_after=frozenset({inv_a}),
        adr_events=(),  # silent removal of INV-002
        decisions=(Decision("D1", "low", None),),
        generator_slices=(GenerationSlice("A3", frozenset({"spec"})),),
        verifier_slices=(VerificationSlice("A4", frozenset({"adrs"})),),
        context_load=ContextLoad(100, 1000, frozenset({"INV-001"}), frozenset({"INV-001"})),
        event_log_range=EventLogRange(events, _chain_hash(events)),
        impact="local",
    )


def _local_manifest(registry=None):
    return parse_manifest(
        json.dumps({"id": "test-workflow", "version": "1.0.0", "impact": "local"}),
        registry=registry,
    )


def _subsystem_manifest(registry=None):
    return parse_manifest(
        json.dumps({"id": "test-sub", "version": "1.0.0", "impact": "subsystem"}),
        registry=registry,
    )


def test_clean_run_promotes():
    reg = _registry_with_stubs_as_preserved()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            result = WorkflowRunner(registry=reg).run(
                _local_manifest(reg), _clean_run(), log)
        finally:
            log.close()
        assert result.outcome == "promoted"
        assert all(g.status == "preserved" for g in result.gate_results)


def test_q1_breach_aborts_run():
    """Q1 breach must immediately abort the run (Kernel §2.2), skipping
    any remaining gates."""
    reg = _registry_with_stubs_as_preserved()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            result = WorkflowRunner(registry=reg).run(
                _local_manifest(reg), _q1_breach_run(), log)
        finally:
            log.close()
        assert result.outcome == "aborted"
        evaluated_ids = [g.predicate_id for g in result.gate_results]
        assert evaluated_ids[-1] == "P_Q1_invariant_integrity"
        assert result.gate_results[-1].status == "breached"


def test_aborted_run_emits_correct_frames():
    reg = _registry_with_stubs_as_preserved()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            WorkflowRunner(registry=reg).run(
                _local_manifest(reg), _q1_breach_run(), log)
        finally:
            log.close()
        log2 = EventLog(tmp)
        frames = list(log2.replay())
        log2.close()
        kinds = [f.kind for f in frames]
        assert kinds[0] == "run.started"
        assert "gate.evaluated" in kinds
        assert kinds[-1] == "run.aborted"


def test_promoted_run_emits_promoted_frame():
    reg = _registry_with_stubs_as_preserved()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            result = WorkflowRunner(registry=reg).run(
                _local_manifest(reg), _clean_run(), log)
        finally:
            log.close()
        log2 = EventLog(tmp)
        frames = list(log2.replay())
        log2.close()
        final = frames[result.final_event_seq]
        assert final.kind == "artifact.promoted"
        assert final.actor == "A5"


def test_stub_predicate_causes_rejection_not_silent_pass():
    """A workflow that explicitly includes a still-stub predicate
    (P_acceptance_tests) must be rejected — stubs cannot silently pass.
    P_schema_valid was promoted in sprint 25 and P_PI_sentinel in
    sprint 45; P_acceptance_tests is the remaining stub."""
    manifest = parse_manifest(json.dumps({
        "id": "stub-demo",
        "version": "1.0",
        "impact": "local",
        "required_gates": ["P_acceptance_tests"],
    }))

    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            result = WorkflowRunner().run(manifest, _clean_run(), log)
        finally:
            log.close()
        assert result.outcome == "rejected"
        stub_results = [g for g in result.gate_results
                        if g.status == "not_implemented"]
        assert stub_results
        assert any(g.predicate_id == "P_acceptance_tests" for g in stub_results)


def test_subsystem_runs_m4_and_o5():
    reg = _registry_with_stubs_as_preserved()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            result = WorkflowRunner(registry=reg).run(
                _subsystem_manifest(reg),
                _clean_run(impact="subsystem"), log)
        finally:
            log.close()
        pid_list = [g.predicate_id for g in result.gate_results]
        assert "P_M4_independence" in pid_list
        assert "P_O5_context_sufficiency_hard" in pid_list


def test_workflow_result_summary_is_human_readable():
    reg = _registry_with_stubs_as_preserved()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            result = WorkflowRunner(registry=reg).run(
                _local_manifest(reg), _clean_run(), log)
        finally:
            log.close()
        text = result.summary()
        assert "PROMOTED" in text
        assert "[ok]" in text
        assert "test-workflow" in text


def test_manifest_impact_overrides_runstate_impact():
    """If the caller passes runstate impact=local but manifest declares
    impact=subsystem, the runner uses the manifest's impact."""
    reg = _registry_with_stubs_as_preserved()
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            result = WorkflowRunner(registry=reg).run(
                _subsystem_manifest(reg),
                _clean_run(impact="local"),  # mismatch
                log)
        finally:
            log.close()
        m4 = [g for g in result.gate_results if g.predicate_id == "P_M4_independence"]
        assert m4
        assert m4[0].status == "preserved"
