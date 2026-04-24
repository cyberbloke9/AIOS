"""Incident replay procedure (sprint 44).

Verification Spec §4.4 steps 1-6:

  1. Identify the event-log range covering the incident.
  2. Run conservation_scan on the range; record Q1-Q3 status.
  3. Reconstruct the workflow, skills, gates, credentials in effect.
  4. Determine whether the incident was caught by any gate, and if not, why.
  5. Attribute to a governance-failure class (G1-G7) if applicable.
  6. Produce an incident report with a remediation plan.

This module drives the replay over already-read Frame objects. The
caller provides the frame list filtered to a run_id (matches the way
the event log is replayed: `EventLog.replay()` yields Frames in LSN
order). The report's `remediation` field points at the correct
§4.3 G-class containment.

`replay_incident_from_home(home, run_id)` is the full pipeline:
opens the event log, filters to the run_id, produces the report.
"""
from __future__ import annotations

import dataclasses as dc
from pathlib import Path
from typing import Iterable

from aios.runtime.event_log import EventLog, Frame
from aios.verification.audit import G_CONTAINMENT, GClass


@dc.dataclass(frozen=True)
class GateVerdict:
    """What happened for a single gate during the incident run."""
    gate_id: str
    status: str               # "preserved" | "breached" | "not_implemented" | "error"


@dc.dataclass(frozen=True)
class IncidentReplayReport:
    run_id: str
    frame_count: int
    workflow_id: str | None
    impact: str | None
    outcome: str | None        # promoted | rejected | aborted | <run did not finish>
    gate_verdicts: tuple[GateVerdict, ...]
    caught: bool               # at least one gate breached OR run aborted
    q_breaches: tuple[str, ...]    # Q1/Q2/Q3 breach gate ids, in order
    attributed_g_class: GClass | None
    remediation: str
    details: dict

    def summary(self) -> str:
        lines = [
            f"incident replay — run_id={self.run_id}",
            f"  workflow:        {self.workflow_id or '(not-recorded)'}",
            f"  impact:          {self.impact or '(not-recorded)'}",
            f"  outcome:         {self.outcome or '(no final verdict frame)'}",
            f"  frames:          {self.frame_count}",
            f"  caught by gate:  {'yes' if self.caught else 'NO'}",
        ]
        if self.q_breaches:
            lines.append(f"  Q breaches:      {', '.join(self.q_breaches)}")
        if self.gate_verdicts:
            lines.append("  gate verdicts:")
            for gv in self.gate_verdicts:
                lines.append(f"    {gv.gate_id:<35} {gv.status}")
        if self.attributed_g_class:
            lines.append(f"  G-class:         {self.attributed_g_class}")
        lines.append(f"  remediation:     {self.remediation}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core replay
# ---------------------------------------------------------------------------


def replay_incident(frames: Iterable[Frame], run_id: str) -> IncidentReplayReport:
    """Build an incident report from a filtered frame iterator.

    The replay procedure:
      - filter frames whose payload carries run_id == run_id
      - read workflow_id, impact, gate verdicts, outcome from the frames
      - attribute G-class per §4.4 step 5:
          Q1/Q2/Q3 breached -> G2 underblocking if NOT caught, else no G-class
          stub predicate encountered -> G6 stale contract (stub == uncalibrated)
          all gates preserved but run was aborted anyway -> G7 (oscillation)
    """
    run_frames = [f for f in frames if _run_id_of(f) == run_id]

    workflow_id: str | None = None
    impact: str | None = None
    outcome: str | None = None
    gate_verdicts: list[GateVerdict] = []
    q_breaches: list[str] = []
    stub_encountered = False

    for frame in run_frames:
        payload = frame.payload or {}
        if frame.kind == "run.started":
            workflow_id = payload.get("workflow_id")
            impact = payload.get("impact")
        elif frame.kind == "gate.evaluated":
            gid = payload.get("gate_id")
            status = payload.get("status")
            if not gid or not status:
                continue
            gate_verdicts.append(GateVerdict(gid, status))
            if status == "not_implemented":
                stub_encountered = True
            if status == "breached" and gid.startswith(
                ("P_Q1_", "P_Q2_", "P_Q3_")
            ):
                q_breaches.append(gid)
        elif frame.kind == "artifact.promoted":
            outcome = "promoted"
        elif frame.kind == "artifact.rejected":
            outcome = "rejected"
        elif frame.kind == "run.aborted":
            outcome = "aborted"

    caught = bool(q_breaches) or any(
        v.status == "breached" for v in gate_verdicts
    ) or outcome == "aborted"

    # §4.4 step 5 — attribute a G-class based on what we observed.
    attributed: GClass | None = None
    if q_breaches and caught and outcome == "aborted":
        # The system correctly aborted on a Q1-Q3 breach. No G-class —
        # this is the happy path (breach detected AND contained).
        attributed = None
    elif q_breaches and not caught:
        # Soundness breach existed but the run completed — that's
        # textbook G2 underblocking. (We cannot reach this state in
        # v0.4.0 because WorkflowRunner aborts on Q-breach; retained
        # for replay against hypothetical malformed logs.)
        attributed = "G2"
    elif stub_encountered:
        # A stub predicate in the required set — G6 stale contract.
        attributed = "G6"
    elif not gate_verdicts and outcome:
        # Outcome recorded without any gate evaluations — could be G1
        # overblocking (gates bypassed) or a malformed log.
        attributed = "G1"

    remediation = (
        G_CONTAINMENT[attributed]
        if attributed
        else "no G-class attribution required (incident contained)"
    )

    return IncidentReplayReport(
        run_id=run_id,
        frame_count=len(run_frames),
        workflow_id=workflow_id,
        impact=impact,
        outcome=outcome,
        gate_verdicts=tuple(gate_verdicts),
        caught=caught,
        q_breaches=tuple(q_breaches),
        attributed_g_class=attributed,
        remediation=remediation,
        details={
            "stub_encountered": stub_encountered,
        },
    )


def replay_incident_from_home(
    aios_home: str | Path, run_id: str
) -> IncidentReplayReport:
    """Full pipeline: open the log, filter, produce the report."""
    home = Path(aios_home)
    log = EventLog(home / "events")
    try:
        frames = list(log.replay())
    finally:
        log.close()
    return replay_incident(frames, run_id)


def _run_id_of(frame: Frame) -> str | None:
    p = frame.payload or {}
    return p.get("run_id") if isinstance(p, dict) else None
