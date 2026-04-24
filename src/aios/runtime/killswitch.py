"""Kernel Spec §5 kill switch (sprint 67).

Kill switches are the constitutional equivalent of a circuit breaker.
A human operator can halt the system WITHOUT diagnosing the cause.

Scopes (§5.1) in narrowing order:

  global     all Z1-Z4 activity halts; Z0 predicates continue so Q1-Q3
             violations remain detectable; read-only mode is implicit.
  authority  one of A1-A5 halts; others continue.
  workflow   one named workflow halts; other workflows continue.
  skill      one named skill halts; workflows that depend fail on next
             invocation.

Authorization (§5.2):
  global    any A5 holder OR two concurrent A4 holders OR the
            designated human operator.
  authority A5 unilaterally.
  workflow  A5 or A4.
  skill     A5 or (skill owner + A4).

This module records kill + lift events into the event log and answers
`is_killed` by scanning. Per §5.3, any global kill flips the system
into read-only mode automatically.
"""
from __future__ import annotations

import dataclasses as dc
import time
from pathlib import Path
from typing import Literal

from aios.runtime.event_log import EventLog, Frame

KillScope = Literal["global", "authority", "workflow", "skill"]

_KILL_KINDS = {
    "global":    "kill.global",
    "authority": "kill.authority",
    "workflow":  "kill.workflow",
    "skill":     "kill.skill",
}

_LIFT_KINDS = {
    "global":    "kill.global.lifted",
    "authority": "kill.authority.lifted",
    "workflow":  "kill.workflow.lifted",
    "skill":     "kill.skill.lifted",
}


class KillSwitchError(RuntimeError):
    """Authorization or structural error."""


# §5.2 authorization table — map scope -> allowed authority ids
_ALLOWED_AUTHORITIES: dict[KillScope, frozenset[str]] = {
    "global":    frozenset({"A4", "A5", "operator"}),
    "authority": frozenset({"A5"}),
    "workflow":  frozenset({"A4", "A5"}),
    "skill":     frozenset({"A4", "A5", "skill_owner"}),
}


@dc.dataclass(frozen=True)
class KillSwitch:
    scope: KillScope
    subject: str           # "*" for global, else entity id
    reason: str
    authority: str         # A1-A5 | operator | skill_owner:<name>
    ts_ns: int | None = None

    def authority_role(self) -> str:
        """The authority's ROLE portion (strips ':<name>' from skill_owner)."""
        return self.authority.split(":", 1)[0]


def _check_authorization(switch: KillSwitch) -> None:
    role = switch.authority_role()
    allowed = _ALLOWED_AUTHORITIES[switch.scope]
    if role not in allowed:
        raise KillSwitchError(
            f"authority {switch.authority!r} (role {role!r}) not allowed "
            f"for scope {switch.scope!r}; need one of {sorted(allowed)}"
        )
    if switch.scope == "global" and switch.subject != "*":
        raise KillSwitchError(
            "global kill subject must be '*' (no specific entity)"
        )
    if switch.scope != "global" and (not switch.subject or switch.subject == "*"):
        raise KillSwitchError(
            f"scope {switch.scope!r} requires a non-empty subject"
        )


def apply_kill_switch(log: EventLog, switch: KillSwitch) -> Frame:
    """Write a kill event to `log` and return the frame.

    Raises KillSwitchError on bad authorization. The caller is
    responsible for opening + closing the EventLog around this call.
    """
    _check_authorization(switch)
    ts = switch.ts_ns or time.time_ns()
    return log.append(
        kind=_KILL_KINDS[switch.scope],
        actor=switch.authority_role(),
        payload={
            "scope": switch.scope,
            "subject": switch.subject,
            "reason": switch.reason,
            "authority": switch.authority,
            "ts_ns": ts,
        },
    )


def lift_kill_switch(log: EventLog, switch: KillSwitch) -> Frame:
    """Write a kill-lifted event. Same authorization rules as applying."""
    _check_authorization(switch)
    ts = switch.ts_ns or time.time_ns()
    return log.append(
        kind=_LIFT_KINDS[switch.scope],
        actor=switch.authority_role(),
        payload={
            "scope": switch.scope,
            "subject": switch.subject,
            "reason": switch.reason,
            "authority": switch.authority,
            "ts_ns": ts,
        },
    )


@dc.dataclass(frozen=True)
class KillState:
    active: bool
    applied_at_seq: int | None
    applied_authority: str | None
    reason: str | None


def is_killed(
    log: EventLog, *,
    scope: KillScope,
    subject: str,
) -> KillState:
    """Scan the log for the last matching kill / lift pair for
    (scope, subject). Returns the active state.

    Global scope ignores `subject` — a global kill affects everything.
    """
    active = False
    seq: int | None = None
    authority: str | None = None
    reason: str | None = None

    kill_kind = _KILL_KINDS[scope]
    lift_kind = _LIFT_KINDS[scope]

    for frame in log.replay():
        if frame.kind == kill_kind:
            payload = frame.payload or {}
            if scope != "global" and payload.get("subject") != subject:
                continue
            active = True
            seq = frame.seq
            authority = payload.get("authority")
            reason = payload.get("reason")
        elif frame.kind == lift_kind:
            payload = frame.payload or {}
            if scope != "global" and payload.get("subject") != subject:
                continue
            active = False
            seq = None
            authority = None
            reason = None

    return KillState(
        active=active,
        applied_at_seq=seq,
        applied_authority=authority,
        reason=reason,
    )


def read_only_mode(log: EventLog) -> bool:
    """§5.3 — read-only mode is implied by ANY active global kill."""
    return is_killed(log, scope="global", subject="*").active
