"""AIOS command-line interface (sprint 6).

Usage:
    aios --help
    aios --version
    aios init <root> [--profile P-Local] [--force]
    aios append --kind KIND --actor ACTOR [--payload JSON] [--home PATH]
    aios replay [--home PATH] [--format text|json]
    aios scan [--home PATH] [--run-json PATH]
    aios info [--home PATH]
    aios check-profile [--home PATH]

`--home` defaults to $AIOS_HOME or ./aios_home.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from aios import __spec_versions__, __version__
from aios.runtime.event_log import EventLog
from aios.runtime.init import init_aios_home, read_config, is_initialized
from aios.runtime.profile import check_profile
from aios.verification.conservation_scan import (
    ADREvent, ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
    any_breach, conservation_scan,
)
from aios.workflow import WorkflowRunner, parse_manifest, ManifestError

DEFAULT_HOME = "aios_home"


def _home_from_args(args: argparse.Namespace) -> Path:
    home = getattr(args, "home", None) or os.environ.get("AIOS_HOME") or DEFAULT_HOME
    return Path(home).resolve()


def _require_initialized(home: Path) -> bool:
    """Return True if initialized, else write error and return False."""
    if not is_initialized(home):
        sys.stderr.write(
            f"error: no AIOS home at {home}\n"
            f"run `aios init {home}` first, or set AIOS_HOME.\n"
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    try:
        result = init_aios_home(args.root, profile=args.profile, force=args.force)
    except FileExistsError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2
    print(f"initialized AIOS home at {result.root}")
    print(f"  profile: {result.profile}")
    print(f"  config:  {result.config_path}")
    print(f"  events:  {result.events_dir}")
    print(f"  seq 0:   install.complete")
    print(f"  seq 1:   profile.declared")
    return 0


def cmd_append(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    try:
        payload = json.loads(args.payload) if args.payload else {}
    except json.JSONDecodeError as e:
        sys.stderr.write(f"error: --payload must be valid JSON: {e}\n")
        return 2
    if not isinstance(payload, dict):
        sys.stderr.write("error: --payload must be a JSON object\n")
        return 2

    log = EventLog(home / "events")
    try:
        frame = log.append(kind=args.kind, actor=args.actor, payload=payload)
    finally:
        log.close()

    print(f"appended seq={frame.seq} kind={frame.kind} actor={frame.actor}")
    print(f"  hash: {frame.frame_hash().hex()[:16]}...")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    log = EventLog(home / "events")
    try:
        frames = list(log.replay())
    except ValueError as e:
        sys.stderr.write(f"REPLAY REJECTED: {e}\n")
        return 3
    finally:
        log.close()

    if args.format == "json":
        out = [
            {
                "seq": f.seq,
                "kind": f.kind,
                "actor": f.actor,
                "ts_ns": f.ts_ns,
                "prev": f.prev.hex(),
                "payload": _payload_to_jsonable(f.payload),
                "hash": f.frame_hash().hex(),
            }
            for f in frames
        ]
        print(json.dumps(out, indent=2))
    else:
        for f in frames:
            print(f"seq={f.seq:>6} {f.actor:>3} {f.kind:<30} "
                  f"{f.frame_hash().hex()[:12]}  {json.dumps(_payload_to_jsonable(f.payload))}")
        print(f"\n{len(frames)} frame(s) replayed; hash chain verified.")
    return 0


def _payload_to_jsonable(p):
    """Convert CBOR-decoded payload to JSON-safe form (bytes → hex)."""
    if isinstance(p, bytes):
        return p.hex()
    if isinstance(p, dict):
        return {k: _payload_to_jsonable(v) for k, v in p.items()}
    if isinstance(p, list):
        return [_payload_to_jsonable(v) for v in p]
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    if args.run_json:
        run = _load_runstate_from_json(Path(args.run_json))
    else:
        run = _demo_runstate()

    ledger = conservation_scan(run)
    print(json.dumps(ledger, indent=2, sort_keys=True))
    if any_breach(ledger):
        print("\nQ1/Q2/Q3 BREACH DETECTED", file=sys.stderr)
        return 4
    print("\nQ1-Q3 preserved.")
    return 0


def _demo_runstate() -> RunState:
    inv = Invariant(id="INV-001", source="principle", statement="demo invariant")
    events = ({"kind": "demo"},)
    return RunState(
        run_id="demo",
        invariants_before=frozenset({inv}),
        invariants_after=frozenset({inv}),
        adr_events=(),
        decisions=(Decision(decision_id="D1", rollback_cost="low", irreversibility_adr_id=None),),
        generator_slices=(GenerationSlice(actor="A3", inputs_seen=frozenset({"spec"})),),
        verifier_slices=(VerificationSlice(actor="A4", inputs_seen=frozenset({"adrs"})),),
        context_load=ContextLoad(
            tokens_loaded=1000, budget=32000,
            invariants_loaded=frozenset({"INV-001"}),
            invariants_required=frozenset({"INV-001"}),
        ),
        event_log_range=EventLogRange(events=events,
                                      stored_projection_hash=_chain_hash(events)),
        impact="local",
    )


def _load_runstate_from_json(path: Path) -> RunState:
    raw = json.loads(path.read_text(encoding="utf-8"))

    def _inv(d):
        return Invariant(id=d["id"], source=d["source"], statement=d["statement"])

    def _adr(d):
        return ADREvent(
            adr_id=d["adr_id"], status=d["status"],
            removes=frozenset(d.get("removes", [])),
            deprecates=d.get("deprecates"),
        )

    def _dec(d):
        return Decision(
            decision_id=d["decision_id"], rollback_cost=d["rollback_cost"],
            irreversibility_adr_id=d.get("irreversibility_adr_id"),
        )

    invs_b = frozenset(_inv(x) for x in raw.get("invariants_before", []))
    invs_a = frozenset(_inv(x) for x in raw.get("invariants_after", []))
    cl = raw.get("context_load", {})
    elr = raw.get("event_log_range", {})
    events = tuple(elr.get("events", ()))
    stored = elr.get("stored_projection_hash") or _chain_hash(events)

    return RunState(
        run_id=raw.get("run_id", "cli"),
        invariants_before=invs_b,
        invariants_after=invs_a,
        adr_events=tuple(_adr(x) for x in raw.get("adr_events", [])),
        decisions=tuple(_dec(x) for x in raw.get("decisions", [])),
        generator_slices=tuple(
            GenerationSlice(actor=x["actor"], inputs_seen=frozenset(x["inputs_seen"]))
            for x in raw.get("generator_slices", [])
        ),
        verifier_slices=tuple(
            VerificationSlice(actor=x["actor"], inputs_seen=frozenset(x["inputs_seen"]))
            for x in raw.get("verifier_slices", [])
        ),
        context_load=ContextLoad(
            tokens_loaded=cl.get("tokens_loaded", 0),
            budget=cl.get("budget", 0),
            invariants_loaded=frozenset(cl.get("invariants_loaded", [])),
            invariants_required=frozenset(cl.get("invariants_required", [])),
        ),
        event_log_range=EventLogRange(events=events, stored_projection_hash=stored),
        impact=raw.get("impact", "local"),
    )


def cmd_info(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    config = read_config(home)
    log = EventLog(home / "events")
    try:
        frames = list(log.replay())
    finally:
        log.close()

    print(f"AIOS home:      {home}")
    print(f"profile:        {config.get('profile')}")
    print(f"aios_version:   {config.get('aios_version')}")
    print("spec_versions:")
    for k, v in sorted(config.get("spec_versions", {}).items()):
        print(f"  {k:<20} {v}")
    print(f"frames:         {len(frames)}")
    if frames:
        print(f"head_seq:       {frames[-1].seq}")
        print(f"head_hash:      {frames[-1].frame_hash().hex()}")
    segments = sorted((home / "events").glob("segment_*.aios"))
    print(f"segments:       {len(segments)}")
    return 0


def cmd_check_profile(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    result = check_profile(home)
    print(result.format_report())
    return 0 if result.passed else 5


def cmd_run(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    try:
        manifest = parse_manifest(Path(args.manifest))
    except (ManifestError, OSError) as e:
        sys.stderr.write(f"error: manifest parse failed: {e}\n")
        return 2

    if args.run_json:
        try:
            run = _load_runstate_from_json(Path(args.run_json))
        except (OSError, KeyError, ValueError) as e:
            sys.stderr.write(f"error: run JSON parse failed: {e}\n")
            return 2
    else:
        run = _demo_runstate()

    log = EventLog(home / "events")
    try:
        result = WorkflowRunner().run(manifest, run, log)
    finally:
        log.close()

    print(result.summary())

    if result.outcome == "promoted":
        return 0
    if result.outcome == "aborted":
        return 4  # Q1-Q3 soundness breach (same code as `aios scan` breach)
    return 6      # rejected (non-soundness gate failure / stub)


def cmd_version(args: argparse.Namespace) -> int:
    print(f"aios {__version__}")
    for k, v in sorted(__spec_versions__.items()):
        print(f"  {k}: {v}")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aios",
        description="AIOS v8 P-Local reference CLI",
    )
    p.add_argument("--version", action="store_true",
                   help="print version info and exit")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    sp = sub.add_parser("init", help="initialize an AIOS home directory")
    sp.add_argument("root", help="directory to initialize")
    sp.add_argument("--profile", default="P-Local",
                    choices=["P-Local", "P-Enterprise", "P-Airgap", "P-HighAssurance"],
                    help="profile declaration (only P-Local is enforced in v0.1.0)")
    sp.add_argument("--force", action="store_true",
                    help="overwrite existing config and re-init")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("append", help="append a frame to the event log")
    sp.add_argument("--kind", required=True, help="event kind (e.g. gate.evaluated)")
    sp.add_argument("--actor", required=True,
                    choices=["A1", "A2", "A3", "A4", "A5"],
                    help="authority")
    sp.add_argument("--payload", default="", help="JSON object payload")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_append)

    sp = sub.add_parser("replay", help="replay the event log (verifies hash chain)")
    sp.add_argument("--home", help="AIOS home directory")
    sp.add_argument("--format", choices=["text", "json"], default="text")
    sp.set_defaults(func=cmd_replay)

    sp = sub.add_parser("scan", help="run conservation scan (Q1-Q3, M4, O5)")
    sp.add_argument("--home", help="AIOS home directory")
    sp.add_argument("--run-json", help="path to a JSON RunState to scan")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("info", help="show AIOS home summary")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("check-profile",
                        help="run profile enforcement checks (Runtime §10.6)")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_check_profile)

    sp = sub.add_parser("run",
                        help="execute a workflow manifest against a RunState")
    sp.add_argument("manifest", help="path to workflow manifest (JSON or YAML)")
    sp.add_argument("--run-json", help="path to a JSON RunState (defaults to demo)")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("version", help="print version info")
    sp.set_defaults(func=cmd_version)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        return cmd_version(args)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
