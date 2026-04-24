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
from aios.verification.calibration_record import (
    CalibrationQualityError,
    calibrate as _calibrate,
    load_corpus_from_json,
    save_record,
)
from aios.verification.calibration_status import (
    check_calibration_status,
    record_calibration_attempt,
)
from aios.verification.credentials import (
    CredentialError, CredentialLedger,
)
from aios.verification.incident_replay import replay_incident_from_home
from aios.verification.conservation_scan import (
    ADREvent, ContextLoad, Decision, EventLogRange, GenerationSlice,
    Invariant, RunState, VerificationSlice, _chain_hash,
    any_breach, conservation_scan,
)
from aios.verification.corpus import CorpusQualityError
from aios.project import (
    adopt as _adopt_project,
    install_post_commit_hook,
    runstate_from_project,
)
from aios.skills import default_skill_registry
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


def cmd_adopt(args: argparse.Namespace) -> int:
    try:
        result = _adopt_project(args.repo, profile=args.profile, force=args.force)
    except (FileExistsError, NotADirectoryError, ValueError) as e:
        sys.stderr.write(f"error: {e}\n")
        return 1 if isinstance(e, FileExistsError) else 2

    print(f"adopted AIOS into repo {result.repo}")
    print(f"  profile:         {result.init.profile}")
    print(f"  aios home:       {result.init.root}")
    print(f"  invariants.yaml: {'created' if result.invariants_template_written else 'existing'}")
    print(f"  .gitignore:      {'updated' if result.gitignore_updated else 'already had runtime entries'}")
    print("")
    print("Next: edit .aios/invariants.yaml, then run `aios git-init` to install")
    print("      a post-commit hook that logs every commit into the event log.")
    return 0


def cmd_calibrate(args: argparse.Namespace) -> int:
    """Fit a calibrator for a skill and persist the §2.4 record."""
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    try:
        corpus = load_corpus_from_json(args.corpus)
    except (OSError, KeyError, ValueError) as e:
        sys.stderr.write(f"error: could not load corpus: {e}\n")
        return 2

    try:
        record = _calibrate(
            args.skill_id, corpus,
            method=args.method, impact=args.impact,
        )
    except CorpusQualityError as e:
        record_calibration_attempt(home, args.skill_id, success=False,
                                   detail=f"corpus [{e.rule}]: {e.detail}")
        sys.stderr.write(f"corpus rejected [{e.rule}]: {e.detail}\n")
        return 7
    except CalibrationQualityError as e:
        record_calibration_attempt(home, args.skill_id, success=False,
                                   detail=str(e))
        sys.stderr.write(f"calibration refused: {e}\n")
        return 7

    path = save_record(home, record)
    record_calibration_attempt(home, args.skill_id, success=True)
    print(f"calibrated {args.skill_id} with {args.method}")
    print(f"  brier:        {record.metrics_brier:.4f}  (<= {record.thresholds_brier_max})")
    print(f"  ece:          {record.metrics_ece:.4f}  (<= {record.thresholds_ece_max})")
    print(f"  corpus size:  {record.corpus_size}")
    print(f"  adversarial:  {record.corpus_adversarial_share:.3f}")
    print(f"  record:       {path}")
    return 0


def cmd_replay_incident(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    try:
        report = replay_incident_from_home(home, args.run_id)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    print(report.summary())
    if report.frame_count == 0:
        sys.stderr.write(f"warning: no frames found for run_id={args.run_id!r}\n")
        return 10
    return 0 if report.caught else 11


def cmd_credential_status(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2
    try:
        ledger = CredentialLedger(home)
    except CredentialError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2
    entities = ledger.list_entities()
    if not entities:
        print("no credentials in ledger (seed with `aios credential seed ENTITY`)")
        return 0
    print(f"{'entity':<20} {'phase':<6} {'standing':<10} {'local':<7} {'subsys':<7} {'system':<7}")
    for eid in entities:
        rec = ledger.get(eid)
        bands = rec.competency_bands
        print(f"{eid:<20} {rec.phase:<6} {rec.standing:.3f}      "
              f"{bands.get('local', bands['local']).standing:.3f}   "
              f"{bands['subsystem'].standing:.3f}   "
              f"{bands['system_wide'].standing:.3f}")
    return 0


def cmd_credential_seed(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2
    ledger = CredentialLedger(home)
    try:
        rec = ledger.seed(args.entity_id)
    except CredentialError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    ledger.save()
    print(f"seeded credential for {rec.entity_id} at phase={rec.phase} "
          f"standing={rec.standing:.3f}")
    return 0


def cmd_calibration_status(args: argparse.Namespace) -> int:
    home = _home_from_args(args)
    if not _require_initialized(home):
        return 2

    report = check_calibration_status(home, args.skill_id)
    print(f"calibration status for {report.skill_id}: {report.state.upper()}")
    print(f"  reason: {report.reason}")
    if report.last_fit_iso:
        print(f"  last_fit: {report.last_fit_iso}")
        print(f"  age_days: {report.age_days:.1f}")
        print(f"  window_days: {report.window_days}")
    if report.recent_failure_count:
        print(f"  recent_failures: {report.recent_failure_count} (30d)")

    if report.state in ("drift", "not_calibrated"):
        return 8
    if report.state == "quarantined":
        return 9
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """One-shot project scan: conservation + SK-ADR-CHECK + gate sweep."""
    repo = Path(args.repo).resolve()
    home = repo / ".aios"
    if not home.is_dir():
        sys.stderr.write(
            f"error: {repo} is not AIOS-adopted (no .aios/ directory). "
            f"Run `aios adopt {repo}` first.\n"
        )
        return 2

    # 1. Build RunState from project state (optionally diffing against before_ref).
    try:
        runstate = runstate_from_project(
            repo,
            before_ref=args.before,
            after_ref=args.after,
            impact=args.impact,
        )
    except Exception as e:
        sys.stderr.write(f"error: could not read project state: {e}\n")
        return 2

    # 2. SK-ADR-CHECK — structural ADR validation.
    try:
        adr_report = default_skill_registry.invoke(
            "SK-ADR-CHECK", {"root": str(repo)},
        )
    except Exception as e:
        sys.stderr.write(f"error: SK-ADR-CHECK failed: {e}\n")
        return 2

    # 3. Synthesize a minimal workflow manifest for the declared impact
    #    and execute it against the RunState, emitting frames into the
    #    repo's event log.
    manifest = parse_manifest(json.dumps({
        "id": "aios-check",
        "version": "0.3.0",
        "impact": args.impact,
        "required_gates": [
            "P_Q1_invariant_integrity",
            "P_Q2_state_traceability",
            "P_Q3_decision_reversibility",
        ],
    }))

    log = EventLog(home / "events")
    try:
        result = WorkflowRunner().run(manifest, runstate, log)
        # Also record the SK-ADR-CHECK result as a skill.evaluated frame.
        log.append(
            kind="skill.evaluated",
            actor="A4",
            payload={
                "skill_id": "SK-ADR-CHECK",
                "violation_count": adr_report["count"],
                "run_id": runstate.run_id,
            },
        )
    finally:
        log.close()

    # 4. Human-readable summary
    print(f"aios check — {repo}")
    print(f"  before_ref:     {args.before or '(none — working tree only)'}")
    print(f"  after_ref:      {args.after}")
    print(f"  impact:         {args.impact}")
    print(f"  invariants:     {len(runstate.invariants_after)}")
    print(f"  ADRs:           {len(runstate.adr_events)}")
    print("")
    print(f"  ADR structural violations: {adr_report['count']}")
    for v in adr_report["violations"][:5]:
        print(f"    - {v['adr_id']}: {v['kind']} — {v['detail']}")
    if adr_report["count"] > 5:
        print(f"    ... and {adr_report['count'] - 5} more")
    print("")
    print(result.summary())

    if result.outcome == "aborted":
        return 4
    if adr_report["count"] > 0 or result.outcome == "rejected":
        return 6
    return 0


def cmd_git_init(args: argparse.Namespace) -> int:
    try:
        hook_path = install_post_commit_hook(args.repo)
    except FileNotFoundError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    print(f"installed post-commit hook at {hook_path}")
    print("Commits from now on will append a commit.landed frame to .aios/events/.")
    return 0


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

    sp = sub.add_parser("adopt",
                        help="scaffold AIOS into an existing repo (.aios/ + .gitignore)")
    sp.add_argument("repo", help="repository root to adopt")
    sp.add_argument("--profile", default="P-Local",
                    choices=["P-Local", "P-Enterprise", "P-Airgap", "P-HighAssurance"])
    sp.add_argument("--force", action="store_true",
                    help="overwrite existing .aios/ config")
    sp.set_defaults(func=cmd_adopt)

    sp = sub.add_parser("git-init",
                        help="install a post-commit hook that logs commits")
    sp.add_argument("repo", nargs="?", default=".",
                    help="repository root (default: current directory)")
    sp.set_defaults(func=cmd_git_init)

    sp = sub.add_parser("calibrate",
                        help="fit a calibrator for a skill against a corpus")
    sp.add_argument("skill_id", help="skill to calibrate (e.g. SK-ADR-CHECK)")
    sp.add_argument("--corpus", required=True,
                    help="path to corpus JSON file")
    sp.add_argument("--method", default="temperature_scaling",
                    choices=["temperature_scaling", "platt_scaling"])
    sp.add_argument("--impact", default="local",
                    choices=["local", "subsystem", "system_wide"])
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_calibrate)

    sp = sub.add_parser("calibration-status",
                        help="check whether a skill's calibration is current / drift / quarantined")
    sp.add_argument("skill_id")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_calibration_status)

    sp = sub.add_parser("credential-status",
                        help="show all credentials in the ledger (phase + standing)")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_credential_status)

    sp = sub.add_parser("replay-incident",
                        help="replay a run_id's frames and attribute a G-class")
    sp.add_argument("run_id", help="run_id to replay")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_replay_incident)

    sp = sub.add_parser("credential-seed",
                        help="seed a new Phase 0 credential for ENTITY")
    sp.add_argument("entity_id", help="entity identifier (e.g. A4 or SK-ADR-CHECK)")
    sp.add_argument("--home", help="AIOS home directory")
    sp.set_defaults(func=cmd_credential_seed)

    sp = sub.add_parser("check",
                        help="one-shot project scan: Q1-Q3 + SK-ADR-CHECK")
    sp.add_argument("--repo", default=".",
                    help="project root (default: current directory)")
    sp.add_argument("--before", default=None,
                    help="git ref to diff against (default: working-tree-only)")
    sp.add_argument("--after", default="working",
                    help="git ref to check (default: 'working' = on-disk)")
    sp.add_argument("--impact", default="local",
                    choices=["local", "subsystem", "system_wide"])
    sp.set_defaults(func=cmd_check)

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
