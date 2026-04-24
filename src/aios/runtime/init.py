"""AIOS directory initialization (sprint 3).

Per Distribution Spec §4.1 install contract:
  - Event log initialized at the configured path with a genesis event.
  - Config with constitution/kernel/distribution/verification/runtime-protocol
    spec versions and profile declaration.
  - `install.complete` event (seq=0) and `profile.declared` event (seq=1)
    written at init time per Runtime Protocol §10.5.

The subdirectory layout mirrors the §4.1 post-install state:

  <root>/
    events/          <- EventLog segment files
    registry/        <- workflow/skill manifests (empty for v1 P-Local)
    projections/     <- materialized state (empty until snapshots)
    credentials/     <- credential records (empty in Phase 0)
    config.json      <- profile + spec version declaration
"""
from __future__ import annotations

import dataclasses as dc
import json
from pathlib import Path

from aios import __spec_versions__, __version__
from aios.runtime.event_log import EventLog

VALID_PROFILES = ("P-Local", "P-Enterprise", "P-Airgap", "P-HighAssurance")

# P-Local is the only profile the v1 loader fully supports. Declaring
# anything else at init time is allowed but the loader will refuse to
# start until the missing mechanisms are implemented (Runtime §10.6).
DEFAULT_PROFILE = "P-Local"


@dc.dataclass(frozen=True)
class InitResult:
    root: Path
    profile: str
    events_dir: Path
    config_path: Path
    install_seq: int
    profile_seq: int


def init_aios_home(root: str | Path, *, profile: str = DEFAULT_PROFILE,
                   force: bool = False) -> InitResult:
    """Initialize an AIOS home directory. Returns paths + seq numbers written.

    Raises FileExistsError if the directory is already initialized and
    `force` is False.
    """
    if profile not in VALID_PROFILES:
        raise ValueError(
            f"unknown profile {profile!r}; valid: {', '.join(VALID_PROFILES)}"
        )

    root_path = Path(root).resolve()
    config_path = root_path / "config.json"

    if config_path.exists() and not force:
        raise FileExistsError(
            f"AIOS home already initialized at {root_path} "
            f"(config.json present). Pass force=True to reinitialize."
        )

    # Create the directory layout per Distribution Spec §4.1
    for sub in ("events", "registry", "projections", "credentials"):
        (root_path / sub).mkdir(parents=True, exist_ok=True)

    # Write the configuration
    config = {
        "aios_version": __version__,
        "spec_versions": __spec_versions__,
        "profile": profile,
        "paths": {
            "events": "events",
            "registry": "registry",
            "projections": "projections",
            "credentials": "credentials",
        },
    }
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")

    # Write genesis install.complete and profile.declared events (§10.5)
    log = EventLog(root_path / "events")
    try:
        install_frame = log.append(
            kind="install.complete",
            actor="A5",
            payload={
                "aios_version": __version__,
                "spec_versions": __spec_versions__,
            },
        )
        profile_frame = log.append(
            kind="profile.declared",
            actor="A5",
            payload={
                "profile": profile,
                "declared_at_seq": install_frame.seq,
            },
        )
    finally:
        log.close()

    return InitResult(
        root=root_path,
        profile=profile,
        events_dir=root_path / "events",
        config_path=config_path,
        install_seq=install_frame.seq,
        profile_seq=profile_frame.seq,
    )


def read_config(root: str | Path) -> dict:
    """Read the config.json from an initialized AIOS home."""
    root_path = Path(root).resolve()
    config_path = root_path / "config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"no AIOS config at {config_path}")
    return json.loads(config_path.read_text(encoding="utf-8"))


def is_initialized(root: str | Path) -> bool:
    return (Path(root) / "config.json").exists()
