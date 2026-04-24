"""Package integrity verifier (sprint 52).

Distribution Spec §8.1 says integrity checks run at install-time
(signature) and at load-time (hash chain). This module covers a gap
between those two: after install, a developer or an auditor can verify
that the installed package files exactly match the shipped manifest.
No cryptography required — SHA-256 of every file + whole-tree manifest
hash. Signatures are the sprint-55 release-bundle concern.

Workflow:

    # At build time (release pipeline)
    manifest = build_integrity_manifest(src_root)
    manifest.to_json_path(release_dir / "integrity.manifest.json")

    # At install time (shipped with the release)
    loaded = IntegrityManifest.from_json_path(home / "integrity.manifest.json")
    report = verify_install(src_root, loaded)
    assert report.ok
"""
from __future__ import annotations

import dataclasses as dc
import datetime as _dt
import hashlib
import json
from pathlib import Path

MANIFEST_VERSION = "1.0"


@dc.dataclass(frozen=True)
class FileEntry:
    path: str            # path relative to `root`, forward-slashed
    sha256: str          # hex digest
    size: int


@dc.dataclass(frozen=True)
class IntegrityManifest:
    root: str
    manifest_version: str
    generated_iso: str
    files: tuple[FileEntry, ...]

    @property
    def tree_sha256(self) -> str:
        """Deterministic hash of the whole manifest — sorted by path,
        joined with newline. Changes if any file changes or is
        added/removed."""
        h = hashlib.sha256()
        for f in sorted(self.files, key=lambda x: x.path):
            h.update(f"{f.path}\t{f.sha256}\t{f.size}\n".encode("utf-8"))
        return h.hexdigest()

    def to_dict(self) -> dict:
        return {
            "manifest_version": self.manifest_version,
            "root": self.root,
            "generated_iso": self.generated_iso,
            "tree_sha256": self.tree_sha256,
            "files": [
                {"path": f.path, "sha256": f.sha256, "size": f.size}
                for f in sorted(self.files, key=lambda x: x.path)
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_json_path(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(self.to_json() + "\n", encoding="utf-8")
        return p

    @classmethod
    def from_dict(cls, data: dict) -> "IntegrityManifest":
        if data.get("manifest_version") != MANIFEST_VERSION:
            raise ValueError(
                f"unsupported manifest version: {data.get('manifest_version')}"
            )
        files = tuple(
            FileEntry(
                path=f["path"],
                sha256=f["sha256"],
                size=int(f["size"]),
            )
            for f in data.get("files", [])
        )
        return cls(
            root=data["root"],
            manifest_version=data["manifest_version"],
            generated_iso=data["generated_iso"],
            files=files,
        )

    @classmethod
    def from_json_path(cls, path: str | Path) -> "IntegrityManifest":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


@dc.dataclass(frozen=True)
class IntegrityReport:
    ok: bool
    missing: tuple[str, ...]         # in manifest, absent on disk
    extra: tuple[str, ...]           # on disk, absent from manifest
    mismatched: tuple[str, ...]      # hash does not match
    tree_sha256_expected: str
    tree_sha256_actual: str


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_integrity_manifest(
    root: str | Path,
    *,
    include_extensions: tuple[str, ...] = (".py", ".json", ".yaml", ".yml",
                                            ".md", ".toml", ".txt", ".cfg"),
    exclude_names: tuple[str, ...] = ("__pycache__", ".pytest_cache",
                                       ".git", ".aios", "dist", "build",
                                       "aios_home"),
) -> IntegrityManifest:
    """Walk `root` and build a manifest of every matching file.

    Default filter includes source + config files only — excludes
    __pycache__, .git, and runtime-state directories that are expected
    to differ between installs. Add more extensions / exclude more
    names as needed.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"{root_path} is not a directory")

    entries: list[FileEntry] = []
    for fp in _walk(root_path, include_extensions, exclude_names):
        rel = fp.relative_to(root_path).as_posix()
        raw = fp.read_bytes()
        entries.append(FileEntry(
            path=rel,
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
        ))

    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return IntegrityManifest(
        root=root_path.name,
        manifest_version=MANIFEST_VERSION,
        generated_iso=ts,
        files=tuple(entries),
    )


def _walk(root: Path, include_ext: tuple[str, ...],
          exclude_names: tuple[str, ...]):
    for path in root.rglob("*"):
        # Skip excluded directories in any ancestor
        if any(part in exclude_names for part in path.parts):
            continue
        if not path.is_file():
            continue
        if include_ext and path.suffix.lower() not in include_ext:
            continue
        yield path


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def verify_install(
    root: str | Path,
    manifest: IntegrityManifest,
    *,
    check_extras: bool = True,
) -> IntegrityReport:
    """Recompute hashes under `root` + compare to `manifest`.

    `check_extras=False` makes the report tolerate extra files on disk
    not present in the manifest (useful when the caller wants to verify
    a subtree without a full snapshot of every file).
    """
    current = build_integrity_manifest(
        root,
        include_extensions=_inferred_extensions(manifest),
        exclude_names=(),  # manifest may explicitly list these
    )
    current_by_path = {f.path: f for f in current.files}
    manifest_by_path = {f.path: f for f in manifest.files}

    missing: list[str] = []
    extra: list[str] = []
    mismatched: list[str] = []

    for path, entry in manifest_by_path.items():
        live = current_by_path.get(path)
        if live is None:
            missing.append(path)
            continue
        if live.sha256 != entry.sha256 or live.size != entry.size:
            mismatched.append(path)

    if check_extras:
        for path in current_by_path:
            if path not in manifest_by_path:
                extra.append(path)

    ok = not missing and not mismatched and (not extra or not check_extras)
    return IntegrityReport(
        ok=ok,
        missing=tuple(sorted(missing)),
        extra=tuple(sorted(extra)),
        mismatched=tuple(sorted(mismatched)),
        tree_sha256_expected=manifest.tree_sha256,
        tree_sha256_actual=current.tree_sha256,
    )


def _inferred_extensions(m: IntegrityManifest) -> tuple[str, ...]:
    """Pull the set of file suffixes out of a manifest so re-walking
    the tree picks up the same file set the manifest captured."""
    exts: set[str] = set()
    for f in m.files:
        suffix = Path(f.path).suffix.lower()
        if suffix:
            exts.add(suffix)
    return tuple(sorted(exts)) if exts else (".py",)
