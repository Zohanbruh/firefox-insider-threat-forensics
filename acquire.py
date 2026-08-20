"""
Acquisition & preservation — ACPO Principles 1, 2 and 3.

This module is the programmatic equivalent of the shell sequence recorded in
the Case 029 audit trail::

    cp -rp <profile> Firefox-Linux-Evidence
    zip -r Firefox-Linux-Evidence.zip Firefox-Linux-Evidence/*
    sha256sum Firefox-Linux-Evidence.zip > Firefox-Linux-Evidence.zip.sha256
    find Firefox-Linux-Evidence/ -type f -exec sha256sum {} \\; > ...-all.sha256
    find Firefox-Linux-Evidence/ -type f -exec chmod 400 {} \\;

Doing it in one auditable call removes the two failure modes seen in manual
acquisition: forgetting a hash step, and mistyping a path so the wrong tree is
hashed.  The original profile is opened read-only and is never modified.
"""

from __future__ import annotations

import os
import shutil
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from ffxforensics.audit import AuditTrail
from ffxforensics.hashing import hash_directory, sha256_file, write_manifest

#: Files that carry evidential value in a Firefox profile.
KEY_ARTEFACTS = (
    "places.sqlite",
    "cookies.sqlite",
    "formhistory.sqlite",
    "favicons.sqlite",
    "permissions.sqlite",
    "webappsstore.sqlite",
    "content-prefs.sqlite",
    "sessionstore.jsonlz4",
    "prefs.js",
    "extensions.json",
    "logins.json",
    "handlers.json",
    "search.json.mozlz4",
)


@dataclass
class AcquisitionResult:
    """Everything produced by :func:`acquire_profile`."""

    source_profile: Path
    evidence_dir: Path
    archive_path: Optional[Path]
    archive_hash: Optional[str]
    archive_manifest: Optional[Path]
    file_manifest: Path
    file_count: int
    total_bytes: int
    key_artefacts_found: List[str] = field(default_factory=list)
    key_artefacts_missing: List[str] = field(default_factory=list)
    hashes: List[Tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"Source profile   : {self.source_profile}",
            f"Evidence copy    : {self.evidence_dir}",
            f"Files acquired   : {self.file_count} ({self.total_bytes:,} bytes)",
            f"File manifest    : {self.file_manifest}",
        ]
        if self.archive_path:
            lines.append(f"Archive          : {self.archive_path}")
            lines.append(f"Archive SHA-256  : {self.archive_hash}")
        lines.append(
            "Key artefacts    : "
            + (", ".join(self.key_artefacts_found) or "none found")
        )
        if self.key_artefacts_missing:
            lines.append(
                "Missing artefacts: " + ", ".join(self.key_artefacts_missing)
            )
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "source_profile": str(self.source_profile),
            "evidence_dir": str(self.evidence_dir),
            "archive_path": str(self.archive_path) if self.archive_path else None,
            "archive_sha256": self.archive_hash,
            "file_manifest": str(self.file_manifest),
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "key_artefacts_found": self.key_artefacts_found,
            "key_artefacts_missing": self.key_artefacts_missing,
        }


def set_read_only(root: os.PathLike | str) -> int:
    """chmod 0400 every file below ``root``; returns the count changed.

    Guards against accidental modification of the working copy during
    analysis, mirroring ``find ... -exec chmod 400 {} \\;`` in the audit trail.
    """
    changed = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            target = Path(dirpath) / name
            try:
                os.chmod(target, stat.S_IRUSR)
                changed += 1
            except OSError:  # pragma: no cover - platform dependent
                continue
    return changed


def restore_write_access(root: os.PathLike | str) -> int:
    """Re-enable owner write access (needed to delete a locked working copy)."""
    changed = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            target = Path(dirpath) / name
            try:
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
                changed += 1
            except OSError:  # pragma: no cover
                continue
    return changed


def create_archive(source_dir: os.PathLike | str, archive_path: os.PathLike | str) -> Path:
    """Zip ``source_dir`` deterministically (sorted entries, fixed timestamps).

    Deterministic ordering matters: two examiners acquiring the same tree must
    be able to produce the same archive hash.
    """
    source_dir = Path(source_dir)
    archive_path = Path(archive_path)
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    entries: List[Tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(source_dir):
        dirnames.sort()
        for name in sorted(filenames):
            file_path = Path(dirpath) / name
            arcname = (Path(source_dir.name) / file_path.relative_to(source_dir)).as_posix()
            entries.append((arcname, file_path))
    entries.sort(key=lambda item: item[0])

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, file_path in entries:
            info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o400 << 16
            zf.writestr(info, file_path.read_bytes())
    return archive_path


def acquire_profile(
    source_profile: os.PathLike | str,
    output_dir: os.PathLike | str,
    evidence_name: str = "Firefox-Linux-Evidence",
    make_archive: bool = True,
    lock_read_only: bool = True,
    trail: Optional[AuditTrail] = None,
) -> AcquisitionResult:
    """Create a hashed, verifiable forensic copy of a Firefox profile.

    Parameters
    ----------
    source_profile:
        Path to the live profile directory (e.g.
        ``~/.mozilla/firefox/69mytvds.default-esr``).  Opened read-only.
    output_dir:
        Working directory to receive the evidence copy, archive and manifests.
    evidence_name:
        Base name for the evidence directory / archive / manifests.
    make_archive:
        Also produce ``<evidence_name>.zip`` plus its ``.sha256`` sidecar.
    lock_read_only:
        chmod 0400 the copied files once hashing has completed.
    trail:
        Optional :class:`AuditTrail` to receive one entry per step.
    """
    source_profile = Path(source_profile).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()

    if not source_profile.is_dir():
        raise NotADirectoryError(f"Profile directory not found: {source_profile}")

    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / evidence_name

    if evidence_dir.exists():
        raise FileExistsError(
            f"Refusing to overwrite an existing evidence directory: {evidence_dir}"
        )

    def log(phase: str, tool: str, command: str, explanation: str, artefact: str = "",
            hash_value: str = "") -> None:
        if trail is not None:
            trail.record(phase, tool, command, explanation, artefact, hash_value)

    log(
        "Evidence Identification",
        "ffxforensics.acquire",
        f"stat {source_profile}",
        "Located and validated the suspect Firefox profile directory",
        str(source_profile),
    )

    # --- Principle 1: copy, never work on the original --------------------
    shutil.copytree(source_profile, evidence_dir, symlinks=True, dirs_exist_ok=False)
    log(
        "Evidence Collection",
        "shutil.copytree (cp -rp equivalent)",
        f"cp -rp {source_profile} {evidence_dir}",
        "Created forensic copy of the profile preserving structure and metadata",
        str(evidence_dir),
    )

    # --- Principle 2: hash everything ------------------------------------
    hashes = hash_directory(evidence_dir)
    file_manifest = output_dir / f"{evidence_name}-all.sha256"
    write_manifest(hashes, file_manifest, prefix=evidence_name)
    total_bytes = sum(
        (evidence_dir / rel).stat().st_size for rel, _digest in hashes
    )
    log(
        "Evidence Preservation",
        "ffxforensics.hashing",
        f"find {evidence_name}/ -type f -exec sha256sum {{}} \\; > {file_manifest.name}",
        f"Computed SHA-256 for all {len(hashes)} acquired files",
        str(file_manifest),
    )

    archive_path: Optional[Path] = None
    archive_hash: Optional[str] = None
    archive_manifest: Optional[Path] = None
    if make_archive:
        archive_path = create_archive(evidence_dir, output_dir / f"{evidence_name}.zip")
        archive_hash = sha256_file(archive_path)
        archive_manifest = output_dir / f"{evidence_name}.zip.sha256"
        write_manifest([(archive_path.name, archive_hash)], archive_manifest)
        log(
            "Evidence Preservation",
            "zipfile / ffxforensics.hashing",
            f"zip -r {archive_path.name} {evidence_name}/* && sha256sum {archive_path.name}",
            "Compressed the evidence set for transfer and recorded its hash",
            str(archive_path),
            archive_hash,
        )

    present = {path.name for path in evidence_dir.rglob("*") if path.is_file()}
    found = [name for name in KEY_ARTEFACTS if name in present]
    missing = [name for name in KEY_ARTEFACTS if name not in present]

    if lock_read_only:
        locked = set_read_only(evidence_dir)
        log(
            "Evidence Preservation",
            "os.chmod",
            f"find {evidence_name}/ -type f -exec chmod 400 {{}} \\;",
            f"Set {locked} evidence files to read-only prior to analysis",
            str(evidence_dir),
        )

    return AcquisitionResult(
        source_profile=source_profile,
        evidence_dir=evidence_dir,
        archive_path=archive_path,
        archive_hash=archive_hash,
        archive_manifest=archive_manifest,
        file_manifest=file_manifest,
        file_count=len(hashes),
        total_bytes=total_bytes,
        key_artefacts_found=found,
        key_artefacts_missing=missing,
        hashes=hashes,
    )
