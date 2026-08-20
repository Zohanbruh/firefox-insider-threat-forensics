"""
Integrity primitives — ACPO Principles 1 & 2.

Everything in this module is deliberately compatible with the coreutils
``sha256sum`` format used in the Case 029 audit trail::

    sha256sum Firefox-Linux-Evidence.zip > Firefox-Linux-Evidence.zip.sha256
    sha256sum -c Firefox-Linux-Evidence-all.sha256

which means manifests written here can be verified with ``sha256sum -c`` by a
third party who does not have this toolkit installed — an important property
for disclosure and peer review.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple

#: Read size for hashing.  1 MiB keeps memory flat on multi-GB evidence sets.
CHUNK_SIZE = 1024 * 1024

DEFAULT_ALGORITHM = "sha256"


class IntegrityError(Exception):
    """Raised when an integrity verification step fails hard."""


def hash_file(path: os.PathLike | str, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the hex digest of a single file, streamed in chunks."""
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: os.PathLike | str) -> str:
    """Convenience wrapper: SHA-256 hex digest of ``path``."""
    return hash_file(path, "sha256")


def iter_files(root: os.PathLike | str) -> Iterator[Path]:
    """Yield every regular file below ``root``, deterministically ordered.

    Symlinks are *not* followed: a forensic copy should hash the link target
    only if that target was itself copied into the evidence set.
    """
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            candidate = Path(dirpath) / name
            if candidate.is_file() and not candidate.is_symlink():
                yield candidate


def hash_directory(
    root: os.PathLike | str, algorithm: str = DEFAULT_ALGORITHM
) -> List[Tuple[str, str]]:
    """Hash every file under ``root``.

    Returns a list of ``(relative_posix_path, hexdigest)`` tuples sorted by
    path, so two runs over identical content always produce byte-identical
    manifests.
    """
    root = Path(root)
    entries: List[Tuple[str, str]] = []
    for file_path in iter_files(root):
        rel = file_path.relative_to(root).as_posix()
        entries.append((rel, hash_file(file_path, algorithm)))
    entries.sort(key=lambda item: item[0])
    return entries


def write_manifest(
    entries: Sequence[Tuple[str, str]],
    manifest_path: os.PathLike | str,
    prefix: str = "",
) -> Path:
    """Write a ``sha256sum``-compatible manifest.

    Each line is ``<hexdigest>  <path>`` (two spaces = binary mode marker),
    which is exactly what ``sha256sum -c`` expects.

    ``prefix`` lets you write paths relative to the manifest's parent
    directory, e.g. ``Firefox-Linux-Evidence/places.sqlite``.
    """
    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for rel, digest in entries:
        rel_path = f"{prefix.rstrip('/')}/{rel}" if prefix else rel
        lines.append(f"{digest}  {rel_path}")
    manifest_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return manifest_path


def read_manifest(manifest_path: os.PathLike | str) -> Dict[str, str]:
    """Parse a ``sha256sum`` manifest into ``{path: hexdigest}``."""
    mapping: Dict[str, str] = {}
    text = Path(manifest_path).read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts
        # coreutils prefixes binary-mode entries with '*'
        mapping[name.lstrip("*").strip()] = digest.lower()
    return mapping


@dataclass
class VerificationResult:
    """Outcome of verifying a directory against a manifest."""

    checked: int = 0
    matched: List[str] = field(default_factory=list)
    mismatched: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    unexpected: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only when every file matched and nothing is missing/extra."""
        return not (self.mismatched or self.missing or self.unexpected)

    def summary(self) -> str:
        verdict = "PASS" if self.ok else "FAIL"
        return (
            f"[{verdict}] checked={self.checked} matched={len(self.matched)} "
            f"mismatched={len(self.mismatched)} missing={len(self.missing)} "
            f"unexpected={len(self.unexpected)}"
        )

    def as_dict(self) -> dict:
        return {
            "verdict": "PASS" if self.ok else "FAIL",
            "checked": self.checked,
            "matched": len(self.matched),
            "mismatched": self.mismatched,
            "missing": self.missing,
            "unexpected": self.unexpected,
        }


def verify_manifest(
    manifest_path: os.PathLike | str,
    root: os.PathLike | str,
    algorithm: str = DEFAULT_ALGORITHM,
    strict: bool = False,
) -> VerificationResult:
    """Re-hash ``root`` and compare against ``manifest_path``.

    ``strict=True`` additionally reports files present on disk but absent from
    the manifest (``unexpected``) — evidence that something was added to the
    working copy after acquisition.
    """
    root = Path(root)
    expected = read_manifest(manifest_path)
    result = VerificationResult()

    seen: set[str] = set()
    for name, digest in sorted(expected.items()):
        candidate = root / name
        if not candidate.exists():
            # Manifests are often written relative to the parent of `root`.
            alt = root.parent / name
            candidate = alt if alt.exists() else candidate
        result.checked += 1
        if not candidate.is_file():
            result.missing.append(name)
            continue
        seen.add(candidate.resolve().as_posix())
        actual = hash_file(candidate, algorithm)
        if actual.lower() == digest.lower():
            result.matched.append(name)
        else:
            result.mismatched.append(name)

    if strict:
        for file_path in iter_files(root):
            if file_path.resolve().as_posix() not in seen:
                result.unexpected.append(file_path.relative_to(root).as_posix())

    return result


def hash_pairs_to_text(entries: Iterable[Tuple[str, str]]) -> str:
    """Render ``(path, digest)`` pairs as manifest text (no file written)."""
    return "".join(f"{digest}  {rel}\n" for rel, digest in entries)
