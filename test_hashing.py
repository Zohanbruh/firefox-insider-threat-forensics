"""Integrity layer — the part that has to be right or nothing else counts."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from ffxforensics.hashing import (
    hash_directory,
    read_manifest,
    sha256_file,
    verify_manifest,
    write_manifest,
)


def test_sha256_matches_hashlib(tmp_path: Path) -> None:
    target = tmp_path / "evidence.bin"
    payload = b"forensic payload \x00\xff" * 5000
    target.write_bytes(payload)
    assert sha256_file(target) == hashlib.sha256(payload).hexdigest()


def test_hash_directory_is_deterministic_and_sorted(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "sub" / "c.txt").write_text("c")

    first = hash_directory(tmp_path)
    second = hash_directory(tmp_path)

    assert first == second, "hashing the same tree twice must give the same result"
    assert [name for name, _ in first] == ["a.txt", "b.txt", "sub/c.txt"]


def test_manifest_roundtrip(tmp_path: Path) -> None:
    (tmp_path / "one.txt").write_text("one")
    entries = hash_directory(tmp_path)
    manifest = write_manifest(entries, tmp_path / "manifest.sha256")

    parsed = read_manifest(manifest)
    assert parsed["one.txt"] == entries[0][1]


def test_verify_manifest_passes_on_untouched_tree(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "places.sqlite").write_bytes(b"database bytes")
    manifest = write_manifest(hash_directory(evidence), tmp_path / "m.sha256")

    result = verify_manifest(manifest, evidence)
    assert result.ok
    assert result.checked == 1
    assert "PASS" in result.summary()


def test_verify_manifest_detects_modification(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "places.sqlite"
    target.write_bytes(b"original")
    manifest = write_manifest(hash_directory(evidence), tmp_path / "m.sha256")

    target.write_bytes(b"tampered")

    result = verify_manifest(manifest, evidence)
    assert not result.ok
    assert result.mismatched == ["places.sqlite"]
    assert "FAIL" in result.summary()


def test_verify_manifest_detects_deletion(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "gone.txt").write_text("here")
    manifest = write_manifest(hash_directory(evidence), tmp_path / "m.sha256")
    (evidence / "gone.txt").unlink()

    result = verify_manifest(manifest, evidence)
    assert result.missing == ["gone.txt"]
    assert not result.ok


def test_strict_mode_flags_added_files(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "known.txt").write_text("known")
    manifest = write_manifest(hash_directory(evidence), tmp_path / "m.sha256")
    (evidence / "planted.txt").write_text("planted after acquisition")

    lenient = verify_manifest(manifest, evidence)
    strict = verify_manifest(manifest, evidence, strict=True)

    assert lenient.ok, "a file added after acquisition is invisible without --strict"
    assert strict.unexpected == ["planted.txt"]
    assert not strict.ok


@pytest.mark.skipif(
    subprocess.run(["which", "sha256sum"], capture_output=True).returncode != 0,
    reason="coreutils sha256sum not available",
)
def test_manifest_is_readable_by_coreutils(tmp_path: Path) -> None:
    """A third party must be able to check our manifest without this toolkit."""
    evidence = tmp_path / "Firefox-Linux-Evidence"
    evidence.mkdir()
    (evidence / "places.sqlite").write_bytes(b"db")
    (evidence / "cookies.sqlite").write_bytes(b"ck")

    write_manifest(
        hash_directory(evidence),
        tmp_path / "all.sha256",
        prefix="Firefox-Linux-Evidence",
    )

    completed = subprocess.run(
        ["sha256sum", "-c", "all.sha256"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.count(": OK") == 2


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "real.txt").write_text("real")
    try:
        (evidence / "link.txt").symlink_to(evidence / "real.txt")
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks unsupported on this platform")

    names = [name for name, _ in hash_directory(evidence)]
    assert names == ["real.txt"]
