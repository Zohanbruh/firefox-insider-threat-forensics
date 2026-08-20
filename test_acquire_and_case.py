"""Acquisition, case orchestration and report generation."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from ffxforensics.acquire import (
    acquire_profile,
    create_archive,
    restore_write_access,
    set_read_only,
)
from ffxforensics.audit import AuditTrail
from ffxforensics.case import CaseAnalyser, CaseMetadata
from ffxforensics.hashing import sha256_file, verify_manifest
from ffxforensics.report.exporters import export_all, export_findings_json
from ffxforensics.report.html import render_html
from ffxforensics.report.markdown import render_markdown


# --------------------------------------------------------------------------
# acquisition
# --------------------------------------------------------------------------
def test_acquisition_produces_a_verifiable_copy(sample_profile: Path, tmp_path: Path) -> None:
    trail = AuditTrail(case_id="029")
    result = acquire_profile(sample_profile, tmp_path / "wd", trail=trail)

    assert result.file_count == 50
    assert result.evidence_dir.is_dir()
    assert result.archive_path and result.archive_path.exists()
    assert len(result.archive_hash or "") == 64

    verification = verify_manifest(result.file_manifest, result.evidence_dir)
    assert verification.ok, verification.summary()

    # every ACPO phase should be represented in the trail
    phases = {entry.phase for entry in trail}
    assert {"Evidence Identification", "Evidence Collection", "Evidence Preservation"} <= phases


def test_acquisition_leaves_the_source_untouched(sample_profile: Path, tmp_path: Path) -> None:
    before = sha256_file(sample_profile / "places.sqlite")
    acquire_profile(sample_profile, tmp_path / "wd")
    assert sha256_file(sample_profile / "places.sqlite") == before


def test_acquisition_identifies_key_artefacts(sample_profile: Path, tmp_path: Path) -> None:
    result = acquire_profile(sample_profile, tmp_path / "wd")
    assert "places.sqlite" in result.key_artefacts_found
    assert "cookies.sqlite" in result.key_artefacts_found
    assert "formhistory.sqlite" in result.key_artefacts_found


def test_acquisition_refuses_to_overwrite(sample_profile: Path, tmp_path: Path) -> None:
    acquire_profile(sample_profile, tmp_path / "wd")
    with pytest.raises(FileExistsError):
        acquire_profile(sample_profile, tmp_path / "wd")


def test_acquisition_rejects_a_missing_profile(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        acquire_profile(tmp_path / "no-such-profile", tmp_path / "wd")


@pytest.mark.skipif(
    hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0,
    reason="chmod does not restrict root; run as an unprivileged user to exercise this",
)
def test_read_only_lock_prevents_writes(sample_profile: Path, tmp_path: Path) -> None:
    result = acquire_profile(sample_profile, tmp_path / "wd", lock_read_only=True)
    target = result.evidence_dir / "places.sqlite"
    with pytest.raises(PermissionError):
        target.open("ab")
    restore_write_access(result.evidence_dir)  # so pytest can clean up


def test_archive_is_deterministic(sample_profile: Path, tmp_path: Path) -> None:
    """Two examiners archiving the same tree must obtain the same hash."""
    first = create_archive(sample_profile, tmp_path / "one.zip")
    second = create_archive(sample_profile, tmp_path / "two.zip")
    assert sha256_file(first) == sha256_file(second)

    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
    assert names == sorted(names)
    assert all(name.startswith(sample_profile.name + "/") for name in names)


def test_set_read_only_reports_a_count(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    assert set_read_only(tmp_path) == 2
    restore_write_access(tmp_path)


# --------------------------------------------------------------------------
# case orchestration
# --------------------------------------------------------------------------
def test_analyser_requires_an_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        CaseAnalyser(tmp_path / "missing")


def test_analyser_finds_artefacts_in_nested_directories(sample_profile: Path, tmp_path: Path) -> None:
    """Evidence is often one level down inside an extracted archive."""
    nested = tmp_path / "Firefox-Linux-Evidence"
    nested.mkdir()
    import shutil

    shutil.copytree(sample_profile, nested / "profile")

    result = CaseAnalyser(nested).run()
    assert result.places
    assert not result.errors


def test_missing_artefacts_are_reported_not_raised(tmp_path: Path) -> None:
    empty = tmp_path / "empty-evidence"
    empty.mkdir()
    result = CaseAnalyser(empty).run()

    assert result.places == []
    assert len(result.errors) == 3
    assert any("places.sqlite" in error for error in result.errors)


def test_corroboration_separates_typed_from_merely_visited(case_result) -> None:
    corroboration = case_result.assessment["corroboration"]
    assert corroboration["confirmed_typed_count"] > 0
    assert "neoquant finance - internal api docs" in corroboration["typed_and_in_history"]
    # A YouTube results page was reached by clicking, never typed into a form.
    assert "lan scan internal vulnerabilities" in corroboration["history_only"]


def test_audit_trail_records_every_artefact(sample_profile: Path) -> None:
    trail = AuditTrail(case_id="029")
    CaseAnalyser(sample_profile, trail=trail).run()
    commands = " ".join(entry.command for entry in trail)
    assert "moz_places" in commands
    assert "moz_cookies" in commands
    assert "moz_formhistory" in commands


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def test_markdown_report_contains_every_section(case_result) -> None:
    trail = AuditTrail(case_id="029")
    trail.record("Analysing", "tool", explanation="example")
    report = render_markdown(case_result, trail)

    for heading in (
        "## 1. Investigative context",
        "## 2. Evidence handled and integrity",
        "## 3. Analysis",
        "## 4. Indicator triage",
        "## 5. Conclusion and limitations",
        "## 6. Audit trail",
    ):
        assert heading in report


def test_markdown_report_states_the_intent_caveat(case_result) -> None:
    report = render_markdown(case_result)
    assert "INCONCLUSIVE" in report
    assert "ACPO Principle 4" in report


def test_html_report_is_self_contained(case_result) -> None:
    document = render_html(case_result)
    assert document.startswith("<!DOCTYPE html>")
    assert "<style>" in document
    for external in ("http://", "https://cdn", "<script"):
        assert external not in document.split("</style>")[0], "no external assets in CSS"


def test_html_escapes_evidence_values(tmp_path: Path, case_result) -> None:
    """Evidence is untrusted input: a crafted page title must not inject markup."""
    case_result.searches[0].query = "<script>alert('xss')</script>"
    document = render_html(case_result)
    assert "<script>alert" not in document
    assert "&lt;script&gt;" in document


def test_exports_write_every_expected_file(case_result, tmp_path: Path) -> None:
    written = export_all(case_result, tmp_path)
    names = {path.name for path in written}
    assert {
        "searches.csv",
        "history.csv",
        "visits.csv",
        "bookmarks.csv",
        "timeline.csv",
        "visit_types.csv",
        "findings.json",
    } <= names
    assert all(path.exists() and path.stat().st_size > 0 for path in written)


def test_findings_json_is_valid_and_versioned(case_result, tmp_path: Path) -> None:
    path = export_findings_json(case_result, tmp_path / "findings.json")
    payload = json.loads(path.read_text())

    assert payload["schema_version"] == "1.0"
    assert payload["case"]["case_id"] == "029"
    assert payload["assessment"]["interpretation"]["verdict"].startswith("INCONCLUSIVE")
    assert len(payload["searches"]) == len(case_result.searches)


def test_report_generation_is_stable_across_runs(case_result) -> None:
    """Two renders of the same result must be identical (except the clock)."""
    first = render_markdown(case_result)
    second = render_markdown(case_result)
    assert first == second


def test_metadata_only_exports_populated_fields() -> None:
    metadata = CaseMetadata(case_id="029", examiner="")
    assert "examiner" not in metadata.as_dict()
    assert metadata.as_dict()["case_id"] == "029"
