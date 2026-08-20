"""
End-to-end smoke test — Case 029.

This is the regression test that matters most. It runs the complete pipeline
(generate → acquire → verify → analyse → report) and checks the output against
the **published grids of the Case 029 examination report**, value by value and
timestamp by timestamp.

If a future change to a parser, a query or a timestamp conversion breaks
agreement with the report, this test fails and says exactly which grid moved.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ffxforensics.acquire import acquire_profile, restore_write_access
from ffxforensics.audit import AuditTrail
from ffxforensics.case import CaseAnalyser, CaseMetadata
from ffxforensics.hashing import verify_manifest
from ffxforensics.report.exporters import export_all
from ffxforensics.report.html import write_html
from ffxforensics.report.markdown import write_markdown
from ffxforensics.sampledata import build_case_029
from ffxforensics.timeutil import parse_tz

CASE_TZ = "+01:00"


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Run the whole workflow once and hand every stage's output to the tests."""
    base = tmp_path_factory.mktemp("smoke")
    profile = build_case_029(base / "source", tz_spec=CASE_TZ)

    trail = AuditTrail(case_id="029", examiner="A. Adhikari")
    acquisition = acquire_profile(
        profile,
        base / "working_directory",
        evidence_name="Firefox-Linux-Evidence",
        lock_read_only=False,  # keep the tree writable so pytest can clean up
        trail=trail,
    )

    verification = verify_manifest(acquisition.file_manifest, acquisition.evidence_dir)

    analyser = CaseAnalyser(
        acquisition.evidence_dir,
        metadata=CaseMetadata(
            case_id="029",
            examiner="A. Adhikari",
            subject="Manisha Rao",
            organisation="NeoQuant Finance Limited",
            device="Dell OptiPlex 7090 MT",
            operating_system="Ubuntu GNU/Linux 24.04.1 LTS (64-bit)",
            browser="Firefox ESR 128.13.0 (64-bit)",
        ),
        tz=parse_tz(CASE_TZ),
        trail=trail,
    )
    result = analyser.run()
    result.integrity = verification.as_dict()

    out_dir = base / "results"
    export_all(result, out_dir)
    write_markdown(result, out_dir / "examination_report.md", trail)
    write_html(result, out_dir / "examination_report.html", trail)

    restore_write_access(acquisition.evidence_dir)
    return {
        "profile": profile,
        "acquisition": acquisition,
        "verification": verification,
        "result": result,
        "out_dir": out_dir,
        "trail": trail,
    }


def _csv_rows(path: Path) -> list:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


# --------------------------------------------------------------------------
# acquisition and integrity
# --------------------------------------------------------------------------
def test_evidence_set_contains_fifty_files(pipeline) -> None:
    """The report records 50 files in the Firefox-Linux-Evidence directory."""
    assert pipeline["acquisition"].file_count == 50


def test_manifest_verifies_after_acquisition(pipeline) -> None:
    verification = pipeline["verification"]
    assert verification.ok, verification.summary()
    assert verification.checked == 50


def test_analysis_did_not_alter_the_evidence(pipeline) -> None:
    """Re-verify after the full analysis run: hashes must be unchanged."""
    acquisition = pipeline["acquisition"]
    again = verify_manifest(acquisition.file_manifest, acquisition.evidence_dir)
    assert again.ok, again.summary()


def test_every_artefact_passed_its_integrity_check(pipeline) -> None:
    for artefact in pipeline["result"].artefacts.values():
        assert artefact["integrity_check"] == "ok"
        assert len(artefact["sha256"]) == 64


# --------------------------------------------------------------------------
# Grid 4.2 — search queries
# --------------------------------------------------------------------------
GRID_4_2 = {
    "NeoQuant sql error page exploit": "2025-12-02 15:16:22",
    "Test sql injection using browser only": "2025-12-02 15:17:40",
    "Find exposed database endpoints in API": "2025-12-02 15:18:31",
    "Financial api sql injection examples": "2025-12-02 15:19:06",
    "How to force debug mode using URL parameters": "2025-12-02 15:19:41",
    "Bypass client-side validation by modifying URL": "2025-12-02 15:20:16",
    "Common api parameters that leak database info": "2025-12-02 15:21:00",
    "Check API vulnerabilities using chrome DevTools network tab": "2025-12-02 15:21:49",
    "Common api vectors.pdf download": "2025-12-02 15:23:11",
    "Neoquant finance - internal API docs": "2025-12-02 15:28:57",
    "request inspector- test API requests": "2025-12-02 15:30:09",
    "chrome devtools network inspector guide": "2025-12-02 15:31:14",
}


@pytest.mark.parametrize("query,timestamp", sorted(GRID_4_2.items()))
def test_grid_4_2_search_queries(pipeline, query, timestamp) -> None:
    recovered = {
        search.query: search.last_visited_str for search in pipeline["result"].searches
    }
    assert query in recovered, f"Grid 4.2 query missing from output: {query!r}"
    assert recovered[query] == timestamp


def test_grid_4_2_is_a_subset_of_what_the_tool_recovers(pipeline) -> None:
    """The report tabulated the notable queries; the tool recovers all of them."""
    queries = {search.query for search in pipeline["result"].searches}
    assert set(GRID_4_2) <= queries
    assert len(queries) >= len(GRID_4_2)


# --------------------------------------------------------------------------
# Grid 4.3 — video activity
# --------------------------------------------------------------------------
GRID_4_3 = {
    "https://www.youtube.com/watch?v=0Izu0J6iSoM": (
        "Firewall Penetration Testing: Steps, Methods, and Tools",
        "2025-12-02 15:36:46",
    ),
    "https://www.youtube.com/watch?v=QtwhEz-aON4": (
        "AI Security Exposed: Why 95% of Companies Are Vulnerable",
        "2025-12-02 15:35:37",
    ),
    "https://www.youtube.com/watch?v=8zSoyAmHHc4": (
        "Threats Vulnerabilities and Exploits",
        "2025-12-02 15:34:50",
    ),
    "https://www.youtube.com/watch?v=GD88Pp75Klw": (
        "Using a LAN scan to find INTERNAL vulnerabilities",
        "2025-12-02 15:33:21",
    ),
}


def test_grid_4_3_video_activity(pipeline) -> None:
    recovered = {
        visit.url: (visit.title, visit.visit_date_str)
        for visit in pipeline["result"].video_visits
    }
    assert recovered == GRID_4_3


def test_grid_4_3_is_ordered_newest_first(pipeline) -> None:
    stamps = [visit.visit_date for visit in pipeline["result"].video_visits]
    assert stamps == sorted(stamps, reverse=True)


# --------------------------------------------------------------------------
# Grid 4.4 / Image 3 — bookmarks
# --------------------------------------------------------------------------
GRID_4_4 = {
    "Inspect network activity | Chrome DevTools | Chrome for developers": "2025-12-02 15:31:22",
    "Competitive Analysis | Similarweb": "2025-12-02 15:30:54",
    "Web Request Inspector & Probe Service | Request Inspector": "2025-12-02 15:30:20",
    # Image 3 (the SQL output) shows 15:29:45; the Grid 4.4 prose table shows
    # 15:29:11. The query output is treated as authoritative — see
    # docs/CASE_029_REFERENCE.md.
    "SQL Injection | OWASP Foundation": "2025-12-02 15:29:45",
    "white papers - NeoQuant": "2025-12-02 15:29:11",
}


def test_grid_4_4_bookmarks(pipeline) -> None:
    recovered = {
        bookmark.title: bookmark.last_modified_str
        for bookmark in pipeline["result"].bookmark_entries
    }
    assert recovered == GRID_4_4


def test_image_3_returns_eleven_bookmark_rows(pipeline) -> None:
    """Image 3 of the report shows 11 rows returned from moz_bookmarks."""
    assert len(pipeline["result"].bookmarks) == 11


def test_root_folders_predate_the_session(pipeline) -> None:
    folders = {b.title: b.last_modified_str for b in pipeline["result"].bookmarks if b.is_folder}
    assert folders["unfiled"] == "2025-10-01 16:01:59"
    assert folders["mobile"] == "2025-10-01 16:01:59"
    assert folders["tags"] == "2025-10-01 16:01:59"
    assert folders["menu"] == "2025-12-02 15:02:16"


# --------------------------------------------------------------------------
# Grid 4.5 — visit categories
# --------------------------------------------------------------------------
GRID_4_5 = {1: 29, 2: 19, 3: 0, 4: 0, 5: 3, 6: 5}


def test_grid_4_5_visit_categories(pipeline) -> None:
    recovered = {
        code: data["count"] for code, data in pipeline["result"].visit_types.items()
    }
    assert recovered == GRID_4_5


def test_grid_4_5_totals_match_the_visit_table(pipeline) -> None:
    assert sum(GRID_4_5.values()) == len(pipeline["result"].visits) == 56


# --------------------------------------------------------------------------
# downloads, timeline and narrative
# --------------------------------------------------------------------------
def test_download_recorded_in_the_audit_trail_is_recovered(pipeline) -> None:
    downloads = pipeline["result"].downloads
    assert len(downloads) == 1
    assert downloads[0].file_name == "Common-API-Attack-Vectors.pdf"


def test_activity_is_a_single_continuous_session(pipeline) -> None:
    sessions = pipeline["result"].sessions
    assert len(sessions) == 1
    assert 1200 < sessions[0].duration_seconds < 1320  # ~21 minutes


def test_timeline_starts_and_ends_where_expected(pipeline) -> None:
    timeline = pipeline["result"].timeline
    # Bookmark *folders* are excluded, so the timeline opens with the first
    # navigation event, not the 15:02:16 folder touch.
    assert timeline[0].timestamp_str == "2025-12-02 15:15:40"  # browser opened
    assert timeline[-1].timestamp_str == "2025-12-02 15:36:46"  # last video watched


# --------------------------------------------------------------------------
# triage behaviour
# --------------------------------------------------------------------------
def test_expected_indicator_categories_fire(pipeline) -> None:
    triggered = set(pipeline["result"].assessment["rules_triggered"])
    assert {
        "sql_injection",
        "api_enumeration",
        "control_bypass",
        "network_recon",
        "security_tooling",
        "target_organisation",
    } <= triggered


def test_no_exfiltration_or_antiforensics_indicators_in_this_case(pipeline) -> None:
    """The report found no evidence of these; the tool must not invent them."""
    triggered = set(pipeline["result"].assessment["rules_triggered"])
    assert "data_exfiltration" not in triggered
    assert "anti_forensics" not in triggered


def test_conclusion_remains_inconclusive(pipeline) -> None:
    """The report declined to infer intent. The toolkit must do the same."""
    interpretation = pipeline["result"].assessment["interpretation"]
    assert interpretation["verdict"].startswith("INCONCLUSIVE")
    assert len(interpretation["innocent_explanations"]) >= 3
    assert interpretation["recommended_corroboration"]


# --------------------------------------------------------------------------
# outputs
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "filename",
    [
        "searches.csv",
        "history.csv",
        "visits.csv",
        "video_visits.csv",
        "bookmarks.csv",
        "cookies.csv",
        "form_history.csv",
        "downloads.csv",
        "visit_types.csv",
        "timeline.csv",
        "findings.json",
        "examination_report.md",
        "examination_report.html",
    ],
)
def test_expected_output_file_is_written(pipeline, filename) -> None:
    path = pipeline["out_dir"] / filename
    assert path.exists(), f"missing output: {filename}"
    assert path.stat().st_size > 0


def test_visit_types_csv_matches_grid_4_5(pipeline) -> None:
    rows = _csv_rows(pipeline["out_dir"] / "visit_types.csv")
    counts = {int(row["visit_category"]): int(row["web_presence_count"]) for row in rows}
    assert counts == GRID_4_5


def test_findings_json_round_trips(pipeline) -> None:
    payload = json.loads((pipeline["out_dir"] / "findings.json").read_text())
    assert payload["case"]["subject"] == "Manisha Rao"
    assert payload["integrity"]["verdict"] == "PASS"
    assert len(payload["video_visits"]) == 4


def test_reports_name_the_case_and_the_caveat(pipeline) -> None:
    markdown = (pipeline["out_dir"] / "examination_report.md").read_text()
    html = (pipeline["out_dir"] / "examination_report.html").read_text()
    for document in (markdown, html):
        assert "029" in document
        assert "INCONCLUSIVE" in document
        assert "ACPO" in document


def test_audit_trail_covers_the_full_workflow(pipeline) -> None:
    phases = {entry.phase for entry in pipeline["trail"]}
    assert {
        "Evidence Identification",
        "Evidence Collection",
        "Evidence Preservation",
        "Analysing",
    } <= phases
    assert len(pipeline["trail"]) >= 8
