"""Command line interface — arguments, output and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ffxforensics.cli import EXIT_ERROR, EXIT_INTEGRITY, EXIT_OK, main


@pytest.fixture
def acquired(sample_profile: Path, tmp_path: Path) -> dict:
    """A working directory produced by `ffxforensics acquire`."""
    working = tmp_path / "wd"
    code = main([
        "acquire", str(sample_profile), str(working),
        "--no-lock", "--examiner", "A. Adhikari",
    ])
    assert code == EXIT_OK
    return {
        "working": working,
        "evidence": working / "Firefox-Linux-Evidence",
        "manifest": working / "Firefox-Linux-Evidence-all.sha256",
    }


# --------------------------------------------------------------------------
def test_version_flag_exits_cleanly(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "ffxforensics" in capsys.readouterr().out


def test_no_command_is_rejected() -> None:
    with pytest.raises(SystemExit):
        main([])


def test_sample_command_creates_a_profile(tmp_path: Path, capsys) -> None:
    assert main(["sample", str(tmp_path / "out"), "--tz", "+01:00"]) == EXIT_OK
    profile = tmp_path / "out" / "69mytvds.default-esr"
    assert (profile / "places.sqlite").exists()
    assert "Sample Case 029 profile" in capsys.readouterr().out


def test_acquire_writes_manifest_archive_and_audit(
    sample_profile: Path, tmp_path: Path, capsys
) -> None:
    audit = tmp_path / "audit.csv"
    code = main([
        "acquire", str(sample_profile), str(tmp_path / "wd"),
        "--no-lock", "--audit", str(audit),
    ])
    assert code == EXIT_OK
    assert (tmp_path / "wd" / "Firefox-Linux-Evidence.zip").exists()
    assert (tmp_path / "wd" / "Firefox-Linux-Evidence-all.sha256").exists()
    assert audit.exists()
    assert "Files acquired   : 50" in capsys.readouterr().out


def test_acquire_can_skip_the_archive(sample_profile: Path, tmp_path: Path) -> None:
    main(["acquire", str(sample_profile), str(tmp_path / "wd"), "--no-archive", "--no-lock"])
    assert not (tmp_path / "wd" / "Firefox-Linux-Evidence.zip").exists()


def test_acquire_on_a_missing_profile_returns_error(tmp_path: Path, capsys) -> None:
    code = main(["acquire", str(tmp_path / "nope"), str(tmp_path / "wd")])
    assert code == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


def test_verify_passes_on_an_intact_evidence_set(acquired, capsys) -> None:
    code = main(["verify", str(acquired["manifest"]), str(acquired["working"])])
    assert code == EXIT_OK
    assert "[PASS]" in capsys.readouterr().out


def test_verify_returns_a_distinct_exit_code_on_tampering(acquired, capsys) -> None:
    """A pipeline must be able to halt when evidence fails to verify."""
    target = acquired["evidence"] / "prefs.js"
    target.write_text(target.read_text() + "\n// altered after acquisition\n")

    code = main(["verify", str(acquired["manifest"]), str(acquired["working"])])
    assert code == EXIT_INTEGRITY
    output = capsys.readouterr().out
    assert "[FAIL]" in output
    assert "MISMATCH" in output


def test_verify_json_output_is_parseable(acquired, capsys) -> None:
    main(["verify", str(acquired["manifest"]), str(acquired["working"]), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "PASS"
    assert payload["checked"] == 50


def test_info_lists_artefacts_with_hashes(sample_profile: Path, capsys) -> None:
    assert main(["info", str(sample_profile)]) == EXIT_OK
    output = capsys.readouterr().out
    assert "places.sqlite" in output
    assert "sha256" in output
    assert "integrity: ok" in output


def test_info_json_output(sample_profile: Path, capsys) -> None:
    main(["info", str(sample_profile), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert {entry["artefact"] for entry in payload} == {"places", "cookies", "formhistory"}


def test_analyze_writes_the_full_output_set(sample_profile: Path, tmp_path: Path) -> None:
    out = tmp_path / "results"
    code = main([
        "analyze", str(sample_profile), "-o", str(out), "--tz", "+01:00",
        "--case-id", "029", "--examiner", "A. Adhikari", "--quiet",
    ])
    assert code == EXIT_OK
    for name in ("findings.json", "examination_report.md", "examination_report.html",
                 "audit_trail.csv", "summary.json", "timeline.csv"):
        assert (out / name).exists(), name


def test_analyze_respects_the_timezone_flag(sample_profile: Path, tmp_path: Path) -> None:
    """The same evidence must render differently in a different zone."""
    main(["analyze", str(sample_profile), "-o", str(tmp_path / "cet"),
          "--tz", "+01:00", "--quiet"])
    main(["analyze", str(sample_profile), "-o", str(tmp_path / "utc"),
          "--tz", "UTC", "--quiet"])

    cet = (tmp_path / "cet" / "searches.csv").read_text()
    utc = (tmp_path / "utc" / "searches.csv").read_text()
    assert "2025-12-02 15:16:22" in cet
    assert "2025-12-02 14:16:22" in utc


def test_analyze_can_skip_html(sample_profile: Path, tmp_path: Path) -> None:
    out = tmp_path / "results"
    main(["analyze", str(sample_profile), "-o", str(out), "--no-html", "--quiet"])
    assert not (out / "examination_report.html").exists()
    assert (out / "examination_report.md").exists()


def test_analyze_flags_a_failed_manifest_but_still_reports(
    acquired, tmp_path: Path
) -> None:
    target = acquired["evidence"] / "prefs.js"
    target.write_text("tampered")

    out = tmp_path / "results"
    code = main([
        "analyze", str(acquired["evidence"]), "-o", str(out),
        "--manifest", str(acquired["manifest"]), "--quiet",
    ])
    assert code == EXIT_INTEGRITY, "a failed manifest must be visible in the exit code"
    payload = json.loads((out / "findings.json").read_text())
    assert payload["integrity"]["verdict"] == "FAIL"


def test_analyze_accepts_a_custom_ruleset(sample_profile: Path, tmp_path: Path) -> None:
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([
        {"name": "only_this", "description": "", "weight": 1, "severity": "low",
         "keywords": ["neoquant"]}
    ]))
    out = tmp_path / "results"
    main(["analyze", str(sample_profile), "-o", str(out), "--rules", str(rules), "--quiet"])

    payload = json.loads((out / "findings.json").read_text())
    assert set(payload["assessment"]["rules_triggered"]) == {"only_this"}


def test_analyze_on_an_empty_directory_reports_rather_than_crashes(
    tmp_path: Path, capsys
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    code = main(["analyze", str(empty), "-o", str(tmp_path / "out")])
    assert code == EXIT_OK
    assert "places.sqlite not present" in capsys.readouterr().out


def test_analyze_rejects_an_unknown_timezone(sample_profile: Path, tmp_path: Path, capsys) -> None:
    code = main(["analyze", str(sample_profile), "-o", str(tmp_path / "o"), "--tz", "+99:00"])
    assert code == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


def test_timeline_command_prints_events(sample_profile: Path, capsys) -> None:
    assert main(["timeline", str(sample_profile), "--tz", "+01:00", "--limit", "5"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "2025-12-02" in output
    assert "event(s)" in output


def test_timeline_flagged_only_filters(sample_profile: Path, capsys) -> None:
    main(["timeline", str(sample_profile), "--flagged-only", "--limit", "200"])
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("!")]
    assert lines, "flagged events should exist in this scenario"


def test_search_command_finds_a_known_term(sample_profile: Path, capsys) -> None:
    assert main(["search", str(sample_profile), "sql injection"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "match(es)" in output
    assert "sql injection" in output.lower()


def test_search_reports_zero_matches_cleanly(sample_profile: Path, capsys) -> None:
    main(["search", str(sample_profile), "zzz-not-present-zzz"])
    assert "0 match(es)" in capsys.readouterr().out
