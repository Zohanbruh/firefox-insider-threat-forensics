"""Indicator engine, timeline construction and the audit trail."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from ffxforensics.analysis.indicators import (
    IndicatorEngine,
    Rule,
    load_rules,
)
from ffxforensics.analysis.timeline import (
    activity_window,
    build_timeline,
    group_sessions,
)
from ffxforensics.audit import AuditTrail
from ffxforensics.models import BookmarkRecord, FormHistoryRecord, VisitRecord

UTC = dt.timezone.utc


# --------------------------------------------------------------------------
# indicators
# --------------------------------------------------------------------------
def test_default_rules_load() -> None:
    rules = load_rules()
    assert rules
    names = {rule.name for rule in rules}
    assert {"sql_injection", "api_enumeration", "target_organisation"} <= names


@pytest.mark.parametrize(
    "text,expected_rule",
    [
        ("Test sql injection using browser only", "sql_injection"),
        ("Find exposed database endpoints in API", "api_enumeration"),
        ("Bypass client-side validation by modifying URL", "control_bypass"),
        ("Using a LAN scan to find INTERNAL vulnerabilities", "network_recon"),
        ("Web Request Inspector & Probe Service", "security_tooling"),
        ("white papers - NeoQuant", "target_organisation"),
        ("Competitive Analysis | Similarweb", "competitor_research"),
    ],
)
def test_expected_categories_fire(text, expected_rule) -> None:
    assert expected_rule in IndicatorEngine().categories(text)


@pytest.mark.parametrize(
    "text",
    [
        "weather in copenhagen tomorrow",
        "how to poach an egg",
        "train times to the office",
        "",
    ],
)
def test_benign_text_scores_zero(text) -> None:
    assert IndicatorEngine().score(text) == 0


@pytest.mark.parametrize(
    "text",
    ["recveal the answer", "a nmapping exercise", "postmaster general", "scandinavia"],
)
def test_keywords_respect_word_boundaries(text) -> None:
    """Keywords must not fire on substrings of unrelated words.

    'nmap' inside 'nmapping', 'postman' inside 'postmaster' and 'scan' inside
    'scandinavia' would each produce a false positive in a real report.
    """
    assert IndicatorEngine().score(text) == 0


def test_each_rule_fires_at_most_once_per_text() -> None:
    engine = IndicatorEngine()
    hits = engine.match("sql injection sql injection sqlmap union select")
    rules = [hit.rule for hit in hits]
    assert len(rules) == len(set(rules))


def test_custom_ruleset_can_replace_defaults(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "payroll_access",
                    "description": "Interest in payroll systems",
                    "weight": 7,
                    "severity": "high",
                    "keywords": ["payroll export"],
                }
            ]
        )
    )
    engine = IndicatorEngine(load_rules(path))
    assert engine.score("payroll export csv") == 7
    assert engine.score("sql injection") == 0, "default rules must not leak in"


def test_regex_patterns_are_supported() -> None:
    engine = IndicatorEngine([Rule("re", "", 3, "medium", [], [r"token\s+leak"])])
    assert engine.score("api token leak") == 3


def test_assessment_never_asserts_intent() -> None:
    engine = IndicatorEngine()
    assessment = engine.assess(
        [
            ("Test sql injection using browser only", "search"),
            ("neoquant finance - internal API docs", "search"),
            ("Bypass client-side validation by modifying URL", "search"),
        ]
    )
    interpretation = assessment["interpretation"]

    assert "INCONCLUSIVE" in interpretation["verdict"]
    assert interpretation["innocent_explanations"], "alternatives must always be offered"
    assert interpretation["recommended_corroboration"]
    assert assessment["highest_severity"] == "critical"


def test_assessment_orders_flagged_items_by_score() -> None:
    engine = IndicatorEngine()
    assessment = engine.assess(
        [
            ("owasp guidance", "search"),
            ("neoquant sql injection api endpoints bypass validation", "search"),
        ]
    )
    scores = [item["score"] for item in assessment["flagged_items"]]
    assert scores == sorted(scores, reverse=True)


def test_empty_input_produces_an_empty_assessment() -> None:
    assessment = IndicatorEngine().assess([])
    assert assessment["total_score"] == 0
    assert assessment["flagged_items"] == []
    assert "INCONCLUSIVE" in assessment["interpretation"]["verdict"]


# --------------------------------------------------------------------------
# timeline
# --------------------------------------------------------------------------
def _visit(second: int, title: str, visit_type: int = 1) -> VisitRecord:
    return VisitRecord(
        visit_id=second,
        place_id=second,
        url=f"https://example.com/{second}",
        title=title,
        visit_date=dt.datetime(2025, 12, 2, 15, 0, second, tzinfo=UTC),
        visit_type=visit_type,
    )


def test_timeline_is_sorted_and_typed() -> None:
    events = build_timeline(visits=[_visit(30, "b"), _visit(10, "a")])
    assert [event.timestamp.second for event in events] == [10, 30]
    assert events[0].event_type.startswith("visit:")


def test_timeline_merges_sources() -> None:
    events = build_timeline(
        visits=[_visit(10, "page")],
        bookmarks=[
            BookmarkRecord(
                id=1, parent=3, title="SQL Injection | OWASP", url="https://owasp.org",
                type=1, date_added=None,
                last_modified=dt.datetime(2025, 12, 2, 15, 0, 20, tzinfo=UTC),
            )
        ],
        form_history=[
            FormHistoryRecord(
                id=1, fieldname="searchbar-history", value="sql injection",
                times_used=1, first_used=None,
                last_used=dt.datetime(2025, 12, 2, 15, 0, 15, tzinfo=UTC),
            )
        ],
    )
    sources = [event.event_type for event in events]
    assert sources == ["visit:Interacted with link", "typed:searchbar-history", "bookmark"]


def test_timeline_drops_records_without_timestamps() -> None:
    bookmark = BookmarkRecord(
        id=1, parent=3, title="no dates", url="https://example.com", type=1,
        date_added=None, last_modified=None,
    )
    assert build_timeline(bookmarks=[bookmark]) == []


def test_folders_are_not_timeline_events() -> None:
    folder = BookmarkRecord(
        id=3, parent=1, title="toolbar", url="", type=2,
        date_added=dt.datetime(2025, 12, 2, 15, 0, 0, tzinfo=UTC),
        last_modified=dt.datetime(2025, 12, 2, 15, 0, 0, tzinfo=UTC),
    )
    assert build_timeline(bookmarks=[folder]) == []


def test_indicators_are_attached_to_events() -> None:
    events = build_timeline(visits=[_visit(10, "sql injection cheat sheet")])
    assert "sql_injection" in events[0].indicators
    assert events[0].severity == "high"


def test_sessions_split_on_inactivity_gap() -> None:
    early = _visit(1, "one")
    late = _visit(2, "two")
    late.visit_date = dt.datetime(2025, 12, 2, 18, 0, 0, tzinfo=UTC)

    events = build_timeline(visits=[early, late])
    sessions = group_sessions(events, gap_minutes=30)

    assert len(sessions) == 2
    assert sessions[0].duration_seconds == 0
    assert sessions[1].index == 2


def test_continuous_activity_is_one_session() -> None:
    events = build_timeline(visits=[_visit(second, f"e{second}") for second in (1, 20, 40)])
    sessions = group_sessions(events, gap_minutes=30)
    assert len(sessions) == 1
    assert len(sessions[0].events) == 3
    assert sessions[0].duration_human == "39s"


def test_activity_window_reports_span() -> None:
    events = build_timeline(visits=[_visit(1, "a"), _visit(31, "b")])
    window = activity_window(events)
    assert window["span_seconds"] == 30
    assert window["event_count"] == 2


def test_activity_window_handles_no_events() -> None:
    assert activity_window([])["event_count"] == 0


# --------------------------------------------------------------------------
# audit trail
# --------------------------------------------------------------------------
def test_audit_entries_are_sequential_and_timestamped() -> None:
    trail = AuditTrail(case_id="029", examiner="A. Adhikari")
    trail.record("Analysing", "tool-a", explanation="first")
    trail.record("Analysing", "tool-b", explanation="second")

    assert [entry.seq for entry in trail] == [1, 2]
    assert all(entry.timestamp_utc.endswith("Z") for entry in trail)


def test_audit_history_cannot_be_rewritten_through_the_property() -> None:
    trail = AuditTrail()
    trail.record("Analysing", "tool")
    trail.entries.clear()
    assert len(trail) == 1, "entries must be a copy, not the live list"


def test_audit_csv_and_json_roundtrip(tmp_path: Path) -> None:
    trail = AuditTrail(case_id="029", examiner="A. Adhikari")
    trail.record("Evidence Collection", "cp", command="cp -rp a b", explanation="copy")

    csv_path = trail.to_csv(tmp_path / "audit.csv")
    json_path = trail.to_json(tmp_path / "audit.json")

    assert "cp -rp a b" in csv_path.read_text()
    reloaded = AuditTrail.from_json(json_path)
    assert len(reloaded) == 1
    assert reloaded.case_id == "029"
    assert reloaded.entries[0].command == "cp -rp a b"


def test_audit_markdown_escapes_pipes() -> None:
    trail = AuditTrail()
    trail.record("Analysing", "tool", explanation="a | b")
    assert "a \\| b" in trail.to_markdown()


def test_audit_filter_by_phase() -> None:
    trail = AuditTrail()
    trail.record("Analysing", "x")
    trail.record("Evidence Preservation", "y")
    assert len(trail.filter("Analysing")) == 1
