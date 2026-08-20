"""places.sqlite parsing — history, searches, bookmarks, downloads, visit types."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ffxforensics.parsers import ArtefactError, PlacesArtefact, extract_search_term
from ffxforensics.parsers.places import VISIT_TYPES


# --------------------------------------------------------------------------
# search-term extraction
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://www.google.com/search?q=sql+injection", ("sql injection", "Google")),
        ("https://www.bing.com/search?q=api+keys", ("api keys", "Bing")),
        ("https://duckduckgo.com/?q=owasp+top+10", ("owasp top 10", "DuckDuckGo")),
        (
            "https://www.youtube.com/results?search_query=lan+scan",
            ("lan scan", "YouTube"),
        ),
        ("https://search.yahoo.com/search?p=port+scan", ("port scan", "Yahoo")),
    ],
)
def test_extract_search_term_from_known_engines(url, expected) -> None:
    assert extract_search_term(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://www.google.com/",
        "https://www.google.com/url?q=https://example.com/page",
        "https://www.google.com/aclk?sa=l&ai=abc",
        "https://neoquant.com/white-papers/",
        "https://www.youtube.com/watch?v=GD88Pp75Klw",
        "",
    ],
)
def test_non_searches_are_not_reported_as_searches(url) -> None:
    """Redirectors and ad clicks carry a `q` parameter but are not searches."""
    assert extract_search_term(url) is None


def test_search_term_falls_back_to_title_when_parameter_missing() -> None:
    result = extract_search_term(
        "https://www.google.com/search?client=firefox", "sql injection - Google Search"
    )
    assert result == ("sql injection", "Google")


def test_url_encoded_terms_are_decoded() -> None:
    term, _engine = extract_search_term(
        "https://www.google.com/search?q=api%20keys%20%26%20tokens"
    )
    assert term == "api keys & tokens"


# --------------------------------------------------------------------------
# artefact handling
# --------------------------------------------------------------------------
def test_rejects_a_database_that_is_not_places(tmp_path: Path) -> None:
    bogus = tmp_path / "places.sqlite"
    conn = sqlite3.connect(bogus)
    conn.execute("CREATE TABLE unrelated (id INTEGER)")
    conn.commit()
    conn.close()

    with pytest.raises(ArtefactError, match="does not look like"):
        PlacesArtefact(bogus).connect()


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ArtefactError):
        PlacesArtefact(tmp_path / "nope.sqlite")


def test_opening_does_not_modify_the_evidence(places_path: Path) -> None:
    """ACPO Principle 1: analysis must leave the artefact byte-identical."""
    before = places_path.read_bytes()
    with PlacesArtefact(places_path) as places:
        places.places()
        places.visits()
        places.bookmarks()
    after = places_path.read_bytes()

    assert before == after
    assert not (places_path.parent / "places.sqlite-wal").exists()
    assert not (places_path.parent / "places.sqlite-journal").exists()


def test_summary_reports_provenance(places_path: Path) -> None:
    with PlacesArtefact(places_path) as places:
        summary = places.summary()
    assert summary["file"] == "places.sqlite"
    assert len(summary["sha256"]) == 64
    assert summary["integrity_check"] == "ok"
    assert "moz_places" in summary["tables"]


# --------------------------------------------------------------------------
# content
# --------------------------------------------------------------------------
def test_places_are_ordered_newest_first(places_path: Path, case_tz) -> None:
    with PlacesArtefact(places_path, tz=case_tz) as places:
        records = places.places()
    stamps = [record.last_visit_date for record in records if record.last_visit_date]
    assert stamps == sorted(stamps, reverse=True)


def test_visit_filter_is_parameterised(places_path: Path, case_tz) -> None:
    with PlacesArtefact(places_path, tz=case_tz) as places:
        videos = places.visits(url_like="%youtube.com/watch?%")
    assert videos
    assert all("youtube.com/watch?" in visit.url for visit in videos)


def test_visit_types_cover_codes_one_to_six(places_path: Path) -> None:
    with PlacesArtefact(places_path) as places:
        summary = places.visit_type_summary()
    assert list(summary) == [1, 2, 3, 4, 5, 6]
    assert summary[1]["label"] == VISIT_TYPES[1]
    assert summary[3]["count"] == 0, "unused categories must still appear, as zero"


def test_bookmarks_resolve_urls_and_folders(places_path: Path, case_tz) -> None:
    with PlacesArtefact(places_path, tz=case_tz) as places:
        entries = [b for b in places.bookmarks() if not b.is_folder]
    assert entries
    assert all(entry.url.startswith("http") for entry in entries)
    assert all(entry.folder_path == "toolbar" for entry in entries)


def test_downloads_are_reconstructed_from_annotations(places_path: Path) -> None:
    with PlacesArtefact(places_path) as places:
        downloads = places.downloads()
    assert len(downloads) == 1
    download = downloads[0]
    assert download.file_name == "Common-API-Attack-Vectors.pdf"
    assert download.target_path.startswith("file:///")
    assert download.file_size == 1843277
    assert download.started is not None


def test_search_queries_are_deduplicated(places_path: Path) -> None:
    with PlacesArtefact(places_path) as places:
        queries = [search.query.casefold() for search in places.search_queries()]
    assert len(queries) == len(set(queries))


def test_statistics_match_row_counts(places_path: Path) -> None:
    with PlacesArtefact(places_path) as places:
        stats = places.statistics()
        assert stats["places"] == len(places.places())
        assert stats["visits"] == len(places.visits())
