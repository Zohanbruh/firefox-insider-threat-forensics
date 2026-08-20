"""
``places.sqlite`` — the single most valuable Firefox artefact.

It holds URL history (``moz_places``), individual navigation events
(``moz_historyvisits``), bookmarks (``moz_bookmarks``) and download
annotations (``moz_annos`` / ``moz_anno_attributes``).

All SQL in this module is a hardened version of the queries recorded in the
Case 029 audit trail, with three improvements:

* timestamps are converted in Python against an explicit timezone rather than
  relying on SQLite's ``'localtime'`` modifier (which silently uses the
  *examiner's* machine timezone and is therefore not reproducible);
* joins are explicit ``JOIN ... ON`` rather than implicit comma-joins;
* every query is parameterised, so evidence values can never be interpolated
  into SQL.
"""

from __future__ import annotations

import re
from collections import Counter, OrderedDict
from typing import Dict, List, Optional
from urllib.parse import parse_qs, unquote_plus, urlparse

from ffxforensics.models import (
    BookmarkRecord,
    DownloadRecord,
    PlaceRecord,
    SearchRecord,
    VisitRecord,
)
from ffxforensics.parsers.base import SQLiteArtefact
from ffxforensics.timeutil import prtime_to_datetime

#: ``moz_historyvisits.visit_type`` values, per Firefox's nsINavHistoryService.
#: The wording matches Grid 4.5 of the Case 029 report.
VISIT_TYPES: Dict[int, str] = {
    1: "Interacted with link",
    2: "Inputted link or selected from suggestions",
    3: "Accessed a bookmark",
    4: "Referenced link (embed)",
    5: "301 reroute (permanent redirect)",
    6: "302 reroute (temporary redirect)",
    7: "Download",
    8: "Framed link",
    9: "Reload",
}

#: Search engines: host fragment -> (accepted path prefixes, query parameter, label).
#:
#: The path prefix matters. ``google.com/url?q=…`` and ``google.com/aclk?…`` are
#: *redirectors*: they carry a ``q`` parameter holding a destination URL, not a
#: search term. Matching on host alone would silently record every ad click and
#: outbound redirect as a "search the suspect performed" — a false positive that
#: would be indefensible in a report.
SEARCH_ENGINES = OrderedDict(
    [
        ("google.", (("/search",), "q", "Google")),
        ("bing.com", (("/search",), "q", "Bing")),
        ("duckduckgo.com", (("/", "/html"), "q", "DuckDuckGo")),
        ("search.yahoo.", (("/search",), "p", "Yahoo")),
        ("yandex.", (("/search",), "text", "Yandex")),
        ("baidu.com", (("/s",), "wd", "Baidu")),
        ("ecosia.org", (("/search",), "q", "Ecosia")),
        ("search.brave.com", (("/search",), "q", "Brave")),
        ("startpage.com", (("/sp/search", "/do/search", "/search"), "query", "Startpage")),
        ("youtube.com", (("/results",), "search_query", "YouTube")),
        ("github.com", (("/search",), "q", "GitHub")),
        ("stackoverflow.com", (("/search",), "q", "Stack Overflow")),
    ]
)

_TITLE_SUFFIX_RE = re.compile(
    r"\s*[-–|]\s*(Google Search|Bing|DuckDuckGo|Search Results|YouTube)\s*$",
    re.IGNORECASE,
)

_ROOT_FOLDERS = {
    "root": "root",
    "menu": "Bookmarks Menu",
    "toolbar": "Bookmarks Toolbar",
    "tags": "Tags",
    "unfiled": "Other Bookmarks",
    "mobile": "Mobile Bookmarks",
}


def extract_search_term(url: str, title: str = "") -> Optional[tuple]:
    """Return ``(query, engine)`` if ``url`` is a search-results URL.

    Falls back to the page title (``"foo - Google Search"``) when the query
    parameter is absent — which happens when Firefox records a redirected or
    truncated SERP URL.

    >>> extract_search_term("https://www.google.com/search?q=sql+injection")
    ('sql injection', 'Google')
    """
    if not url:
        return None
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = (parsed.path or "/").lower()

    for marker, (path_prefixes, param, engine) in SEARCH_ENGINES.items():
        if marker not in host:
            continue
        if not any(path.startswith(prefix) for prefix in path_prefixes):
            continue
        values = parse_qs(parsed.query).get(param)
        if values and values[0].strip():
            term = unquote_plus(values[0]).strip()
            # A redirector can still smuggle a URL through the query parameter.
            if term.lower().startswith(("http://", "https://")):
                return None
            return term, engine
        if title:
            cleaned = _TITLE_SUFFIX_RE.sub("", title).strip()
            if cleaned:
                return cleaned, engine
        return None
    return None


class PlacesArtefact(SQLiteArtefact):
    """Read-only accessor for ``places.sqlite``."""

    artefact_name = "places"
    required_tables = ("moz_places", "moz_historyvisits")

    # -- history ---------------------------------------------------------
    def places(self, limit: Optional[int] = None) -> List[PlaceRecord]:
        """Every distinct URL, newest last-visit first (report Image 1)."""
        sql = (
            "SELECT id, url, COALESCE(title, '') AS title, visit_count, "
            "       COALESCE(typed, 0) AS typed, last_visit_date, "
            "       COALESCE(frecency, 0) AS frecency, COALESCE(hidden, 0) AS hidden, "
            "       COALESCE(rev_host, '') AS rev_host "
            "FROM moz_places "
            "ORDER BY last_visit_date DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [
            PlaceRecord(
                id=row["id"],
                url=row["url"],
                title=row["title"],
                visit_count=row["visit_count"],
                typed=row["typed"],
                last_visit_date=prtime_to_datetime(row["last_visit_date"], self.tz),
                frecency=row["frecency"],
                hidden=row["hidden"],
                rev_host=row["rev_host"],
            )
            for row in self.query(sql)
        ]

    def visits(self, url_like: Optional[str] = None) -> List[VisitRecord]:
        """Individual navigation events, newest first.

        ``url_like`` accepts a SQL ``LIKE`` pattern and is passed as a bound
        parameter, e.g. ``"%youtube.com/watch?%"``.
        """
        sql = (
            "SELECT v.id AS visit_id, v.place_id, p.url, COALESCE(p.title, '') AS title, "
            "       v.visit_date, v.visit_type, COALESCE(v.from_visit, 0) AS from_visit "
            "FROM moz_historyvisits v "
            "JOIN moz_places p ON p.id = v.place_id "
        )
        params: List[str] = []
        if url_like:
            sql += "WHERE p.url LIKE ? "
            params.append(url_like)
        sql += "ORDER BY v.visit_date DESC"

        return [
            VisitRecord(
                visit_id=row["visit_id"],
                place_id=row["place_id"],
                url=row["url"],
                title=row["title"],
                visit_date=prtime_to_datetime(row["visit_date"], self.tz),
                visit_type=row["visit_type"],
                from_visit=row["from_visit"],
            )
            for row in self.query(sql, params)
        ]

    # -- derived views ---------------------------------------------------
    def search_queries(self, deduplicate: bool = True) -> List[SearchRecord]:
        """Recover search-engine queries from history (report Grid 4.2)."""
        results: List[SearchRecord] = []
        seen: Dict[str, SearchRecord] = {}

        for place in self.places():
            extracted = extract_search_term(place.url, place.title)
            if not extracted:
                continue
            query, engine = extracted
            record = SearchRecord(
                query=query,
                engine=engine,
                url=place.url,
                last_visited=place.last_visit_date,
                visit_count=place.visit_count,
                source="places",
            )
            key = f"{engine}::{query.casefold()}"
            if deduplicate and key in seen:
                existing = seen[key]
                if record.last_visited and (
                    existing.last_visited is None
                    or record.last_visited > existing.last_visited
                ):
                    existing.last_visited = record.last_visited
                existing.visit_count += record.visit_count
                continue
            seen[key] = record
            results.append(record)

        results.sort(key=lambda item: (item.last_visited is None, item.last_visited))
        return results

    def video_visits(self, pattern: str = "%youtube.com/watch?%") -> List[VisitRecord]:
        """Video watch events (report Grid 4.3)."""
        return self.visits(url_like=pattern)

    def visit_type_summary(self) -> "OrderedDict[int, dict]":
        """Counts per ``visit_type`` (report Grid 4.5).

        Returns an ordered mapping ``{code: {label, count}}`` covering codes
        1-6 even when a code has zero occurrences, so the output table has the
        same shape as the report's grid.
        """
        counter: Counter = Counter()
        for row in self.query(
            "SELECT visit_type, COUNT(*) AS n FROM moz_historyvisits GROUP BY visit_type"
        ):
            counter[row["visit_type"]] = row["n"]

        summary: "OrderedDict[int, dict]" = OrderedDict()
        for code in range(1, 7):
            summary[code] = {"label": VISIT_TYPES[code], "count": counter.get(code, 0)}
        for code in sorted(set(counter) - set(summary)):
            summary[code] = {
                "label": VISIT_TYPES.get(code, f"unknown({code})"),
                "count": counter[code],
            }
        return summary

    # -- bookmarks -------------------------------------------------------
    def bookmarks(self, include_folders: bool = True) -> List[BookmarkRecord]:
        """Bookmarks and folders, most recently modified first (Grid 4.4)."""
        if not self.has_table("moz_bookmarks"):
            return []

        rows = self.query(
            "SELECT b.id, b.parent, COALESCE(b.title, '') AS title, b.type, "
            "       COALESCE(p.url, '') AS url, b.dateAdded, b.lastModified "
            "FROM moz_bookmarks b "
            "LEFT JOIN moz_places p ON p.id = b.fk "
            "ORDER BY b.lastModified DESC"
        )

        by_id = {row["id"]: row for row in rows}

        def folder_path(node_id: int, depth: int = 0) -> str:
            """Walk parents to build ``Toolbar/Security`` style paths."""
            if depth > 32 or node_id not in by_id:
                return ""
            node = by_id[node_id]
            title = node["title"] or _ROOT_FOLDERS.get(str(node["title"]), "")
            parent_path = folder_path(node["parent"], depth + 1) if node["parent"] else ""
            return f"{parent_path}/{title}".strip("/") if title else parent_path

        records = []
        for row in rows:
            if not include_folders and row["type"] == 2:
                continue
            records.append(
                BookmarkRecord(
                    id=row["id"],
                    parent=row["parent"],
                    title=row["title"],
                    url=row["url"],
                    type=row["type"],
                    date_added=prtime_to_datetime(row["dateAdded"], self.tz),
                    last_modified=prtime_to_datetime(row["lastModified"], self.tz),
                    folder_path=folder_path(row["parent"]),
                )
            )
        return records

    # -- downloads -------------------------------------------------------
    def downloads(self) -> List[DownloadRecord]:
        """Reconstruct downloads from ``moz_annos`` annotations.

        Firefox stores the saved path under ``downloads/destinationFileURI``
        and a small JSON blob (end time, byte count) under
        ``downloads/metaData``.
        """
        if not (self.has_table("moz_annos") and self.has_table("moz_anno_attributes")):
            return []

        rows = self.query(
            "SELECT a.place_id, n.name AS attribute, a.content, a.dateAdded, "
            "       a.lastModified, p.url "
            "FROM moz_annos a "
            "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
            "LEFT JOIN moz_places p ON p.id = a.place_id "
            "WHERE n.name LIKE 'downloads/%'"
        )

        grouped: Dict[int, dict] = {}
        for row in rows:
            entry = grouped.setdefault(
                row["place_id"],
                {"url": row["url"] or "", "target": "", "meta": "",
                 "added": None, "modified": None},
            )
            if row["attribute"].endswith("destinationFileURI"):
                entry["target"] = row["content"] or ""
                entry["added"] = row["dateAdded"]
            elif row["attribute"].endswith("metaData"):
                entry["meta"] = row["content"] or ""
                entry["modified"] = row["lastModified"]

        records: List[DownloadRecord] = []
        for place_id, entry in grouped.items():
            size = None
            match = re.search(r'"fileSize"\s*:\s*(\d+)', entry["meta"])
            if match:
                size = int(match.group(1))
            end_ms = None
            match = re.search(r'"endTime"\s*:\s*(\d+)', entry["meta"])
            if match:
                end_ms = int(match.group(1)) * 1000  # metaData uses milliseconds
            target = entry["target"]
            file_name = target.rstrip("/").split("/")[-1] if target else ""
            records.append(
                DownloadRecord(
                    place_id=place_id,
                    source_url=entry["url"],
                    target_path=unquote_plus(target),
                    file_name=unquote_plus(file_name),
                    file_size=size,
                    started=prtime_to_datetime(entry["added"], self.tz),
                    ended=prtime_to_datetime(end_ms, self.tz),
                )
            )
        records.sort(key=lambda item: (item.started is None, item.started))
        return records

    # -- stats -----------------------------------------------------------
    def statistics(self) -> Dict[str, int]:
        return {
            "places": self.row_count("moz_places"),
            "visits": self.row_count("moz_historyvisits"),
            "bookmarks": self.row_count("moz_bookmarks"),
            "annotations": self.row_count("moz_annos"),
            "inputhistory": self.row_count("moz_inputhistory"),
        }
