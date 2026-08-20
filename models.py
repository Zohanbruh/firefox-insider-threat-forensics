"""
Typed records produced by the parsers.

Keeping the artefact model separate from the SQL means the reporting layer,
the indicator engine and the timeline builder all consume the same shapes, and
a new browser family (Chromium, for example) only needs a new parser.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ffxforensics.timeutil import DEFAULT_FORMAT


def _fmt(dt: Optional[_dt.datetime], fmt: str = DEFAULT_FORMAT) -> str:
    return dt.strftime(fmt) if dt else ""


@dataclass
class Record:
    """Base record with dictionary export used by every CSV/JSON exporter."""

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, value in list(data.items()):
            if isinstance(value, _dt.datetime):
                data[key] = value.isoformat()
        return data


@dataclass
class PlaceRecord(Record):
    """A row of ``moz_places`` — one distinct URL known to the browser."""

    id: int
    url: str
    title: str
    visit_count: int
    typed: int
    last_visit_date: Optional[_dt.datetime]
    frecency: int = 0
    hidden: int = 0
    rev_host: str = ""

    @property
    def last_visit_str(self) -> str:
        return _fmt(self.last_visit_date)


@dataclass
class VisitRecord(Record):
    """A row of ``moz_historyvisits`` — one navigation event."""

    visit_id: int
    place_id: int
    url: str
    title: str
    visit_date: Optional[_dt.datetime]
    visit_type: int
    from_visit: int = 0

    @property
    def visit_type_label(self) -> str:
        from ffxforensics.parsers.places import VISIT_TYPES

        return VISIT_TYPES.get(self.visit_type, f"unknown({self.visit_type})")

    @property
    def visit_date_str(self) -> str:
        return _fmt(self.visit_date)


@dataclass
class SearchRecord(Record):
    """A search-engine query recovered from history or form history."""

    query: str
    engine: str
    url: str
    last_visited: Optional[_dt.datetime]
    visit_count: int = 1
    source: str = "places"

    @property
    def last_visited_str(self) -> str:
        return _fmt(self.last_visited)


@dataclass
class BookmarkRecord(Record):
    """A row of ``moz_bookmarks`` (type 1 = bookmark, type 2 = folder)."""

    id: int
    parent: int
    title: str
    url: str
    type: int
    date_added: Optional[_dt.datetime]
    last_modified: Optional[_dt.datetime]
    folder_path: str = ""

    @property
    def is_folder(self) -> bool:
        return self.type == 2

    @property
    def last_modified_str(self) -> str:
        return _fmt(self.last_modified)


@dataclass
class DownloadRecord(Record):
    """A download reconstructed from ``moz_annos`` annotations."""

    place_id: int
    source_url: str
    target_path: str
    file_name: str
    file_size: Optional[int]
    started: Optional[_dt.datetime]
    ended: Optional[_dt.datetime]

    @property
    def started_str(self) -> str:
        return _fmt(self.started)


@dataclass
class CookieRecord(Record):
    """A row of ``moz_cookies``."""

    id: int
    host: str
    name: str
    path: str
    is_secure: int
    is_http_only: int
    same_site: int
    creation_time: Optional[_dt.datetime]
    last_accessed: Optional[_dt.datetime]
    expiry: Optional[_dt.datetime]

    @property
    def same_site_label(self) -> str:
        return {0: "None", 1: "Lax", 2: "Strict"}.get(self.same_site, "Unset")

    @property
    def last_accessed_str(self) -> str:
        return _fmt(self.last_accessed)


@dataclass
class FormHistoryRecord(Record):
    """A row of ``moz_formhistory`` — text typed into a form or search bar."""

    id: int
    fieldname: str
    value: str
    times_used: int
    first_used: Optional[_dt.datetime]
    last_used: Optional[_dt.datetime]

    @property
    def last_used_str(self) -> str:
        return _fmt(self.last_used)


@dataclass
class TimelineEvent(Record):
    """A normalised event on the unified case timeline."""

    timestamp: Optional[_dt.datetime]
    source: str
    event_type: str
    description: str
    detail: str = ""
    severity: str = "info"
    indicators: List[str] = field(default_factory=list)

    @property
    def timestamp_str(self) -> str:
        return _fmt(self.timestamp)
