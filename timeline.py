"""
Unified timeline construction.

Individual artefacts each tell a partial story.  Interleaving them —
navigation, bookmarking, form entry, cookie access — turns a list of URLs into
a *narrative*, which is what an investigator, a disciplinary panel or a court
actually needs.

Sessions are cut on an inactivity gap (default 30 minutes) so the report can
say "one continuous 21-minute session" instead of "56 events".
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ffxforensics.analysis.indicators import IndicatorEngine
from ffxforensics.models import (
    BookmarkRecord,
    CookieRecord,
    DownloadRecord,
    FormHistoryRecord,
    TimelineEvent,
    VisitRecord,
)

DEFAULT_SESSION_GAP_MINUTES = 30


@dataclass
class Session:
    """A contiguous burst of activity."""

    index: int
    start: Optional[_dt.datetime]
    end: Optional[_dt.datetime]
    events: List[TimelineEvent] = field(default_factory=list)

    @property
    def duration_seconds(self) -> int:
        if not (self.start and self.end):
            return 0
        return int((self.end - self.start).total_seconds())

    @property
    def duration_human(self) -> str:
        seconds = self.duration_seconds
        if seconds < 60:
            return f"{seconds}s"
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m {seconds}s"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "duration_seconds": self.duration_seconds,
            "duration_human": self.duration_human,
            "event_count": len(self.events),
            "flagged_events": sum(1 for event in self.events if event.indicators),
        }


def build_timeline(
    visits: Sequence[VisitRecord] = (),
    bookmarks: Sequence[BookmarkRecord] = (),
    form_history: Sequence[FormHistoryRecord] = (),
    downloads: Sequence[DownloadRecord] = (),
    cookies: Sequence[CookieRecord] = (),
    engine: Optional[IndicatorEngine] = None,
    include_cookies: bool = False,
) -> List[TimelineEvent]:
    """Merge artefact records into a single chronological event list.

    Cookies are opt-in: in a busy profile they add thousands of low-value rows
    that bury the navigation narrative.
    """
    engine = engine or IndicatorEngine()
    events: List[TimelineEvent] = []

    def enrich(text: str) -> tuple:
        hits = engine.match(text)
        if not hits:
            return "info", []
        severity = max(
            (hit.severity for hit in hits),
            key=lambda sev: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0),
        )
        return severity, sorted({hit.rule for hit in hits})

    for visit in visits:
        text = f"{visit.title} {visit.url}"
        severity, indicators = enrich(text)
        events.append(
            TimelineEvent(
                timestamp=visit.visit_date,
                source="places.sqlite",
                event_type=f"visit:{visit.visit_type_label}",
                description=visit.title or visit.url,
                detail=visit.url,
                severity=severity,
                indicators=indicators,
            )
        )

    for bookmark in bookmarks:
        if bookmark.is_folder:
            continue
        text = f"{bookmark.title} {bookmark.url}"
        severity, indicators = enrich(text)
        events.append(
            TimelineEvent(
                timestamp=bookmark.last_modified or bookmark.date_added,
                source="places.sqlite",
                event_type="bookmark",
                description=bookmark.title or bookmark.url,
                detail=bookmark.url,
                severity=severity,
                indicators=indicators,
            )
        )

    for entry in form_history:
        severity, indicators = enrich(entry.value)
        events.append(
            TimelineEvent(
                timestamp=entry.last_used,
                source="formhistory.sqlite",
                event_type=f"typed:{entry.fieldname}",
                description=entry.value,
                detail=f"used {entry.times_used}x",
                severity=severity,
                indicators=indicators,
            )
        )

    for download in downloads:
        text = f"{download.file_name} {download.source_url}"
        severity, indicators = enrich(text)
        events.append(
            TimelineEvent(
                timestamp=download.started,
                source="places.sqlite",
                event_type="download",
                description=download.file_name or download.source_url,
                detail=download.target_path,
                severity=severity,
                indicators=indicators,
            )
        )

    if include_cookies:
        for cookie in cookies:
            severity, indicators = enrich(cookie.host)
            events.append(
                TimelineEvent(
                    timestamp=cookie.last_accessed,
                    source="cookies.sqlite",
                    event_type="cookie",
                    description=cookie.host,
                    detail=cookie.name,
                    severity=severity,
                    indicators=indicators,
                )
            )

    events = [event for event in events if event.timestamp is not None]
    events.sort(key=lambda event: event.timestamp)  # type: ignore[arg-type]
    return events


def group_sessions(
    events: Sequence[TimelineEvent],
    gap_minutes: int = DEFAULT_SESSION_GAP_MINUTES,
) -> List[Session]:
    """Split a timeline into sessions separated by ``gap_minutes`` of silence."""
    sessions: List[Session] = []
    gap = _dt.timedelta(minutes=gap_minutes)

    for event in events:
        if event.timestamp is None:
            continue
        if sessions and sessions[-1].end is not None and (
            event.timestamp - sessions[-1].end <= gap  # type: ignore[operator]
        ):
            current = sessions[-1]
            current.events.append(event)
            current.end = event.timestamp
        else:
            sessions.append(
                Session(
                    index=len(sessions) + 1,
                    start=event.timestamp,
                    end=event.timestamp,
                    events=[event],
                )
            )
    return sessions


def activity_window(events: Iterable[TimelineEvent]) -> Dict[str, Any]:
    """First/last event and total span across the whole timeline."""
    stamps = [event.timestamp for event in events if event.timestamp]
    if not stamps:
        return {"first": None, "last": None, "span_seconds": 0, "event_count": 0}
    first, last = min(stamps), max(stamps)
    return {
        "first": first.isoformat(),
        "last": last.isoformat(),
        "span_seconds": int((last - first).total_seconds()),
        "event_count": len(stamps),
    }
