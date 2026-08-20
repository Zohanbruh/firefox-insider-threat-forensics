"""
Case orchestration.

:class:`CaseAnalyser` is the one entry point the CLI, the tests and any
downstream tooling use.  It opens whichever artefacts exist in an evidence
directory, runs every parser, applies the indicator engine, builds the
timeline and returns a single :class:`CaseResult` — while writing an audit
entry for each step so the run is reproducible by a third party
(ACPO Principle 3).
"""

from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ffxforensics.analysis.indicators import IndicatorEngine
from ffxforensics.analysis.timeline import (
    Session,
    activity_window,
    build_timeline,
    group_sessions,
)
from ffxforensics.audit import AuditTrail
from ffxforensics.models import (
    BookmarkRecord,
    CookieRecord,
    DownloadRecord,
    FormHistoryRecord,
    PlaceRecord,
    SearchRecord,
    TimelineEvent,
    VisitRecord,
)
from ffxforensics.parsers import (
    ArtefactError,
    CookiesArtefact,
    FormHistoryArtefact,
    PlacesArtefact,
)
from ffxforensics.timeutil import UTC, now_iso, tz_label

ARTEFACT_FILES = {
    "places": "places.sqlite",
    "cookies": "cookies.sqlite",
    "formhistory": "formhistory.sqlite",
}


@dataclass
class CaseMetadata:
    """Administrative header reproduced on every report."""

    case_id: str = "029"
    examiner: str = ""
    subject: str = ""
    organisation: str = ""
    evidence_name: str = "Firefox-Linux-Evidence"
    exhibit_reference: str = ""
    device: str = ""
    operating_system: str = ""
    browser: str = ""
    notes: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value}


@dataclass
class CaseResult:
    """Everything the analysis produced, ready for rendering or export."""

    metadata: CaseMetadata
    evidence_dir: Path
    timezone: str
    generated_utc: str
    artefacts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    statistics: Dict[str, Dict[str, int]] = field(default_factory=dict)
    places: List[PlaceRecord] = field(default_factory=list)
    visits: List[VisitRecord] = field(default_factory=list)
    searches: List[SearchRecord] = field(default_factory=list)
    video_visits: List[VisitRecord] = field(default_factory=list)
    bookmarks: List[BookmarkRecord] = field(default_factory=list)
    downloads: List[DownloadRecord] = field(default_factory=list)
    cookies: List[CookieRecord] = field(default_factory=list)
    cookie_hosts: List[Dict[str, Any]] = field(default_factory=list)
    form_history: List[FormHistoryRecord] = field(default_factory=list)
    visit_types: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    timeline: List[TimelineEvent] = field(default_factory=list)
    sessions: List[Session] = field(default_factory=list)
    assessment: Dict[str, Any] = field(default_factory=dict)
    window: Dict[str, Any] = field(default_factory=dict)
    integrity: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    # -- convenience views ----------------------------------------------
    @property
    def bookmark_entries(self) -> List[BookmarkRecord]:
        """Bookmarks only (folders excluded)."""
        return [item for item in self.bookmarks if not item.is_folder]

    @property
    def flagged_searches(self) -> List[SearchRecord]:
        engine = IndicatorEngine()
        return [item for item in self.searches if engine.match(item.query)]

    def summary(self) -> Dict[str, Any]:
        return {
            "case_id": self.metadata.case_id,
            "generated_utc": self.generated_utc,
            "timezone": self.timezone,
            "evidence_dir": str(self.evidence_dir),
            "artefacts": list(self.artefacts),
            "counts": {
                "places": len(self.places),
                "visits": len(self.visits),
                "searches": len(self.searches),
                "video_visits": len(self.video_visits),
                "bookmarks": len(self.bookmark_entries),
                "downloads": len(self.downloads),
                "cookies": len(self.cookies),
                "form_history": len(self.form_history),
                "timeline_events": len(self.timeline),
                "sessions": len(self.sessions),
            },
            "window": self.window,
            "assessment": {
                key: value
                for key, value in self.assessment.items()
                if key != "flagged_items"
            },
            "integrity": self.integrity,
            "errors": self.errors,
        }


class CaseAnalyser:
    """Runs the full analysis pipeline over an evidence directory."""

    def __init__(
        self,
        evidence_dir: os.PathLike | str,
        metadata: Optional[CaseMetadata] = None,
        tz: Optional[_dt.tzinfo] = None,
        engine: Optional[IndicatorEngine] = None,
        trail: Optional[AuditTrail] = None,
        session_gap_minutes: int = 30,
    ) -> None:
        self.evidence_dir = Path(evidence_dir)
        if not self.evidence_dir.exists():
            raise FileNotFoundError(f"Evidence directory not found: {self.evidence_dir}")
        self.metadata = metadata or CaseMetadata()
        self.tz = tz or UTC
        self.engine = engine or IndicatorEngine()
        # NB: `trail or AuditTrail(...)` would be wrong here. AuditTrail defines
        # __len__, so a freshly-created empty trail is falsy and the caller's
        # object would be silently discarded along with every entry we then
        # write into the replacement.
        self.trail = (
            trail
            if trail is not None
            else AuditTrail(case_id=self.metadata.case_id, examiner=self.metadata.examiner)
        )
        self.session_gap_minutes = session_gap_minutes

    # -- helpers ---------------------------------------------------------
    def locate(self, filename: str) -> Optional[Path]:
        """Find ``filename`` in the evidence dir (recursively if needed)."""
        direct = self.evidence_dir / filename
        if direct.is_file():
            return direct
        for candidate in sorted(self.evidence_dir.rglob(filename)):
            if candidate.is_file():
                return candidate
        return None

    # -- pipeline --------------------------------------------------------
    def run(self, include_cookies_in_timeline: bool = False) -> CaseResult:
        result = CaseResult(
            metadata=self.metadata,
            evidence_dir=self.evidence_dir,
            timezone=tz_label(self.tz),
            generated_utc=now_iso(),
        )

        self.trail.record(
            "Analysing",
            "ffxforensics.CaseAnalyser",
            command=f"ffxforensics analyze {self.evidence_dir}",
            explanation="Opened evidence directory for read-only artefact analysis",
            artefact=str(self.evidence_dir),
        )

        self._run_places(result)
        self._run_cookies(result)
        self._run_formhistory(result)
        self._run_analysis(result, include_cookies_in_timeline)
        return result

    # -- individual artefacts -------------------------------------------
    def _run_places(self, result: CaseResult) -> None:
        path = self.locate(ARTEFACT_FILES["places"])
        if path is None:
            result.errors.append("places.sqlite not present in evidence set")
            return
        try:
            with PlacesArtefact(path, tz=self.tz) as places:
                result.artefacts["places"] = places.summary()
                result.statistics["places"] = places.statistics()
                result.places = places.places()
                result.visits = places.visits()
                result.searches = places.search_queries()
                result.video_visits = places.video_visits()
                result.bookmarks = places.bookmarks()
                result.downloads = places.downloads()
                result.visit_types = places.visit_type_summary()
                self.trail.record(
                    "Analysing",
                    "ffxforensics.parsers.places",
                    command="SELECT id, url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC",
                    explanation=(
                        f"Extracted {len(result.places)} URLs, {len(result.visits)} visits, "
                        f"{len(result.searches)} searches, {len(result.bookmarks)} bookmark rows"
                    ),
                    artefact=path.name,
                    hash_value=places.sha256,
                )
        except ArtefactError as exc:
            result.errors.append(str(exc))

    def _run_cookies(self, result: CaseResult) -> None:
        path = self.locate(ARTEFACT_FILES["cookies"])
        if path is None:
            result.errors.append("cookies.sqlite not present in evidence set")
            return
        try:
            with CookiesArtefact(path, tz=self.tz) as cookies:
                result.artefacts["cookies"] = cookies.summary()
                result.statistics["cookies"] = cookies.statistics()
                result.cookies = cookies.cookies()
                result.cookie_hosts = cookies.host_summary()
                self.trail.record(
                    "Analysing",
                    "ffxforensics.parsers.cookies",
                    command="SELECT id, host, isHttpOnly, isSecure, sameSite, lastAccessed FROM moz_cookies",
                    explanation=(
                        f"Identified {len(result.cookies)} cookies across "
                        f"{len(result.cookie_hosts)} hosts"
                    ),
                    artefact=path.name,
                    hash_value=cookies.sha256,
                )
        except ArtefactError as exc:
            result.errors.append(str(exc))

    def _run_formhistory(self, result: CaseResult) -> None:
        path = self.locate(ARTEFACT_FILES["formhistory"])
        if path is None:
            result.errors.append("formhistory.sqlite not present in evidence set")
            return
        try:
            with FormHistoryArtefact(path, tz=self.tz) as forms:
                result.artefacts["formhistory"] = forms.summary()
                result.statistics["formhistory"] = forms.statistics()
                result.form_history = forms.entries()
                self.trail.record(
                    "Analysing",
                    "ffxforensics.parsers.formhistory",
                    command="SELECT id, fieldname, value, timesUsed, lastUsed FROM moz_formhistory",
                    explanation=f"Recovered {len(result.form_history)} typed form values",
                    artefact=path.name,
                    hash_value=forms.sha256,
                )
        except ArtefactError as exc:
            result.errors.append(str(exc))

    # -- correlation -----------------------------------------------------
    def _run_analysis(self, result: CaseResult, include_cookies: bool) -> None:
        result.timeline = build_timeline(
            visits=result.visits,
            bookmarks=result.bookmarks,
            form_history=result.form_history,
            downloads=result.downloads,
            cookies=result.cookies,
            engine=self.engine,
            include_cookies=include_cookies,
        )
        result.sessions = group_sessions(result.timeline, self.session_gap_minutes)
        result.window = activity_window(result.timeline)

        items: List[tuple] = []
        items += [(search.query, "search") for search in result.searches]
        items += [
            (f"{visit.title} {visit.url}".strip(), "history") for visit in result.visits
        ]
        items += [
            (bookmark.title or bookmark.url, "bookmark")
            for bookmark in result.bookmark_entries
        ]
        items += [(entry.value, "form-history") for entry in result.form_history]
        items += [(download.file_name, "download") for download in result.downloads]

        result.assessment = self.engine.assess(items)
        result.assessment["corroboration"] = corroborate(result)

        self.trail.record(
            "Analysing",
            "ffxforensics.analysis",
            command="IndicatorEngine.assess() + build_timeline()",
            explanation=(
                f"Built {len(result.timeline)}-event timeline across "
                f"{len(result.sessions)} session(s); "
                f"{result.assessment.get('flagged_count', 0)} artefacts matched indicators"
            ),
            artefact=str(self.evidence_dir),
        )


def corroborate(result: CaseResult) -> Dict[str, Any]:
    """Cross-check search terms recovered from history against form history.

    A term present in *both* places.sqlite and formhistory.sqlite is strong
    evidence it was physically typed rather than arriving via a redirect or an
    auto-suggestion — a distinction that matters when history alone is
    challenged.
    """
    typed = {entry.value.casefold().strip() for entry in result.form_history}
    history = {search.query.casefold().strip() for search in result.searches}

    both = sorted(typed & history)
    history_only = sorted(history - typed)
    typed_only = sorted(typed - history)

    return {
        "typed_and_in_history": both,
        "history_only": history_only,
        "typed_only": typed_only,
        "confirmed_typed_count": len(both),
        "note": (
            "Terms in 'typed_and_in_history' appear in both formhistory.sqlite "
            "and places.sqlite, indicating deliberate keyboard entry. Terms in "
            "'history_only' may have originated from a redirect, a suggestion or "
            "a link click and are weaker evidence of authorship."
        ),
    }
