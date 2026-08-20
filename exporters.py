"""
Machine-readable exports.

CSV so an examiner can open findings in a spreadsheet or load them into a
case-management system; JSON so the whole result can be diffed between runs —
which is how the regression tests prove the toolkit is deterministic.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Sequence

from ffxforensics.case import CaseResult


def _write_csv(path: Path, fieldnames: Sequence[str], rows: Sequence[Dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def export_searches(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "query": search.query,
            "engine": search.engine,
            "last_visited": search.last_visited_str,
            "visit_count": search.visit_count,
            "url": search.url,
        }
        for search in result.searches
    ]
    return _write_csv(
        Path(path), ["query", "engine", "last_visited", "visit_count", "url"], rows
    )


def export_history(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "id": place.id,
            "url": place.url,
            "title": place.title,
            "visit_count": place.visit_count,
            "typed": place.typed,
            "last_visit": place.last_visit_str,
        }
        for place in result.places
    ]
    return _write_csv(
        Path(path), ["id", "url", "title", "visit_count", "typed", "last_visit"], rows
    )


def export_visits(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "visit_id": visit.visit_id,
            "visit_date": visit.visit_date_str,
            "visit_type": visit.visit_type,
            "visit_type_label": visit.visit_type_label,
            "title": visit.title,
            "url": visit.url,
        }
        for visit in result.visits
    ]
    return _write_csv(
        Path(path),
        ["visit_id", "visit_date", "visit_type", "visit_type_label", "title", "url"],
        rows,
    )


def export_video_visits(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "url": visit.url,
            "title": visit.title,
            "last_activity": visit.visit_date_str,
            "visit_type": visit.visit_type_label,
        }
        for visit in result.video_visits
    ]
    return _write_csv(
        Path(path), ["url", "title", "last_activity", "visit_type"], rows
    )


def export_bookmarks(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "id": bookmark.id,
            "title": bookmark.title,
            "url": bookmark.url,
            "folder": bookmark.folder_path,
            "last_modified": bookmark.last_modified_str,
        }
        for bookmark in result.bookmark_entries
    ]
    return _write_csv(
        Path(path), ["id", "title", "url", "folder", "last_modified"], rows
    )


def export_cookies(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "id": cookie.id,
            "host": cookie.host,
            "name": cookie.name,
            "secure": cookie.is_secure,
            "http_only": cookie.is_http_only,
            "same_site": cookie.same_site_label,
            "last_accessed": cookie.last_accessed_str,
        }
        for cookie in result.cookies
    ]
    return _write_csv(
        Path(path),
        ["id", "host", "name", "secure", "http_only", "same_site", "last_accessed"],
        rows,
    )


def export_form_history(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "id": entry.id,
            "fieldname": entry.fieldname,
            "value": entry.value,
            "times_used": entry.times_used,
            "last_used": entry.last_used_str,
        }
        for entry in result.form_history
    ]
    return _write_csv(
        Path(path), ["id", "fieldname", "value", "times_used", "last_used"], rows
    )


def export_downloads(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "file_name": download.file_name,
            "source_url": download.source_url,
            "target_path": download.target_path,
            "file_size": download.file_size or "",
            "started": download.started_str,
        }
        for download in result.downloads
    ]
    return _write_csv(
        Path(path),
        ["file_name", "source_url", "target_path", "file_size", "started"],
        rows,
    )


def export_visit_types(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {"visit_category": code, "meaning": data["label"], "web_presence_count": data["count"]}
        for code, data in result.visit_types.items()
    ]
    return _write_csv(
        Path(path), ["visit_category", "meaning", "web_presence_count"], rows
    )


def export_timeline(result: CaseResult, path: os.PathLike | str) -> Path:
    rows = [
        {
            "timestamp": event.timestamp_str,
            "source": event.source,
            "event_type": event.event_type,
            "description": event.description,
            "detail": event.detail,
            "severity": event.severity,
            "indicators": ";".join(event.indicators),
        }
        for event in result.timeline
    ]
    return _write_csv(
        Path(path),
        ["timestamp", "source", "event_type", "description", "detail", "severity", "indicators"],
        rows,
    )


def export_findings_json(result: CaseResult, path: os.PathLike | str) -> Path:
    """Full structured result — the canonical machine-readable output."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1.0",
        "case": result.metadata.as_dict(),
        "generated_utc": result.generated_utc,
        "timezone": result.timezone,
        "evidence_dir": str(result.evidence_dir),
        "artefacts": result.artefacts,
        "statistics": result.statistics,
        "activity_window": result.window,
        "sessions": [session.as_dict() for session in result.sessions],
        "visit_types": {
            str(code): data for code, data in result.visit_types.items()
        },
        "searches": [search.as_dict() for search in result.searches],
        "video_visits": [visit.as_dict() for visit in result.video_visits],
        "bookmarks": [bookmark.as_dict() for bookmark in result.bookmark_entries],
        "downloads": [download.as_dict() for download in result.downloads],
        "cookie_hosts": [
            {
                **host,
                "last_accessed": host["last_accessed"].isoformat()
                if host.get("last_accessed")
                else None,
            }
            for host in result.cookie_hosts
        ],
        "form_history": [entry.as_dict() for entry in result.form_history],
        "assessment": result.assessment,
        "integrity": result.integrity,
        "errors": result.errors,
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


#: name -> exporter, used by the CLI to write the whole result set at once.
EXPORTERS = {
    "searches.csv": export_searches,
    "history.csv": export_history,
    "visits.csv": export_visits,
    "video_visits.csv": export_video_visits,
    "bookmarks.csv": export_bookmarks,
    "cookies.csv": export_cookies,
    "form_history.csv": export_form_history,
    "downloads.csv": export_downloads,
    "visit_types.csv": export_visit_types,
    "timeline.csv": export_timeline,
    "findings.json": export_findings_json,
}


def export_all(result: CaseResult, out_dir: os.PathLike | str) -> List[Path]:
    """Write every export into ``out_dir`` and return the paths created."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    return [exporter(result, out_dir / name) for name, exporter in EXPORTERS.items()]
