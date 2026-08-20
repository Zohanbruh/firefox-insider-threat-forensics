"""
``cookies.sqlite`` — which domains the browser actually held sessions with.

Cookies corroborate history: a domain with a cookie whose ``lastAccessed``
falls inside the activity window was genuinely loaded in the browser, which is
harder to explain away than a URL that could have been auto-suggested.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

from ffxforensics.models import CookieRecord
from ffxforensics.parsers.base import SQLiteArtefact
from ffxforensics.timeutil import epoch_seconds_to_datetime, prtime_to_datetime

#: Hosts that indicate advertising / analytics rather than deliberate browsing.
THIRD_PARTY_HINTS = (
    "doubleclick",
    "googlesyndication",
    "googleadservices",
    "adservice",
    "scorecardresearch",
    "hotjar",
    "segment.io",
    "facebook.com",
)


class CookiesArtefact(SQLiteArtefact):
    """Read-only accessor for ``cookies.sqlite``."""

    artefact_name = "cookies"
    required_tables = ("moz_cookies",)

    def cookies(self, host_like: Optional[str] = None) -> List[CookieRecord]:
        """All cookies, most recently accessed first."""
        columns = set(self.columns("moz_cookies"))
        same_site_col = "sameSite" if "sameSite" in columns else "0 AS sameSite"
        name_col = "COALESCE(name, '') AS name" if "name" in columns else "'' AS name"

        sql = (
            f"SELECT id, host, {name_col}, COALESCE(path, '') AS path, "
            "       COALESCE(isSecure, 0) AS isSecure, "
            "       COALESCE(isHttpOnly, 0) AS isHttpOnly, "
            f"       {same_site_col}, creationTime, lastAccessed, expiry "
            "FROM moz_cookies "
        )
        params: List[str] = []
        if host_like:
            sql += "WHERE host LIKE ? "
            params.append(host_like)
        sql += "ORDER BY lastAccessed DESC"

        return [
            CookieRecord(
                id=row["id"],
                host=row["host"],
                name=row["name"],
                path=row["path"],
                is_secure=row["isSecure"],
                is_http_only=row["isHttpOnly"],
                same_site=row["sameSite"],
                creation_time=prtime_to_datetime(row["creationTime"], self.tz),
                last_accessed=prtime_to_datetime(row["lastAccessed"], self.tz),
                expiry=epoch_seconds_to_datetime(row["expiry"], self.tz),
            )
            for row in self.query(sql, params)
        ]

    def host_summary(self) -> List[Dict[str, object]]:
        """Cookie count and newest access per host, busiest host first."""
        records = self.cookies()
        counter: Counter = Counter(record.host.lstrip(".") for record in records)
        newest: Dict[str, object] = {}
        for record in records:
            host = record.host.lstrip(".")
            if record.last_accessed and (
                host not in newest or record.last_accessed > newest[host]  # type: ignore[operator]
            ):
                newest[host] = record.last_accessed

        return [
            {
                "host": host,
                "cookies": count,
                "last_accessed": newest.get(host),
                "third_party": any(hint in host for hint in THIRD_PARTY_HINTS),
            }
            for host, count in counter.most_common()
        ]

    def statistics(self) -> Dict[str, int]:
        records = self.cookies()
        return {
            "cookies": len(records),
            "distinct_hosts": len({record.host.lstrip(".") for record in records}),
            "secure": sum(1 for record in records if record.is_secure),
            "http_only": sum(1 for record in records if record.is_http_only),
        }
