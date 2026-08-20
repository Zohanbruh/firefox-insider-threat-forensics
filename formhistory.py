"""
``formhistory.sqlite`` — what the user physically typed.

This is the strongest artefact for *authorship*: history can be populated by a
redirect or a suggestion, but a ``moz_formhistory`` row means text was entered
into a form or the search bar.  ``timesUsed`` also shows repetition, which
distinguishes idle curiosity from a term someone returned to.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ffxforensics.models import FormHistoryRecord
from ffxforensics.parsers.base import SQLiteArtefact
from ffxforensics.timeutil import prtime_to_datetime

#: Field names Firefox uses for the search bar / address bar keyword search.
SEARCHBAR_FIELDS = ("searchbar-history", "q", "search", "query", "search_query")


class FormHistoryArtefact(SQLiteArtefact):
    """Read-only accessor for ``formhistory.sqlite``."""

    artefact_name = "formhistory"
    required_tables = ("moz_formhistory",)

    def entries(self, fieldname: Optional[str] = None) -> List[FormHistoryRecord]:
        """All stored form values, most recently used first."""
        sql = (
            "SELECT id, fieldname, value, COALESCE(timesUsed, 0) AS timesUsed, "
            "       firstUsed, lastUsed "
            "FROM moz_formhistory "
        )
        params: List[str] = []
        if fieldname:
            sql += "WHERE fieldname = ? "
            params.append(fieldname)
        sql += "ORDER BY lastUsed DESC"

        return [
            FormHistoryRecord(
                id=row["id"],
                fieldname=row["fieldname"],
                value=row["value"],
                times_used=row["timesUsed"],
                first_used=prtime_to_datetime(row["firstUsed"], self.tz),
                last_used=prtime_to_datetime(row["lastUsed"], self.tz),
            )
            for row in self.query(sql, params)
        ]

    def typed_searches(self) -> List[FormHistoryRecord]:
        """Only the entries that represent a search the user typed."""
        return [
            record
            for record in self.entries()
            if record.fieldname in SEARCHBAR_FIELDS
        ]

    def statistics(self) -> Dict[str, int]:
        records = self.entries()
        return {
            "entries": len(records),
            "distinct_fields": len({record.fieldname for record in records}),
            "typed_searches": len(self.typed_searches()),
            "total_uses": sum(record.times_used for record in records),
        }
