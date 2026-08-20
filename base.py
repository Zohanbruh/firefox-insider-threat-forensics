"""
Forensically-sound SQLite access.

Two things matter when opening browser databases as evidence:

1. **Never write.**  A plain ``sqlite3.connect(path)`` can create ``-wal`` /
   ``-journal`` side files and update the header, which changes the hash of the
   evidence and breaks ACPO Principle 1.  We therefore open with the URI flags
   ``mode=ro&immutable=1``, which tells SQLite the file cannot change and stops
   it from touching the filesystem at all.

2. **Fail loudly on the wrong file.**  A profile can contain a corrupt or
   truncated database; the parser reports that rather than returning silently
   empty results that an examiner might mistake for "no activity".
"""

from __future__ import annotations

import datetime as _dt
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ffxforensics.hashing import sha256_file
from ffxforensics.timeutil import UTC


class ArtefactError(Exception):
    """Raised when an artefact cannot be opened or is not the expected type."""


class SQLiteArtefact:
    """Base class for read-only access to a Firefox SQLite artefact."""

    #: Tables that must exist for the file to be considered valid.
    required_tables: Sequence[str] = ()
    #: Human-friendly artefact name used in messages and reports.
    artefact_name: str = "sqlite"

    def __init__(
        self,
        path: os.PathLike | str,
        tz: Optional[_dt.tzinfo] = None,
        compute_hash: bool = True,
    ) -> None:
        self.path = Path(path)
        self.tz = tz or UTC
        if not self.path.is_file():
            raise ArtefactError(f"Artefact not found: {self.path}")
        self.sha256 = sha256_file(self.path) if compute_hash else ""
        self._conn: Optional[sqlite3.Connection] = None
        self._tables: Optional[set] = None

    # -- lifecycle ------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        """Open (once) an immutable, read-only connection."""
        if self._conn is None:
            uri = f"file:{self.path.as_posix()}?mode=ro&immutable=1"
            try:
                self._conn = sqlite3.connect(uri, uri=True)
            except sqlite3.Error as exc:  # pragma: no cover - platform dependent
                raise ArtefactError(f"Cannot open {self.path}: {exc}") from exc
            self._conn.row_factory = sqlite3.Row
            self._validate()
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "SQLiteArtefact":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- introspection --------------------------------------------------
    @property
    def tables(self) -> set:
        """Set of table names present in the database."""
        if self._tables is None:
            rows = self.query(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            self._tables = {row["name"] for row in rows}
        return self._tables

    def has_table(self, name: str) -> bool:
        return name in self.tables

    def columns(self, table: str) -> List[str]:
        rows = self.query(f"PRAGMA table_info({table})")
        return [row["name"] for row in rows]

    def row_count(self, table: str) -> int:
        if not self.has_table(table):
            return 0
        return int(self.query(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"])

    def _validate(self) -> None:
        if not self.required_tables:
            return
        missing = [name for name in self.required_tables if name not in self.tables]
        if missing:
            raise ArtefactError(
                f"{self.path.name} does not look like a {self.artefact_name} "
                f"database; missing table(s): {', '.join(missing)}"
            )

    def integrity_check(self) -> str:
        """Run SQLite's own ``PRAGMA integrity_check``."""
        try:
            rows = self.query("PRAGMA integrity_check")
        except ArtefactError:  # pragma: no cover - defensive
            return "unavailable"
        return rows[0][0] if rows else "unknown"

    # -- querying -------------------------------------------------------
    def query(self, sql: str, params: Iterable[Any] = ()) -> List[sqlite3.Row]:
        """Execute a read-only query and return all rows."""
        conn = self._conn or self.connect()
        try:
            cursor = conn.execute(sql, tuple(params))
            return cursor.fetchall()
        except sqlite3.Error as exc:
            raise ArtefactError(f"Query failed on {self.path.name}: {exc}\nSQL: {sql}") from exc

    def summary(self) -> Dict[str, Any]:
        """Provenance block included in every generated report."""
        return {
            "artefact": self.artefact_name,
            "file": self.path.name,
            "path": str(self.path),
            "size_bytes": self.path.stat().st_size,
            "sha256": self.sha256,
            "tables": sorted(self.tables),
            "integrity_check": self.integrity_check(),
        }
