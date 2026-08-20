"""
Audit trail — ACPO Principle 3.

    "An audit trail or other record of all processes applied to digital
     evidence should be created and preserved. An independent third party
     should be able to examine those processes and achieve the same result."

Every action this toolkit performs against evidence appends a row here.  The
schema mirrors the manual audit-trail table in the Case 029 report:

    Case Chronology | Procedure | Tool / Command | Explanation | Document ID + Hash
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ffxforensics.timeutil import now_iso

#: Canonical procedure phases, matching the report's structure.
PHASES = (
    "Evidence Identification",
    "Evidence Collection",
    "Evidence Preservation",
    "Analysing",
    "Reporting",
)

FIELDNAMES = [
    "seq",
    "timestamp_utc",
    "phase",
    "tool",
    "command",
    "explanation",
    "artefact",
    "hash",
    "outcome",
]


@dataclass
class AuditEntry:
    """A single, immutable line of the audit trail."""

    seq: int
    timestamp_utc: str
    phase: str
    tool: str
    command: str
    explanation: str
    artefact: str = ""
    hash: str = ""
    outcome: str = "OK"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def as_markdown_row(self) -> str:
        def esc(value: str) -> str:
            return str(value).replace("|", "\\|").replace("\n", "<br>")

        return (
            f"| {self.seq} | {esc(self.timestamp_utc)} | {esc(self.phase)} | "
            f"`{esc(self.command) or esc(self.tool)}` | {esc(self.explanation)} | "
            f"{esc(self.artefact)} | `{esc(self.hash)}` | {esc(self.outcome)} |"
        )


class AuditTrail:
    """Append-only audit log.

    Usage::

        trail = AuditTrail(case_id="029", examiner="A. Adhikari")
        trail.record("Analysing", "DB Browser for SQLite",
                     command="SELECT ... FROM moz_places",
                     explanation="Timeline of visited URLs")
        trail.to_csv("results/audit_trail.csv")

    The object never mutates or deletes previous entries; ``record`` is the
    only way to add one, and it always stamps UTC time.
    """

    def __init__(
        self,
        case_id: str = "",
        examiner: str = "",
        entries: Optional[Iterable[AuditEntry]] = None,
    ) -> None:
        self.case_id = case_id
        self.examiner = examiner
        self._entries: List[AuditEntry] = list(entries or [])

    # -- construction ---------------------------------------------------
    def record(
        self,
        phase: str,
        tool: str,
        command: str = "",
        explanation: str = "",
        artefact: str = "",
        hash_value: str = "",
        outcome: str = "OK",
    ) -> AuditEntry:
        """Append one entry and return it."""
        entry = AuditEntry(
            seq=len(self._entries) + 1,
            timestamp_utc=now_iso(),
            phase=phase,
            tool=tool,
            command=command,
            explanation=explanation,
            artefact=str(artefact),
            hash=hash_value,
            outcome=outcome,
        )
        self._entries.append(entry)
        return entry

    # -- access ---------------------------------------------------------
    @property
    def entries(self) -> List[AuditEntry]:
        """A *copy* of the entries, so callers cannot rewrite history."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self.entries)

    def filter(self, phase: str) -> List[AuditEntry]:
        return [entry for entry in self._entries if entry.phase == phase]

    # -- export ---------------------------------------------------------
    def to_csv(self, path: os.PathLike | str) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            writer.writeheader()
            for entry in self._entries:
                writer.writerow(entry.as_dict())
        return path

    def to_json(self, path: os.PathLike | str) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "case_id": self.case_id,
            "examiner": self.examiner,
            "generated_utc": now_iso(),
            "entries": [entry.as_dict() for entry in self._entries],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def to_markdown(self) -> str:
        header = (
            "| # | Timestamp (UTC) | Procedure | Tool / Command | Explanation | "
            "Artefact | Hash | Outcome |\n"
            "|---|---|---|---|---|---|---|---|\n"
        )
        body = "\n".join(entry.as_markdown_row() for entry in self._entries)
        title = f"### Audit trail — case {self.case_id or 'n/a'}"
        if self.examiner:
            title += f" (examiner: {self.examiner})"
        return f"{title}\n\n{header}{body}\n"

    def write_markdown(self, path: os.PathLike | str) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown(), encoding="utf-8")
        return path

    # -- reload ---------------------------------------------------------
    @classmethod
    def from_json(cls, path: os.PathLike | str) -> "AuditTrail":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = [AuditEntry(**row) for row in payload.get("entries", [])]
        return cls(
            case_id=payload.get("case_id", ""),
            examiner=payload.get("examiner", ""),
            entries=entries,
        )
