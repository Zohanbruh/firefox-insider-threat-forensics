"""
ffxforensics — Firefox Browser Artefact Forensics Toolkit.

A reproducible, ACPO-aligned toolkit for the acquisition, preservation and
analysis of Mozilla Firefox browser artefacts (places.sqlite, cookies.sqlite,
formhistory.sqlite).

Built to operationalise the methodology documented in Case File 029
("Insider Threat" browser forensics investigation).

The library is deliberately dependency-free (Python standard library only)
so that it can be executed inside locked-down forensic workstations where
installing third-party packages is not permitted.
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Case 029 Digital Forensics Toolkit contributors"
__license__ = "MIT"

from ffxforensics.acquire import AcquisitionResult, acquire_profile  # noqa: E402
from ffxforensics.audit import AuditEntry, AuditTrail  # noqa: E402
from ffxforensics.hashing import (  # noqa: E402
    hash_directory,
    sha256_file,
    verify_manifest,
    write_manifest,
)
from ffxforensics.timeutil import (  # noqa: E402
    parse_tz,
    prtime_to_datetime,
    prtime_to_string,
)

__all__ = [
    "__version__",
    "sha256_file",
    "hash_directory",
    "write_manifest",
    "verify_manifest",
    "AuditTrail",
    "AuditEntry",
    "acquire_profile",
    "AcquisitionResult",
    "parse_tz",
    "prtime_to_datetime",
    "prtime_to_string",
]
