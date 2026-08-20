"""
Time conversion helpers for Firefox artefacts.

Firefox stores most timestamps as **PRTime**: the number of *microseconds*
since the Unix epoch (1970-01-01T00:00:00Z).  A handful of columns
(``moz_cookies.expiry``) use whole seconds instead.

Case 029 note
-------------
The examination in Case File 029 was carried out in a ``GMT+1`` locale and all
grids in the report render wall-clock local time.  Every function here takes an
explicit ``tzinfo`` so a report can be regenerated in the examination timezone
(reproducing the original grids) *or* in UTC (preferred for disclosure), with
no hidden dependence on the workstation clock.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Optional

try:  # pragma: no cover - availability depends on the host OS tzdata
    from zoneinfo import ZoneInfo

    _HAVE_ZONEINFO = True
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment]
    _HAVE_ZONEINFO = False

UTC = _dt.timezone.utc

#: Firefox PRTime resolution (microseconds per second).
PRTIME_SCALE = 1_000_000

_OFFSET_RE = re.compile(r"^(?P<sign>[+-])(?P<hh>\d{1,2})(?::?(?P<mm>\d{2}))?$")

DEFAULT_FORMAT = "%Y-%m-%d %H:%M:%S"


class TimezoneError(ValueError):
    """Raised when a timezone specification cannot be resolved."""


def parse_tz(spec: Optional[str]) -> _dt.tzinfo:
    """Resolve a timezone specification into a ``tzinfo`` object.

    Accepted forms:

    * ``None`` / ``"UTC"``          -> UTC
    * ``"+01:00"``, ``"+0100"``, ``"-5"`` -> fixed UTC offset
    * ``"Europe/Copenhagen"``       -> IANA zone (requires system tzdata)

    Fixed offsets are recommended for court-ready reproducibility because they
    never depend on the tzdata version installed on the examiner's machine.

    >>> parse_tz("+01:00").utcoffset(None)
    datetime.timedelta(seconds=3600)
    """
    if spec is None or spec.strip() == "":
        return UTC

    spec = spec.strip()
    if spec.upper() in {"UTC", "Z", "GMT"}:
        return UTC

    match = _OFFSET_RE.match(spec)
    if match:
        hours = int(match.group("hh"))
        minutes = int(match.group("mm") or 0)
        if hours > 23 or minutes > 59:
            raise TimezoneError(f"UTC offset out of range: {spec!r}")
        delta = _dt.timedelta(hours=hours, minutes=minutes)
        if match.group("sign") == "-":
            delta = -delta
        return _dt.timezone(delta, name=f"UTC{spec}")

    if _HAVE_ZONEINFO:
        try:
            return ZoneInfo(spec)  # type: ignore[misc]
        except Exception as exc:  # pragma: no cover - depends on host tzdata
            raise TimezoneError(f"Unknown timezone {spec!r}: {exc}") from exc

    raise TimezoneError(
        f"Cannot resolve timezone {spec!r}; zoneinfo is unavailable on this host. "
        "Use a fixed offset such as '+01:00'."
    )


def tz_label(tz: _dt.tzinfo) -> str:
    """Human readable label for a tzinfo, e.g. ``UTC+01:00``."""
    offset = tz.utcoffset(_dt.datetime(2000, 1, 1))
    if offset is None:  # pragma: no cover - defensive
        return str(tz)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    name = getattr(tz, "key", None) or ""
    stamp = f"UTC{sign}{total_minutes // 60:02d}:{total_minutes % 60:02d}"
    return f"{name} ({stamp})" if name else stamp


def prtime_to_datetime(
    value: Optional[int], tz: Optional[_dt.tzinfo] = None
) -> Optional[_dt.datetime]:
    """Convert a Firefox PRTime (microseconds) value to an aware ``datetime``.

    Returns ``None`` for ``NULL`` / ``0`` values, which Firefox uses for
    "never visited" or "no timestamp recorded".
    """
    if value in (None, 0):
        return None
    try:
        seconds = int(value) / PRTIME_SCALE
    except (TypeError, ValueError):
        return None
    # Guard against corrupted rows producing OverflowError.
    if not (-62135596800 < seconds < 253402300799):
        return None
    return _dt.datetime.fromtimestamp(seconds, tz or UTC)


def epoch_seconds_to_datetime(
    value: Optional[int], tz: Optional[_dt.tzinfo] = None
) -> Optional[_dt.datetime]:
    """Convert a whole-second epoch value (e.g. ``moz_cookies.expiry``)."""
    if value in (None, 0):
        return None
    return prtime_to_datetime(int(value) * PRTIME_SCALE, tz)


def prtime_to_string(
    value: Optional[int],
    tz: Optional[_dt.tzinfo] = None,
    fmt: str = DEFAULT_FORMAT,
    empty: str = "",
) -> str:
    """Format a PRTime value exactly as the Case 029 grids render it."""
    dt = prtime_to_datetime(value, tz)
    return dt.strftime(fmt) if dt else empty


def datetime_to_prtime(dt: _dt.datetime) -> int:
    """Inverse of :func:`prtime_to_datetime` (used by the sample-data builder)."""
    if dt.tzinfo is None:
        raise ValueError("Refusing to convert a naive datetime; attach a tzinfo.")
    return int(dt.timestamp() * PRTIME_SCALE)


def now_iso() -> str:
    """UTC ISO-8601 timestamp used for audit-trail entries."""
    return _dt.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
