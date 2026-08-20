"""Timestamp conversion — silent timezone errors are how timelines go wrong."""

from __future__ import annotations

import datetime as dt

import pytest

from ffxforensics.timeutil import (
    TimezoneError,
    datetime_to_prtime,
    epoch_seconds_to_datetime,
    parse_tz,
    prtime_to_datetime,
    prtime_to_string,
    tz_label,
)


@pytest.mark.parametrize(
    "spec,expected_seconds",
    [("UTC", 0), (None, 0), ("", 0), ("+01:00", 3600), ("+0100", 3600),
     ("-05:00", -18000), ("+05:30", 19800)],
)
def test_parse_tz_offsets(spec, expected_seconds) -> None:
    offset = parse_tz(spec).utcoffset(None)
    assert offset == dt.timedelta(seconds=expected_seconds)


def test_parse_tz_rejects_nonsense() -> None:
    with pytest.raises(TimezoneError):
        parse_tz("+99:00")
    with pytest.raises(TimezoneError):
        parse_tz("Not/AZone")


def test_prtime_roundtrip() -> None:
    original = dt.datetime(2025, 12, 2, 15, 16, 22, tzinfo=parse_tz("+01:00"))
    prtime = datetime_to_prtime(original)
    assert prtime == 1764684982_000000
    assert prtime_to_datetime(prtime, parse_tz("+01:00")) == original


def test_prtime_renders_in_the_requested_zone() -> None:
    """The same instant must render differently in different zones."""
    prtime = 1764684982_000000
    assert prtime_to_string(prtime, parse_tz("+01:00")) == "2025-12-02 15:16:22"
    assert prtime_to_string(prtime, parse_tz("UTC")) == "2025-12-02 14:16:22"


@pytest.mark.parametrize("value", [None, 0])
def test_null_timestamps_return_none(value) -> None:
    assert prtime_to_datetime(value) is None
    assert prtime_to_string(value) == ""


def test_corrupt_timestamps_do_not_raise() -> None:
    assert prtime_to_datetime(10**20) is None
    assert prtime_to_datetime("not a number") is None


def test_expiry_uses_whole_seconds() -> None:
    """moz_cookies.expiry is seconds, not microseconds."""
    result = epoch_seconds_to_datetime(1764684982, parse_tz("UTC"))
    assert result == dt.datetime(2025, 12, 2, 14, 16, 22, tzinfo=parse_tz("UTC"))


def test_naive_datetime_is_refused() -> None:
    with pytest.raises(ValueError):
        datetime_to_prtime(dt.datetime(2025, 12, 2, 15, 0, 0))


def test_tz_label_is_human_readable() -> None:
    assert tz_label(parse_tz("+01:00")) == "UTC+01:00"
    assert tz_label(parse_tz("UTC")) == "UTC+00:00"
