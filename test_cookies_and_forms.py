"""cookies.sqlite and formhistory.sqlite parsers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ffxforensics.parsers import ArtefactError, CookiesArtefact, FormHistoryArtefact


# ---------------------------------------------------------------- cookies
def test_cookies_are_ordered_newest_first(cookies_path: Path, case_tz) -> None:
    with CookiesArtefact(cookies_path, tz=case_tz) as cookies:
        records = cookies.cookies()
    stamps = [record.last_accessed for record in records if record.last_accessed]
    assert stamps == sorted(stamps, reverse=True)


def test_cookie_host_filter(cookies_path: Path) -> None:
    with CookiesArtefact(cookies_path) as cookies:
        neoquant = cookies.cookies(host_like="%neoquant%")
    assert neoquant
    assert all("neoquant" in record.host for record in neoquant)


def test_same_site_labels(cookies_path: Path) -> None:
    with CookiesArtefact(cookies_path) as cookies:
        labels = {record.same_site_label for record in cookies.cookies()}
    assert labels <= {"None", "Lax", "Strict", "Unset"}


def test_host_summary_flags_third_party_trackers(cookies_path: Path) -> None:
    with CookiesArtefact(cookies_path) as cookies:
        hosts = cookies.host_summary()
    by_host = {entry["host"]: entry for entry in hosts}
    assert by_host["doubleclick.net"]["third_party"] is True
    assert by_host["neoquant.com"]["third_party"] is False
    # counts descend
    counts = [entry["cookies"] for entry in hosts]
    assert counts == sorted(counts, reverse=True)


def test_expiry_is_parsed_as_seconds_not_microseconds(cookies_path: Path) -> None:
    """A microsecond misreading would push expiry ~50,000 years into the future."""
    with CookiesArtefact(cookies_path) as cookies:
        expiries = [c.expiry for c in cookies.cookies() if c.expiry]
    assert expiries
    assert all(2020 < value.year < 2100 for value in expiries)


def test_rejects_a_database_that_is_not_cookies(tmp_path: Path) -> None:
    bogus = tmp_path / "cookies.sqlite"
    conn = sqlite3.connect(bogus)
    conn.execute("CREATE TABLE something_else (id INTEGER)")
    conn.commit()
    conn.close()
    with pytest.raises(ArtefactError):
        CookiesArtefact(bogus).connect()


def test_handles_schema_without_optional_columns(tmp_path: Path) -> None:
    """Older profiles have no `sameSite` column; the parser must cope."""
    legacy = tmp_path / "cookies.sqlite"
    conn = sqlite3.connect(legacy)
    conn.execute(
        "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, "
        "path TEXT, isSecure INTEGER, isHttpOnly INTEGER, creationTime INTEGER, "
        "lastAccessed INTEGER, expiry INTEGER)"
    )
    conn.execute(
        "INSERT INTO moz_cookies VALUES (1,'example.com','sid','/',1,1,0,0,0)"
    )
    conn.commit()
    conn.close()

    with CookiesArtefact(legacy) as cookies:
        records = cookies.cookies()
    assert records[0].same_site_label == "None"


# ----------------------------------------------------------- form history
def test_form_entries_ordered_newest_first(formhistory_path: Path, case_tz) -> None:
    with FormHistoryArtefact(formhistory_path, tz=case_tz) as forms:
        records = forms.entries()
    stamps = [record.last_used for record in records if record.last_used]
    assert stamps == sorted(stamps, reverse=True)


def test_typed_searches_exclude_ordinary_form_fields(formhistory_path: Path) -> None:
    with FormHistoryArtefact(formhistory_path) as forms:
        all_fields = {record.fieldname for record in forms.entries()}
        typed = forms.typed_searches()
    assert "email" in all_fields
    assert all(record.fieldname != "email" for record in typed)


def test_times_used_is_preserved(formhistory_path: Path) -> None:
    with FormHistoryArtefact(formhistory_path) as forms:
        repeated = [r for r in forms.entries() if r.times_used > 1]
    assert repeated, "repetition is evidentially significant and must survive parsing"


def test_fieldname_filter(formhistory_path: Path) -> None:
    with FormHistoryArtefact(formhistory_path) as forms:
        only_q = forms.entries(fieldname="q")
    assert only_q
    assert all(record.fieldname == "q" for record in only_q)
