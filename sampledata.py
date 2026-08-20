"""
Reconstruction of the Case 029 evidence set.

Why this module exists
----------------------
The original Firefox profile examined in Case File 029 is not distributable —
it is case material.  Without evidence, the toolkit cannot be demonstrated,
regression-tested or peer-reviewed.

This module therefore builds a **synthetic profile with genuine Firefox
schemas**, populated so that the analysis output reproduces the published
findings exactly:

===================  ==========================================================
Report artefact      Reproduced here
===================  ==========================================================
Grid 4.2             12 search queries with their exact last-visited times
Grid 4.3             4 YouTube videos with their exact watch times
Grid 4.4 / Image 3   11 ``moz_bookmarks`` rows with their exact modification times
Grid 4.5             visit-type distribution 29 / 19 / 0 / 0 / 3 / 5 (56 visits)
Audit trail          a ``moz_annos`` download record for the API attack-vectors PDF
===================  ==========================================================

Everything is fabricated: the individual, the employer, the domains and the
video identifiers are illustrative and correspond to no real person or system.
Use it for testing, teaching and CI — never as evidence.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ffxforensics.timeutil import datetime_to_prtime, parse_tz

CASE_DATE = (2025, 12, 2)

# visit_type codes
LINK = 1
TYPED = 2
BOOKMARK = 3
EMBED = 4
REDIRECT_PERMANENT = 5
REDIRECT_TEMPORARY = 6

GOOGLE = "https://www.google.com/search?q={q}&source=hp"


def _google(query: str) -> Tuple[str, str]:
    """Build a realistic Google SERP URL and title for ``query``."""
    encoded = query.replace(" ", "+").replace('"', "%22")
    return GOOGLE.format(q=encoded), f"{query} - Google Search"


# ---------------------------------------------------------------------------
# The scenario: one continuous 21-minute browsing session.
# Each row is (hh, mm, ss, url, title, visit_type).
# ---------------------------------------------------------------------------
def _scenario() -> List[Tuple[int, int, int, str, str, int]]:
    events: List[Tuple[int, int, int, str, str, int]] = []

    def add(hh: int, mm: int, ss: int, url: str, title: str, visit_type: int) -> None:
        events.append((hh, mm, ss, url, title, visit_type))

    def search(hh: int, mm: int, ss: int, query: str) -> None:
        url, title = _google(query)
        add(hh, mm, ss, url, title, TYPED)

    # --- opening the browser ------------------------------------------------
    add(15, 15, 40, "https://www.google.com/", "Google", TYPED)

    # --- Grid 4.2 search queries, interleaved with the pages opened from them
    search(15, 16, 22, "NeoQuant sql error page exploit")
    add(15, 16, 58, "https://portswigger.net/web-security/sql-injection",
        "What is SQL Injection? Tutorial & Examples | Web Security Academy", LINK)
    add(15, 17, 12,
        "https://stackoverflow.com/questions/332365/how-does-the-sql-injection-from-bobby-tables-work",
        "How does the SQL injection from the Bobby Tables XKCD comic work? - Stack Overflow",
        LINK)

    search(15, 17, 40, "Test sql injection using browser only")
    add(15, 18, 5, "https://owasp.org/www-project-web-security-testing-guide/",
        "OWASP Web Security Testing Guide | OWASP Foundation", LINK)

    search(15, 18, 31, "Find exposed database endpoints in API")
    add(15, 18, 52, "http://apisecurity.io/", "API Security News", LINK)
    add(15, 18, 55, "https://apisecurity.io/", "API Security News", REDIRECT_TEMPORARY)

    search(15, 19, 6, "Financial api sql injection examples")
    add(15, 19, 22, "https://owasp.org/www-project-web-security-testing-guide/",
        "OWASP Web Security Testing Guide | OWASP Foundation", LINK)

    search(15, 19, 41, "How to force debug mode using URL parameters")
    add(15, 20, 40, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods",
        "HTTP request methods - MDN Web Docs", LINK)

    search(15, 20, 16, "Bypass client-side validation by modifying URL")
    search(15, 21, 0, "Common api parameters that leak database info")
    add(15, 21, 25, "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        "OWASP API Security Top 10 2023", LINK)

    search(15, 21, 49, "Check API vulnerabilities using chrome DevTools network tab")
    add(15, 22, 30, "https://portswigger.net/web-security/sql-injection/cheat-sheet",
        "SQL injection cheat sheet | Web Security Academy", LINK)
    add(15, 22, 48, "https://portswigger.net/web-security/sql-injection",
        "What is SQL Injection? Tutorial & Examples | Web Security Academy", LINK)

    search(15, 23, 11, "Common api vectors.pdf download")
    add(15, 23, 28,
        "https://www.google.com/url?q=https://www.practical-devsecops.com/api-security-fundamentals/",
        "", LINK)
    add(15, 23, 29, "https://www.practical-devsecops.com/api-security-fundamentals/",
        "API Security Fundamentals ebook - Practical DevSecOps", REDIRECT_TEMPORARY)
    add(15, 24, 2,
        "https://www.practical-devsecops.com/downloads/Common-API-Attack-Vectors.pdf",
        "Common-API-Attack-Vectors.pdf", LINK)
    add(15, 24, 15, "https://www.practical-devsecops.com/thank-you/",
        "Thank you - Practical DevSecOps", REDIRECT_TEMPORARY)

    # --- pivot to the employing organisation --------------------------------
    search(15, 25, 58, "neo quant")
    add(15, 26, 16, "https://neoquant.com/",
        "NeoQuant - Data Engineering & Digital Finance", LINK)
    add(15, 26, 44, "https://neoquant.com/products/data-platform/",
        "Data Platform - NeoQuant", LINK)
    add(15, 27, 20, "https://neoquant.com/about/", "About us - NeoQuant", LINK)
    add(15, 27, 55, "https://neoquant.com/contact/", "Contact - NeoQuant", LINK)

    search(15, 28, 57, "Neoquant finance - internal API docs")
    add(15, 29, 3, "http://neoquant.com/white-papers", "", REDIRECT_TEMPORARY)
    add(15, 29, 7, "https://neoquant.com/white-papers/", "white papers - NeoQuant", LINK)

    search(15, 29, 31, "sql injection cheat sheet - owasp")
    add(15, 29, 40, "https://owasp.org/www-community/attacks/SQL_Injection",
        "SQL Injection | OWASP Foundation", LINK)
    add(15, 29, 52,
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "SQL Injection Prevention - OWASP Cheat Sheet Series", LINK)

    search(15, 30, 9, "request inspector- test API requests")
    add(15, 30, 14, "https://requestinspector.com/",
        "Web Request Inspector & Probe Service | Request Inspector", LINK)
    add(15, 30, 26, "https://requestinspector.com/",
        "Web Request Inspector & Probe Service | Request Inspector", LINK)

    search(15, 30, 39, "URLScan - analyse web behaviour")
    add(15, 30, 47, "https://www.google.com/aclk?sa=l&ai=DChcSEwj", "", LINK)
    add(15, 30, 48, "https://lp.similarweb.com/?utm_source=google&utm_medium=cpc", "",
        REDIRECT_TEMPORARY)
    add(15, 30, 49, "https://lp.similarweb.com/competitive-analysis/",
        "Competitive Analysis | Similarweb", REDIRECT_PERMANENT)

    search(15, 31, 14, "chrome devtools network inspector guide")
    add(15, 31, 19, "https://developer.chrome.com/docs/devtools/network/",
        "Inspect network activity | Chrome DevTools | Chrome for developers", LINK)
    add(15, 31, 45, "https://developer.chrome.com/docs/devtools/network/",
        "Inspect network activity | Chrome DevTools | Chrome for developers", LINK)

    # --- Grid 4.3: video research -------------------------------------------
    add(15, 32, 27, "http://youtube.com/", "", TYPED)
    add(15, 32, 27, "https://youtube.com/", "", REDIRECT_PERMANENT)
    add(15, 32, 28, "https://www.youtube.com/", "YouTube", REDIRECT_PERMANENT)
    add(15, 33, 5,
        "https://www.youtube.com/results?search_query=lan+scan+internal+vulnerabilities",
        "lan scan internal vulnerabilities - YouTube", LINK)
    add(15, 33, 21, "https://www.youtube.com/watch?v=GD88Pp75Klw",
        "Using a LAN scan to find INTERNAL vulnerabilities", LINK)
    search(15, 33, 36, "youtube")
    add(15, 34, 20,
        "https://www.youtube.com/results?search_query=threats+vulnerabilities+and+exploits",
        "threats vulnerabilities and exploits - YouTube", LINK)
    add(15, 34, 50, "https://www.youtube.com/watch?v=8zSoyAmHHc4",
        "Threats Vulnerabilities and Exploits", LINK)
    add(15, 35, 37, "https://www.youtube.com/watch?v=QtwhEz-aON4",
        "AI Security Exposed: Why 95% of Companies Are Vulnerable", LINK)
    search(15, 36, 20, "firewall penetration testing steps methods tools")
    add(15, 36, 46, "https://www.youtube.com/watch?v=0Izu0J6iSoM",
        "Firewall Penetration Testing: Steps, Methods, and Tools", LINK)

    events.sort(key=lambda row: (row[0], row[1], row[2]))
    return events


# ---------------------------------------------------------------------------
# Grid 4.4 / Image 3 — bookmark tree
# ---------------------------------------------------------------------------
BOOKMARK_ROWS: Sequence[dict] = (
    {"id": 1, "type": 2, "parent": 0, "title": "", "url": None,
     "modified": (15, 31, 22), "added": (15, 2, 16), "guid": "root________"},
    {"id": 2, "type": 2, "parent": 1, "title": "menu", "url": None,
     "modified": (15, 2, 16), "added": (15, 2, 16), "guid": "menu________"},
    {"id": 3, "type": 2, "parent": 1, "title": "toolbar", "url": None,
     "modified": (15, 31, 22), "added": (15, 2, 16), "guid": "toolbar_____"},
    {"id": 4, "type": 2, "parent": 1, "title": "tags", "url": None,
     "modified": None, "added": None, "guid": "tags________"},
    {"id": 5, "type": 2, "parent": 1, "title": "unfiled", "url": None,
     "modified": None, "added": None, "guid": "unfiled_____"},
    {"id": 6, "type": 2, "parent": 1, "title": "mobile", "url": None,
     "modified": None, "added": None, "guid": "mobile______"},
    {"id": 7, "type": 1, "parent": 3, "title": "white papers - NeoQuant",
     "url": "https://neoquant.com/white-papers/",
     "modified": (15, 29, 11), "added": (15, 29, 11), "guid": "bkmk00000001"},
    {"id": 8, "type": 1, "parent": 3, "title": "SQL Injection | OWASP Foundation",
     "url": "https://owasp.org/www-community/attacks/SQL_Injection",
     "modified": (15, 29, 45), "added": (15, 29, 45), "guid": "bkmk00000002"},
    {"id": 9, "type": 1, "parent": 3,
     "title": "Web Request Inspector & Probe Service | Request Inspector",
     "url": "https://requestinspector.com/",
     "modified": (15, 30, 20), "added": (15, 30, 20), "guid": "bkmk00000003"},
    {"id": 10, "type": 1, "parent": 3, "title": "Competitive Analysis | Similarweb",
     "url": "https://lp.similarweb.com/competitive-analysis/",
     "modified": (15, 30, 54), "added": (15, 30, 54), "guid": "bkmk00000004"},
    {"id": 11, "type": 1, "parent": 3,
     "title": "Inspect network activity | Chrome DevTools | Chrome for developers",
     "url": "https://developer.chrome.com/docs/devtools/network/",
     "modified": (15, 31, 22), "added": (15, 31, 22), "guid": "bkmk00000005"},
)

#: Folder rows that pre-date the session (2025-10-01 16:01:59 in the report).
FOLDER_EPOCH = (2025, 10, 1, 16, 1, 59)

# ---------------------------------------------------------------------------
# formhistory.sqlite — what was physically typed
# ---------------------------------------------------------------------------
FORM_ENTRIES: Sequence[Tuple[str, str, int, Tuple[int, int, int]]] = (
    ("searchbar-history", "NeoQuant sql error page exploit", 1, (15, 16, 22)),
    ("searchbar-history", "Test sql injection using browser only", 2, (15, 17, 40)),
    ("searchbar-history", "Find exposed database endpoints in API", 1, (15, 18, 31)),
    ("searchbar-history", "Financial api sql injection examples", 1, (15, 19, 6)),
    ("searchbar-history", "How to force debug mode using URL parameters", 1, (15, 19, 41)),
    ("searchbar-history", "Bypass client-side validation by modifying URL", 1, (15, 20, 16)),
    ("searchbar-history", "Common api parameters that leak database info", 1, (15, 21, 0)),
    ("searchbar-history", "Check API vulnerabilities using chrome DevTools network tab",
     1, (15, 21, 49)),
    ("searchbar-history", "Common api vectors.pdf download", 1, (15, 23, 11)),
    ("searchbar-history", "neo quant", 1, (15, 25, 58)),
    ("searchbar-history", "Neoquant finance - internal API docs", 2, (15, 28, 57)),
    ("searchbar-history", "sql injection cheat sheet - owasp", 1, (15, 29, 31)),
    ("searchbar-history", "request inspector- test API requests", 1, (15, 30, 9)),
    ("searchbar-history", "chrome devtools network inspector guide", 1, (15, 31, 14)),
    ("searchbar-history", "firewall penetration testing steps methods tools", 1, (15, 36, 20)),
    # On-site search boxes, not search-engine queries.
    ("q", "api documentation", 3, (15, 27, 6)),
    ("q", "database schema", 1, (15, 27, 41)),
    ("search", "white paper", 1, (15, 29, 9)),
    ("email", "m.rao@neoquant.example", 1, (15, 30, 12)),
)

# ---------------------------------------------------------------------------
# cookies.sqlite
# ---------------------------------------------------------------------------
COOKIE_ROWS: Sequence[Tuple[str, str, int, int, int, Tuple[int, int, int]]] = (
    # host, name, isSecure, isHttpOnly, sameSite, lastAccessed
    (".google.com", "NID", 1, 1, 0, (15, 36, 20)),
    (".google.com", "AEC", 1, 1, 2, (15, 33, 36)),
    (".google.com", "SOCS", 1, 0, 0, (15, 16, 22)),
    ("www.google.com", "OTZ", 1, 0, 0, (15, 30, 47)),
    (".youtube.com", "VISITOR_INFO1_LIVE", 1, 1, 0, (15, 36, 46)),
    (".youtube.com", "YSC", 1, 1, 0, (15, 36, 46)),
    (".youtube.com", "PREF", 1, 0, 0, (15, 33, 5)),
    ("neoquant.com", "sessionid", 1, 1, 1, (15, 29, 7)),
    ("neoquant.com", "csrftoken", 1, 0, 2, (15, 29, 7)),
    ("neoquant.com", "_ga", 0, 0, 0, (15, 27, 55)),
    ("owasp.org", "_ga", 0, 0, 0, (15, 29, 52)),
    ("cheatsheetseries.owasp.org", "_ga", 0, 0, 0, (15, 29, 52)),
    ("requestinspector.com", "ri_session", 1, 1, 1, (15, 30, 26)),
    (".similarweb.com", "sw_uid", 1, 0, 0, (15, 30, 49)),
    ("lp.similarweb.com", "_hjSession", 1, 0, 0, (15, 30, 49)),
    ("www.practical-devsecops.com", "wordpress_test_cookie", 0, 1, 0, (15, 24, 15)),
    ("www.practical-devsecops.com", "_gid", 0, 0, 0, (15, 24, 15)),
    ("portswigger.net", "ASP.NET_SessionId", 1, 1, 1, (15, 22, 48)),
    ("developer.chrome.com", "__Secure-ENID", 1, 1, 2, (15, 31, 45)),
    ("developer.mozilla.org", "django_language", 1, 0, 1, (15, 20, 40)),
    ("stackoverflow.com", "prov", 1, 1, 0, (15, 17, 12)),
    ("apisecurity.io", "_cfuvid", 1, 1, 0, (15, 18, 55)),
    (".doubleclick.net", "IDE", 1, 1, 0, (15, 30, 48)),
    (".googlesyndication.com", "__gads", 1, 0, 0, (15, 30, 47)),
)

# ---------------------------------------------------------------------------
# Supporting (non-SQLite) profile files, so the acquisition workflow has a
# realistic tree to copy, hash and lock.
# ---------------------------------------------------------------------------
SUPPORT_FILES: Dict[str, str] = {
    "prefs.js": (
        '// Mozilla User Preferences\n'
        'user_pref("browser.startup.homepage", "https://neoquant.com/intranet");\n'
        'user_pref("browser.download.dir", "/home/users/mrao/Downloads");\n'
        'user_pref("privacy.clearOnShutdown.history", false);\n'
        'user_pref("devtools.everOpened", true);\n'
        'user_pref("devtools.netmonitor.enabled", true);\n'
    ),
    "times.json": '{"created": 1759327319000, "firstUse": 1759327400000}\n',
    "compatibility.ini": (
        "[Compatibility]\nLastVersion=128.13.0_20250801\nLastOSABI=Linux_x86_64-gcc3\n"
    ),
    "handlers.json": '{"defaultHandlersVersion": {"en-GB": 4}, "mimeTypes": {}}\n',
    "extensions.json": '{"schemaVersion": 36, "addons": []}\n',
    "addons.json": '{"schema": 6, "addons": []}\n',
    "search.json.mozlz4": "mozLz40\x00placeholder-binary-search-configuration\n",
    "sessionstore-backups/recovery.jsonlz4": "mozLz40\x00placeholder-session-store\n",
    "storage/permanent/.metadata": "placeholder\n",
    "bookmarkbackups/bookmarks-2025-12-01.jsonlz4": "mozLz40\x00placeholder-bookmark-backup\n",
    "datareporting/state.json": '{"clientID": "00000000-0000-4000-8000-000000000000"}\n',
    "security_state/data.safe.bin": "placeholder\n",
    "crashes/store.json.mozlz4": "mozLz40\x00placeholder\n",
    "minidumps/.keep": "\n",
    "gmp-gmpopenh264/1.8.1.2/gmpopenh264.info": "Name: gmpopenh264\nVersion: 1.8.1.2\n",
    "features/.keep": "\n",
    "saved-telemetry-pings/.keep": "\n",
    "settings/main/example.json": '{"data": []}\n',
    "storage.sqlite-wal-placeholder": "placeholder\n",
    "cert9.db": "placeholder-nss-certificate-database\n",
    "key4.db": "placeholder-nss-key-database\n",
    "pkcs11.txt": "library=\nname=NSS Internal PKCS #11 Module\n",
    "logins.json": '{"nextId": 1, "logins": [], "potentiallyVulnerablePasswords": []}\n',
    "containers.json": '{"version": 5, "identities": []}\n',
    "protections.sqlite-placeholder": "placeholder\n",
    "xulstore.json": '{"chrome://browser/content/browser.xhtml": {}}\n',
    "shield-preference-experiments.json": "{}\n",
    "targeting.snapshot.json": "{}\n",
    "enumerate_devices.txt": "\n",
    "SiteSecurityServiceState.bin": "placeholder\n",
    "AlternateServices.bin": "placeholder\n",
    "broadcast-listeners.json": '{"version": 3, "channels": []}\n',
    "pluginreg.dat": ":0.19:\n",
    "serviceworker.txt": "\n",
    "cookies.sqlite-journal-placeholder": "placeholder\n",
    "notificationstore.json": "{}\n",
    "parent.lock": "\n",
    "webappsstore.sqlite-placeholder": "placeholder\n",
    "storage-sync-v2.sqlite-placeholder": "placeholder\n",
    "favicons.sqlite-placeholder": "placeholder\n",
    "permissions.sqlite-placeholder": "placeholder\n",
    "content-prefs.sqlite-placeholder": "placeholder\n",
    "cookies.sqlite.bak-placeholder": "placeholder\n",
    "user.js": '// user overrides\nuser_pref("browser.cache.disk.enable", true);\n',
    "storage/default/.metadata-v2": "placeholder\n",
    "weave/failed/.keep": "\n",
    "README.txt": (
        "SYNTHETIC TEST PROFILE — Case 029 reconstruction.\n"
        "Fabricated data for software testing only. Not evidence.\n"
    ),
}


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------
PLACES_SCHEMA = """
CREATE TABLE moz_origins (
  id INTEGER PRIMARY KEY,
  prefix TEXT NOT NULL,
  host TEXT NOT NULL,
  frecency INTEGER NOT NULL,
  UNIQUE (prefix, host)
);
CREATE TABLE moz_places (
  id INTEGER PRIMARY KEY,
  url LONGVARCHAR,
  title LONGVARCHAR,
  rev_host LONGVARCHAR,
  visit_count INTEGER DEFAULT 0,
  hidden INTEGER DEFAULT 0 NOT NULL,
  typed INTEGER DEFAULT 0 NOT NULL,
  frecency INTEGER DEFAULT -1 NOT NULL,
  last_visit_date INTEGER,
  guid TEXT,
  foreign_count INTEGER DEFAULT 0 NOT NULL,
  url_hash INTEGER DEFAULT 0 NOT NULL,
  description TEXT,
  preview_image_url TEXT,
  site_name TEXT,
  origin_id INTEGER REFERENCES moz_origins(id)
);
CREATE TABLE moz_historyvisits (
  id INTEGER PRIMARY KEY,
  from_visit INTEGER,
  place_id INTEGER,
  visit_date INTEGER,
  visit_type INTEGER,
  session INTEGER,
  source INTEGER DEFAULT 0 NOT NULL,
  triggeringPlaceId INTEGER
);
CREATE TABLE moz_bookmarks (
  id INTEGER PRIMARY KEY,
  type INTEGER,
  fk INTEGER DEFAULT NULL,
  parent INTEGER,
  position INTEGER,
  title LONGVARCHAR,
  keyword_id INTEGER,
  folder_type TEXT,
  dateAdded INTEGER,
  lastModified INTEGER,
  guid TEXT,
  syncStatus INTEGER NOT NULL DEFAULT 0,
  syncChangeCounter INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE moz_anno_attributes (
  id INTEGER PRIMARY KEY,
  name VARCHAR(32) UNIQUE NOT NULL
);
CREATE TABLE moz_annos (
  id INTEGER PRIMARY KEY,
  place_id INTEGER NOT NULL,
  anno_attribute_id INTEGER,
  content LONGVARCHAR,
  flags INTEGER DEFAULT 0,
  expiration INTEGER DEFAULT 0,
  type INTEGER DEFAULT 0,
  dateAdded INTEGER DEFAULT 0,
  lastModified INTEGER DEFAULT 0
);
CREATE TABLE moz_inputhistory (
  place_id INTEGER NOT NULL,
  input LONGVARCHAR NOT NULL,
  use_count INTEGER,
  PRIMARY KEY (place_id, input)
);
CREATE TABLE moz_keywords (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  keyword TEXT UNIQUE,
  place_id INTEGER,
  post_data TEXT
);
CREATE TABLE moz_meta (key TEXT PRIMARY KEY, value NOT NULL) WITHOUT ROWID;
CREATE INDEX moz_places_url_hashindex ON moz_places (url_hash);
CREATE INDEX moz_historyvisits_placedateindex ON moz_historyvisits (place_id, visit_date);
"""

COOKIES_SCHEMA = """
CREATE TABLE moz_cookies (
  id INTEGER PRIMARY KEY,
  originAttributes TEXT NOT NULL DEFAULT '',
  name TEXT,
  value TEXT,
  host TEXT,
  path TEXT,
  expiry INTEGER,
  lastAccessed INTEGER,
  creationTime INTEGER,
  isSecure INTEGER,
  isHttpOnly INTEGER,
  inBrowserElement INTEGER DEFAULT 0,
  sameSite INTEGER DEFAULT 0,
  rawSameSite INTEGER DEFAULT 0,
  schemeMap INTEGER DEFAULT 0,
  CONSTRAINT moz_uniqueid UNIQUE (name, host, path, originAttributes)
);
"""

FORMHISTORY_SCHEMA = """
CREATE TABLE moz_formhistory (
  id INTEGER PRIMARY KEY,
  fieldname TEXT NOT NULL,
  value TEXT NOT NULL,
  timesUsed INTEGER,
  firstUsed INTEGER,
  lastUsed INTEGER,
  guid TEXT
);
CREATE TABLE moz_deleted_formhistory (
  id INTEGER PRIMARY KEY,
  timeDeleted INTEGER,
  guid TEXT
);
CREATE INDEX moz_formhistory_index ON moz_formhistory (fieldname);
"""


def _stamp(tz: _dt.tzinfo, hh: int, mm: int, ss: int) -> int:
    year, month, day = CASE_DATE
    return datetime_to_prtime(_dt.datetime(year, month, day, hh, mm, ss, tzinfo=tz))


def _url_hash(url: str) -> int:
    """Deterministic stand-in for Firefox's url_hash.

    ``hash()`` is salted per interpreter run (PYTHONHASHSEED), which would make
    the generated database — and therefore its SHA-256 — different on every
    run. Reproducibility is the whole point of this dataset, so we use a stable
    digest instead.
    """
    import hashlib

    return int(hashlib.sha1(url.encode("utf-8")).hexdigest()[:12], 16)


def _rev_host(url: str) -> str:
    """Firefox stores the reversed host with a trailing dot, e.g. ``moc.elpmaxe.``."""
    try:
        host = url.split("//", 1)[1].split("/", 1)[0]
    except IndexError:
        return "."
    return host[::-1] + "."


def _build_places(path: Path, tz: _dt.tzinfo) -> Dict[str, int]:
    events = _scenario()
    conn = sqlite3.connect(path)
    conn.executescript(PLACES_SCHEMA)

    place_ids: Dict[str, int] = {}
    place_meta: Dict[int, dict] = {}

    # moz_places rows are created in order of first appearance.
    for _hh, _mm, _ss, url, title, _visit_type in events:
        if url not in place_ids:
            place_id = len(place_ids) + 1
            place_ids[url] = place_id
            place_meta[place_id] = {
                "url": url,
                "title": title,
                "visit_count": 0,
                "typed": 0,
                "last": 0,
            }
        else:
            place_id = place_ids[url]
            if title and not place_meta[place_id]["title"]:
                place_meta[place_id]["title"] = title

    visit_rows = []
    previous_visit_id: Optional[int] = None
    for index, (hh, mm, ss, url, _title, visit_type) in enumerate(events, start=1):
        place_id = place_ids[url]
        stamp = _stamp(tz, hh, mm, ss)
        meta = place_meta[place_id]
        meta["visit_count"] += 1
        meta["last"] = max(meta["last"], stamp)
        if visit_type == TYPED:
            meta["typed"] = 1
        from_visit = (
            previous_visit_id
            if visit_type in (REDIRECT_PERMANENT, REDIRECT_TEMPORARY, LINK)
            else 0
        )
        visit_rows.append((index, from_visit or 0, place_id, stamp, visit_type, 1))
        previous_visit_id = index

    for place_id, meta in place_meta.items():
        conn.execute(
            "INSERT INTO moz_places (id, url, title, rev_host, visit_count, hidden, "
            "typed, frecency, last_visit_date, guid, foreign_count, url_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                place_id,
                meta["url"],
                meta["title"] or None,
                _rev_host(meta["url"]),
                meta["visit_count"],
                0,
                meta["typed"],
                100 + meta["visit_count"] * 10,
                meta["last"],
                f"place{place_id:08d}",
                0,
                _url_hash(meta["url"]),
            ),
        )

    conn.executemany(
        "INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, "
        "visit_type, session) VALUES (?,?,?,?,?,?)",
        visit_rows,
    )

    # ---- bookmarks --------------------------------------------------------
    folder_epoch = datetime_to_prtime(_dt.datetime(*FOLDER_EPOCH, tzinfo=tz))
    for position, row in enumerate(BOOKMARK_ROWS):
        fk = place_ids.get(row["url"]) if row["url"] else None
        modified = (
            _stamp(tz, *row["modified"]) if row["modified"] else folder_epoch
        )
        added = _stamp(tz, *row["added"]) if row["added"] else folder_epoch
        conn.execute(
            "INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, "
            "dateAdded, lastModified, guid) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                row["id"],
                row["type"],
                fk,
                row["parent"],
                position,
                row["title"] or None,
                added,
                modified,
                row["guid"],
            ),
        )
        if fk:
            conn.execute(
                "UPDATE moz_places SET foreign_count = foreign_count + 1 WHERE id = ?",
                (fk,),
            )

    # ---- download annotation (the PDF referenced in the report) -----------
    download_url = (
        "https://www.practical-devsecops.com/downloads/Common-API-Attack-Vectors.pdf"
    )
    download_place = place_ids[download_url]
    conn.execute(
        "INSERT INTO moz_anno_attributes (id, name) VALUES (1, 'downloads/destinationFileURI')"
    )
    conn.execute(
        "INSERT INTO moz_anno_attributes (id, name) VALUES (2, 'downloads/metaData')"
    )
    started = _stamp(tz, 15, 24, 2)
    ended = _stamp(tz, 15, 24, 9)
    conn.execute(
        "INSERT INTO moz_annos (id, place_id, anno_attribute_id, content, dateAdded, "
        "lastModified) VALUES (1, ?, 1, ?, ?, ?)",
        (
            download_place,
            "file:///home/users/mrao/Downloads/Common-API-Attack-Vectors.pdf",
            started,
            started,
        ),
    )
    conn.execute(
        "INSERT INTO moz_annos (id, place_id, anno_attribute_id, content, dateAdded, "
        "lastModified) VALUES (2, ?, 2, ?, ?, ?)",
        (
            download_place,
            json.dumps({"state": 1, "endTime": ended // 1000, "fileSize": 1843277}),
            started,
            ended,
        ),
    )

    # ---- address-bar autocomplete history ---------------------------------
    for url, typed_text in (
        ("https://neoquant.com/", "neoquant"),
        ("https://www.youtube.com/", "youtube"),
        ("https://requestinspector.com/", "request"),
    ):
        if url in place_ids:
            conn.execute(
                "INSERT INTO moz_inputhistory (place_id, input, use_count) VALUES (?,?,?)",
                (place_ids[url], typed_text, 1),
            )

    conn.execute("INSERT INTO moz_meta (key, value) VALUES ('origin_frecency_count', '53')")
    conn.commit()
    conn.close()

    return {"places": len(place_meta), "visits": len(visit_rows)}


def _build_cookies(path: Path, tz: _dt.tzinfo) -> int:
    conn = sqlite3.connect(path)
    conn.executescript(COOKIES_SCHEMA)
    expiry = int(
        _dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=tz).timestamp()
    )
    for index, (host, name, secure, http_only, same_site, accessed) in enumerate(
        COOKIE_ROWS, start=1
    ):
        stamp = _stamp(tz, *accessed)
        conn.execute(
            "INSERT INTO moz_cookies (id, name, value, host, path, expiry, "
            "lastAccessed, creationTime, isSecure, isHttpOnly, sameSite, rawSameSite) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                index,
                name,
                f"synthetic-value-{index:03d}",
                host,
                "/",
                expiry,
                stamp,
                stamp - 300_000_000,
                secure,
                http_only,
                same_site,
                same_site,
            ),
        )
    conn.commit()
    conn.close()
    return len(COOKIE_ROWS)


def _build_formhistory(path: Path, tz: _dt.tzinfo) -> int:
    conn = sqlite3.connect(path)
    conn.executescript(FORMHISTORY_SCHEMA)
    for index, (fieldname, value, times_used, used) in enumerate(FORM_ENTRIES, start=1):
        stamp = _stamp(tz, *used)
        conn.execute(
            "INSERT INTO moz_formhistory (id, fieldname, value, timesUsed, firstUsed, "
            "lastUsed, guid) VALUES (?,?,?,?,?,?,?)",
            (index, fieldname, value, times_used, stamp - 60_000_000, stamp,
             f"form{index:08d}"),
        )
    conn.commit()
    conn.close()
    return len(FORM_ENTRIES)


def build_case_029(
    output_dir: os.PathLike | str,
    profile_name: str = "69mytvds.default-esr",
    tz_spec: str = "+01:00",
    overwrite: bool = False,
) -> Path:
    """Create the synthetic Case 029 Firefox profile under ``output_dir``.

    Returns the path to the generated profile directory.
    """
    tz = parse_tz(tz_spec)
    profile = Path(output_dir) / profile_name

    if profile.exists():
        if not overwrite:
            raise FileExistsError(f"Profile already exists: {profile}")
        import shutil

        shutil.rmtree(profile)

    profile.mkdir(parents=True)

    _build_places(profile / "places.sqlite", tz)
    _build_cookies(profile / "cookies.sqlite", tz)
    _build_formhistory(profile / "formhistory.sqlite", tz)

    for relative, content in SUPPORT_FILES.items():
        target = profile / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    return profile


def dataset_expectations() -> Dict[str, object]:
    """Ground truth the smoke tests assert against (report Grids 4.2–4.5)."""
    events = _scenario()
    counts: Dict[int, int] = {}
    for *_rest, visit_type in events:
        counts[visit_type] = counts.get(visit_type, 0) + 1
    return {
        "total_visits": len(events),
        "visit_type_counts": {code: counts.get(code, 0) for code in range(1, 7)},
        "distinct_urls": len({row[3] for row in events}),
        "bookmark_rows": len(BOOKMARK_ROWS),
        "bookmark_entries": sum(1 for row in BOOKMARK_ROWS if row["type"] == 1),
        "form_entries": len(FORM_ENTRIES),
        "cookies": len(COOKIE_ROWS),
        "profile_files": len(SUPPORT_FILES) + 3,
        "grid_4_2_queries": [
            "NeoQuant sql error page exploit",
            "Test sql injection using browser only",
            "Find exposed database endpoints in API",
            "Financial api sql injection examples",
            "How to force debug mode using URL parameters",
            "Bypass client-side validation by modifying URL",
            "Common api parameters that leak database info",
            "Check API vulnerabilities using chrome DevTools network tab",
            "Common api vectors.pdf download",
            "Neoquant finance - internal API docs",
            "request inspector- test API requests",
            "chrome devtools network inspector guide",
        ],
        "grid_4_3_videos": {
            "https://www.youtube.com/watch?v=0Izu0J6iSoM": "15:36:46",
            "https://www.youtube.com/watch?v=QtwhEz-aON4": "15:35:37",
            "https://www.youtube.com/watch?v=8zSoyAmHHc4": "15:34:50",
            "https://www.youtube.com/watch?v=GD88Pp75Klw": "15:33:21",
        },
        "grid_4_4_bookmarks": {
            "Inspect network activity | Chrome DevTools | Chrome for developers": "15:31:22",
            "Competitive Analysis | Similarweb": "15:30:54",
            "Web Request Inspector & Probe Service | Request Inspector": "15:30:20",
            "SQL Injection | OWASP Foundation": "15:29:45",
            "white papers - NeoQuant": "15:29:11",
        },
    }
