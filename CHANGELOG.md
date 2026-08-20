# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this is forensic tooling, entries state explicitly whether a change
could have affected **previously produced findings**.

## [1.0.0] — 2026-08-18

First release. Implements the acquire → preserve → verify → analyse → report
pipeline described in the Case 029 examination.

### Added

- **Acquisition** (`acquire.py`) — forensic copy with metadata preservation,
  SHA-256 manifest, deterministic ZIP archive, `chmod 0400` lock, all recorded
  to the audit trail.
- **Integrity** (`hashing.py`) — SHA-256 hashing, coreutils-compatible
  manifests, verification reporting matched/mismatched/missing/unexpected files,
  with a `--strict` mode that flags additions.
- **Audit trail** (`audit.py`) — append-only ACPO Principle 3 record, exported
  as CSV, JSON and Markdown.
- **Parsers** — `places.sqlite` (history, visits, searches, video activity,
  bookmarks with folder paths, downloads from `moz_annos`, visit-type
  distribution), `cookies.sqlite` (flags, host summary, third-party hints),
  `formhistory.sqlite` (typed values with repetition counts). All open
  `mode=ro&immutable=1`.
- **Analysis** — configurable indicator engine across ten categories; unified
  cross-artefact timeline with session grouping; cross-artefact corroboration
  distinguishing typed terms from merely visited URLs.
- **Reporting** — Markdown, self-contained offline HTML (no CDN, no webfonts,
  no JavaScript), ten CSV exports and a versioned `findings.json`.
- **CLI** — `sample`, `acquire`, `verify`, `info`, `analyze`, `timeline`,
  `search`, with a distinct exit code (`2`) for integrity failure.
- **Synthetic evidence generator** (`sampledata.py`) reproducing the Case 029
  scenario against genuine Firefox schemas.
- 185 tests, including an end-to-end smoke test asserted against the source
  report's published grids.

### Fixed during development

These defects existed only in unreleased code, but are recorded because each
would have produced incorrect findings:

- **Redirectors counted as searches.** `google.com/url?q=…` and
  `google.com/aclk?…` carry a `q` parameter but are redirectors, not searches.
  Matching on host alone recorded every ad click as a query the subject had
  typed. Search extraction now requires a search path prefix and rejects `q`
  values that are themselves URLs.
- **Caller-supplied audit trails discarded.** `AuditTrail` defines `__len__`,
  so an empty trail is falsy and `trail or AuditTrail(...)` silently replaced
  the caller's object — losing every subsequent entry from the case record.
- **Non-deterministic sample generation.** Python's `hash()` is salted per
  process, so generated databases differed between runs and could not be used
  as a reproducibility fixture. Replaced with SHA-1-derived identifiers.
- **List values rendered as raw Python syntax** (`[]`) in report integrity
  tables.
- **Archive entries sorted by filesystem path** rather than in-archive name,
  producing an order that did not match what a reader sees.

### Known issues

- No deleted-record recovery from freed SQLite pages.
- Firefox only; no Chromium parser.
- No live acquisition of a running browser.

### Documented discrepancy in the source material

The source report's Grid 4.4 gives `15:29:11` for the *SQL Injection | OWASP
Foundation* bookmark, while Image 3 — the raw query output — shows `15:29:45`.
The query output is treated as authoritative. See
`docs/CASE_029_REFERENCE.md`.
