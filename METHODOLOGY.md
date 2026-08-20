# Methodology

The examination workflow this toolkit implements, and the reasoning behind each
stage. It follows the structure of the Case 029 examination, with the manual
steps replaced by auditable code.

---

## Stage 1 — Identification

Establish what exists before touching it.

```bash
ffxforensics info /path/to/profile
```

Reports each artefact present, its SHA-256, its schema validity, its SQLite
integrity check result and its record count. Nothing is written.

A Firefox profile directory typically holds fifty or more files. The three that
carry most evidential weight:

| File | Contains |
|---|---|
| `places.sqlite` | History, visits, bookmarks, downloads, search queries |
| `cookies.sqlite` | Cookies, with creation and last-access times |
| `formhistory.sqlite` | Text physically typed into forms and the search bar |

Others worth noting in a report even when not parsed: `prefs.js` (configuration,
including whether history was set to clear on exit), `sessionstore-backups/`
(open tabs at last shutdown), `logins.json` and `key4.db` (credential storage —
frequently outside the authorised scope of an examination), `permissions.sqlite`
(per-site permissions granted).

**Decision point.** If the browser is running, the databases may be mid-write.
Acquire from a powered-down or logged-out system where possible, and record the
state either way.

---

## Stage 2 — Acquisition and preservation

```bash
ffxforensics acquire /path/to/profile ./working_directory \
    --case-id 029 --examiner "A. Adhikari" --audit acquisition_audit.csv
```

Five operations, in order, each written to the audit trail:

1. **Enumerate** the source and record the file count.
2. **Copy** with `shutil.copytree(..., symlinks=True)`, preserving metadata.
   Symlinks are copied as links, not followed — following them can pull in
   files from outside the authorised scope.
3. **Hash** every file and write `<name>-all.sha256` in coreutils format.
4. **Archive** to a ZIP with fixed entry timestamps and sorted entries, then
   hash the archive itself. Determinism matters: two examiners archiving the
   same tree must get the same hash, or the hash proves nothing.
5. **Lock** the working copy to `0400`, so an accidental write fails loudly.

The original is only ever read. The manifest is the anchor for everything that
follows.

**Why hash before analysis and again after.** The first manifest proves the
copy matches the original. The second proves the analysis changed nothing. Only
the pair together supports the claim that the findings describe the evidence as
seized.

---

## Stage 3 — Verification

```bash
ffxforensics verify working_directory/Firefox-Linux-Evidence-all.sha256 ./working_directory
```

Exit code `2` on failure, distinct from `1` for ordinary errors, so a pipeline
can halt on integrity failure specifically.

Verification distinguishes four outcomes: **matched**, **mismatched** (content
changed), **missing** (file gone), and — with `--strict` — **unexpected** (a
file present that was not in the manifest). The last case is easy to overlook:
a planted file passes an ordinary check because nothing compares against it.

Because manifests are coreutils format, a third party can verify without this
toolkit at all:

```bash
cd working_directory && sha256sum -c Firefox-Linux-Evidence-all.sha256
```

That property is what makes ACPO Principle 3 real rather than aspirational.

---

## Stage 4 — Analysis

```bash
ffxforensics analyze working_directory/Firefox-Linux-Evidence \
    -o results --tz +01:00 --manifest working_directory/Firefox-Linux-Evidence-all.sha256
```

Every database opens as `file:<path>?mode=ro&immutable=1`. `immutable=1` is the
important half: a plain read-only connection can still cause SQLite to create
`-wal` or `-journal` side-files and touch the header while recovering a hot
journal, which changes the acquisition hash and invalidates the manifest.

### Determining the timezone

Firefox stores PRTime — microseconds since the Unix epoch, timezone-free. A
timestamp only becomes a fact about a person's day once a zone is applied.

Establish the subject system's zone from the system configuration
(`/etc/timezone`, `timedatectl`), corroborate against a known-time event if one
exists, and pass it explicitly with `--tz`. Never rely on the examiner's host
clock; see the warning in `SQL_QUERY_REFERENCE.md`.

Every generated report states the zone it was rendered in.

### Weighing what is recovered

Not all artefacts carry equal weight:

| Evidence | Establishes | Weakness |
|---|---|---|
| `moz_formhistory` row | Text was **typed** | Says nothing about why |
| Visit type 2 (typed/suggested) | URL was entered or chosen from suggestions | Includes autocomplete selections |
| Bookmark | Deliberate **retention** for later | Could be transient interest |
| Visit type 1 (link) | Deliberate click | Target chosen by the page |
| Visit types 5, 6 (redirects) | Server-driven navigation | **Not a user action** |
| Visit type 4 (embed) | Resource loaded by a page | Not a user action at all |
| Cookie `lastAccessed` | Domain genuinely loaded | Includes third-party trackers |

The toolkit cross-references form history against recovered searches, and
reports terms found in both as **confirmed keyboard entry**. That distinction —
between what the subject typed and what merely appeared in their history — is
usually the difference between a finding that survives challenge and one that
does not.

### Sessions

The timeline groups events on an inactivity gap (30 minutes by default,
`--session-gap`). This converts "56 events" into "one continuous 21-minute
session", which is the form a reader can reason about — and it exposes whether
activity was sustained and focused or scattered across a fortnight.

---

## Stage 5 — Reporting and interpretation

```
results/
├── examination_report.html    self-contained, printable
├── examination_report.md      for case management systems
├── findings.json              versioned, machine-readable
├── audit_trail.csv/.json      the ACPO Principle 3 record
├── summary.json               counts and integrity verdict
└── *.csv                      searches, history, visits, video_visits,
                               bookmarks, cookies, form_history, downloads,
                               visit_types, timeline
```

Reports render directly from parsed records. Nothing is retyped between the
database and the table — which is how the transcription error documented in
`CASE_029_REFERENCE.md` becomes structurally impossible.

### The limit of the method

Indicator scores measure **topic**, not **intent**. A penetration tester on an
authorised engagement, a student revising for a security module, and a genuine
insider threat produce indistinguishable browser artefacts.

So every report states:

- a verdict of `INCONCLUSIVE — intent cannot be established from browser
  artefacts alone`;
- innocent explanations consistent with the same evidence;
- the corroborating enquiries that could actually settle it — proxy and
  firewall logs (was anything actually accessed?), application and database
  logs (were the techniques attempted?), the subject's role and authorisation
  (was this their job?), endpoint artefacts, DLP alerts, and an interview;
- the attribution caveat: an artefact places activity in a **profile**, not at
  a **person**. Shared credentials, an unlocked workstation and remote access
  all break the link.

A report that omits these is not shorter. It is wrong.
