# Case 029 — source examination reference

This document maps the findings of the original *Case File 029* browser
forensics examination onto the automated toolkit, so a reviewer can see exactly
what is reproduced, what was corrected, and what is fabricated.

## Investigative context (from the source report)

| Field | Value |
|---|---|
| File number | 029 |
| Examiner | Arjun Adhikari (Student ID 25928892) |
| Examination window | 02/12/2025 – 03/12/2025 |
| Subject | Manisha Rao (employee) |
| Organisation | NeoQuant Finance Limited |
| Evidence type | Browser forensics |
| Browser | Firefox ESR 128.13.0 (64-bit) |
| Device | Dell OptiPlex 7090 MT |
| Operating system | Ubuntu GNU/Linux 24.04.1 LTS (64-bit) |
| Analysis tooling | DB Browser for SQLite 3.13.1, Autopsy 4.22.1 |
| Locale | GMT+1 |

Access to the subject's system was granted on 1 December 2025 at 14:05 (GMT+1)
after the company revoked the subject's access, with a chain of custody
maintained throughout.

## What the toolkit reproduces

The synthetic dataset in `src/ffxforensics/sampledata.py` is built so that
running the pipeline over it produces the report's grids exactly. Each is
asserted in `tests/test_smoke_case029.py`.

### Grid 4.2 — search queries

| Search query | Last visited |
|---|---|
| NeoQuant sql error page exploit | 2025-12-02 15:16:22 |
| Test sql injection using browser only | 2025-12-02 15:17:40 |
| Find exposed database endpoints in API | 2025-12-02 15:18:31 |
| Financial api sql injection examples | 2025-12-02 15:19:06 |
| How to force debug mode using URL parameters | 2025-12-02 15:19:41 |
| Bypass client-side validation by modifying URL | 2025-12-02 15:20:16 |
| Common api parameters that leak database info | 2025-12-02 15:21:00 |
| Check API vulnerabilities using chrome DevTools network tab | 2025-12-02 15:21:49 |
| Common api vectors.pdf download | 2025-12-02 15:23:11 |
| Neoquant finance - internal API docs | 2025-12-02 15:28:57 |
| Request inspector - test API requests | 2025-12-02 15:30:09 |
| Chrome devtools network inspector guide | 2025-12-02 15:31:14 |

The toolkit recovers **19** queries in total. Grid 4.2 tabulated the notable
twelve; Image 1 of the report shows others (`neo quant`, `sql injection cheat
sheet - owasp`, `URLScan - analyse web behaviour`, `youtube`) that the grid
omitted. The dataset includes all of them, and the smoke test asserts the
twelve are a subset of what is recovered.

### Grid 4.3 — video activity

| Link | Title | Most recent activity |
|---|---|---|
| youtube.com/watch?v=0Izu0J6iSoM | Firewall Penetration Testing: Steps, Methods, and Tools | 2025-12-02 15:36:46 |
| youtube.com/watch?v=QtwhEz-aON4 | AI Security Exposed: Why 95% of Companies Are Vulnerable | 2025-12-02 15:35:37 |
| youtube.com/watch?v=8zSoyAmHHc4 | Threats Vulnerabilities and Exploits | 2025-12-02 15:34:50 |
| youtube.com/watch?v=GD88Pp75Klw | Using a LAN scan to find INTERNAL vulnerabilities | 2025-12-02 15:33:21 |

### Grid 4.4 / Image 3 — bookmarks

| Bookmark | Last modified |
|---|---|
| Inspect network activity \| Chrome DevTools \| Chrome for developers | 2025-12-02 15:31:22 |
| Competitive Analysis \| Similarweb | 2025-12-02 15:30:54 |
| Web Request Inspector & Probe Service \| Request Inspector | 2025-12-02 15:30:20 |
| SQL Injection \| OWASP Foundation | 2025-12-02 15:29:45 |
| white papers - NeoQuant | 2025-12-02 15:29:11 |

Plus six structural folder rows (`root`, `menu`, `toolbar`, `tags`, `unfiled`,
`mobile`) for the 11 rows Image 3 reports.

> ### ⚠ Documented discrepancy
>
> The report's **Grid 4.4** prose table gives `2025-12-02 15:29:11` for the
> *SQL Injection | OWASP Foundation* bookmark. **Image 3** — the screenshot of
> the actual `moz_bookmarks` query output — shows `15:29:45` for that row and
> `15:29:11` for *white papers - NeoQuant*.
>
> This looks like a transcription error when the query output was copied into
> the prose table: the `15:29:11` value from the row below was carried up.
>
> **Resolution adopted here:** the query output (Image 3) is treated as
> authoritative, because it is the direct product of the tool rather than a
> hand-copied summary. The toolkit therefore reproduces `15:29:45`.
>
> This is precisely the class of error that generating reports directly from
> parsed records eliminates — nothing is retyped between the database and the
> table.

### Grid 4.5 — visit categories

| Category | Meaning | Count |
|---|---|---|
| 1 | Interacted with link | 29 |
| 2 | Inputted link or selected from suggestions | 19 |
| 3 | Accessed a bookmark | 0 |
| 4 | Referenced link (embed) | 0 |
| 5 | 301 reroute (permanent redirect) | 3 |
| 6 | 302 reroute (temporary redirect) | 5 |
| | **Total** | **56** |

### Other reproduced facts

- 50 files in the `Firefox-Linux-Evidence` directory (report section 4).
- A download of the API attack-vectors PDF, recoverable from `moz_annos`
  (report audit trail, 03/12/2025 16:50).
- A single continuous session of roughly 21 minutes.

## Improvements over the manual method

| Source method | Issue | Toolkit approach |
|---|---|---|
| `datetime(..., 'localtime')` in SQL | Renders in the *examiner's* machine timezone; a report regenerated elsewhere silently shifts | Conversion in Python against an explicit `--tz`; UTC by default |
| Implicit comma joins (`FROM moz_places, moz_historyvisits WHERE ...`) | Easy to produce a cartesian product if a join predicate is dropped | Explicit `JOIN ... ON` |
| Grids transcribed by hand | Introduced the Grid 4.4 discrepancy above | Reports render directly from parsed records |
| Hash steps run one at a time | A missed step is invisible until challenged | Acquisition hashes everything in one call and writes the manifest |
| Timestamps altered by `cp` into the working directory (noted in report §4) | Directory-level timestamps not preserved | Filesystem times are never used as evidence; all timestamps come from inside the databases, and `copytree(..., copystat)` preserves file metadata |

## What is fabricated

Everything in the synthetic dataset. The subject, the employer, the domains
(`neoquant.com` and similar), the video identifiers, the cookie values and the
file hashes are invented for testing. The hashes recorded in the source
report's audit trail are **not** reproduced — inventing matching hashes would
be dishonest, and the generated dataset carries its own, computed from its own
bytes.

The synthetic profile is a demonstration and regression fixture. It is not
evidence and must never be presented as such.
