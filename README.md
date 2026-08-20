# ffxforensics — Firefox Browser Artefact Forensics Toolkit

[![CI](https://github.com/your-username/firefox-insider-threat-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/firefox-insider-threat-forensics/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-185%20passing-brightgreen.svg)](#testing)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-none-informational.svg)](requirements.txt)

Acquisition, preservation and analysis of Mozilla Firefox browser artefacts,
aligned to the **ACPO Good Practice Guide for Digital Evidence**.

This repository turns a manual browser-forensics examination — the kind
documented in *Case File 029, "Insider Threat"* — into a reproducible pipeline
that any examiner can rerun and any reviewer can audit.

```
┌─────────┐   ┌─────────┐   ┌────────┐   ┌─────────┐   ┌────────┐
│ ACQUIRE │──▶│ PRESERVE│──▶│ VERIFY │──▶│ ANALYSE │──▶│ REPORT │
└─────────┘   └─────────┘   └────────┘   └─────────┘   └────────┘
 read-only     SHA-256        sha256sum    immutable    Markdown
 copy of the   manifest +     -c compatible SQLite      HTML
 live profile  archive        check         queries     CSV / JSON
        │            │             │             │           │
        └────────────┴─────────────┴─────────────┴───────────┘
                    every step written to the audit trail
```

---

## Why this exists

A manual browser examination is slow, and its weak points are always the same:
a hash step gets skipped under time pressure, `datetime(..., 'localtime')`
silently renders timestamps in the *examiner's* timezone rather than the
suspect's, a redirect gets recorded as a search the subject performed, and
findings drift from the evidence when the report is written by hand.

This toolkit removes those failure modes:

| Manual risk | How the toolkit removes it |
|---|---|
| Working on the original file | Databases open with `mode=ro&immutable=1` — SQLite cannot write, and no WAL or journal side-file is created |
| Missed hashing step | Acquisition hashes every file and writes a manifest in one auditable call |
| Timezone drift | Timestamps convert against an **explicit** `--tz`, never the host clock |
| Redirects counted as searches | `google.com/url?q=…` and `/aclk?…` are recognised as redirectors, not queries |
| Undocumented process | Every operation appends to an audit trail exported as CSV, JSON and Markdown |
| Findings drifting from evidence | Reports render directly from the parsed records; nothing is retyped |

---

## Quickstart

```bash
git clone https://github.com/your-username/firefox-insider-threat-forensics.git
cd firefox-insider-threat-forensics
pip install -e ".[dev]"

# Run the entire Case 029 examination end to end
./scripts/run_case029.sh
```

That script generates a synthetic evidence set, acquires it, verifies the
manifest, analyses it, renders the reports, and then **re-verifies** to prove
the analysis left the evidence byte-identical. Output lands in `demo/results/`.

### On a real profile

```bash
# 1. Forensic copy + hashes + archive (never touches the original)
ffxforensics acquire ~/.mozilla/firefox/xxxxxxxx.default-esr ./working_directory \
    --case-id 029 --examiner "A. Adhikari" --audit acquisition_audit.csv

# 2. Confirm the copy matches
ffxforensics verify working_directory/Firefox-Linux-Evidence-all.sha256 ./working_directory

# 3. Analyse and report
ffxforensics analyze working_directory/Firefox-Linux-Evidence \
    -o results --tz +01:00 \
    --manifest working_directory/Firefox-Linux-Evidence-all.sha256 \
    --subject "Subject name" --organisation "Employer"
```

`results/` then contains `examination_report.html`, `examination_report.md`,
`findings.json`, `audit_trail.csv` and ten CSV exports.

---

## What it recovers

| Artefact | Recovered |
|---|---|
| `places.sqlite` | URL history, individual navigation events, search-engine queries, video watches, bookmarks (with folder paths), downloads from `moz_annos`, visit-type distribution |
| `cookies.sqlite` | Cookies with `secure` / `httpOnly` / `sameSite` flags, per-host summary, third-party tracker flagging |
| `formhistory.sqlite` | Text physically typed into forms and the search bar, with repetition counts |

On top of the raw extraction:

- **Unified timeline** — all artefacts interleaved chronologically and grouped
  into sessions on an inactivity gap, so a report can say *"one continuous
  21-minute session"* rather than *"56 events"*.
- **Indicator triage** — a configurable keyword ruleset flags SQL injection
  research, API enumeration, control bypass, network recon, tooling, activity
  naming the employing organisation, exfiltration channels and anti-forensics.
- **Cross-artefact corroboration** — terms appearing in *both* `formhistory`
  and `places` are marked as confirmed keyboard entry, distinguishing them from
  terms that could have arrived via a redirect or an auto-suggestion.

---

## Verified against the source examination

The repository ships a **synthetic evidence set** that reconstructs the Case
029 scenario using genuine Firefox schemas. The test suite asserts the
toolkit's output against the report's published grids, value by value:

| Report grid | Content | Status |
|---|---|---|
| Grid 4.2 | 12 search queries + exact last-visited times | ✅ reproduced |
| Grid 4.3 | 4 video URLs, titles and watch times | ✅ reproduced |
| Grid 4.4 / Image 3 | 5 bookmarks + 6 folders (11 rows) with modification times | ✅ reproduced |
| Grid 4.5 | Visit-type distribution `29 / 19 / 0 / 0 / 3 / 5` (56 visits) | ✅ reproduced |
| Audit trail | The `Common-API-Attack-Vectors.pdf` download | ✅ reproduced |
| Section 2 | 50 files in the evidence directory | ✅ reproduced |

If a future change breaks agreement with the report, the smoke test fails and
names the grid that moved. See [`results/`](results/) for committed output and
[`docs/CASE_029_REFERENCE.md`](docs/CASE_029_REFERENCE.md) for the mapping —
including a **documented discrepancy** between the report's Grid 4.4 prose
table and the SQL output in Image 3.

> The synthetic dataset is entirely fabricated. The individual, the employer,
> the domains and the video identifiers correspond to no real person or system.
> It exists so the toolkit can be tested and demonstrated without distributing
> case material — it is **not evidence**.

---

## ACPO alignment

| Principle | Implementation |
|---|---|
| **1** — no action should change data held on a device | `shutil.copytree` for acquisition; every database opened `mode=ro&immutable=1`; `chmod 0400` on the working copy. Tested: `test_opening_does_not_modify_the_evidence`, `test_acquisition_leaves_the_source_untouched` |
| **2** — a competent person may access original data and must explain their actions | SHA-256 manifests before and after; `verify` exits non-zero on mismatch; every SQL query documented in [`docs/SQL_QUERY_REFERENCE.md`](docs/SQL_QUERY_REFERENCE.md) |
| **3** — an audit trail should let a third party reach the same result | `AuditTrail` records every operation with UTC timestamps, commands and artefact hashes; the manifest is `sha256sum -c` compatible, so a third party can verify **without this toolkit**. Tested: `test_manifest_is_readable_by_coreutils` |
| **4** — the case officer is responsible for adherence | Reports state the verdict as `INCONCLUSIVE` with alternative explanations and recommended corroboration; the tool never asserts intent |

Full discussion: [`docs/ACPO_COMPLIANCE.md`](docs/ACPO_COMPLIANCE.md).

---

## The conclusion this tool will not draw

Indicator scores measure **topic**, never **intent**. A penetration tester, a
student revising for a security exam, and a genuine insider all light up the
same rules.

The reporting layer therefore always emits:

- a verdict of `INCONCLUSIVE — intent cannot be established from browser artefacts alone`;
- at least three innocent explanations consistent with the same evidence;
- a list of corroborating enquiries (proxy logs, application logs, role and
  authorisation, endpoint artefacts, DLP) that *could* settle the question;
- an attribution caveat: an artefact proves something happened *in this
  profile*, not *who did it*.

This mirrors the source examination, which declined to infer intent from
browsing topics. `test_conclusion_remains_inconclusive` enforces it.

---

## Command reference

| Command | Purpose |
|---|---|
| `ffxforensics sample <dir>` | Generate the synthetic Case 029 evidence set |
| `ffxforensics acquire <profile> <workdir>` | Forensic copy + hash manifest + archive |
| `ffxforensics verify <manifest> <root>` | Verify integrity (`--strict` also flags added files) |
| `ffxforensics info <evidence>` | Artefact inventory, hashes and record counts |
| `ffxforensics analyze <evidence> -o <out>` | Full analysis, exports and reports |
| `ffxforensics timeline <evidence>` | Print the unified timeline (`--flagged-only`) |
| `ffxforensics search <evidence> <term>` | Keyword search across all artefacts |

Exit codes: `0` success · `1` runtime/evidence error · `2` integrity
verification failed · `130` interrupted. The distinct integrity code lets the
tool sit in a pipeline that must halt when evidence does not verify.

Useful options: `--tz` (fixed offset such as `+01:00`, or an IANA zone),
`--rules custom.json` (replace the indicator ruleset), `--session-gap`,
`--strict`, `--json`, `--quiet`.

---

## Project layout

```
src/ffxforensics/
├── acquire.py          forensic copy, deterministic archive, read-only lock
├── audit.py            ACPO Principle 3 audit trail (CSV / JSON / Markdown)
├── case.py             orchestration — one run produces one CaseResult
├── cli.py              argparse command line interface
├── hashing.py          SHA-256, sha256sum-compatible manifests, verification
├── models.py           typed artefact records
├── sampledata.py       synthetic Case 029 evidence generator
├── timeutil.py         PRTime conversion with explicit timezones
├── parsers/            places · cookies · formhistory (read-only SQLite)
├── analysis/           indicator engine · timeline builder
└── report/             Markdown · self-contained HTML · CSV/JSON exporters

tests/                  185 tests (unit, integration, end-to-end smoke)
docs/                   methodology, ACPO mapping, SQL reference, chain of custody
results/                committed output from a real run of the pipeline
scripts/run_case029.sh  one-command reproduction
```

---

## Testing

```bash
make test        # or: python -m pytest
make cov         # coverage report
make lint        # ruff
```

185 tests across seven modules; the suite runs in under a second and needs no
network, no fixtures on disk and no third-party services.

```
tests/test_hashing.py            integrity primitives, tampering detection,
                                 coreutils interoperability
tests/test_timeutil.py           PRTime conversion, timezone handling, corrupt values
tests/test_places_parser.py      history, searches, bookmarks, downloads, visit types
tests/test_cookies_and_forms.py  cookie flags, legacy schemas, typed-value recovery
tests/test_analysis.py           indicator rules, timeline construction, audit trail
tests/test_acquire_and_case.py   acquisition, orchestration, report rendering, XSS escaping
tests/test_cli.py                every subcommand, flags and exit codes
tests/test_smoke_case029.py      end-to-end run asserted against the report's grids
```

Notable properties under test: acquisition leaves the source byte-identical;
analysis leaves the evidence byte-identical; archives are deterministic across
runs; manifests verify with GNU `sha256sum -c`; a crafted page title cannot
inject markup into the HTML report; a tampered file changes the exit code.

Three real bugs were found and fixed by these tests during development —
a falsy empty `AuditTrail` silently discarding a caller's trail, non-deterministic
`url_hash` breaking reproducibility, and Google redirector URLs being recorded
as searches. See [`docs/TESTING.md`](docs/TESTING.md).

---

## Limitations

- **Firefox only.** Chromium-family browsers use a different schema; the parser
  interface is designed for it, but no Chromium parser ships today.
- **No deleted-record recovery.** Rows removed from SQLite may persist in freed
  pages; carving those is not implemented. Findings describe what the databases
  *currently* contain.
- **No live acquisition of a running browser.** Acquire from a powered-down or
  logged-out system, or the copy may catch a database mid-write.
- **Timestamps are profile-local facts.** They reflect the system clock at the
  time; clock skew or deliberate change must be checked separately.
- **Attribution is out of scope.** A browser artefact places activity in a
  profile, not at a person.

---

## Responsible use

Use this only on systems you are authorised to examine. Browser artefacts are
among the most intimate records a person leaves — health, finances,
relationships, beliefs. An examination that ranges beyond its authorised scope
is both an ethical failure and, in most jurisdictions, a legal one.

Practical guidance: agree the scope in writing before acquisition; record the
authority under which you act in the case metadata; extract only what the scope
covers; and treat every finding as provisional until corroborated.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). In short: keep the runtime
dependency-free, add a test with every change, never commit case material, and
never weaken the interpretation caveats.

## License

MIT — see [`LICENSE`](LICENSE).

## Acknowledgements

Methodology and scenario structure follow the *Case File 029* browser-forensics
examination by **Arjun Adhikari** (Student ID 25928892). Standards reference:
Association of Chief Police Officers (2012) *ACPO Good Practice Guide for
Digital Evidence*, 5th edn.
