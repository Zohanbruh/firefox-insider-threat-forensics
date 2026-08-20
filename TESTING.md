# Testing

185 tests, under a second, no network and no fixtures on disk. The synthetic
evidence set is generated in a temporary directory at session scope and reused
across the suite.

```bash
make test                  # everything
make cov                   # coverage report
python -m pytest tests/test_smoke_case029.py -v   # the end-to-end run
python -m pytest -k bookmark                      # by keyword
```

## Structure

| Layer | Modules | What it establishes |
|---|---|---|
| Unit | `test_hashing.py`, `test_timeutil.py` | The primitives everything else trusts — hashing, manifest format, PRTime conversion |
| Parser | `test_places_parser.py`, `test_cookies_and_forms.py` | Each artefact yields the right records, and reading never modifies it |
| Analysis | `test_analysis.py` | Indicator rules, timeline construction, session grouping, audit trail immutability |
| Integration | `test_acquire_and_case.py` | Acquisition, orchestration and report rendering working together |
| Interface | `test_cli.py` | Every subcommand, flag and exit code |
| End-to-end | `test_smoke_case029.py` | The whole pipeline, asserted against the source report's grids |

## The invariants that matter

Forensic code has a small set of properties that must never regress. Each has a
test whose failure means the tool cannot be trusted with evidence:

**Evidence immutability.** `test_opening_does_not_modify_the_evidence` hashes
an artefact, opens and fully parses it, hashes again, and asserts equality —
then asserts no `-wal` or `-journal` file appeared alongside it. The side-file
check is the important half: a plain `mode=ro` connection can still create one,
which changes the directory and invalidates a manifest even though the database
itself is untouched.

`test_analysis_did_not_alter_the_evidence` does the same at the whole-evidence
level, re-verifying all fifty files after a complete analysis run.

**Third-party verifiability.** `test_manifest_is_readable_by_coreutils` shells
out to GNU `sha256sum -c` and asserts it accepts the manifest. If this fails,
ACPO Principle 3 is not satisfied — a reviewer would need this toolkit to check
our work, which defeats the point.

**Determinism.** `test_archive_is_deterministic` builds the same tree twice and
compares hashes. `test_generation_is_deterministic` does the same for the
sample dataset. A hash that varies between runs proves nothing.

**Tamper detection.** `test_verify_returns_a_distinct_exit_code_on_tampering`
modifies a file after acquisition and asserts exit code `2`, separate from the
`1` used for ordinary errors, so a pipeline can halt on integrity failure
specifically. Sibling tests cover deletion and — in `--strict` mode — planted
files.

**Report safety.** `test_html_escapes_evidence_values` puts
`<script>alert('xss')</script>` in a page title and asserts it renders escaped.
Evidence is untrusted input; a hostile page title must not be able to inject
markup into a report that will be opened in a browser.

**Interpretation limits.** `test_conclusion_remains_inconclusive` and
`test_assessment_never_asserts_intent` fail if the reporting language is ever
weakened to assert intent, drop the innocent explanations, or remove the
recommended corroboration.

## Grid assertions

`test_smoke_case029.py` is the regression test that matters most. It runs the
full pipeline once at module scope, then asserts the output against the source
report grid by grid — Grid 4.2's twelve queries are parametrised individually,
so a failure names the exact query and timestamp that moved rather than
reporting a dict mismatch.

If a parser change breaks agreement with the report, this suite says which grid
broke.

## Negative and boundary cases

Roughly a third of the suite covers things going wrong, because that is where
forensic tools fail quietly:

- Corrupt, null, negative and absurdly large PRTime values
- A profile missing artefacts entirely (reported, not raised)
- A non-SQLite file passed as evidence
- A legacy schema with no `sameSite` column
- Cookie `expiry` in seconds while sibling columns are microseconds
- Word-boundary false positives (`scan` in `scandinavia`, `nmap` in `nmapping`)
- An empty evidence directory
- An invalid timezone
- Acquisition refusing to overwrite an existing working directory
- Symlinks in the source tree (not followed)

## Adding tests

Name the behaviour, not the function: `test_expiry_is_parsed_as_seconds_not_microseconds`
tells a future reader what broke; `test_cookies_2` does not.

For a bug fix, write the failing test first and keep it named after the defect.
The three defects found during development each left a test behind — see
`results/TEST_RESULTS.md`.
