# Contributing

Thanks for considering a contribution. This is forensic tooling, so a few of
the rules below are stricter than a typical Python project — output from this
code may end up in a disciplinary hearing or a courtroom.

## Ground rules

1. **Never commit case material.** No real profiles, no real hashes from a live
   case, no screenshots containing personal data. `.gitignore` blocks the usual
   paths, but the responsibility is yours. If you need test data, extend
   `src/ffxforensics/sampledata.py`.
2. **Keep the runtime dependency-free.** Forensic workstations are often
   air-gapped and locked down, and every third-party package is another thing
   an opposing expert can question. Development tools (pytest, ruff) are fine.
3. **Never weaken the interpretation caveats.** Pull requests that make the
   tool assert intent, drop the innocent explanations, or remove the
   attribution caveat will be declined. Those caveats are the difference
   between a forensic tool and an accusation generator.
4. **Every change needs a test.** Bug fixes need a test that fails before the
   fix. Parser changes need a test that pins the behaviour to a known record.
5. **Never break agreement with the source examination.**
   `tests/test_smoke_case029.py` asserts the toolkit's output against the
   report's published grids. If a change makes it fail, the change is wrong —
   unless you can show the grid itself was wrong, in which case document it in
   `docs/CASE_029_REFERENCE.md` the way the Grid 4.4 discrepancy is documented.

## Development setup

```bash
git clone https://github.com/your-username/firefox-insider-threat-forensics.git
cd firefox-insider-threat-forensics
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

make test    # 185 tests, under a second
make lint    # ruff
make cov     # coverage report
make demo    # full pipeline against synthetic evidence
```

## Evidence-handling invariants

These are the properties that must hold after any change. Each has a test:

| Invariant | Test |
|---|---|
| Acquisition leaves the source byte-identical | `test_acquisition_leaves_the_source_untouched` |
| Opening an artefact leaves it byte-identical and creates no WAL/journal | `test_opening_does_not_modify_the_evidence` |
| A full analysis run leaves the evidence byte-identical | `test_analysis_did_not_alter_the_evidence` |
| Manifests verify with GNU `sha256sum -c` | `test_manifest_is_readable_by_coreutils` |
| Archives are byte-identical across runs | `test_archive_is_deterministic` |
| A tampered file changes the exit code | `test_verify_returns_a_distinct_exit_code_on_tampering` |
| Evidence values cannot inject markup into the HTML report | `test_html_escapes_evidence_values` |
| The verdict stays inconclusive | `test_conclusion_remains_inconclusive` |

If you find yourself editing one of these tests to make a change pass, stop and
reconsider the change.

## Adding a parser

New artefacts (Chromium `History`, Firefox `favicons.sqlite`, `sessionstore`)
are welcome. Subclass `SQLiteArtefact` in `src/ffxforensics/parsers/base.py`;
it handles the immutable read-only connection, schema validation, integrity
check and provenance summary. Then:

1. Declare `REQUIRED_TABLES` so a wrong file fails loudly instead of returning
   empty results.
2. Handle schema variation across browser versions by inspecting
   `PRAGMA table_info` rather than assuming a column exists — see how
   `CookiesArtefact` handles profiles with no `sameSite` column.
3. Bind every value as a parameter. No f-strings in SQL.
4. Document each query in `docs/SQL_QUERY_REFERENCE.md`, including the
   evidential meaning of the columns and any pitfall you had to guard against.
5. Return typed records from `models.py`, not raw tuples.

## Adding indicator rules

Rules live in `DEFAULT_RULES` in `src/ffxforensics/analysis/indicators.py`.
Keep in mind:

- Keywords match on **word boundaries**. `scan` must not fire on
  `scandinavia`; there is a parametrised test for exactly this class of
  false positive.
- Weight and severity should reflect how *specific* the term is, not how
  alarming it sounds. `sqlmap` is specific; `security` is not.
- Every new category should be defensible to someone being investigated by it.
  If you cannot state the innocent explanation for a rule firing, the rule is
  not ready.

Users can override the whole ruleset with `--rules custom.json`, so
organisation-specific terms belong there rather than in the defaults.

## Style

- `ruff check src tests` must pass.
- Type hints on public functions.
- Docstrings explain *why*, not *what* — particularly the forensic reasoning.
- Python 3.9 compatibility (hence `typing.List` rather than `list[...]` in
  signatures).

## Reporting a security issue

Do not open a public issue for anything that could cause a tool to misreport
evidence. See `SECURITY.md`.
