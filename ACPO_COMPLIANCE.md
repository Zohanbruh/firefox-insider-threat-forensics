# ACPO compliance

How each principle of the *ACPO Good Practice Guide for Digital Evidence*
(5th edn, 2012) is implemented, and how a reviewer can check it.

---

## Principle 1

> No action taken by law enforcement agencies, persons employed within those
> agencies or their agents should change data which may subsequently be relied
> upon in court.

**Implementation**

1. **Acquisition copies, never moves.** `acquire_profile()` uses
   `shutil.copytree(..., symlinks=True)` with metadata preservation. The source
   profile is only ever read.
2. **Databases open immutable.** Every parser connects with
   `file:<path>?mode=ro&immutable=1`. This matters more than `mode=ro` alone:
   a plain read-only connection can still cause SQLite to create `-wal` or
   `-journal` side-files and to touch the header when recovering a hot journal,
   which changes the acquisition hash. `immutable=1` tells SQLite the file
   cannot change and suppresses all filesystem activity.
3. **The working copy is locked.** After hashing, `chmod 0400` is applied to
   every file, so an accidental write during analysis fails loudly.

**How to check**

```bash
python -m pytest tests/test_places_parser.py::test_opening_does_not_modify_the_evidence
python -m pytest tests/test_acquire_and_case.py::test_acquisition_leaves_the_source_untouched
python -m pytest tests/test_smoke_case029.py::test_analysis_did_not_alter_the_evidence
```

The first compares the artefact's bytes before and after a full parse and
asserts no WAL or journal file appeared. The last re-verifies the whole
manifest after the complete analysis run.

---

## Principle 2

> In circumstances where a person finds it necessary to access original data,
> that person must be competent to do so and be able to give evidence
> explaining the relevance and the implications of their actions.

**Implementation**

1. **Integrity is provable at both ends.** SHA-256 manifests are written at
   acquisition and can be re-verified at any point. `verify` exits `2` on
   mismatch, distinct from the `1` used for ordinary errors.
2. **`--strict` catches additions.** A file *added* to the working copy after
   acquisition passes an ordinary check (it is not in the manifest, so nothing
   compares against it). `--strict` reports it as `unexpected`.
3. **Every query is documented.** `docs/SQL_QUERY_REFERENCE.md` gives the exact
   SQL used for each finding, with the column semantics, so an examiner can
   explain what a result means and an opposing expert can reproduce it.
4. **Nothing is interpolated into SQL.** All filters are bound parameters, so
   an evidence value can never alter query structure.

**How to check**

```bash
python -m pytest tests/test_hashing.py -v
```

Covers detection of modification, deletion and (in strict mode) planted files.

---

## Principle 3

> An audit trail or other record of all processes applied to digital evidence
> should be created and preserved. An independent third party should be able to
> examine those processes and achieve the same result.

**Implementation**

1. **Automatic recording.** Every acquisition step, artefact opened and query
   run appends an `AuditEntry` with a UTC timestamp, the phase, the command,
   an explanation, the artefact and its hash.
2. **Append-only.** `AuditTrail.entries` returns a copy; there is no public API
   to delete or edit an entry.
3. **Three export formats.** CSV for case management, JSON for tooling,
   Markdown for the report body.
4. **Third-party verification without this toolkit.** Manifests are written in
   coreutils format, so any reviewer can run `sha256sum -c` — no Python, no
   installation.

**How to check**

```bash
python -m pytest tests/test_hashing.py::test_manifest_is_readable_by_coreutils
python -m pytest tests/test_analysis.py::test_audit_history_cannot_be_rewritten_through_the_property
cd working_directory && sha256sum -c Firefox-Linux-Evidence-all.sha256
```

**Reproducibility.** Two independent runs over the same evidence produce the
same findings: hashing is deterministic and sorted, archives are built with
fixed timestamps and sorted entries, and timestamp rendering depends only on
the `--tz` argument, never on the host clock.

---

## Principle 4

> The person in charge of the investigation has overall responsibility for
> ensuring that the law and these principles are adhered to.

**Implementation**

The tool is explicit that it does not replace the examiner's judgement:

- Reports state the verdict as `INCONCLUSIVE — intent cannot be established
  from browser artefacts alone`.
- Every report lists innocent explanations alongside any observation that
  narrows the activity.
- Every report lists the corroborating enquiries that could actually settle the
  question — proxy logs, application logs, role and authorisation, endpoint
  artefacts, DLP.
- Every report carries the attribution caveat: an artefact proves activity in a
  *profile*, not by a *person*.
- Reports close by stating that disciplinary or legal action should follow
  organisational policy and further investigation, not the report alone.

`tests/test_smoke_case029.py::test_conclusion_remains_inconclusive` and
`tests/test_analysis.py::test_assessment_never_asserts_intent` fail if this
language is ever weakened.

---

## Evidence handling checklist

Before acquisition:

- [ ] Authority to examine confirmed and recorded in writing
- [ ] Scope agreed and documented
- [ ] Chain of custody form opened (`docs/CHAIN_OF_CUSTODY.md`)
- [ ] Device state (powered on/off, network) photographed or noted
- [ ] Examiner details recorded for `--examiner`

During:

- [ ] `acquire` run with `--audit` to capture the trail
- [ ] Manifest verified before analysis begins
- [ ] Timezone of the subject system determined and passed as `--tz`

After:

- [ ] Manifest re-verified after analysis
- [ ] Audit trail exported and attached to the case file
- [ ] Report reviewed against the underlying CSV exports
- [ ] Evidence copy and archive stored per organisational retention policy
