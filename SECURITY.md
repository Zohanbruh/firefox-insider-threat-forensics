# Security policy

## Scope

This project's threat model is unusual: the most serious "vulnerability" is not
remote code execution, it is **a tool that silently misreports evidence**.

Please report privately:

- Any input that causes a parser to return **wrong** records rather than an
  error (a missed row, a wrong timestamp, a misattributed search).
- Any path where analysis **modifies** evidence.
- Any way a crafted artefact value could inject content into a generated report
  (HTML/CSV injection) or alter a SQL query.
- Ordinary vulnerabilities: path traversal during acquisition or extraction,
  arbitrary code execution, resource exhaustion on hostile input.

## How to report

Open a private security advisory through GitHub, or contact the maintainers
directly. Please do not open a public issue first for anything in the first
three categories above — a live case may be relying on the current output.

Include the artefact schema version, the Python version, and a minimal
reproduction. Please do **not** attach real case material; construct a
synthetic sample with `ffxforensics sample` and modify it.

## What to expect

An acknowledgement within a few days, an assessment of whether prior findings
could have been affected, and — where a defect could have caused incorrect
results — a note in `CHANGELOG.md` stating which versions were affected, so
examiners can decide whether to re-run past examinations.
