# Chain of custody

A record that accounts for the evidence continuously from seizure to
disposal. Any unexplained gap is an opening for challenge, and the challenge
does not have to prove tampering — only that tampering could not be ruled out.

Copy the template below into the case file at the point of seizure and complete
it as the examination proceeds.

---

## Template

### 1. Case details

| Field | Value |
|---|---|
| Case / file number | |
| Investigating officer | |
| Examiner | |
| Authority to examine (reference) | |
| Agreed scope | |
| Date opened | |

### 2. Item seized

| Field | Value |
|---|---|
| Exhibit reference | |
| Description | |
| Make / model | |
| Serial number | |
| Operating system | |
| Browser and version | |
| **System timezone** | |
| State when seized (on / off / locked / network connected) | |
| Seized by | |
| Date and time of seizure | |
| Location of seizure | |
| Witness | |

> Record the system timezone at seizure. Every timestamp in the examination
> depends on it, and it may be impossible to establish later.

### 3. Acquisition

| Field | Value |
|---|---|
| Acquired by | |
| Date and time | |
| Method | `ffxforensics acquire` (`shutil.copytree`, metadata preserved) |
| Tool version | `ffxforensics --version` |
| Source path | |
| Working copy path | |
| Files acquired | |
| Manifest file | |
| Archive file | |
| Archive SHA-256 | |
| Write-protection applied | ☐ `chmod 0400` ☐ write blocker ☐ other: |
| Audit trail file | |

### 4. Integrity verification log

| Date / time | Verified by | Purpose | Files checked | Result | Notes |
|---|---|---|---|---|---|
| | | Post-acquisition baseline | | ☐ PASS ☐ FAIL | |
| | | Pre-analysis | | ☐ PASS ☐ FAIL | |
| | | Post-analysis | | ☐ PASS ☐ FAIL | |
| | | | | ☐ PASS ☐ FAIL | |

> Verify at minimum immediately after acquisition and immediately after
> analysis. The pair is what supports the claim that the findings describe the
> evidence as seized. Attach the `verify --json` output.

### 5. Custody transfers

| Date / time | Released by | Received by | Reason | Method | Signature |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |

Every movement of the evidence — including between examiners in the same team,
and into and out of storage — is a transfer.

### 6. Analysis performed

| Date / time | Examiner | Tool and version | Operation | Output location |
|---|---|---|---|---|
| | | | | |

The `ffxforensics` audit trail (`audit_trail.csv`) populates this section
automatically; attach it rather than re-transcribing.

### 7. Storage

| Field | Value |
|---|---|
| Storage location | |
| Access control | |
| Retention period | |
| Review date | |

### 8. Disposal

| Field | Value |
|---|---|
| Authorised by | |
| Date | |
| Method | |
| Witness | |

---

## Notes on completing this record

**Record contemporaneously.** A form completed from memory a week later is
worth considerably less than one completed as the work happened, and the
difference will be apparent under questioning.

**Record failures too.** A verification that failed, a copy that had to be
repeated, a file that could not be read — an honest record of a problem and its
resolution is stronger than a suspiciously clean one.

**Do not overwrite entries.** If something was recorded incorrectly, add a
dated correction rather than amending the original.

**Attach, don't summarise.** The audit trail, the manifest and the `verify`
output are the primary records. Attach them; do not retype them into this form.
