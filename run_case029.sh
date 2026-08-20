#!/usr/bin/env bash
#
# Reproduce the Case 029 examination end to end.
#
#   ./scripts/run_case029.sh [output-directory]
#
# Stages: generate synthetic evidence -> forensic copy + hashes -> verify
# manifest -> analyse -> render reports -> verify again (proving the analysis
# left the evidence byte-identical).
#
set -euo pipefail

OUT="${1:-demo}"
TZ_SPEC="${TZ_SPEC:-+01:00}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT}/src:${PYTHONPATH:-}"
FFX="python3 -m ffxforensics.cli"

EVIDENCE_NAME="Firefox-Linux-Evidence"
SOURCE_DIR="${OUT}/source"
WORKING_DIR="${OUT}/working_directory"
RESULTS_DIR="${OUT}/results"
MANIFEST="${WORKING_DIR}/${EVIDENCE_NAME}-all.sha256"

rule() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

rm -rf "${OUT}"
mkdir -p "${OUT}"

rule "1/6  Generate synthetic Case 029 evidence"
${FFX} sample "${SOURCE_DIR}" --tz "${TZ_SPEC}"

rule "2/6  Acquire (forensic copy, hash manifest, archive)"
${FFX} acquire "${SOURCE_DIR}/69mytvds.default-esr" "${WORKING_DIR}" \
    --name "${EVIDENCE_NAME}" \
    --no-lock \
    --case-id 029 \
    --examiner "A. Adhikari" \
    --audit "${OUT}/acquisition_audit.csv"

rule "3/6  Verify the manifest before analysis"
${FFX} verify "${MANIFEST}" "${WORKING_DIR}"

rule "4/6  Analyse and render reports"
${FFX} analyze "${WORKING_DIR}/${EVIDENCE_NAME}" \
    -o "${RESULTS_DIR}" \
    --tz "${TZ_SPEC}" \
    --manifest "${MANIFEST}" \
    --case-id 029 \
    --examiner "A. Adhikari" \
    --subject "Manisha Rao" \
    --organisation "NeoQuant Finance Limited" \
    --exhibit "File No. 029" \
    --device "Dell OptiPlex 7090 MT" \
    --os "Ubuntu GNU/Linux 24.04.1 LTS (64-bit)" \
    --browser "Firefox ESR 128.13.0 (64-bit)" \
    --notes "Synthetic reconstruction of Case 029 for testing and demonstration."

rule "5/6  Flagged events on the timeline"
${FFX} timeline "${WORKING_DIR}/${EVIDENCE_NAME}" --tz "${TZ_SPEC}" --flagged-only --limit 15

rule "6/6  Re-verify: analysis must not have altered the evidence"
${FFX} verify "${MANIFEST}" "${WORKING_DIR}"

printf '\n\033[1mDone.\033[0m Reports and exports are in %s\n' "${RESULTS_DIR}"
