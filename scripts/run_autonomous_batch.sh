#!/usr/bin/env bash
# Batch runner for autonomous workflow with lightweight log triage.
# Usage: scripts/run_autonomous_batch.sh [iterations] [target]

set -euo pipefail

ITERATIONS="${1:-5}"
TARGET="${2:-${TARGET:-http://192.168.1.130:3000}}"
CMD=(python -m cli.main workflow run --name autonomous --target "${TARGET}")

mkdir -p reports

latest_log() {
  ls -1t reports/console_*.log 2>/dev/null | head -n1
}

echo "Running ${ITERATIONS} iteration(s) against target: ${TARGET}"

for i in $(seq 1 "${ITERATIONS}"); do
  echo "---- Iteration ${i}/${ITERATIONS} ----"
  before="$(latest_log || true)"

  "${CMD[@]}" || true

  sleep 1
  after="$(latest_log || true)"
  if [[ -z "${after}" || "${after}" == "${before}" ]]; then
    echo "WARN: could not locate a new console log after iteration ${i}"
    continue
  fi

  echo "Log: ${after}"
  unknown_count=$(grep -c "Skipping AI decision because action is unknown" "${after}" || true)
  error_count=$(grep -c " - ERROR -" "${after}" || true)
  nuclei_flags=$(grep -c "flag provided but not defined" "${after}" || true)
  no_output=$(grep -c "No actionable output" "${after}" || true)

  echo "  Unknown/ignored actions: ${unknown_count}"
  echo "  Errors: ${error_count}"
  echo "  Nuclei flag errors: ${nuclei_flags}"
  echo "  No-output analyses: ${no_output}"
done

echo "Batch complete."
