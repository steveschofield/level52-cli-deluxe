#!/usr/bin/env bash
set -euo pipefail

IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
TARGET="${1:-}"
OUT_DIR="${ZAP_OUT_DIR:-$(pwd)/reports/zap_test}"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not available in PATH" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "Using image: $IMAGE"

echo "Checking ZAP scripts inside container..."
docker run --rm --pull=missing "$IMAGE" bash -lc "ls -la /zap/zap-baseline.py /zap/zap-full-scan.py"

if [[ -z "$TARGET" ]]; then
  echo "No target provided; skipping scan."
  echo "Usage: $(basename "$0") <target-url>"
  exit 0
fi

TS=$(date +%Y%m%d_%H%M%S)
JSON_NAME="zap_baseline_${TS}.json"
HTML_NAME="zap_baseline_${TS}.html"
MD_NAME="zap_baseline_${TS}.md"

echo "Running baseline scan against: $TARGET"

docker run --rm --pull=missing \
  -v "$OUT_DIR:/zap/wrk" \
  "$IMAGE" \
  bash -lc "set -euo pipefail; \
  /zap/zap-baseline.py -t '$TARGET' \
  -J /zap/wrk/$JSON_NAME \
  -r /zap/wrk/$HTML_NAME \
  -w /zap/wrk/$MD_NAME \
  -m 1 || true; \
  cat /zap/wrk/$JSON_NAME 2>/dev/null || true"

echo "Reports saved to: $OUT_DIR"
