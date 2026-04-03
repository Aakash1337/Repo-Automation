#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/artifacts/downloaded/api" "${TMP_DIR}/artifacts/downloaded/web"
cp "${ROOT_DIR}/testdata/discovery/sample-discovery.json" "${TMP_DIR}/discovery.json"
cp "${ROOT_DIR}/testdata/results/api-scan-summary.json" "${TMP_DIR}/artifacts/downloaded/api/scan-summary.json"
cp "${ROOT_DIR}/testdata/results/web-scan-summary.json" "${TMP_DIR}/artifacts/downloaded/web/scan-summary.json"

python3 "${ROOT_DIR}/scripts/select_docker_targets.py" \
  --discovery-file "${TMP_DIR}/discovery.json" \
  --policy-file "${ROOT_DIR}/testdata/policy/org-scan-policy.test.yaml" \
  --matrix-out "${TMP_DIR}/matrix.json" \
  --inventory-out "${TMP_DIR}/inventory.json"

python3 "${ROOT_DIR}/scripts/normalize_results.py" aggregate \
  --artifacts-dir "${TMP_DIR}/artifacts/downloaded" \
  --output-json "${TMP_DIR}/org-scan-summary.json" \
  --output-csv "${TMP_DIR}/org-scan-summary.csv" \
  --output-markdown "${TMP_DIR}/org-scan-summary.md"

echo "Smoke test completed successfully."
echo "Artifacts:"
echo "  ${TMP_DIR}/matrix.json"
echo "  ${TMP_DIR}/inventory.json"
echo "  ${TMP_DIR}/org-scan-summary.json"
echo "  ${TMP_DIR}/org-scan-summary.csv"
echo "  ${TMP_DIR}/org-scan-summary.md"
