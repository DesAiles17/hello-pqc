#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Hybrid profiles: 2 classical × 2 PQC
# Classical: EdDSA, ECDSA
# PQC: ML-DSA, FN-DSA
HYBRID_PROFILES=(
  "eddsa_ml_dsa"
  "eddsa_fn_dsa"
  "ecdsa_ml_dsa"
  "ecdsa_fn_dsa"
)

PROFILES=$(IFS=, ; echo "${HYBRID_PROFILES[*]}")
HASHES="blake3,sha256"
BUCKETS="10KB,1MB,50MB"
SCENARIOS="workflow,sign_only,verify_manifest,verify_stored,verify_uploaded,verify_full"

# Parse args - pass through everything except --estimate-only
ESTIMATE_ONLY=""
ARGS=()
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--estimate-only" ]]; then
    ESTIMATE_ONLY="true"
  else
    ARGS+=("$1")
  fi
  shift
done

# Call campaign script with hybrid matrix
"${SCRIPT_DIR}/../run_benchmark_campaign.sh" \
  --output-dir "${REPO_ROOT}/hybrid_output" \
  --profiles "${PROFILES}" \
  --hashes "${HASHES}" \
  --buckets "${BUCKETS}" \
  --scenarios "${SCENARIOS}" \
  ${ESTIMATE_ONLY:+--estimate-only} \
  "${ARGS[@]}"
