#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

BASE_URL="http://localhost:3000"
DATASET_DIR="./benchmark-dataset"
OUTPUT_DIR="./output/benchmarks"
PROFILES="classical,pqc,hybrid"
HASHES="sha256,keccak256"
BUCKETS="10KB,100KB,1MB,10MB,50MB"
SCENARIOS="workflow,sign_only,verify_manifest,verify_stored,verify_uploaded,verify_full"
WARMUP_RUNS="5"
MEASURED_RUNS="30"
SEED="42"
INTER_RUN_DELAY_MS="1200"
OPERATIONS_ENDPOINT=""
CLEANUP_UPLOADS="true"

STORAGE_STATE_MODE="warm"
CAMPAIGN_REPEATS="1"
CAMPAIGN_LABEL="formal-$(date -u +%Y%m%dT%H%M%SZ)"
DATASET_SEED_BASE="pqc-hons-benchmark-dataset-v2"
DATASET_FILES_PER_BUCKET="32"
DATASET_FILE_TYPES="bin,txt,json,csv,md"
REGENERATE_WARM_DATASET="false"
PREWARM_WARM_DATASET="true"
KEEP_COLD_DATASETS="true"

MIN_SUCCESS_RATE="0.90"
MIN_CONDITION_SUCCESS_RATE="0.90"
MIN_SERVER_COVERAGE="1.00"
MAX_RELATIVE_IQR="0.50"
HYBRID_GOOD_THRESHOLD="1.25"
PQC_GOOD_THRESHOLD="1.25"
PQC_STAGED_THRESHOLD="1.60"
ANALYSIS_BOOTSTRAP_SAMPLES="2000"

API_KEY="${PQC_API_KEY:-}"

usage() {
  cat <<'EOF'
Usage: scripts/run_benchmark_campaign.sh [options]

Runs benchmark-cli and analyzes every generated JSON report. Supports repeated
cold and warm campaigns so the output is suitable for formal benchmarking.

Options:
  --api-key <key>                 API key (default: env PQC_API_KEY)
  --base-url <url>                API gateway URL (default: http://localhost:3000)
  --dataset-dir <dir>             Warm-state dataset path (default: ./benchmark-dataset)
  --output-dir <dir>              Benchmark output path (default: ./output/benchmarks)
  --profiles <csv>                Profiles CSV (default: classical,pqc,hybrid)
  --hashes <csv>                  Hashes CSV (default: sha256,keccak256)
  --buckets <csv>                 Buckets CSV (default: 10KB,100KB,1MB,10MB,50MB)
  --scenarios <csv>               Scenarios CSV
                                  (default: workflow,sign_only,verify_manifest,verify_stored,verify_uploaded,verify_full)
  --warmup-runs <n>               Warm-up runs per condition (default: 5)
  --measured-runs <n>             Measured runs per condition (default: 30)
  --seed <n>                      RNG seed passed to benchmark-cli (default: 42)
  --inter-run-delay-ms <n>        Delay between runs in ms (default: 1200)
  --operations-endpoint <url>     Operations endpoint URL (default: <base-url>/operations)
  --cleanup-uploads               Clear /data/uploads in api-gateway before each run (default: on)
  --no-cleanup-uploads            Skip cleanup of /data/uploads

  --storage-state-mode <mode>     warm | cold | both (default: warm)
  --campaign-repeats <n>          Independent repeats per state (default: 1)
  --campaign-label <label>        Label recorded in reports and manifest
  --dataset-seed-base <seed>      Base dataset seed label (default: pqc-hons-benchmark-dataset-v2)
  --dataset-files-per-bucket <n>  Dataset size per bucket (default: 32)
  --dataset-file-types <csv>      Dataset file types (default: bin,txt,json,csv,md)
  --regenerate-warm-dataset       Rebuild the warm-state dataset before running
  --no-prewarm-warm-dataset       Skip warm-state prewarm pass
  --discard-cold-datasets         Delete generated cold datasets after the campaign

  --min-success-rate <float>      Analysis quality gate threshold (default: 0.90)
  --min-condition-success-rate <float>
                                  Per-condition scenario success threshold (default: 0.90)
  --min-server-coverage <float>   Required per-condition server timing coverage (default: 1.00)
  --max-relative-iqr <float>      Relative-IQR stability threshold (default: 0.50)
  --hybrid-good-threshold <float> Base hybrid viable ratio threshold (default: 1.25)
  --pqc-good-threshold <float>    Base PQC viable ratio threshold (default: 1.25)
  --pqc-staged-threshold <float>  Base conditional ratio threshold (default: 1.60)
  --analysis-bootstrap-samples <n>
                                  Bootstrap samples for analysis ratio CIs (default: 2000)

  -h, --help                      Show this help

Examples:
  export PQC_API_KEY="<operator-or-admin-key>"
  scripts/run_benchmark_campaign.sh --storage-state-mode both --campaign-repeats 3
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --dataset-dir)
      DATASET_DIR="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --profiles)
      PROFILES="$2"
      shift 2
      ;;
    --hashes)
      HASHES="$2"
      shift 2
      ;;
    --buckets)
      BUCKETS="$2"
      shift 2
      ;;
    --scenarios)
      SCENARIOS="$2"
      shift 2
      ;;
    --warmup-runs)
      WARMUP_RUNS="$2"
      shift 2
      ;;
    --measured-runs)
      MEASURED_RUNS="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --inter-run-delay-ms)
      INTER_RUN_DELAY_MS="$2"
      shift 2
      ;;
    --operations-endpoint)
      OPERATIONS_ENDPOINT="$2"
      shift 2
      ;;
    --cleanup-uploads)
      CLEANUP_UPLOADS="true"
      shift 1
      ;;
    --no-cleanup-uploads)
      CLEANUP_UPLOADS="false"
      shift 1
      ;;
    --storage-state-mode)
      STORAGE_STATE_MODE="$2"
      shift 2
      ;;
    --campaign-repeats)
      CAMPAIGN_REPEATS="$2"
      shift 2
      ;;
    --campaign-label)
      CAMPAIGN_LABEL="$2"
      shift 2
      ;;
    --dataset-seed-base)
      DATASET_SEED_BASE="$2"
      shift 2
      ;;
    --dataset-files-per-bucket)
      DATASET_FILES_PER_BUCKET="$2"
      shift 2
      ;;
    --dataset-file-types)
      DATASET_FILE_TYPES="$2"
      shift 2
      ;;
    --regenerate-warm-dataset)
      REGENERATE_WARM_DATASET="true"
      shift 1
      ;;
    --no-prewarm-warm-dataset)
      PREWARM_WARM_DATASET="false"
      shift 1
      ;;
    --discard-cold-datasets)
      KEEP_COLD_DATASETS="false"
      shift 1
      ;;
    --min-success-rate)
      MIN_SUCCESS_RATE="$2"
      shift 2
      ;;
    --min-condition-success-rate)
      MIN_CONDITION_SUCCESS_RATE="$2"
      shift 2
      ;;
    --min-server-coverage)
      MIN_SERVER_COVERAGE="$2"
      shift 2
      ;;
    --max-relative-iqr)
      MAX_RELATIVE_IQR="$2"
      shift 2
      ;;
    --hybrid-good-threshold)
      HYBRID_GOOD_THRESHOLD="$2"
      shift 2
      ;;
    --pqc-good-threshold)
      PQC_GOOD_THRESHOLD="$2"
      shift 2
      ;;
    --pqc-staged-threshold)
      PQC_STAGED_THRESHOLD="$2"
      shift 2
      ;;
    --analysis-bootstrap-samples)
      ANALYSIS_BOOTSTRAP_SAMPLES="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${API_KEY}" ]]; then
  echo "Error: API key missing. Set PQC_API_KEY or pass --api-key." >&2
  exit 2
fi

if [[ -z "${OPERATIONS_ENDPOINT}" ]]; then
  OPERATIONS_ENDPOINT="${BASE_URL%/}/operations"
fi

case "${STORAGE_STATE_MODE}" in
  warm)
    STORAGE_STATES=("warm")
    ;;
  cold)
    STORAGE_STATES=("cold")
    ;;
  both)
    STORAGE_STATES=("cold" "warm")
    ;;
  *)
    echo "Unsupported --storage-state-mode: ${STORAGE_STATE_MODE}" >&2
    exit 2
    ;;
esac

mkdir -p "${OUTPUT_DIR}" "${OUTPUT_DIR}/analysis" "${OUTPUT_DIR}/datasets"
MANIFEST_PATH="${OUTPUT_DIR}/campaign-manifest-${CAMPAIGN_LABEL}.tsv"
printf "state\trepeat_index\tdataset_seed\tdataset_dir\treport_json\tanalysis_dir\n" > "${MANIFEST_PATH}"

cleanup_upload_cache() {
  if [[ "${CLEANUP_UPLOADS}" != "true" ]]; then
    return
  fi
  echo "Cleaning upload cache in api-gateway..."
  if docker compose ps --services --filter status=running | grep -qx "api-gateway"; then
    docker compose exec -T api-gateway sh -lc 'rm -rf /data/uploads/* && mkdir -p /data/uploads'
  else
    echo "api-gateway is not running; skipping upload cleanup."
  fi
}

generate_dataset() {
  local target_dir="$1"
  local dataset_seed="$2"
  echo "Generating dataset at ${target_dir} with seed ${dataset_seed}..."
  python3 scripts/generate_benchmark_dataset.py \
    --output-dir "${target_dir}" \
    --files-per-bucket "${DATASET_FILES_PER_BUCKET}" \
    --seed "${dataset_seed}" \
    --file-types "${DATASET_FILE_TYPES}"
}

ensure_warm_dataset() {
  local warm_seed="${DATASET_SEED_BASE}:warm"
  if [[ ! -d "${DATASET_DIR}" || "${REGENERATE_WARM_DATASET}" == "true" ]]; then
    generate_dataset "${DATASET_DIR}" "${warm_seed}"
  fi
}

prewarm_warm_dataset() {
  local dataset_seed="$1"
  local repeat_index="$2"
  if [[ "${PREWARM_WARM_DATASET}" != "true" ]]; then
    return
  fi
  cleanup_upload_cache
  echo "Prewarming warm-state object cache using ${DATASET_DIR}..."
  ./target/release/benchmark-cli \
    --api-key "${API_KEY}" \
    --base-url "${BASE_URL}" \
    --dataset-dir "${DATASET_DIR}" \
    --output-dir "${OUTPUT_DIR}/prewarm" \
    --profiles "classical" \
    --hashes "${HASHES}" \
    --buckets "${BUCKETS}" \
    --scenarios "sign_only" \
    --warmup-runs 0 \
    --measured-runs "${DATASET_FILES_PER_BUCKET}" \
    --seed "$((SEED + repeat_index + 100000))" \
    --inter-run-delay-ms 0 \
    --operations-endpoint "${OPERATIONS_ENDPOINT}" \
    --storage-state-label "prewarm" \
    --campaign-label "${CAMPAIGN_LABEL}-prewarm-${dataset_seed}" \
    --repeat-index "${repeat_index}" >/dev/null
}

resolve_new_report() {
  local before_reports="$1"
  local after_reports="$2"
  local new_report
  new_report="$(comm -13 "${before_reports}" "${after_reports}" | tail -n 1 || true)"
  if [[ -z "${new_report}" ]]; then
    new_report="$(tail -n 1 "${after_reports}" || true)"
  fi
  printf "%s" "${new_report}"
}

run_analysis() {
  local report_json="$1"
  python3 scripts/analyze_benchmark_report.py \
    "${report_json}" \
    --min-success-rate "${MIN_SUCCESS_RATE}" \
    --min-condition-success-rate "${MIN_CONDITION_SUCCESS_RATE}" \
    --min-server-coverage "${MIN_SERVER_COVERAGE}" \
    --max-relative-iqr "${MAX_RELATIVE_IQR}" \
    --hybrid-good-threshold "${HYBRID_GOOD_THRESHOLD}" \
    --pqc-good-threshold "${PQC_GOOD_THRESHOLD}" \
    --pqc-staged-threshold "${PQC_STAGED_THRESHOLD}" \
    --bootstrap-samples "${ANALYSIS_BOOTSTRAP_SAMPLES}"
}

echo "[1/5] Building benchmark CLI..."
cargo build --release --bin benchmark-cli >/dev/null

echo "[2/5] Preparing datasets..."
ensure_warm_dataset

echo "[3/5] Running campaign matrix..."
for state in "${STORAGE_STATES[@]}"; do
  for ((repeat_index = 1; repeat_index <= CAMPAIGN_REPEATS; repeat_index++)); do
    dataset_seed="${DATASET_SEED_BASE}:${state}:repeat-${repeat_index}"
    dataset_dir="${DATASET_DIR}"

    if [[ "${state}" == "cold" ]]; then
      dataset_dir="${OUTPUT_DIR}/datasets/${CAMPAIGN_LABEL}-${state}-r${repeat_index}"
      generate_dataset "${dataset_dir}" "${dataset_seed}"
    else
      dataset_seed="${DATASET_SEED_BASE}:warm"
      prewarm_warm_dataset "${dataset_seed}" "${repeat_index}"
    fi

    cleanup_upload_cache

    echo "Running benchmark: state=${state} repeat=${repeat_index} dataset=${dataset_dir}"
    before_reports="$(mktemp)"
    after_reports="$(mktemp)"
    find "${OUTPUT_DIR}" -maxdepth 1 -type f -name 'benchmark-report-*.json' -print | sort > "${before_reports}"

    ./target/release/benchmark-cli \
      --api-key "${API_KEY}" \
      --base-url "${BASE_URL}" \
      --dataset-dir "${dataset_dir}" \
      --output-dir "${OUTPUT_DIR}" \
      --profiles "${PROFILES}" \
      --hashes "${HASHES}" \
      --buckets "${BUCKETS}" \
      --scenarios "${SCENARIOS}" \
      --warmup-runs "${WARMUP_RUNS}" \
      --measured-runs "${MEASURED_RUNS}" \
      --seed "$((SEED + repeat_index))" \
      --inter-run-delay-ms "${INTER_RUN_DELAY_MS}" \
      --operations-endpoint "${OPERATIONS_ENDPOINT}" \
      --storage-state-label "${state}" \
      --campaign-label "${CAMPAIGN_LABEL}" \
      --repeat-index "${repeat_index}"

    find "${OUTPUT_DIR}" -maxdepth 1 -type f -name 'benchmark-report-*.json' -print | sort > "${after_reports}"
    new_report="$(resolve_new_report "${before_reports}" "${after_reports}")"
    rm -f "${before_reports}" "${after_reports}"

    if [[ -z "${new_report}" ]]; then
      echo "Error: benchmark completed but no new benchmark-report-*.json found in ${OUTPUT_DIR}" >&2
      exit 3
    fi

    echo "Analyzing ${new_report}..."
    run_analysis "${new_report}"
    report_stem="$(basename "${new_report}" .json)"
    analysis_dir="${OUTPUT_DIR}/analysis/${report_stem}"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
      "${state}" \
      "${repeat_index}" \
      "${dataset_seed}" \
      "${dataset_dir}" \
      "${new_report}" \
      "${analysis_dir}" >> "${MANIFEST_PATH}"

    if [[ "${state}" == "cold" && "${KEEP_COLD_DATASETS}" != "true" ]]; then
      rm -rf "${dataset_dir}"
    fi
  done
done

echo "[4/5] Campaign manifest..."
echo "- ${MANIFEST_PATH}"

echo "[5/5] Aggregating repeat-level campaign outputs..."
python3 scripts/analyze_campaign_manifest.py "${MANIFEST_PATH}"

echo "[6/6] Complete."
echo "- Output dir: ${OUTPUT_DIR}"
echo "- Manifest:   ${MANIFEST_PATH}"
