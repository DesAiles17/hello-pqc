#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

BASE_URL="http://localhost:3000"
DATASET_DIR="./dataset"
OUTPUT_DIR="./output/benchmarks"
PROFILES="rsa_pss,eddsa,ecdsa,hmac_sha256,ml_dsa,slh_dsa,fn_dsa"
HASHES="sha256,blake3,keccak256"
BUCKETS="10KB,100KB,1MB,10MB,50MB"
SCENARIOS="workflow,sign_only,verify_manifest,verify_stored,verify_uploaded,verify_full"
WARMUP_RUNS="10"
MEASURED_RUNS="100"
SEED="42"
INTER_RUN_DELAY_MS="350"
OPERATIONS_ENDPOINT=""
CLEANUP_UPLOADS="true"

STORAGE_STATE_MODE="warm"
CAMPAIGN_REPEATS="1"
CAMPAIGN_LABEL="formal-$(date -u +%Y%m%dT%H%M%SZ)"
DATASET_SEED_BASE="pqc-hons-dataset-v2"
DATASET_FILES_PER_BUCKET="32"
DATASET_FILE_TYPES="bin,txt,json,csv,md"
DATASET_LAYOUT_VERSION="2"
REGENERATE_WARM_DATASET="false"
PREWARM_WARM_DATASET="true"
KEEP_COLD_DATASETS="true"

MIN_SUCCESS_RATE="0.90"
MIN_CONDITION_SUCCESS_RATE="0.90"
MIN_SERVER_COVERAGE="1.00"
MAX_RELATIVE_IQR="0.20"
MAX_SERVER_RELATIVE_IQR="0.20"
MIN_SAMPLES_FOR_CI="20"
ANALYSIS_BOOTSTRAP_SAMPLES="2000"
PLOT_FORMATS="png,svg"
SKIP_ANALYSIS_PLOTS="false"

RESUME="false"
FORCE_OVERWRITE="false"
ESTIMATE_ONLY="false"
SMOKE_MODE="false"
CAMPAIGN_SETUP_PATH=""

OVERRIDE_DATASET_DIR=""
OVERRIDE_OUTPUT_DIR=""
OVERRIDE_PROFILES=""
OVERRIDE_HASHES=""
OVERRIDE_BUCKETS=""
OVERRIDE_SCENARIOS=""
OVERRIDE_WARMUP_RUNS=""
OVERRIDE_MEASURED_RUNS=""
OVERRIDE_SEED=""
OVERRIDE_INTER_RUN_DELAY_MS=""
OVERRIDE_STORAGE_STATE_MODE=""
OVERRIDE_CAMPAIGN_REPEATS=""
OVERRIDE_DATASET_SEED_BASE=""
OVERRIDE_DATASET_FILES_PER_BUCKET=""
OVERRIDE_DATASET_FILE_TYPES=""
OVERRIDE_REGENERATE_WARM_DATASET=""
OVERRIDE_PREWARM_WARM_DATASET=""
OVERRIDE_KEEP_COLD_DATASETS=""

API_KEY="${PQC_API_KEY:-}"
API_KEY_SOURCE="${PQC_API_KEY:+env:PQC_API_KEY}"
LOCAL_API_KEYS_FILE="${REPO_ROOT}/api-keys.local.json"
ORIG_RATE_LIMIT_SIGN_PER_MIN="${RATE_LIMIT_SIGN_PER_MIN-__UNSET__}"
ORIG_RATE_LIMIT_VERIFY_PER_MIN="${RATE_LIMIT_VERIFY_PER_MIN-__UNSET__}"
ORIG_RATE_LIMIT_HASH_PER_MIN="${RATE_LIMIT_HASH_PER_MIN-__UNSET__}"
ORIG_RATE_LIMIT_GLOBAL_PER_MIN="${RATE_LIMIT_GLOBAL_PER_MIN-__UNSET__}"
ORIG_RATE_LIMIT_AUTH_FAIL_PER_MIN="${RATE_LIMIT_AUTH_FAIL_PER_MIN-__UNSET__}"
ORIG_MAX_UPLOAD_STORAGE_PER_KEY="${MAX_UPLOAD_STORAGE_PER_KEY-__UNSET__}"
GATEWAY_BENCHMARK_MODE_APPLIED="false"

usage() {
  cat <<'EOF'
Usage: scripts/run_benchmark_campaign.sh [options]

Runs benchmark-cli and analyzes every generated JSON report. Supports repeated
cold and warm campaigns so the output is suitable for formal benchmarking.
Use `--smoke` for a short single-state sanity run with small defaults.

Options:
  --api-key <key>                 API key (default: env PQC_API_KEY, otherwise auto-detect local operator/admin key)
  --base-url <url>                API gateway URL (default: http://localhost:3000)
  --dataset-dir <dir>             Warm-state dataset path (default: ./dataset)
  --output-dir <dir>              Benchmark output path (default: ./output/benchmarks)
  --profiles <csv>                Profiles CSV (default: rsa_pss,eddsa,ecdsa,hmac_sha256,ml_dsa,slh_dsa,fn_dsa)
  --hashes <csv>                  Hashes CSV (default: sha256,blake3,keccak256)
  --buckets <csv>                 Buckets CSV (default: 10KB,100KB,1MB,10MB,50MB)
  --scenarios <csv>               Scenarios CSV
                                  (default: workflow,sign_only,verify_manifest,verify_stored,verify_uploaded,verify_full)
  --warmup-runs <n>               Warm-up runs per condition (default: 10)
  --measured-runs <n>             Measured runs per condition (default: 100)
  --seed <n>                      RNG seed passed to benchmark-cli (default: 42)
  --inter-run-delay-ms <n>        Delay between runs in ms (default: 350)
  --operations-endpoint <url>     Operations endpoint URL (default: <base-url>/operations)
  --cleanup-uploads               Clear /data/uploads in local api-gateway before each run (default: on)
  --no-cleanup-uploads            Skip cleanup of /data/uploads

  --storage-state-mode <mode>     warm | cold | both (default: warm)
  --campaign-repeats <n>          Independent repeats per state (default: 1)
  --campaign-label <label>        Label recorded in reports and manifest
  --dataset-seed-base <seed>      Base dataset seed label (default: pqc-hons-dataset-v2)
  --dataset-files-per-bucket <n>  Dataset size per bucket (default: 32)
  --dataset-file-types <csv>      Dataset file types (default: bin,txt,json,csv,md)
  --regenerate-warm-dataset       Rebuild the warm-state dataset before running
  --no-prewarm-warm-dataset       Skip warm-state prewarm pass
  --discard-cold-datasets         Delete generated cold datasets after the campaign

  --resume                        Resume from the latest manifest rows for this campaign label
  --force-overwrite               Remove existing campaign outputs for this label before running
  --estimate-only                 Print the run-count and delay estimate, then exit
  --smoke                         Apply short smoke-test defaults within this same runner

  --min-success-rate <float>      Analysis quality gate threshold (default: 0.90)
  --min-condition-success-rate <float>
                                  Per-condition scenario success threshold (default: 0.90)
  --min-server-coverage <float>   Required per-condition server timing coverage (default: 1.00)
  --max-relative-iqr <float>      Relative-IQR stability threshold (default: 0.20)
  --max-server-relative-iqr <float>
                                  Server relative-IQR stability threshold (default: 0.20)
  --min-samples-for-ci <n>        Minimum successful runs for a condition to be comparison-valid (default: 20)
  --analysis-bootstrap-samples <n>
                                  Bootstrap samples for analysis CIs (default: 2000)
  --plot-formats <csv>            Plot formats for analysis figures (default: png,svg)
  --skip-analysis-plots           Disable analysis figure generation

  -h, --help                      Show this help

Examples:
  export PQC_API_KEY="<operator-or-admin-key>"
  scripts/run_benchmark_campaign.sh --storage-state-mode both --campaign-repeats 3
  scripts/run_benchmark_campaign.sh --campaign-label honours-formal --resume
  scripts/run_benchmark_campaign.sh --smoke
  scripts/run_benchmark_campaign.sh --storage-state-mode both --estimate-only
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-key)
      API_KEY="$2"
      API_KEY_SOURCE="flag:--api-key"
      shift 2
      ;;
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --dataset-dir)
      DATASET_DIR="$2"
      OVERRIDE_DATASET_DIR="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      OVERRIDE_OUTPUT_DIR="$2"
      shift 2
      ;;
    --profiles)
      PROFILES="$2"
      OVERRIDE_PROFILES="$2"
      shift 2
      ;;
    --hashes)
      HASHES="$2"
      OVERRIDE_HASHES="$2"
      shift 2
      ;;
    --buckets)
      BUCKETS="$2"
      OVERRIDE_BUCKETS="$2"
      shift 2
      ;;
    --scenarios)
      SCENARIOS="$2"
      OVERRIDE_SCENARIOS="$2"
      shift 2
      ;;
    --warmup-runs)
      WARMUP_RUNS="$2"
      OVERRIDE_WARMUP_RUNS="$2"
      shift 2
      ;;
    --measured-runs)
      MEASURED_RUNS="$2"
      OVERRIDE_MEASURED_RUNS="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      OVERRIDE_SEED="$2"
      shift 2
      ;;
    --inter-run-delay-ms)
      INTER_RUN_DELAY_MS="$2"
      OVERRIDE_INTER_RUN_DELAY_MS="$2"
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
      OVERRIDE_STORAGE_STATE_MODE="$2"
      shift 2
      ;;
    --campaign-repeats)
      CAMPAIGN_REPEATS="$2"
      OVERRIDE_CAMPAIGN_REPEATS="$2"
      shift 2
      ;;
    --campaign-label)
      CAMPAIGN_LABEL="$2"
      shift 2
      ;;
    --dataset-seed-base)
      DATASET_SEED_BASE="$2"
      OVERRIDE_DATASET_SEED_BASE="$2"
      shift 2
      ;;
    --dataset-files-per-bucket)
      DATASET_FILES_PER_BUCKET="$2"
      OVERRIDE_DATASET_FILES_PER_BUCKET="$2"
      shift 2
      ;;
    --dataset-file-types)
      DATASET_FILE_TYPES="$2"
      OVERRIDE_DATASET_FILE_TYPES="$2"
      shift 2
      ;;
    --regenerate-warm-dataset)
      REGENERATE_WARM_DATASET="true"
      OVERRIDE_REGENERATE_WARM_DATASET="true"
      shift 1
      ;;
    --no-prewarm-warm-dataset)
      PREWARM_WARM_DATASET="false"
      OVERRIDE_PREWARM_WARM_DATASET="false"
      shift 1
      ;;
    --discard-cold-datasets)
      KEEP_COLD_DATASETS="false"
      OVERRIDE_KEEP_COLD_DATASETS="false"
      shift 1
      ;;
    --resume)
      RESUME="true"
      shift 1
      ;;
    --force-overwrite)
      FORCE_OVERWRITE="true"
      shift 1
      ;;
    --estimate-only)
      ESTIMATE_ONLY="true"
      shift 1
      ;;
    --smoke)
      SMOKE_MODE="true"
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
    --max-server-relative-iqr)
      MAX_SERVER_RELATIVE_IQR="$2"
      shift 2
      ;;
    --min-samples-for-ci)
      MIN_SAMPLES_FOR_CI="$2"
      shift 2
      ;;
    --analysis-bootstrap-samples)
      ANALYSIS_BOOTSTRAP_SAMPLES="$2"
      shift 2
      ;;
    --plot-formats)
      PLOT_FORMATS="$2"
      shift 2
      ;;
    --skip-analysis-plots)
      SKIP_ANALYSIS_PLOTS="true"
      shift 1
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

if [[ "${SMOKE_MODE}" == "true" ]]; then
  DATASET_DIR="./dataset-smoke"
  OUTPUT_DIR="./output/benchmarks-smoke"
  PROFILES="rsa_pss,eddsa,ecdsa,hmac_sha256,ml_dsa,slh_dsa,fn_dsa"
  HASHES="sha256,blake3,keccak256"
  BUCKETS="10KB"
  SCENARIOS="workflow"
  WARMUP_RUNS="1"
  MEASURED_RUNS="2"
  SEED="4242"
  INTER_RUN_DELAY_MS="250"
  STORAGE_STATE_MODE="warm"
  CAMPAIGN_REPEATS="1"
  DATASET_SEED_BASE="pqc-hons-benchmark-smoke-v1"
  DATASET_FILES_PER_BUCKET="4"
  REGENERATE_WARM_DATASET="true"
  PREWARM_WARM_DATASET="false"
  KEEP_COLD_DATASETS="true"

  [[ -n "${OVERRIDE_DATASET_DIR}" ]] && DATASET_DIR="${OVERRIDE_DATASET_DIR}"
  [[ -n "${OVERRIDE_OUTPUT_DIR}" ]] && OUTPUT_DIR="${OVERRIDE_OUTPUT_DIR}"
  [[ -n "${OVERRIDE_PROFILES}" ]] && PROFILES="${OVERRIDE_PROFILES}"
  [[ -n "${OVERRIDE_HASHES}" ]] && HASHES="${OVERRIDE_HASHES}"
  [[ -n "${OVERRIDE_BUCKETS}" ]] && BUCKETS="${OVERRIDE_BUCKETS}"
  [[ -n "${OVERRIDE_SCENARIOS}" ]] && SCENARIOS="${OVERRIDE_SCENARIOS}"
  [[ -n "${OVERRIDE_WARMUP_RUNS}" ]] && WARMUP_RUNS="${OVERRIDE_WARMUP_RUNS}"
  [[ -n "${OVERRIDE_MEASURED_RUNS}" ]] && MEASURED_RUNS="${OVERRIDE_MEASURED_RUNS}"
  [[ -n "${OVERRIDE_SEED}" ]] && SEED="${OVERRIDE_SEED}"
  [[ -n "${OVERRIDE_INTER_RUN_DELAY_MS}" ]] && INTER_RUN_DELAY_MS="${OVERRIDE_INTER_RUN_DELAY_MS}"
  [[ -n "${OVERRIDE_STORAGE_STATE_MODE}" ]] && STORAGE_STATE_MODE="${OVERRIDE_STORAGE_STATE_MODE}"
  [[ -n "${OVERRIDE_CAMPAIGN_REPEATS}" ]] && CAMPAIGN_REPEATS="${OVERRIDE_CAMPAIGN_REPEATS}"
  [[ -n "${OVERRIDE_DATASET_SEED_BASE}" ]] && DATASET_SEED_BASE="${OVERRIDE_DATASET_SEED_BASE}"
  [[ -n "${OVERRIDE_DATASET_FILES_PER_BUCKET}" ]] && DATASET_FILES_PER_BUCKET="${OVERRIDE_DATASET_FILES_PER_BUCKET}"
  [[ -n "${OVERRIDE_DATASET_FILE_TYPES}" ]] && DATASET_FILE_TYPES="${OVERRIDE_DATASET_FILE_TYPES}"
  [[ -n "${OVERRIDE_REGENERATE_WARM_DATASET}" ]] && REGENERATE_WARM_DATASET="${OVERRIDE_REGENERATE_WARM_DATASET}"
  [[ -n "${OVERRIDE_PREWARM_WARM_DATASET}" ]] && PREWARM_WARM_DATASET="${OVERRIDE_PREWARM_WARM_DATASET}"
  [[ -n "${OVERRIDE_KEEP_COLD_DATASETS}" ]] && KEEP_COLD_DATASETS="${OVERRIDE_KEEP_COLD_DATASETS}"
fi

if [[ "${FORCE_OVERWRITE}" == "true" && "${RESUME}" == "true" ]]; then
  echo "Error: --resume and --force-overwrite are mutually exclusive." >&2
  exit 2
fi

if [[ -z "${OPERATIONS_ENDPOINT}" ]]; then
  OPERATIONS_ENDPOINT="${BASE_URL%/}/operations"
fi

is_local_gateway() {
  case "${BASE_URL}" in
    http://localhost*|https://localhost*|http://127.0.0.1*|https://127.0.0.1*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

local_gateway_docker_available() {
  is_local_gateway || return 1
  command -v docker >/dev/null 2>&1 || return 1
  docker compose config --services >/dev/null 2>&1 || return 1
  docker compose config --services | grep -qx "api-gateway"
}

discover_local_api_key() {
  local keys_file="${LOCAL_API_KEYS_FILE}"
  [[ -f "${keys_file}" ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1

  python3 - "${keys_file}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text())

def usable_key(key: str) -> bool:
    return bool(key) and not key.startswith("CHANGE_ME")

def emit_first_from_list(items):
    preferred = []
    fallback = []
    for item in items:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not usable_key(key):
            continue
        if item.get("enabled", True) is False:
            continue
        role = item.get("role")
        if role in {"admin", "operator"}:
            preferred.append(key)
        else:
            fallback.append(key)
    for pool in (preferred, fallback):
        if pool:
            print(pool[0])
            return True
    return False

if isinstance(data, dict) and isinstance(data.get("keys"), list):
    if emit_first_from_list(data["keys"]):
        raise SystemExit(0)

if isinstance(data, dict):
    preferred = []
    fallback = []
    for key, meta in data.items():
        if not usable_key(key):
            continue
        role = meta.get("role") if isinstance(meta, dict) else None
        if role in {"admin", "operator"}:
            preferred.append(key)
        else:
            fallback.append(key)
    for pool in (preferred, fallback):
        if pool:
            print(pool[0])
            raise SystemExit(0)

raise SystemExit(1)
PY
}

ensure_api_key() {
  if [[ -n "${API_KEY}" ]]; then
    return
  fi

  if is_local_gateway; then
    if API_KEY="$(discover_local_api_key)"; then
      API_KEY_SOURCE="auto:${LOCAL_API_KEYS_FILE}"
      echo "Using local API key discovered from ${LOCAL_API_KEYS_FILE}."
      return
    fi
  fi

  echo "Error: API key missing. Set PQC_API_KEY, pass --api-key, or provide a usable local key in ${LOCAL_API_KEYS_FILE}." >&2
  exit 2
}

restore_gateway_env_var() {
  local name="$1"
  local previous="$2"
  if [[ "${previous}" == "__UNSET__" ]]; then
    unset "${name}"
  else
    export "${name}=${previous}"
  fi
}

ensure_gateway_ready() {
  local health_url="${BASE_URL%/}/health"
  echo "Checking gateway health at ${health_url}..."
  local status
  status="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-API-Key: ${API_KEY}" "${health_url}" || true)"
  if [[ "${status}" == "200" ]]; then
    return
  fi

  if [[ "${status}" =~ ^(401|403)$ ]] && is_local_gateway; then
    local discovered_key
    if discovered_key="$(discover_local_api_key)" && [[ -n "${discovered_key}" && "${discovered_key}" != "${API_KEY}" ]]; then
      API_KEY="${discovered_key}"
      API_KEY_SOURCE="auto:${LOCAL_API_KEYS_FILE}"
      echo "Replaced rejected API key with a local key from ${LOCAL_API_KEYS_FILE}."
      status="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-API-Key: ${API_KEY}" "${health_url}" || true)"
      if [[ "${status}" == "200" ]]; then
        return
      fi
    fi
  fi

  echo "Error: API gateway is not healthy at ${health_url} (HTTP ${status:-curl_error}) using ${API_KEY_SOURCE:-provided key}." >&2
    echo "Start the stack first with: docker compose up -d" >&2
    exit 1
}

configure_gateway_benchmark_mode() {
  if ! is_local_gateway; then
    echo "Base URL is not local; skipping automatic gateway benchmark-mode configuration."
    return
  fi

  if ! local_gateway_docker_available; then
    echo "Local api-gateway docker service unavailable; skipping automatic benchmark-mode configuration."
    return
  fi

  echo "Configuring api-gateway for benchmark mode..."
  export RATE_LIMIT_SIGN_PER_MIN=0
  export RATE_LIMIT_VERIFY_PER_MIN=0
  export RATE_LIMIT_HASH_PER_MIN=0
  export RATE_LIMIT_GLOBAL_PER_MIN=0
  export RATE_LIMIT_AUTH_FAIL_PER_MIN=0
  export MAX_UPLOAD_STORAGE_PER_KEY=0

  docker compose up -d --force-recreate --no-deps api-gateway >/dev/null
  GATEWAY_BENCHMARK_MODE_APPLIED="true"
  ensure_gateway_ready
}

restore_gateway_configuration() {
  if [[ "${GATEWAY_BENCHMARK_MODE_APPLIED}" != "true" ]]; then
    return
  fi

  echo "Restoring api-gateway configuration..."
  restore_gateway_env_var "RATE_LIMIT_SIGN_PER_MIN" "${ORIG_RATE_LIMIT_SIGN_PER_MIN}"
  restore_gateway_env_var "RATE_LIMIT_VERIFY_PER_MIN" "${ORIG_RATE_LIMIT_VERIFY_PER_MIN}"
  restore_gateway_env_var "RATE_LIMIT_HASH_PER_MIN" "${ORIG_RATE_LIMIT_HASH_PER_MIN}"
  restore_gateway_env_var "RATE_LIMIT_GLOBAL_PER_MIN" "${ORIG_RATE_LIMIT_GLOBAL_PER_MIN}"
  restore_gateway_env_var "RATE_LIMIT_AUTH_FAIL_PER_MIN" "${ORIG_RATE_LIMIT_AUTH_FAIL_PER_MIN}"
  restore_gateway_env_var "MAX_UPLOAD_STORAGE_PER_KEY" "${ORIG_MAX_UPLOAD_STORAGE_PER_KEY}"

  docker compose up -d --force-recreate --no-deps api-gateway >/dev/null || true
}

trap restore_gateway_configuration EXIT

if [[ "${ESTIMATE_ONLY}" != "true" ]]; then
  ensure_api_key
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

CAMPAIGN_RUN_ROOT="${OUTPUT_DIR}/campaign-runs/${CAMPAIGN_LABEL}"
PREWARM_ROOT="${OUTPUT_DIR}/.campaign-prewarm/${CAMPAIGN_LABEL}"
CAMPAIGN_ANALYSIS_DIR="${OUTPUT_DIR}/analysis/campaign-manifest-${CAMPAIGN_LABEL}"
MANIFEST_PATH="${OUTPUT_DIR}/campaign-manifest-${CAMPAIGN_LABEL}.tsv"
CAMPAIGN_SETUP_PATH="${OUTPUT_DIR}/campaign-setup-${CAMPAIGN_LABEL}.json"
MANIFEST_HEADER=$'state\trepeat_index\trun_slug\tdataset_seed\tdataset_dir\trun_output_dir\tlog_path\treport_json\truns_csv\tsummary_csv\tevidence_csv\tanalysis_dir\tbenchmark_status\tanalysis_status\tstarted_at\tbenchmark_finished_at\tanalysis_finished_at\tprewarm_enabled\tbenchmark_seed\tprewarm_seed\toperations_endpoint\tcampaign_label\tnotes\n'

sanitize_manifest_field() {
  local value="${1-}"
  value="${value//$'\t'/ }"
  value="${value//$'\n'/ }"
  printf '%s' "${value}"
}

init_manifest_file() {
  if [[ ! -f "${MANIFEST_PATH}" ]]; then
    printf "%s" "${MANIFEST_HEADER}" > "${MANIFEST_PATH}"
  fi
}

append_manifest_row() {
  local state="$1"
  local repeat_index="$2"
  local run_slug="$3"
  local dataset_seed="$4"
  local dataset_dir="$5"
  local run_output_dir="$6"
  local log_path="$7"
  local report_json="$8"
  local runs_csv="$9"
  local summary_csv="${10}"
  local evidence_csv="${11}"
  local analysis_dir="${12}"
  local benchmark_status="${13}"
  local analysis_status="${14}"
  local started_at="${15}"
  local benchmark_finished_at="${16}"
  local analysis_finished_at="${17}"
  local prewarm_enabled="${18}"
  local benchmark_seed="${19}"
  local prewarm_seed="${20}"
  local operations_endpoint="${21}"
  local campaign_label="${22}"
  local notes="${23}"

  init_manifest_file
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${state}" \
    "${repeat_index}" \
    "${run_slug}" \
    "$(sanitize_manifest_field "${dataset_seed}")" \
    "$(sanitize_manifest_field "${dataset_dir}")" \
    "$(sanitize_manifest_field "${run_output_dir}")" \
    "$(sanitize_manifest_field "${log_path}")" \
    "$(sanitize_manifest_field "${report_json}")" \
    "$(sanitize_manifest_field "${runs_csv}")" \
    "$(sanitize_manifest_field "${summary_csv}")" \
    "$(sanitize_manifest_field "${evidence_csv}")" \
    "$(sanitize_manifest_field "${analysis_dir}")" \
    "${benchmark_status}" \
    "${analysis_status}" \
    "${started_at}" \
    "${benchmark_finished_at}" \
    "${analysis_finished_at}" \
    "${prewarm_enabled}" \
    "${benchmark_seed}" \
    "${prewarm_seed}" \
    "$(sanitize_manifest_field "${operations_endpoint}")" \
    "$(sanitize_manifest_field "${campaign_label}")" \
    "$(sanitize_manifest_field "${notes}")" >> "${MANIFEST_PATH}"
}

latest_manifest_row() {
  local state="$1"
  local repeat_index="$2"
  [[ -f "${MANIFEST_PATH}" ]] || return 1

  python3 - "${MANIFEST_PATH}" "${state}" "${repeat_index}" <<'PY'
import csv
import sys

path, state, repeat_index = sys.argv[1:]
last = None
with open(path, "r", encoding="utf-8", newline="") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    for row in reader:
        if row.get("state") == state and row.get("repeat_index") == repeat_index:
            last = row

if last is None:
    raise SystemExit(1)

fields = [
    "benchmark_status",
    "analysis_status",
    "report_json",
    "runs_csv",
    "summary_csv",
    "evidence_csv",
    "analysis_dir",
    "run_output_dir",
    "log_path",
    "benchmark_finished_at",
    "analysis_finished_at",
    "started_at",
    "dataset_dir",
    "dataset_seed",
    "prewarm_enabled",
    "benchmark_seed",
    "prewarm_seed",
]
print(
    "\t".join(
        (last.get(field, "") or "").replace("\t", " ").replace("\n", " ")
        for field in fields
    )
)
PY
}

csv_count() {
  python3 - "$1" <<'PY'
import sys

raw = sys.argv[1]
items = [part.strip() for part in raw.split(",") if part.strip()]
print(len(items))
PY
}

join_csv() {
  local IFS=","
  printf '%s' "$*"
}

print_benchmark_setup_summary() {
  local storage_states_csv
  storage_states_csv="$(join_csv "${STORAGE_STATES[@]}")"

  echo "Benchmark setup:"
  echo "- Primary matrix:"
  echo "  scenario=${SCENARIOS}"
  echo "  storage_state=${storage_states_csv}"
  echo "  signature_strategy=${PROFILES}"
  echo "  hash_algorithm=${HASHES}"
  echo "  payload_bucket=${BUCKETS}"
  echo "- Secondary factors:"
  echo "  file_content_class=${DATASET_FILE_TYPES}"
  echo "  run_phase=warmup,measured"
  echo "  telemetry_scope=client,server,artifact,quality"
  echo "- Measurement groups:"
  echo "  outcome_and_validity=scenario_status,verify_outcome,scenario_success_rate,verify_applicable_success_rate,server_telemetry_status,server_telemetry_coverage"
  echo "  performance_timings=setup_upload_ms,setup_process_ms,client_upload_ms,client_process_ms,client_verify_ms,client_total_ms,server_hash_ms,server_verify_ms,server_total_ms"
  echo "  artifact_overhead=manifest_core_bytes,manifest_core_cbor_bytes,total_signature_bytes,manifest_overhead_pct,signature_overhead_pct"
  echo "  provenance_and_controls=dataset_seed,dataset_relative_path,dataset_bucket_index,dataset_file_type,storage_state_label,campaign_label,repeat_index"
}

write_benchmark_setup_json() {
  local output_path="$1"
  local storage_states_csv
  storage_states_csv="$(join_csv "${STORAGE_STATES[@]}")"

  python3 - "${output_path}" "${PROFILES}" "${HASHES}" "${BUCKETS}" "${SCENARIOS}" "${storage_states_csv}" "${DATASET_FILE_TYPES}" "${CAMPAIGN_LABEL}" <<'PY'
import json
import sys

(
    output_path,
    profiles_csv,
    hashes_csv,
    buckets_csv,
    scenarios_csv,
    storage_states_csv,
    file_types_csv,
    campaign_label,
) = sys.argv[1:]

def split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]

payload = {
    "version": "benchmarking.v2",
    "campaign_label": campaign_label,
    "purpose": "Decision-grade performance benchmarking for RSA-PSS, ml_dsa, and RSA-PSS + ml_dsa signing workflows",
    "primary_matrix": [
        {"name": "scenario", "role": "primary_matrix", "options": split_csv(scenarios_csv)},
        {"name": "storage_state", "role": "primary_matrix", "options": split_csv(storage_states_csv)},
        {"name": "signature_strategy", "role": "primary_matrix", "options": split_csv(profiles_csv)},
        {"name": "hash_algorithm", "role": "primary_matrix", "options": split_csv(hashes_csv)},
        {"name": "payload_bucket", "role": "primary_matrix", "options": split_csv(buckets_csv)},
    ],
    "secondary_factors": [
        {"name": "file_content_class", "role": "secondary_factor", "options": split_csv(file_types_csv)},
        {"name": "run_phase", "role": "secondary_factor", "options": ["warmup", "measured"]},
        {"name": "telemetry_scope", "role": "secondary_factor", "options": ["client", "server", "artifact", "quality"]},
    ],
    "measurement_groups": [
        {
            "name": "outcome_and_validity",
            "fields": [
                "scenario_status",
                "verify_outcome",
                "scenario_success_rate",
                "verify_applicable_success_rate",
                "server_telemetry_status",
                "server_telemetry_coverage",
            ],
        },
        {
            "name": "performance_timings",
            "fields": [
                "setup_upload_ms",
                "setup_process_ms",
                "client_upload_ms",
                "client_process_ms",
                "client_verify_ms",
                "client_total_ms",
                "server_hash_ms",
                "server_verify_ms",
                "server_total_ms",
            ],
        },
        {
            "name": "artifact_overhead",
            "fields": [
                "manifest_core_bytes",
                "manifest_core_cbor_bytes",
                "total_signature_bytes",
                "manifest_overhead_pct",
                "signature_overhead_pct",
            ],
        },
        {
            "name": "provenance_and_controls",
            "fields": [
                "dataset_seed",
                "dataset_relative_path",
                "dataset_bucket_index",
                "dataset_file_type",
                "storage_state_label",
                "campaign_label",
                "repeat_index",
            ],
        },
    ],
    "notes": [
        "Treat file identity as a sampled replicate inside each bucket, not as a primary comparison axis.",
        "Use server-side timings as the source of truth for crypto-stage conclusions.",
        "Warm-up runs are excluded from measured summaries.",
        "For sign_only, client_total_ms still includes upload and setup overhead.",
    ],
}

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")
PY
}

utc_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

analysis_dir_for_report() {
  local report_json="$1"
  local report_dir report_stem
  report_dir="$(dirname "${report_json}")"
  report_stem="$(basename "${report_json}" .json)"
  printf '%s/analysis/%s' "${report_dir}" "${report_stem}"
}

resolve_single_artifact() {
  local search_dir="$1"
  local pattern="$2"
  local matches=()

  shopt -s nullglob
  matches=("${search_dir}"/${pattern})
  shopt -u nullglob

  if [[ ${#matches[@]} -ne 1 ]]; then
    echo "Error: expected exactly one '${pattern}' in ${search_dir}, found ${#matches[@]}." >&2
    return 1
  fi

  printf '%s' "${matches[0]}"
}

resolve_run_artifacts() {
  local run_output_dir="$1"
  local report_json runs_csv summary_csv evidence_csv

  report_json="$(resolve_single_artifact "${run_output_dir}" "benchmark-report-*.json")" || return 1
  runs_csv="$(resolve_single_artifact "${run_output_dir}" "benchmark-runs-*.csv")" || return 1
  summary_csv="$(resolve_single_artifact "${run_output_dir}" "benchmark-summary-*.csv")" || return 1
  evidence_csv="$(resolve_single_artifact "${run_output_dir}" "benchmark-evidence-metrics-*.csv")" || return 1

  printf '%s\t%s\t%s\t%s' \
    "${report_json}" \
    "${runs_csv}" \
    "${summary_csv}" \
    "${evidence_csv}"
}

print_campaign_estimate() {
  local profiles_count hashes_count buckets_count scenarios_count states_count warm_repeats
  local conditions_per_repeat runs_per_condition runs_per_repeat main_runs_total
  local fixed_delay_ms fixed_delay_s fixed_delay_min fixed_delay_hr prewarm_runs_total

  profiles_count="$(csv_count "${PROFILES}")"
  hashes_count="$(csv_count "${HASHES}")"
  buckets_count="$(csv_count "${BUCKETS}")"
  scenarios_count="$(csv_count "${SCENARIOS}")"
  states_count="${#STORAGE_STATES[@]}"


  # Calculate valid profile+hash combinations
  classical_profiles_count=0
  pqc_profiles_count=0
  for p in ${PROFILES//,/ }; do
    if [[ "$p" =~ ^(ml_dsa|ml_dsa|slh_dsa|fn_dsa)$ ]]; then
      pqc_profiles_count=$((pqc_profiles_count + 1))
    else
      classical_profiles_count=$((classical_profiles_count + 1))
    fi
  done

  classical_hashes_count=0
  pqc_hashes_count=0
  for h in ${HASHES//,/ }; do
    if [[ "$h" == *"keccak"* || "$h" == *"sha3"* || "$h" == *"shake"* ]]; then
      pqc_hashes_count=$((pqc_hashes_count + 1))
    else
      classical_hashes_count=$((classical_hashes_count + 1))
    fi
  done

  valid_profile_hash_combos=$(( (classical_profiles_count * classical_hashes_count) + (pqc_profiles_count * pqc_hashes_count) ))
  conditions_per_repeat=$(( valid_profile_hash_combos * buckets_count * scenarios_count ))
  runs_per_condition=$(( WARMUP_RUNS + MEASURED_RUNS ))
  runs_per_repeat=$(( conditions_per_repeat * runs_per_condition ))
  main_runs_total=$(( runs_per_repeat * states_count * CAMPAIGN_REPEATS ))

  warm_repeats=0
  if [[ "${STORAGE_STATE_MODE}" == "warm" || "${STORAGE_STATE_MODE}" == "both" ]]; then
    warm_repeats="${CAMPAIGN_REPEATS}"
  fi
  prewarm_runs_total=0
  if [[ "${PREWARM_WARM_DATASET}" == "true" && "${warm_repeats}" -gt 0 ]]; then
    prewarm_runs_total=$(( warm_repeats * hashes_count * buckets_count * DATASET_FILES_PER_BUCKET ))
  fi

  fixed_delay_ms=$(( main_runs_total * INTER_RUN_DELAY_MS ))
  fixed_delay_s=$(( fixed_delay_ms / 1000 ))
  fixed_delay_min="$(python3 - "${fixed_delay_s}" <<'PY'
import sys
seconds = float(sys.argv[1])
print(f"{seconds / 60:.1f}")
PY
)"
  fixed_delay_hr="$(python3 - "${fixed_delay_s}" <<'PY'
import sys
seconds = float(sys.argv[1])
print(f"{seconds / 3600:.2f}")
PY
)"

  print_benchmark_setup_summary
  echo "Campaign estimate:"
  echo "- Storage states: ${STORAGE_STATES[*]}"
  echo "- Conditions per repeat: ${conditions_per_repeat} (${valid_profile_hash_combos} valid hash-profile pairs x ${buckets_count} buckets x ${scenarios_count} scenarios)"
  echo "- Runs per condition: ${runs_per_condition} (${WARMUP_RUNS} warmup + ${MEASURED_RUNS} measured)"
  echo "- Main benchmark runs total: ${main_runs_total}"
  echo "- Warm-state prewarm runs total: ${prewarm_runs_total}"
  echo "- Fixed inter-run delay floor: ${fixed_delay_s}s (${fixed_delay_min} min, ${fixed_delay_hr} h)"
  if [[ "${STORAGE_STATE_MODE}" == "cold" || "${STORAGE_STATE_MODE}" == "both" ]]; then
    echo "- Cold-state note: this script regenerates the dataset and clears local upload cache, but it does not automatically reset external object storage beyond the local Docker gateway benchmark-mode helpers."
  fi
}

ensure_campaign_workspace() {
  local path
  for path in "${OUTPUT_DIR}" "${OUTPUT_DIR}/analysis" "${OUTPUT_DIR}/datasets"; do
    mkdir -p "${path}"
  done
}

reset_campaign_outputs_if_requested() {
  if [[ "${FORCE_OVERWRITE}" != "true" ]]; then
    return
  fi

  echo "Removing existing outputs for campaign label '${CAMPAIGN_LABEL}'..."
  rm -f "${MANIFEST_PATH}"
  rm -rf "${CAMPAIGN_RUN_ROOT}" "${PREWARM_ROOT}" "${CAMPAIGN_ANALYSIS_DIR}"
}

guard_against_existing_outputs() {
  if [[ "${FORCE_OVERWRITE}" == "true" || "${RESUME}" == "true" ]]; then
    return
  fi

  if [[ -f "${MANIFEST_PATH}" || -d "${CAMPAIGN_RUN_ROOT}" || -d "${PREWARM_ROOT}" || -d "${CAMPAIGN_ANALYSIS_DIR}" ]]; then
    echo "Error: campaign outputs already exist for label '${CAMPAIGN_LABEL}'." >&2
    echo "Use --resume to continue or --force-overwrite to remove the previous outputs." >&2
    exit 2
  fi
}

cleanup_upload_cache() {
  if [[ "${CLEANUP_UPLOADS}" != "true" ]]; then
    return
  fi
  if ! is_local_gateway; then
    echo "Base URL is not local; skipping upload cleanup."
    return
  fi
  if ! local_gateway_docker_available; then
    echo "Local api-gateway docker service unavailable; skipping upload cleanup."
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
  rm -rf "${target_dir}"
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
    return
  fi

  if ! dataset_layout_matches_expected "${DATASET_DIR}" "${warm_seed}"; then
    echo "Regenerating warm-state dataset to match benchmark layout v${DATASET_LAYOUT_VERSION}..."
    generate_dataset "${DATASET_DIR}" "${warm_seed}"
  fi
}

dataset_layout_matches_expected() {
  local dataset_dir="$1"
  local expected_seed="$2"
  local metadata_path="${dataset_dir}/dataset-metadata.json"

  if [[ ! -f "${metadata_path}" ]]; then
    return 1
  fi

  python3 - "${metadata_path}" "${DATASET_LAYOUT_VERSION}" "${expected_seed}" "${DATASET_FILES_PER_BUCKET}" "${DATASET_FILE_TYPES}" <<'PY'
import json
import sys

metadata_path, expected_version, expected_seed, expected_files_per_bucket, expected_file_types = sys.argv[1:]

with open(metadata_path, "r", encoding="utf-8") as handle:
    metadata = json.load(handle)

actual_file_types = ",".join(metadata.get("file_types", []))
is_valid = (
    str(metadata.get("layout_version")) == expected_version
    and metadata.get("seed") == expected_seed
    and str(metadata.get("files_per_bucket")) == expected_files_per_bucket
    and actual_file_types == expected_file_types
    and metadata.get("size_selection_mode") == "exact_bucket_size"
)

raise SystemExit(0 if is_valid else 1)
PY
}

preflight_analysis_tools() {
  python3 scripts/analyze_benchmark_report.py --help >/dev/null
}

prewarm_warm_dataset() {
  local dataset_seed="$1"
  local repeat_index="$2"
  local prewarm_seed="$3"
  local prewarm_output_dir="${PREWARM_ROOT}/repeat-${repeat_index}"

  if [[ "${PREWARM_WARM_DATASET}" != "true" ]]; then
    return
  fi

  cleanup_upload_cache
  rm -rf "${prewarm_output_dir}"
  mkdir -p "${prewarm_output_dir}"

  echo "Prewarming warm-state object cache using ${DATASET_DIR}..."
  ./target/release/benchmark-cli \
    --api-key "${API_KEY}" \
    --base-url "${BASE_URL}" \
    --dataset-dir "${DATASET_DIR}" \
    --output-dir "${prewarm_output_dir}" \
    --profiles "rsa_pss" \
    --hashes "${HASHES}" \
    --buckets "${BUCKETS}" \
    --scenarios "sign_only" \
    --warmup-runs 0 \
    --measured-runs "${DATASET_FILES_PER_BUCKET}" \
    --seed "${prewarm_seed}" \
    --inter-run-delay-ms 0 \
    --operations-endpoint "${OPERATIONS_ENDPOINT}" \
    --storage-state-label "prewarm" \
    --campaign-label "${CAMPAIGN_LABEL}-prewarm-${dataset_seed}" \
    --repeat-index "${repeat_index}" >/dev/null

  rm -rf "${prewarm_output_dir}"
}

run_analysis() {
  local report_json="$1"
  if [[ "${SKIP_ANALYSIS_PLOTS}" == "true" ]]; then
    python3 scripts/analyze_benchmark_report.py \
      "${report_json}" \
      --min-condition-success-rate "${MIN_CONDITION_SUCCESS_RATE}" \
      --min-server-coverage "${MIN_SERVER_COVERAGE}" \
      --max-relative-iqr "${MAX_RELATIVE_IQR}" \
      --max-server-relative-iqr "${MAX_SERVER_RELATIVE_IQR}" \
      --min-samples "${MIN_SAMPLES_FOR_CI}" \
      --plot-formats "${PLOT_FORMATS}" \
      --bootstrap-samples "${ANALYSIS_BOOTSTRAP_SAMPLES}" \
      --skip-plots
  else
    python3 scripts/analyze_benchmark_report.py \
      "${report_json}" \
      --min-condition-success-rate "${MIN_CONDITION_SUCCESS_RATE}" \
      --min-server-coverage "${MIN_SERVER_COVERAGE}" \
      --max-relative-iqr "${MAX_RELATIVE_IQR}" \
      --max-server-relative-iqr "${MAX_SERVER_RELATIVE_IQR}" \
      --min-samples "${MIN_SAMPLES_FOR_CI}" \
      --plot-formats "${PLOT_FORMATS}" \
      --bootstrap-samples "${ANALYSIS_BOOTSTRAP_SAMPLES}"
  fi
}

cleanup_cold_dataset_if_needed() {
  local state="$1"
  local dataset_dir="$2"
  if [[ "${state}" == "cold" && "${KEEP_COLD_DATASETS}" != "true" ]]; then
    rm -rf "${dataset_dir}"
  fi
}

print_campaign_estimate
if [[ "${ESTIMATE_ONLY}" == "true" ]]; then
  exit 0
fi

ensure_campaign_workspace
reset_campaign_outputs_if_requested
guard_against_existing_outputs

mkdir -p "${CAMPAIGN_RUN_ROOT}" "${PREWARM_ROOT}"
init_manifest_file
write_benchmark_setup_json "${CAMPAIGN_SETUP_PATH}"

echo "[1/6] Building benchmark CLI..."
cargo build --release --bin benchmark-cli >/dev/null

echo "[2/6] Preflighting analysis tools..."
preflight_analysis_tools

echo "[3/6] Preparing datasets..."
ensure_gateway_ready
configure_gateway_benchmark_mode
ensure_warm_dataset

echo "[4/6] Running campaign matrix..."
for state in "${STORAGE_STATES[@]}"; do
  for ((repeat_index = 1; repeat_index <= CAMPAIGN_REPEATS; repeat_index++)); do
    run_slug="${state}-repeat-${repeat_index}"
    run_output_dir="${CAMPAIGN_RUN_ROOT}/${state}/repeat-${repeat_index}"
    run_log_path="${run_output_dir}/campaign.log"
    benchmark_seed="$((SEED + repeat_index))"
    prewarm_seed=""
    prewarm_enabled="false"
    dataset_seed="${DATASET_SEED_BASE}:${state}:repeat-${repeat_index}"
    dataset_dir="${DATASET_DIR}"

    latest_benchmark_status=""
    latest_analysis_status=""
    latest_report_json=""
    latest_runs_csv=""
    latest_summary_csv=""
    latest_evidence_csv=""
    latest_analysis_dir=""
    latest_run_output_dir=""
    latest_log_path=""
    latest_benchmark_finished_at=""
    latest_analysis_finished_at=""
    latest_started_at=""
    latest_dataset_dir=""
    latest_dataset_seed=""
    latest_prewarm_enabled=""
    latest_benchmark_seed=""
    latest_prewarm_seed=""

    if latest_info="$(latest_manifest_row "${state}" "${repeat_index}" 2>/dev/null)"; then
      IFS=$'\t' read -r \
        latest_benchmark_status \
        latest_analysis_status \
        latest_report_json \
        latest_runs_csv \
        latest_summary_csv \
        latest_evidence_csv \
        latest_analysis_dir \
        latest_run_output_dir \
        latest_log_path \
        latest_benchmark_finished_at \
        latest_analysis_finished_at \
        latest_started_at \
        latest_dataset_dir \
        latest_dataset_seed \
        latest_prewarm_enabled \
        latest_benchmark_seed \
        latest_prewarm_seed <<< "${latest_info}"
    fi

    if [[ "${RESUME}" == "true" && "${latest_benchmark_status}" == "ok" && "${latest_analysis_status}" == "ok" && -n "${latest_report_json}" && -f "${latest_report_json}" ]]; then
      echo "Skipping completed run: state=${state} repeat=${repeat_index}"
      continue
    fi

    needs_benchmark="true"
    report_json=""
    runs_csv=""
    summary_csv=""
    evidence_csv=""
    analysis_dir=""
    run_started_at=""
    benchmark_finished_at=""
    analysis_finished_at=""

    if [[ "${RESUME}" == "true" && "${latest_benchmark_status}" == "ok" && -n "${latest_report_json}" && -f "${latest_report_json}" ]]; then
      needs_benchmark="false"
      report_json="${latest_report_json}"
      runs_csv="${latest_runs_csv}"
      summary_csv="${latest_summary_csv}"
      evidence_csv="${latest_evidence_csv}"
      analysis_dir="${latest_analysis_dir}"
      run_output_dir="${latest_run_output_dir:-${run_output_dir}}"
      run_log_path="${latest_log_path:-${run_log_path}}"
      run_started_at="${latest_started_at}"
      benchmark_finished_at="${latest_benchmark_finished_at}"
      dataset_dir="${latest_dataset_dir:-${dataset_dir}}"
      dataset_seed="${latest_dataset_seed:-${dataset_seed}}"
      prewarm_enabled="${latest_prewarm_enabled:-${prewarm_enabled}}"
      benchmark_seed="${latest_benchmark_seed:-${benchmark_seed}}"
      prewarm_seed="${latest_prewarm_seed:-${prewarm_seed}}"

      if [[ -z "${runs_csv}" || ! -f "${runs_csv}" || -z "${summary_csv}" || ! -f "${summary_csv}" || -z "${evidence_csv}" || ! -f "${evidence_csv}" ]]; then
        if artifact_info="$(resolve_run_artifacts "${run_output_dir}" 2>/dev/null)"; then
          IFS=$'\t' read -r report_json runs_csv summary_csv evidence_csv <<< "${artifact_info}"
          analysis_dir="$(analysis_dir_for_report "${report_json}")"
        else
          needs_benchmark="true"
        fi
      fi

      if [[ "${needs_benchmark}" == "false" ]]; then
        echo "Resuming analysis only: state=${state} repeat=${repeat_index}"
      fi
    fi

    if [[ "${needs_benchmark}" == "true" ]]; then
      if [[ "${state}" == "cold" ]]; then
        dataset_dir="${OUTPUT_DIR}/datasets/${CAMPAIGN_LABEL}-${state}-r${repeat_index}"
        generate_dataset "${dataset_dir}" "${dataset_seed}"
      else
        dataset_seed="${DATASET_SEED_BASE}:warm"
        prewarm_enabled="${PREWARM_WARM_DATASET}"
        if [[ "${PREWARM_WARM_DATASET}" == "true" ]]; then
          prewarm_seed="$((SEED + repeat_index + 100000))"
          prewarm_warm_dataset "${dataset_seed}" "${repeat_index}" "${prewarm_seed}"
        fi
      fi

      cleanup_upload_cache
      rm -rf "${run_output_dir}"
      mkdir -p "${run_output_dir}"
      : > "${run_log_path}"

      run_started_at="$(utc_now)"
      append_manifest_row \
        "${state}" \
        "${repeat_index}" \
        "${run_slug}" \
        "${dataset_seed}" \
        "${dataset_dir}" \
        "${run_output_dir}" \
        "${run_log_path}" \
        "" \
        "" \
        "" \
        "" \
        "" \
        "running" \
        "pending" \
        "${run_started_at}" \
        "" \
        "" \
        "${prewarm_enabled}" \
        "${benchmark_seed}" \
        "${prewarm_seed}" \
        "${OPERATIONS_ENDPOINT}" \
        "${CAMPAIGN_LABEL}" \
        "benchmark started"

      echo "Running benchmark: state=${state} repeat=${repeat_index} dataset=${dataset_dir}"
      if ./target/release/benchmark-cli \
        --api-key "${API_KEY}" \
        --base-url "${BASE_URL}" \
        --dataset-dir "${dataset_dir}" \
        --output-dir "${run_output_dir}" \
        --profiles "${PROFILES}" \
        --hashes "${HASHES}" \
        --buckets "${BUCKETS}" \
        --scenarios "${SCENARIOS}" \
        --warmup-runs "${WARMUP_RUNS}" \
        --measured-runs "${MEASURED_RUNS}" \
        --seed "${benchmark_seed}" \
        --inter-run-delay-ms "${INTER_RUN_DELAY_MS}" \
        --operations-endpoint "${OPERATIONS_ENDPOINT}" \
        --storage-state-label "${state}" \
        --campaign-label "${CAMPAIGN_LABEL}" \
        --repeat-index "${repeat_index}" 2>&1 | tee -a "${run_log_path}"; then
        benchmark_finished_at="$(utc_now)"
      else
        benchmark_finished_at="$(utc_now)"
        append_manifest_row \
          "${state}" \
          "${repeat_index}" \
          "${run_slug}" \
          "${dataset_seed}" \
          "${dataset_dir}" \
          "${run_output_dir}" \
          "${run_log_path}" \
          "" \
          "" \
          "" \
          "" \
          "" \
          "failed" \
          "skipped" \
          "${run_started_at}" \
          "${benchmark_finished_at}" \
          "" \
          "${prewarm_enabled}" \
          "${benchmark_seed}" \
          "${prewarm_seed}" \
          "${OPERATIONS_ENDPOINT}" \
          "${CAMPAIGN_LABEL}" \
          "benchmark-cli exited non-zero"
        cleanup_cold_dataset_if_needed "${state}" "${dataset_dir}"
        exit 3
      fi

      artifact_info="$(resolve_run_artifacts "${run_output_dir}")"
      IFS=$'\t' read -r report_json runs_csv summary_csv evidence_csv <<< "${artifact_info}"
      analysis_dir="$(analysis_dir_for_report "${report_json}")"

      append_manifest_row \
        "${state}" \
        "${repeat_index}" \
        "${run_slug}" \
        "${dataset_seed}" \
        "${dataset_dir}" \
        "${run_output_dir}" \
        "${run_log_path}" \
        "${report_json}" \
        "${runs_csv}" \
        "${summary_csv}" \
        "${evidence_csv}" \
        "${analysis_dir}" \
        "ok" \
        "pending" \
        "${run_started_at}" \
        "${benchmark_finished_at}" \
        "" \
        "${prewarm_enabled}" \
        "${benchmark_seed}" \
        "${prewarm_seed}" \
        "${OPERATIONS_ENDPOINT}" \
        "${CAMPAIGN_LABEL}" \
        "benchmark completed"
    fi

    analysis_dir="${analysis_dir:-$(analysis_dir_for_report "${report_json}")}"
    rm -rf "${analysis_dir}"
    append_manifest_row \
      "${state}" \
      "${repeat_index}" \
      "${run_slug}" \
      "${dataset_seed}" \
      "${dataset_dir}" \
      "${run_output_dir}" \
      "${run_log_path}" \
      "${report_json}" \
      "${runs_csv}" \
      "${summary_csv}" \
      "${evidence_csv}" \
      "${analysis_dir}" \
      "ok" \
      "running" \
      "${run_started_at}" \
      "${benchmark_finished_at}" \
      "" \
      "${prewarm_enabled}" \
      "${benchmark_seed}" \
      "${prewarm_seed}" \
      "${OPERATIONS_ENDPOINT}" \
      "${CAMPAIGN_LABEL}" \
      "analysis started"

    echo "Analyzing ${report_json}..."
    if run_analysis "${report_json}" 2>&1 | tee -a "${run_log_path}"; then
      analysis_finished_at="$(utc_now)"
      append_manifest_row \
        "${state}" \
        "${repeat_index}" \
        "${run_slug}" \
        "${dataset_seed}" \
        "${dataset_dir}" \
        "${run_output_dir}" \
        "${run_log_path}" \
        "${report_json}" \
        "${runs_csv}" \
        "${summary_csv}" \
        "${evidence_csv}" \
        "${analysis_dir}" \
        "ok" \
        "ok" \
        "${run_started_at}" \
        "${benchmark_finished_at}" \
        "${analysis_finished_at}" \
        "${prewarm_enabled}" \
        "${benchmark_seed}" \
        "${prewarm_seed}" \
        "${OPERATIONS_ENDPOINT}" \
        "${CAMPAIGN_LABEL}" \
        "analysis completed"
    else
      analysis_finished_at="$(utc_now)"
      append_manifest_row \
        "${state}" \
        "${repeat_index}" \
        "${run_slug}" \
        "${dataset_seed}" \
        "${dataset_dir}" \
        "${run_output_dir}" \
        "${run_log_path}" \
        "${report_json}" \
        "${runs_csv}" \
        "${summary_csv}" \
        "${evidence_csv}" \
        "${analysis_dir}" \
        "ok" \
        "failed" \
        "${run_started_at}" \
        "${benchmark_finished_at}" \
        "${analysis_finished_at}" \
        "${prewarm_enabled}" \
        "${benchmark_seed}" \
        "${prewarm_seed}" \
        "${OPERATIONS_ENDPOINT}" \
        "${CAMPAIGN_LABEL}" \
        "analysis failed"
      cleanup_cold_dataset_if_needed "${state}" "${dataset_dir}"
      exit 4
    fi

    cleanup_cold_dataset_if_needed "${state}" "${dataset_dir}"
  done
done

echo "[5/6] Campaign manifest..."
echo "- ${MANIFEST_PATH}"

echo "[6/6] Complete."
echo "- Output dir: ${OUTPUT_DIR}"
echo "- Manifest:   ${MANIFEST_PATH}"
echo "- Setup:      ${CAMPAIGN_SETUP_PATH}"
