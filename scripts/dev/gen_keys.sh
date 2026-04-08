#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

KEYS_DIR="keys"
ALGORITHMS="all"

usage() {
  cat <<'EOF'
Usage: scripts/dev/gen_keys.sh [options]

Generate project key material through a single entrypoint.

Options:
  --algorithms <csv>  Comma-separated algorithms to generate.
                      Supported: rsa_pss, eddsa, ecdsa, hmac_sha256,
                      ml_dsa, ml_dsa, slh_dsa, fn_dsa, all
                      Default: all
  --keys-dir <path>   Output directory for generated key files (default: keys)
  --list              Print supported algorithms and exit
  -h, --help          Show this help

Examples:
  ./gen_keys.sh
  ./gen_keys.sh --algorithms rsa_pss,ml_dsa
  ./gen_keys.sh --algorithms ml_dsa,slh_dsa --keys-dir ./tmp-keys
EOF
}

list_algorithms() {
  cat <<'EOF'
rsa_pss
eddsa
ecdsa
hmac_sha256
ml_dsa
ml_dsa
slh_dsa
fn_dsa
all
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --algorithms)
      ALGORITHMS="$2"
      shift 2
      ;;
    --keys-dir)
      KEYS_DIR="$2"
      shift 2
      ;;
    --list)
      list_algorithms
      exit 0
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

normalize_algorithm() {
  local raw
  raw="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "${raw}" in
    rsa|rsa_pss|rsa-pss|classical)
      printf 'rsa_pss'
      ;;
    eddsa|ed25519)
      printf 'eddsa'
      ;;
    ecdsa|ecdsa_p256|p256)
      printf 'ecdsa'
      ;;
    hmac|hmac_sha256|hmac-sha256)
      printf 'hmac_sha256'
      ;;
    ml_dsa|ml_dsa|crystals_ml_dsa|pqc)
      printf 'ml_dsa'
      ;;
    ml_dsa|ml_dsa|mldsa)
      printf 'ml_dsa'
      ;;
    slh_dsa|slh-dsa|slhdsa)
      printf 'slh_dsa'
      ;;
    fn_dsa|fn_dsa512)
      printf 'fn_dsa'
      ;;
    hybrid|all)
      printf 'all'
      ;;
    *)
      return 1
      ;;
  esac
}

append_unique() {
  local item="$1"
  shift
  local existing
  for existing in "$@"; do
    if [[ "${existing}" == "${item}" ]]; then
      return 0
    fi
  done
  RESOLVED_ALGORITHMS+=("${item}")
}

declare -a RESOLVED_ALGORITHMS=()
IFS=',' read -r -a REQUESTED_ALGORITHMS <<< "${ALGORITHMS}"
for raw in "${REQUESTED_ALGORITHMS[@]}"; do
  trimmed="${raw//[[:space:]]/}"
  [[ -z "${trimmed}" ]] && continue
  normalized="$(normalize_algorithm "${trimmed}")" || {
    echo "Unsupported algorithm: ${raw}" >&2
    exit 2
  }
  if [[ "${normalized}" == "all" ]]; then
    RESOLVED_ALGORITHMS=(
      "rsa_pss"
      "eddsa"
      "ecdsa"
      "hmac_sha256"
      "ml_dsa"
      "ml_dsa"
      "slh_dsa"
      "fn_dsa"
    )
    break
  fi
  append_unique "${normalized}" "${RESOLVED_ALGORITHMS[@]}"
done

if [[ ${#RESOLVED_ALGORITHMS[@]} -eq 0 ]]; then
  RESOLVED_ALGORITHMS=(
    "rsa_pss"
    "eddsa"
    "ecdsa"
    "hmac_sha256"
    "ml_dsa"
    "ml_dsa"
    "slh_dsa"
    "fn_dsa"
  )
fi

contains_algorithm() {
  local wanted="$1"
  local item
  for item in "${RESOLVED_ALGORITHMS[@]}"; do
    if [[ "${item}" == "${wanted}" ]]; then
      return 0
    fi
  done
  return 1
}

mkdir -p "${KEYS_DIR}"

echo "Generating cryptographic keys into ${KEYS_DIR}..."
echo "- algorithms: ${RESOLVED_ALGORITHMS[*]}"
echo ""

declare -a RUST_ALGORITHMS=()
declare -a PRIVATE_FILES=()
declare -a PUBLIC_FILES=()

if contains_algorithm "rsa_pss"; then
  echo "Generating RSA-3072 keypair..."
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${KEYS_DIR}/rsa_private.pem"
  openssl rsa -in "${KEYS_DIR}/rsa_private.pem" -pubout -out "${KEYS_DIR}/rsa_public.pem"
  PRIVATE_FILES+=("${KEYS_DIR}/rsa_private.pem")
  PUBLIC_FILES+=("${KEYS_DIR}/rsa_public.pem")
  echo "  rsa_private.pem / rsa_public.pem"
  echo ""
fi

if contains_algorithm "eddsa"; then
  echo "Generating Ed25519 (EdDSA) keypair..."
  openssl genpkey -algorithm ed25519 -out "${KEYS_DIR}/eddsa_private.pem"
  openssl pkey -in "${KEYS_DIR}/eddsa_private.pem" -pubout -out "${KEYS_DIR}/eddsa_public.pem"
  openssl pkey -in "${KEYS_DIR}/eddsa_private.pem" -outform DER | tail -c 32 > "${KEYS_DIR}/eddsa_sk.bin"
  openssl pkey -in "${KEYS_DIR}/eddsa_public.pem" -pubin -outform DER | tail -c 32 > "${KEYS_DIR}/eddsa_pk.bin"
  PRIVATE_FILES+=("${KEYS_DIR}/eddsa_private.pem" "${KEYS_DIR}/eddsa_sk.bin")
  PUBLIC_FILES+=("${KEYS_DIR}/eddsa_public.pem" "${KEYS_DIR}/eddsa_pk.bin")
  echo "  eddsa_sk.bin (32B) / eddsa_pk.bin (32B)"
  echo ""
fi

if contains_algorithm "hmac_sha256"; then
  echo "Generating HMAC-SHA256 secret (32 bytes)..."
  openssl rand -out "${KEYS_DIR}/hmac_secret.bin" 32
  PRIVATE_FILES+=("${KEYS_DIR}/hmac_secret.bin")
  echo "  hmac_secret.bin (32B)"
  echo ""
fi

for rust_algorithm in ecdsa ml_dsa ml_dsa slh_dsa fn_dsa; do
  if contains_algorithm "${rust_algorithm}"; then
    RUST_ALGORITHMS+=("${rust_algorithm}")
  fi
done

if [[ ${#RUST_ALGORITHMS[@]} -gt 0 ]]; then
  rust_algorithms_csv="$(IFS=,; printf '%s' "${RUST_ALGORITHMS[*]}")"
  cargo run --bin gen-keys -- --keys-dir "${KEYS_DIR}" --algorithms "${rust_algorithms_csv}"

  if contains_algorithm "ecdsa"; then
    PRIVATE_FILES+=("${KEYS_DIR}/ecdsa_sk.bin")
    PUBLIC_FILES+=("${KEYS_DIR}/ecdsa_pk.bin")
  fi
  if contains_algorithm "ecdsa"; then
    PRIVATE_FILES+=("${KEYS_DIR}/ecdsa_sk.bin")
    PUBLIC_FILES+=("${KEYS_DIR}/ecdsa_pk.bin")
  fi
  if contains_algorithm "ml_dsa"; then
    PRIVATE_FILES+=("${KEYS_DIR}/ml_dsa_sk.bin")
    PUBLIC_FILES+=("${KEYS_DIR}/ml_dsa_pk.bin")
  fi
  if contains_algorithm "ml_dsa"; then
    PRIVATE_FILES+=("${KEYS_DIR}/ml_dsa_sk.bin")
    PUBLIC_FILES+=("${KEYS_DIR}/ml_dsa_pk.bin")
  fi
  if contains_algorithm "slh_dsa"; then
    PRIVATE_FILES+=("${KEYS_DIR}/slh_dsa_sk.bin")
    PUBLIC_FILES+=("${KEYS_DIR}/slh_dsa_pk.bin")
  fi
  if contains_algorithm "fn_dsa"; then
    PRIVATE_FILES+=("${KEYS_DIR}/fn_dsa_sk.bin")
    PUBLIC_FILES+=("${KEYS_DIR}/fn_dsa_pk.bin")
  fi
  echo ""
fi

if [[ ${#PRIVATE_FILES[@]} -gt 0 ]]; then
  chmod 600 "${PRIVATE_FILES[@]}"
fi

if [[ ${#PUBLIC_FILES[@]} -gt 0 ]]; then
  chmod 644 "${PUBLIC_FILES[@]}"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Requested keys generated successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "SECURITY WARNING:"
echo "  - Keep all *_sk.bin / *_private.pem / hmac_secret.bin files SECRET"
echo "  - Never commit ${KEYS_DIR}/ to version control"
echo "  - Store in a secure key management system (HSM/Vault) for production"
echo "  - Private key permissions set to 600 (owner read/write only)"
echo ""
