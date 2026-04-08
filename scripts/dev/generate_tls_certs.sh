#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TLS_DIR="${ROOT_DIR}/tls"
MINIO_DIR="${TLS_DIR}/minio"

mkdir -p "${TLS_DIR}" "${MINIO_DIR}"

CA_KEY="${TLS_DIR}/ca.key"
CA_CRT="${TLS_DIR}/ca.crt"

if [[ ! -f "${CA_KEY}" || ! -f "${CA_CRT}" ]]; then
  echo "Generating local TLS CA..."
  openssl genrsa -out "${CA_KEY}" 4096
  openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
    -subj "/CN=pqc-local-ca" -out "${CA_CRT}"
fi

gen_cert() {
  local name="$1"
  shift
  local sans=("$@")

  local key="${TLS_DIR}/${name}.key"
  local csr="${TLS_DIR}/${name}.csr"
  local crt="${TLS_DIR}/${name}.crt"
  local ext="${TLS_DIR}/${name}.ext"

  cat > "${ext}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
EOF

  local i=1
  for san in "${sans[@]}"; do
    if [[ "${san}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "IP.${i} = ${san}" >> "${ext}"
    else
      echo "DNS.${i} = ${san}" >> "${ext}"
    fi
    i=$((i + 1))
  done

  openssl genrsa -out "${key}" 2048
  openssl req -new -key "${key}" -subj "/CN=${name}" -out "${csr}"
  openssl x509 -req -in "${csr}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${crt}" -days 825 -sha256 -extfile "${ext}"

  rm -f "${csr}" "${ext}"
}

gen_cert "hasher-service-tls" "hasher-service-tls"
gen_cert "manifest-builder-service-tls" "manifest-builder-service-tls"
gen_cert "minio" "minio" "localhost" "127.0.0.1"

cp "${TLS_DIR}/minio.crt" "${MINIO_DIR}/public.crt"
cp "${TLS_DIR}/minio.key" "${MINIO_DIR}/private.key"

# Bundle for clients that expect a PEM trust bundle file.
cat "${TLS_DIR}/ca.crt" "${TLS_DIR}/minio.crt" > "${TLS_DIR}/ca-bundle.crt"

chmod 600 "${TLS_DIR}"/*.key "${MINIO_DIR}/private.key"
chmod 644 "${TLS_DIR}"/*.crt "${MINIO_DIR}/public.crt" "${TLS_DIR}/ca-bundle.crt"

echo "TLS artifacts generated in ${TLS_DIR}"
echo "- CA cert: ${TLS_DIR}/ca.crt"
echo "- CA bundle: ${TLS_DIR}/ca-bundle.crt"
echo "- Internal service certs: hasher-service-tls / manifest-builder-service-tls"
echo "- MinIO certs copied to ${MINIO_DIR}"
