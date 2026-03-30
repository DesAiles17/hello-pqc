# Security Setup (P0 Hardening)

## API authentication defaults

- `REQUIRE_AUTH` is now secure-by-default in `docker-compose.yml`.
- The gateway expects API keys from `/app/api-keys.json`.
- Host mapping now uses local untracked file: `api-keys.local.json`.

## Internal service authentication (P1)

- `api-gateway` now sends `X-Service-Token` to `hasher-service` and `manifest-builder-service`.
- Internal services reject non-health requests without a valid token.
- Set `INTERNAL_SERVICE_TOKEN` in your environment before `docker compose up`.
- Do not keep the default token value outside local development.

## Required environment variables (P0)

`docker-compose.yml` now fails fast if critical secrets are not explicitly set.

Set these before running services:

- `INTERNAL_SERVICE_TOKEN`
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`
- `MINIO_HASHER_ACCESS_KEY`
- `MINIO_HASHER_SECRET_KEY`
- `MINIO_VERIFIER_ACCESS_KEY`
- `MINIO_VERIFIER_SECRET_KEY`
- `POSTGRES_PASSWORD`
- `DATABASE_URL`

Example pattern:

```bash
export INTERNAL_SERVICE_TOKEN="$(openssl rand -hex 32)"
export MINIO_ROOT_USER="pqc-minio"
export MINIO_ROOT_PASSWORD="$(openssl rand -hex 24)"
export MINIO_HASHER_ACCESS_KEY="pqc-hasher"
export MINIO_HASHER_SECRET_KEY="$(openssl rand -hex 24)"
export MINIO_VERIFIER_ACCESS_KEY="pqc-verifier"
export MINIO_VERIFIER_SECRET_KEY="$(openssl rand -hex 24)"
export POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export DATABASE_URL="postgres://pqc:${POSTGRES_PASSWORD}@postgres:5432/pqc"
```

## Secure-mode transport controls

- Internal service URLs are HTTPS-only by default.
- MinIO endpoint is HTTPS-only by default.
- For local Docker development only, set:
	- `ALLOW_INSECURE_INTERNAL_HTTP=true`
	- `ALLOW_INSECURE_MINIO_HTTP=true`

Both toggles now default to `false` in compose and must be explicitly enabled for non-TLS local stacks.

Do not enable these in cloud/production deployments.

## Local TLS mode (gateway -> internal services -> MinIO)

The stack now supports true local TLS mode without disabling secure checks.

1. Generate local CA + service certificates:

```bash
./scripts/generate_tls_certs.sh
```

2. Keep secure flags disabled:

- `ALLOW_INSECURE_INTERNAL_HTTP=false`
- `ALLOW_INSECURE_MINIO_HTTP=false`

3. Start the stack:

```bash
docker compose up -d --build
```

4. Verify internal endpoints in container logs:

- `HASHER_SERVICE_URL=https://hasher-service-tls:3443`
- `MANIFEST_SERVICE_URL=https://manifest-builder-service-tls:3443`
- `MINIO_ENDPOINT=https://minio:9000`

The CA certificate is mounted at `/app/tls/ca.crt` and used by gateway/internal clients.

`ENVIRONMENT` now gates insecure internal HTTP behavior:

- `ALLOW_INSECURE_INTERNAL_HTTP=true` is honored only when `ENVIRONMENT` is `local`, `development`, or `test`.
- In other environments, insecure internal HTTP is rejected.

## Verification policy controls

- `verify_object=false` requests are rejected by policy.
- `MAX_MANIFEST_AGE_HOURS` controls manifest freshness (default `24`).
- `MAX_VERIFY_OBJECT_SIZE` caps storage-object verification size (default `104857600` bytes).
- `MAX_CONCURRENT_VERIFY` caps in-flight verify requests at the gateway (default `4`).
- Revoked manifests (non-null `revoked_at`) fail verification.

## P2 hardening controls

- API gateway rate limiting is now keyed per authenticated API key identity.
- Authentication failures (missing/invalid API keys) are now separately rate-limited in middleware.
- Internal service token comparison now uses constant-time equality checks.
- Hasher now spools uploads to disk before S3 upload to avoid full-file memory buffering.
- Upstream service error details are logged server-side but redacted from client-facing errors.
- Web UI shell includes a baseline CSP to reduce XSS-driven API key theft risk.

Optional P2 environment variables:

- `RATE_LIMIT_AUTH_FAIL_PER_MIN` (default `60`, set `0` to disable)
- `HASH_SPOOL_DIR` (default `/tmp/pqc-hash-spool`)
- `TRUST_PROXY_HEADERS` (default `false`; keep `false` unless behind a trusted reverse proxy)
- `MAX_JSON_BODY_SIZE` (default `65536` bytes; used for `/process` and `/verify`)
- `MAX_UPLOAD_STORAGE_PER_KEY` (default `536870912` bytes)
- `UPLOAD_RETENTION_HOURS` (default `24`; stale uploads are pruned during new uploads)

## Infrastructure exposure hardening

- PostgreSQL and MinIO host port bindings are now loopback-only in compose:
	- `127.0.0.1:5432:5432`
	- `127.0.0.1:9000:9000`
	- `127.0.0.1:9001:9001`

This reduces accidental external exposure in cloud-like host deployments.

## API key files

- `api-keys.json` is now a template only (non-secret placeholders).
- `api-keys.local.json` contains real runtime keys and is git-ignored.

## Rotation guidance

Because live keys were previously committed, treat them as compromised:

1. Stop using old keys immediately.
2. Use newly generated keys in `api-keys.local.json`.
3. Restart services so the gateway loads the new keys.
4. Update any scripts/UI sessions to the new key values.
