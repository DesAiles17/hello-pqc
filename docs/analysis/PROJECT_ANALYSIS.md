# Current Project Analysis and Usage Guide

This document reflects the repository state inspected on 2026-03-29.

## 1. What This Project Is

This repository is a research prototype for comparing three signing modes over the same file-processing workflow:

- Classical signing: RSA-PSS
- Post-quantum signing: CRYSTALS-ml_dsa Round 3 via `pqcrypto-ml_dsa::ml_dsa`
- Hybrid signing: RSA-PSS + CRYSTALS-ml_dsa Round 3 on the same canonical manifest

Terminology note:

- the current Rust implementation is based on the pre-FIPS CRYSTALS-ml_dsa
  Round 3 variant, not FIPS 204 ML-DSA
- the helper script currently generates RSA-3072 keys, although the runtime
  code will use whichever RSA key material is supplied
- hybrid signing is independent dual-signature generation, but it is currently
  sequential in code rather than parallel

The project is not a generic file-sharing app and it is not positioned as production-ready enterprise infrastructure. Its main purpose is to:

- upload files through a gateway,
- hash them with a selected algorithm,
- store immutable copies in object storage,
- build a canonical signed manifest,
- verify both the signature set and the stored object later,
- run repeatable benchmark campaigns for dissertation evidence.

The most important architectural rule is that cryptographic operations happen only on the backend. The web UI and benchmark CLI are orchestration layers; they never compute signatures locally.

## 2. What The System Does Today

At a high level, the current implementation works like this:

1. A client authenticates to the API gateway with an API key.
2. The client uploads a file to the gateway.
3. The gateway stores the upload under a per-key directory.
4. The gateway calls the hasher service, which validates the path, hashes the file, and stores an immutable object in MinIO using a content-addressed key.
5. The gateway calls the manifest builder service, which creates a canonical manifest core, signs it, and stores the signed manifest in PostgreSQL.
6. The client receives the signed manifest, including `request_id`, hash, storage metadata, and signatures.
7. For verification, the client re-uploads the file, submits the `request_id`, and the gateway:
   - fetches the stored manifest,
   - re-hashes the uploaded file using the same hash algorithm as the original manifest,
   - forwards the derived values to the manifest builder service,
   - receives a detailed verification result with per-check outcomes.

This gives the project two main user-facing modes:

- interactive sign/verify through the web UI,
- repeatable benchmark execution through `benchmark-cli`.

## 3. Architecture Summary

### API Gateway

Implemented in [`src/bin/api_gateway.rs`](/home/denys/hello-pqc/src/bin/api_gateway.rs).

Responsibilities:

- API-key authentication and role handling
- rate limiting
- file upload handling
- upload ownership enforcement
- orchestration of hash -> manifest build -> verify flow
- request size and concurrency controls
- CORS policy

External endpoints currently exposed:

| Endpoint | Method | Purpose | Auth |
| --- | --- | --- | --- |
| `/` | `GET` | basic health string | API key required |
| `/health` | `GET` | detailed gateway health/version payload | API key required |
| `/config` | `GET` | current default profile/hash/domain settings | API key required |
| `/upload` | `POST` | upload a file | any authenticated role |
| `/process` | `POST` | hash + sign a file | `operator` or `admin` |
| `/verify` | `POST` | verify by `request_id` and uploaded file | any authenticated role |

### Hasher Service

Implemented in [`src/bin/hasher_service.rs`](/home/denys/hello-pqc/src/bin/hasher_service.rs).

Responsibilities:

- secure file path validation
- SHA-256 or Keccak-256 hashing
- content-addressed storage in MinIO
- spool-to-disk upload flow for large files
- immutable object ID generation

Internal endpoint:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/hash` | `POST` | hash a validated file path and store the immutable object |

### Manifest Builder Service

Implemented in [`src/bin/manifest_builder_service.rs`](/home/denys/hello-pqc/src/bin/manifest_builder_service.rs).

Responsibilities:

- canonical manifest construction
- RSA-PSS signing
- CRYSTALS-ml_dsa Round 3 signing
- hybrid manifest signing
- manifest persistence in PostgreSQL
- signature verification
- object integrity verification against MinIO
- owner-scoped manifest lookup

Internal endpoints:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/manifest` | `POST` | build and sign a manifest |
| `/verify` | `POST` | verify signatures and stored object integrity |
| `/fetch` | `POST` | fetch a stored manifest by `request_id` and owner |

### Storage

PostgreSQL:

- stores signed manifests in `signed_manifests`
- stores indexed lookup fields such as `request_id`, `owner_key_fingerprint`, `hash`, `immutable_object_id`, `algorithm`, and `created_at`
- includes a `revoked_at` column checked during verification
- includes a `manifest_audit_log` table scaffold; structured audit events are
  now emitted by the gateway for upload/sign/verify, but DB writes to that table
  are still not implemented

MinIO:

- stores immutable object copies in bucket `pqc-objects` by default
- object key pattern:
  - `objects/SHA-256/<shard>/<hash>`
  - `objects/KECCAK-256/<shard>/<hash>`
- object ID pattern:
  - `sha256:<hash>`
  - `keccak256:<hash>`

### Web UI

Implemented under [`web-ui/`](/home/denys/hello-pqc/web-ui).

Current capabilities:

- API key login screen
- drag-and-drop or click-to-select file upload
- signature profile selection
- hash algorithm selection
- manifest inspection and JSON download
- verification workflow using uploaded file + request ID
- display of detailed verification checks and manifest metadata

### Benchmark CLI

Implemented in [`src/bin/benchmark_cli.rs`](/home/denys/hello-pqc/src/bin/benchmark_cli.rs).

Current capabilities:

- dataset-driven benchmark execution against the gateway
- warm-up and measured phases
- blocked randomized condition ordering
- bucket-local file rotation to reduce repeated-file bias
- scenario-aware execution:
  - `workflow`
  - `sign_only`
  - `verify_manifest`
  - `verify_stored`
  - `verify_uploaded`
  - `verify_full`
- explicit storage-state labeling for cold vs warm campaigns
- repeat labeling for independent campaign repeats
- JSON and CSV export
- server-attributed timing capture through `GET /operations?request_id=...`
- richer per-run server metrics for object-store, DB, canonicalization, and verify substeps
- normalized artifact-overhead metrics (`manifest_overhead_pct`, `signature_overhead_pct`, `storage_amplification`)
- effective throughput metrics for workflow and server-attributed stages
- summary metrics:
  - median
  - IQR
  - p95
  - bootstrap 95% CI for medians
- ratio metrics:
  - `S_pqc`
  - `S_hybrid`
  - `S_pqc_server`
  - `S_hybrid_server`

## 4. Post-Quantum Cryptography Specifics

### Signature algorithms

The code currently uses:

- RSA-PSS for classical signing
- CRYSTALS-ml_dsa Round 3 for post-quantum signing via `pqcrypto-ml_dsa`

Important naming note:

- the crate currently used by this repository exposes the Round 3
  `ml_dsa` implementation
- this should not be described as direct FIPS 204 ML-DSA interoperability
  without qualification

Relevant code:

- RSA signing and verification in [`src/bin/manifest_builder_service.rs`](/home/denys/hello-pqc/src/bin/manifest_builder_service.rs)
- project key generation in [`src/bin/gen_keys.rs`](/home/denys/hello-pqc/src/bin/gen_keys.rs)

### Manifest design

The signed object is not the raw file. The signed object is a canonical manifest core containing:

- `schema_version`
- `domain_sep`
- `signature_profile`
- `request_id`
- `immutable_object_id`
- `hash`
- `algorithm`
- `size`
- `storage_bucket`
- `storage_key`

This core is serialized with canonical CBOR before signing. The signing bytes are:

- `domain_sep || 0x00 || canonical_cbor(core)`

This matters because it provides:

- deterministic signing input,
- domain separation,
- stable replay of the exact signed content,
- a clean distinction between signed core fields and unsigned envelope metadata.

### Hash algorithms

The system currently supports:

- `SHA256` / `SHA-256`
- `KECCAK` / `KECCAK256` / `KECCAK-256`

The gateway normalizes user-friendly profile names and hash names before forwarding to internal services.

### Signature profiles

The manifest builder supports three profiles:

- `classical_only`
- `pqc_only`
- `hybrid`

The gateway also accepts user-facing aliases such as:

- `classical`
- `pqc`
- `hybrid`

### Hybrid behavior

Hybrid mode currently means:

- the same canonical manifest bytes are signed by RSA-PSS,
- the same canonical manifest bytes are signed by CRYSTALS-ml_dsa Round 3,
- both signatures are stored in the same signed manifest,
- verification requires both signatures to pass.

Important current-state note:

- the architecture docs historically described hybrid as parallel,
- the current implementation signs RSA first and ml_dsa second inside the same request handler,
- so the signatures are independent, but the code is currently sequential rather than parallel.

### Important discrepancy: RSA key size

There is a historical mismatch in the repo documentation:

- some older architecture notes refer to RSA-4096,
- the shipped key-generation script [`scripts/dev/gen_keys.sh`](/home/denys/hello-pqc/scripts/dev/gen_keys.sh) currently generates RSA-3072.

The runtime code does not hardcode a key size; it uses whatever PEM key you provide. In practice, the currently provided helper script produces RSA-3072 unless you change it.

## 5. Current Feature Set

### Backend features implemented

- API key authentication with `X-API-Key` or `Authorization: Bearer <key>`
- role model:
  - `admin`
  - `operator`
  - `readonly`
- secure upload handling with filename sanitization
- per-API-key upload isolation using a key fingerprint directory
- SHA-256 and Keccak-256 hashing
- immutable object storage in MinIO
- canonical manifest generation
- RSA-PSS signing
- CRYSTALS-ml_dsa Round 3 signing
- hybrid signing
- verification against stored object and uploaded file-derived attributes
- manifest freshness checking
- revoked manifest rejection
- rate limiting and verification concurrency limiting
- explicit CORS policy
- JSON body size limiting
- upload quota and retention pruning

### UI features implemented

- API key validation against `/health`
- session-scoped API key storage
- session expiry for API key storage
- sign workflow
- verify workflow
- detailed verification check display
- manifest JSON download
- manifest field copy-to-clipboard actions

### Benchmark and analysis features implemented

- deterministic benchmark dataset generation
- reproducible benchmark campaign runner
- output files in JSON and CSV
- automated evidence-first analysis helper with structured tables and dissertation figures
- sample benchmark outputs already present under [`output/benchmarks/`](/home/denys/hello-pqc/output/benchmarks)

### Helper scripts implemented

- [`scripts/dev/gen_keys.sh`](/home/denys/hello-pqc/scripts/dev/gen_keys.sh): generate RSA + ml_dsa keys
- [`scripts/dev/generate_tls_certs.sh`](/home/denys/hello-pqc/scripts/dev/generate_tls_certs.sh): create local CA and service certs
- [`scripts/generate_benchmark_dataset.py`](/home/denys/hello-pqc/scripts/generate_benchmark_dataset.py): generate deterministic datasets
- [`scripts/run_benchmark_campaign.sh`](/home/denys/hello-pqc/scripts/run_benchmark_campaign.sh): run benchmark + analysis
- [`scripts/analyze_benchmark_report.py`](/home/denys/hello-pqc/scripts/analyze_benchmark_report.py): build evidence-first report tables, diagnostics, and figures
- [`scripts/dev/reset-db.sh`](/home/denys/hello-pqc/scripts/dev/reset-db.sh): recreate the Postgres volume

### Notable things that are present but not fully wired

- `manifest_audit_log` table exists, but the services do not currently write audit records into it.
- `src/audit.rs` is now used for structured gateway audit events, but audit persistence is still partial.
- `revoked_at` is enforced during verification, but there is no public/admin revoke endpoint in the current API.
- benchmark quality still depends on campaign discipline: state isolation, repeat count, and rate-limit/quota tuning are external to the CLI itself.
- campaign validity still depends on report quality gates and repeat stability; figures and tables should be interpreted only when those gates pass.

## 6. Security Model And Attack Resistance

### 6.1 Authentication and authorization

Implemented controls:

- API gateway requires configured API keys when `REQUIRE_AUTH=true` and refuses startup if auth is required but no keys are configured.
- Internal services require `X-Service-Token` on non-health routes.
- Internal service token comparison uses constant-time equality.
- Gateway stores a SHA-256 fingerprint of the caller API key identity and passes that owner fingerprint to the manifest service.
- Verification and manifest fetch lookups are scoped by both `request_id` and `owner_key_fingerprint`, not `request_id` alone.
- Signing requires `operator` or `admin`.
- Verification is allowed for authenticated users, including `readonly`.

Mitigated attack classes:

- missing authorization
- insecure direct object reference / cross-tenant lookup by `request_id`
- internal service bypass from unauthenticated callers
- simple timing leaks on service-token comparison

### 6.2 Upload ownership and IDOR protection

Uploaded files are placed under:

- `/data/uploads/<api-key-fingerprint>/<uuid>-<sanitized-filename>`

Before `/process` or `/verify` can use a file path, the gateway canonicalizes the requested path and checks that it lives under the authenticated key's directory.

This prevents:

- one API key referencing another user's uploaded file,
- arbitrary path injection into downstream crypto services,
- simple path-based authorization bypass.

### 6.3 Path traversal, symlink, and TOCTOU defenses

Implemented controls in the hasher:

- reject empty paths
- reject null bytes
- reject paths outside configured allowed roots
- reject sensitive system prefixes such as `/etc`, `/root`, `/proc`, `/dev`, `/usr/bin`
- resolve paths without following symlinks by default
- reject symlink final targets when symlinks are disabled
- detect symlink components below the allowed root
- securely open files with `O_NOFOLLOW` on Unix
- read metadata after opening the file
- fail if the file is no longer a regular file after open

This specifically addresses:

- path traversal
- symlink swapping
- device-file abuse
- a class of TOCTOU attacks where a path is changed between validation and later use

Important nuance:

- no filesystem check can make TOCTOU risk literally zero,
- but this implementation reduces exposure substantially by combining canonical path checks, no-follow open, symlink-component rejection, and post-open metadata validation.

### 6.4 DoS and abuse controls

Implemented controls:

- per-key rate limiting for sign, verify, hash/upload, and global request volume
- separate rate limiter for repeated authentication failures
- auth-failure limiter keyed by IP plus user-agent fingerprint
- `MAX_CONCURRENT_VERIFY` semaphore in the gateway
- `MAX_JSON_BODY_SIZE` for `/process` and `/verify`
- `MAX_UPLOAD_SIZE` for multipart upload body size
- `MAX_UPLOAD_STORAGE_PER_KEY` quota
- stale upload pruning via `UPLOAD_RETENTION_HOURS`
- `MAX_VERIFY_OBJECT_SIZE` cap for storage-object verification
- spool-to-disk hashing before S3 upload to avoid full-file in-memory buffering

Mitigated attack classes:

- request floods
- auth spraying
- oversized-body abuse
- storage exhaustion by repeated uploads
- memory pressure from large hash/upload operations

### 6.5 Integrity and tamper detection

Implemented controls:

- immutable object storage keyed by content hash
- stored object verification by re-reading the MinIO object and re-hashing it
- uploaded file verification by hashing the uploaded file with the original manifest algorithm
- comparison of uploaded file-derived values against:
  - manifest hash
  - manifest size
  - hash algorithm
  - immutable object ID
  - storage bucket
  - storage key
- signature re-verification against uploaded-content-derived manifest bytes
- manifest profile-conformance checks
- canonical manifest hash included in verification metadata

Mitigated attack classes:

- tampering with stored objects
- verifying the wrong local file against a valid request ID
- manifest/signature mismatch
- storage metadata substitution
- partial downgrade or profile-confusion attacks

### 6.6 Freshness and revocation controls

Implemented controls:

- manifest timestamp cannot be implausibly far in the future
- manifest age must be within `MAX_MANIFEST_AGE_HOURS` (default 24)
- `verify_object=false` is rejected by policy
- manifests with non-null `revoked_at` fail verification

Mitigated attack classes:

- stale manifest replay
- skipping object verification to get a weaker check
- use of revoked manifests

### 6.7 Secret handling and key protection

Implemented controls:

- compose fails fast if critical secrets are not set
- runtime API keys are expected in `api-keys.local.json`, which is git-ignored
- `api-keys.json` in repo is template-only
- private key file permissions are enforced on Unix before signing
- Docker services run as non-root user `1000:1000`
- Docker services drop Linux capabilities and enable `no-new-privileges`
- MinIO service accounts are separated:
  - hasher: read-write
  - verifier/manifest builder: read-only

Mitigated attack classes:

- secret sprawl in version control
- accidental key overexposure on disk
- unnecessary privilege inside containers
- broader-than-needed object storage access

### 6.8 Transport and browser-side protections

Implemented controls:

- internal service URLs must be HTTPS unless explicitly downgraded for local/dev/test
- MinIO endpoint must be HTTPS unless explicitly downgraded for local/dev/test
- local TLS helper script generates a CA and service certificates
- internal traffic is normally routed through nginx TLS wrappers on port `3443`
- PostgreSQL and MinIO host ports are bound to loopback only in compose
- gateway CORS is explicit, not wildcard
- web UI has a baseline CSP in [`web-ui/index.html`](/home/denys/hello-pqc/web-ui/index.html)
- web UI stores API key in `sessionStorage`, not `localStorage`
- web UI expires stored API keys after inactivity
- web UI clears stored API key on `401`/`403`

Mitigated attack classes:

- internal MITM in non-local deployments
- broad browser-origin access
- XSS-driven long-lived API-key persistence
- accidental external exposure of Postgres and MinIO

Important nuance:

- the local compose stack exposes the gateway itself on `http://localhost:3000`,
- so external client-to-gateway TLS termination is not part of the local compose setup,
- internal service-to-service and MinIO traffic are the parts that are TLS-hardened by default in this repo.

### 6.9 Error-handling safety

Implemented controls:

- upstream internal-service errors are logged server-side but redacted to generic client messages
- UI presents normalized safe error messages by status code
- automatic retry in the UI is explicitly disabled for crypto-related routes:
  - `/upload`
  - `/process`
  - `/verify`

This reduces the risk of:

- leaking internal details to clients
- duplicate cryptographic operations caused by automatic retries

## 7. Current Limitations And Important Gaps

These are important if you want the document to reflect the actual project state rather than the intended end-state.

1. The optional `/operations` endpoint is implemented, but reports only contain full server-side attribution when benchmark runs are executed against a stack that persists those metrics and the CLI is pointed at that endpoint.
2. Some benchmark conditions still fail the generated evidence-quality gates, so conclusions need to stay condition-specific rather than universal.
3. Hybrid signing is currently sequential in code, not parallel.
4. Revocation is checked during verification, but there is no revoke management API.
5. Audit events are now logged from gateway request handlers, but the database-backed `manifest_audit_log` table is still not populated by application code.
6. Older repository messaging referred to RSA-4096, but the bundled key-generation helper currently creates RSA-3072.
7. The root binary in [`src/main.rs`](/home/denys/hello-pqc/src/main.rs) states that the old TUI has been removed; the active interfaces are the web UI and CLI tooling.

## 8. How To Run The Project

### 8.1 Generate keys

```bash
./scripts/dev/gen_keys.sh
```

This creates:

- `keys/rsa_private.pem`
- `keys/rsa_public.pem`
- `keys/ml_dsa_sk.bin`
- `keys/ml_dsa_pk.bin`

### 8.2 Generate local TLS certificates

```bash
./scripts/dev/generate_tls_certs.sh
```

This creates:

- a local CA,
- nginx TLS certs for internal service wrappers,
- MinIO certs,
- a CA bundle used by internal clients.

### 8.3 Create local API keys

Create `api-keys.local.json` in the repository root:

```json
{
  "replace-with-admin-key": {
    "role": "admin",
    "description": "Admin key"
  },
  "replace-with-operator-key": {
    "role": "operator",
    "description": "Operator key"
  },
  "replace-with-readonly-key": {
    "role": "readonly",
    "description": "Read only key"
  }
}
```

Generate random values, for example:

```bash
openssl rand -hex 32
```

Do not use `api-keys.json` directly for live secrets; it is a template file.

### 8.4 Export required environment variables

Minimum secure local example:

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
export ENVIRONMENT="local"
export ALLOW_INSECURE_INTERNAL_HTTP="false"
export ALLOW_INSECURE_MINIO_HTTP="false"
```

### 8.5 Start the backend stack

```bash
docker compose up -d --build
```

Default local ports:

- gateway: `localhost:3000`
- postgres: `127.0.0.1:5432`
- MinIO API: `127.0.0.1:9000`
- MinIO console: `127.0.0.1:9001`

### 8.6 Start the web UI

```bash
cd web-ui
npm install
npm run dev
```

The Vite dev server runs on `http://localhost:5173` and proxies `/api` to `http://localhost:3000`.

## 9. How To Use The Current Features

### 9.1 Gateway endpoints

All gateway requests require an API key header.

Get config defaults:

```bash
curl -s \
  -H "X-API-Key: <your-key>" \
  http://localhost:3000/config
```

Health check:

```bash
curl -s \
  -H "X-API-Key: <your-key>" \
  http://localhost:3000/health
```

### 9.2 Sign a file through the API

Upload:

```bash
curl -s \
  -H "X-API-Key: <operator-or-admin-key>" \
  -F "file=@./sample.bin" \
  http://localhost:3000/upload
```

Example response fields:

- `file_path`
- `original_filename`
- `size`
- `uploaded_at`

Process:

```bash
curl -s \
  -H "X-API-Key: <operator-or-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/data/uploads/<fingerprint>/<uuid>-sample.bin",
    "signature_profile": "hybrid",
    "hash_algorithm": "SHA256"
  }' \
  http://localhost:3000/process
```

The response contains the signed manifest. Save the `request_id` from:

- `manifest.core.request_id`

### 9.3 Verify a file through the API

Verification requires:

- the original `request_id`,
- an uploaded file path owned by the same API key identity.

Upload the verification copy:

```bash
curl -s \
  -H "X-API-Key: <readonly-operator-or-admin-key>" \
  -F "file=@./sample.bin" \
  http://localhost:3000/upload
```

Verify:

```bash
curl -s \
  -H "X-API-Key: <readonly-operator-or-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "<request-id-from-signing>",
    "verify_object": true,
    "file_path": "/data/uploads/<fingerprint>/<uuid>-sample.bin"
  }' \
  http://localhost:3000/verify
```

Important behavior:

- the gateway ignores client attempts to weaken verification,
- it forces `verify_object=true`,
- it fetches the stored manifest first to learn the original hash algorithm,
- then it hashes the uploaded verification file with that same algorithm before forwarding to the manifest service.

### 9.4 Use the web UI

Typical flow:

1. Open `http://localhost:5173`.
2. Paste a valid API key.
3. Choose `Sign File` or `Verify Signature`.
4. For signing:
   - upload a file,
   - choose `Classical`, `Post-Quantum`, or `Hybrid`,
   - choose `SHA-256` or `Keccak-256`,
   - sign and inspect/download the returned manifest.
5. For verification:
   - upload the verification file,
   - paste the previously issued `request_id`,
   - review pass/fail state, detailed checks, and manifest metadata.

### 9.5 Run a benchmark campaign

Generate a dataset:

```bash
python3 scripts/generate_benchmark_dataset.py \
  --output-dir ./benchmark-dataset \
  --files-per-bucket 32 \
  --seed pqc-hons-benchmark-dataset-v2
```

Run the CLI directly:

```bash
export PQC_API_KEY="<operator-or-admin-key>"

cargo run --bin benchmark-cli -- \
  --base-url http://localhost:3000 \
  --operations-endpoint http://localhost:3000/operations \
  --dataset-dir ./benchmark-dataset \
  --output-dir ./output/benchmarks \
  --profiles rsa_pss,ml_dsa,rsa_pss_ml_dsa \
  --hashes sha256,keccak256 \
  --buckets 10KB,100KB,1MB,10MB,50MB \
  --scenarios workflow,sign_only,verify_manifest,verify_stored,verify_uploaded,verify_full \
  --warmup-runs 5 \
  --measured-runs 30 \
  --seed 42 \
  --storage-state-label warm \
  --campaign-label honours-formal \
  --repeat-index 1
```

Or run the wrapper script:

```bash
export PQC_API_KEY="<operator-or-admin-key>"
scripts/run_benchmark_campaign.sh \
  --storage-state-mode both \
  --campaign-repeats 3 \
  --campaign-label honours-formal
```

Outputs include:

- `benchmark-report-<timestamp>.json`
- `benchmark-runs-<timestamp>.csv`
- `benchmark-summary-<timestamp>.csv`
- `output/benchmarks/analysis/<report-stem>/analysis_manifest.json`
- `output/benchmarks/analysis/<report-stem>/quality_checks.json`
- `output/benchmarks/analysis/<report-stem>/condition_quality.csv`
- `output/benchmarks/analysis/<report-stem>/latency_summary.csv`
- `output/benchmarks/analysis/<report-stem>/artifact_summary.csv`
- `output/benchmarks/analysis/<report-stem>/stage_metrics_long.csv`
- `output/benchmarks/analysis/<report-stem>/comparison_metrics.csv`
- `output/benchmarks/analysis/<report-stem>/run_diagnostics.csv`
- `output/benchmarks/campaign-manifest-<label>.tsv`
- `output/benchmarks/analysis/campaign-manifest-<label>/campaign_analysis_manifest.json`
- `output/benchmarks/analysis/campaign-manifest-<label>/campaign_repeat_overview.csv`
- `output/benchmarks/analysis/campaign-manifest-<label>/campaign_condition_stability.csv`
- `output/benchmarks/analysis/campaign-manifest-<label>/campaign_comparison_stability.csv`

## 10. Example Workflows

### Workflow A: Sign and verify through the web UI

Use this when demonstrating the system interactively.

1. Start the backend stack and Vite UI.
2. Log in with an `operator` key.
3. Upload a file and sign it in `rsa_pss_ml_dsa` mode with `SHA256`.
4. Copy the `request_id` from the manifest viewer.
5. Open `Verify Signature`.
6. Upload the same file again.
7. Paste the `request_id`.
8. Confirm that:
   - `signature_ok` passes,
   - `object_ok` passes,
   - `file_hash_match` passes,
   - `overall_ok` is `true`.

### Workflow B: Compare RSA-PSS, ml_dsa, and RSA-PSS + ml_dsa for the same dataset

Use this when generating dissertation evidence.

1. Generate a deterministic dataset.
2. Fix the same hardware, OS, Docker config, and API limits for the whole run.
3. Run `benchmark-cli` or `scripts/run_benchmark_campaign.sh` across:
   - profiles: `rsa_pss,ml_dsa,rsa_pss_ml_dsa`
   - hashes: `sha256,keccak256`
   - buckets: `10KB,100KB,1MB,10MB,50MB`
   - scenarios: `workflow,sign_only,verify_manifest,verify_stored,verify_uploaded,verify_full`
   - storage states: `cold` and `warm`
   - independent repeats: at least `3`
4. Analyze each produced JSON report with `scripts/analyze_benchmark_report.py`.
5. Use:
   - median
   - IQR
   - p95
   - 95% CI
   - absolute deltas vs `rsa_pss`
   - `rsa_pss`-relative ratios
   - server-attributed ratio CIs
   - effect sizes
   - CV and relative-IQR diagnostics
   - campaign repeat-stability summaries
   - storage and artifact-overhead metrics
   for your write-up.

### Workflow C: Demonstrate owner isolation between API keys

Use this to demonstrate the current authorization model.

1. Sign a file with an `operator` key and record the `request_id`.
2. Log in separately with a different `readonly` key.
3. Upload the same candidate file with the read-only identity.
4. Call `/verify` using that read-only identity and the original `request_id`.
5. Expect verification to fail because manifest lookup is scoped to `request_id + owner_key_fingerprint`, not `request_id` alone.
6. Repeat verification with the original signing key identity to show that the same manifest is accessible only to its owning API-key fingerprint.

## 11. Bottom Line

The project already provides a functioning end-to-end research system for:

- authenticated upload,
- classical/PQC/hybrid manifest signing,
- owner-scoped verification,
- immutable object checking,
- UI-based demonstration,
- CLI-based benchmark collection.

Its security posture is strongest around:

- backend-only crypto,
- owner-scoped authorization,
- path and symlink hardening,
- TOCTOU risk reduction in the hasher,
- rate and size limits,
- transport hardening for internal traffic,
- secret-handling improvements in compose and UI.

Its biggest current gaps are measurement-related rather than basic workflow-related:

- server-side timing extraction is not yet fully exposed,
- audit/revocation administration is only partial,
- and a few architecture statements in docs are ahead of the current code.
