# Post-Quantum Cryptography Signing System
Honours Dissertation – Research Prototype

---

## 1) Mission (Active)

This project is a research prototype for measurable comparison of:
- Classical: RSA + SHA256
- PQC: Dilithium + Keccak256
- Hybrid: RSA + Dilithium (independent execution)

Primary outcome:
- Defensible empirical evidence for performance trade-offs and migration guidance.

Out of scope:
- Enterprise hardening
- Horizontal scaling studies
- UX polish unrelated to benchmarking

---

## 2) Architecture Snapshot (Stable Baseline)

- Backend: Rust + Axum microservices
- Services:
  - API Gateway (3000): auth, routing, metrics
  - Hasher (3001): SHA256/Keccak256 + hash timing
  - Manifest Builder (3002): sign/verify + signature timing
- Storage:
  - PostgreSQL: manifests + metrics
  - MinIO: immutable objects

Rule:
- Each cryptographic stage must remain independently measurable.

---

## 3) Non-Negotiable Invariants

- Cryptography is backend-only.
- UI and CLI never compute signatures.
- Hashing and signing stay separable stages.
- Hybrid executes classical and PQC signing independently.
- Metrics must be attributable by algorithm/profile.
- Server-side crypto timings are the source of truth.

---

## 4) API + Data Contract (Stable)

Required API endpoints:
- `POST /upload`
- `POST /process`
- `POST /verify`
- `GET /health`

Optional endpoint:
- `GET /operations`

Auth:
- `X-API-Key` header
- Never log API keys
- Never put keys in URLs

Core manifest requirements:
- Reproducible manifest content
- `signature_profile`: `classical | pqc | hybrid`
- `request_id` (UUID) for traceability

---

## 5) Benchmarking Scope (Academic)

Include:
- Stage timing:
  - Hash time
  - RSA sign time
  - Dilithium sign time
  - Verify time
  - Total processing time
- Artifact overhead:
  - Signature size
  - Manifest size
  - Storage growth impact
- Workload sensitivity:
  - File-size bucket effects
  - Profile/hash algorithm effects

Exclude:
- UI rendering performance
- Internet latency as primary evidence
- Enterprise throughput/scaling claims

---

## 6) Experimental Protocol (Required)

Environment control:
- Same hardware + OS across all conditions
- Stable build profile and service config
- Minimal background workload

Dataset control:
- Fixed size buckets (e.g., 10KB, 100KB, 1MB, 10MB, 50MB)
- Representative file types if relevant
- Immutable dataset during campaign

Run design:
- Warm-up runs excluded from analysis
- Target >= 30 measured runs per condition
- Randomize condition order

Condition matrix:
- Signature profile: `classical | pqc | hybrid`
- Hash algorithm: `sha256 | keccak256`
- File-size bucket

---

## 7) Analysis & Evidence Standard

Report per condition:
- Median
- IQR
- p95
- 95% CI (where appropriate)

Comparative metrics:
- `S_pqc = t_pqc / t_classical`
- `S_hybrid = t_hybrid / t_classical`

Statistical guidance:
- Prefer non-parametric tests when normality is uncertain
- Report effect size (not only p-values)
- Separate statistical vs practical significance

Evidence quality:
- Every conclusion maps to explicit metrics
- Avoid single-run or mean-only claims
- Preserve raw outputs for reproduction

---

## 8) Recommendation Framework (Dissertation Output)

Recommendations must be threshold-based and condition-specific:
- Profile by latency budget + file-size band
- Where hybrid overhead is justified
- Where classical remains preferable
- Migration sequence (e.g., verifier readiness first)

Must include:
- Observed trade-off linkage
- Limitations and external-validity boundaries

---

## 9) CLI Role (Canonical for Headless Benchmarks)

CLI is the formal benchmarking interface.

CLI responsibilities:
- Reproducible batch execution
- Matrix orchestration
- Structured export (`CSV/JSON`)

CLI boundaries:
- Orchestrates only; cryptographic ops remain backend services
- Uses existing API flow (`/upload`, `/process`, `/verify`) unless explicitly running isolated internal tests
- Keeps metrics stage-level and algorithm-attributable

Positioning:
- Web UI = transparent live demo
- CLI = formal evidence generation

---

## 10) Active Priorities (Execution Queue)

1. Implement/validate CLI benchmark runner
2. Ensure stage-level metric persistence completeness
3. Verify end-to-end sign + verify benchmark flow
4. Generate analysis-ready exports and summary statistics
5. Produce visual comparison outputs for dissertation chapters

---

## 11) Security + Error Baseline (Compact)

Security constraints:
- Explicit CORS policy (no wildcard in production)
- HTTPS in production
- CSP
- File path sanitisation
- Upload size limits

Error handling:
- Distinguish validation, auth (`401/403`), rate-limit (`429`), and server (`5xx`) failures
- Retry only transient failures
- Never blindly retry cryptographic operations
