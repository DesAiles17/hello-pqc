# hello-pqc

`hello-pqc` is a research prototype for measuring the system-level cost of
classical, post-quantum, and hybrid digital-signing workflows in a file
processing pipeline.

The implementation is intentionally benchmark-oriented rather than
production-ready. Its main goal is to generate reproducible evidence for how
different signing profiles affect latency, artifact size, and verification
behaviour when integrated into a realistic microservice workflow.

## What Is Implemented

- Rust + Axum backend services:
  - `api-gateway`
  - `hasher-service`
  - `manifest-builder-service`
- PostgreSQL for signed manifests and benchmark operation metadata
- MinIO for immutable object storage
- React web UI for interactive sign/verify demonstrations
- Rust `benchmark-cli` for formal benchmark campaigns and export

The public workflow is built around:

- `POST /upload`
- `POST /process`
- `POST /verify`
- `GET /health`
- `GET /operations`

Cryptographic operations remain backend-only. The UI and CLI orchestrate the
workflow but never compute signatures locally.

## Current Cryptography Terminology

- Classical profile: `RSA-PSS`
- Post-quantum profile in this repo: `CRYSTALS-ml_dsa Round 3`, implemented
  via `pqcrypto-ml_dsa::ml_dsa`
- Hybrid profile: independent dual signatures over the same canonical manifest

Important current-state notes:

- The repository does **not** implement FIPS 204 ML-DSA directly. It uses the
  earlier CRYSTALS-ml_dsa Round 3 implementation exposed by the current Rust
  crate.
- The canonical dev helper now lives at
  [`scripts/dev/gen_keys.sh`](/home/denys/hello-pqc/scripts/dev/gen_keys.sh).
  The root-level [`gen_keys.sh`](/home/denys/hello-pqc/gen_keys.sh) remains as
  a compatibility wrapper. The generated RSA helper key is currently
  `RSA-3072`, while runtime code uses whatever PEM key material is mounted at
  runtime.
- Hybrid signing is independent but currently **sequential** in the codebase.
  It is intended for measurement of dual-signature overhead, not as a claim of
  standards-compliant composite-signature security properties.

## Why The Architecture Looks This Way

The system separates hashing from signing so each stage remains independently
measurable. This is the main reason the project uses multiple services instead
of collapsing everything into one process.

- The gateway owns auth, rate limits, upload handling, orchestration, and
  client-visible timing.
- The hasher owns hash computation and immutable object storage.
- The manifest builder owns canonical manifest generation, signing, and
  verification.

This structure supports both the interactive UI workflow and the formal
benchmark CLI without moving cryptographic work into the client.

## Repo Status

The repo now includes:

- passing unit tests for the current Rust test suite
- request-path audit logging for upload, sign, and verify events
- benchmark analysis outputs under
  [`output/benchmarks/analysis/`](/home/denys/hello-pqc/output/benchmarks/analysis)
- project-specific UI documentation instead of the default Vite template README

Known limitations remain part of the research framing:

- benchmark evidence is structured and reproducible, but not every condition
  clears the quality gates in the generated analysis
- the `manifest_audit_log` database table is still scaffolded rather than fully
  populated by application code
- the dissertation/report source is still a working academic artifact, not a
  polished publication

## Project Layout

- [`docs/architecture/`](/home/denys/hello-pqc/docs/architecture): architecture overviews and diagrams
- [`docs/benchmarking/`](/home/denys/hello-pqc/docs/benchmarking): benchmark runner and evidence export docs
- [`docs/analysis/`](/home/denys/hello-pqc/docs/analysis): deeper repo and dissertation analysis notes
- [`docs/setup/`](/home/denys/hello-pqc/docs/setup): local security and TLS setup guidance
- [`docs/dissertation/`](/home/denys/hello-pqc/docs/dissertation): dissertation source artifacts
- [`scripts/dev/`](/home/denys/hello-pqc/scripts/dev): operational/dev helpers
- [`scripts/`](/home/denys/hello-pqc/scripts): benchmark runners and analysis tooling
- [`legacy/`](/home/denys/hello-pqc/legacy): retained historical helpers that are no longer part of the active workflow
- [`fixtures/`](/home/denys/hello-pqc/fixtures): sample test inputs and other non-source assets

## Helpful Docs

- [`ARCHITECTURE.md`](/home/denys/hello-pqc/docs/architecture/ARCHITECTURE.md)
- [`ARCHITECTURE.txt`](/home/denys/hello-pqc/docs/architecture/ARCHITECTURE.txt)
- [`BENCHMARK_CLI.md`](/home/denys/hello-pqc/docs/benchmarking/BENCHMARK_CLI.md)
- [`PROJECT_ANALYSIS.md`](/home/denys/hello-pqc/docs/analysis/PROJECT_ANALYSIS.md)
- [`SECURITY_SETUP.md`](/home/denys/hello-pqc/docs/setup/SECURITY_SETUP.md)
