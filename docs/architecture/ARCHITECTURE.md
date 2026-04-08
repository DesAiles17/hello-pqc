# Architecture Overview

This file is the concise, repo-grounded architecture summary for the current
implementation. The longer historical specification remains in
[`ARCHITECTURE.txt`](/home/denys/hello-pqc/docs/architecture/ARCHITECTURE.txt).

## Purpose

The project is a dissertation research prototype for comparing:

- classical signing with `RSA-PSS`
- post-quantum signing with `CRYSTALS-ml_dsa Round 3`
- hybrid dual-signature signing with both algorithms over the same canonical
  manifest

The main deliverable is reproducible benchmark evidence, not a production-ready
service platform.

## Components

- `api-gateway` on port `3000`
  - API-key authentication
  - upload handling
  - rate limiting and verification concurrency control
  - orchestration of hash, sign, and verify workflows
  - benchmark operation metric persistence
- `hasher-service` on port `3001`
  - SHA-256 and Keccak-256 hashing
  - immutable object storage in MinIO
  - server-side hash timing
- `manifest-builder-service` on port `3002`
  - canonical CBOR manifest generation
  - RSA-PSS signing
  - CRYSTALS-ml_dsa Round 3 signing
  - manifest verification and revocation checks
  - server-side sign and verify timing
- PostgreSQL
  - signed manifests
  - benchmark operation metrics
  - scaffolded audit-log table
- MinIO
  - immutable content-addressed object storage
- `web-ui`
  - interactive demo and inspection interface
- `benchmark-cli`
  - reproducible benchmark execution and export

## Current Implementation Notes

- The Rust PQC crate in use is `pqcrypto-ml_dsa::ml_dsa`, so the repo is
  currently implementing the pre-FIPS CRYSTALS-ml_dsa Round 3 variant rather
  than FIPS 204 ML-DSA.
- The helper key-generation script creates `RSA-3072` keys, which is the
  practical baseline currently used by this repository.
- Hybrid signing is independent but sequential in code. Verification requires
  the signatures expected by the selected profile.
- Audit events are now emitted in the gateway for upload, sign, and verify
  operations, but the database-backed `manifest_audit_log` table is still not
  fully wired into application writes.

## Public API Surface

- `POST /upload`
- `POST /process`
- `POST /verify`
- `GET /health`
- `GET /operations`

## Measurement Invariants

- cryptography is backend-only
- hashing and signing stay separate stages
- benchmark results rely on server-side timings as the source of truth
- the CLI is the canonical benchmarking interface for dissertation evidence
