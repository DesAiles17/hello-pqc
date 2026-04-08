# Benchmark CLI (Headless)

The `benchmark-cli` binary runs reproducible benchmark matrices against the API gateway using:

- `POST /upload`
- `POST /process`
- `POST /verify`

It is designed for formal evidence generation (batch mode, randomized condition order, warm-up exclusion, raw export).

## Build

```bash
cargo build --release --bin benchmark-cli
```

## Required inputs

- API gateway URL (`--base-url`, default `http://localhost:3000`)
- API key with operator role (`--api-key` or env `PQC_API_KEY`)
- Dataset directory with fixed files (`--dataset-dir`)

## Prepare dataset

Generate deterministic bucketed files before running benchmarks:

```bash
python3 scripts/generate_benchmark_dataset.py \
  --output-dir ./benchmark-dataset \
  --files-per-bucket 32 \
  --seed pqc-hons-benchmark-dataset-v2
```

## Example run

```bash
export PQC_API_KEY="<operator-api-key>"

./target/release/benchmark-cli \
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

## Controlled-condition notes

- Keep hardware/OS/build profile fixed across campaigns.
- Keep dataset immutable during a campaign.
- Warm-up runs are executed first and excluded from summaries.
- Measured jobs are randomized in blocked replicate order across profile/hash/bucket/scenario conditions.
- Files are rotated within each bucket before reuse to reduce repeated-file bias.
- Benchmark scenarios let you separate workflow latency from sign-only and verify-only behaviour.
- Storage state labels distinguish cold-ingest campaigns from warm steady-state campaigns.
- Use the same `--seed` for deterministic run ordering.
- `--inter-run-delay-ms` defaults to **400 ms** in `benchmark-cli`. Increase it for shared or heavily loaded hosts.

## Outputs

Each run writes timestamped files under `--output-dir`:

- `benchmark-report-<timestamp>.json`
  - Full config, raw runs (with typed `scenario_status`, `verify_outcome`, `server_telemetry_status`, dataset provenance), condition summaries, and pre-computed `evidence_metrics` array
- `benchmark-runs-<timestamp>.csv`
  - Per-run records for analysis/reproducibility
- `benchmark-evidence-metrics-<timestamp>.csv` (**primary evidence table**)
  - Long-form per-condition metric table with explicit `metric_applicability` and `coverage` columns; suitable for dissertation tables and downstream statistical tools
- `benchmark-summary-<timestamp>.csv` (secondary/legacy)
  - Wide per-condition summary; kept for backward compatibility

Generated analysis adds:

- `analysis/<report>/analysis_manifest.json`
- `analysis/<report>/quality_checks.json`
- `analysis/<report>/condition_quality.csv`
- `analysis/<report>/warmup_adequacy.csv`
- `analysis/<report>/warmup_trajectory.csv`
- `analysis/<report>/trend_test.csv`
- `analysis/<report>/latency_summary.csv`
- `analysis/<report>/artifact_summary.csv`
- `analysis/<report>/stage_metrics_long.csv`
- `analysis/<report>/comparison_metrics.csv`
- `analysis/<report>/run_diagnostics.csv`
- `analysis/<report>/evidence_metrics_long.csv` — pass-through of the report's `evidence_metrics` array with applicability and coverage metadata
- `analysis/<report>/fig_*.png` and `fig_*.svg` when plotting is enabled
- `analysis/campaign-manifest-<label>/campaign_analysis_manifest.json`
- `analysis/campaign-manifest-<label>/campaign_repeat_overview.csv`
- `analysis/campaign-manifest-<label>/campaign_condition_stability.csv`
- `analysis/campaign-manifest-<label>/campaign_comparison_stability.csv`

## Summary metrics

Per condition (`scenario × storage_state × profile × hash × bucket`), the CLI reports:

- median
- IQR
- p95
- 95% CI (bootstrap over median)

The CLI also computes comparative median ratios for total latency:

- `S_pqc = median_total_pqc / median_total_classical`
- `S_hybrid = median_total_hybrid / median_total_classical`

When server timings are available, it also reports:

- server-attributed stage medians (`server_hash_ms`, `server_rsa_sign_ms`, `server_ml_dsa_sign_ms`, `server_verify_ms`, `server_total_ms`)
- lower-level per-run stage exports for object-store, DB, and verify substeps
- normalized artifact metrics:
  - `manifest_overhead_pct`
  - `signature_overhead_pct`
  - `storage_amplification`
- effective throughput metrics:
  - `client_total_mib_s`
  - `server_hash_mib_s`
  - `server_verify_mib_s`
  - `server_total_mib_s`
- server-side comparative ratios:
  - `S_pqc_server = median_server_total_pqc / median_server_total_classical`
  - `S_hybrid_server = median_server_total_hybrid / median_server_total_classical`

## Server timing extraction

For formal benchmarking, provide the gateway operations endpoint keyed by `request_id`:

```bash
--operations-endpoint http://localhost:3000/operations
```

The CLI extracts typed server-side timing data from that endpoint and includes it in per-run output and per-condition summaries.

Without this option, reports are limited to client-observed workflow latency and should not be used as the source of truth for crypto-stage conclusions.

**sign_only client timing note**: For the `sign_only` scenario, `client_total_ms` covers the full round-trip including the upload phase, not just signing. Rows for `sign_only` + `client_*` metrics in `comparison_metrics.csv` carry a `client_note` column flagging this. Use `server_*` metrics for crypto-stage conclusions in that scenario.

## Run record schema

Each raw run record carries typed status fields to avoid ambiguity in analysis:

### `scenario_status` (enum)

| Value | Meaning |
|---|---|
| `ok` | Scenario body completed successfully |
| `failed` | Scenario body was attempted but failed |
| `not_attempted` | Run aborted before the scenario body (e.g. fixture setup failure) |

### `verify_outcome` (enum)

| Value | Meaning |
|---|---|
| `ok` | Verification step passed |
| `failed` | Verification step was attempted and failed |
| `not_applicable` | This scenario does not include a verify step (e.g. `sign_only`) |
| `not_attempted` | Verify was expected but not reached due to an earlier failure |

**Note on `verify_success_rate` in `condition_quality.csv`**: the legacy `verify_success_rate` field counts all non-verify runs (e.g. `sign_only`) as failures, giving a misleading 0% rate. Use `verify_applicable_success_rate` instead, which is `None` when the scenario has no verify step and a true success rate otherwise.

### `server_telemetry_status` (enum)

| Value | Meaning |
|---|---|
| `not_configured` | `--operations-endpoint` was not provided; no server timings collected |
| `available` | Server timing record fetched and all expected fields present |
| `partial` | Record fetched but some expected fields are missing |
| `error` | Fetch attempt failed (network error or non-200 response) |

`condition_quality.csv` reports `server_total_coverage` as the fraction of successful runs with `server_telemetry_status == available` (or with `server_total_ms` present for legacy reports).

### Setup vs scenario body timings

All scenarios run an upload+process step to create a signed fixture before the scenario body. For `workflow` and `sign_only` this is the scenario body itself; for verify-only scenarios (`verify_manifest`, `verify_stored`, `verify_uploaded`, `verify_full`) this is setup overhead:

| Field | Populated for |
|---|---|
| `setup_upload_ms` | All scenarios (fixture upload wall time) |
| `setup_process_ms` | All scenarios (fixture sign wall time) |
| `client_upload_ms` | `workflow`, `sign_only` only |
| `client_process_ms` | `workflow`, `sign_only` only |

### Dataset provenance

Each run record includes host-independent dataset identifiers sourced from `dataset-manifest.csv` and `dataset-metadata.json`:

- `dataset_seed` — deterministic seed string used to generate the dataset
- `dataset_relative_path` — path relative to `--dataset-dir` (not host-dependent)
- `dataset_bucket_index` — file index within its bucket (1-based)
- `dataset_file_type` — file type (`bin`, `txt`, `json`, `csv`, `md`)

The absolute `file_path` is retained as an operational reference only and should not be used as a primary identifier in analysis.

## Analyze a generated report

Use the analysis utility to convert a benchmark JSON report into:

- report-level quality checks
- per-condition latency summary tables
- per-condition artifact summary tables
- long-form stage metrics for attribution work
- comparison tables with absolute deltas, ratios, CIs, and effect sizes
- run diagnostics for client/server gap and unattributed server time
- PNG/SVG dissertation figures when `matplotlib` is available

Run:

```bash
python3 scripts/analyze_benchmark_report.py \
  output/benchmarks/benchmark-report-<timestamp>.json
```

Default output path:

```text
output/benchmarks/analysis/benchmark-report-<timestamp>/
```

Useful options:

- `--output-dir <path>` custom output folder
- `--min-success-rate 0.90` overall measured success threshold
- `--min-condition-success-rate 0.90` per-condition success threshold
- `--min-server-coverage 1.00` required server-attributed coverage per condition
- `--max-relative-iqr 0.50` workflow dispersion threshold (`IQR / median`)
- `--max-server-relative-iqr 0.50` server dispersion threshold (`IQR / median`)
- `--plot-formats png,svg` figure formats
- `--skip-plots` disable figure generation
- `--bootstrap-samples 2000` bootstrap resamples

If plots are skipped, install matplotlib and re-run:

```bash
python3 -m pip install matplotlib
```

## One-command campaign runner

Run benchmark + analysis in one command:

```bash
export PQC_API_KEY="<operator-or-admin-key>"
scripts/run_benchmark_campaign.sh \
  --storage-state-mode both \
  --campaign-repeats 3 \
  --campaign-label honours-formal
```

This script will:

1. build `benchmark-cli`
2. preflight the analysis tooling before the long campaign starts
3. prepare deterministic warm and/or cold datasets
4. optionally prewarm the warm-state dataset
5. execute each benchmark repeat with explicit scenario and storage-state labels
6. write each repeat into a dedicated output directory under `output/benchmarks/campaign-runs/<label>/...`
7. append status rows to `campaign-manifest-<label>.tsv` including dataset seed, run output dir, report path, evidence CSV path, log path, and benchmark/analysis status
8. run `scripts/analyze_benchmark_report.py` on every completed report

You can override key settings, for example:

```bash
scripts/run_benchmark_campaign.sh \
  --inter-run-delay-ms 1500 \
  --measured-runs 20
```

Useful campaign-runner controls:

- `--resume` continue a partially completed campaign using the latest manifest row per `(state, repeat_index)`
- `--force-overwrite` remove the existing outputs for the current campaign label before starting again
- `--estimate-only` print the condition count, total planned runs, warm-state prewarm runs, and fixed delay floor without running anything
- `--smoke` run the same script with reduced warm-state defaults for a quick end-to-end sanity check

Notes:

- Upload-cache cleanup is now only attempted for a local Docker-managed gateway.
- The campaign manifest is append-only; downstream aggregation uses the latest row per repeat.
- A `cold` run still means a fresh dataset plus local upload-cache cleanup. It does not automatically guarantee a full object-store reset unless you provide that separately in your environment.

## Benchmark mode (avoid 429 during campaigns)

If you see repeated `429` errors during benchmark campaigns, set benchmark-oriented gateway limits in your environment before restarting `api-gateway`:

```bash
export RATE_LIMIT_SIGN_PER_MIN=0
export RATE_LIMIT_VERIFY_PER_MIN=0
export RATE_LIMIT_HASH_PER_MIN=0
export RATE_LIMIT_GLOBAL_PER_MIN=0
export RATE_LIMIT_AUTH_FAIL_PER_MIN=0

# Remove the per-key upload quota for controlled benchmark runs
export MAX_UPLOAD_STORAGE_PER_KEY=0
```

Then recreate gateway:

```bash
docker compose up -d --force-recreate api-gateway
```

Notes:

- `0` disables the rate limiters in the current implementation.
- `MAX_UPLOAD_STORAGE_PER_KEY=0` disables the per-key upload quota in the current implementation.
- `scripts/run_benchmark_campaign.sh` now does this automatically for local Docker-based runs and restores the normal gateway config afterward.
- Keep these settings for controlled local benchmarking only, not production.
