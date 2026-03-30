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
  --profiles classical,pqc,hybrid \
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

## Outputs

Each run writes timestamped files under `--output-dir`:

- `benchmark-report-<timestamp>.json`
  - Full config, raw runs, and condition summaries
- `benchmark-runs-<timestamp>.csv`
  - Per-run records for analysis/reproducibility
- `benchmark-summary-<timestamp>.csv`
  - Per-condition summary metrics

Generated analysis adds:

- `analysis/<report>/summary_flat.csv`
- `analysis/<report>/condition_quality.csv`
- `analysis/<report>/ratio_table.csv`
- `analysis/<report>/stage_breakdown.csv`
- `analysis/<report>/scenario_recommendations.csv`
- `analysis/<report>/quality_gate.json`
- `analysis/<report>/interpretation.md`
- `analysis/campaign-manifest-<label>/campaign_recommendation_consensus.csv`

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

- server-attributed stage medians (`server_hash_ms`, `server_rsa_sign_ms`, `server_dilithium_sign_ms`, `server_verify_ms`, `server_total_ms`)
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

## Analyze a generated report

Use the analysis utility to convert a benchmark JSON report into:

- quality-gate diagnostics
- flat CSV tables for stats work
- ratio table with bootstrap CIs and effect sizes
- stage-breakdown CSV for crypto/storage attribution
- scenario recommendation table keyed by evidence scope and storage impact
- dissertation-ready interpretation markdown
- optional PNG plots (if `matplotlib` is installed)

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
- `--max-relative-iqr 0.50` dispersion threshold (`IQR / median`)
- `--hybrid-good-threshold 1.25` base hybrid viability threshold
- `--pqc-good-threshold 1.25` base PQC viability threshold
- `--pqc-staged-threshold 1.60` base conditional threshold
- `--bootstrap-samples 2000` ratio/bootstrap resamples

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
2. prepare deterministic warm and/or cold datasets
3. optionally prewarm the warm-state dataset
4. execute each benchmark repeat with explicit scenario and storage-state labels
5. run `scripts/analyze_benchmark_report.py` on every generated report
6. write `campaign-manifest-<label>.tsv` with dataset seed, state, repeat, and report paths
7. aggregate repeat-level results with `scripts/analyze_campaign_manifest.py`

You can override key settings, for example:

```bash
scripts/run_benchmark_campaign.sh \
  --inter-run-delay-ms 1500 \
  --measured-runs 20
```

## Benchmark mode (avoid 429 during campaigns)

If you see repeated `429` errors during benchmark campaigns, set benchmark-oriented gateway limits in your environment before restarting `api-gateway`:

```bash
export RATE_LIMIT_SIGN_PER_MIN=0
export RATE_LIMIT_VERIFY_PER_MIN=0
export RATE_LIMIT_HASH_PER_MIN=0
export RATE_LIMIT_GLOBAL_PER_MIN=0
export RATE_LIMIT_AUTH_FAIL_PER_MIN=0

# Prevent per-key upload quota exhaustion during large campaigns
export MAX_UPLOAD_STORAGE_PER_KEY=21474836480
```

Then recreate gateway:

```bash
docker compose up -d --force-recreate api-gateway
```

Notes:

- `0` disables that limiter in the current implementation.
- Keep these settings for controlled local benchmarking only, not production.
