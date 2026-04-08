use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use pqc_hons::{
    benchmark_hash_to_service, benchmark_profile_to_service, normalize_benchmark_hash,
    normalize_benchmark_profile,
};
use pqc_hons::{OperationMetricsResponse, UploadCleanupRequest, VerifyResponse};
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use reqwest::{multipart, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub const DEFAULT_SIGNATURE_PROFILES: [&str; 7] = [
    "rsa_pss",
    "eddsa",
    "ecdsa",
    "hmac_sha256",
    "ml_dsa",
    "slh_dsa",
    "fn_dsa",
];
pub const DEFAULT_HASH_ALGORITHMS: [&str; 3] = ["sha256", "blake3", "keccak256"];
pub const DEFAULT_BUCKETS: [&str; 5] = ["10KB", "100KB", "1MB", "10MB", "50MB"];
pub const DEFAULT_SCENARIOS: [&str; 6] = [
    "workflow",
    "sign_only",
    "verify_manifest",
    "verify_stored",
    "verify_uploaded",
    "verify_full",
];
pub const DEFAULT_STORAGE_STATES: [&str; 2] = ["cold", "warm"];
pub const DEFAULT_DATASET_FILE_TYPES: [&str; 5] = ["bin", "txt", "json", "csv", "md"];
pub const DEFAULT_RUN_PHASES: [&str; 2] = ["warmup", "measured"];
pub const DEFAULT_TELEMETRY_SCOPES: [&str; 4] = ["client", "server", "artifact", "quality"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkCategory {
    pub name: String,
    pub role: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMeasurementGroup {
    pub name: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSetup {
    pub version: String,
    pub purpose: String,
    pub primary_matrix: Vec<BenchmarkCategory>,
    pub secondary_factors: Vec<BenchmarkCategory>,
    pub measurement_groups: Vec<BenchmarkMeasurementGroup>,
    pub notes: Vec<String>,
}

impl BenchmarkSetup {
    pub fn dissertation_defaults() -> Self {
        Self::from_resolved_options(
            &strings(&DEFAULT_SIGNATURE_PROFILES),
            &strings(&DEFAULT_HASH_ALGORITHMS),
            &strings(&DEFAULT_BUCKETS),
            &strings(&DEFAULT_SCENARIOS),
            &strings(&DEFAULT_STORAGE_STATES),
            &strings(&DEFAULT_DATASET_FILE_TYPES),
        )
    }

    pub fn from_resolved_options(
        signature_profiles: &[String],
        hash_algorithms: &[String],
        payload_buckets: &[String],
        scenarios: &[String],
        storage_states: &[String],
        file_types: &[String],
    ) -> Self {
        let signature_profiles =
            resolved_or_default(signature_profiles, &DEFAULT_SIGNATURE_PROFILES);
        let hash_algorithms = resolved_or_default(hash_algorithms, &DEFAULT_HASH_ALGORITHMS);
        let payload_buckets = resolved_or_default(payload_buckets, &DEFAULT_BUCKETS);
        let scenarios = resolved_or_default(scenarios, &DEFAULT_SCENARIOS);
        let storage_states = resolved_or_default(storage_states, &DEFAULT_STORAGE_STATES);
        let file_types = resolved_or_default(file_types, &DEFAULT_DATASET_FILE_TYPES);

        Self {
            version: "benchmarking.v2".to_string(),
            purpose:
                "Decision-grade performance benchmarking for classical and post-quantum signing workflows"
                    .to_string(),
            primary_matrix: vec![
                category("scenario", "primary_matrix", &scenarios),
                category("storage_state", "primary_matrix", &storage_states),
                category("signature_strategy", "primary_matrix", &signature_profiles),
                category("hash_algorithm", "primary_matrix", &hash_algorithms),
                category("payload_bucket", "primary_matrix", &payload_buckets),
            ],
            secondary_factors: vec![
                category("file_content_class", "secondary_factor", &file_types),
                category("run_phase", "secondary_factor", &strings(&DEFAULT_RUN_PHASES)),
                category(
                    "telemetry_scope",
                    "secondary_factor",
                    &strings(&DEFAULT_TELEMETRY_SCOPES),
                ),
            ],
            measurement_groups: vec![
                BenchmarkMeasurementGroup {
                    name: "outcome_and_validity".to_string(),
                    fields: strings(&[
                        "scenario_status",
                        "verify_outcome",
                        "scenario_success_rate",
                        "verify_applicable_success_rate",
                        "server_telemetry_status",
                        "server_telemetry_coverage",
                    ]),
                },
                BenchmarkMeasurementGroup {
                    name: "performance_timings".to_string(),
                    fields: strings(&[
                        "setup_upload_ms",
                        "setup_process_ms",
                        "client_upload_ms",
                        "client_process_ms",
                        "client_verify_ms",
                        "client_total_ms",
                        "server_hash_ms",
                        "server_verify_ms",
                        "server_total_ms",
                    ]),
                },
                BenchmarkMeasurementGroup {
                    name: "artifact_overhead".to_string(),
                    fields: strings(&[
                        "manifest_core_bytes",
                        "manifest_core_cbor_bytes",
                        "total_signature_bytes",
                        "manifest_overhead_pct",
                        "signature_overhead_pct",
                    ]),
                },
                BenchmarkMeasurementGroup {
                    name: "provenance_and_controls".to_string(),
                    fields: strings(&[
                        "dataset_seed",
                        "dataset_relative_path",
                        "dataset_bucket_index",
                        "dataset_file_type",
                        "storage_state_label",
                        "campaign_label",
                        "repeat_index",
                    ]),
                },
            ],
            notes: strings(&[
                "Treat file identity as a sampled replicate inside each bucket, not as a headline comparison axis.",
                "Use server-side timings as the source of truth for crypto-stage conclusions.",
                "Warm-up runs are excluded from measured summaries.",
                "For sign_only, client_total_ms still includes upload and setup overhead.",
            ]),
        }
    }
}

fn category(name: &str, role: &str, options: &[String]) -> BenchmarkCategory {
    BenchmarkCategory {
        name: name.to_string(),
        role: role.to_string(),
        options: options.to_vec(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn resolved_or_default(values: &[String], defaults: &[&str]) -> Vec<String> {
    if values.is_empty() {
        strings(defaults)
    } else {
        values.to_vec()
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "benchmark-cli")]
#[command(
    about = "Headless benchmark runner for classical and PQC signatures"
)]
struct Cli {
    #[arg(long, default_value = "http://localhost:3000")]
    base_url: String,

    #[arg(long, env = "PQC_API_KEY")]
    api_key: String,

    #[arg(long)]
    dataset_dir: PathBuf,

    #[arg(long, default_value = "output/benchmarks")]
    output_dir: PathBuf,

    #[arg(
        long,
        value_delimiter = ',',
    )]
    profiles: Vec<String>,

    #[arg(long, value_delimiter = ',', default_value = "sha256,blake3,keccak256")]
    hashes: Vec<String>,

    #[arg(long, value_delimiter = ',', default_value = "10KB,100KB,1MB,10MB,50MB")]
    buckets: Vec<String>,

    #[arg(long, value_delimiter = ',', default_value = "workflow")]
    scenarios: Vec<String>,

    #[arg(long, default_value_t = 30)]
    measured_runs: u32,

    #[arg(long, default_value_t = 3)]
    warmup_runs: u32,

    #[arg(long, default_value_t = 400)]
    inter_run_delay_ms: u64,

    #[arg(long, default_value_t = false)]
    fail_fast: bool,

    #[arg(long)]
    seed: Option<u64>,

    #[arg(long)]
    operations_endpoint: Option<String>,

    #[arg(long, default_value_t = 1000)]
    bootstrap_samples: usize,

    #[arg(long, default_value = "warm")]
    storage_state_label: String,

    #[arg(long)]
    campaign_label: Option<String>,

    #[arg(long)]
    repeat_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct Condition {
    signature_profile: String,
    hash_algorithm: String,
    bucket: String,
    benchmark_scenario: String,
}

#[derive(Debug, Clone)]
struct Job {
    condition: Condition,
    phase: Phase,
    ordinal: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Warmup,
    Measured,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileSelectionKey {
    phase: Phase,
    ordinal: u32,
    bucket: String,
}

#[derive(Debug, Clone)]
struct BucketSpec {
    label: String,
    min_bytes: u64,
    max_bytes: u64,
}

/// Status of a benchmark scenario attempt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ScenarioStatus {
    /// Scenario attempted and completed successfully.
    Ok,
    /// Scenario attempted but the operation failed (e.g. verify returned false, HTTP error in
    /// scenario body).
    Failed,
    /// Run failed during fixture setup before the scenario body was reached.
    NotAttempted,
}

/// Outcome of the verify stage for a run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum VerifyOutcome {
    /// Verification was part of this scenario and passed.
    Ok,
    /// Verification was part of this scenario but failed.
    Failed,
    /// Verification is not part of this scenario (sign_only).
    NotApplicable,
    /// Scenario failed before reaching the verify stage.
    NotAttempted,
}

/// Whether server-side operation telemetry was available for a run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ServerTelemetryStatus {
    /// No --operations-endpoint was configured; server metrics were not collected.
    NotConfigured,
    /// Telemetry retrieved and all expected operations for this scenario are present.
    Available,
    /// Endpoint responded but some expected operations were absent (possible propagation delay).
    Partial,
    /// Telemetry fetch failed (network error, HTTP error, or parse failure).
    Error,
}

/// Host-independent provenance record for a dataset file.
#[derive(Debug, Clone)]
struct DatasetFileEntry {
    index: u32,
    file_type: String,
    relative_path: String,
    seed: String,
}

/// Loaded dataset manifest for provenance enrichment.
#[derive(Debug, Default)]
struct DatasetManifest {
    /// Seed string from dataset-metadata.json, if present.
    seed: Option<String>,
    /// Entries keyed by relative path (as stored in dataset-manifest.csv).
    entries: HashMap<String, DatasetFileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadResponse {
    file_path: String,
    original_filename: String,
    size: u64,
    content_type: String,
    uploaded_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessRequest {
    file_path: String,
    signature_profile: String,
    hash_algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessResponse {
    manifest: SignedManifest,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyRequest {
    request_id: String,
    verify_object: bool,
    file_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedManifest {
    core: ManifestCore,
    envelope: serde_json::Value,
    signatures: Signatures,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestCore {
    schema_version: String,
    domain_sep: String,
    request_id: String,
    signature_profile: String,
    immutable_object_id: String,
    hash: String,
    algorithm: String,
    size: u64,
    storage_bucket: String,
    storage_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Signatures {
    rsa_pss: Option<String>,
    #[serde(default)]
    eddsa: Option<String>,
    #[serde(default)]
    ecdsa_p256: Option<String>,
    #[serde(default)]
    hmac_sha256: Option<String>,
    #[serde(default)]
    ml_dsa: Option<String>,
    #[serde(default)]
    slh_dsa: Option<String>,
    #[serde(default)]
    fn_dsa: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RunRecord {
    run_index: u64,
    phase: Phase,
    condition_signature_profile: String,
    condition_hash_algorithm: String,
    condition_bucket: String,
    benchmark_scenario: String,
    storage_state_label: String,
    campaign_label: Option<String>,
    repeat_index: Option<u32>,

    // ── Dataset provenance (host-independent) ───────────────────────────────
    /// Dataset generator seed string (from dataset-metadata.json).
    dataset_seed: Option<String>,
    /// Path relative to the dataset root (from dataset-manifest.csv).
    dataset_relative_path: Option<String>,
    /// 1-based file index within its bucket (from dataset-manifest.csv).
    dataset_bucket_index: Option<u32>,
    /// Content class of the file: bin, txt, json, csv, md (from dataset-manifest.csv).
    dataset_file_type: Option<String>,
    /// Absolute local path — operational reference only, not primary evidence.
    file_path: String,
    file_size_bytes: u64,

    // ── Operational identifiers (debug / tracing only) ───────────────────────
    request_id: Option<String>,

    // ── HTTP-stage outcome flags ─────────────────────────────────────────────
    upload_http_ok: bool,
    process_http_ok: bool,
    verify_http_ok: bool,

    // ── Typed outcome fields ─────────────────────────────────────────────────
    /// Typed scenario result: ok | failed | not_attempted.
    scenario_status: ScenarioStatus,
    /// Convenience boolean derived from scenario_status (backward compat).
    scenario_success: bool,
    /// Typed verify result: ok | failed | not_applicable | not_attempted.
    verify_outcome: VerifyOutcome,
    /// Whether server telemetry was configured, available, partial, or missing.
    server_telemetry_status: ServerTelemetryStatus,

    verify_overall_ok: Option<bool>,
    verify_signature_ok: Option<bool>,
    verify_object_ok: Option<bool>,
    verify_file_hash_match: Option<bool>,
    verify_error_details: Option<String>,

    // ── Fixture setup timings (always recorded; separate from scenario body) ─
    /// Client-observed upload time for the fixture setup step (all scenarios).
    setup_upload_ms: Option<f64>,
    /// Client-observed process/sign time for the fixture setup step (all scenarios).
    setup_process_ms: Option<f64>,

    // ── Scenario body timings (only for stages that are part of the scenario) ─
    /// Upload time as part of the scenario body (workflow and sign_only only).
    client_upload_ms: Option<f64>,
    /// Process/sign time as part of the scenario body (workflow and sign_only only).
    client_process_ms: Option<f64>,
    client_verify_ms: Option<f64>,
    client_total_ms: Option<f64>,
    manifest_size_bytes: Option<usize>,
    manifest_core_bytes: Option<usize>,
    manifest_core_cbor_bytes: Option<usize>,
    manifest_envelope_bytes: Option<usize>,
    rsa_signature_bytes: Option<usize>,
    eddsa_signature_bytes: Option<usize>,
    ecdsa_signature_bytes: Option<usize>,
    hmac_signature_bytes: Option<usize>,
    ml_dsa_signature_bytes: Option<usize>,
    slh_dsa_signature_bytes: Option<usize>,
    fn_dsa_signature_bytes: Option<usize>,
    total_signature_bytes: Option<usize>,
    manifest_overhead_pct: Option<f64>,
    signature_overhead_pct: Option<f64>,
    storage_amplification: Option<f64>,
    storage_bytes_written: Option<u64>,
    storage_bytes_read: Option<u64>,
    client_upload_mib_s: Option<f64>,
    client_process_mib_s: Option<f64>,
    client_verify_mib_s: Option<f64>,
    client_total_mib_s: Option<f64>,
    server_hash_mib_s: Option<f64>,
    server_verify_mib_s: Option<f64>,
    server_total_mib_s: Option<f64>,
    server_process_gateway_ms: Option<f64>,
    server_verify_gateway_ms: Option<f64>,
    server_hash_ms: Option<f64>,
    server_object_exists_check_ms: Option<f64>,
    server_object_store_ms: Option<f64>,
    server_object_store_hit: Option<bool>,
    server_multipart_used: Option<bool>,
    server_hash_bytes_read: Option<u64>,
    server_hash_bytes_written: Option<u64>,
    server_manifest_canonicalize_ms: Option<f64>,
    server_db_persist_ms: Option<f64>,
    server_rsa_sign_ms: Option<f64>,
    server_eddsa_sign_ms: Option<f64>,
    server_ecdsa_sign_ms: Option<f64>,
    server_hmac_sign_ms: Option<f64>,
    server_ml_dsa_sign_ms: Option<f64>,
    server_slh_dsa_sign_ms: Option<f64>,
    server_fn_dsa_sign_ms: Option<f64>,
    server_eddsa_verify_ms: Option<f64>,
    server_ecdsa_verify_ms: Option<f64>,
    server_hmac_verify_ms: Option<f64>,
    server_ml_dsa_verify_ms: Option<f64>,
    server_slh_dsa_verify_ms: Option<f64>,
    server_fn_dsa_verify_ms: Option<f64>,
    server_manifest_fetch_db_lookup_ms: Option<f64>,
    server_verify_hash_ms: Option<f64>,
    server_verify_canonicalize_ms: Option<f64>,
    server_signature_verify_ms: Option<f64>,
    server_stored_object_verify_ms: Option<f64>,
    server_uploaded_content_verify_ms: Option<f64>,
    server_verify_ms: Option<f64>,
    server_total_ms: Option<f64>,
    error_stage: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MetricSummary {
    n: usize,
    median: f64,
    iqr: f64,
    p95: f64,
    ci95_low: Option<f64>,
    ci95_high: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct ConditionSummary {
    signature_profile: String,
    hash_algorithm: String,
    bucket: String,
    benchmark_scenario: String,
    storage_state_label: String,
    measured_runs_total: usize,
    measured_runs_success: usize,
    measured_runs_failed: usize,
    scenario_success_rate: f64,
    /// Number of runs where verify was applicable (non-zero only for verify scenarios).
    verify_applicable_runs: usize,
    /// Number of applicable runs where verify passed.
    verify_ok_runs: usize,
    /// Success rate among applicable verify runs; None when verify is not part of this scenario.
    verify_applicable_success_rate: Option<f64>,
    /// Legacy field kept for backward compatibility — use verify_applicable_success_rate instead.
    /// For sign_only this is always 0.0 which is misleading; prefer the typed fields above.
    verify_success_rate: f64,
    /// Whether an --operations-endpoint was configured for this run set.
    server_telemetry_configured: bool,
    /// Fraction of successful runs that produced server-side telemetry.
    server_telemetry_coverage: f64,
    /// Setup stage timings (fixture upload; present for all scenarios).
    setup_upload_ms: Option<MetricSummary>,
    /// Setup stage timings (fixture process/sign; present for all scenarios).
    setup_process_ms: Option<MetricSummary>,
    upload_ms: Option<MetricSummary>,
    process_ms: Option<MetricSummary>,
    verify_ms: Option<MetricSummary>,
    total_ms: Option<MetricSummary>,
    server_process_gateway_ms: Option<MetricSummary>,
    server_verify_gateway_ms: Option<MetricSummary>,
    server_hash_ms: Option<MetricSummary>,
    server_rsa_sign_ms: Option<MetricSummary>,
    server_eddsa_sign_ms: Option<MetricSummary>,
    server_ecdsa_sign_ms: Option<MetricSummary>,
    server_hmac_sign_ms: Option<MetricSummary>,
    server_ml_dsa_sign_ms: Option<MetricSummary>,
    server_slh_dsa_sign_ms: Option<MetricSummary>,
    server_fn_dsa_sign_ms: Option<MetricSummary>,
    server_eddsa_verify_ms: Option<MetricSummary>,
    server_ecdsa_verify_ms: Option<MetricSummary>,
    server_hmac_verify_ms: Option<MetricSummary>,
    server_ml_dsa_verify_ms: Option<MetricSummary>,
    server_slh_dsa_verify_ms: Option<MetricSummary>,
    server_fn_dsa_verify_ms: Option<MetricSummary>,
    server_verify_ms: Option<MetricSummary>,
    server_total_ms: Option<MetricSummary>,
    manifest_size_bytes: Option<MetricSummary>,
    manifest_core_bytes: Option<MetricSummary>,
    manifest_core_cbor_bytes: Option<MetricSummary>,
    manifest_envelope_bytes: Option<MetricSummary>,
    rsa_signature_bytes: Option<MetricSummary>,
    eddsa_signature_bytes: Option<MetricSummary>,
    ecdsa_signature_bytes: Option<MetricSummary>,
    hmac_signature_bytes: Option<MetricSummary>,
    ml_dsa_signature_bytes: Option<MetricSummary>,
    slh_dsa_signature_bytes: Option<MetricSummary>,
    fn_dsa_signature_bytes: Option<MetricSummary>,
    total_signature_bytes: Option<MetricSummary>,
    manifest_overhead_pct: Option<MetricSummary>,
    signature_overhead_pct: Option<MetricSummary>,
    storage_amplification: Option<MetricSummary>,
    client_total_mib_s: Option<MetricSummary>,
    server_hash_mib_s: Option<MetricSummary>,
    server_verify_mib_s: Option<MetricSummary>,
    server_total_mib_s: Option<MetricSummary>,
    ratio_vs_rsa_pss_total_median: Option<f64>,
    ratio_vs_rsa_pss_server_total_median: Option<f64>,
}

#[derive(Debug, Serialize)]
struct ConditionSummaryCsv {
    signature_profile: String,
    hash_algorithm: String,
    bucket: String,
    benchmark_scenario: String,
    storage_state_label: String,
    measured_runs_total: usize,
    measured_runs_success: usize,
    measured_runs_failed: usize,
    scenario_success_rate: f64,
    verify_applicable_runs: usize,
    verify_ok_runs: usize,
    verify_applicable_success_rate: Option<f64>,
    verify_success_rate: f64,
    server_telemetry_configured: bool,
    server_telemetry_coverage: f64,
    setup_upload_ms_median: Option<f64>,
    setup_upload_ms_iqr: Option<f64>,
    setup_upload_ms_p95: Option<f64>,
    setup_upload_ms_ci95_low: Option<f64>,
    setup_upload_ms_ci95_high: Option<f64>,
    setup_process_ms_median: Option<f64>,
    setup_process_ms_iqr: Option<f64>,
    setup_process_ms_p95: Option<f64>,
    setup_process_ms_ci95_low: Option<f64>,
    setup_process_ms_ci95_high: Option<f64>,
    upload_ms_median: Option<f64>,
    upload_ms_iqr: Option<f64>,
    upload_ms_p95: Option<f64>,
    upload_ms_ci95_low: Option<f64>,
    upload_ms_ci95_high: Option<f64>,
    process_ms_median: Option<f64>,
    process_ms_iqr: Option<f64>,
    process_ms_p95: Option<f64>,
    process_ms_ci95_low: Option<f64>,
    process_ms_ci95_high: Option<f64>,
    verify_ms_median: Option<f64>,
    verify_ms_iqr: Option<f64>,
    verify_ms_p95: Option<f64>,
    verify_ms_ci95_low: Option<f64>,
    verify_ms_ci95_high: Option<f64>,
    total_ms_median: Option<f64>,
    total_ms_iqr: Option<f64>,
    total_ms_p95: Option<f64>,
    total_ms_ci95_low: Option<f64>,
    total_ms_ci95_high: Option<f64>,
    server_process_gateway_ms_median: Option<f64>,
    server_process_gateway_ms_iqr: Option<f64>,
    server_process_gateway_ms_p95: Option<f64>,
    server_process_gateway_ms_ci95_low: Option<f64>,
    server_process_gateway_ms_ci95_high: Option<f64>,
    server_verify_gateway_ms_median: Option<f64>,
    server_verify_gateway_ms_iqr: Option<f64>,
    server_verify_gateway_ms_p95: Option<f64>,
    server_verify_gateway_ms_ci95_low: Option<f64>,
    server_verify_gateway_ms_ci95_high: Option<f64>,
    server_hash_ms_median: Option<f64>,
    server_hash_ms_iqr: Option<f64>,
    server_hash_ms_p95: Option<f64>,
    server_hash_ms_ci95_low: Option<f64>,
    server_hash_ms_ci95_high: Option<f64>,
    server_rsa_sign_ms_median: Option<f64>,
    server_rsa_sign_ms_iqr: Option<f64>,
    server_rsa_sign_ms_p95: Option<f64>,
    server_rsa_sign_ms_ci95_low: Option<f64>,
    server_rsa_sign_ms_ci95_high: Option<f64>,
    server_eddsa_sign_ms_median: Option<f64>,
    server_eddsa_sign_ms_iqr: Option<f64>,
    server_eddsa_sign_ms_p95: Option<f64>,
    server_eddsa_sign_ms_ci95_low: Option<f64>,
    server_eddsa_sign_ms_ci95_high: Option<f64>,
    server_ecdsa_sign_ms_median: Option<f64>,
    server_ecdsa_sign_ms_iqr: Option<f64>,
    server_ecdsa_sign_ms_p95: Option<f64>,
    server_ecdsa_sign_ms_ci95_low: Option<f64>,
    server_ecdsa_sign_ms_ci95_high: Option<f64>,
    server_hmac_sign_ms_median: Option<f64>,
    server_hmac_sign_ms_iqr: Option<f64>,
    server_hmac_sign_ms_p95: Option<f64>,
    server_hmac_sign_ms_ci95_low: Option<f64>,
    server_hmac_sign_ms_ci95_high: Option<f64>,
    server_ml_dsa_sign_ms_median: Option<f64>,
    server_ml_dsa_sign_ms_iqr: Option<f64>,
    server_ml_dsa_sign_ms_p95: Option<f64>,
    server_ml_dsa_sign_ms_ci95_low: Option<f64>,
    server_ml_dsa_sign_ms_ci95_high: Option<f64>,
    server_slh_dsa_sign_ms_median: Option<f64>,
    server_slh_dsa_sign_ms_iqr: Option<f64>,
    server_slh_dsa_sign_ms_p95: Option<f64>,
    server_slh_dsa_sign_ms_ci95_low: Option<f64>,
    server_slh_dsa_sign_ms_ci95_high: Option<f64>,
    server_fn_dsa_sign_ms_median: Option<f64>,
    server_fn_dsa_sign_ms_iqr: Option<f64>,
    server_fn_dsa_sign_ms_p95: Option<f64>,
    server_fn_dsa_sign_ms_ci95_low: Option<f64>,
    server_fn_dsa_sign_ms_ci95_high: Option<f64>,
    server_eddsa_verify_ms_median: Option<f64>,
    server_eddsa_verify_ms_iqr: Option<f64>,
    server_eddsa_verify_ms_p95: Option<f64>,
    server_eddsa_verify_ms_ci95_low: Option<f64>,
    server_eddsa_verify_ms_ci95_high: Option<f64>,
    server_ecdsa_verify_ms_median: Option<f64>,
    server_ecdsa_verify_ms_iqr: Option<f64>,
    server_ecdsa_verify_ms_p95: Option<f64>,
    server_ecdsa_verify_ms_ci95_low: Option<f64>,
    server_ecdsa_verify_ms_ci95_high: Option<f64>,
    server_hmac_verify_ms_median: Option<f64>,
    server_hmac_verify_ms_iqr: Option<f64>,
    server_hmac_verify_ms_p95: Option<f64>,
    server_hmac_verify_ms_ci95_low: Option<f64>,
    server_hmac_verify_ms_ci95_high: Option<f64>,
    server_ml_dsa_verify_ms_median: Option<f64>,
    server_ml_dsa_verify_ms_iqr: Option<f64>,
    server_ml_dsa_verify_ms_p95: Option<f64>,
    server_ml_dsa_verify_ms_ci95_low: Option<f64>,
    server_ml_dsa_verify_ms_ci95_high: Option<f64>,
    server_slh_dsa_verify_ms_median: Option<f64>,
    server_slh_dsa_verify_ms_iqr: Option<f64>,
    server_slh_dsa_verify_ms_p95: Option<f64>,
    server_slh_dsa_verify_ms_ci95_low: Option<f64>,
    server_slh_dsa_verify_ms_ci95_high: Option<f64>,
    server_fn_dsa_verify_ms_median: Option<f64>,
    server_fn_dsa_verify_ms_iqr: Option<f64>,
    server_fn_dsa_verify_ms_p95: Option<f64>,
    server_fn_dsa_verify_ms_ci95_low: Option<f64>,
    server_fn_dsa_verify_ms_ci95_high: Option<f64>,
    server_verify_ms_median: Option<f64>,
    server_verify_ms_iqr: Option<f64>,
    server_verify_ms_p95: Option<f64>,
    server_verify_ms_ci95_low: Option<f64>,
    server_verify_ms_ci95_high: Option<f64>,
    server_total_ms_median: Option<f64>,
    server_total_ms_iqr: Option<f64>,
    server_total_ms_p95: Option<f64>,
    server_total_ms_ci95_low: Option<f64>,
    server_total_ms_ci95_high: Option<f64>,
    manifest_size_median: Option<f64>,
    manifest_size_iqr: Option<f64>,
    manifest_size_p95: Option<f64>,
    manifest_size_ci95_low: Option<f64>,
    manifest_size_ci95_high: Option<f64>,
    manifest_core_bytes_median: Option<f64>,
    manifest_core_bytes_iqr: Option<f64>,
    manifest_core_bytes_p95: Option<f64>,
    manifest_core_bytes_ci95_low: Option<f64>,
    manifest_core_bytes_ci95_high: Option<f64>,
    manifest_core_cbor_bytes_median: Option<f64>,
    manifest_core_cbor_bytes_iqr: Option<f64>,
    manifest_core_cbor_bytes_p95: Option<f64>,
    manifest_core_cbor_bytes_ci95_low: Option<f64>,
    manifest_core_cbor_bytes_ci95_high: Option<f64>,
    manifest_envelope_bytes_median: Option<f64>,
    manifest_envelope_bytes_iqr: Option<f64>,
    manifest_envelope_bytes_p95: Option<f64>,
    manifest_envelope_bytes_ci95_low: Option<f64>,
    manifest_envelope_bytes_ci95_high: Option<f64>,
    rsa_signature_bytes_median: Option<f64>,
    rsa_signature_bytes_iqr: Option<f64>,
    rsa_signature_bytes_p95: Option<f64>,
    rsa_signature_bytes_ci95_low: Option<f64>,
    rsa_signature_bytes_ci95_high: Option<f64>,
    eddsa_signature_bytes_median: Option<f64>,
    eddsa_signature_bytes_iqr: Option<f64>,
    eddsa_signature_bytes_p95: Option<f64>,
    eddsa_signature_bytes_ci95_low: Option<f64>,
    eddsa_signature_bytes_ci95_high: Option<f64>,
    ecdsa_signature_bytes_median: Option<f64>,
    ecdsa_signature_bytes_iqr: Option<f64>,
    ecdsa_signature_bytes_p95: Option<f64>,
    ecdsa_signature_bytes_ci95_low: Option<f64>,
    ecdsa_signature_bytes_ci95_high: Option<f64>,
    hmac_signature_bytes_median: Option<f64>,
    hmac_signature_bytes_iqr: Option<f64>,
    hmac_signature_bytes_p95: Option<f64>,
    hmac_signature_bytes_ci95_low: Option<f64>,
    hmac_signature_bytes_ci95_high: Option<f64>,
    ml_dsa_signature_bytes_median: Option<f64>,
    ml_dsa_signature_bytes_iqr: Option<f64>,
    ml_dsa_signature_bytes_p95: Option<f64>,
    ml_dsa_signature_bytes_ci95_low: Option<f64>,
    ml_dsa_signature_bytes_ci95_high: Option<f64>,
    slh_dsa_signature_bytes_median: Option<f64>,
    slh_dsa_signature_bytes_iqr: Option<f64>,
    slh_dsa_signature_bytes_p95: Option<f64>,
    slh_dsa_signature_bytes_ci95_low: Option<f64>,
    slh_dsa_signature_bytes_ci95_high: Option<f64>,
    fn_dsa_signature_bytes_median: Option<f64>,
    fn_dsa_signature_bytes_iqr: Option<f64>,
    fn_dsa_signature_bytes_p95: Option<f64>,
    fn_dsa_signature_bytes_ci95_low: Option<f64>,
    fn_dsa_signature_bytes_ci95_high: Option<f64>,
    signature_size_median: Option<f64>,
    signature_size_iqr: Option<f64>,
    signature_size_p95: Option<f64>,
    signature_size_ci95_low: Option<f64>,
    signature_size_ci95_high: Option<f64>,
    manifest_overhead_pct_median: Option<f64>,
    manifest_overhead_pct_iqr: Option<f64>,
    manifest_overhead_pct_p95: Option<f64>,
    manifest_overhead_pct_ci95_low: Option<f64>,
    manifest_overhead_pct_ci95_high: Option<f64>,
    signature_overhead_pct_median: Option<f64>,
    signature_overhead_pct_iqr: Option<f64>,
    signature_overhead_pct_p95: Option<f64>,
    signature_overhead_pct_ci95_low: Option<f64>,
    signature_overhead_pct_ci95_high: Option<f64>,
    storage_amplification_median: Option<f64>,
    storage_amplification_iqr: Option<f64>,
    storage_amplification_p95: Option<f64>,
    storage_amplification_ci95_low: Option<f64>,
    storage_amplification_ci95_high: Option<f64>,
    client_total_mib_s_median: Option<f64>,
    client_total_mib_s_iqr: Option<f64>,
    client_total_mib_s_p95: Option<f64>,
    client_total_mib_s_ci95_low: Option<f64>,
    client_total_mib_s_ci95_high: Option<f64>,
    server_hash_mib_s_median: Option<f64>,
    server_hash_mib_s_iqr: Option<f64>,
    server_hash_mib_s_p95: Option<f64>,
    server_hash_mib_s_ci95_low: Option<f64>,
    server_hash_mib_s_ci95_high: Option<f64>,
    server_verify_mib_s_median: Option<f64>,
    server_verify_mib_s_iqr: Option<f64>,
    server_verify_mib_s_p95: Option<f64>,
    server_verify_mib_s_ci95_low: Option<f64>,
    server_verify_mib_s_ci95_high: Option<f64>,
    server_total_mib_s_median: Option<f64>,
    server_total_mib_s_iqr: Option<f64>,
    server_total_mib_s_p95: Option<f64>,
    server_total_mib_s_ci95_low: Option<f64>,
    server_total_mib_s_ci95_high: Option<f64>,
    ratio_vs_rsa_pss_total_median: Option<f64>,
    ratio_vs_rsa_pss_server_total_median: Option<f64>,
}

/// One row in the long-form primary evidence metrics table.
///
/// Compared to the wide summary CSV, this format is easier to filter,
/// pivot, and import into statistical tools. Each metric occupies exactly
/// one row with explicit coverage and applicability metadata, so null values
/// are always interpretable.
#[derive(Debug, Clone, Serialize)]
struct EvidenceMetricRow {
    benchmark_scenario: String,
    storage_state: String,
    signature_profile: String,
    hash_algorithm: String,
    bucket: String,
    metric_name: String,
    metric_unit: &'static str,
    /// Scope of the metric: "client" | "server" | "artifact" | "setup"
    metric_scope: &'static str,
    /// "applicable" | "not_applicable" | "not_configured"
    metric_applicability: &'static str,
    /// Number of successful runs that contributed a value for this metric.
    n: Option<usize>,
    /// Fraction of successful runs where this metric was present (0.0–1.0).
    coverage: Option<f64>,
    median: Option<f64>,
    iqr: Option<f64>,
    p95: Option<f64>,
    ci95_low: Option<f64>,
    ci95_high: Option<f64>,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    generated_at: String,
    cli_config: CliReportConfig,
    environment: EnvironmentMetadata,
    raw_runs: Vec<RunRecord>,
    summaries: Vec<ConditionSummary>,
    /// Long-form primary evidence metrics table (one metric per row).
    evidence_metrics: Vec<EvidenceMetricRow>,
}

#[derive(Debug, Serialize)]
struct CliReportConfig {
    base_url: String,
    dataset_dir: String,
    output_dir: String,
    profiles: Vec<String>,
    hashes: Vec<String>,
    buckets: Vec<String>,
    scenarios: Vec<String>,
    measured_runs: u32,
    warmup_runs: u32,
    inter_run_delay_ms: u64,
    seed: u64,
    operations_endpoint: Option<String>,
    bootstrap_samples: usize,
    storage_state_label: String,
    campaign_label: Option<String>,
    repeat_index: Option<u32>,
    benchmark_setup: BenchmarkSetup,
}

#[derive(Debug, Serialize)]
struct EnvironmentMetadata {
    git_commit: Option<String>,
    git_dirty: Option<bool>,
    build_profile: String,
    os: String,
    arch: String,
    logical_cores: Option<usize>,
    cpu_model: Option<String>,
    total_memory_bytes: Option<u64>,
    hostname: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if cli.measured_runs == 0 {
        bail!("measured-runs must be >= 1");
    }

    let seed = cli.seed.unwrap_or_else(rand::random::<u64>);
    cli.seed = Some(seed);

    let mut rng = StdRng::seed_from_u64(seed);
    let normalized_profiles = normalize_profiles(&cli.profiles)?;
    let normalized_hashes = normalize_hashes(&cli.hashes)?;
    let normalized_scenarios = normalize_scenarios(&cli.scenarios)?;
    let bucket_specs = parse_bucket_specs(&cli.buckets)?;

    if !cli.dataset_dir.exists() {
        bail!(
            "Dataset directory does not exist: {}. Generate it first, e.g. `python3 scripts/generate_benchmark_dataset.py --output-dir {}`",
            cli.dataset_dir.display(),
            cli.dataset_dir.display()
        );
    }
    if !cli.dataset_dir.is_dir() {
        bail!(
            "Dataset path is not a directory: {}",
            cli.dataset_dir.display()
        );
    }

    let all_files = collect_files_recursively(&cli.dataset_dir)
        .with_context(|| format!("Failed to scan dataset dir: {}", cli.dataset_dir.display()))?;
    if all_files.is_empty() {
        bail!(
            "Dataset directory has no files: {}",
            cli.dataset_dir.display()
        );
    }

    let dataset_manifest = load_dataset_manifest(&cli.dataset_dir);
    let dataset_file_types = collect_dataset_file_types(&dataset_manifest);

    let files_by_bucket = index_files_by_bucket(&all_files, &bucket_specs)?;

    let conditions = build_conditions(
        &normalized_profiles,
        &normalized_hashes,
        &bucket_specs,
        &normalized_scenarios,
    );
    if conditions.is_empty() {
        bail!("No benchmark conditions generated");
    }

    let jobs = build_jobs(&conditions, cli.warmup_runs, cli.measured_runs, &mut rng);

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("Failed to build HTTP client")?;

    tokio::fs::create_dir_all(&cli.output_dir)
        .await
        .with_context(|| format!("Failed to create output dir: {}", cli.output_dir.display()))?;

    let mut run_records: Vec<RunRecord> = Vec::with_capacity(jobs.len());
    let mut bucket_file_cycles = files_by_bucket.clone();
    for files in bucket_file_cycles.values_mut() {
        files.shuffle(&mut rng);
    }
    let mut bucket_offsets: HashMap<String, usize> = bucket_file_cycles
        .keys()
        .map(|bucket| (bucket.clone(), 0usize))
        .collect();
    let mut selected_files: HashMap<FileSelectionKey, PathBuf> = HashMap::new();
    let mut previous_phase: Option<Phase> = None;

    for (idx, job) in jobs.iter().enumerate() {
        if previous_phase != Some(job.phase) {
            for files in bucket_file_cycles.values_mut() {
                files.shuffle(&mut rng);
            }
            for offset in bucket_offsets.values_mut() {
                *offset = 0;
            }
            previous_phase = Some(job.phase);
        }

        let selection_key = FileSelectionKey {
            phase: job.phase,
            ordinal: job.ordinal,
            bucket: job.condition.bucket.clone(),
        };
        let selected = if let Some(existing) = selected_files.get(&selection_key) {
            existing.clone()
        } else {
            let candidate_files = bucket_file_cycles
                .get_mut(&job.condition.bucket)
                .ok_or_else(|| anyhow!("Missing files for bucket {}", job.condition.bucket))?;

            if candidate_files.is_empty() {
                bail!("No files found for bucket {}", job.condition.bucket);
            }

            let offset = bucket_offsets
                .entry(job.condition.bucket.clone())
                .or_insert(0usize);
            if *offset >= candidate_files.len() {
                candidate_files.shuffle(&mut rng);
                *offset = 0;
            }

            let selected = candidate_files[*offset].clone();
            *offset += 1;
            selected_files.insert(selection_key, selected.clone());
            selected
        };

        let run_idx = (idx + 1) as u64;
        let record =
            run_single_job(&client, &cli, run_idx, job, &selected, &dataset_manifest).await;

        let is_failed = record.error.is_some();
        run_records.push(record);

        if is_failed && cli.fail_fast {
            bail!("Run {} failed and --fail-fast is set", run_idx);
        }

        if cli.inter_run_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(cli.inter_run_delay_ms)).await;
        }
    }

    let summaries = build_condition_summaries(&run_records, cli.bootstrap_samples, seed);
    let evidence_metrics = build_evidence_metrics(&summaries, cli.bootstrap_samples, seed);
    let benchmark_setup = BenchmarkSetup::from_resolved_options(
        &normalized_profiles,
        &normalized_hashes,
        &bucket_specs
            .iter()
            .map(|b| b.label.clone())
            .collect::<Vec<_>>(),
        &normalized_scenarios,
        &[cli.storage_state_label.clone()],
        &dataset_file_types,
    );

    let report = BenchmarkReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        cli_config: CliReportConfig {
            base_url: cli.base_url.clone(),
            dataset_dir: cli.dataset_dir.display().to_string(),
            output_dir: cli.output_dir.display().to_string(),
            profiles: normalized_profiles.clone(),
            hashes: normalized_hashes.clone(),
            buckets: bucket_specs.iter().map(|b| b.label.clone()).collect(),
            scenarios: normalized_scenarios.clone(),
            measured_runs: cli.measured_runs,
            warmup_runs: cli.warmup_runs,
            inter_run_delay_ms: cli.inter_run_delay_ms,
            seed,
            operations_endpoint: cli.operations_endpoint.clone(),
            bootstrap_samples: cli.bootstrap_samples,
            storage_state_label: cli.storage_state_label.clone(),
            campaign_label: cli.campaign_label.clone(),
            repeat_index: cli.repeat_index,
            benchmark_setup,
        },
        environment: collect_environment_metadata(),
        raw_runs: run_records.clone(),
        summaries: summaries.clone(),
        evidence_metrics: evidence_metrics.clone(),
    };

    write_outputs(
        &cli.output_dir,
        &report,
        &run_records,
        &summaries,
        &evidence_metrics,
    )
    .await?;

    println!("Benchmark completed.");
    println!("Seed: {}", seed);
    println!("Raw runs: {}", report.raw_runs.len());
    println!("Summaries: {}", report.summaries.len());
    println!("Output dir: {}", cli.output_dir.display());

    Ok(())
}

async fn run_single_job(
    client: &Client,
    cli: &Cli,
    run_idx: u64,
    job: &Job,
    selected_file: &PathBuf,
    manifest: &DatasetManifest,
) -> RunRecord {
    // Resolve dataset-relative provenance fields.
    let (dataset_seed, dataset_relative_path, dataset_bucket_index, dataset_file_type) =
        if let Some(entry) = manifest.entries.get(selected_file.to_str().unwrap_or("")) {
            (
                Some(entry.seed.clone()),
                Some(entry.relative_path.clone()),
                Some(entry.index),
                Some(entry.file_type.clone()),
            )
        } else {
            // Fall back to manifest seed even if the file isn't in the manifest.
            (manifest.seed.clone(), None, None, None)
        };

    let server_telemetry_status_default = if cli.operations_endpoint.is_some() {
        ServerTelemetryStatus::Error // will be overwritten on success
    } else {
        ServerTelemetryStatus::NotConfigured
    };

    let mut record = RunRecord {
        run_index: run_idx,
        phase: job.phase,
        condition_signature_profile: job.condition.signature_profile.clone(),
        condition_hash_algorithm: job.condition.hash_algorithm.clone(),
        condition_bucket: job.condition.bucket.clone(),
        benchmark_scenario: job.condition.benchmark_scenario.clone(),
        storage_state_label: cli.storage_state_label.clone(),
        campaign_label: cli.campaign_label.clone(),
        repeat_index: cli.repeat_index,
        dataset_seed,
        dataset_relative_path,
        dataset_bucket_index,
        dataset_file_type,
        file_path: selected_file.display().to_string(),
        file_size_bytes: 0,
        request_id: None,
        upload_http_ok: false,
        process_http_ok: false,
        verify_http_ok: false,
        scenario_status: ScenarioStatus::NotAttempted,
        scenario_success: false,
        verify_outcome: VerifyOutcome::NotAttempted,
        server_telemetry_status: server_telemetry_status_default,
        verify_overall_ok: None,
        verify_signature_ok: None,
        verify_object_ok: None,
        verify_file_hash_match: None,
        verify_error_details: None,
        setup_upload_ms: None,
        setup_process_ms: None,
        client_upload_ms: None,
        client_process_ms: None,
        client_verify_ms: None,
        client_total_ms: None,
        manifest_size_bytes: None,
        manifest_core_bytes: None,
        manifest_core_cbor_bytes: None,
        manifest_envelope_bytes: None,
        rsa_signature_bytes: None,
        eddsa_signature_bytes: None,
        ecdsa_signature_bytes: None,
        hmac_signature_bytes: None,
        ml_dsa_signature_bytes: None,
        slh_dsa_signature_bytes: None,
        fn_dsa_signature_bytes: None,
        total_signature_bytes: None,
        manifest_overhead_pct: None,
        signature_overhead_pct: None,
        storage_amplification: None,
        storage_bytes_written: None,
        storage_bytes_read: None,
        client_upload_mib_s: None,
        client_process_mib_s: None,
        client_verify_mib_s: None,
        client_total_mib_s: None,
        server_hash_mib_s: None,
        server_verify_mib_s: None,
        server_total_mib_s: None,
        server_process_gateway_ms: None,
        server_verify_gateway_ms: None,
        server_hash_ms: None,
        server_object_exists_check_ms: None,
        server_object_store_ms: None,
        server_object_store_hit: None,
        server_multipart_used: None,
        server_hash_bytes_read: None,
        server_hash_bytes_written: None,
        server_manifest_canonicalize_ms: None,
        server_db_persist_ms: None,
        server_rsa_sign_ms: None,
        server_eddsa_sign_ms: None,
        server_ecdsa_sign_ms: None,
        server_hmac_sign_ms: None,
        server_ml_dsa_sign_ms: None,
        server_slh_dsa_sign_ms: None,
        server_fn_dsa_sign_ms: None,
        server_eddsa_verify_ms: None,
        server_ecdsa_verify_ms: None,
        server_hmac_verify_ms: None,
        server_ml_dsa_verify_ms: None,
        server_slh_dsa_verify_ms: None,
        server_fn_dsa_verify_ms: None,
        server_manifest_fetch_db_lookup_ms: None,
        server_verify_hash_ms: None,
        server_verify_canonicalize_ms: None,
        server_signature_verify_ms: None,
        server_stored_object_verify_ms: None,
        server_uploaded_content_verify_ms: None,
        server_verify_ms: None,
        server_total_ms: None,
        error_stage: None,
        error: None,
    };

    match execute_single_flow(client, cli, &job.condition, selected_file).await {
        Ok(flow) => {
            record.file_size_bytes = flow.file_size_bytes;
            record.request_id = Some(flow.request_id.clone());
            record.upload_http_ok = flow.upload_http_ok;
            record.process_http_ok = flow.process_http_ok;
            record.verify_http_ok = flow.verify_http_ok;
            record.scenario_status = flow.scenario_status;
            record.scenario_success = matches!(flow.scenario_status, ScenarioStatus::Ok);
            record.verify_outcome = flow.verify_outcome;
            record.server_telemetry_status = flow.server_telemetry_status;
            record.verify_overall_ok = flow.verify_overall_ok;
            record.verify_signature_ok = flow.verify_signature_ok;
            record.verify_object_ok = flow.verify_object_ok;
            record.verify_file_hash_match = flow.verify_file_hash_match;
            record.verify_error_details = flow.verify_error_details.clone();
            record.setup_upload_ms = Some(flow.setup_upload_ms);
            record.setup_process_ms = Some(flow.setup_process_ms);
            record.client_upload_ms = flow.client_upload_ms;
            record.client_process_ms = flow.client_process_ms;
            record.client_verify_ms = flow.client_verify_ms;
            record.client_total_ms = flow.client_total_ms;
            record.manifest_size_bytes = Some(flow.manifest_size_bytes);
            record.manifest_core_bytes = Some(flow.manifest_core_bytes);
            record.manifest_core_cbor_bytes = Some(flow.manifest_core_cbor_bytes);
            record.manifest_envelope_bytes = Some(flow.manifest_envelope_bytes);
            record.rsa_signature_bytes = flow.rsa_signature_bytes;
            record.eddsa_signature_bytes = flow.eddsa_signature_bytes;
            record.ecdsa_signature_bytes = flow.ecdsa_signature_bytes;
            record.hmac_signature_bytes = flow.hmac_signature_bytes;
            record.ml_dsa_signature_bytes = flow.ml_dsa_signature_bytes;
            record.slh_dsa_signature_bytes = flow.slh_dsa_signature_bytes;
            record.fn_dsa_signature_bytes = flow.fn_dsa_signature_bytes;
            record.total_signature_bytes = flow.total_signature_bytes;
            record.manifest_overhead_pct = flow.manifest_overhead_pct;
            record.signature_overhead_pct = flow.signature_overhead_pct;
            record.storage_amplification = flow.storage_amplification;
            record.storage_bytes_written = flow.storage_bytes_written;
            record.storage_bytes_read = flow.storage_bytes_read;
            record.client_upload_mib_s = flow.client_upload_mib_s;
            record.client_process_mib_s = flow.client_process_mib_s;
            record.client_verify_mib_s = flow.client_verify_mib_s;
            record.client_total_mib_s = flow.client_total_mib_s;
            record.server_hash_mib_s = flow.server_hash_mib_s;
            record.server_verify_mib_s = flow.server_verify_mib_s;
            record.server_total_mib_s = flow.server_total_mib_s;
            record.server_process_gateway_ms = flow.server_process_gateway_ms;
            record.server_verify_gateway_ms = flow.server_verify_gateway_ms;
            record.server_hash_ms = flow.server_hash_ms;
            record.server_object_exists_check_ms = flow.server_object_exists_check_ms;
            record.server_object_store_ms = flow.server_object_store_ms;
            record.server_object_store_hit = flow.server_object_store_hit;
            record.server_multipart_used = flow.server_multipart_used;
            record.server_hash_bytes_read = flow.server_hash_bytes_read;
            record.server_hash_bytes_written = flow.server_hash_bytes_written;
            record.server_manifest_canonicalize_ms = flow.server_manifest_canonicalize_ms;
            record.server_db_persist_ms = flow.server_db_persist_ms;
            record.server_rsa_sign_ms = flow.server_rsa_sign_ms;
            record.server_eddsa_sign_ms = flow.server_eddsa_sign_ms;
            record.server_ecdsa_sign_ms = flow.server_ecdsa_sign_ms;
            record.server_hmac_sign_ms = flow.server_hmac_sign_ms;
            record.server_ml_dsa_sign_ms = flow.server_ml_dsa_sign_ms;
            record.server_slh_dsa_sign_ms = flow.server_slh_dsa_sign_ms;
            record.server_fn_dsa_sign_ms = flow.server_fn_dsa_sign_ms;
            record.server_eddsa_verify_ms = flow.server_eddsa_verify_ms;
            record.server_ecdsa_verify_ms = flow.server_ecdsa_verify_ms;
            record.server_hmac_verify_ms = flow.server_hmac_verify_ms;
            record.server_ml_dsa_verify_ms = flow.server_ml_dsa_verify_ms;
            record.server_slh_dsa_verify_ms = flow.server_slh_dsa_verify_ms;
            record.server_fn_dsa_verify_ms = flow.server_fn_dsa_verify_ms;
            record.server_manifest_fetch_db_lookup_ms = flow.server_manifest_fetch_db_lookup_ms;
            record.server_verify_hash_ms = flow.server_verify_hash_ms;
            record.server_verify_canonicalize_ms = flow.server_verify_canonicalize_ms;
            record.server_signature_verify_ms = flow.server_signature_verify_ms;
            record.server_stored_object_verify_ms = flow.server_stored_object_verify_ms;
            record.server_uploaded_content_verify_ms = flow.server_uploaded_content_verify_ms;
            record.server_verify_ms = flow.server_verify_ms;
            record.server_total_ms = flow.server_total_ms;

            if !matches!(flow.scenario_status, ScenarioStatus::Ok) {
                record.error_stage = Some("scenario".to_string());
                record.error = Some(match flow.verify_error_details.as_deref() {
                    Some(details) if !details.is_empty() => {
                        format!("Verification returned overall_ok=false: {}", details)
                    }
                    _ => "Verification returned overall_ok=false".to_string(),
                });
            }
        }
        Err(err) => {
            let message = err.to_string();
            let stage = classify_error_stage(&message);
            record.error_stage = Some(stage.to_string());
            // setup_upload / setup_process failures → NotAttempted (scenario was never reached)
            // upload / process / verify failures → Failed (within scenario body)
            record.scenario_status = match stage {
                "setup_upload" | "setup_process" => ScenarioStatus::NotAttempted,
                _ => ScenarioStatus::Failed,
            };
            record.scenario_success = false;
            record.verify_outcome = match stage {
                "setup_upload" | "setup_process" | "upload" | "process" => {
                    // Scenario body not reached or verify step not reached
                    let scenario = ScenarioKind::from_label(&job.condition.benchmark_scenario)
                        .ok()
                        .unwrap_or(ScenarioKind::Workflow);
                    if scenario == ScenarioKind::SignOnly {
                        VerifyOutcome::NotApplicable
                    } else {
                        VerifyOutcome::NotAttempted
                    }
                }
                "verify" => VerifyOutcome::Failed,
                _ => VerifyOutcome::NotAttempted,
            };
            match stage {
                "upload" => {}
                "process" => {
                    record.upload_http_ok = true;
                }
                "verify" => {
                    record.upload_http_ok = true;
                    record.process_http_ok = true;
                }
                "setup_upload" => {}
                "setup_process" => {
                    record.upload_http_ok = true;
                }
                _ => {}
            }
            record.error = Some(message);
        }
    }

    println!(
        "[{} #{}/{}] scenario={} profile={} hash={} bucket={} file={} status={}",
        match job.phase {
            Phase::Warmup => "warmup",
            Phase::Measured => "measured",
        },
        job.ordinal,
        if matches!(job.phase, Phase::Warmup) {
            cli.warmup_runs
        } else {
            cli.measured_runs
        },
        job.condition.benchmark_scenario,
        job.condition.signature_profile,
        job.condition.hash_algorithm,
        job.condition.bucket,
        selected_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>"),
        if record.error.is_some() {
            "failed"
        } else {
            "ok"
        }
    );

    record
}

#[derive(Debug)]
struct FlowResult {
    scenario_status: ScenarioStatus,
    verify_outcome: VerifyOutcome,
    server_telemetry_status: ServerTelemetryStatus,
    upload_http_ok: bool,
    process_http_ok: bool,
    verify_http_ok: bool,
    request_id: String,
    /// Upload time for the fixture setup step (always present on Ok flow).
    setup_upload_ms: f64,
    /// Process/sign time for the fixture setup step (always present on Ok flow).
    setup_process_ms: f64,
    verify_overall_ok: Option<bool>,
    verify_signature_ok: Option<bool>,
    verify_object_ok: Option<bool>,
    verify_file_hash_match: Option<bool>,
    verify_error_details: Option<String>,
    file_size_bytes: u64,
    client_upload_ms: Option<f64>,
    client_process_ms: Option<f64>,
    client_verify_ms: Option<f64>,
    client_total_ms: Option<f64>,
    manifest_size_bytes: usize,
    manifest_core_bytes: usize,
    manifest_core_cbor_bytes: usize,
    manifest_envelope_bytes: usize,
    rsa_signature_bytes: Option<usize>,
    eddsa_signature_bytes: Option<usize>,
    ecdsa_signature_bytes: Option<usize>,
    hmac_signature_bytes: Option<usize>,
    ml_dsa_signature_bytes: Option<usize>,
    slh_dsa_signature_bytes: Option<usize>,
    fn_dsa_signature_bytes: Option<usize>,
    total_signature_bytes: Option<usize>,
    manifest_overhead_pct: Option<f64>,
    signature_overhead_pct: Option<f64>,
    storage_amplification: Option<f64>,
    storage_bytes_written: Option<u64>,
    storage_bytes_read: Option<u64>,
    client_upload_mib_s: Option<f64>,
    client_process_mib_s: Option<f64>,
    client_verify_mib_s: Option<f64>,
    client_total_mib_s: Option<f64>,
    server_hash_mib_s: Option<f64>,
    server_verify_mib_s: Option<f64>,
    server_total_mib_s: Option<f64>,
    server_process_gateway_ms: Option<f64>,
    server_verify_gateway_ms: Option<f64>,
    server_hash_ms: Option<f64>,
    server_object_exists_check_ms: Option<f64>,
    server_object_store_ms: Option<f64>,
    server_object_store_hit: Option<bool>,
    server_multipart_used: Option<bool>,
    server_hash_bytes_read: Option<u64>,
    server_hash_bytes_written: Option<u64>,
    server_manifest_canonicalize_ms: Option<f64>,
    server_db_persist_ms: Option<f64>,
    server_rsa_sign_ms: Option<f64>,
    server_eddsa_sign_ms: Option<f64>,
    server_ecdsa_sign_ms: Option<f64>,
    server_hmac_sign_ms: Option<f64>,
    server_ml_dsa_sign_ms: Option<f64>,
    server_slh_dsa_sign_ms: Option<f64>,
    server_fn_dsa_sign_ms: Option<f64>,
    server_eddsa_verify_ms: Option<f64>,
    server_ecdsa_verify_ms: Option<f64>,
    server_hmac_verify_ms: Option<f64>,
    server_ml_dsa_verify_ms: Option<f64>,
    server_slh_dsa_verify_ms: Option<f64>,
    server_fn_dsa_verify_ms: Option<f64>,
    server_manifest_fetch_db_lookup_ms: Option<f64>,
    server_verify_hash_ms: Option<f64>,
    server_verify_canonicalize_ms: Option<f64>,
    server_signature_verify_ms: Option<f64>,
    server_stored_object_verify_ms: Option<f64>,
    server_uploaded_content_verify_ms: Option<f64>,
    server_verify_ms: Option<f64>,
    server_total_ms: Option<f64>,
}

#[derive(Debug)]
struct ServerMetricValues {
    server_process_gateway_ms: Option<f64>,
    server_verify_gateway_ms: Option<f64>,
    server_hash_ms: Option<f64>,
    server_object_exists_check_ms: Option<f64>,
    server_object_store_ms: Option<f64>,
    server_object_store_hit: Option<bool>,
    server_multipart_used: Option<bool>,
    server_hash_bytes_read: Option<u64>,
    server_hash_bytes_written: Option<u64>,
    server_manifest_canonicalize_ms: Option<f64>,
    server_db_persist_ms: Option<f64>,
    server_rsa_sign_ms: Option<f64>,
    server_eddsa_sign_ms: Option<f64>,
    server_ecdsa_sign_ms: Option<f64>,
    server_hmac_sign_ms: Option<f64>,
    server_ml_dsa_sign_ms: Option<f64>,
    server_slh_dsa_sign_ms: Option<f64>,
    server_fn_dsa_sign_ms: Option<f64>,
    server_eddsa_verify_ms: Option<f64>,
    server_ecdsa_verify_ms: Option<f64>,
    server_hmac_verify_ms: Option<f64>,
    server_ml_dsa_verify_ms: Option<f64>,
    server_slh_dsa_verify_ms: Option<f64>,
    server_fn_dsa_verify_ms: Option<f64>,
    server_manifest_fetch_db_lookup_ms: Option<f64>,
    server_verify_hash_ms: Option<f64>,
    server_verify_canonicalize_ms: Option<f64>,
    server_signature_verify_ms: Option<f64>,
    server_stored_object_verify_ms: Option<f64>,
    server_uploaded_content_verify_ms: Option<f64>,
    server_verify_ms: Option<f64>,
    storage_bytes_written: Option<u64>,
    storage_bytes_read: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScenarioKind {
    Workflow,
    SignOnly,
    VerifyManifest,
    VerifyStored,
    VerifyUploaded,
    VerifyFull,
}

impl ScenarioKind {
    fn from_label(label: &str) -> Result<Self> {
        match label.trim().to_ascii_lowercase().as_str() {
            "workflow" | "workflow_full" | "full" => Ok(Self::Workflow),
            "sign_only" | "process_only" | "sign" => Ok(Self::SignOnly),
            "verify_manifest" | "verify_manifest_only" | "manifest_only" => {
                Ok(Self::VerifyManifest)
            }
            "verify_stored" | "verify_object" | "verify_stored_object" => Ok(Self::VerifyStored),
            "verify_uploaded" | "verify_uploaded_only" | "verify_no_object" => {
                Ok(Self::VerifyUploaded)
            }
            "verify_full" | "verify_with_object" => Ok(Self::VerifyFull),
            other => bail!("Unsupported benchmark scenario '{}'", other),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Workflow => "workflow",
            Self::SignOnly => "sign_only",
            Self::VerifyManifest => "verify_manifest",
            Self::VerifyStored => "verify_stored",
            Self::VerifyUploaded => "verify_uploaded",
            Self::VerifyFull => "verify_full",
        }
    }
}

async fn execute_single_flow(
    client: &Client,
    cli: &Cli,
    condition: &Condition,
    file_path: &Path,
) -> Result<FlowResult> {
    let scenario = ScenarioKind::from_label(&condition.benchmark_scenario)?;
    let file_size = tokio::fs::metadata(file_path)
        .await
        .with_context(|| {
            format!(
                "Failed to read dataset file metadata: {}",
                file_path.display()
            )
        })?
        .len();

    let fixture = prepare_signed_fixture(client, cli, condition, file_path, scenario).await?;
    let cleanup_path = fixture.upload.file_path.clone();

    let flow_result: Result<FlowResult> = async {
        let artifact_metrics = compute_artifact_metrics(&fixture.process.manifest, file_size)?;

        let mut client_upload_ms = None;
        let mut client_process_ms = None;
        let mut client_verify_ms = None;
        let mut verify_overall_ok = None;
        let mut verify_signature_ok = None;
        let mut verify_object_ok = None;
        let mut verify_file_hash_match = None;
        let mut verify_error_details = None;
        let mut upload_http_ok = true;
        let mut process_http_ok = true;
        let mut verify_http_ok = false;
        let scenario_status;
        let verify_outcome;

        match scenario {
            ScenarioKind::Workflow => {
                let verify = verify_request_call(
                    client,
                    cli,
                    &fixture.request_id,
                    true,
                    Some(fixture.upload.file_path.clone()),
                )
                .await
                .map_err(|err| stage_error("verify", err))?;
                // Upload+process are scenario body for workflow
                client_upload_ms = Some(fixture.client_upload_ms);
                client_process_ms = Some(fixture.client_process_ms);
                apply_verify_result(
                    &verify,
                    &mut client_verify_ms,
                    &mut verify_overall_ok,
                    &mut verify_http_ok,
                    &mut verify_signature_ok,
                    &mut verify_object_ok,
                    &mut verify_file_hash_match,
                    &mut verify_error_details,
                );
                scenario_status = if verify.verify.overall_ok {
                    ScenarioStatus::Ok
                } else {
                    ScenarioStatus::Failed
                };
                verify_outcome = if verify.verify.overall_ok {
                    VerifyOutcome::Ok
                } else {
                    VerifyOutcome::Failed
                };
            }
            ScenarioKind::SignOnly => {
                // Upload+process are scenario body for sign_only; no verify step
                client_upload_ms = Some(fixture.client_upload_ms);
                client_process_ms = Some(fixture.client_process_ms);
                scenario_status = ScenarioStatus::Ok;
                verify_outcome = VerifyOutcome::NotApplicable;
            }
            ScenarioKind::VerifyManifest => {
                // Upload+process are fixture setup only; scenario body is verify
                let verify = verify_request_call(client, cli, &fixture.request_id, false, None)
                    .await
                    .map_err(|err| stage_error("verify", err))?;
                apply_verify_result(
                    &verify,
                    &mut client_verify_ms,
                    &mut verify_overall_ok,
                    &mut verify_http_ok,
                    &mut verify_signature_ok,
                    &mut verify_object_ok,
                    &mut verify_file_hash_match,
                    &mut verify_error_details,
                );
                scenario_status = if verify.verify.overall_ok {
                    ScenarioStatus::Ok
                } else {
                    ScenarioStatus::Failed
                };
                verify_outcome = if verify.verify.overall_ok {
                    VerifyOutcome::Ok
                } else {
                    VerifyOutcome::Failed
                };
            }
            ScenarioKind::VerifyStored => {
                let verify = verify_request_call(client, cli, &fixture.request_id, true, None)
                    .await
                    .map_err(|err| stage_error("verify", err))?;
                apply_verify_result(
                    &verify,
                    &mut client_verify_ms,
                    &mut verify_overall_ok,
                    &mut verify_http_ok,
                    &mut verify_signature_ok,
                    &mut verify_object_ok,
                    &mut verify_file_hash_match,
                    &mut verify_error_details,
                );
                scenario_status = if verify.verify.overall_ok {
                    ScenarioStatus::Ok
                } else {
                    ScenarioStatus::Failed
                };
                verify_outcome = if verify.verify.overall_ok {
                    VerifyOutcome::Ok
                } else {
                    VerifyOutcome::Failed
                };
            }
            ScenarioKind::VerifyUploaded => {
                let verify = verify_request_call(
                    client,
                    cli,
                    &fixture.request_id,
                    false,
                    Some(fixture.upload.file_path.clone()),
                )
                .await
                .map_err(|err| stage_error("verify", err))?;
                apply_verify_result(
                    &verify,
                    &mut client_verify_ms,
                    &mut verify_overall_ok,
                    &mut verify_http_ok,
                    &mut verify_signature_ok,
                    &mut verify_object_ok,
                    &mut verify_file_hash_match,
                    &mut verify_error_details,
                );
                scenario_status = if verify.verify.overall_ok {
                    ScenarioStatus::Ok
                } else {
                    ScenarioStatus::Failed
                };
                verify_outcome = if verify.verify.overall_ok {
                    VerifyOutcome::Ok
                } else {
                    VerifyOutcome::Failed
                };
            }
            ScenarioKind::VerifyFull => {
                let verify = verify_request_call(
                    client,
                    cli,
                    &fixture.request_id,
                    true,
                    Some(fixture.upload.file_path.clone()),
                )
                .await
                .map_err(|err| stage_error("verify", err))?;
                apply_verify_result(
                    &verify,
                    &mut client_verify_ms,
                    &mut verify_overall_ok,
                    &mut verify_http_ok,
                    &mut verify_signature_ok,
                    &mut verify_object_ok,
                    &mut verify_file_hash_match,
                    &mut verify_error_details,
                );
                scenario_status = if verify.verify.overall_ok {
                    ScenarioStatus::Ok
                } else {
                    ScenarioStatus::Failed
                };
                verify_outcome = if verify.verify.overall_ok {
                    VerifyOutcome::Ok
                } else {
                    VerifyOutcome::Failed
                };
            }
        }

        let (derived, server_telemetry_status) =
            if let Some(ops_url) = cli.operations_endpoint.as_deref() {
                match fetch_operations_metrics(
                    client,
                    ops_url,
                    &cli.api_key,
                    &fixture.request_id,
                    scenario,
                )
                .await
                {
                    Ok(record) => {
                        let status = if operation_metrics_ready(&record, scenario) {
                            ServerTelemetryStatus::Available
                        } else {
                            ServerTelemetryStatus::Partial
                        };
                        (derive_server_metrics(&record), status)
                    }
                    Err(_) => (empty_server_metrics(), ServerTelemetryStatus::Error),
                }
            } else {
                (empty_server_metrics(), ServerTelemetryStatus::NotConfigured)
            };

        let client_total_ms = match scenario {
            ScenarioKind::Workflow | ScenarioKind::SignOnly => {
                sum_stage_millis(&[client_upload_ms, client_process_ms, client_verify_ms])
            }
            ScenarioKind::VerifyManifest
            | ScenarioKind::VerifyStored
            | ScenarioKind::VerifyUploaded
            | ScenarioKind::VerifyFull => client_verify_ms,
        };

        let server_total_ms = match scenario {
            ScenarioKind::Workflow => match (
                derived.server_process_gateway_ms,
                derived.server_verify_gateway_ms,
            ) {
                (Some(process_ms), Some(verify_ms)) => Some(process_ms + verify_ms),
                (Some(process_ms), None) => Some(process_ms),
                (None, Some(verify_ms)) => Some(verify_ms),
                (None, None) => None,
            },
            ScenarioKind::SignOnly => derived.server_process_gateway_ms,
            ScenarioKind::VerifyManifest
            | ScenarioKind::VerifyStored
            | ScenarioKind::VerifyUploaded
            | ScenarioKind::VerifyFull => derived.server_verify_gateway_ms,
        };

        let client_upload_mib_s =
            client_upload_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));
        let client_process_mib_s =
            client_process_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));
        let client_verify_mib_s =
            client_verify_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));
        let client_total_mib_s = client_total_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));
        let server_hash_mib_s = derived
            .server_hash_ms
            .and_then(|ms| throughput_mib_per_s(file_size, ms));
        let server_verify_mib_s = derived
            .server_verify_ms
            .and_then(|ms| throughput_mib_per_s(file_size, ms));
        let server_total_mib_s = server_total_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));

        let storage_bytes_written = match scenario {
            ScenarioKind::Workflow | ScenarioKind::SignOnly => derived.storage_bytes_written,
            ScenarioKind::VerifyManifest | ScenarioKind::VerifyStored => None,
            ScenarioKind::VerifyUploaded | ScenarioKind::VerifyFull => {
                derived.storage_bytes_written
            }
        };
        let storage_bytes_read = match scenario {
            ScenarioKind::Workflow => derived.storage_bytes_read,
            ScenarioKind::SignOnly => None,
            ScenarioKind::VerifyManifest => None,
            ScenarioKind::VerifyStored
            | ScenarioKind::VerifyUploaded
            | ScenarioKind::VerifyFull => derived.storage_bytes_read,
        };

        if !matches!(
            scenario,
            ScenarioKind::Workflow
                | ScenarioKind::SignOnly
                | ScenarioKind::VerifyManifest
                | ScenarioKind::VerifyStored
                | ScenarioKind::VerifyUploaded
                | ScenarioKind::VerifyFull
        ) {
            upload_http_ok = false;
            process_http_ok = false;
        }

        Ok(FlowResult {
            scenario_status,
            verify_outcome,
            server_telemetry_status,
            upload_http_ok,
            process_http_ok,
            verify_http_ok,
            request_id: fixture.request_id.clone(),
            setup_upload_ms: fixture.client_upload_ms,
            setup_process_ms: fixture.client_process_ms,
            verify_overall_ok,
            verify_signature_ok,
            verify_object_ok,
            verify_file_hash_match,
            verify_error_details,
            file_size_bytes: file_size,
            client_upload_ms,
            client_process_ms,
            client_verify_ms,
            client_total_ms,
            manifest_size_bytes: artifact_metrics.manifest_size_bytes,
            manifest_core_bytes: artifact_metrics.manifest_core_bytes,
            manifest_core_cbor_bytes: artifact_metrics.manifest_core_cbor_bytes,
            manifest_envelope_bytes: artifact_metrics.manifest_envelope_bytes,
            rsa_signature_bytes: artifact_metrics.rsa_signature_bytes,
            eddsa_signature_bytes: artifact_metrics.eddsa_signature_bytes,
            ecdsa_signature_bytes: artifact_metrics.ecdsa_signature_bytes,
            hmac_signature_bytes: artifact_metrics.hmac_signature_bytes,
            ml_dsa_signature_bytes: artifact_metrics.ml_dsa_signature_bytes,
            slh_dsa_signature_bytes: artifact_metrics.slh_dsa_signature_bytes,
            fn_dsa_signature_bytes: artifact_metrics.fn_dsa_signature_bytes,
            total_signature_bytes: artifact_metrics.total_signature_bytes,
            manifest_overhead_pct: artifact_metrics.manifest_overhead_pct,
            signature_overhead_pct: artifact_metrics.signature_overhead_pct,
            storage_amplification: artifact_metrics.storage_amplification,
            storage_bytes_written,
            storage_bytes_read,
            client_upload_mib_s,
            client_process_mib_s,
            client_verify_mib_s,
            client_total_mib_s,
            server_hash_mib_s,
            server_verify_mib_s,
            server_total_mib_s,
            server_process_gateway_ms: derived.server_process_gateway_ms,
            server_verify_gateway_ms: derived.server_verify_gateway_ms,
            server_hash_ms: derived.server_hash_ms,
            server_object_exists_check_ms: derived.server_object_exists_check_ms,
            server_object_store_ms: derived.server_object_store_ms,
            server_object_store_hit: derived.server_object_store_hit,
            server_multipart_used: derived.server_multipart_used,
            server_hash_bytes_read: derived.server_hash_bytes_read,
            server_hash_bytes_written: derived.server_hash_bytes_written,
            server_manifest_canonicalize_ms: derived.server_manifest_canonicalize_ms,
            server_db_persist_ms: derived.server_db_persist_ms,
            server_rsa_sign_ms: derived.server_rsa_sign_ms,
            server_eddsa_sign_ms: derived.server_eddsa_sign_ms,
            server_ecdsa_sign_ms: derived.server_ecdsa_sign_ms,
            server_hmac_sign_ms: derived.server_hmac_sign_ms,
            server_ml_dsa_sign_ms: derived.server_ml_dsa_sign_ms,
            server_slh_dsa_sign_ms: derived.server_slh_dsa_sign_ms,
            server_fn_dsa_sign_ms: derived.server_fn_dsa_sign_ms,
            server_eddsa_verify_ms: derived.server_eddsa_verify_ms,
            server_ecdsa_verify_ms: derived.server_ecdsa_verify_ms,
            server_hmac_verify_ms: derived.server_hmac_verify_ms,
            server_ml_dsa_verify_ms: derived.server_ml_dsa_verify_ms,
            server_slh_dsa_verify_ms: derived.server_slh_dsa_verify_ms,
            server_fn_dsa_verify_ms: derived.server_fn_dsa_verify_ms,
            server_manifest_fetch_db_lookup_ms: derived.server_manifest_fetch_db_lookup_ms,
            server_verify_hash_ms: derived.server_verify_hash_ms,
            server_verify_canonicalize_ms: derived.server_verify_canonicalize_ms,
            server_signature_verify_ms: derived.server_signature_verify_ms,
            server_stored_object_verify_ms: derived.server_stored_object_verify_ms,
            server_uploaded_content_verify_ms: derived.server_uploaded_content_verify_ms,
            server_verify_ms: derived.server_verify_ms,
            server_total_ms,
        })
    }
    .await;

    let cleanup_result = cleanup_uploaded_file(client, cli, &cleanup_path).await;
    match (flow_result, cleanup_result) {
        (Err(flow_err), _) => Err(flow_err),
        (Ok(flow), Ok(())) => Ok(flow),
        (Ok(_), Err(cleanup_err)) => Err(stage_error("cleanup_upload", cleanup_err)),
    }
}

#[derive(Debug)]
struct UploadStageResult {
    upload: UploadResponse,
    client_upload_ms: f64,
}

#[derive(Debug)]
struct ProcessStageResult {
    process: ProcessResponse,
    client_process_ms: f64,
}

#[derive(Debug)]
struct VerifyStageResult {
    verify: VerifyResponse,
    client_verify_ms: f64,
}

fn apply_verify_result(
    verify: &VerifyStageResult,
    client_verify_ms: &mut Option<f64>,
    verify_overall_ok: &mut Option<bool>,
    verify_http_ok: &mut bool,
    verify_signature_ok: &mut Option<bool>,
    verify_object_ok: &mut Option<bool>,
    verify_file_hash_match: &mut Option<bool>,
    verify_error_details: &mut Option<String>,
) {
    *client_verify_ms = Some(verify.client_verify_ms);
    *verify_overall_ok = Some(verify.verify.overall_ok);
    *verify_http_ok = true;
    *verify_signature_ok = Some(verify.verify.signature_ok);
    *verify_object_ok = Some(verify.verify.object_ok);
    *verify_file_hash_match = Some(verify.verify.file_hash_match);
    *verify_error_details = if verify.verify.errors.is_empty() {
        None
    } else {
        Some(verify.verify.errors.join(" | "))
    };
}

#[derive(Debug)]
struct PreparedFixture {
    upload: UploadResponse,
    process: ProcessResponse,
    request_id: String,
    client_upload_ms: f64,
    client_process_ms: f64,
}

#[derive(Debug)]
struct ArtifactMetrics {
    manifest_size_bytes: usize,
    manifest_core_bytes: usize,
    manifest_core_cbor_bytes: usize,
    manifest_envelope_bytes: usize,
    rsa_signature_bytes: Option<usize>,
    eddsa_signature_bytes: Option<usize>,
    ecdsa_signature_bytes: Option<usize>,
    hmac_signature_bytes: Option<usize>,
    ml_dsa_signature_bytes: Option<usize>,
    slh_dsa_signature_bytes: Option<usize>,
    fn_dsa_signature_bytes: Option<usize>,
    total_signature_bytes: Option<usize>,
    manifest_overhead_pct: Option<f64>,
    signature_overhead_pct: Option<f64>,
    storage_amplification: Option<f64>,
}

async fn prepare_signed_fixture(
    client: &Client,
    cli: &Cli,
    condition: &Condition,
    file_path: &Path,
    scenario: ScenarioKind,
) -> Result<PreparedFixture> {
    // For workflow/sign_only, upload/process are part of the scenario body.
    // For verify-only scenarios they are fixture setup, so tag errors differently.
    let (upload_tag, process_tag) = match scenario {
        ScenarioKind::Workflow | ScenarioKind::SignOnly => ("upload", "process"),
        _ => ("setup_upload", "setup_process"),
    };

    let upload = upload_dataset_file(client, cli, file_path)
        .await
        .map_err(|err| stage_error(upload_tag, err))?;
    let upload_path = upload.upload.file_path.clone();
    let process = match process_uploaded_file(client, cli, condition, &upload_path).await {
        Ok(process) => process,
        Err(err) => {
            let _ = cleanup_uploaded_file(client, cli, &upload_path).await;
            return Err(stage_error(process_tag, err));
        }
    };

    Ok(PreparedFixture {
        request_id: process.process.manifest.core.request_id.clone(),
        upload: upload.upload,
        process: process.process,
        client_upload_ms: upload.client_upload_ms,
        client_process_ms: process.client_process_ms,
    })
}

async fn upload_dataset_file(
    client: &Client,
    cli: &Cli,
    file_path: &Path,
) -> Result<UploadStageResult> {
    let file_bytes = tokio::fs::read(file_path)
        .await
        .with_context(|| format!("Failed to read dataset file: {}", file_path.display()))?;
    let upload_url = format!("{}/upload", cli.base_url.trim_end_matches('/'));
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid filename for path {}", file_path.display()))?
        .to_string();

    let upload_start = Instant::now();
    let part = multipart::Part::bytes(file_bytes)
        .file_name(filename)
        .mime_str("application/octet-stream")?;
    let form = multipart::Form::new().part("file", part);

    let upload_resp = client
        .post(&upload_url)
        .header("X-API-Key", &cli.api_key)
        .multipart(form)
        .send()
        .await
        .context("Upload request failed")?;

    ensure_success_status(upload_resp.status(), "upload")?;
    let upload: UploadResponse = upload_resp
        .json()
        .await
        .context("Failed to parse /upload response")?;

    Ok(UploadStageResult {
        upload,
        client_upload_ms: upload_start.elapsed().as_secs_f64() * 1000.0,
    })
}

async fn cleanup_uploaded_file(client: &Client, cli: &Cli, uploaded_path: &str) -> Result<()> {
    let cleanup_url = format!("{}/upload/cleanup", cli.base_url.trim_end_matches('/'));
    let payload = UploadCleanupRequest {
        file_path: uploaded_path.to_string(),
    };

    let cleanup_resp = client
        .post(&cleanup_url)
        .header("X-API-Key", &cli.api_key)
        .json(&payload)
        .send()
        .await
        .context("Upload cleanup request failed")?;

    ensure_success_status(cleanup_resp.status(), "cleanup_upload")
}

async fn process_uploaded_file(
    client: &Client,
    cli: &Cli,
    condition: &Condition,
    uploaded_path: &str,
) -> Result<ProcessStageResult> {
    let process_url = format!("{}/process", cli.base_url.trim_end_matches('/'));
    let process_payload = ProcessRequest {
        file_path: uploaded_path.to_string(),
        signature_profile: to_gateway_profile(&condition.signature_profile),
        hash_algorithm: to_gateway_hash(&condition.hash_algorithm).to_string(),
    };

    let process_start = Instant::now();
    let process_resp = client
        .post(&process_url)
        .header("X-API-Key", &cli.api_key)
        .json(&process_payload)
        .send()
        .await
        .context("Process request failed")?;
    ensure_success_status(process_resp.status(), "process")?;

    let process: ProcessResponse = process_resp
        .json()
        .await
        .context("Failed to parse /process response")?;

    Ok(ProcessStageResult {
        process,
        client_process_ms: process_start.elapsed().as_secs_f64() * 1000.0,
    })
}

async fn verify_request_call(
    client: &Client,
    cli: &Cli,
    request_id: &str,
    verify_object: bool,
    file_path: Option<String>,
) -> Result<VerifyStageResult> {
    let verify_url = format!("{}/verify", cli.base_url.trim_end_matches('/'));
    let verify_payload = VerifyRequest {
        request_id: request_id.to_string(),
        verify_object,
        file_path,
    };

    let verify_start = Instant::now();
    let verify_resp = client
        .post(&verify_url)
        .header("X-API-Key", &cli.api_key)
        .json(&verify_payload)
        .send()
        .await
        .context("Verify request failed")?;
    ensure_success_status(verify_resp.status(), "verify")?;

    let verify: VerifyResponse = verify_resp
        .json()
        .await
        .context("Failed to parse /verify response")?;

    Ok(VerifyStageResult {
        verify,
        client_verify_ms: verify_start.elapsed().as_secs_f64() * 1000.0,
    })
}

async fn fetch_operations_metrics(
    client: &Client,
    operations_endpoint: &str,
    api_key: &str,
    request_id: &str,
    scenario: ScenarioKind,
) -> Result<OperationMetricsResponse> {
    let url =
        reqwest::Url::parse(operations_endpoint).context("Invalid operations-endpoint URL")?;

    let mut request_url = url.clone();
    request_url
        .query_pairs_mut()
        .append_pair("request_id", request_id);

    const MAX_ATTEMPTS: usize = 5;
    const INITIAL_RETRY_DELAY_MS: u64 = 40;

    for attempt in 0..MAX_ATTEMPTS {
        let resp = client
            .get(request_url.clone())
            .header("X-API-Key", api_key)
            .send()
            .await
            .context("Failed calling operations endpoint")?;

        if resp.status().is_success() {
            let record: OperationMetricsResponse = resp
                .json()
                .await
                .context("Failed to parse operations JSON")?;
            if operation_metrics_ready(&record, scenario) || attempt + 1 == MAX_ATTEMPTS {
                return Ok(record);
            }
        } else if !operations_status_is_retryable(resp.status()) || attempt + 1 == MAX_ATTEMPTS {
            bail!("Operations endpoint returned status {}", resp.status());
        }

        let backoff_ms = INITIAL_RETRY_DELAY_MS * (1_u64 << attempt.min(3));
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
    }

    unreachable!("operations metrics retry loop should always return or bail")
}

fn operations_status_is_retryable(status: StatusCode) -> bool {
    status == StatusCode::NOT_FOUND
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn operation_metrics_ready(record: &OperationMetricsResponse, scenario: ScenarioKind) -> bool {
    match scenario {
        ScenarioKind::Workflow => record.process.is_some() && record.verify.is_some(),
        ScenarioKind::SignOnly => record.process.is_some(),
        ScenarioKind::VerifyManifest
        | ScenarioKind::VerifyStored
        | ScenarioKind::VerifyUploaded
        | ScenarioKind::VerifyFull => record.verify.is_some(),
    }
}

fn derive_server_metrics(record: &OperationMetricsResponse) -> ServerMetricValues {
    let process = record.process.as_ref();
    let verify = record.verify.as_ref();
    let process_hash = process.and_then(|value| value.hash_metrics.as_ref());
    let process_manifest = process.and_then(|value| value.manifest_metrics.as_ref());
    let verify_fetch = verify.and_then(|value| value.manifest_fetch_metrics.as_ref());
    let verify_hash = verify.and_then(|value| value.verify_hash_metrics.as_ref());
    let verify_manifest = verify.and_then(|value| value.manifest_verify_metrics.as_ref());

    let storage_bytes_written = match (process_hash, verify_hash) {
        (Some(a), Some(b)) => Some(a.bytes_written + b.bytes_written),
        (Some(a), None) => Some(a.bytes_written),
        (None, Some(b)) => Some(b.bytes_written),
        (None, None) => None,
    };

    let storage_bytes_read = match (verify_hash, verify_manifest) {
        (Some(a), Some(b)) => Some(a.bytes_read + b.stored_object_bytes_read),
        (Some(a), None) => Some(a.bytes_read),
        (None, Some(b)) => Some(b.stored_object_bytes_read),
        (None, None) => None,
    };

    ServerMetricValues {
        server_process_gateway_ms: process.map(|value| value.gateway_total_ms),
        server_verify_gateway_ms: verify.map(|value| value.gateway_total_ms),
        server_hash_ms: process_hash.map(|metrics| metrics.hash_compute_ms),
        server_object_exists_check_ms: process_hash.map(|metrics| metrics.object_exists_check_ms),
        server_object_store_ms: process_hash.map(|metrics| metrics.object_store_ms),
        server_object_store_hit: process_hash.map(|metrics| metrics.object_store_hit),
        server_multipart_used: process_hash.map(|metrics| metrics.multipart_used),
        server_hash_bytes_read: process_hash.map(|metrics| metrics.bytes_read),
        server_hash_bytes_written: process_hash.map(|metrics| metrics.bytes_written),
        server_manifest_canonicalize_ms: process_manifest.map(|metrics| metrics.canonicalize_ms),
        server_db_persist_ms: process_manifest.map(|metrics| metrics.db_persist_ms),
        server_rsa_sign_ms: process_manifest.and_then(|m| m.rsa_sign_ms),
        server_eddsa_sign_ms: process_manifest.and_then(|m| m.eddsa_sign_ms),
        server_ecdsa_sign_ms: process_manifest.and_then(|m| m.ecdsa_sign_ms),
        server_hmac_sign_ms: process_manifest.and_then(|m| m.hmac_sign_ms),
        server_ml_dsa_sign_ms: process_manifest.and_then(|m| m.ml_dsa_sign_ms),
        server_slh_dsa_sign_ms: process_manifest.and_then(|m| m.slh_dsa_sign_ms),
        server_fn_dsa_sign_ms: process_manifest.and_then(|m| m.fn_dsa_sign_ms),
        server_eddsa_verify_ms: verify_manifest.and_then(|m| m.eddsa_verify_ms),
        server_ecdsa_verify_ms: verify_manifest.and_then(|m| m.ecdsa_verify_ms),
        server_hmac_verify_ms: verify_manifest.and_then(|m| m.hmac_verify_ms),
        server_ml_dsa_verify_ms: verify_manifest.and_then(|m| m.ml_dsa_verify_ms),
        server_slh_dsa_verify_ms: verify_manifest.and_then(|m| m.slh_dsa_verify_ms),
        server_fn_dsa_verify_ms: verify_manifest.and_then(|m| m.fn_dsa_verify_ms),
        server_manifest_fetch_db_lookup_ms: verify_fetch.map(|metrics| metrics.db_lookup_ms),
        server_verify_hash_ms: verify_hash.map(|metrics| metrics.total_ms),
        server_verify_canonicalize_ms: verify_manifest.map(|metrics| metrics.canonicalize_ms),
        server_signature_verify_ms: verify_manifest.map(|metrics| metrics.signature_verify_ms),
        server_stored_object_verify_ms: verify_manifest
            .map(|metrics| metrics.stored_object_verify_ms),
        server_uploaded_content_verify_ms: verify_manifest
            .map(|metrics| metrics.uploaded_content_verify_ms),
        server_verify_ms: verify_manifest.map(|metrics| metrics.total_ms),
        storage_bytes_written,
        storage_bytes_read,
    }
}

fn empty_server_metrics() -> ServerMetricValues {
    ServerMetricValues {
        server_process_gateway_ms: None,
        server_verify_gateway_ms: None,
        server_hash_ms: None,
        server_object_exists_check_ms: None,
        server_object_store_ms: None,
        server_object_store_hit: None,
        server_multipart_used: None,
        server_hash_bytes_read: None,
        server_hash_bytes_written: None,
        server_manifest_canonicalize_ms: None,
        server_db_persist_ms: None,
        server_rsa_sign_ms: None,
        server_eddsa_sign_ms: None,
        server_ecdsa_sign_ms: None,
        server_hmac_sign_ms: None,
        server_ml_dsa_sign_ms: None,
        server_slh_dsa_sign_ms: None,
        server_fn_dsa_sign_ms: None,
        server_eddsa_verify_ms: None,
        server_ecdsa_verify_ms: None,
        server_hmac_verify_ms: None,
        server_ml_dsa_verify_ms: None,
        server_slh_dsa_verify_ms: None,
        server_fn_dsa_verify_ms: None,
        server_manifest_fetch_db_lookup_ms: None,
        server_verify_hash_ms: None,
        server_verify_canonicalize_ms: None,
        server_signature_verify_ms: None,
        server_stored_object_verify_ms: None,
        server_uploaded_content_verify_ms: None,
        server_verify_ms: None,
        storage_bytes_written: None,
        storage_bytes_read: None,
    }
}

fn stage_error(stage: &str, err: anyhow::Error) -> anyhow::Error {
    anyhow!("{stage}: {err:#}")
}

fn classify_error_stage(message: &str) -> &'static str {
    if message.starts_with("upload:") || message.contains("Upload request failed") {
        "upload"
    } else if message.starts_with("cleanup_upload:")
        || message.contains("Upload cleanup request failed")
    {
        "cleanup_upload"
    } else if message.starts_with("process:") || message.contains("Process request failed") {
        "process"
    } else if message.starts_with("verify:") || message.contains("Verify request failed") {
        "verify"
    } else {
        "unknown"
    }
}

fn sum_stage_millis(values: &[Option<f64>]) -> Option<f64> {
    let mut total = 0.0;
    let mut saw_any = false;
    for value in values.iter().flatten() {
        total += *value;
        saw_any = true;
    }
    if saw_any {
        Some(total)
    } else {
        None
    }
}

fn compute_artifact_metrics(manifest: &SignedManifest, file_size: u64) -> Result<ArtifactMetrics> {
    let manifest_size_bytes = serde_json::to_vec(manifest)
        .context("Failed to compute manifest serialized size")?
        .len();
    let manifest_core_bytes = serde_json::to_vec(&manifest.core)
        .context("Failed to compute manifest core serialized size")?
        .len();
    let mut core_cbor = Vec::new();
    ciborium::into_writer(&manifest.core, &mut core_cbor)
        .context("Failed to compute manifest core CBOR size")?;
    let manifest_core_cbor_bytes = core_cbor.len();
    let manifest_envelope_bytes = serde_json::to_vec(&manifest.envelope)
        .context("Failed to compute manifest envelope serialized size")?
        .len();
    let sig_bytes = |opt: &Option<String>| opt.as_ref().map(|v| base64_decoded_len_approx(v));
    let rsa_signature_bytes = sig_bytes(&manifest.signatures.rsa_pss);
    let eddsa_signature_bytes = sig_bytes(&manifest.signatures.eddsa);
    let ecdsa_signature_bytes = sig_bytes(&manifest.signatures.ecdsa_p256);
    let hmac_signature_bytes = sig_bytes(&manifest.signatures.hmac_sha256);
    let ml_dsa_signature_bytes = sig_bytes(&manifest.signatures.ml_dsa);
    let slh_dsa_signature_bytes = sig_bytes(&manifest.signatures.slh_dsa);
    let fn_dsa_signature_bytes = sig_bytes(&manifest.signatures.fn_dsa);
    let all_sig_sizes = [
        rsa_signature_bytes,
        eddsa_signature_bytes,
        ecdsa_signature_bytes,
        hmac_signature_bytes,
        ml_dsa_signature_bytes,
        slh_dsa_signature_bytes,
        fn_dsa_signature_bytes,
    ];
    let total_signature_bytes = if all_sig_sizes.iter().all(|v| v.is_none()) {
        None
    } else {
        Some(all_sig_sizes.iter().filter_map(|v| *v).sum())
    };

    Ok(ArtifactMetrics {
        manifest_size_bytes,
        manifest_core_bytes,
        manifest_core_cbor_bytes,
        manifest_envelope_bytes,
        rsa_signature_bytes,
        eddsa_signature_bytes,
        ecdsa_signature_bytes,
        hmac_signature_bytes,
        ml_dsa_signature_bytes,
        slh_dsa_signature_bytes,
        fn_dsa_signature_bytes,
        total_signature_bytes,
        manifest_overhead_pct: percentage_of_file(manifest_size_bytes as f64, file_size),
        signature_overhead_pct: total_signature_bytes
            .map(|value| percentage_of_file(value as f64, file_size))
            .unwrap_or(None),
        storage_amplification: storage_amplification_ratio(file_size, manifest_size_bytes),
    })
}

fn ensure_success_status(status: StatusCode, operation: &str) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        bail!("{} returned HTTP {}", operation, status)
    }
}

fn base64_decoded_len_approx(encoded: &str) -> usize {
    let len = encoded.len();
    if len == 0 {
        return 0;
    }

    let padding = encoded.chars().rev().take_while(|c| *c == '=').count();
    len / 4 * 3 - padding
}

fn percentage_of_file(bytes: f64, file_size_bytes: u64) -> Option<f64> {
    if file_size_bytes == 0 {
        None
    } else {
        Some((bytes / file_size_bytes as f64) * 100.0)
    }
}

fn storage_amplification_ratio(file_size_bytes: u64, manifest_size_bytes: usize) -> Option<f64> {
    if file_size_bytes == 0 {
        None
    } else {
        Some((file_size_bytes as f64 + manifest_size_bytes as f64) / file_size_bytes as f64)
    }
}

fn throughput_mib_per_s(file_size_bytes: u64, duration_ms: f64) -> Option<f64> {
    if file_size_bytes == 0 || duration_ms <= 0.0 {
        None
    } else {
        Some((file_size_bytes as f64 / (1024.0 * 1024.0)) / (duration_ms / 1000.0))
    }
}

fn normalize_profiles(input: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for p in input {
        let normalized =
            normalize_benchmark_profile(p).ok_or_else(|| anyhow!("Unsupported profile '{}'", p))?;
        if !out.iter().any(|v| v == &normalized) {
            out.push(normalized);
        }
    }
    Ok(out)
}

fn normalize_hashes(input: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for h in input {
        let normalized = normalize_benchmark_hash(h)
            .ok_or_else(|| anyhow!("Unsupported hash algorithm '{}'", h))?;
        if !out.iter().any(|v| v == normalized) {
            out.push(normalized.to_string());
        }
    }
    Ok(out)
}

fn normalize_scenarios(input: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for scenario in input {
        let normalized = ScenarioKind::from_label(scenario)?.label().to_string();
        if !out.iter().any(|value| value == &normalized) {
            out.push(normalized);
        }
    }
    Ok(out)
}

fn to_gateway_profile(profile: &str) -> String {
    benchmark_profile_to_service(profile).unwrap_or_else(|| profile.to_string())
}

fn to_gateway_hash(hash: &str) -> &str {
    benchmark_hash_to_service(hash).unwrap_or(hash)
}

fn parse_bucket_specs(labels: &[String]) -> Result<Vec<BucketSpec>> {
    let mut specs = Vec::new();

    for label in labels {
        let trimmed = label.trim();
        let upper = trimmed.to_ascii_uppercase();
        let max = match upper.as_str() {
            "10KB" => 10 * 1024,
            "100KB" => 100 * 1024,
            "1MB" => 1024 * 1024,
            "10MB" => 10 * 1024 * 1024,
            "50MB" => 50 * 1024 * 1024,
            _ => parse_size_to_bytes(trimmed)
                .ok_or_else(|| anyhow!("Unsupported bucket label '{}'", trimmed))?,
        };

        specs.push(BucketSpec {
            label: trimmed.to_string(),
            min_bytes: 0,
            max_bytes: max,
        });
    }

    specs.sort_by_key(|b| b.max_bytes);
    let mut previous = 0u64;
    for spec in &mut specs {
        spec.min_bytes = previous;
        previous = spec.max_bytes.saturating_add(1);
    }

    Ok(specs)
}

fn parse_size_to_bytes(input: &str) -> Option<u64> {
    let upper = input.trim().to_ascii_uppercase();
    if let Some(v) = upper.strip_suffix("KB") {
        return v.trim().parse::<u64>().ok().map(|n| n * 1024);
    }
    if let Some(v) = upper.strip_suffix("MB") {
        return v.trim().parse::<u64>().ok().map(|n| n * 1024 * 1024);
    }
    if let Some(v) = upper.strip_suffix("B") {
        return v.trim().parse::<u64>().ok();
    }
    upper.parse::<u64>().ok()
}

fn collect_files_recursively(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_recursive_impl(root, &mut files)?;
    Ok(files)
}

fn collect_files_recursive_impl(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;

        if metadata.is_dir() {
            collect_files_recursive_impl(&path, out)?;
        } else if metadata.is_file() {
            if is_dataset_support_file(&path) {
                continue;
            }
            out.push(path);
        }
    }
    Ok(())
}

fn is_dataset_support_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some("dataset-manifest.csv" | "dataset-metadata.json")
    )
}

fn bucket_label_from_path(file: &Path) -> Option<String> {
    for ancestor in file.ancestors() {
        let Some(name) = ancestor.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if parse_size_to_bytes(name).is_some() {
            return Some(name.to_string());
        }
    }

    None
}

fn index_files_by_bucket(
    files: &[PathBuf],
    buckets: &[BucketSpec],
) -> Result<HashMap<String, Vec<PathBuf>>> {
    let mut grouped: HashMap<String, Vec<PathBuf>> = buckets
        .iter()
        .map(|b| (b.label.clone(), Vec::new()))
        .collect();

    for file in files {
        if let Some(path_bucket_label) = bucket_label_from_path(file) {
            if let Some(bucket) = buckets
                .iter()
                .find(|bucket| bucket.label.eq_ignore_ascii_case(&path_bucket_label))
            {
                grouped
                    .entry(bucket.label.clone())
                    .or_default()
                    .push(file.clone());
            }
            continue;
        }

        let size = std::fs::metadata(file)
            .with_context(|| format!("Failed to read metadata for {}", file.display()))?
            .len();

        if let Some(bucket) = buckets
            .iter()
            .find(|b| size >= b.min_bytes && size <= b.max_bytes)
        {
            grouped
                .entry(bucket.label.clone())
                .or_default()
                .push(file.clone());
        }
    }

    for bucket in buckets {
        let count = grouped.get(&bucket.label).map(|v| v.len()).unwrap_or(0);
        if count == 0 {
            bail!(
                "No dataset files fit bucket '{}' ({}..={} bytes)",
                bucket.label,
                bucket.min_bytes,
                bucket.max_bytes
            );
        }
    }

    Ok(grouped)
}

fn build_conditions(
    profiles: &[String],
    hashes: &[String],
    buckets: &[BucketSpec],
    scenarios: &[String],
) -> Vec<Condition> {
    let mut out = Vec::new();
    for p in profiles {
        for h in hashes {
            for b in buckets {
                for scenario in scenarios {
                    out.push(Condition {
                        signature_profile: p.clone(),
                        hash_algorithm: h.clone(),
                        bucket: b.label.clone(),
                        benchmark_scenario: scenario.clone(),
                    });
                }
            }
        }
    }
    out
}

fn build_jobs(
    conditions: &[Condition],
    warmup_runs: u32,
    measured_runs: u32,
    rng: &mut StdRng,
) -> Vec<Job> {
    let mut jobs = Vec::new();

    let mut warmups = Vec::new();
    for ordinal in 1..=warmup_runs {
        let mut block = Vec::new();
        for condition in conditions {
            block.push(Job {
                condition: condition.clone(),
                phase: Phase::Warmup,
                ordinal,
            });
        }
        block.shuffle(rng);
        warmups.extend(block);
    }

    let mut measured = Vec::new();
    for ordinal in 1..=measured_runs {
        let mut block = Vec::new();
        for condition in conditions {
            block.push(Job {
                condition: condition.clone(),
                phase: Phase::Measured,
                ordinal,
            });
        }
        block.shuffle(rng);
        measured.extend(block);
    }

    jobs.extend(warmups);
    jobs.extend(measured);
    jobs
}

fn build_condition_summaries(
    runs: &[RunRecord],
    bootstrap_samples: usize,
    seed: u64,
) -> Vec<ConditionSummary> {
    let mut grouped: HashMap<(String, String, String, String, String), Vec<&RunRecord>> =
        HashMap::new();

    for run in runs.iter().filter(|r| matches!(r.phase, Phase::Measured)) {
        grouped
            .entry((
                run.condition_signature_profile.clone(),
                run.condition_hash_algorithm.clone(),
                run.condition_bucket.clone(),
                run.benchmark_scenario.clone(),
                run.storage_state_label.clone(),
            ))
            .or_default()
            .push(run);
    }

    let mut summaries: Vec<ConditionSummary> = grouped
        .into_iter()
        .map(
            |((profile, hash, bucket, benchmark_scenario, storage_state_label), records)| {
                let successes: Vec<&RunRecord> = records
                    .iter()
                    .copied()
                    .filter(|r| matches!(r.scenario_status, ScenarioStatus::Ok))
                    .collect();

                let verify_applicable_runs = records
                    .iter()
                    .filter(|r| {
                        matches!(r.verify_outcome, VerifyOutcome::Ok | VerifyOutcome::Failed)
                    })
                    .count();
                let verify_ok_runs = records
                    .iter()
                    .filter(|r| matches!(r.verify_outcome, VerifyOutcome::Ok))
                    .count();
                let verify_applicable_success_rate = if verify_applicable_runs == 0 {
                    None
                } else {
                    Some(verify_ok_runs as f64 / verify_applicable_runs as f64)
                };
                // Legacy field: counts verify_ok across all runs (misleading for sign_only = always 0)
                let legacy_verify_ok = records
                    .iter()
                    .filter(|r| r.verify_overall_ok.unwrap_or(false))
                    .count();
                let scenario_success_count = successes.len();

                let server_telemetry_configured = records.iter().any(|r| {
                    !matches!(
                        r.server_telemetry_status,
                        ServerTelemetryStatus::NotConfigured
                    )
                });
                let server_telemetry_available = successes
                    .iter()
                    .filter(|r| {
                        matches!(r.server_telemetry_status, ServerTelemetryStatus::Available)
                    })
                    .count();
                let server_telemetry_coverage = if successes.is_empty() {
                    0.0
                } else {
                    server_telemetry_available as f64 / successes.len() as f64
                };

                let setup_upload_vals = collect_metric(&successes, |r| r.setup_upload_ms);
                let setup_process_vals = collect_metric(&successes, |r| r.setup_process_ms);
                let upload_vals = collect_metric(&successes, |r| r.client_upload_ms);
                let process_vals = collect_metric(&successes, |r| r.client_process_ms);
                let verify_vals = collect_metric(&successes, |r| r.client_verify_ms);
                let total_vals = collect_metric(&successes, |r| r.client_total_ms);
                let server_process_gateway_vals =
                    collect_metric(&successes, |r| r.server_process_gateway_ms);
                let server_verify_gateway_vals =
                    collect_metric(&successes, |r| r.server_verify_gateway_ms);
                let server_hash_vals = collect_metric(&successes, |r| r.server_hash_ms);
                let server_rsa_sign_vals = collect_metric(&successes, |r| r.server_rsa_sign_ms);
                let server_eddsa_sign_vals = collect_metric(&successes, |r| r.server_eddsa_sign_ms);
                let server_ecdsa_sign_vals = collect_metric(&successes, |r| r.server_ecdsa_sign_ms);
                let server_hmac_sign_vals = collect_metric(&successes, |r| r.server_hmac_sign_ms);
                let server_ml_dsa_sign_vals =
                    collect_metric(&successes, |r| r.server_ml_dsa_sign_ms);
                let server_slh_dsa_sign_vals =
                    collect_metric(&successes, |r| r.server_slh_dsa_sign_ms);
                let server_fn_dsa_sign_vals =
                    collect_metric(&successes, |r| r.server_fn_dsa_sign_ms);
                let server_eddsa_verify_vals =
                    collect_metric(&successes, |r| r.server_eddsa_verify_ms);
                let server_ecdsa_verify_vals =
                    collect_metric(&successes, |r| r.server_ecdsa_verify_ms);
                let server_hmac_verify_vals =
                    collect_metric(&successes, |r| r.server_hmac_verify_ms);
                let server_ml_dsa_verify_vals =
                    collect_metric(&successes, |r| r.server_ml_dsa_verify_ms);
                let server_slh_dsa_verify_vals =
                    collect_metric(&successes, |r| r.server_slh_dsa_verify_ms);
                let server_fn_dsa_verify_vals =
                    collect_metric(&successes, |r| r.server_fn_dsa_verify_ms);
                let server_verify_vals = collect_metric(&successes, |r| r.server_verify_ms);
                let server_total_vals = collect_metric(&successes, |r| r.server_total_ms);
                let manifest_vals =
                    collect_metric(&successes, |r| r.manifest_size_bytes.map(|v| v as f64));
                let manifest_core_vals =
                    collect_metric(&successes, |r| r.manifest_core_bytes.map(|v| v as f64));
                let manifest_core_cbor_vals =
                    collect_metric(&successes, |r| r.manifest_core_cbor_bytes.map(|v| v as f64));
                let manifest_envelope_vals =
                    collect_metric(&successes, |r| r.manifest_envelope_bytes.map(|v| v as f64));
                let rsa_signature_vals =
                    collect_metric(&successes, |r| r.rsa_signature_bytes.map(|v| v as f64));
                let eddsa_signature_vals =
                    collect_metric(&successes, |r| r.eddsa_signature_bytes.map(|v| v as f64));
                let ecdsa_signature_vals =
                    collect_metric(&successes, |r| r.ecdsa_signature_bytes.map(|v| v as f64));
                let hmac_signature_vals =
                    collect_metric(&successes, |r| r.hmac_signature_bytes.map(|v| v as f64));
                let ml_dsa_signature_vals =
                    collect_metric(&successes, |r| r.ml_dsa_signature_bytes.map(|v| v as f64));
                let slh_dsa_signature_vals =
                    collect_metric(&successes, |r| r.slh_dsa_signature_bytes.map(|v| v as f64));
                let fn_dsa_signature_vals =
                    collect_metric(&successes, |r| r.fn_dsa_signature_bytes.map(|v| v as f64));
                let signature_vals =
                    collect_metric(&successes, |r| r.total_signature_bytes.map(|v| v as f64));
                let manifest_overhead_vals =
                    collect_metric(&successes, |r| r.manifest_overhead_pct);
                let signature_overhead_vals =
                    collect_metric(&successes, |r| r.signature_overhead_pct);
                let storage_amplification_vals =
                    collect_metric(&successes, |r| r.storage_amplification);
                let client_total_mib_s_vals = collect_metric(&successes, |r| r.client_total_mib_s);
                let server_hash_mib_s_vals = collect_metric(&successes, |r| r.server_hash_mib_s);
                let server_verify_mib_s_vals =
                    collect_metric(&successes, |r| r.server_verify_mib_s);
                let server_total_mib_s_vals = collect_metric(&successes, |r| r.server_total_mib_s);

                ConditionSummary {
                    signature_profile: profile,
                    hash_algorithm: hash,
                    bucket,
                    benchmark_scenario,
                    storage_state_label,
                    measured_runs_total: records.len(),
                    measured_runs_success: successes.len(),
                    measured_runs_failed: records.len().saturating_sub(successes.len()),
                    scenario_success_rate: if records.is_empty() {
                        0.0
                    } else {
                        scenario_success_count as f64 / records.len() as f64
                    },
                    verify_applicable_runs,
                    verify_ok_runs,
                    verify_applicable_success_rate,
                    verify_success_rate: if records.is_empty() {
                        0.0
                    } else {
                        legacy_verify_ok as f64 / records.len() as f64
                    },
                    server_telemetry_configured,
                    server_telemetry_coverage,
                    setup_upload_ms: summarize_metric(&setup_upload_vals, bootstrap_samples, seed),
                    setup_process_ms: summarize_metric(
                        &setup_process_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    upload_ms: summarize_metric(&upload_vals, bootstrap_samples, seed),
                    process_ms: summarize_metric(&process_vals, bootstrap_samples, seed),
                    verify_ms: summarize_metric(&verify_vals, bootstrap_samples, seed),
                    total_ms: summarize_metric(&total_vals, bootstrap_samples, seed),
                    server_process_gateway_ms: summarize_metric(
                        &server_process_gateway_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_verify_gateway_ms: summarize_metric(
                        &server_verify_gateway_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_hash_ms: summarize_metric(&server_hash_vals, bootstrap_samples, seed),
                    server_rsa_sign_ms: summarize_metric(
                        &server_rsa_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_eddsa_sign_ms: summarize_metric(
                        &server_eddsa_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_ecdsa_sign_ms: summarize_metric(
                        &server_ecdsa_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_hmac_sign_ms: summarize_metric(
                        &server_hmac_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_ml_dsa_sign_ms: summarize_metric(
                        &server_ml_dsa_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_slh_dsa_sign_ms: summarize_metric(
                        &server_slh_dsa_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_fn_dsa_sign_ms: summarize_metric(
                        &server_fn_dsa_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_eddsa_verify_ms: summarize_metric(
                        &server_eddsa_verify_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_ecdsa_verify_ms: summarize_metric(
                        &server_ecdsa_verify_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_hmac_verify_ms: summarize_metric(
                        &server_hmac_verify_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_ml_dsa_verify_ms: summarize_metric(
                        &server_ml_dsa_verify_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_slh_dsa_verify_ms: summarize_metric(
                        &server_slh_dsa_verify_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_fn_dsa_verify_ms: summarize_metric(
                        &server_fn_dsa_verify_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_verify_ms: summarize_metric(
                        &server_verify_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_total_ms: summarize_metric(&server_total_vals, bootstrap_samples, seed),
                    manifest_size_bytes: summarize_metric(&manifest_vals, bootstrap_samples, seed),
                    manifest_core_bytes: summarize_metric(
                        &manifest_core_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    manifest_core_cbor_bytes: summarize_metric(
                        &manifest_core_cbor_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    manifest_envelope_bytes: summarize_metric(
                        &manifest_envelope_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    rsa_signature_bytes: summarize_metric(
                        &rsa_signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    eddsa_signature_bytes: summarize_metric(
                        &eddsa_signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    ecdsa_signature_bytes: summarize_metric(
                        &ecdsa_signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    hmac_signature_bytes: summarize_metric(
                        &hmac_signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    ml_dsa_signature_bytes: summarize_metric(
                        &ml_dsa_signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    slh_dsa_signature_bytes: summarize_metric(
                        &slh_dsa_signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    fn_dsa_signature_bytes: summarize_metric(
                        &fn_dsa_signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    total_signature_bytes: summarize_metric(
                        &signature_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    manifest_overhead_pct: summarize_metric(
                        &manifest_overhead_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    signature_overhead_pct: summarize_metric(
                        &signature_overhead_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    storage_amplification: summarize_metric(
                        &storage_amplification_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    client_total_mib_s: summarize_metric(
                        &client_total_mib_s_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_hash_mib_s: summarize_metric(
                        &server_hash_mib_s_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_verify_mib_s: summarize_metric(
                        &server_verify_mib_s_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_total_mib_s: summarize_metric(
                        &server_total_mib_s_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    ratio_vs_rsa_pss_total_median: None,
                    ratio_vs_rsa_pss_server_total_median: None,
                }
            },
        )
        .collect();

    summaries.sort_by(|a, b| {
        (
            a.benchmark_scenario.as_str(),
            a.storage_state_label.as_str(),
            a.hash_algorithm.as_str(),
            a.bucket.as_str(),
            a.signature_profile.as_str(),
        )
            .cmp(&(
                b.benchmark_scenario.as_str(),
                b.storage_state_label.as_str(),
                b.hash_algorithm.as_str(),
                b.bucket.as_str(),
                b.signature_profile.as_str(),
            ))
    });

    let mut baseline_map: HashMap<(String, String, String, String), f64> = HashMap::new();
    let mut server_baseline_map: HashMap<(String, String, String, String), f64> = HashMap::new();
    for summary in &summaries {
        if summary.signature_profile == "rsa_pss" {
            if let Some(total) = &summary.total_ms {
                baseline_map.insert(
                    (
                        summary.benchmark_scenario.clone(),
                        summary.storage_state_label.clone(),
                        summary.hash_algorithm.clone(),
                        summary.bucket.clone(),
                    ),
                    total.median,
                );
            }
            if let Some(total) = &summary.server_total_ms {
                server_baseline_map.insert(
                    (
                        summary.benchmark_scenario.clone(),
                        summary.storage_state_label.clone(),
                        summary.hash_algorithm.clone(),
                        summary.bucket.clone(),
                    ),
                    total.median,
                );
            }
        }
    }

    for summary in &mut summaries {
        if let Some(base) = baseline_map
            .get(&(
                summary.benchmark_scenario.clone(),
                summary.storage_state_label.clone(),
                summary.hash_algorithm.clone(),
                summary.bucket.clone(),
            ))
            .copied()
        {
            if base > 0.0 {
                if let Some(total) = &summary.total_ms {
                    if summary.signature_profile != "rsa_pss" {
                        summary.ratio_vs_rsa_pss_total_median = Some(total.median / base);
                    }
                }
            }
        }

        if let Some(base) = server_baseline_map
            .get(&(
                summary.benchmark_scenario.clone(),
                summary.storage_state_label.clone(),
                summary.hash_algorithm.clone(),
                summary.bucket.clone(),
            ))
            .copied()
        {
            if base > 0.0 {
                if let Some(total) = &summary.server_total_ms {
                    if summary.signature_profile != "rsa_pss" {
                        summary.ratio_vs_rsa_pss_server_total_median = Some(total.median / base);
                    }
                }
            }
        }
    }

    summaries
}

fn collect_metric<F>(records: &[&RunRecord], getter: F) -> Vec<f64>
where
    F: Fn(&RunRecord) -> Option<f64>,
{
    records.iter().filter_map(|r| getter(r)).collect()
}

fn summarize_metric(values: &[f64], bootstrap_samples: usize, seed: u64) -> Option<MetricSummary> {
    if values.is_empty() {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));

    let median = percentile(&sorted, 0.50);
    let p25 = percentile(&sorted, 0.25);
    let p75 = percentile(&sorted, 0.75);
    let p95 = percentile(&sorted, 0.95);

    let (ci95_low, ci95_high) = if sorted.len() >= 2 && bootstrap_samples > 0 {
        let mut rng = StdRng::seed_from_u64(seed ^ (sorted.len() as u64).wrapping_mul(2654435761));
        let mut medians = Vec::with_capacity(bootstrap_samples);

        for _ in 0..bootstrap_samples {
            let mut sample = Vec::with_capacity(sorted.len());
            for _ in 0..sorted.len() {
                let idx = rng.gen_range(0..sorted.len());
                sample.push(sorted[idx]);
            }
            sample.sort_by(|a, b| a.total_cmp(b));
            medians.push(percentile(&sample, 0.50));
        }

        medians.sort_by(|a, b| a.total_cmp(b));
        (
            Some(percentile(&medians, 0.025)),
            Some(percentile(&medians, 0.975)),
        )
    } else {
        (None, None)
    };

    Some(MetricSummary {
        n: sorted.len(),
        median,
        iqr: p75 - p25,
        p95,
        ci95_low,
        ci95_high,
    })
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.len() == 1 {
        return sorted[0];
    }

    let clamped = p.clamp(0.0, 1.0);
    let rank = clamped * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;

    if lo == hi {
        sorted[lo]
    } else {
        let weight = rank - lo as f64;
        sorted[lo] * (1.0 - weight) + sorted[hi] * weight
    }
}

fn collect_environment_metadata() -> EnvironmentMetadata {
    EnvironmentMetadata {
        git_commit: command_output("git", &["rev-parse", "HEAD"]),
        git_dirty: git_dirty_state(),
        build_profile: if cfg!(debug_assertions) {
            "debug".to_string()
        } else {
            "release".to_string()
        },
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        logical_cores: std::thread::available_parallelism()
            .ok()
            .map(|value| value.get()),
        cpu_model: cpu_model(),
        total_memory_bytes: total_memory_bytes(),
        hostname: std::env::var("HOSTNAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| command_output("hostname", &[])),
    }
}

fn command_output(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn git_dirty_state() -> Option<bool> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn cpu_model() -> Option<String> {
    if cfg!(target_os = "macos") {
        command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
    } else if cfg!(target_os = "linux") {
        let data = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        data.lines().find_map(|line| {
            line.strip_prefix("model name\t: ")
                .map(|value| value.to_string())
        })
    } else {
        None
    }
}

fn total_memory_bytes() -> Option<u64> {
    if cfg!(target_os = "macos") {
        command_output("sysctl", &["-n", "hw.memsize"])?
            .parse::<u64>()
            .ok()
    } else if cfg!(target_os = "linux") {
        let data = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb = data.lines().find_map(|line| {
            let rest = line.strip_prefix("MemTotal:")?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })?;
        Some(kb * 1024)
    } else {
        None
    }
}

async fn write_outputs(
    output_dir: &Path,
    report: &BenchmarkReport,
    runs: &[RunRecord],
    summaries: &[ConditionSummary],
    evidence_metrics: &[EvidenceMetricRow],
) -> Result<()> {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let json_path = output_dir.join(format!("benchmark-report-{}.json", ts));
    let runs_csv_path = output_dir.join(format!("benchmark-runs-{}.csv", ts));
    let summary_csv_path = output_dir.join(format!("benchmark-summary-{}.csv", ts));
    let evidence_csv_path = output_dir.join(format!("benchmark-evidence-metrics-{}.csv", ts));

    let json = serde_json::to_string_pretty(report).context("Failed to serialize report JSON")?;
    tokio::fs::write(&json_path, json)
        .await
        .with_context(|| format!("Failed to write {}", json_path.display()))?;

    {
        let mut writer = csv::Writer::from_path(&runs_csv_path)
            .with_context(|| format!("Failed to write {}", runs_csv_path.display()))?;
        for record in runs {
            writer.serialize(record)?;
        }
        writer.flush()?;
    }

    {
        let mut writer = csv::Writer::from_path(&summary_csv_path)
            .with_context(|| format!("Failed to write {}", summary_csv_path.display()))?;
        for summary in summaries {
            let row = flatten_summary_csv(summary);
            writer.serialize(row)?;
        }
        writer.flush()?;
    }

    {
        let mut writer = csv::Writer::from_path(&evidence_csv_path)
            .with_context(|| format!("Failed to write {}", evidence_csv_path.display()))?;
        for row in evidence_metrics {
            writer.serialize(row)?;
        }
        writer.flush()?;
    }

    Ok(())
}

fn flatten_summary_csv(summary: &ConditionSummary) -> ConditionSummaryCsv {
    let (
        setup_upload_ms_median,
        setup_upload_ms_iqr,
        setup_upload_ms_p95,
        setup_upload_ms_ci95_low,
        setup_upload_ms_ci95_high,
    ) = flatten_metric(&summary.setup_upload_ms);
    let (
        setup_process_ms_median,
        setup_process_ms_iqr,
        setup_process_ms_p95,
        setup_process_ms_ci95_low,
        setup_process_ms_ci95_high,
    ) = flatten_metric(&summary.setup_process_ms);
    let (upload_ms_median, upload_ms_iqr, upload_ms_p95, upload_ms_ci95_low, upload_ms_ci95_high) =
        flatten_metric(&summary.upload_ms);
    let (
        process_ms_median,
        process_ms_iqr,
        process_ms_p95,
        process_ms_ci95_low,
        process_ms_ci95_high,
    ) = flatten_metric(&summary.process_ms);
    let (verify_ms_median, verify_ms_iqr, verify_ms_p95, verify_ms_ci95_low, verify_ms_ci95_high) =
        flatten_metric(&summary.verify_ms);
    let (total_ms_median, total_ms_iqr, total_ms_p95, total_ms_ci95_low, total_ms_ci95_high) =
        flatten_metric(&summary.total_ms);
    let (
        server_process_gateway_ms_median,
        server_process_gateway_ms_iqr,
        server_process_gateway_ms_p95,
        server_process_gateway_ms_ci95_low,
        server_process_gateway_ms_ci95_high,
    ) = flatten_metric(&summary.server_process_gateway_ms);
    let (
        server_verify_gateway_ms_median,
        server_verify_gateway_ms_iqr,
        server_verify_gateway_ms_p95,
        server_verify_gateway_ms_ci95_low,
        server_verify_gateway_ms_ci95_high,
    ) = flatten_metric(&summary.server_verify_gateway_ms);
    let (
        server_hash_ms_median,
        server_hash_ms_iqr,
        server_hash_ms_p95,
        server_hash_ms_ci95_low,
        server_hash_ms_ci95_high,
    ) = flatten_metric(&summary.server_hash_ms);
    let (
        server_rsa_sign_ms_median,
        server_rsa_sign_ms_iqr,
        server_rsa_sign_ms_p95,
        server_rsa_sign_ms_ci95_low,
        server_rsa_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_rsa_sign_ms);
    let (
        server_eddsa_sign_ms_median,
        server_eddsa_sign_ms_iqr,
        server_eddsa_sign_ms_p95,
        server_eddsa_sign_ms_ci95_low,
        server_eddsa_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_eddsa_sign_ms);
    let (
        server_ecdsa_sign_ms_median,
        server_ecdsa_sign_ms_iqr,
        server_ecdsa_sign_ms_p95,
        server_ecdsa_sign_ms_ci95_low,
        server_ecdsa_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_ecdsa_sign_ms);
    let (
        server_hmac_sign_ms_median,
        server_hmac_sign_ms_iqr,
        server_hmac_sign_ms_p95,
        server_hmac_sign_ms_ci95_low,
        server_hmac_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_hmac_sign_ms);
    let (
        server_ml_dsa_sign_ms_median,
        server_ml_dsa_sign_ms_iqr,
        server_ml_dsa_sign_ms_p95,
        server_ml_dsa_sign_ms_ci95_low,
        server_ml_dsa_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_ml_dsa_sign_ms);
    let (
        server_slh_dsa_sign_ms_median,
        server_slh_dsa_sign_ms_iqr,
        server_slh_dsa_sign_ms_p95,
        server_slh_dsa_sign_ms_ci95_low,
        server_slh_dsa_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_slh_dsa_sign_ms);
    let (
        server_fn_dsa_sign_ms_median,
        server_fn_dsa_sign_ms_iqr,
        server_fn_dsa_sign_ms_p95,
        server_fn_dsa_sign_ms_ci95_low,
        server_fn_dsa_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_fn_dsa_sign_ms);
    let (
        server_eddsa_verify_ms_median,
        server_eddsa_verify_ms_iqr,
        server_eddsa_verify_ms_p95,
        server_eddsa_verify_ms_ci95_low,
        server_eddsa_verify_ms_ci95_high,
    ) = flatten_metric(&summary.server_eddsa_verify_ms);
    let (
        server_ecdsa_verify_ms_median,
        server_ecdsa_verify_ms_iqr,
        server_ecdsa_verify_ms_p95,
        server_ecdsa_verify_ms_ci95_low,
        server_ecdsa_verify_ms_ci95_high,
    ) = flatten_metric(&summary.server_ecdsa_verify_ms);
    let (
        server_hmac_verify_ms_median,
        server_hmac_verify_ms_iqr,
        server_hmac_verify_ms_p95,
        server_hmac_verify_ms_ci95_low,
        server_hmac_verify_ms_ci95_high,
    ) = flatten_metric(&summary.server_hmac_verify_ms);
    let (
        server_ml_dsa_verify_ms_median,
        server_ml_dsa_verify_ms_iqr,
        server_ml_dsa_verify_ms_p95,
        server_ml_dsa_verify_ms_ci95_low,
        server_ml_dsa_verify_ms_ci95_high,
    ) = flatten_metric(&summary.server_ml_dsa_verify_ms);
    let (
        server_slh_dsa_verify_ms_median,
        server_slh_dsa_verify_ms_iqr,
        server_slh_dsa_verify_ms_p95,
        server_slh_dsa_verify_ms_ci95_low,
        server_slh_dsa_verify_ms_ci95_high,
    ) = flatten_metric(&summary.server_slh_dsa_verify_ms);
    let (
        server_fn_dsa_verify_ms_median,
        server_fn_dsa_verify_ms_iqr,
        server_fn_dsa_verify_ms_p95,
        server_fn_dsa_verify_ms_ci95_low,
        server_fn_dsa_verify_ms_ci95_high,
    ) = flatten_metric(&summary.server_fn_dsa_verify_ms);
    let (
        server_verify_ms_median,
        server_verify_ms_iqr,
        server_verify_ms_p95,
        server_verify_ms_ci95_low,
        server_verify_ms_ci95_high,
    ) = flatten_metric(&summary.server_verify_ms);
    let (
        server_total_ms_median,
        server_total_ms_iqr,
        server_total_ms_p95,
        server_total_ms_ci95_low,
        server_total_ms_ci95_high,
    ) = flatten_metric(&summary.server_total_ms);
    let (
        manifest_size_median,
        manifest_size_iqr,
        manifest_size_p95,
        manifest_size_ci95_low,
        manifest_size_ci95_high,
    ) = flatten_metric(&summary.manifest_size_bytes);
    let (
        manifest_core_bytes_median,
        manifest_core_bytes_iqr,
        manifest_core_bytes_p95,
        manifest_core_bytes_ci95_low,
        manifest_core_bytes_ci95_high,
    ) = flatten_metric(&summary.manifest_core_bytes);
    let (
        manifest_core_cbor_bytes_median,
        manifest_core_cbor_bytes_iqr,
        manifest_core_cbor_bytes_p95,
        manifest_core_cbor_bytes_ci95_low,
        manifest_core_cbor_bytes_ci95_high,
    ) = flatten_metric(&summary.manifest_core_cbor_bytes);
    let (
        manifest_envelope_bytes_median,
        manifest_envelope_bytes_iqr,
        manifest_envelope_bytes_p95,
        manifest_envelope_bytes_ci95_low,
        manifest_envelope_bytes_ci95_high,
    ) = flatten_metric(&summary.manifest_envelope_bytes);
    let (
        rsa_signature_bytes_median,
        rsa_signature_bytes_iqr,
        rsa_signature_bytes_p95,
        rsa_signature_bytes_ci95_low,
        rsa_signature_bytes_ci95_high,
    ) = flatten_metric(&summary.rsa_signature_bytes);
    let (
        eddsa_signature_bytes_median,
        eddsa_signature_bytes_iqr,
        eddsa_signature_bytes_p95,
        eddsa_signature_bytes_ci95_low,
        eddsa_signature_bytes_ci95_high,
    ) = flatten_metric(&summary.eddsa_signature_bytes);
    let (
        ecdsa_signature_bytes_median,
        ecdsa_signature_bytes_iqr,
        ecdsa_signature_bytes_p95,
        ecdsa_signature_bytes_ci95_low,
        ecdsa_signature_bytes_ci95_high,
    ) = flatten_metric(&summary.ecdsa_signature_bytes);
    let (
        hmac_signature_bytes_median,
        hmac_signature_bytes_iqr,
        hmac_signature_bytes_p95,
        hmac_signature_bytes_ci95_low,
        hmac_signature_bytes_ci95_high,
    ) = flatten_metric(&summary.hmac_signature_bytes);
    let (
        ml_dsa_signature_bytes_median,
        ml_dsa_signature_bytes_iqr,
        ml_dsa_signature_bytes_p95,
        ml_dsa_signature_bytes_ci95_low,
        ml_dsa_signature_bytes_ci95_high,
    ) = flatten_metric(&summary.ml_dsa_signature_bytes);
    let (
        slh_dsa_signature_bytes_median,
        slh_dsa_signature_bytes_iqr,
        slh_dsa_signature_bytes_p95,
        slh_dsa_signature_bytes_ci95_low,
        slh_dsa_signature_bytes_ci95_high,
    ) = flatten_metric(&summary.slh_dsa_signature_bytes);
    let (
        fn_dsa_signature_bytes_median,
        fn_dsa_signature_bytes_iqr,
        fn_dsa_signature_bytes_p95,
        fn_dsa_signature_bytes_ci95_low,
        fn_dsa_signature_bytes_ci95_high,
    ) = flatten_metric(&summary.fn_dsa_signature_bytes);
    let (
        signature_size_median,
        signature_size_iqr,
        signature_size_p95,
        signature_size_ci95_low,
        signature_size_ci95_high,
    ) = flatten_metric(&summary.total_signature_bytes);
    let (
        manifest_overhead_pct_median,
        manifest_overhead_pct_iqr,
        manifest_overhead_pct_p95,
        manifest_overhead_pct_ci95_low,
        manifest_overhead_pct_ci95_high,
    ) = flatten_metric(&summary.manifest_overhead_pct);
    let (
        signature_overhead_pct_median,
        signature_overhead_pct_iqr,
        signature_overhead_pct_p95,
        signature_overhead_pct_ci95_low,
        signature_overhead_pct_ci95_high,
    ) = flatten_metric(&summary.signature_overhead_pct);
    let (
        storage_amplification_median,
        storage_amplification_iqr,
        storage_amplification_p95,
        storage_amplification_ci95_low,
        storage_amplification_ci95_high,
    ) = flatten_metric(&summary.storage_amplification);
    let (
        client_total_mib_s_median,
        client_total_mib_s_iqr,
        client_total_mib_s_p95,
        client_total_mib_s_ci95_low,
        client_total_mib_s_ci95_high,
    ) = flatten_metric(&summary.client_total_mib_s);
    let (
        server_hash_mib_s_median,
        server_hash_mib_s_iqr,
        server_hash_mib_s_p95,
        server_hash_mib_s_ci95_low,
        server_hash_mib_s_ci95_high,
    ) = flatten_metric(&summary.server_hash_mib_s);
    let (
        server_verify_mib_s_median,
        server_verify_mib_s_iqr,
        server_verify_mib_s_p95,
        server_verify_mib_s_ci95_low,
        server_verify_mib_s_ci95_high,
    ) = flatten_metric(&summary.server_verify_mib_s);
    let (
        server_total_mib_s_median,
        server_total_mib_s_iqr,
        server_total_mib_s_p95,
        server_total_mib_s_ci95_low,
        server_total_mib_s_ci95_high,
    ) = flatten_metric(&summary.server_total_mib_s);

    ConditionSummaryCsv {
        signature_profile: summary.signature_profile.clone(),
        hash_algorithm: summary.hash_algorithm.clone(),
        bucket: summary.bucket.clone(),
        benchmark_scenario: summary.benchmark_scenario.clone(),
        storage_state_label: summary.storage_state_label.clone(),
        measured_runs_total: summary.measured_runs_total,
        measured_runs_success: summary.measured_runs_success,
        measured_runs_failed: summary.measured_runs_failed,
        scenario_success_rate: summary.scenario_success_rate,
        verify_applicable_runs: summary.verify_applicable_runs,
        verify_ok_runs: summary.verify_ok_runs,
        verify_applicable_success_rate: summary.verify_applicable_success_rate,
        verify_success_rate: summary.verify_success_rate,
        server_telemetry_configured: summary.server_telemetry_configured,
        server_telemetry_coverage: summary.server_telemetry_coverage,
        setup_upload_ms_median,
        setup_upload_ms_iqr,
        setup_upload_ms_p95,
        setup_upload_ms_ci95_low,
        setup_upload_ms_ci95_high,
        setup_process_ms_median,
        setup_process_ms_iqr,
        setup_process_ms_p95,
        setup_process_ms_ci95_low,
        setup_process_ms_ci95_high,
        upload_ms_median,
        upload_ms_iqr,
        upload_ms_p95,
        upload_ms_ci95_low,
        upload_ms_ci95_high,
        process_ms_median,
        process_ms_iqr,
        process_ms_p95,
        process_ms_ci95_low,
        process_ms_ci95_high,
        verify_ms_median,
        verify_ms_iqr,
        verify_ms_p95,
        verify_ms_ci95_low,
        verify_ms_ci95_high,
        total_ms_median,
        total_ms_iqr,
        total_ms_p95,
        total_ms_ci95_low,
        total_ms_ci95_high,
        server_process_gateway_ms_median,
        server_process_gateway_ms_iqr,
        server_process_gateway_ms_p95,
        server_process_gateway_ms_ci95_low,
        server_process_gateway_ms_ci95_high,
        server_verify_gateway_ms_median,
        server_verify_gateway_ms_iqr,
        server_verify_gateway_ms_p95,
        server_verify_gateway_ms_ci95_low,
        server_verify_gateway_ms_ci95_high,
        server_hash_ms_median,
        server_hash_ms_iqr,
        server_hash_ms_p95,
        server_hash_ms_ci95_low,
        server_hash_ms_ci95_high,
        server_rsa_sign_ms_median,
        server_rsa_sign_ms_iqr,
        server_rsa_sign_ms_p95,
        server_rsa_sign_ms_ci95_low,
        server_rsa_sign_ms_ci95_high,
        server_eddsa_sign_ms_median,
        server_eddsa_sign_ms_iqr,
        server_eddsa_sign_ms_p95,
        server_eddsa_sign_ms_ci95_low,
        server_eddsa_sign_ms_ci95_high,
        server_ecdsa_sign_ms_median,
        server_ecdsa_sign_ms_iqr,
        server_ecdsa_sign_ms_p95,
        server_ecdsa_sign_ms_ci95_low,
        server_ecdsa_sign_ms_ci95_high,
        server_hmac_sign_ms_median,
        server_hmac_sign_ms_iqr,
        server_hmac_sign_ms_p95,
        server_hmac_sign_ms_ci95_low,
        server_hmac_sign_ms_ci95_high,
        server_ml_dsa_sign_ms_median,
        server_ml_dsa_sign_ms_iqr,
        server_ml_dsa_sign_ms_p95,
        server_ml_dsa_sign_ms_ci95_low,
        server_ml_dsa_sign_ms_ci95_high,
        server_slh_dsa_sign_ms_median,
        server_slh_dsa_sign_ms_iqr,
        server_slh_dsa_sign_ms_p95,
        server_slh_dsa_sign_ms_ci95_low,
        server_slh_dsa_sign_ms_ci95_high,
        server_fn_dsa_sign_ms_median,
        server_fn_dsa_sign_ms_iqr,
        server_fn_dsa_sign_ms_p95,
        server_fn_dsa_sign_ms_ci95_low,
        server_fn_dsa_sign_ms_ci95_high,
        server_eddsa_verify_ms_median,
        server_eddsa_verify_ms_iqr,
        server_eddsa_verify_ms_p95,
        server_eddsa_verify_ms_ci95_low,
        server_eddsa_verify_ms_ci95_high,
        server_ecdsa_verify_ms_median,
        server_ecdsa_verify_ms_iqr,
        server_ecdsa_verify_ms_p95,
        server_ecdsa_verify_ms_ci95_low,
        server_ecdsa_verify_ms_ci95_high,
        server_hmac_verify_ms_median,
        server_hmac_verify_ms_iqr,
        server_hmac_verify_ms_p95,
        server_hmac_verify_ms_ci95_low,
        server_hmac_verify_ms_ci95_high,
        server_ml_dsa_verify_ms_median,
        server_ml_dsa_verify_ms_iqr,
        server_ml_dsa_verify_ms_p95,
        server_ml_dsa_verify_ms_ci95_low,
        server_ml_dsa_verify_ms_ci95_high,
        server_slh_dsa_verify_ms_median,
        server_slh_dsa_verify_ms_iqr,
        server_slh_dsa_verify_ms_p95,
        server_slh_dsa_verify_ms_ci95_low,
        server_slh_dsa_verify_ms_ci95_high,
        server_fn_dsa_verify_ms_median,
        server_fn_dsa_verify_ms_iqr,
        server_fn_dsa_verify_ms_p95,
        server_fn_dsa_verify_ms_ci95_low,
        server_fn_dsa_verify_ms_ci95_high,
        server_verify_ms_median,
        server_verify_ms_iqr,
        server_verify_ms_p95,
        server_verify_ms_ci95_low,
        server_verify_ms_ci95_high,
        server_total_ms_median,
        server_total_ms_iqr,
        server_total_ms_p95,
        server_total_ms_ci95_low,
        server_total_ms_ci95_high,
        manifest_size_median,
        manifest_size_iqr,
        manifest_size_p95,
        manifest_size_ci95_low,
        manifest_size_ci95_high,
        manifest_core_bytes_median,
        manifest_core_bytes_iqr,
        manifest_core_bytes_p95,
        manifest_core_bytes_ci95_low,
        manifest_core_bytes_ci95_high,
        manifest_core_cbor_bytes_median,
        manifest_core_cbor_bytes_iqr,
        manifest_core_cbor_bytes_p95,
        manifest_core_cbor_bytes_ci95_low,
        manifest_core_cbor_bytes_ci95_high,
        manifest_envelope_bytes_median,
        manifest_envelope_bytes_iqr,
        manifest_envelope_bytes_p95,
        manifest_envelope_bytes_ci95_low,
        manifest_envelope_bytes_ci95_high,
        rsa_signature_bytes_median,
        rsa_signature_bytes_iqr,
        rsa_signature_bytes_p95,
        rsa_signature_bytes_ci95_low,
        rsa_signature_bytes_ci95_high,
        eddsa_signature_bytes_median,
        eddsa_signature_bytes_iqr,
        eddsa_signature_bytes_p95,
        eddsa_signature_bytes_ci95_low,
        eddsa_signature_bytes_ci95_high,
        ecdsa_signature_bytes_median,
        ecdsa_signature_bytes_iqr,
        ecdsa_signature_bytes_p95,
        ecdsa_signature_bytes_ci95_low,
        ecdsa_signature_bytes_ci95_high,
        hmac_signature_bytes_median,
        hmac_signature_bytes_iqr,
        hmac_signature_bytes_p95,
        hmac_signature_bytes_ci95_low,
        hmac_signature_bytes_ci95_high,
        ml_dsa_signature_bytes_median,
        ml_dsa_signature_bytes_iqr,
        ml_dsa_signature_bytes_p95,
        ml_dsa_signature_bytes_ci95_low,
        ml_dsa_signature_bytes_ci95_high,
        slh_dsa_signature_bytes_median,
        slh_dsa_signature_bytes_iqr,
        slh_dsa_signature_bytes_p95,
        slh_dsa_signature_bytes_ci95_low,
        slh_dsa_signature_bytes_ci95_high,
        fn_dsa_signature_bytes_median,
        fn_dsa_signature_bytes_iqr,
        fn_dsa_signature_bytes_p95,
        fn_dsa_signature_bytes_ci95_low,
        fn_dsa_signature_bytes_ci95_high,
        signature_size_median,
        signature_size_iqr,
        signature_size_p95,
        signature_size_ci95_low,
        signature_size_ci95_high,
        manifest_overhead_pct_median,
        manifest_overhead_pct_iqr,
        manifest_overhead_pct_p95,
        manifest_overhead_pct_ci95_low,
        manifest_overhead_pct_ci95_high,
        signature_overhead_pct_median,
        signature_overhead_pct_iqr,
        signature_overhead_pct_p95,
        signature_overhead_pct_ci95_low,
        signature_overhead_pct_ci95_high,
        storage_amplification_median,
        storage_amplification_iqr,
        storage_amplification_p95,
        storage_amplification_ci95_low,
        storage_amplification_ci95_high,
        client_total_mib_s_median,
        client_total_mib_s_iqr,
        client_total_mib_s_p95,
        client_total_mib_s_ci95_low,
        client_total_mib_s_ci95_high,
        server_hash_mib_s_median,
        server_hash_mib_s_iqr,
        server_hash_mib_s_p95,
        server_hash_mib_s_ci95_low,
        server_hash_mib_s_ci95_high,
        server_verify_mib_s_median,
        server_verify_mib_s_iqr,
        server_verify_mib_s_p95,
        server_verify_mib_s_ci95_low,
        server_verify_mib_s_ci95_high,
        server_total_mib_s_median,
        server_total_mib_s_iqr,
        server_total_mib_s_p95,
        server_total_mib_s_ci95_low,
        server_total_mib_s_ci95_high,
        ratio_vs_rsa_pss_total_median: summary.ratio_vs_rsa_pss_total_median,
        ratio_vs_rsa_pss_server_total_median: summary.ratio_vs_rsa_pss_server_total_median,
    }
}

fn flatten_metric(
    metric: &Option<MetricSummary>,
) -> (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
) {
    match metric {
        Some(value) => (
            Some(value.median),
            Some(value.iqr),
            Some(value.p95),
            value.ci95_low,
            value.ci95_high,
        ),
        None => (None, None, None, None, None),
    }
}

/// Load dataset manifest from the dataset directory for host-independent provenance.
///
/// Reads `dataset-metadata.json` for the seed and `dataset-manifest.csv` for per-file
/// entries. Missing files are silently ignored — provenance fields will be None in that case.
fn load_dataset_manifest(dataset_dir: &Path) -> DatasetManifest {
    let mut manifest = DatasetManifest::default();

    // Load seed from dataset-metadata.json
    let metadata_path = dataset_dir.join("dataset-metadata.json");
    if let Ok(text) = std::fs::read_to_string(&metadata_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(seed) = json.get("seed").and_then(|v| v.as_str()) {
                manifest.seed = Some(seed.to_string());
            }
        }
    }

    // Load entries from dataset-manifest.csv
    let csv_path = dataset_dir.join("dataset-manifest.csv");
    if let Ok(mut reader) = csv::Reader::from_path(&csv_path) {
        for result in reader.records() {
            let Ok(record) = result else { continue };
            let index: u32 = record.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
            let file_type = record.get(2).unwrap_or("").to_string();
            let relative_path = record.get(4).unwrap_or("").to_string();
            let seed = record.get(5).unwrap_or("").to_string();

            if relative_path.is_empty() {
                continue;
            }

            // Key by absolute path for fast lookup during runs.
            let abs = dataset_dir.join(&relative_path);
            let abs_str = abs.display().to_string();

            let entry = DatasetFileEntry {
                index,
                file_type,
                relative_path: relative_path.clone(),
                seed: if seed.is_empty() {
                    manifest.seed.clone().unwrap_or_default()
                } else {
                    seed
                },
            };
            manifest.entries.insert(abs_str, entry);
        }
    }

    manifest
}

fn collect_dataset_file_types(manifest: &DatasetManifest) -> Vec<String> {
    let mut values = manifest
        .entries
        .values()
        .map(|entry| entry.file_type.clone())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

/// Specification for a single metric in the evidence table.
struct EvidenceMetricSpec {
    name: &'static str,
    unit: &'static str,
    scope: &'static str,
    /// Returns (Some(value), is_applicable_for_this_scenario) from a ConditionSummary.
    extract: fn(&ConditionSummary) -> (Option<&MetricSummary>, bool),
}

/// Build the long-form primary evidence metrics table from condition summaries.
///
/// Each row represents one (condition, metric) combination with explicit coverage
/// and applicability metadata. Null values are always interpretable.
fn build_evidence_metrics(
    summaries: &[ConditionSummary],
    _bootstrap_samples: usize,
    _seed: u64,
) -> Vec<EvidenceMetricRow> {
    let specs: &[EvidenceMetricSpec] = &[
        // ── Setup timings (fixture overhead; present for all scenarios) ────────
        EvidenceMetricSpec {
            name: "setup_upload_ms",
            unit: "ms",
            scope: "setup",
            extract: |s| (s.setup_upload_ms.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "setup_process_ms",
            unit: "ms",
            scope: "setup",
            extract: |s| (s.setup_process_ms.as_ref(), true),
        },
        // ── Client end-to-end timings ─────────────────────────────────────────
        EvidenceMetricSpec {
            name: "client_total_ms",
            unit: "ms",
            scope: "client",
            extract: |s| (s.total_ms.as_ref(), true),
        },
        // ── Server-attributed crypto timings ──────────────────────────────────
        EvidenceMetricSpec {
            name: "server_hash_ms",
            unit: "ms",
            scope: "server",
            extract: |s| (s.server_hash_ms.as_ref(), s.server_telemetry_configured),
        },
        EvidenceMetricSpec {
            name: "server_rsa_sign_ms",
            unit: "ms",
            scope: "server",
            extract: |s| (s.server_rsa_sign_ms.as_ref(), s.server_telemetry_configured),
        },
        EvidenceMetricSpec {
            name: "server_eddsa_sign_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_eddsa_sign_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_ecdsa_sign_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_ecdsa_sign_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_hmac_sign_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_hmac_sign_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_ml_dsa_sign_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_ml_dsa_sign_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_slh_dsa_sign_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_slh_dsa_sign_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_fn_dsa_sign_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_fn_dsa_sign_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_eddsa_verify_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_eddsa_verify_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_ecdsa_verify_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_ecdsa_verify_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_hmac_verify_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_hmac_verify_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_ml_dsa_verify_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_ml_dsa_verify_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_slh_dsa_verify_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_slh_dsa_verify_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_fn_dsa_verify_ms",
            unit: "ms",
            scope: "server",
            extract: |s| {
                (
                    s.server_fn_dsa_verify_ms.as_ref(),
                    s.server_telemetry_configured,
                )
            },
        },
        EvidenceMetricSpec {
            name: "server_verify_ms",
            unit: "ms",
            scope: "server",
            extract: |s| (s.server_verify_ms.as_ref(), s.server_telemetry_configured),
        },
        EvidenceMetricSpec {
            name: "server_total_ms",
            unit: "ms",
            scope: "server",
            extract: |s| (s.server_total_ms.as_ref(), s.server_telemetry_configured),
        },
        // ── Artifact size metrics (crypto-relevant) ───────────────────────────
        EvidenceMetricSpec {
            name: "manifest_core_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.manifest_core_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "manifest_core_cbor_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.manifest_core_cbor_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "rsa_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.rsa_signature_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "eddsa_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.eddsa_signature_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "ecdsa_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.ecdsa_signature_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "hmac_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.hmac_signature_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "ml_dsa_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.ml_dsa_signature_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "slh_dsa_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.slh_dsa_signature_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "fn_dsa_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.fn_dsa_signature_bytes.as_ref(), true),
        },
        EvidenceMetricSpec {
            name: "total_signature_bytes",
            unit: "bytes",
            scope: "artifact",
            extract: |s| (s.total_signature_bytes.as_ref(), true),
        },
    ];

    let mut rows = Vec::new();

    for summary in summaries {
        // Only emit evidence rows for measured-phase summaries (all summaries are measured).
        for spec in specs {
            let (metric_opt, is_applicable) = (spec.extract)(summary);

            let metric_applicability = if !is_applicable {
                "not_configured"
            } else if metric_opt.is_none() {
                // or the scenario doesn't produce this metric. Label as not_applicable.
                "not_applicable"
            } else {
                "applicable"
            };

            let (n, coverage, median, iqr, p95, ci95_low, ci95_high) = match metric_opt {
                Some(m) => {
                    let cov = if summary.measured_runs_success == 0 {
                        0.0
                    } else {
                        m.n as f64 / summary.measured_runs_success as f64
                    };
                    (
                        Some(m.n),
                        Some(cov),
                        Some(m.median),
                        Some(m.iqr),
                        Some(m.p95),
                        m.ci95_low,
                        m.ci95_high,
                    )
                }
                None => (None, None, None, None, None, None, None),
            };

            rows.push(EvidenceMetricRow {
                benchmark_scenario: summary.benchmark_scenario.clone(),
                storage_state: summary.storage_state_label.clone(),
                signature_profile: summary.signature_profile.clone(),
                hash_algorithm: summary.hash_algorithm.clone(),
                bucket: summary.bucket.clone(),
                metric_name: spec.name.to_string(),
                metric_unit: spec.unit,
                metric_scope: spec.scope,
                metric_applicability,
                n,
                coverage,
                median,
                iqr,
                p95,
                ci95_low,
                ci95_high,
            });
        }
    }

    rows
}
