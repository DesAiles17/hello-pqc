use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use pqc_hons::OperationMetricsResponse;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use reqwest::{multipart, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Parser, Debug, Clone)]
#[command(name = "benchmark-cli")]
#[command(about = "Headless benchmark runner for classical vs PQC vs hybrid signing")]
struct Cli {
    #[arg(long, default_value = "http://localhost:3000")]
    base_url: String,

    #[arg(long, env = "PQC_API_KEY")]
    api_key: String,

    #[arg(long)]
    dataset_dir: PathBuf,

    #[arg(long, default_value = "output/benchmarks")]
    output_dir: PathBuf,

    #[arg(long, value_delimiter = ',', default_value = "classical,pqc,hybrid")]
    profiles: Vec<String>,

    #[arg(long, value_delimiter = ',', default_value = "sha256,keccak256")]
    hashes: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        default_value = "10KB,100KB,1MB,10MB,50MB"
    )]
    buckets: Vec<String>,

    #[arg(long, value_delimiter = ',', default_value = "workflow")]
    scenarios: Vec<String>,

    #[arg(long, default_value_t = 30)]
    measured_runs: u32,

    #[arg(long, default_value_t = 3)]
    warmup_runs: u32,

    #[arg(long, default_value_t = 0)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Warmup,
    Measured,
}

#[derive(Debug, Clone)]
struct BucketSpec {
    label: String,
    min_bytes: u64,
    max_bytes: u64,
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
struct VerifyResponse {
    request_id: String,
    signature_ok: bool,
    object_ok: bool,
    file_hash_match: bool,
    overall_ok: bool,
    errors: Vec<String>,
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
    dilithium: Option<String>,
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
    file_path: String,
    file_extension: Option<String>,
    file_size_bytes: u64,
    request_id: Option<String>,
    upload_http_ok: bool,
    process_http_ok: bool,
    verify_http_ok: bool,
    scenario_success: bool,
    verify_overall_ok: Option<bool>,
    client_upload_ms: Option<f64>,
    client_process_ms: Option<f64>,
    client_verify_ms: Option<f64>,
    client_total_ms: Option<f64>,
    manifest_size_bytes: Option<usize>,
    manifest_core_bytes: Option<usize>,
    manifest_core_cbor_bytes: Option<usize>,
    manifest_envelope_bytes: Option<usize>,
    rsa_signature_bytes: Option<usize>,
    dilithium_signature_bytes: Option<usize>,
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
    server_dilithium_sign_ms: Option<f64>,
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
    verify_success_rate: f64,
    upload_ms: Option<MetricSummary>,
    process_ms: Option<MetricSummary>,
    verify_ms: Option<MetricSummary>,
    total_ms: Option<MetricSummary>,
    server_hash_ms: Option<MetricSummary>,
    server_rsa_sign_ms: Option<MetricSummary>,
    server_dilithium_sign_ms: Option<MetricSummary>,
    server_verify_ms: Option<MetricSummary>,
    server_total_ms: Option<MetricSummary>,
    manifest_size_bytes: Option<MetricSummary>,
    total_signature_bytes: Option<MetricSummary>,
    manifest_overhead_pct: Option<MetricSummary>,
    signature_overhead_pct: Option<MetricSummary>,
    storage_amplification: Option<MetricSummary>,
    client_total_mib_s: Option<MetricSummary>,
    server_hash_mib_s: Option<MetricSummary>,
    server_verify_mib_s: Option<MetricSummary>,
    server_total_mib_s: Option<MetricSummary>,
    s_pqc_vs_classical_total_median: Option<f64>,
    s_hybrid_vs_classical_total_median: Option<f64>,
    s_pqc_vs_classical_server_total_median: Option<f64>,
    s_hybrid_vs_classical_server_total_median: Option<f64>,
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
    verify_success_rate: f64,
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
    server_dilithium_sign_ms_median: Option<f64>,
    server_dilithium_sign_ms_iqr: Option<f64>,
    server_dilithium_sign_ms_p95: Option<f64>,
    server_dilithium_sign_ms_ci95_low: Option<f64>,
    server_dilithium_sign_ms_ci95_high: Option<f64>,
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
    s_pqc_vs_classical_total_median: Option<f64>,
    s_hybrid_vs_classical_total_median: Option<f64>,
    s_pqc_vs_classical_server_total_median: Option<f64>,
    s_hybrid_vs_classical_server_total_median: Option<f64>,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    generated_at: String,
    cli_config: CliReportConfig,
    environment: EnvironmentMetadata,
    raw_runs: Vec<RunRecord>,
    summaries: Vec<ConditionSummary>,
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

        let run_idx = (idx + 1) as u64;
        let record = run_single_job(&client, &cli, run_idx, job, &selected).await;

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
        },
        environment: collect_environment_metadata(),
        raw_runs: run_records.clone(),
        summaries: summaries.clone(),
    };

    write_outputs(&cli.output_dir, &report, &run_records, &summaries).await?;

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
) -> RunRecord {
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
        file_path: selected_file.display().to_string(),
        file_extension: selected_file
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_string()),
        file_size_bytes: 0,
        request_id: None,
        upload_http_ok: false,
        process_http_ok: false,
        verify_http_ok: false,
        scenario_success: false,
        verify_overall_ok: None,
        client_upload_ms: None,
        client_process_ms: None,
        client_verify_ms: None,
        client_total_ms: None,
        manifest_size_bytes: None,
        manifest_core_bytes: None,
        manifest_core_cbor_bytes: None,
        manifest_envelope_bytes: None,
        rsa_signature_bytes: None,
        dilithium_signature_bytes: None,
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
        server_dilithium_sign_ms: None,
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
            record.scenario_success = flow.scenario_success;
            record.verify_overall_ok = flow.verify_overall_ok;
            record.client_upload_ms = flow.client_upload_ms;
            record.client_process_ms = flow.client_process_ms;
            record.client_verify_ms = flow.client_verify_ms;
            record.client_total_ms = flow.client_total_ms;
            record.manifest_size_bytes = Some(flow.manifest_size_bytes);
            record.manifest_core_bytes = Some(flow.manifest_core_bytes);
            record.manifest_core_cbor_bytes = Some(flow.manifest_core_cbor_bytes);
            record.manifest_envelope_bytes = Some(flow.manifest_envelope_bytes);
            record.rsa_signature_bytes = flow.rsa_signature_bytes;
            record.dilithium_signature_bytes = flow.dilithium_signature_bytes;
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
            record.server_dilithium_sign_ms = flow.server_dilithium_sign_ms;
            record.server_manifest_fetch_db_lookup_ms = flow.server_manifest_fetch_db_lookup_ms;
            record.server_verify_hash_ms = flow.server_verify_hash_ms;
            record.server_verify_canonicalize_ms = flow.server_verify_canonicalize_ms;
            record.server_signature_verify_ms = flow.server_signature_verify_ms;
            record.server_stored_object_verify_ms = flow.server_stored_object_verify_ms;
            record.server_uploaded_content_verify_ms = flow.server_uploaded_content_verify_ms;
            record.server_verify_ms = flow.server_verify_ms;
            record.server_total_ms = flow.server_total_ms;

            if flow.verify_overall_ok == Some(false) || !flow.scenario_success {
                record.error_stage = Some("scenario".to_string());
                record.error = Some("Verification returned overall_ok=false".to_string());
            }
        }
        Err(err) => {
            let message = err.to_string();
            let stage = classify_error_stage(&message);
            record.error_stage = Some(stage.to_string());
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
    scenario_success: bool,
    upload_http_ok: bool,
    process_http_ok: bool,
    verify_http_ok: bool,
    request_id: String,
    verify_overall_ok: Option<bool>,
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
    dilithium_signature_bytes: Option<usize>,
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
    server_dilithium_sign_ms: Option<f64>,
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
    server_dilithium_sign_ms: Option<f64>,
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

    let fixture = prepare_signed_fixture(client, cli, condition, file_path).await?;
    let artifact_metrics = compute_artifact_metrics(&fixture.process.manifest, file_size)?;

    let mut client_upload_ms = None;
    let mut client_process_ms = None;
    let mut client_verify_ms = None;
    let mut verify_overall_ok = None;
    let mut upload_http_ok = true;
    let mut process_http_ok = true;
    let mut verify_http_ok = false;
    let scenario_success;

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
            client_upload_ms = Some(fixture.client_upload_ms);
            client_process_ms = Some(fixture.client_process_ms);
            client_verify_ms = Some(verify.client_verify_ms);
            verify_overall_ok = Some(verify.verify.overall_ok);
            verify_http_ok = true;
            scenario_success = verify.verify.overall_ok;
        }
        ScenarioKind::SignOnly => {
            client_upload_ms = Some(fixture.client_upload_ms);
            client_process_ms = Some(fixture.client_process_ms);
            scenario_success = true;
        }
        ScenarioKind::VerifyManifest => {
            let verify = verify_request_call(client, cli, &fixture.request_id, false, None)
                .await
                .map_err(|err| stage_error("verify", err))?;
            client_verify_ms = Some(verify.client_verify_ms);
            verify_overall_ok = Some(verify.verify.overall_ok);
            verify_http_ok = true;
            scenario_success = verify.verify.overall_ok;
        }
        ScenarioKind::VerifyStored => {
            let verify = verify_request_call(client, cli, &fixture.request_id, true, None)
                .await
                .map_err(|err| stage_error("verify", err))?;
            client_verify_ms = Some(verify.client_verify_ms);
            verify_overall_ok = Some(verify.verify.overall_ok);
            verify_http_ok = true;
            scenario_success = verify.verify.overall_ok;
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
            client_verify_ms = Some(verify.client_verify_ms);
            verify_overall_ok = Some(verify.verify.overall_ok);
            verify_http_ok = true;
            scenario_success = verify.verify.overall_ok;
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
            client_verify_ms = Some(verify.client_verify_ms);
            verify_overall_ok = Some(verify.verify.overall_ok);
            verify_http_ok = true;
            scenario_success = verify.verify.overall_ok;
        }
    }

    let derived = if let Some(ops_url) = cli.operations_endpoint.as_deref() {
        fetch_operations_metrics(client, ops_url, &cli.api_key, &fixture.request_id)
            .await
            .ok()
            .map(|value| derive_server_metrics(&value))
            .unwrap_or_else(empty_server_metrics)
    } else {
        empty_server_metrics()
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

    let client_upload_mib_s = client_upload_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));
    let client_process_mib_s = client_process_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));
    let client_verify_mib_s = client_verify_ms.and_then(|ms| throughput_mib_per_s(file_size, ms));
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
        ScenarioKind::VerifyUploaded | ScenarioKind::VerifyFull => derived.storage_bytes_written,
    };
    let storage_bytes_read = match scenario {
        ScenarioKind::Workflow => derived.storage_bytes_read,
        ScenarioKind::SignOnly => None,
        ScenarioKind::VerifyManifest => None,
        ScenarioKind::VerifyStored | ScenarioKind::VerifyUploaded | ScenarioKind::VerifyFull => {
            derived.storage_bytes_read
        }
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
        scenario_success,
        upload_http_ok,
        process_http_ok,
        verify_http_ok,
        request_id: fixture.request_id,
        verify_overall_ok,
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
        dilithium_signature_bytes: artifact_metrics.dilithium_signature_bytes,
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
        server_dilithium_sign_ms: derived.server_dilithium_sign_ms,
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
    dilithium_signature_bytes: Option<usize>,
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
) -> Result<PreparedFixture> {
    let upload = upload_dataset_file(client, cli, file_path)
        .await
        .map_err(|err| stage_error("upload", err))?;
    let process = process_uploaded_file(client, cli, condition, &upload.upload.file_path)
        .await
        .map_err(|err| stage_error("process", err))?;

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

async fn process_uploaded_file(
    client: &Client,
    cli: &Cli,
    condition: &Condition,
    uploaded_path: &str,
) -> Result<ProcessStageResult> {
    let process_url = format!("{}/process", cli.base_url.trim_end_matches('/'));
    let process_payload = ProcessRequest {
        file_path: uploaded_path.to_string(),
        signature_profile: to_gateway_profile(&condition.signature_profile).to_string(),
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
) -> Result<OperationMetricsResponse> {
    let url =
        reqwest::Url::parse(operations_endpoint).context("Invalid operations-endpoint URL")?;

    let mut request_url = url.clone();
    request_url
        .query_pairs_mut()
        .append_pair("request_id", request_id);

    let resp = client
        .get(request_url)
        .header("X-API-Key", api_key)
        .send()
        .await
        .context("Failed calling operations endpoint")?;

    if !resp.status().is_success() {
        bail!("Operations endpoint returned status {}", resp.status());
    }

    resp.json().await.context("Failed to parse operations JSON")
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
        server_rsa_sign_ms: process_manifest.and_then(|metrics| metrics.rsa_sign_ms),
        server_dilithium_sign_ms: process_manifest.and_then(|metrics| metrics.dilithium_sign_ms),
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
        server_dilithium_sign_ms: None,
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
    let rsa_signature_bytes = manifest
        .signatures
        .rsa_pss
        .as_ref()
        .map(|value| base64_decoded_len_approx(value));
    let dilithium_signature_bytes = manifest
        .signatures
        .dilithium
        .as_ref()
        .map(|value| base64_decoded_len_approx(value));
    let total_signature_bytes = match (rsa_signature_bytes, dilithium_signature_bytes) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
    };

    Ok(ArtifactMetrics {
        manifest_size_bytes,
        manifest_core_bytes,
        manifest_core_cbor_bytes,
        manifest_envelope_bytes,
        rsa_signature_bytes,
        dilithium_signature_bytes,
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
    let mut out = Vec::new();
    for p in input {
        let normalized = match p.trim().to_ascii_lowercase().as_str() {
            "classical" | "classical_only" | "classic" | "rsa" => "classical",
            "pqc" | "pqc_only" | "dilithium" => "pqc",
            "hybrid" => "hybrid",
            other => bail!("Unsupported profile '{}'", other),
        };
        if !out.iter().any(|v| v == normalized) {
            out.push(normalized.to_string());
        }
    }
    Ok(out)
}

fn normalize_hashes(input: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for h in input {
        let normalized = match h.trim().to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => "sha256",
            "keccak" | "keccak256" | "keccak-256" => "keccak256",
            other => bail!("Unsupported hash algorithm '{}'", other),
        };
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

fn to_gateway_profile(profile: &str) -> &str {
    match profile {
        "classical" => "classical_only",
        "pqc" => "pqc_only",
        "hybrid" => "hybrid",
        _ => profile,
    }
}

fn to_gateway_hash(hash: &str) -> &str {
    match hash {
        "sha256" => "SHA256",
        "keccak256" => "KECCAK256",
        _ => hash,
    }
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
            out.push(path);
        }
    }
    Ok(())
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
                    .filter(|r| r.scenario_success)
                    .collect();

                let verify_ok = records
                    .iter()
                    .filter(|r| r.verify_overall_ok.unwrap_or(false))
                    .count();
                let scenario_success = records.iter().filter(|r| r.scenario_success).count();

                let upload_vals = collect_metric(&successes, |r| r.client_upload_ms);
                let process_vals = collect_metric(&successes, |r| r.client_process_ms);
                let verify_vals = collect_metric(&successes, |r| r.client_verify_ms);
                let total_vals = collect_metric(&successes, |r| r.client_total_ms);
                let server_hash_vals = collect_metric(&successes, |r| r.server_hash_ms);
                let server_rsa_sign_vals = collect_metric(&successes, |r| r.server_rsa_sign_ms);
                let server_dilithium_sign_vals =
                    collect_metric(&successes, |r| r.server_dilithium_sign_ms);
                let server_verify_vals = collect_metric(&successes, |r| r.server_verify_ms);
                let server_total_vals = collect_metric(&successes, |r| r.server_total_ms);
                let manifest_vals =
                    collect_metric(&successes, |r| r.manifest_size_bytes.map(|v| v as f64));
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
                        scenario_success as f64 / records.len() as f64
                    },
                    verify_success_rate: if records.is_empty() {
                        0.0
                    } else {
                        verify_ok as f64 / records.len() as f64
                    },
                    upload_ms: summarize_metric(&upload_vals, bootstrap_samples, seed),
                    process_ms: summarize_metric(&process_vals, bootstrap_samples, seed),
                    verify_ms: summarize_metric(&verify_vals, bootstrap_samples, seed),
                    total_ms: summarize_metric(&total_vals, bootstrap_samples, seed),
                    server_hash_ms: summarize_metric(&server_hash_vals, bootstrap_samples, seed),
                    server_rsa_sign_ms: summarize_metric(
                        &server_rsa_sign_vals,
                        bootstrap_samples,
                        seed,
                    ),
                    server_dilithium_sign_ms: summarize_metric(
                        &server_dilithium_sign_vals,
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
                    s_pqc_vs_classical_total_median: None,
                    s_hybrid_vs_classical_total_median: None,
                    s_pqc_vs_classical_server_total_median: None,
                    s_hybrid_vs_classical_server_total_median: None,
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
        if summary.signature_profile == "classical" {
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
                    if summary.signature_profile == "pqc" {
                        summary.s_pqc_vs_classical_total_median = Some(total.median / base);
                    } else if summary.signature_profile == "hybrid" {
                        summary.s_hybrid_vs_classical_total_median = Some(total.median / base);
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
                    if summary.signature_profile == "pqc" {
                        summary.s_pqc_vs_classical_server_total_median = Some(total.median / base);
                    } else if summary.signature_profile == "hybrid" {
                        summary.s_hybrid_vs_classical_server_total_median =
                            Some(total.median / base);
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
) -> Result<()> {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let json_path = output_dir.join(format!("benchmark-report-{}.json", ts));
    let runs_csv_path = output_dir.join(format!("benchmark-runs-{}.csv", ts));
    let summary_csv_path = output_dir.join(format!("benchmark-summary-{}.csv", ts));

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

    Ok(())
}

fn flatten_summary_csv(summary: &ConditionSummary) -> ConditionSummaryCsv {
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
        server_dilithium_sign_ms_median,
        server_dilithium_sign_ms_iqr,
        server_dilithium_sign_ms_p95,
        server_dilithium_sign_ms_ci95_low,
        server_dilithium_sign_ms_ci95_high,
    ) = flatten_metric(&summary.server_dilithium_sign_ms);
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
        verify_success_rate: summary.verify_success_rate,
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
        server_dilithium_sign_ms_median,
        server_dilithium_sign_ms_iqr,
        server_dilithium_sign_ms_p95,
        server_dilithium_sign_ms_ci95_low,
        server_dilithium_sign_ms_ci95_high,
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
        s_pqc_vs_classical_total_median: summary.s_pqc_vs_classical_total_median,
        s_hybrid_vs_classical_total_median: summary.s_hybrid_vs_classical_total_median,
        s_pqc_vs_classical_server_total_median: summary.s_pqc_vs_classical_server_total_median,
        s_hybrid_vs_classical_server_total_median: summary
            .s_hybrid_vs_classical_server_total_median,
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
