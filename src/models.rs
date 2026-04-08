use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashTimingMetrics {
    pub hash_compute_ms: f64,
    pub object_exists_check_ms: f64,
    pub object_store_ms: f64,
    pub total_ms: f64,
    #[serde(default)]
    pub bytes_read: u64,
    #[serde(default)]
    pub bytes_written: u64,
    #[serde(default)]
    pub object_store_hit: bool,
    #[serde(default)]
    pub multipart_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBuildTimingMetrics {
    pub canonicalize_ms: f64,
    #[serde(default)]
    pub rsa_sign_ms: Option<f64>,
    #[serde(default)]
    pub eddsa_sign_ms: Option<f64>,
    #[serde(default)]
    pub ecdsa_sign_ms: Option<f64>,
    #[serde(default)]
    pub hmac_sign_ms: Option<f64>,
    #[serde(default)]
    pub ml_dsa_sign_ms: Option<f64>,
    #[serde(default)]
    pub slh_dsa_sign_ms: Option<f64>,
    #[serde(default)]
    pub fn_dsa_sign_ms: Option<f64>,
    pub db_persist_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchManifestTimingMetrics {
    pub db_lookup_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTimingMetrics {
    pub db_lookup_ms: f64,
    pub canonicalize_ms: f64,
    pub signature_verify_ms: f64,
    #[serde(default)]
    pub rsa_verify_ms: Option<f64>,
    #[serde(default)]
    pub eddsa_verify_ms: Option<f64>,
    #[serde(default)]
    pub ecdsa_verify_ms: Option<f64>,
    #[serde(default)]
    pub hmac_verify_ms: Option<f64>,
    #[serde(default)]
    pub ml_dsa_verify_ms: Option<f64>,
    #[serde(default)]
    pub slh_dsa_verify_ms: Option<f64>,
    #[serde(default)]
    pub fn_dsa_verify_ms: Option<f64>,
    pub stored_object_verify_ms: f64,
    #[serde(default)]
    pub stored_object_bytes_read: u64,
    pub uploaded_content_verify_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperationMetrics {
    pub gateway_total_ms: f64,
    pub hasher_roundtrip_ms: f64,
    #[serde(default)]
    pub hash_metrics: Option<HashTimingMetrics>,
    pub manifest_roundtrip_ms: f64,
    #[serde(default)]
    pub manifest_metrics: Option<ManifestBuildTimingMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyOperationMetrics {
    pub gateway_total_ms: f64,
    pub manifest_fetch_roundtrip_ms: Option<f64>,
    #[serde(default)]
    pub manifest_fetch_metrics: Option<FetchManifestTimingMetrics>,
    pub verify_hash_roundtrip_ms: Option<f64>,
    #[serde(default)]
    pub verify_hash_metrics: Option<HashTimingMetrics>,
    pub manifest_verify_roundtrip_ms: f64,
    #[serde(default)]
    pub manifest_verify_metrics: Option<VerifyTimingMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMetricsResponse {
    pub request_id: String,
    #[serde(default)]
    pub signature_profile: Option<String>,
    #[serde(default)]
    pub hash_algorithm: Option<String>,
    #[serde(default)]
    pub file_size_bytes: Option<u64>,
    #[serde(default)]
    pub process: Option<ProcessOperationMetrics>,
    #[serde(default)]
    pub verify: Option<VerifyOperationMetrics>,
    #[serde(default)]
    pub recorded_at: Option<String>,
}

/// Request from API Gateway to Hasher Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashRequest {
    pub file_path: String,
    pub request_id: String,
    pub storage_bucket: Option<String>,
    pub hash_algorithm: Option<String>,
}

/// Response from Hasher Service containing hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResponse {
    pub request_id: String,
    pub hash: String,
    pub algorithm: String,
    pub file_size: u64,
    pub storage_bucket: String,
    pub storage_key: String,
    pub immutable_object_id: String,
    #[serde(default)]
    pub metrics: Option<HashTimingMetrics>,
}

/// Request from API Gateway to Manifest Builder Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRequest {
    pub request_id: String,
    /// Internal-only: API key fingerprint of the authenticated caller
    #[serde(default)]
    pub owner_key_fingerprint: Option<String>,
    pub hash: String,
    pub algorithm: String,
    pub file_size: u64,
    pub file_path: String,
    pub storage_bucket: String,
    pub storage_key: String,
    pub immutable_object_id: String,
    pub schema_version: Option<String>,
    pub domain_sep: Option<String>,
    pub signature_profile: Option<String>,
}

/// Canonical, signed manifest core (deterministic fields only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestCore {
    pub schema_version: String,
    pub domain_sep: String,
    pub signature_profile: String,
    pub request_id: String,
    pub immutable_object_id: String,
    pub hash: String,
    pub algorithm: String,
    pub size: u64,
    pub storage_bucket: String,
    pub storage_key: String,
}

/// Unsigned manifest envelope (auditable metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEnvelope {
    pub created_at: DateTime<Utc>,
    pub context: String,
    pub original_path: String,
    pub source_file_metadata: Option<SourceFileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFileMetadata {
    pub created_at: Option<String>,
    pub last_modified_at: Option<String>,
    pub last_accessed_at: Option<String>,
}

/// Signatures over the canonical manifest (one field per supported algorithm)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signatures {
    /// RSA-PSS signature (base64)
    pub rsa_pss: Option<String>,
    /// ml_dsa-3 signature (base64)
    /// Ed25519 (EdDSA) signature (base64)
    #[serde(default)]
    pub eddsa: Option<String>,
    /// ECDSA P-256 DER signature (base64)
    #[serde(default)]
    pub ecdsa_p256: Option<String>,
    /// HMAC-SHA256 MAC (base64)
    #[serde(default)]
    pub hmac_sha256: Option<String>,
    /// ML-DSA-65 (FIPS 204) signature (base64)
    #[serde(default)]
    pub ml_dsa: Option<String>,
    /// SLH-DSA-SHAKE-128s (FIPS 205) signature (base64)
    #[serde(default)]
    pub slh_dsa: Option<String>,
    /// fn_dsa-512 detached signature (base64)
    #[serde(default)]
    pub fn_dsa: Option<String>,
}

/// Signed manifest envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub core: ManifestCore,
    pub envelope: ManifestEnvelope,
    pub signatures: Signatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBuildResponse {
    pub manifest: SignedManifest,
    #[serde(default)]
    pub metrics: Option<ManifestBuildTimingMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchManifestResponse {
    pub manifest: SignedManifest,
    #[serde(default)]
    pub metrics: Option<FetchManifestTimingMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub request_id: String,
    /// Internal-only: API key fingerprint of the authenticated caller
    #[serde(default)]
    pub owner_key_fingerprint: Option<String>,
    pub verify_object: bool,
    /// Optional: path to file for verification (will be hashed and compared)
    pub file_path: Option<String>,
    /// Optional: if provided, verify the uploaded file's hash matches the manifest
    pub provided_hash: Option<String>,
    /// Optional: if provided, verify uploaded file size matches manifest size
    pub provided_size: Option<u64>,
    /// Optional: if provided, verify uploaded file hash algorithm matches manifest algorithm
    pub provided_algorithm: Option<String>,
    /// Optional: if provided, verify uploaded file immutable object id matches manifest
    pub provided_immutable_object_id: Option<String>,
    /// Optional: if provided, verify uploaded file storage bucket matches manifest
    pub provided_storage_bucket: Option<String>,
    /// Optional: if provided, verify uploaded file storage key matches manifest
    pub provided_storage_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub request_id: String,
    pub signature_ok: bool,
    pub object_ok: bool,
    pub file_hash_match: bool,
    /// True if provided_hash matches manifest hash
    pub overall_ok: bool,
    pub errors: Vec<String>,
    #[serde(default)]
    pub checks: Vec<VerificationCheck>,
    #[serde(default)]
    pub metadata: Option<VerificationMetadata>,
    #[serde(default)]
    pub metrics: Option<VerifyTimingMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub passed: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMetadata {
    pub signature_profile: String,
    pub hash_algorithm: String,
    pub canonical_manifest_hash: String,
    pub manifest_created_at: String,
    pub manifest_size: u64,
    pub storage_bucket: String,
    pub storage_key: String,
}

/// Request to delete an uploaded file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadCleanupRequest {
    pub file_path: String,
}

/// Error response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub request_id: Option<String>,
}
pub fn normalize_benchmark_profile(input: &str) -> Option<String> {
    let lower = input.trim().to_ascii_lowercase();

    let basic = match lower.as_str() {
        "classical" | "classical_only" | "classic" | "rsa" | "rsa_pss" | "rsa-pss" => {
            Some("rsa_pss")
        }
        "eddsa" | "ed25519" => Some("eddsa"),
        "ecdsa" | "ecdsa_p256" | "p256" => Some("ecdsa"),
        "hmac" | "hmac_sha256" => Some("hmac_sha256"),
        "ml_dsa" | "mldsa" => Some("ml_dsa"),
        "slh_dsa" | "slh-dsa" | "slhdsa" => Some("slh_dsa"),
        "fn_dsa" | "fn_dsa512" => Some("fn_dsa"),
        _ => None,
    };

    if let Some(m) = basic {
        return Some(m.to_string());
    }

    let classical_opts = ["rsa_pss", "eddsa", "ecdsa", "hmac_sha256"];
    let pqc_opts = ["ml_dsa", "slh_dsa", "fn_dsa"];

    for c in classical_opts.iter() {
        for p in pqc_opts.iter() {
            let hybrid = format!("{}_{}", c, p);
            let hybrid_plus = format!("{}+{}", c, p);
            if lower == hybrid || lower == hybrid_plus {
                return Some(hybrid);
            }
        }
    }

    None
}

pub fn normalize_service_signature_profile(input: &str) -> String {
    normalize_benchmark_profile(input).unwrap_or_else(|| input.to_string())
}

pub fn benchmark_profile_to_service(input: &str) -> Option<String> {
    normalize_benchmark_profile(input)
}

pub fn normalize_benchmark_hash(input: &str) -> Option<&'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "sha256" | "sha-256" => Some("sha256"),
        "keccak" | "keccak256" | "keccak-256" => Some("keccak256"),
        "blake3" => Some("blake3"),
        "argon2" | "argon2id" => Some("argon2id"),
        "shake256" => Some("shake256"),
        "sha3-512" | "sha3_512" => Some("sha3-512"),
        _ => None,
    }
}

pub fn benchmark_hash_to_service(input: &str) -> Option<&'static str> {
    match normalize_benchmark_hash(input) {
        Some("sha256") => Some("SHA256"),
        Some("keccak256") => Some("KECCAK256"),
        Some("blake3") => Some("BLAKE3"),
        Some("argon2id") => Some("ARGON2ID"),
        Some("shake256") => Some("SHAKE256"),
        Some("sha3-512") => Some("SHA3-512"),
        Some(_) => None,
        None => None,
    }
}

pub fn signatures_satisfy_service_profile(profile: &str, sigs: &Signatures) -> bool {
    let p = normalize_service_signature_profile(profile);
    let rsa_req = p == "rsa_pss" || p.starts_with("rsa_pss_");
    let eddsa_req = p == "eddsa" || p.starts_with("eddsa_");
    let ecdsa_req = p == "ecdsa" || p.starts_with("ecdsa_");
    let hmac_req = p == "hmac_sha256" || p.starts_with("hmac_sha256_");
    let mldsa_req = p == "ml_dsa" || p.ends_with("_ml_dsa");
    let slhdsa_req = p == "slh_dsa" || p.ends_with("_slh_dsa");
    let fn_dsa_req = p == "fn_dsa" || p.ends_with("_fn_dsa");

    (rsa_req == sigs.rsa_pss.is_some()) &&
    (eddsa_req == sigs.eddsa.is_some()) &&
    (ecdsa_req == sigs.ecdsa_p256.is_some()) &&
    (hmac_req == sigs.hmac_sha256.is_some()) &&
    (mldsa_req == sigs.ml_dsa.is_some()) &&
    (slhdsa_req == sigs.slh_dsa.is_some()) &&
    (fn_dsa_req == sigs.fn_dsa.is_some())
}
