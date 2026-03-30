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
    pub rsa_sign_ms: Option<f64>,
    pub dilithium_sign_ms: Option<f64>,
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
    pub rsa_verify_ms: Option<f64>,
    pub dilithium_verify_ms: Option<f64>,
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

/// Hybrid signatures over the canonical manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signatures {
    /// RSA-PSS signature over canonical manifest (base64)
    pub rsa_pss: Option<String>,
    /// Dilithium signature over canonical manifest (base64)
    pub dilithium: Option<String>,
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

/// Error response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub request_id: Option<String>,
}
