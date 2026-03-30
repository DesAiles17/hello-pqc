use anyhow::{anyhow, Context, Result};
use aws_config::Region;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::Builder as S3ConfigBuilder;
use aws_sdk_s3::Client as S3Client;
use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chrono::{Duration, Utc};
use pqc_hons::{
    security::{internal_service_auth_middleware, InternalServiceAuthConfig},
    ErrorResponse, FetchManifestResponse, FetchManifestTimingMetrics, ManifestBuildResponse,
    ManifestBuildTimingMetrics, ManifestCore, ManifestEnvelope, ManifestRequest, Signatures,
    SignedManifest, SourceFileMetadata, VerificationCheck, VerificationMetadata, VerifyRequest,
    VerifyResponse, VerifyTimingMetrics,
};
use pqcrypto_dilithium::dilithium3::{
    self, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DilithiumSignatureTrait, PublicKey as DilithiumPublicKeyTrait,
    SecretKey as DilithiumSecretKeyTrait,
};
use rand::thread_rng;
use rsa::pss::Signature as RsaPssSignature;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey, pss::SigningKey, RsaPrivateKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sqlx::types::Json as SqlxJson;
use sqlx::PgPool;
use sqlx::Row;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    s3: S3Client,
}

#[derive(Debug, serde::Deserialize)]
struct FetchManifestRequest {
    request_id: String,
    owner_key_fingerprint: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "3002".to_string());
    let internal_auth = InternalServiceAuthConfig::from_env()?;

    let db = init_db_pool().await?;
    ensure_schema(&db).await?;
    let s3 = init_s3_client().await?;

    let state = Arc::new(AppState { db, s3 });

    let app = Router::new()
        .route("/", get(health_check))
        .route("/manifest", post(build_manifest))
        .route("/verify", post(verify_manifest))
        .route("/fetch", post(fetch_manifest)) // New endpoint to just fetch a manifest        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(internal_service_auth_middleware))
        .layer(axum::Extension(internal_auth))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("Manifest Builder Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "Manifest Builder Service is healthy"
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

#[derive(Default)]
struct SignatureTimingMetrics {
    rsa_verify_ms: Option<f64>,
    dilithium_verify_ms: Option<f64>,
    total_ms: f64,
}

async fn build_manifest(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ManifestRequest>,
) -> Result<Json<ManifestBuildResponse>, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();
    info!("Building manifest for request_id: {}", payload.request_id);

    let owner_key_fingerprint = payload
        .owner_key_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Missing owner key fingerprint in manifest request".to_string(),
                    request_id: Some(payload.request_id.clone()),
                }),
            )
        })?
        .to_string();

    // Build canonical manifest (the primary signed object)
    let schema_version = payload.schema_version.clone().unwrap_or_else(|| {
        std::env::var("MANIFEST_SCHEMA_VERSION")
            .unwrap_or_else(|_| "pqc-hons.manifest.v1".to_string())
    });
    let domain_sep = payload.domain_sep.clone().unwrap_or_else(|| {
        std::env::var("MANIFEST_DOMAIN_SEP").unwrap_or_else(|_| "pqc-hons.manifest.v1".to_string())
    });
    let signature_profile =
        normalize_signature_profile(payload.signature_profile.clone().unwrap_or_else(|| {
            std::env::var("SIGNATURE_PROFILE").unwrap_or_else(|_| "hybrid".to_string())
        }));

    let created_at = Utc::now();
    let source_file_metadata = read_source_file_metadata(&payload.file_path).await;
    let core = ManifestCore {
        schema_version,
        domain_sep,
        signature_profile,
        request_id: payload.request_id.clone(),
        immutable_object_id: payload.immutable_object_id.clone(),
        hash: payload.hash.clone(),
        algorithm: payload.algorithm.clone(),
        size: payload.file_size,
        storage_bucket: payload.storage_bucket.clone(),
        storage_key: payload.storage_key.clone(),
    };

    let envelope = ManifestEnvelope {
        created_at,
        context: format!("File: {}", payload.file_path),
        original_path: payload.file_path.clone(),
        source_file_metadata,
    };

    let canonical_start = Instant::now();
    let canonical = canonical_cbor(&core).map_err(|e| {
        error!("Failed to canonicalize manifest (CBOR): {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to canonicalize manifest (CBOR): {}", e),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    // Domain-separated signing bytes: domain_sep || 0x00 || canonical_cbor
    let mut signing_bytes = Vec::with_capacity(core.domain_sep.len() + 1 + canonical.len());
    signing_bytes.extend_from_slice(core.domain_sep.as_bytes());
    signing_bytes.push(0);
    signing_bytes.extend_from_slice(&canonical);
    let canonicalize_ms = elapsed_ms(canonical_start);

    // Sign the canonical manifest with RSA-PSS and Dilithium
    let rsa_key_path = env_path_required("RSA_PRIVATE_KEY").map_err(|e| {
        error!("Missing RSA private key configuration: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "RSA private key is not configured".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;
    let dilithium_key_path = env_path_required("DILITHIUM_SECRET_KEY").map_err(|e| {
        error!("Missing Dilithium secret key configuration: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Dilithium secret key is not configured".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    let mut rsa_pss: Option<String> = None;
    let mut dilithium: Option<String> = None;
    let mut rsa_sign_ms: Option<f64> = None;
    let mut dilithium_sign_ms: Option<f64> = None;
    match core.signature_profile.as_str() {
        "classical_only" => {
            let rsa_start = Instant::now();
            rsa_pss = Some(sign_rsa_pss(&signing_bytes, &rsa_key_path).map_err(|e| {
                error!("Failed to sign manifest with RSA-PSS: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to sign manifest with RSA-PSS: {}", e),
                        request_id: Some(payload.request_id.clone()),
                    }),
                )
            })?);
            rsa_sign_ms = Some(elapsed_ms(rsa_start));
        }
        "pqc_only" => {
            let dilithium_start = Instant::now();
            dilithium = Some(
                sign_dilithium(&signing_bytes, &dilithium_key_path).map_err(|e| {
                    error!("Failed to sign manifest with Dilithium: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to sign manifest with Dilithium: {}", e),
                            request_id: Some(payload.request_id.clone()),
                        }),
                    )
                })?,
            );
            dilithium_sign_ms = Some(elapsed_ms(dilithium_start));
        }
        "hybrid" => {
            let rsa_start = Instant::now();
            rsa_pss = Some(sign_rsa_pss(&signing_bytes, &rsa_key_path).map_err(|e| {
                error!("Failed to sign manifest with RSA-PSS: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to sign manifest with RSA-PSS: {}", e),
                        request_id: Some(payload.request_id.clone()),
                    }),
                )
            })?);
            rsa_sign_ms = Some(elapsed_ms(rsa_start));
            let dilithium_start = Instant::now();
            dilithium = Some(
                sign_dilithium(&signing_bytes, &dilithium_key_path).map_err(|e| {
                    error!("Failed to sign manifest with Dilithium: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to sign manifest with Dilithium: {}", e),
                            request_id: Some(payload.request_id.clone()),
                        }),
                    )
                })?,
            );
            dilithium_sign_ms = Some(elapsed_ms(dilithium_start));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid signature profile '{}'. Use 'classical_only', 'pqc_only', or 'hybrid'.",
                        other
                    ),
                    request_id: Some(payload.request_id.clone()),
                }),
            ));
        }
    }

    if !signatures_satisfy_profile(&core.signature_profile, &rsa_pss, &dilithium) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!(
                    "Signature profile '{}' not satisfied by produced signatures",
                    core.signature_profile
                ),
                request_id: Some(payload.request_id.clone()),
            }),
        ));
    }

    let signed_manifest = SignedManifest {
        core,
        envelope,
        signatures: Signatures { rsa_pss, dilithium },
    };

    let signed_manifest_json = serde_json::to_value(&signed_manifest).map_err(|e| {
        error!("Failed to serialize manifest: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize manifest: {}", e),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    let db_persist_start = Instant::now();
    if let Err(e) = sqlx::query(
        r#"
        insert into signed_manifests
           (hash, request_id, owner_key_fingerprint, immutable_object_id, algorithm, size_bytes, storage_bucket, storage_key, original_path, schema_version, domain_sep, signature_profile, manifest_json, created_at)
        values
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())
        "#,
    )
    .bind(&signed_manifest.core.hash)
    .bind(&signed_manifest.core.request_id)
    .bind(&owner_key_fingerprint)
    .bind(&signed_manifest.core.immutable_object_id)
    .bind(&signed_manifest.core.algorithm)
    .bind(signed_manifest.core.size as i64)
    .bind(&signed_manifest.core.storage_bucket)
    .bind(&signed_manifest.core.storage_key)
    .bind(&signed_manifest.envelope.original_path)
    .bind(&signed_manifest.core.schema_version)
    .bind(&signed_manifest.core.domain_sep)
    .bind(&signed_manifest.core.signature_profile)
    .bind(SqlxJson(signed_manifest_json))
    .execute(&state.db)
    .await
    {
        error!("Failed to persist manifest: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to persist manifest".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        ));
    }
    let db_persist_ms = elapsed_ms(db_persist_start);

    info!(
        "Manifest built and signed for request_id: {} (stored in DB)",
        payload.request_id
    );

    Ok(Json(ManifestBuildResponse {
        manifest: signed_manifest,
        metrics: Some(ManifestBuildTimingMetrics {
            canonicalize_ms,
            rsa_sign_ms,
            dilithium_sign_ms,
            db_persist_ms,
            total_ms: elapsed_ms(total_start),
        }),
    }))
}

async fn verify_manifest(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();

    let owner_key_fingerprint = payload
        .owner_key_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Missing owner key fingerprint in verify request".to_string(),
                    request_id: Some(payload.request_id.clone()),
                }),
            )
        })?
        .to_string();

    let request_id = payload.request_id.clone();
    let mut errors = Vec::new();
    let mut checks = Vec::new();

    let db_lookup_start = Instant::now();
    let row = sqlx::query(
        r#"
        select manifest_json, created_at, revoked_at
        from signed_manifests
        where request_id = $1 and owner_key_fingerprint = $2
        order by created_at desc
        limit 1
        "#,
    )
    .bind(&payload.request_id)
    .bind(&owner_key_fingerprint)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to query manifest: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to query manifest".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;
    let db_lookup_ms = elapsed_ms(db_lookup_start);

    let Some(row) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Manifest not found for request_id".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        ));
    };

    let manifest_json: serde_json::Value = row.try_get("manifest_json").map_err(|e| {
        error!("Failed to extract manifest_json: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to extract manifest".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    let signed_manifest: SignedManifest = serde_json::from_value(manifest_json).map_err(|e| {
        error!("Failed to parse manifest JSON: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to parse stored manifest".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    let persisted_created_at: chrono::DateTime<Utc> = row.try_get("created_at").map_err(|e| {
        error!("Failed to extract created_at: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to extract manifest timestamp".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    let revoked_at: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at").map_err(|e| {
        error!("Failed to extract revoked_at: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to extract manifest revocation state".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    let canonical_start = Instant::now();
    let canonical = canonical_cbor(&signed_manifest.core).map_err(|e| {
        error!("Failed to canonicalize manifest (CBOR): {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to canonicalize manifest".to_string(),
                request_id: Some(payload.request_id.clone()),
            }),
        )
    })?;

    let mut signing_bytes =
        Vec::with_capacity(signed_manifest.core.domain_sep.len() + 1 + canonical.len());
    signing_bytes.extend_from_slice(signed_manifest.core.domain_sep.as_bytes());
    signing_bytes.push(0);
    signing_bytes.extend_from_slice(&canonical);
    let canonicalize_ms = elapsed_ms(canonical_start);

    let canonical_manifest_hash = format!("{:x}", Sha256::digest(&canonical));

    let request_id_match = signed_manifest.core.request_id == request_id;
    if !request_id_match {
        errors.push(format!(
            "Request ID mismatch: payload={}, manifest={}",
            request_id, signed_manifest.core.request_id
        ));
    }
    add_check(
        &mut checks,
        "manifest.request_id_match",
        request_id_match,
        if request_id_match {
            "Manifest request_id matches verification request"
        } else {
            "Manifest request_id does not match verification request"
        },
    );

    let created_at_not_future =
        signed_manifest.envelope.created_at <= Utc::now() + Duration::minutes(5);
    if !created_at_not_future {
        errors.push(format!(
            "Manifest created_at is in the future: {}",
            signed_manifest.envelope.created_at
        ));
    }
    add_check(
        &mut checks,
        "manifest.timestamp_not_future",
        created_at_not_future,
        if created_at_not_future {
            "Manifest timestamp is plausible"
        } else {
            "Manifest timestamp is beyond allowed clock skew"
        },
    );

    let max_age = max_manifest_age();
    let manifest_age = Utc::now().signed_duration_since(persisted_created_at);
    let not_expired = manifest_age >= Duration::zero() && manifest_age <= max_age;
    if !not_expired {
        errors.push(format!(
            "Manifest age '{}' exceeds max allowed age '{}'",
            manifest_age, max_age
        ));
    }
    add_check(
        &mut checks,
        "manifest.not_expired",
        not_expired,
        if not_expired {
            "Manifest is within allowed age"
        } else {
            "Manifest exceeded allowed age"
        },
    );

    let not_revoked = revoked_at.is_none();
    if !not_revoked {
        errors.push("Manifest is revoked".to_string());
    }
    add_check(
        &mut checks,
        "manifest.not_revoked",
        not_revoked,
        if not_revoked {
            "Manifest is not revoked"
        } else {
            "Manifest has been revoked"
        },
    );

    let algorithm_supported = matches!(
        signed_manifest.core.algorithm.to_ascii_uppercase().as_str(),
        "SHA256" | "SHA-256" | "KECCAK" | "KECCAK256" | "KECCAK-256"
    );
    if !algorithm_supported {
        errors.push(format!(
            "Unsupported hash algorithm '{}'",
            signed_manifest.core.algorithm
        ));
    }
    add_check(
        &mut checks,
        "manifest.hash_algorithm_supported",
        algorithm_supported,
        if algorithm_supported {
            "Manifest hash algorithm is supported"
        } else {
            "Manifest hash algorithm is not supported"
        },
    );

    let (signature_ok, stored_signature_metrics) =
        verify_signatures(&signed_manifest, &signing_bytes, &mut checks, &mut errors);
    let max_verify_size = max_verify_object_size_bytes();
    let object_size_allowed = signed_manifest.core.size <= max_verify_size;
    if !object_size_allowed {
        errors.push(format!(
            "Manifest object size {} exceeds MAX_VERIFY_OBJECT_SIZE {}",
            signed_manifest.core.size, max_verify_size
        ));
    }
    add_check(
        &mut checks,
        "storage.object_size_within_verification_limit",
        object_size_allowed,
        if object_size_allowed {
            "Object size is within verification policy limit"
        } else {
            "Object size exceeds verification policy limit"
        },
    );

    let (object_ok, stored_object_verify_ms, stored_object_bytes_read) = if !payload.verify_object {
        add_check(
            &mut checks,
            "storage.object_verification_requested",
            true,
            "Stored-object verification skipped for this benchmark scenario",
        );
        (true, 0.0, 0)
    } else if object_size_allowed {
        verify_object_hash(&state.s3, &signed_manifest, &mut checks, &mut errors).await
    } else {
        (false, 0.0, 0)
    };

    // Compare uploaded file-derived values (if supplied by gateway) against the signed manifest
    let file_hash_match = if let Some(provided_hash) = payload.provided_hash.as_deref() {
        let matches = provided_hash.eq_ignore_ascii_case(&signed_manifest.core.hash);
        if !matches {
            errors.push(format!(
                "File hash mismatch: {} != {}",
                provided_hash, signed_manifest.core.hash
            ));
        }
        add_check(
            &mut checks,
            "file.provided_hash_match",
            matches,
            if matches {
                "Provided file hash matches manifest hash"
            } else {
                "Provided file hash does not match manifest hash"
            },
        );
        matches
    } else {
        add_check(
            &mut checks,
            "file.provided_hash_match",
            true,
            "No provided hash supplied; check not applicable",
        );
        true
    };

    let size_match = if let Some(provided_size) = payload.provided_size {
        let matches = provided_size == signed_manifest.core.size;
        if !matches {
            errors.push(format!(
                "File size mismatch: {} != {}",
                provided_size, signed_manifest.core.size
            ));
        }
        add_check(
            &mut checks,
            "file.provided_size_match",
            matches,
            if matches {
                "Provided file size matches manifest size"
            } else {
                "Provided file size does not match manifest size"
            },
        );
        matches
    } else {
        add_check(
            &mut checks,
            "file.provided_size_match",
            true,
            "No provided size supplied; check not applicable",
        );
        true
    };

    let algorithm_match = if let Some(provided_algorithm) = payload.provided_algorithm.as_deref() {
        let matches = normalize_hash_algorithm_label(provided_algorithm)
            == normalize_hash_algorithm_label(&signed_manifest.core.algorithm);
        if !matches {
            errors.push(format!(
                "File hash algorithm mismatch: {} != {}",
                provided_algorithm, signed_manifest.core.algorithm
            ));
        }
        add_check(
            &mut checks,
            "file.provided_algorithm_match",
            matches,
            if matches {
                "Provided hash algorithm matches manifest algorithm"
            } else {
                "Provided hash algorithm does not match manifest algorithm"
            },
        );
        matches
    } else {
        add_check(
            &mut checks,
            "file.provided_algorithm_match",
            true,
            "No provided algorithm supplied; check not applicable",
        );
        true
    };

    let immutable_object_id_match = if let Some(provided_immutable_object_id) =
        payload.provided_immutable_object_id.as_deref()
    {
        let matches = provided_immutable_object_id
            .eq_ignore_ascii_case(&signed_manifest.core.immutable_object_id);
        if !matches {
            errors.push(format!(
                "Immutable object id mismatch: {} != {}",
                provided_immutable_object_id, signed_manifest.core.immutable_object_id
            ));
        }
        add_check(
            &mut checks,
            "file.provided_immutable_object_id_match",
            matches,
            if matches {
                "Provided immutable object id matches manifest"
            } else {
                "Provided immutable object id does not match manifest"
            },
        );
        matches
    } else {
        add_check(
            &mut checks,
            "file.provided_immutable_object_id_match",
            true,
            "No provided immutable object id supplied; check not applicable",
        );
        true
    };

    let storage_bucket_match =
        if let Some(provided_storage_bucket) = payload.provided_storage_bucket.as_deref() {
            let matches = provided_storage_bucket == signed_manifest.core.storage_bucket;
            if !matches {
                errors.push(format!(
                    "Storage bucket mismatch: {} != {}",
                    provided_storage_bucket, signed_manifest.core.storage_bucket
                ));
            }
            add_check(
                &mut checks,
                "file.provided_storage_bucket_match",
                matches,
                if matches {
                    "Provided storage bucket matches manifest"
                } else {
                    "Provided storage bucket does not match manifest"
                },
            );
            matches
        } else {
            add_check(
                &mut checks,
                "file.provided_storage_bucket_match",
                true,
                "No provided storage bucket supplied; check not applicable",
            );
            true
        };

    let storage_key_match =
        if let Some(provided_storage_key) = payload.provided_storage_key.as_deref() {
            let matches = provided_storage_key == signed_manifest.core.storage_key;
            if !matches {
                errors.push(format!(
                    "Storage key mismatch: {} != {}",
                    provided_storage_key, signed_manifest.core.storage_key
                ));
            }
            add_check(
                &mut checks,
                "file.provided_storage_key_match",
                matches,
                if matches {
                    "Provided storage key matches manifest"
                } else {
                    "Provided storage key does not match manifest"
                },
            );
            matches
        } else {
            add_check(
                &mut checks,
                "file.provided_storage_key_match",
                true,
                "No provided storage key supplied; check not applicable",
            );
            true
        };

    let provided_manifest_match = file_hash_match
        && size_match
        && algorithm_match
        && immutable_object_id_match
        && storage_bucket_match
        && storage_key_match;

    add_check(
        &mut checks,
        "file.provided_manifest_attributes_match",
        provided_manifest_match,
        if provided_manifest_match {
            "All provided file-derived attributes match the signed manifest"
        } else {
            "One or more provided file-derived attributes differ from the signed manifest"
        },
    );

    let (file_signature_match, uploaded_signature_metrics) = if payload.provided_hash.is_some() {
        let mut provided_core = signed_manifest.core.clone();
        if let Some(provided_hash) = payload.provided_hash.as_ref() {
            provided_core.hash = provided_hash.clone();
        }
        if let Some(provided_size) = payload.provided_size {
            provided_core.size = provided_size;
        }
        if let Some(provided_algorithm) = payload.provided_algorithm.as_ref() {
            provided_core.algorithm = provided_algorithm.clone();
        }
        if let Some(provided_immutable_object_id) = payload.provided_immutable_object_id.as_ref() {
            provided_core.immutable_object_id = provided_immutable_object_id.clone();
        }
        if let Some(provided_storage_bucket) = payload.provided_storage_bucket.as_ref() {
            provided_core.storage_bucket = provided_storage_bucket.clone();
        }
        if let Some(provided_storage_key) = payload.provided_storage_key.as_ref() {
            provided_core.storage_key = provided_storage_key.clone();
        }

        let provided_canonical = canonical_cbor(&provided_core).map_err(|e| {
            error!(
                "Failed to canonicalize provided manifest core (CBOR): {}",
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!(
                        "Failed to canonicalize provided manifest core (CBOR): {}",
                        e
                    ),
                    request_id: Some(payload.request_id.clone()),
                }),
            )
        })?;

        let mut provided_signing_bytes =
            Vec::with_capacity(provided_core.domain_sep.len() + 1 + provided_canonical.len());
        provided_signing_bytes.extend_from_slice(provided_core.domain_sep.as_bytes());
        provided_signing_bytes.push(0);
        provided_signing_bytes.extend_from_slice(&provided_canonical);

        verify_signatures_against_uploaded_content(
            &signed_manifest,
            &provided_signing_bytes,
            &mut checks,
            &mut errors,
        )
    } else {
        add_check(
            &mut checks,
            "file.signature_match_uploaded_content",
            true,
            "No uploaded file-derived hash supplied; check not applicable",
        );
        (true, SignatureTimingMetrics::default())
    };

    let overall_ok = signature_ok
        && object_ok
        && file_hash_match
        && provided_manifest_match
        && file_signature_match
        && request_id_match
        && created_at_not_future
        && not_expired
        && not_revoked
        && algorithm_supported
        && errors.is_empty();

    Ok(Json(VerifyResponse {
        request_id,
        signature_ok,
        object_ok,
        file_hash_match,
        overall_ok,
        errors,
        checks,
        metadata: Some(VerificationMetadata {
            signature_profile: signed_manifest.core.signature_profile.clone(),
            hash_algorithm: signed_manifest.core.algorithm.clone(),
            canonical_manifest_hash,
            manifest_created_at: signed_manifest.envelope.created_at.to_rfc3339(),
            manifest_size: signed_manifest.core.size,
            storage_bucket: signed_manifest.core.storage_bucket.clone(),
            storage_key: signed_manifest.core.storage_key.clone(),
        }),
        metrics: Some(VerifyTimingMetrics {
            db_lookup_ms,
            canonicalize_ms,
            signature_verify_ms: stored_signature_metrics.total_ms,
            rsa_verify_ms: stored_signature_metrics.rsa_verify_ms,
            dilithium_verify_ms: stored_signature_metrics.dilithium_verify_ms,
            stored_object_verify_ms,
            stored_object_bytes_read,
            uploaded_content_verify_ms: uploaded_signature_metrics.total_ms,
            total_ms: elapsed_ms(total_start),
        }),
    }))
}

fn add_check(checks: &mut Vec<VerificationCheck>, name: &str, passed: bool, details: &str) {
    checks.push(VerificationCheck {
        name: name.to_string(),
        passed,
        details: details.to_string(),
    });
}

async fn read_source_file_metadata(file_path: &str) -> Option<SourceFileMetadata> {
    let metadata = match fs::metadata(file_path).await {
        Ok(metadata) => metadata,
        Err(e) => {
            info!(
                "Source file metadata unavailable for '{}': {}",
                file_path, e
            );
            return None;
        }
    };

    Some(SourceFileMetadata {
        created_at: system_time_to_rfc3339(metadata.created().ok()),
        last_modified_at: system_time_to_rfc3339(metadata.modified().ok()),
        last_accessed_at: system_time_to_rfc3339(metadata.accessed().ok()),
    })
}

fn system_time_to_rfc3339(value: Option<SystemTime>) -> Option<String> {
    value.map(|system_time| chrono::DateTime::<Utc>::from(system_time).to_rfc3339())
}

fn normalize_hash_algorithm_label(input: &str) -> String {
    match input.trim().to_ascii_uppercase().as_str() {
        "SHA256" | "SHA-256" => "SHA256".to_string(),
        "KECCAK" | "KECCAK256" | "KECCAK-256" => "KECCAK".to_string(),
        other => other.to_string(),
    }
}

/// New endpoint to just fetch a manifest without verification
/// This is useful for the API gateway to determine the hash algorithm
async fn fetch_manifest(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<FetchManifestRequest>,
) -> Result<Json<FetchManifestResponse>, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();
    let request_id = payload.request_id;
    let owner_key_fingerprint = payload
        .owner_key_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Missing owner key fingerprint in fetch request".to_string(),
                    request_id: Some(request_id.clone()),
                }),
            )
        })?
        .to_string();

    let db_lookup_start = Instant::now();
    let row = sqlx::query(
        r#"
        select manifest_json
        from signed_manifests
        where request_id = $1 and owner_key_fingerprint = $2
        order by created_at desc
        limit 1
        "#,
    )
    .bind(&request_id)
    .bind(&owner_key_fingerprint)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to query manifest: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to query manifest".to_string(),
                request_id: Some(request_id.clone()),
            }),
        )
    })?;
    let db_lookup_ms = elapsed_ms(db_lookup_start);

    let Some(row) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Manifest not found for request_id".to_string(),
                request_id: Some(request_id.clone()),
            }),
        ));
    };

    let manifest_json: serde_json::Value = row.try_get("manifest_json").map_err(|e| {
        error!("Failed to extract manifest_json: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to extract manifest".to_string(),
                request_id: Some(request_id.clone()),
            }),
        )
    })?;

    let signed_manifest: SignedManifest = serde_json::from_value(manifest_json).map_err(|e| {
        error!("Failed to parse manifest JSON: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to parse stored manifest".to_string(),
                request_id: Some(request_id.clone()),
            }),
        )
    })?;

    Ok(Json(FetchManifestResponse {
        manifest: signed_manifest,
        metrics: Some(FetchManifestTimingMetrics {
            db_lookup_ms,
            total_ms: elapsed_ms(total_start),
        }),
    }))
}

fn env_path_required(key: &str) -> Result<PathBuf> {
    let value = std::env::var(key)
        .with_context(|| format!("{} must be set", key))?
        .trim()
        .to_string();

    if value.is_empty() {
        return Err(anyhow!("{} cannot be empty", key));
    }

    Ok(PathBuf::from(value))
}

fn max_manifest_age() -> Duration {
    let hours = std::env::var("MAX_MANIFEST_AGE_HOURS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(24);

    let bounded = hours.clamp(1, 24 * 365);
    Duration::hours(bounded)
}

fn max_verify_object_size_bytes() -> u64 {
    std::env::var("MAX_VERIFY_OBJECT_SIZE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|value| value.clamp(1, 100 * 1024 * 1024))
        .unwrap_or(100 * 1024 * 1024)
}

fn enforce_secret_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read key file metadata: {}", path.display()))?;
        let mode = metadata.permissions().mode() & 0o777;

        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "Insecure permissions on secret key file '{}': mode {:o} (must not be group/world readable)",
                path.display(),
                mode
            ));
        }
    }

    Ok(())
}

fn sign_rsa_pss(message: &[u8], key_path: &Path) -> Result<String> {
    enforce_secret_file_permissions(key_path)?;
    let pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read RSA key from {}", key_path.display()))?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)?;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let mut rng = thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, message);
    Ok(STANDARD_NO_PAD.encode(signature.to_bytes()))
}

fn sign_dilithium(message: &[u8], key_path: &Path) -> Result<String> {
    enforce_secret_file_permissions(key_path)?;
    let sk_bytes = std::fs::read(key_path).with_context(|| {
        format!(
            "Failed to read Dilithium secret key from {}",
            key_path.display()
        )
    })?;
    let sk = DilithiumSecretKey::from_bytes(&sk_bytes)
        .map_err(|_| anyhow!("Invalid Dilithium secret key bytes"))?;
    let signature = dilithium3::detached_sign(message, &sk);
    Ok(STANDARD_NO_PAD.encode(signature.as_bytes()))
}

fn signatures_satisfy_profile(
    profile: &str,
    rsa_pss: &Option<String>,
    dilithium: &Option<String>,
) -> bool {
    match profile {
        "classical_only" => rsa_pss.is_some() && dilithium.is_none(),
        "pqc_only" => rsa_pss.is_none() && dilithium.is_some(),
        "hybrid" => rsa_pss.is_some() && dilithium.is_some(),
        _ => false,
    }
}

fn normalize_signature_profile(input: String) -> String {
    let trimmed = input.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "classic" | "classical" | "rsa" | "classical_only" => "classical_only".to_string(),
        "pqc" | "dilithium" | "pqc_only" => "pqc_only".to_string(),
        "hybrid" => "hybrid".to_string(),
        _ => input,
    }
}

fn canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

fn verify_signatures(
    signed: &SignedManifest,
    signing_bytes: &[u8],
    checks: &mut Vec<VerificationCheck>,
    errors: &mut Vec<String>,
) -> (bool, SignatureTimingMetrics) {
    let total_start = Instant::now();
    let profile = signed.core.signature_profile.as_str();
    let rsa_required = matches!(profile, "classical_only" | "hybrid");
    let dilithium_required = matches!(profile, "pqc_only" | "hybrid");
    let mut metrics = SignatureTimingMetrics::default();

    let profile_conformant = signatures_satisfy_profile(
        profile,
        &signed.signatures.rsa_pss,
        &signed.signatures.dilithium,
    );
    if !profile_conformant {
        errors.push(format!(
            "Signature set does not satisfy profile '{}'",
            profile
        ));
    }
    add_check(
        checks,
        "signature.profile_conformance",
        profile_conformant,
        if profile_conformant {
            "Required signatures are present for manifest profile"
        } else {
            "Manifest profile and included signatures are inconsistent"
        },
    );

    let rsa_ok = if let Some(sig) = &signed.signatures.rsa_pss {
        let rsa_start = Instant::now();
        let outcome = verify_rsa_pss(signing_bytes, sig);
        metrics.rsa_verify_ms = Some(elapsed_ms(rsa_start));
        match outcome {
            Ok(true) => {
                add_check(
                    checks,
                    "signature.rsa_pss_valid",
                    true,
                    "RSA-PSS signature verified",
                );
                true
            }
            Ok(false) => {
                errors.push("RSA-PSS signature verification failed".to_string());
                add_check(
                    checks,
                    "signature.rsa_pss_valid",
                    false,
                    "RSA-PSS signature failed verification",
                );
                false
            }
            Err(e) => {
                errors.push(format!("RSA-PSS verification error: {}", e));
                add_check(
                    checks,
                    "signature.rsa_pss_valid",
                    false,
                    "RSA-PSS signature verification errored",
                );
                false
            }
        }
    } else {
        add_check(
            checks,
            "signature.rsa_pss_present",
            !rsa_required,
            if rsa_required {
                "RSA-PSS signature is required but missing"
            } else {
                "RSA-PSS signature is not required for this profile"
            },
        );
        false
    };

    let dilithium_ok = if let Some(sig) = &signed.signatures.dilithium {
        let dilithium_start = Instant::now();
        let outcome = verify_dilithium(signing_bytes, sig);
        metrics.dilithium_verify_ms = Some(elapsed_ms(dilithium_start));
        match outcome {
            Ok(true) => {
                add_check(
                    checks,
                    "signature.dilithium_valid",
                    true,
                    "Dilithium signature verified",
                );
                true
            }
            Ok(false) => {
                errors.push("Dilithium signature verification failed".to_string());
                add_check(
                    checks,
                    "signature.dilithium_valid",
                    false,
                    "Dilithium signature failed verification",
                );
                false
            }
            Err(e) => {
                errors.push(format!("Dilithium verification error: {}", e));
                add_check(
                    checks,
                    "signature.dilithium_valid",
                    false,
                    "Dilithium signature verification errored",
                );
                false
            }
        }
    } else {
        add_check(
            checks,
            "signature.dilithium_present",
            !dilithium_required,
            if dilithium_required {
                "Dilithium signature is required but missing"
            } else {
                "Dilithium signature is not required for this profile"
            },
        );
        false
    };

    let signature_ok = match profile {
        "classical_only" => rsa_ok && signed.signatures.dilithium.is_none(),
        "pqc_only" => dilithium_ok && signed.signatures.rsa_pss.is_none(),
        "hybrid" => rsa_ok && dilithium_ok,
        _ => {
            errors.push(format!("Unknown signature profile '{}'", profile));
            false
        }
    };

    add_check(
        checks,
        "signature.overall",
        signature_ok,
        if signature_ok {
            "Signature checks satisfied profile policy"
        } else {
            "Signature checks failed profile policy"
        },
    );

    metrics.total_ms = elapsed_ms(total_start);
    (signature_ok, metrics)
}

fn verify_signatures_against_uploaded_content(
    signed: &SignedManifest,
    signing_bytes: &[u8],
    checks: &mut Vec<VerificationCheck>,
    errors: &mut Vec<String>,
) -> (bool, SignatureTimingMetrics) {
    let total_start = Instant::now();
    let profile = signed.core.signature_profile.as_str();
    let rsa_required = matches!(profile, "classical_only" | "hybrid");
    let dilithium_required = matches!(profile, "pqc_only" | "hybrid");
    let mut metrics = SignatureTimingMetrics::default();

    let rsa_ok = if let Some(sig) = &signed.signatures.rsa_pss {
        let rsa_start = Instant::now();
        let outcome = verify_rsa_pss(signing_bytes, sig);
        metrics.rsa_verify_ms = Some(elapsed_ms(rsa_start));
        match outcome {
            Ok(true) => {
                add_check(
                    checks,
                    "file.signature_rsa_pss_matches_uploaded_content",
                    true,
                    "RSA-PSS signature matches uploaded-file-derived manifest content",
                );
                true
            }
            Ok(false) => {
                errors.push(
                    "RSA-PSS signature does not match uploaded-file-derived manifest content"
                        .to_string(),
                );
                add_check(
                    checks,
                    "file.signature_rsa_pss_matches_uploaded_content",
                    false,
                    "RSA-PSS signature does not match uploaded-file-derived manifest content",
                );
                false
            }
            Err(e) => {
                errors.push(format!(
                    "RSA-PSS verification error for uploaded-file-derived manifest content: {}",
                    e
                ));
                add_check(
                    checks,
                    "file.signature_rsa_pss_matches_uploaded_content",
                    false,
                    "RSA-PSS verification errored for uploaded-file-derived manifest content",
                );
                false
            }
        }
    } else {
        add_check(
            checks,
            "file.signature_rsa_pss_present",
            !rsa_required,
            if rsa_required {
                "RSA-PSS signature is required but missing"
            } else {
                "RSA-PSS signature is not required for this profile"
            },
        );
        false
    };

    let dilithium_ok = if let Some(sig) = &signed.signatures.dilithium {
        let dilithium_start = Instant::now();
        let outcome = verify_dilithium(signing_bytes, sig);
        metrics.dilithium_verify_ms = Some(elapsed_ms(dilithium_start));
        match outcome {
            Ok(true) => {
                add_check(
                    checks,
                    "file.signature_dilithium_matches_uploaded_content",
                    true,
                    "Dilithium signature matches uploaded-file-derived manifest content",
                );
                true
            }
            Ok(false) => {
                errors.push(
                    "Dilithium signature does not match uploaded-file-derived manifest content"
                        .to_string(),
                );
                add_check(
                    checks,
                    "file.signature_dilithium_matches_uploaded_content",
                    false,
                    "Dilithium signature does not match uploaded-file-derived manifest content",
                );
                false
            }
            Err(e) => {
                errors.push(format!(
                    "Dilithium verification error for uploaded-file-derived manifest content: {}",
                    e
                ));
                add_check(
                    checks,
                    "file.signature_dilithium_matches_uploaded_content",
                    false,
                    "Dilithium verification errored for uploaded-file-derived manifest content",
                );
                false
            }
        }
    } else {
        add_check(
            checks,
            "file.signature_dilithium_present",
            !dilithium_required,
            if dilithium_required {
                "Dilithium signature is required but missing"
            } else {
                "Dilithium signature is not required for this profile"
            },
        );
        false
    };

    let signature_match_uploaded_content = match profile {
        "classical_only" => rsa_ok && signed.signatures.dilithium.is_none(),
        "pqc_only" => dilithium_ok && signed.signatures.rsa_pss.is_none(),
        "hybrid" => rsa_ok && dilithium_ok,
        _ => {
            errors.push(format!("Unknown signature profile '{}'", profile));
            false
        }
    };

    add_check(
        checks,
        "file.signature_match_uploaded_content",
        signature_match_uploaded_content,
        if signature_match_uploaded_content {
            "Signatures match uploaded-file-derived manifest content"
        } else {
            "Signatures do not match uploaded-file-derived manifest content"
        },
    );

    metrics.total_ms = elapsed_ms(total_start);
    (signature_match_uploaded_content, metrics)
}

fn allow_insecure_minio_http() -> bool {
    let requested = std::env::var("ALLOW_INSECURE_MINIO_HTTP")
        .ok()
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(false);

    if !requested {
        return false;
    }

    let environment = std::env::var("ENVIRONMENT")
        .unwrap_or_else(|_| "production".to_string())
        .to_ascii_lowercase();

    environment == "local" || environment == "development" || environment == "test"
}

fn verify_rsa_pss(message: &[u8], signature_b64: &str) -> Result<bool> {
    // SECURITY FIX: Use public key for verification, not private key!
    let key_path = env_path_required("RSA_PUBLIC_KEY")?;
    let pem = std::fs::read_to_string(key_path)?;

    // Parse public key from PEM
    let public_key = rsa::RsaPublicKey::from_public_key_pem(&pem)?;
    let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(public_key);

    let sig_bytes = STANDARD_NO_PAD.decode(signature_b64)?;
    let sig = RsaPssSignature::try_from(sig_bytes.as_slice())?;
    Ok(verifying_key.verify(message, &sig).is_ok())
}

fn verify_dilithium(message: &[u8], signature_b64: &str) -> Result<bool> {
    let pk_path = env_path_required("DILITHIUM_PUBLIC_KEY")?;
    let pk_bytes = std::fs::read(pk_path)?;
    let pk = DilithiumPublicKey::from_bytes(&pk_bytes)
        .map_err(|_| anyhow!("Invalid Dilithium public key bytes"))?;
    let sig_bytes = STANDARD_NO_PAD.decode(signature_b64)?;
    let sig = dilithium3::DetachedSignature::from_bytes(&sig_bytes)
        .map_err(|_| anyhow!("Invalid Dilithium signature bytes"))?;
    Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
}

async fn verify_object_hash(
    s3: &S3Client,
    signed: &SignedManifest,
    checks: &mut Vec<VerificationCheck>,
    errors: &mut Vec<String>,
) -> (bool, f64, u64) {
    let total_start = Instant::now();
    let bucket = &signed.core.storage_bucket;
    let key = &signed.core.storage_key;
    let resp = match s3.get_object().bucket(bucket).key(key).send().await {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!("Failed to fetch object from storage: {}", e));
            add_check(
                checks,
                "storage.object_fetch",
                false,
                "Object could not be fetched from storage",
            );
            return (false, elapsed_ms(total_start), 0);
        }
    };

    add_check(
        checks,
        "storage.object_fetch",
        true,
        "Object fetched from storage",
    );

    let object_size = resp.content_length().unwrap_or_default();
    let size_ok = object_size >= 0 && object_size as u64 == signed.core.size;
    if !size_ok {
        errors.push(format!(
            "Object size mismatch: expected {}, got {}",
            signed.core.size, object_size
        ));
    }
    add_check(
        checks,
        "storage.object_size_match",
        size_ok,
        if size_ok {
            "Object size matches manifest size"
        } else {
            "Object size differs from manifest size"
        },
    );

    let mut reader = resp.body.into_async_read();
    let mut buffer = vec![0u8; 8192];
    let mut sha256 = Sha256::new();
    let mut keccak = Keccak256::new();
    let alg = signed.core.algorithm.to_ascii_uppercase();

    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(n) => n,
            Err(e) => {
                errors.push(format!("Failed to read object stream: {}", e));
                add_check(
                    checks,
                    "storage.object_stream_read",
                    false,
                    "Object stream could not be read",
                );
                return (false, elapsed_ms(total_start), 0);
            }
        };
        if n == 0 {
            break;
        }
        match alg.as_str() {
            "SHA256" | "SHA-256" => sha256.update(&buffer[..n]),
            "KECCAK" | "KECCAK256" | "KECCAK-256" => keccak.update(&buffer[..n]),
            other => {
                errors.push(format!("Unsupported hash algorithm '{}'", other));
                add_check(
                    checks,
                    "storage.object_hash_algorithm_supported",
                    false,
                    "Unsupported hash algorithm in manifest",
                );
                return (false, elapsed_ms(total_start), 0);
            }
        }
    }

    add_check(
        checks,
        "storage.object_stream_read",
        true,
        "Object stream read successfully",
    );
    add_check(
        checks,
        "storage.object_hash_algorithm_supported",
        true,
        "Manifest hash algorithm supported for object verification",
    );

    let computed = match alg.as_str() {
        "SHA256" | "SHA-256" => format!("{:x}", sha256.finalize()),
        "KECCAK" | "KECCAK256" | "KECCAK-256" => format!("{:x}", keccak.finalize()),
        _ => return (false, elapsed_ms(total_start), 0),
    };
    if computed != signed.core.hash {
        errors.push(format!(
            "Object hash mismatch: expected {}, got {}",
            signed.core.hash, computed
        ));
        add_check(
            checks,
            "storage.object_hash_match",
            false,
            "Stored object hash does not match manifest hash",
        );
        return (false, elapsed_ms(total_start), object_size.max(0) as u64);
    }
    add_check(
        checks,
        "storage.object_hash_match",
        true,
        "Stored object hash matches manifest hash",
    );
    (true, elapsed_ms(total_start), object_size.max(0) as u64)
}

async fn init_s3_client() -> Result<S3Client> {
    let endpoint =
        std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://minio:9000".to_string());
    let access_key = std::env::var("MINIO_ACCESS_KEY")
        .context("MINIO_ACCESS_KEY must be set for manifest-builder-service")?;
    let secret_key = std::env::var("MINIO_SECRET_KEY")
        .context("MINIO_SECRET_KEY must be set for manifest-builder-service")?;
    let region = std::env::var("MINIO_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let allow_insecure_http = allow_insecure_minio_http();
    if !endpoint.starts_with("https://") && !allow_insecure_http {
        return Err(anyhow!(
            "MINIO_ENDPOINT must use HTTPS in secure mode (set ALLOW_INSECURE_MINIO_HTTP=true only for local development)"
        ));
    }

    let creds = Credentials::new(access_key, secret_key, None, None, "static");
    let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region))
        .credentials_provider(creds)
        .endpoint_url(endpoint)
        .load()
        .await;

    let s3_config = S3ConfigBuilder::from(&shared_config)
        .force_path_style(true)
        .build();
    Ok(S3Client::from_conf(s3_config))
}

async fn init_db_pool() -> Result<PgPool> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://pqc:pqc@postgres:5432/pqc".to_string());
    let pool = PgPool::connect(&database_url).await?;
    Ok(pool)
}

async fn ensure_schema(pool: &PgPool) -> Result<()> {
    // Execute each SQL statement separately (PostgreSQL prepared statements don't support multiple statements)
    sqlx::query(
        r#"
        create table if not exists signed_manifests (
            id uuid primary key default gen_random_uuid(),
            hash text not null,
            request_id text not null,
            owner_key_fingerprint text not null default '',
            immutable_object_id text not null,
            algorithm text not null,
            size_bytes bigint not null,
            storage_bucket text not null,
            storage_key text not null,
            original_path text not null,
            schema_version text not null,
            domain_sep text not null,
            signature_profile text not null,
            manifest_json jsonb not null,
            created_at timestamptz not null,
            updated_at timestamptz default now()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "alter table signed_manifests add column if not exists owner_key_fingerprint text not null default ''",
    )
    .execute(pool)
    .await?;

    // Benchmark and replay flows may legitimately produce multiple manifests
    // that reference the same immutable object/hash pair. Keep those fields indexed,
    // but not uniquely constrained.
    sqlx::query(
        "alter table signed_manifests drop constraint if exists signed_manifests_immutable_object_id_key",
    )
    .execute(pool)
    .await?;

    sqlx::query("alter table signed_manifests drop constraint if exists unique_hash_algorithm")
        .execute(pool)
        .await?;

    sqlx::query("alter table signed_manifests add column if not exists revoked_at timestamptz")
        .execute(pool)
        .await?;

    sqlx::query("create index if not exists idx_signed_manifests_hash on signed_manifests(hash)")
        .execute(pool)
        .await?;

    sqlx::query(
        "create index if not exists idx_signed_manifests_immutable_object_id on signed_manifests(immutable_object_id)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "create index if not exists idx_signed_manifests_hash_algorithm on signed_manifests(hash, algorithm)",
    )
    .execute(pool)
    .await?;

    sqlx::query("create index if not exists idx_signed_manifests_request_id on signed_manifests(request_id)")
        .execute(pool)
        .await?;

    sqlx::query(
        "create index if not exists idx_signed_manifests_request_owner on signed_manifests(request_id, owner_key_fingerprint)",
    )
    .execute(pool)
    .await?;

    sqlx::query("create index if not exists idx_signed_manifests_created_at on signed_manifests(created_at desc)")
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        create table if not exists manifest_audit_log (
            id uuid primary key default gen_random_uuid(),
            manifest_id uuid,
            action text not null,
            changed_by text,
            changed_at timestamptz default now(),
            old_data jsonb,
            new_data jsonb
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
