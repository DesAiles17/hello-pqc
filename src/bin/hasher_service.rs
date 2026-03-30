use anyhow::{anyhow, Context, Result};
use aws_config::Region;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::Builder as S3ConfigBuilder;
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client as S3Client;
use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use pqc_hons::{
    security::{
        internal_service_auth_middleware, validate_file_path, InternalServiceAuthConfig,
        PathSecurityPolicy,
    },
    ErrorResponse, HashRequest, HashResponse, HashTimingMetrics,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    s3: S3Client,
    bucket: String,
    path_policy: PathSecurityPolicy,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let internal_auth = InternalServiceAuthConfig::from_env()?;

    let (s3, bucket) = init_s3_client().await?;
    ensure_bucket(&s3, &bucket).await?;

    // Load path security policy from environment
    let path_policy = PathSecurityPolicy::from_env();
    info!("Path security policy loaded:");
    info!(
        "  Allowed directories: {:?}",
        path_policy.allowed_directories
    );
    info!("  Max file size: {} bytes", path_policy.max_file_size);
    info!("  Follow symlinks: {}", path_policy.follow_symlinks);

    let state = Arc::new(AppState {
        s3,
        bucket,
        path_policy,
    });

    let app = Router::new()
        .route("/", get(health_check))
        .route("/hash", post(compute_hash))
        .layer(middleware::from_fn(internal_service_auth_middleware))
        .layer(axum::Extension(internal_auth))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("Hasher Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "Hasher Service is healthy"
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn internal_server_error(
    message: &str,
    request_id: Option<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: message.to_string(),
            request_id,
        }),
    )
}

async fn compute_hash(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<HashRequest>,
) -> Result<Json<HashResponse>, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();
    info!(
        "Computing hash for file: {} (request_id: {})",
        payload.file_path, payload.request_id
    );

    // SECURITY: Validate and sanitize file path to prevent directory traversal
    let file_path = match validate_file_path(&payload.file_path, &state.path_policy) {
        Ok(path) => path,
        Err(e) => {
            error!("Path validation failed: {}", e);
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("Path validation failed: {}", e),
                    request_id: Some(payload.request_id),
                }),
            ));
        }
    };

    info!("Validated file path: {}", file_path.display());

    let file_handle = open_readonly_file_no_symlink(&file_path)
        .await
        .map_err(|e| {
            error!("Failed to securely open file for hashing: {}", e);
            internal_server_error(
                "Failed to securely open file for hashing",
                Some(payload.request_id.clone()),
            )
        })?;

    // Compute hash and store immutable object in content-addressed storage
    let bucket = payload
        .storage_bucket
        .clone()
        .unwrap_or_else(|| state.bucket.clone());
    if let Err(e) = ensure_bucket(&state.s3, &bucket).await {
        error!("Failed to ensure bucket {}: {}", bucket, e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to ensure bucket {}: {}", bucket, e),
                request_id: Some(payload.request_id),
            }),
        ));
    }

    let requested_alg = payload
        .hash_algorithm
        .clone()
        .unwrap_or_else(|| "SHA256".to_string());

    if let Err(e) = match_algorithm(&requested_alg) {
        error!("Unsupported hash algorithm: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Unsupported hash algorithm: {}", e),
                request_id: Some(payload.request_id),
            }),
        ));
    }

    match compute_and_store(file_handle, &file_path, &state.s3, &bucket, &requested_alg).await {
        Ok((
            hash,
            size,
            storage_bucket,
            storage_key,
            immutable_object_id,
            algorithm,
            mut metrics,
        )) => {
            info!(
                "Hash computed successfully for request_id: {}",
                payload.request_id
            );
            metrics.total_ms = elapsed_ms(total_start);
            Ok(Json(HashResponse {
                request_id: payload.request_id,
                hash,
                algorithm,
                file_size: size,
                storage_bucket,
                storage_key,
                immutable_object_id,
                metrics: Some(metrics),
            }))
        }
        Err(e) => {
            error!("Failed to compute hash: {}", e);
            Err(internal_server_error(
                "Failed to compute file hash",
                Some(payload.request_id),
            ))
        }
    }
}

async fn compute_and_store(
    mut file_handle: File,
    file_path: &Path,
    s3: &S3Client,
    bucket: &str,
    requested_alg: &str,
) -> Result<(
    String,
    u64,
    String,
    String,
    String,
    String,
    HashTimingMetrics,
)> {
    const MULTIPART_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
    const MULTIPART_CHUNK_BYTES: usize = 10 * 1024 * 1024;
    // Validate metadata AFTER opening (reduces TOCTOU exposure)
    let metadata = file_handle.metadata().await.with_context(|| {
        format!(
            "Failed to read file metadata after opening: {}",
            file_path.display()
        )
    })?;

    // Ensure it's still a regular file (not replaced with device/symlink)
    if !metadata.is_file() {
        return Err(anyhow!(
            "File type changed after opening (possible TOCTOU attack)"
        ));
    }

    let file_size = metadata.len();

    let (alg_label, object_prefix, immutable_prefix) = match_algorithm(requested_alg)?;

    let spool_root =
        std::env::var("HASH_SPOOL_DIR").unwrap_or_else(|_| "/tmp/pqc-hash-spool".to_string());
    tokio::fs::create_dir_all(&spool_root)
        .await
        .with_context(|| format!("Failed to create hash spool directory: {}", spool_root))?;
    let spool_path = Path::new(&spool_root).join(format!("{}.spool", Uuid::new_v4()));

    let mut spool_file = File::create(&spool_path)
        .await
        .with_context(|| format!("Failed to create hash spool file: {}", spool_path.display()))?;

    let mut hasher_sha256 = Sha256::new();
    let mut hasher_keccak = Keccak256::new();
    let mut buffer = vec![0u8; 8192];

    let hash_compute_start = Instant::now();
    loop {
        let n = file_handle.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        spool_file
            .write_all(&buffer[..n])
            .await
            .with_context(|| format!("Failed to write spool file: {}", spool_path.display()))?;

        match alg_label {
            "SHA256" => hasher_sha256.update(&buffer[..n]),
            "KECCAK" => hasher_keccak.update(&buffer[..n]),
            _ => {}
        }
    }

    spool_file.flush().await.with_context(|| {
        format!(
            "Failed to flush spool file before upload: {}",
            spool_path.display()
        )
    })?;

    drop(spool_file);

    let hash = match alg_label {
        "SHA256" => format!("{:x}", hasher_sha256.finalize()),
        "KECCAK" => format!("{:x}", hasher_keccak.finalize()),
        _ => unreachable!(),
    };
    let hash_compute_ms = elapsed_ms(hash_compute_start);

    let shard = &hash[0..2];
    let object_key = format!("objects/{}/{}/{}", object_prefix, shard, hash);

    let object_exists_start = Instant::now();
    let exists = match s3
        .head_object()
        .bucket(bucket)
        .key(&object_key)
        .send()
        .await
    {
        Ok(_) => true,
        Err(_) => false,
    };
    let object_exists_check_ms = elapsed_ms(object_exists_start);

    let multipart_used = file_size > MULTIPART_THRESHOLD_BYTES;
    let object_store_start = Instant::now();
    let upload_result = async {
        if !exists {
            info!(
                "Uploading object {} (size: {} bytes, multipart: {})",
                object_key, file_size, multipart_used
            );
            if multipart_used {
                upload_spool_multipart(s3, bucket, &object_key, &spool_path, MULTIPART_CHUNK_BYTES)
                    .await?;
            } else {
                let spool_bytes = tokio::fs::read(&spool_path).await.with_context(|| {
                    format!(
                        "Failed to read hash spool file before upload: {}",
                        spool_path.display()
                    )
                })?;

                let body = ByteStream::from(spool_bytes);

                s3.put_object()
                    .bucket(bucket)
                    .key(&object_key)
                    .content_length(file_size as i64)
                    .content_type("application/octet-stream")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| anyhow!("S3 put_object failed: {e:?}"))?;
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;
    let object_store_ms = elapsed_ms(object_store_start);

    if let Err(cleanup_error) = tokio::fs::remove_file(&spool_path).await {
        warn!(
            "Failed to remove hash spool file '{}': {}",
            spool_path.display(),
            cleanup_error
        );
    }

    upload_result?;

    let immutable_object_id = format!("{}:{}", immutable_prefix, hash);

    Ok((
        hash,
        file_size,
        bucket.to_string(),
        object_key,
        immutable_object_id,
        alg_label.to_string(),
        HashTimingMetrics {
            hash_compute_ms,
            object_exists_check_ms,
            object_store_ms,
            total_ms: 0.0,
            bytes_read: file_size,
            bytes_written: if exists { 0 } else { file_size },
            object_store_hit: exists,
            multipart_used,
        },
    ))
}

async fn upload_spool_multipart(
    s3: &S3Client,
    bucket: &str,
    object_key: &str,
    spool_path: &Path,
    chunk_bytes: usize,
) -> Result<()> {
    const MIN_PART_SIZE: usize = 5 * 1024 * 1024; // 5 MB minimum for S3/MinIO

    if chunk_bytes < MIN_PART_SIZE {
        return Err(anyhow!(
            "Multipart chunk size {} is below S3 minimum part size {}",
            chunk_bytes,
            MIN_PART_SIZE
        ));
    }

    info!(
        "Starting multipart upload for {} (chunk size: {} bytes)",
        object_key, chunk_bytes
    );
    let create = s3
        .create_multipart_upload()
        .bucket(bucket)
        .key(object_key)
        .content_type("application/octet-stream")
        .send()
        .await
        .map_err(|e| anyhow!("S3 create_multipart_upload failed: {e:?}"))?;

    let upload_id = create
        .upload_id()
        .ok_or_else(|| anyhow!("S3 create_multipart_upload missing upload_id"))?
        .to_string();

    let mut file = File::open(spool_path)
        .await
        .with_context(|| format!("Failed to open spool file: {}", spool_path.display()))?;
    let total_size = file
        .metadata()
        .await
        .with_context(|| {
            format!(
                "Failed to read spool file metadata: {}",
                spool_path.display()
            )
        })?
        .len() as usize;
    let mut parts: Vec<CompletedPart> = Vec::new();
    let mut part_number: i32 = 1;
    let mut bytes_remaining = total_size;

    let upload_result = async {
        while bytes_remaining > 0 {
            let is_last_part = bytes_remaining <= chunk_bytes;
            let current_part_size = if is_last_part {
                bytes_remaining
            } else {
                chunk_bytes
            };

            if !is_last_part && current_part_size < MIN_PART_SIZE {
                return Err(anyhow!(
                    "Non-final multipart part {} is too small: {} bytes",
                    part_number,
                    current_part_size
                ));
            }

            let mut part_bytes = vec![0u8; current_part_size];
            file.read_exact(&mut part_bytes).await.map_err(|e| {
                anyhow!(
                    "Failed to read {} bytes for multipart part {}: {}",
                    current_part_size,
                    part_number,
                    e
                )
            })?;

            let body = ByteStream::from(part_bytes);

            let resp = s3
                .upload_part()
                .bucket(bucket)
                .key(object_key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .content_length(current_part_size as i64)
                .body(body)
                .send()
                .await
                .map_err(|e| anyhow!("S3 upload_part failed (part {part_number}): {e:?}"))?;

            let e_tag = resp
                .e_tag()
                .ok_or_else(|| anyhow!("S3 upload_part missing ETag for part {part_number}"))?;

            parts.push(
                CompletedPart::builder()
                    .e_tag(e_tag)
                    .part_number(part_number)
                    .build(),
            );

            bytes_remaining -= current_part_size;
            part_number += 1;
        }

        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();

        s3.complete_multipart_upload()
            .bucket(bucket)
            .key(object_key)
            .upload_id(&upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|e| anyhow!("S3 complete_multipart_upload failed: {e:?}"))?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(err) = upload_result {
        let _ = s3
            .abort_multipart_upload()
            .bucket(bucket)
            .key(object_key)
            .upload_id(&upload_id)
            .send()
            .await;
        return Err(err);
    }

    Ok(())
}

async fn open_readonly_file_no_symlink(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        return options.open(path).await.with_context(|| {
            format!(
                "Failed to open file without following symlink: {}",
                path.display()
            )
        });
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .open(path)
            .await
            .with_context(|| format!("Failed to open file: {}", path.display()))
    }
}

fn match_algorithm(requested: &str) -> Result<(&'static str, &'static str, &'static str)> {
    let normalized = requested.to_ascii_uppercase();
    match normalized.as_str() {
        "SHA256" | "SHA-256" => Ok(("SHA256", "SHA-256", "sha256")),
        "KECCAK" | "KECCAK256" | "KECCAK-256" => Ok(("KECCAK", "KECCAK-256", "keccak256")),
        other => Err(anyhow!("Unsupported hash algorithm '{}'", other)),
    }
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

async fn init_s3_client() -> Result<(S3Client, String)> {
    let endpoint =
        std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://minio:9000".to_string());
    let access_key = std::env::var("MINIO_ACCESS_KEY")
        .context("MINIO_ACCESS_KEY must be set for hasher-service")?;
    let secret_key = std::env::var("MINIO_SECRET_KEY")
        .context("MINIO_SECRET_KEY must be set for hasher-service")?;
    let region = std::env::var("MINIO_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let bucket = std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "pqc-objects".to_string());

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
    let client = S3Client::from_conf(s3_config);

    Ok((client, bucket))
}

async fn ensure_bucket(client: &S3Client, bucket: &str) -> Result<()> {
    if client.head_bucket().bucket(bucket).send().await.is_ok() {
        return Ok(());
    }

    // Try to create the bucket, but if it already exists, that's fine
    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => Ok(()),
        Err(e) => {
            if let Some(service_err) = e.as_service_error() {
                if matches!(
                    service_err.code(),
                    Some("BucketAlreadyOwnedByYou") | Some("BucketAlreadyExists")
                ) {
                    info!(
                        "Bucket '{}' already exists and is usable (code: {:?})",
                        bucket,
                        service_err.code()
                    );
                    return Ok(());
                }
            }

            let err_str = e.to_string();
            // Fallback for providers that only expose these as strings
            if err_str.contains("BucketAlreadyOwnedByYou")
                || err_str.contains("BucketAlreadyExists")
            {
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}
