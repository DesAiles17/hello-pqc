use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Multipart, Query, State},
    http::{header, Method, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use pqc_hons::{
    security::{
        auth_middleware, check_role, AuthConfig, AuthIdentity, RateLimitConfig, UserRole,
        ValidationConfig,
    },
    ErrorResponse, FetchManifestResponse, HashRequest, HashResponse, ManifestBuildResponse,
    ManifestRequest, OperationMetricsResponse, ProcessOperationMetrics, SignedManifest,
    VerifyOperationMetrics, VerifyRequest, VerifyResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::types::Json as SqlxJson;
use sqlx::{PgPool, Row};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::{fs::File as TokioFile, io::AsyncWriteExt, sync::Semaphore};
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    hasher_url: String,
    manifest_url: String,
    upload_dir: String,
    internal_service_token: String,
    client: reqwest::Client,
    sign_limiter: Option<RequestLimiter>,
    verify_limiter: Option<RequestLimiter>,
    hash_limiter: Option<RequestLimiter>,
    global_limiter: Option<RequestLimiter>,
    verify_concurrency_guard: Arc<Semaphore>,
}

type RequestLimiter = Arc<
    governor::RateLimiter<
        String,
        governor::state::keyed::DashMapStateStore<String>,
        governor::clock::DefaultClock,
        governor::middleware::NoOpMiddleware,
    >,
>;

#[derive(Debug, Serialize, Deserialize)]
struct ProcessFileRequest {
    file_path: String,
    signature_profile: Option<String>,
    hash_algorithm: Option<String>,
    domain_sep: Option<String>,
    schema_version: Option<String>,
    bucket: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessFileResponse {
    manifest: SignedManifest,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfigDefaultsResponse {
    signature_profile: String,
    hash_algorithm: String,
    domain_sep: String,
    schema_version: String,
    bucket: String,
}

#[derive(Debug, Deserialize)]
struct OperationsQuery {
    request_id: String,
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
struct HealthCheckResponse {
    status: String,
    version: String,
    timestamp: String,
    uptime_seconds: u64,
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn normalize_signature_profile(input: &str) -> String {
    let trimmed = input.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "classic" | "classical" | "rsa" | "classical_only" => "classical_only".to_string(),
        "pqc" | "dilithium" | "pqc_only" => "pqc_only".to_string(),
        "hybrid" => "hybrid".to_string(),
        _ => input.to_string(),
    }
}

fn check_rate_limit(
    limiter: &Option<RequestLimiter>,
    identity_key: &str,
    operation: &str,
    request_id: Option<String>,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if let Some(limiter) = limiter {
        if limiter.check_key(&identity_key.to_string()).is_err() {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: format!("Rate limit exceeded for {} operations", operation),
                    request_id,
                }),
            ));
        }
    }
    Ok(())
}

fn upstream_service_error(
    service: &str,
    status: reqwest::StatusCode,
    request_id: Option<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    let client_message = format!("{} service request failed", service);
    let details = format!("{} service returned upstream status {}", service, status);
    error!("{}", details);

    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse {
            error: client_message,
            request_id,
        }),
    )
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

fn resolve_cors_origin() -> axum::http::HeaderValue {
    const DEFAULT_ORIGIN: &str = "http://localhost:5173";

    let configured = std::env::var("CORS_ORIGIN").unwrap_or_else(|_| DEFAULT_ORIGIN.to_string());
    let trimmed = configured.trim();

    if trimmed.is_empty() || trimmed == "*" {
        error!(
            "Invalid CORS_ORIGIN '{}'; falling back to {}",
            configured, DEFAULT_ORIGIN
        );
        return axum::http::HeaderValue::from_static(DEFAULT_ORIGIN);
    }

    match trimmed.parse::<axum::http::HeaderValue>() {
        Ok(value) => value,
        Err(err) => {
            error!(
                "Failed to parse CORS_ORIGIN '{}': {}; falling back to {}",
                configured, err, DEFAULT_ORIGIN
            );
            axum::http::HeaderValue::from_static(DEFAULT_ORIGIN)
        }
    }
}

fn ensure_user_owned_upload_path(
    user_file_path: &str,
    upload_root: &str,
    key_fingerprint: &str,
) -> Result<PathBuf> {
    if user_file_path.trim().is_empty() {
        return Err(anyhow!("File path cannot be empty"));
    }

    let canonical_upload_root = std::fs::canonicalize(upload_root)
        .with_context(|| format!("Failed to canonicalize upload root: {}", upload_root))?;
    let expected_prefix = canonical_upload_root.join(key_fingerprint);

    let canonical_user_path = std::fs::canonicalize(user_file_path)
        .with_context(|| format!("Invalid or missing file path: {}", user_file_path))?;

    if !canonical_user_path.starts_with(&expected_prefix) {
        return Err(anyhow!(
            "File path is not owned by the authenticated key identity"
        ));
    }

    Ok(canonical_user_path)
}

fn allow_insecure_internal_http() -> bool {
    let requested = std::env::var("ALLOW_INSECURE_INTERNAL_HTTP")
        .ok()
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(false);

    if !requested {
        return false;
    }

    let environment = std::env::var("ENVIRONMENT")
        .unwrap_or_else(|_| "production".to_string())
        .to_ascii_lowercase();

    let local_env = environment == "local" || environment == "development" || environment == "test";
    if !local_env {
        warn!(
            "ALLOW_INSECURE_INTERNAL_HTTP=true ignored because ENVIRONMENT='{}' is not local/development/test",
            environment
        );
        return false;
    }

    true
}

fn validate_internal_service_url(name: &str, url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url)
        .with_context(|| format!("Failed to parse {} URL '{}'", name, url))?;

    if parsed.scheme() != "https" && !allow_insecure_internal_http() {
        return Err(anyhow!(
            "{} URL must use HTTPS in secure mode (set ALLOW_INSECURE_INTERNAL_HTTP=true only for local development)",
            name
        ));
    }

    Ok(())
}

fn build_internal_reqwest_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30));

    if let Ok(path) = std::env::var("INTERNAL_CA_CERT_PATH") {
        let trimmed = path.trim();
        tracing::info!("INTERNAL_CA_CERT_PATH is set: {}", trimmed);
        if !trimmed.is_empty() {
            let cert_bytes = std::fs::read(trimmed).with_context(|| {
                format!("Failed to read INTERNAL_CA_CERT_PATH file: {}", trimmed)
            })?;
            tracing::info!(
                "Successfully read {} bytes from CA cert file",
                cert_bytes.len()
            );
            let cert = reqwest::Certificate::from_pem(&cert_bytes)
                .with_context(|| format!("Failed to parse PEM certificate in {}", trimmed))?;
            tracing::info!("Successfully parsed CA certificate");
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert);
            tracing::info!("Added CA root certificate to reqwest client (built-in roots disabled)");
        }
    } else {
        tracing::warn!("INTERNAL_CA_CERT_PATH environment variable not set");
    }

    builder
        .build()
        .context("Failed to build internal reqwest client")
}

fn max_concurrent_verify() -> usize {
    std::env::var("MAX_CONCURRENT_VERIFY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|value| value.clamp(1, 128))
        .unwrap_or(4)
}

fn max_json_body_size() -> usize {
    std::env::var("MAX_JSON_BODY_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|value| value.clamp(4 * 1024, 2 * 1024 * 1024))
        .unwrap_or(64 * 1024)
}

fn max_upload_storage_per_key() -> u64 {
    std::env::var("MAX_UPLOAD_STORAGE_PER_KEY")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|value| value.max(10 * 1024 * 1024))
        .unwrap_or(512 * 1024 * 1024)
}

fn upload_retention_duration() -> Duration {
    let hours = std::env::var("UPLOAD_RETENTION_HOURS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|value| value.clamp(1, 24 * 30))
        .unwrap_or(24);

    Duration::from_secs(hours * 60 * 60)
}

async fn prune_and_measure_upload_usage(caller_dir: &str, retention: Duration) -> Result<u64> {
    let mut total_bytes: u64 = 0;
    let mut dir = match tokio::fs::read_dir(caller_dir).await {
        Ok(handle) => handle,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(anyhow!(
                "Failed to read caller upload directory '{}': {}",
                caller_dir,
                error
            ))
        }
    };

    let now = SystemTime::now();
    while let Some(entry) = dir
        .next_entry()
        .await
        .with_context(|| format!("Failed reading upload directory entry in {}", caller_dir))?
    {
        let path = entry.path();
        let metadata = match entry.metadata().await {
            Ok(value) => value,
            Err(_) => continue,
        };

        if !metadata.is_file() {
            continue;
        }

        let should_delete = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .map(|age| age > retention)
            .unwrap_or(false);

        if should_delete {
            if let Err(error) = tokio::fs::remove_file(&path).await {
                warn!(
                    "Failed to remove expired upload '{}': {}",
                    path.display(),
                    error
                );
            }
            continue;
        }

        total_bytes = total_bytes.saturating_add(metadata.len());
    }

    Ok(total_bytes)
}

async fn init_db_pool() -> Result<PgPool> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://pqc:pqc@postgres:5432/pqc".to_string());
    let pool = PgPool::connect(&database_url).await?;
    Ok(pool)
}

async fn ensure_operations_schema(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        create table if not exists benchmark_operations (
            request_id text primary key,
            owner_key_fingerprint text not null,
            metrics_json jsonb not null,
            created_at timestamptz not null default now(),
            updated_at timestamptz not null default now()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "create index if not exists idx_benchmark_operations_request_owner on benchmark_operations(request_id, owner_key_fingerprint)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn load_operation_metrics(
    pool: &PgPool,
    request_id: &str,
    owner_key_fingerprint: &str,
) -> Result<Option<OperationMetricsResponse>> {
    let row = sqlx::query(
        r#"
        select metrics_json
        from benchmark_operations
        where request_id = $1 and owner_key_fingerprint = $2
        "#,
    )
    .bind(request_id)
    .bind(owner_key_fingerprint)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let metrics_json: serde_json::Value = row.try_get("metrics_json")?;
    let record = serde_json::from_value(metrics_json)?;
    Ok(Some(record))
}

async fn persist_operation_metrics(
    pool: &PgPool,
    owner_key_fingerprint: &str,
    record: &OperationMetricsResponse,
) -> Result<()> {
    let mut persisted = record.clone();
    persisted.recorded_at = Some(Utc::now().to_rfc3339());

    sqlx::query(
        r#"
        insert into benchmark_operations (request_id, owner_key_fingerprint, metrics_json, created_at, updated_at)
        values ($1, $2, $3, now(), now())
        on conflict (request_id) do update
        set owner_key_fingerprint = excluded.owner_key_fingerprint,
            metrics_json = excluded.metrics_json,
            updated_at = now()
        "#,
    )
    .bind(&persisted.request_id)
    .bind(owner_key_fingerprint)
    .bind(SqlxJson(serde_json::to_value(&persisted)?))
    .execute(pool)
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let hasher_url =
        std::env::var("HASHER_SERVICE_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());
    let manifest_url = std::env::var("MANIFEST_SERVICE_URL")
        .unwrap_or_else(|_| "http://localhost:3002".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let upload_dir = std::env::var("UPLOAD_DIR").unwrap_or_else(|_| "/data/uploads".to_string());
    let internal_service_token = std::env::var("INTERNAL_SERVICE_TOKEN")
        .map_err(|_| anyhow!("INTERNAL_SERVICE_TOKEN must be set in api-gateway"))?;

    if internal_service_token.trim().is_empty() {
        return Err(anyhow!(
            "INTERNAL_SERVICE_TOKEN cannot be empty in api-gateway"
        ));
    }

    validate_internal_service_url("HASHER_SERVICE_URL", &hasher_url)?;
    validate_internal_service_url("MANIFEST_SERVICE_URL", &manifest_url)?;

    std::fs::create_dir_all(&upload_dir)
        .with_context(|| format!("Failed to create upload root directory: {}", upload_dir))?;

    let auth_config = match AuthConfig::from_env() {
        Ok(config) => {
            info!("Authentication enabled: {}", config.require_auth);
            info!("Loaded {} API keys", config.api_keys.len());
            Arc::new(config)
        }
        Err(e) => {
            error!("Failed to load auth config: {}", e);
            return Err(e);
        }
    };

    let db = init_db_pool().await?;
    ensure_operations_schema(&db).await?;

    let state = Arc::new(AppState {
        db,
        hasher_url,
        manifest_url,
        upload_dir,
        internal_service_token,
        client: build_internal_reqwest_client()?,
        sign_limiter: RateLimitConfig::from_env().create_limiter("sign"),
        verify_limiter: RateLimitConfig::from_env().create_limiter("verify"),
        hash_limiter: RateLimitConfig::from_env().create_limiter("hash"),
        global_limiter: RateLimitConfig::from_env().create_limiter("global"),
        verify_concurrency_guard: Arc::new(Semaphore::new(max_concurrent_verify())),
    });

    let cors_origin = resolve_cors_origin();

    let max_upload_size: usize = std::env::var("MAX_UPLOAD_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100 * 1024 * 1024);
    let max_json_body_size = max_json_body_size();

    if let Ok(origin_value) = cors_origin.to_str() {
        info!("CORS configured for origin: {}", origin_value);
    }

    let cors = CorsLayer::new()
        .allow_origin(cors_origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-api-key"),
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(3600));

    let app = Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check_detailed))
        .route("/config", get(config_defaults))
        .route("/operations", get(get_operation_metrics))
        .route(
            "/upload",
            post(upload_file).layer(axum::extract::DefaultBodyLimit::max(max_upload_size)),
        )
        .route(
            "/verify",
            post(verify_request).layer(RequestBodyLimitLayer::new(max_json_body_size)),
        )
        .route(
            "/process",
            post(process_file).layer(RequestBodyLimitLayer::new(max_json_body_size)),
        )
        .layer(middleware::from_fn(auth_middleware))
        .layer(axum::Extension((*auth_config).clone()))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("API Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "API Gateway is healthy"
}

async fn health_check_detailed(State(_state): State<Arc<AppState>>) -> Json<HealthCheckResponse> {
    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Json(HealthCheckResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now().to_rfc3339(),
        uptime_seconds: uptime,
    })
}

async fn get_operation_metrics(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_role): axum::Extension<UserRole>,
    axum::Extension(auth_identity): axum::Extension<AuthIdentity>,
    Query(query): Query<OperationsQuery>,
) -> Result<Json<OperationMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !check_role(&user_role, &UserRole::ReadOnly) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient permissions for operations lookup".to_string(),
                request_id: None,
            }),
        ));
    }

    let validator = ValidationConfig::default();
    if let Err(e) = validator.validate_request_id(&query.request_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid request_id: {}", e),
                request_id: Some(query.request_id.clone()),
            }),
        ));
    }

    let record =
        load_operation_metrics(&state.db, &query.request_id, &auth_identity.key_fingerprint)
            .await
            .map_err(|e| {
                error!("Failed to load operation metrics: {}", e);
                internal_server_error(
                    "Failed to load operation metrics",
                    Some(query.request_id.clone()),
                )
            })?;

    let Some(record) = record else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Operation metrics not found for request_id".to_string(),
                request_id: Some(query.request_id),
            }),
        ));
    };

    Ok(Json(record))
}

async fn upload_file(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_role): axum::Extension<UserRole>,
    axum::Extension(auth_identity): axum::Extension<AuthIdentity>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !check_role(&user_role, &UserRole::ReadOnly) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient permissions for upload".into(),
                request_id: None,
            }),
        ));
    }

    check_rate_limit(
        &state.global_limiter,
        &auth_identity.key_fingerprint,
        "global",
        None,
    )?;
    check_rate_limit(
        &state.hash_limiter,
        &auth_identity.key_fingerprint,
        "upload",
        None,
    )?;

    let max_upload_size: u64 = std::env::var("MAX_UPLOAD_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100 * 1024 * 1024);

    let upload_dir = state.upload_dir.clone();
    let max_upload_storage_per_key = max_upload_storage_per_key();
    let upload_retention = upload_retention_duration();

    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        error!("Invalid multipart request: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid multipart request".into(),
                request_id: None,
            }),
        )
    })? {
        let file_name = field
            .file_name()
            .ok_or_else(|| {
                error!("Missing filename in upload");
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Missing filename in upload".into(),
                        request_id: None,
                    }),
                )
            })?
            .to_string();

        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();

        let sanitized_name = file_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .collect::<String>()
            .trim_start_matches('.')
            .to_string();

        if sanitized_name.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid filename after sanitization".into(),
                    request_id: None,
                }),
            ));
        }

        let upload_id = Uuid::new_v4();
        let caller_dir = format!("{}/{}", upload_dir, auth_identity.key_fingerprint);
        let file_path = format!("{}/{}-{}", caller_dir, upload_id, sanitized_name);

        tokio::fs::create_dir_all(&caller_dir).await.map_err(|e| {
            error!("Failed to create upload directory: {}", e);
            internal_server_error("Failed to prepare upload directory", None)
        })?;

        let retained_usage = prune_and_measure_upload_usage(&caller_dir, upload_retention)
            .await
            .map_err(|e| {
                error!("Failed to evaluate upload usage for {}: {}", caller_dir, e);
                internal_server_error("Failed to evaluate upload storage usage", None)
            })?;

        if retained_usage >= max_upload_storage_per_key {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: format!(
                        "Upload storage quota exceeded for API key identity ({} MB used, {} MB limit)",
                        retained_usage / (1024 * 1024),
                        max_upload_storage_per_key / (1024 * 1024)
                    ),
                    request_id: None,
                }),
            ));
        }

        let mut file = TokioFile::create(&file_path).await.map_err(|e| {
            error!("Failed to save file: {}", e);
            internal_server_error("Failed to create upload file", None)
        })?;

        let mut total_size: u64 = 0;
        loop {
            let maybe_chunk = match field.chunk().await {
                Ok(chunk) => chunk,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&file_path).await;
                    let error_text = e.to_string();
                    let lowered = error_text.to_ascii_lowercase();
                    let status = if lowered.contains("too large")
                        || lowered.contains("body")
                        || lowered.contains("size")
                    {
                        StatusCode::PAYLOAD_TOO_LARGE
                    } else {
                        StatusCode::BAD_REQUEST
                    };
                    error!("Failed to read upload chunk: {}", error_text);
                    return Err((
                        status,
                        Json(ErrorResponse {
                            error: "Failed to read upload chunk".into(),
                            request_id: None,
                        }),
                    ));
                }
            };

            let Some(chunk) = maybe_chunk else {
                break;
            };

            total_size += chunk.len() as u64;

            if total_size > max_upload_size {
                let _ = tokio::fs::remove_file(&file_path).await;
                error!(
                    "File size {}MB exceeds maximum {}MB",
                    total_size / (1024 * 1024),
                    max_upload_size / (1024 * 1024)
                );
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(ErrorResponse {
                        error: format!(
                            "File size {}MB exceeds maximum {}MB",
                            total_size / (1024 * 1024),
                            max_upload_size / (1024 * 1024)
                        ),
                        request_id: None,
                    }),
                ));
            }

            if retained_usage.saturating_add(total_size) > max_upload_storage_per_key {
                let _ = tokio::fs::remove_file(&file_path).await;
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: format!(
                            "Upload storage quota exceeded for API key identity ({} MB limit)",
                            max_upload_storage_per_key / (1024 * 1024)
                        ),
                        request_id: None,
                    }),
                ));
            }

            if let Err(e) = file.write_all(&chunk).await {
                let _ = tokio::fs::remove_file(&file_path).await;
                error!("Failed to write file: {}", e);
                return Err(internal_server_error(
                    "Failed to persist uploaded file",
                    None,
                ));
            }
        }

        info!("File uploaded: {} ({} bytes)", file_path, total_size);

        return Ok(Json(UploadResponse {
            file_path,
            original_filename: file_name,
            size: total_size,
            content_type,
            uploaded_at: Utc::now().to_rfc3339(),
        }));
    }

    Err((
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: "No file provided in multipart request".into(),
            request_id: None,
        }),
    ))
}

async fn config_defaults(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ConfigDefaultsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let signature_profile =
        std::env::var("SIGNATURE_PROFILE").unwrap_or_else(|_| "hybrid".to_string());
    let domain_sep =
        std::env::var("MANIFEST_DOMAIN_SEP").unwrap_or_else(|_| "pqc-hons.manifest.v1".to_string());
    let schema_version = std::env::var("MANIFEST_SCHEMA_VERSION")
        .unwrap_or_else(|_| "pqc-hons.manifest.v1".to_string());
    let hash_algorithm = std::env::var("HASH_ALGORITHM").unwrap_or_else(|_| "SHA256".to_string());
    let bucket = std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "pqc-objects".to_string());

    Ok(Json(ConfigDefaultsResponse {
        signature_profile,
        hash_algorithm,
        domain_sep,
        schema_version,
        bucket,
    }))
}

async fn verify_request(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_role): axum::Extension<UserRole>,
    axum::Extension(auth_identity): axum::Extension<AuthIdentity>,
    Json(mut payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();
    if !check_role(&user_role, &UserRole::ReadOnly) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient permissions for verify".to_string(),
                request_id: None,
            }),
        ));
    }

    check_rate_limit(
        &state.global_limiter,
        &auth_identity.key_fingerprint,
        "global",
        Some(payload.request_id.clone()),
    )?;
    check_rate_limit(
        &state.verify_limiter,
        &auth_identity.key_fingerprint,
        "verify",
        Some(payload.request_id.clone()),
    )?;

    let _verify_permit = state
        .verify_concurrency_guard
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| {
            internal_server_error(
                "Verification capacity is currently unavailable",
                Some(payload.request_id.clone()),
            )
        })?;

    let validator = ValidationConfig::default();
    if let Err(e) = validator.validate_request_id(&payload.request_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid request_id: {}", e),
                request_id: Some(payload.request_id.clone()),
            }),
        ));
    }

    payload.file_path = payload.file_path.and_then(|p| {
        let trimmed = p.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    payload.owner_key_fingerprint = Some(auth_identity.key_fingerprint.clone());
    let request_id = payload.request_id.clone();
    let mut manifest_fetch_roundtrip_ms = None;
    let mut manifest_fetch_metrics = None;
    let mut verify_hash_roundtrip_ms = None;
    let mut verify_hash_metrics = None;
    let mut fetched_manifest_profile = None;
    let mut fetched_manifest_algorithm = None;
    let mut fetched_manifest_size = None;

    // If a file_path is provided, hash it and add the hash to the payload
    if let Some(ref file_path) = payload.file_path {
        let owned_path = ensure_user_owned_upload_path(
            file_path,
            &state.upload_dir,
            &auth_identity.key_fingerprint,
        )
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("Invalid verification file path: {}", e),
                    request_id: Some(payload.request_id.clone()),
                }),
            )
        })?;

        let owned_file_path = owned_path.to_string_lossy().to_string();
        info!("Hashing file for verification: {}", file_path);

        // BUGFIX: First, fetch the manifest to determine which hash algorithm was used
        // This ensures we hash the verification file with the SAME algorithm
        info!("Fetching manifest to determine hash algorithm used during signing");

        let manifest_fetch_start = Instant::now();
        let manifest_resp = state
            .client
            .post(format!("{}/fetch", state.manifest_url))
            .header("X-Service-Token", &state.internal_service_token)
            .json(&serde_json::json!({
                "request_id": payload.request_id,
                "owner_key_fingerprint": auth_identity.key_fingerprint,
            }))
            .send()
            .await
            .map_err(|e| {
                error!("Failed to fetch manifest: {}", e);
                internal_server_error(
                    "Failed to retrieve manifest for verification",
                    Some(payload.request_id.clone()),
                )
            })?;

        manifest_fetch_roundtrip_ms = Some(elapsed_ms(manifest_fetch_start));
        let manifest_status = manifest_resp.status();
        if !manifest_status.is_success() {
            let _ = manifest_resp.text().await;
            return Err(upstream_service_error(
                "Manifest",
                manifest_status,
                Some(payload.request_id.clone()),
            ));
        }

        // Parse the manifest to extract the hash algorithm
        let fetch_response: FetchManifestResponse = manifest_resp.json().await.map_err(|e| {
            error!("Failed to parse manifest response: {}", e);
            internal_server_error(
                "Failed to parse manifest response",
                Some(payload.request_id.clone()),
            )
        })?;
        let signed_manifest = fetch_response.manifest;
        manifest_fetch_metrics = fetch_response.metrics;

        let hash_algorithm = signed_manifest.core.algorithm.clone();
        fetched_manifest_profile = Some(signed_manifest.core.signature_profile.clone());
        fetched_manifest_algorithm = Some(hash_algorithm.clone());
        fetched_manifest_size = Some(signed_manifest.core.size);
        info!("Original manifest used hash algorithm: {}", hash_algorithm);

        // Create a temporary request_id for this hash operation (not stored)
        let hash_request = HashRequest {
            file_path: owned_file_path,
            request_id: uuid::Uuid::new_v4().to_string(),
            storage_bucket: None,
            hash_algorithm: Some(hash_algorithm), // Use the SAME algorithm as the original signing
        };

        let verify_hash_start = Instant::now();
        let hash_resp = state
            .client
            .post(format!("{}/hash", state.hasher_url))
            .header("X-Service-Token", &state.internal_service_token)
            .json(&hash_request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to contact hasher service for verification: {}", e);
                internal_server_error(
                    "Failed to hash file for verification",
                    Some(payload.request_id.clone()),
                )
            })?;

        verify_hash_roundtrip_ms = Some(elapsed_ms(verify_hash_start));
        let hash_status = hash_resp.status();
        let hash_body = hash_resp.text().await.map_err(|e| {
            error!("Failed to read hasher response: {}", e);
            internal_server_error(
                "Failed to read hash service response",
                Some(payload.request_id.clone()),
            )
        })?;

        if !hash_status.is_success() {
            error!("Hasher error {}: {}", hash_status, hash_body);
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "Failed to hash file with hasher service".to_string(),
                    request_id: Some(payload.request_id.clone()),
                }),
            ));
        }

        let hash_response: HashResponse = serde_json::from_str(&hash_body).map_err(|e| {
            error!("Failed to parse hasher response: {}", e);
            internal_server_error(
                "Failed to parse hash service response",
                Some(payload.request_id.clone()),
            )
        })?;
        verify_hash_metrics = hash_response.metrics.clone();

        info!(
            "Computed hash for verification file using {}: {}",
            hash_response.algorithm, hash_response.hash
        );

        // Add the provided hash to the verify request
        payload.provided_hash = Some(hash_response.hash);
        payload.provided_size = Some(hash_response.file_size);
        payload.provided_algorithm = Some(hash_response.algorithm);
        payload.provided_immutable_object_id = Some(hash_response.immutable_object_id);
        payload.provided_storage_bucket = Some(hash_response.storage_bucket);
        payload.provided_storage_key = Some(hash_response.storage_key);
        payload.file_path = None; // Clear file_path as it's no longer needed
    }

    let manifest_verify_roundtrip_start = Instant::now();
    let resp = state
        .client
        .post(format!("{}/verify", state.manifest_url))
        .header("X-Service-Token", &state.internal_service_token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to contact manifest service: {}", e);
            internal_server_error(
                "Failed to contact manifest service",
                Some(payload.request_id.clone()),
            )
        })?;

    let manifest_verify_roundtrip_ms = elapsed_ms(manifest_verify_roundtrip_start);
    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        error!("Failed to read manifest response body: {}", e);
        internal_server_error(
            "Failed to read manifest service response",
            Some(payload.request_id.clone()),
        )
    })?;

    if !status.is_success() {
        let request_id = payload.request_id.clone();
        error!("Manifest service error {}: {}", status, body);
        return Err(upstream_service_error("Manifest", status, Some(request_id)));
    }

    let parsed: VerifyResponse = serde_json::from_str(&body).map_err(|e| {
        error!("Failed to parse manifest response: {}", e);
        internal_server_error(
            "Failed to parse verification response",
            Some(payload.request_id),
        )
    })?;

    let mut operation_record =
        load_operation_metrics(&state.db, &request_id, &auth_identity.key_fingerprint)
            .await
            .map_err(|e| {
                error!("Failed to load existing operation metrics: {}", e);
                internal_server_error(
                    "Failed to load existing operation metrics",
                    Some(request_id.clone()),
                )
            })?
            .unwrap_or(OperationMetricsResponse {
                request_id: request_id.clone(),
                signature_profile: fetched_manifest_profile.clone(),
                hash_algorithm: fetched_manifest_algorithm.clone(),
                file_size_bytes: fetched_manifest_size,
                process: None,
                verify: None,
                recorded_at: None,
            });

    if operation_record.signature_profile.is_none() {
        operation_record.signature_profile = fetched_manifest_profile;
    }
    if operation_record.hash_algorithm.is_none() {
        operation_record.hash_algorithm = fetched_manifest_algorithm;
    }
    if operation_record.file_size_bytes.is_none() {
        operation_record.file_size_bytes = fetched_manifest_size;
    }

    operation_record.verify = Some(VerifyOperationMetrics {
        gateway_total_ms: elapsed_ms(total_start),
        manifest_fetch_roundtrip_ms,
        manifest_fetch_metrics,
        verify_hash_roundtrip_ms,
        verify_hash_metrics,
        manifest_verify_roundtrip_ms,
        manifest_verify_metrics: parsed.metrics.clone(),
    });

    persist_operation_metrics(&state.db, &auth_identity.key_fingerprint, &operation_record)
        .await
        .map_err(|e| {
            error!("Failed to persist verify operation metrics: {}", e);
            internal_server_error(
                "Failed to persist verify operation metrics",
                Some(request_id.clone()),
            )
        })?;

    Ok(Json(parsed))
}

async fn process_file(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_role): axum::Extension<UserRole>,
    axum::Extension(auth_identity): axum::Extension<AuthIdentity>,
    Json(payload): Json<ProcessFileRequest>,
) -> Result<Json<ProcessFileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();
    let request_id = Uuid::new_v4().to_string();

    if !check_role(&user_role, &UserRole::Operator) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient permissions for signing".to_string(),
                request_id: Some(request_id.clone()),
            }),
        ));
    }

    check_rate_limit(
        &state.global_limiter,
        &auth_identity.key_fingerprint,
        "global",
        Some(request_id.clone()),
    )?;
    check_rate_limit(
        &state.sign_limiter,
        &auth_identity.key_fingerprint,
        "sign",
        Some(request_id.clone()),
    )?;

    info!(
        "Processing file: {} (request_id: {})",
        payload.file_path, request_id
    );

    let owned_file_path = ensure_user_owned_upload_path(
        &payload.file_path,
        &state.upload_dir,
        &auth_identity.key_fingerprint,
    )
    .map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Invalid process file path: {}", e),
                request_id: Some(request_id.clone()),
            }),
        )
    })?
    .to_string_lossy()
    .to_string();

    let validator = ValidationConfig::default();

    if let Some(hash_alg) = payload.hash_algorithm.as_deref() {
        if let Err(e) = validator.validate_hash_algorithm(hash_alg) {
            error!("Invalid hash algorithm: {}", e);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                    request_id: Some(request_id.clone()),
                }),
            ));
        }
    }

    if let Some(profile) = payload.signature_profile.as_deref() {
        let normalized = normalize_signature_profile(profile);
        if let Err(e) = validator.validate_signature_profile(&normalized) {
            error!("Invalid signature profile: {}", e);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                    request_id: Some(request_id.clone()),
                }),
            ));
        }
    }

    let schema_version = std::env::var("MANIFEST_SCHEMA_VERSION")
        .unwrap_or_else(|_| "pqc-hons.manifest.v1".to_string());
    let domain_sep =
        std::env::var("MANIFEST_DOMAIN_SEP").unwrap_or_else(|_| "pqc-hons.manifest.v1".to_string());

    if let Some(user_domain) = &payload.domain_sep {
        if user_domain != &domain_sep {
            error!(
                "User attempted to override domain_sep: {} != {}",
                user_domain, domain_sep
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Cannot override domain_sep (server-controlled for security)"
                        .to_string(),
                    request_id: Some(request_id.clone()),
                }),
            ));
        }
    }

    if let Some(user_schema) = &payload.schema_version {
        if user_schema != &schema_version {
            error!(
                "User attempted to override schema_version: {} != {}",
                user_schema, schema_version
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Cannot override schema_version (server-controlled for security)"
                        .to_string(),
                    request_id: Some(request_id.clone()),
                }),
            ));
        }
    }

    info!("Requesting hash from Hasher Service...");
    let hash_request = HashRequest {
        file_path: owned_file_path.clone(),
        request_id: request_id.clone(),
        storage_bucket: payload.bucket.clone(),
        hash_algorithm: payload.hash_algorithm.clone(),
    };

    if let Some(hash_alg) = payload.hash_algorithm.as_deref() {
        let normalized = hash_alg.to_ascii_uppercase();
        if normalized != "SHA256"
            && normalized != "SHA-256"
            && normalized != "KECCAK"
            && normalized != "KECCAK256"
            && normalized != "KECCAK-256"
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Unsupported hash algorithm '{}'", hash_alg),
                    request_id: Some(request_id.clone()),
                }),
            ));
        }
    }

    if let Some(profile) = payload.signature_profile.as_deref() {
        let normalized = normalize_signature_profile(profile);
        if normalized != "classical_only" && normalized != "pqc_only" && normalized != "hybrid" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Unsupported signature profile '{}'", profile),
                    request_id: Some(request_id.clone()),
                }),
            ));
        }
    }

    let hash_roundtrip_start = Instant::now();
    let hash_resp = state
        .client
        .post(format!("{}/hash", state.hasher_url))
        .header("X-Service-Token", &state.internal_service_token)
        .json(&hash_request)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to contact hasher service: {}", e);
            internal_server_error("Failed to contact hash service", Some(request_id.clone()))
        })?;

    let hash_roundtrip_ms = elapsed_ms(hash_roundtrip_start);
    let hash_status = hash_resp.status();
    let hash_body = hash_resp.text().await.map_err(|e| {
        error!("Failed to read hasher response body: {}", e);
        internal_server_error(
            "Failed to read hash service response",
            Some(request_id.clone()),
        )
    })?;

    if !hash_status.is_success() {
        error!("Hasher error {}: {}", hash_status, hash_body);
        return Err(upstream_service_error(
            "Hasher",
            hash_status,
            Some(request_id.clone()),
        ));
    }

    let hash_response: HashResponse = serde_json::from_str(&hash_body).map_err(|e| {
        error!("Failed to parse hasher response: {}", e);
        internal_server_error(
            "Failed to parse hash service response",
            Some(request_id.clone()),
        )
    })?;

    info!("Hash computed successfully");

    info!("Requesting manifest from Manifest Builder Service...");
    let manifest_request = ManifestRequest {
        request_id: request_id.clone(),
        owner_key_fingerprint: Some(auth_identity.key_fingerprint.clone()),
        hash: hash_response.hash,
        algorithm: hash_response.algorithm,
        file_size: hash_response.file_size,
        file_path: owned_file_path,
        storage_bucket: hash_response.storage_bucket,
        storage_key: hash_response.storage_key,
        immutable_object_id: hash_response.immutable_object_id,
        schema_version: Some(schema_version),
        domain_sep: Some(domain_sep),
        signature_profile: payload
            .signature_profile
            .map(|p| normalize_signature_profile(&p)),
    };

    let manifest_roundtrip_start = Instant::now();
    let manifest_resp = state
        .client
        .post(format!("{}/manifest", state.manifest_url))
        .header("X-Service-Token", &state.internal_service_token)
        .json(&manifest_request)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to contact manifest service: {}", e);
            internal_server_error(
                "Failed to contact manifest service",
                Some(request_id.clone()),
            )
        })?;

    let manifest_roundtrip_ms = elapsed_ms(manifest_roundtrip_start);
    let manifest_status = manifest_resp.status();
    let manifest_body = manifest_resp.text().await.map_err(|e| {
        error!("Failed to read manifest response body: {}", e);
        internal_server_error(
            "Failed to read manifest service response",
            Some(request_id.clone()),
        )
    })?;

    if !manifest_status.is_success() {
        error!(
            "Manifest service error {}: {}",
            manifest_status, manifest_body
        );
        return Err(upstream_service_error(
            "Manifest",
            manifest_status,
            Some(request_id.clone()),
        ));
    }

    let manifest_response: ManifestBuildResponse =
        serde_json::from_str(&manifest_body).map_err(|e| {
            error!("Failed to parse manifest response: {}", e);
            internal_server_error(
                "Failed to parse manifest response",
                Some(request_id.clone()),
            )
        })?;

    info!("Manifest built successfully");
    let manifest = manifest_response.manifest;

    let operation_record = OperationMetricsResponse {
        request_id: request_id.clone(),
        signature_profile: Some(manifest.core.signature_profile.clone()),
        hash_algorithm: Some(manifest.core.algorithm.clone()),
        file_size_bytes: Some(hash_response.file_size),
        process: Some(ProcessOperationMetrics {
            gateway_total_ms: elapsed_ms(total_start),
            hasher_roundtrip_ms: hash_roundtrip_ms,
            hash_metrics: hash_response.metrics.clone(),
            manifest_roundtrip_ms,
            manifest_metrics: manifest_response.metrics,
        }),
        verify: None,
        recorded_at: None,
    };

    persist_operation_metrics(&state.db, &auth_identity.key_fingerprint, &operation_record)
        .await
        .map_err(|e| {
            error!("Failed to persist process operation metrics: {}", e);
            internal_server_error(
                "Failed to persist process operation metrics",
                Some(request_id.clone()),
            )
        })?;

    Ok(Json(ProcessFileResponse { manifest }))
}
