use anyhow::{anyhow, Context, Result};
use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use governor::{Quota, RateLimiter};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

#[derive(Clone, Debug)]
pub struct AuthIdentity {
    pub role: UserRole,
    pub key_fingerprint: String,
}

#[derive(Clone, Debug)]
pub struct InternalServiceAuthConfig {
    pub token: String,
}

impl InternalServiceAuthConfig {
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("INTERNAL_SERVICE_TOKEN")
            .context("INTERNAL_SERVICE_TOKEN must be set for internal service authentication")?;

        if token.trim().is_empty() {
            return Err(anyhow!(
                "INTERNAL_SERVICE_TOKEN cannot be empty for internal service authentication"
            ));
        }

        if token.trim().len() < 32 {
            return Err(anyhow!(
                "INTERNAL_SERVICE_TOKEN must be at least 32 characters"
            ));
        }

        Ok(Self { token })
    }
}

/// API authentication configuration
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Map of API keys to roles
    pub api_keys: HashMap<String, ApiKeyInfo>,
    /// Whether authentication is required
    pub require_auth: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApiKeyInfo {
    pub role: UserRole,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,    // Full access
    Operator, // Can sign and verify
    ReadOnly, // Can only verify
}

impl AuthConfig {
    /// Load authentication config from environment
    pub fn from_env() -> Result<Self> {
        let require_auth = std::env::var("REQUIRE_AUTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true); // Default to requiring auth for security

        let mut api_keys = HashMap::new();

        // Load API keys from environment variable (JSON format)
        // Example: API_KEYS='{"key1": {"role": "admin", "description": "Admin key"}}'
        if let Ok(keys_json) = std::env::var("API_KEYS") {
            api_keys = serde_json::from_str(&keys_json).context("Failed to parse API_KEYS JSON")?;
        }

        // Also load from file if specified
        if let Ok(keys_file) = std::env::var("API_KEYS_FILE") {
            let content = std::fs::read_to_string(&keys_file)
                .with_context(|| format!("Failed to read API keys file: {}", keys_file))?;
            let file_keys: HashMap<String, ApiKeyInfo> =
                serde_json::from_str(&content).context("Failed to parse API keys file")?;
            api_keys.extend(file_keys);
        }

        if require_auth && api_keys.is_empty() {
            return Err(anyhow!(
                "Authentication is required but no API keys configured. Set API_KEYS or API_KEYS_FILE."
            ));
        }

        Ok(Self {
            api_keys,
            require_auth,
        })
    }

    /// Validate API key and return role
    pub fn validate_key(&self, key: &str) -> Option<&ApiKeyInfo> {
        self.api_keys.get(key)
    }
}

/// Extract and validate API key from request headers
pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-API-Key")
        .or_else(|| headers.get("Authorization"))
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            // Handle "Bearer <key>" format
            if s.starts_with("Bearer ") {
                s[7..].to_string()
            } else {
                s.to_string()
            }
        })
}

type AuthFailureLimiter = Arc<
    RateLimiter<
        String,
        governor::state::keyed::DashMapStateStore<String>,
        governor::clock::DefaultClock,
        governor::middleware::NoOpMiddleware,
    >,
>;

fn auth_failure_limiter() -> &'static Option<AuthFailureLimiter> {
    static LIMITER: OnceLock<Option<AuthFailureLimiter>> = OnceLock::new();
    LIMITER.get_or_init(|| {
        let per_minute = std::env::var("RATE_LIMIT_AUTH_FAIL_PER_MIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        NonZeroU32::new(per_minute)
            .map(Quota::per_minute)
            .map(|quota| Arc::new(RateLimiter::keyed(quota)))
    })
}

fn trust_forwarded_auth_headers() -> bool {
    std::env::var("TRUST_PROXY_HEADERS")
        .ok()
        .and_then(|value| value.parse::<bool>().ok())
        .unwrap_or(false)
}

fn auth_failure_identity_key(headers: &HeaderMap, request: &Request) -> String {
    let remote_ip = request
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let forwarded_ip = if trust_forwarded_auth_headers() {
        headers
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .or_else(|| {
                headers
                    .get("X-Real-IP")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
            })
    } else {
        None
    };

    let identity_ip = forwarded_ip.unwrap_or(remote_ip);

    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown");

    api_key_fingerprint(&format!("{}|{}", identity_ip, user_agent))
}

fn check_auth_failure_rate_limit(
    headers: &HeaderMap,
    request: &Request,
) -> Result<(), (StatusCode, Json<crate::ErrorResponse>)> {
    if let Some(limiter) = auth_failure_limiter() {
        let key = auth_failure_identity_key(headers, request);
        if limiter.check_key(&key).is_err() {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(crate::ErrorResponse {
                    error: "Too many authentication failures. Please retry later.".to_string(),
                    request_id: None,
                }),
            ));
        }
    }

    Ok(())
}

fn constant_time_equals(left: &str, right: &str) -> bool {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let max_len = left_bytes.len().max(right_bytes.len());

    let mut diff = left_bytes.len() ^ right_bytes.len();
    for index in 0..max_len {
        let left_value = *left_bytes.get(index).unwrap_or(&0);
        let right_value = *right_bytes.get(index).unwrap_or(&0);
        diff |= (left_value ^ right_value) as usize;
    }

    diff == 0
}

/// Axum middleware for API key authentication
pub async fn auth_middleware(
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<crate::ErrorResponse>)> {
    // Get auth config from request extensions (set during startup)
    let auth_config = request
        .extensions()
        .get::<AuthConfig>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(crate::ErrorResponse {
                    error: "Auth configuration not found".to_string(),
                    request_id: None,
                }),
            )
        })?;

    // Skip auth if not required (for development only!)
    if !auth_config.require_auth {
        return Ok(next.run(request).await);
    }

    // Extract API key
    let api_key = match extract_api_key(&headers) {
        Some(value) => value,
        None => {
            check_auth_failure_rate_limit(&headers, &request)?;
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(crate::ErrorResponse {
                    error: "Missing API key. Provide X-API-Key or Authorization header."
                        .to_string(),
                    request_id: None,
                }),
            ));
        }
    };

    // Validate API key
    let key_info = match auth_config.validate_key(&api_key) {
        Some(value) => value,
        None => {
            check_auth_failure_rate_limit(&headers, &request)?;
            return Err((
                StatusCode::FORBIDDEN,
                Json(crate::ErrorResponse {
                    error: "Invalid API key".to_string(),
                    request_id: None,
                }),
            ));
        }
    };

    // Add role to request extensions for downstream handlers
    request.extensions_mut().insert(key_info.role.clone());
    request.extensions_mut().insert(AuthIdentity {
        role: key_info.role.clone(),
        key_fingerprint: api_key_fingerprint(&api_key),
    });

    Ok(next.run(request).await)
}

pub async fn internal_service_auth_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<crate::ErrorResponse>)> {
    let path = request.uri().path();
    if path == "/" || path == "/health" {
        return Ok(next.run(request).await);
    }

    let auth_config = request
        .extensions()
        .get::<InternalServiceAuthConfig>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(crate::ErrorResponse {
                    error: "Internal service auth configuration not found".to_string(),
                    request_id: None,
                }),
            )
        })?;

    let provided = headers
        .get("X-Service-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(crate::ErrorResponse {
                    error: "Missing X-Service-Token".to_string(),
                    request_id: None,
                }),
            )
        })?;

    if !constant_time_equals(provided, &auth_config.token) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(crate::ErrorResponse {
                error: "Invalid X-Service-Token".to_string(),
                request_id: None,
            }),
        ));
    }

    Ok(next.run(request).await)
}

fn api_key_fingerprint(api_key: &str) -> String {
    let digest = Sha256::digest(api_key.as_bytes());
    format!("{:x}", digest)
}

/// Check if user has required role
pub fn check_role(user_role: &UserRole, required_role: &UserRole) -> bool {
    match (user_role, required_role) {
        (UserRole::Admin, _) => true, // Admin can do everything
        (UserRole::Operator, UserRole::Operator) => true,
        (UserRole::Operator, UserRole::ReadOnly) => true,
        (UserRole::ReadOnly, UserRole::ReadOnly) => true,
        _ => false,
    }
}

/// Rate limiting configuration
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Requests per minute for signing operations
    pub sign_requests_per_minute: u32,
    /// Requests per minute for verify operations
    pub verify_requests_per_minute: u32,
    /// Requests per minute for hash operations
    pub hash_requests_per_minute: u32,
    /// Global rate limit (all operations)
    pub global_requests_per_minute: u32,
}

impl RateLimitConfig {
    pub fn from_env() -> Self {
        Self {
            sign_requests_per_minute: std::env::var("RATE_LIMIT_SIGN_PER_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60), // 60 signature requests per minute
            verify_requests_per_minute: std::env::var("RATE_LIMIT_VERIFY_PER_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(120), // 120 verify requests per minute
            hash_requests_per_minute: std::env::var("RATE_LIMIT_HASH_PER_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100), // 100 hash requests per minute
            global_requests_per_minute: std::env::var("RATE_LIMIT_GLOBAL_PER_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(200), // 200 total requests per minute
        }
    }

    /// Create a rate limiter for the specified operation type
    pub fn create_limiter(
        &self,
        operation: &str,
    ) -> Option<
        Arc<
            RateLimiter<
                String,
                governor::state::keyed::DashMapStateStore<String>,
                governor::clock::DefaultClock,
                governor::middleware::NoOpMiddleware,
            >,
        >,
    > {
        let per_minute = match operation {
            "sign" => self.sign_requests_per_minute,
            "verify" => self.verify_requests_per_minute,
            "hash" => self.hash_requests_per_minute,
            "global" => self.global_requests_per_minute,
            _ => return None,
        };

        if let Some(quota) = NonZeroU32::new(per_minute) {
            let quota = Quota::per_minute(quota);
            Some(Arc::new(RateLimiter::keyed(quota)))
        } else {
            None
        }
    }
}

/// Input validation constraints
#[derive(Clone, Debug)]
pub struct ValidationConfig {
    /// Maximum request ID length
    pub max_request_id_len: usize,
    /// Maximum file path length
    pub max_file_path_len: usize,
    /// Maximum domain separator length
    pub max_domain_sep_len: usize,
    /// Allowed hash algorithms
    pub allowed_hash_algorithms: Vec<String>,
    /// Allowed signature profiles
    pub allowed_signature_profiles: Vec<String>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_request_id_len: 128,
            max_file_path_len: 4096,
            max_domain_sep_len: 256,
            allowed_hash_algorithms: vec![
                "SHA256".to_string(),
                "SHA-256".to_string(),
                "KECCAK".to_string(),
                "KECCAK256".to_string(),
                "KECCAK-256".to_string(),
            ],
            allowed_signature_profiles: vec![
                "classical_only".to_string(),
                "pqc_only".to_string(),
                "hybrid".to_string(),
            ],
        }
    }
}

impl ValidationConfig {
    /// Validate request ID format and length
    pub fn validate_request_id(&self, request_id: &str) -> Result<()> {
        if request_id.is_empty() {
            return Err(anyhow!("Request ID cannot be empty"));
        }
        if request_id.len() > self.max_request_id_len {
            return Err(anyhow!(
                "Request ID too long: {} chars (max: {})",
                request_id.len(),
                self.max_request_id_len
            ));
        }
        // Check for valid UUID format
        if uuid::Uuid::parse_str(request_id).is_err() {
            return Err(anyhow!("Request ID must be a valid UUID"));
        }
        Ok(())
    }

    /// Validate hash algorithm
    pub fn validate_hash_algorithm(&self, algorithm: &str) -> Result<()> {
        let normalized = algorithm.to_uppercase();
        if !self.allowed_hash_algorithms.contains(&normalized) {
            return Err(anyhow!(
                "Invalid hash algorithm '{}'. Allowed: {:?}",
                algorithm,
                self.allowed_hash_algorithms
            ));
        }
        Ok(())
    }

    /// Validate signature profile
    pub fn validate_signature_profile(&self, profile: &str) -> Result<()> {
        let normalized = profile.to_lowercase();
        if !self.allowed_signature_profiles.contains(&normalized) {
            return Err(anyhow!(
                "Invalid signature profile '{}'. Allowed: {:?}",
                profile,
                self.allowed_signature_profiles
            ));
        }
        Ok(())
    }

    /// Validate domain separator
    pub fn validate_domain_separator(&self, domain_sep: &str) -> Result<()> {
        if domain_sep.is_empty() {
            return Err(anyhow!("Domain separator cannot be empty"));
        }
        if domain_sep.len() > self.max_domain_sep_len {
            return Err(anyhow!(
                "Domain separator too long: {} chars (max: {})",
                domain_sep.len(),
                self.max_domain_sep_len
            ));
        }
        // Ensure domain separator contains only ASCII printable characters
        if !domain_sep.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return Err(anyhow!("Domain separator contains invalid characters"));
        }
        Ok(())
    }
}

/// Security configuration for file access control
#[derive(Clone, Debug)]
pub struct PathSecurityPolicy {
    /// Allowed base directories where files can be read
    pub allowed_directories: Vec<PathBuf>,
    /// Maximum file size in bytes (for DoS protection)
    pub max_file_size: u64,
    /// Whether to follow symlinks
    pub follow_symlinks: bool,
}

impl Default for PathSecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_directories: vec![PathBuf::from("/data/uploads")],
            max_file_size: 100 * 1024 * 1024, // 100 MB default
            follow_symlinks: false,
        }
    }
}

impl PathSecurityPolicy {
    /// Create policy from environment variables
    pub fn from_env() -> Self {
        let mut allowed_dirs: Vec<PathBuf> = std::env::var("ALLOWED_FILE_DIRECTORIES")
            .unwrap_or_else(|_| "/data/uploads".to_string())
            .split(':')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .collect();

        if allowed_dirs.is_empty() {
            allowed_dirs.push(PathBuf::from("/data/uploads"));
        }

        let max_file_size = std::env::var("MAX_FILE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024); // 100 MB

        let max_file_size = max_file_size.min(100 * 1024 * 1024);

        let requested_follow_symlinks = std::env::var("FOLLOW_SYMLINKS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);

        let allow_insecure_follow_symlinks = std::env::var("ALLOW_INSECURE_FOLLOW_SYMLINKS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);

        let follow_symlinks = requested_follow_symlinks && allow_insecure_follow_symlinks;

        Self {
            allowed_directories: allowed_dirs,
            max_file_size,
            follow_symlinks,
        }
    }
}

/// Validates and sanitizes file paths to prevent directory traversal attacks
pub fn validate_file_path(user_path: &str, policy: &PathSecurityPolicy) -> Result<PathBuf> {
    // Reject empty paths
    if user_path.is_empty() {
        return Err(anyhow!("File path cannot be empty"));
    }

    // Reject paths with null bytes (can bypass security checks)
    if user_path.contains('\0') {
        return Err(anyhow!("File path contains null byte"));
    }

    // Convert to PathBuf and canonicalize
    let path = PathBuf::from(user_path);

    // Reject absolute paths that try to access sensitive system directories
    let sensitive_prefixes = [
        "/etc",
        "/root",
        "/boot",
        "/sys",
        "/proc",
        "/dev",
        "/var/run",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
    ];

    if let Ok(abs_path) = path.canonicalize() {
        for sensitive in &sensitive_prefixes {
            if abs_path.starts_with(sensitive) {
                return Err(anyhow!(
                    "Access denied: Cannot access system directory '{}'",
                    sensitive
                ));
            }
        }
    }

    let resolved_path = resolve_path_without_symlinks(&path)?;

    // Resolve to absolute path (resolves .. and, when enabled, symlinks)
    let canonical_path = if policy.follow_symlinks {
        path.canonicalize()
            .with_context(|| format!("Failed to resolve path: {}", user_path))?
    } else {
        resolved_path.clone()
    };

    let allowed_check_path = path
        .canonicalize()
        .unwrap_or_else(|_| resolved_path.clone());

    // Check if path is within allowed directories, tracking the matched source directory
    let matched_allowed_dir = policy.allowed_directories.iter().find_map(|allowed_dir| {
        let canonical_allowed = allowed_dir.canonicalize().ok()?;
        if allowed_check_path.starts_with(&canonical_allowed) {
            resolve_path_without_symlinks(allowed_dir).ok()
        } else {
            None
        }
    });

    let Some(matched_allowed_dir) = matched_allowed_dir else {
        return Err(anyhow!(
            "Access denied: Path '{}' is not within allowed directories. Allowed: {:?}",
            canonical_path.display(),
            policy.allowed_directories
        ));
    };

    // Check file exists and inspect without following symlinks
    let symlink_metadata = std::fs::symlink_metadata(&canonical_path).with_context(|| {
        format!(
            "Failed to read file metadata without following symlinks: {}",
            canonical_path.display()
        )
    })?;

    if !policy.follow_symlinks && symlink_metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "Symlinks are not allowed: {}",
            canonical_path.display()
        ));
    }

    // Reject symlink anywhere in path when symlinks are disabled
    if !policy.follow_symlinks
        && contains_symlink_component_below_root(&canonical_path, &matched_allowed_dir)?
    {
        return Err(anyhow!(
            "Symlink component detected in path: {}",
            canonical_path.display()
        ));
    }

    // Check if it's a regular file (not directory, device, etc.)
    if !symlink_metadata.file_type().is_file() {
        return Err(anyhow!(
            "Path is not a regular file: {}",
            canonical_path.display()
        ));
    }

    // Check file size
    let metadata = std::fs::metadata(&canonical_path)
        .with_context(|| format!("Failed to read file metadata: {}", canonical_path.display()))?;

    if metadata.len() > policy.max_file_size {
        return Err(anyhow!(
            "File too large: {} bytes (max: {} bytes)",
            metadata.len(),
            policy.max_file_size
        ));
    }

    Ok(canonical_path)
}

fn contains_symlink_component_below_root(path: &Path, root: &Path) -> Result<bool> {
    let root_resolved = resolve_path_without_symlinks(root)?;

    if !path.starts_with(&root_resolved) {
        return Err(anyhow!(
            "Path '{}' does not start with expected root '{}'",
            path.display(),
            root_resolved.display()
        ));
    }

    let root_meta = std::fs::symlink_metadata(&root_resolved).with_context(|| {
        format!(
            "Failed to inspect allowed directory '{}'",
            root_resolved.display()
        )
    })?;
    if root_meta.file_type().is_symlink() {
        return Ok(true);
    }

    let mut current = root_resolved.clone();
    let relative = path
        .strip_prefix(&root_resolved)
        .context("Failed to compute path suffix under allowed root")?;

    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("Failed to inspect path component '{}'", current.display()))?;

        if metadata.file_type().is_symlink() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Manually resolve path without following symlinks
fn resolve_path_without_symlinks(path: &Path) -> Result<PathBuf> {
    let mut resolved = PathBuf::new();

    // Handle absolute vs relative paths
    if path.is_absolute() {
        resolved.push("/");
    } else {
        resolved = std::env::current_dir().context("Failed to get current directory")?;
    }

    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if !resolved.pop() {
                    return Err(anyhow!("Path traversal beyond root"));
                }
            }
            std::path::Component::Normal(name) => {
                resolved.push(name);
            }
            std::path::Component::CurDir => {
                // Skip "." components
            }
            std::path::Component::RootDir => {
                resolved = PathBuf::from("/");
            }
            std::path::Component::Prefix(_) => {
                // Windows-specific, not applicable in containerized Linux environment
                return Err(anyhow!("Windows paths not supported"));
            }
        }
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_reject_path_traversal() {
        let policy = PathSecurityPolicy::default();

        // Should reject directory traversal attempts
        assert!(validate_file_path("../../etc/passwd", &policy).is_err());
        assert!(validate_file_path("/etc/passwd", &policy).is_err());
        assert!(validate_file_path("../../../root/.ssh/id_rsa", &policy).is_err());
    }

    #[test]
    fn test_reject_null_bytes() {
        let policy = PathSecurityPolicy::default();
        assert!(validate_file_path("/tmp/file\0.txt", &policy).is_err());
    }

    #[test]
    fn test_reject_empty_path() {
        let policy = PathSecurityPolicy::default();
        assert!(validate_file_path("", &policy).is_err());
    }

    #[test]
    fn test_allowed_path() {
        let temp_dir = std::env::temp_dir().join("pqc-uploads");
        fs::create_dir_all(&temp_dir).unwrap();

        let test_file = temp_dir.join("test.txt");
        fs::write(&test_file, b"test content").unwrap();

        let mut policy = PathSecurityPolicy::default();
        policy.allowed_directories = vec![temp_dir];

        let result = validate_file_path(test_file.to_str().unwrap(), &policy);
        assert!(result.is_ok());

        // Cleanup
        fs::remove_file(&test_file).ok();
    }
}
