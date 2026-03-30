use serde::Serialize;
use std::path::Path;
use tracing::{info, warn};

/// AuditEventType categorizes security-relevant events
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    Authentication,
    AuthenticationFailure,
    FileAccess,
    SignatureCreated,
    SignatureVerified,
    SignatureVerificationFailed,
    RateLimitExceeded,
    PathTraversalAttempt,
    DomainSeparationViolation,
    PrivateKeyAccess,
    ConfigurationChange,
}

/// AuditEvent represents a security-relevant event
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user: Option<String>,
    pub request_id: Option<String>,
    pub source_ip: Option<String>,
    pub resource: Option<String>,
    pub action: String,
    pub result: AuditResult,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
}

impl AuditEvent {
    pub fn new(event_type: AuditEventType, action: String, result: AuditResult) -> Self {
        Self {
            event_type,
            timestamp: chrono::Utc::now(),
            user: None,
            request_id: None,
            source_ip: None,
            resource: None,
            action,
            result,
            details: None,
        }
    }

    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(mask_sensitive_path(&resource));
        self
    }

    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Log the audit event
    pub fn log(&self) {
        let json = serde_json::to_string(self).unwrap_or_else(|_| format!("{:?}", self));

        match self.result {
            AuditResult::Success => info!(
                audit_event = true,
                event_type = ?self.event_type,
                user = ?self.user,
                request_id = ?self.request_id,
                "{}",
                json
            ),
            AuditResult::Failure | AuditResult::Denied => warn!(
                audit_event = true,
                security_event = true,
                event_type = ?self.event_type,
                user = ?self.user,
                request_id = ?self.request_id,
                "{}",
                json
            ),
        }
    }
}

/// Mask sensitive file paths for logging
/// Example: "/home/user/secret/file.txt" -> "/home/***/secret/***"
pub fn mask_sensitive_path(path: &str) -> String {
    let path_obj = Path::new(path);

    let components: Vec<_> = path_obj.components().collect();
    if components.len() <= 2 {
        return path.to_string();
    }

    // Mask middle components but keep first and last for context
    let mut masked = String::new();
    for (i, component) in components.iter().enumerate() {
        if i > 0 {
            masked.push('/');
        }

        if i == 0 || i == components.len() - 1 {
            // Keep first and last component
            masked.push_str(&component.as_os_str().to_string_lossy());
        } else if i == 1 && components.len() > 3 {
            // Keep second component if path is long enough
            masked.push_str(&component.as_os_str().to_string_lossy());
        } else {
            masked.push_str("***");
        }
    }

    masked
}

/// Mask API keys in strings
pub fn mask_api_key(key: &str) -> String {
    if key.len() <= 8 {
        return "***".to_string();
    }
    format!("{}...{}", &key[..4], &key[key.len() - 4..])
}

/// Mask signature values (show first/last 8 chars)
pub fn mask_signature(signature: &str) -> String {
    if signature.len() <= 16 {
        return "***".to_string();
    }
    format!(
        "{}...{}",
        &signature[..8],
        &signature[signature.len() - 8..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_sensitive_path() {
        assert_eq!(
            mask_sensitive_path("/home/user/documents/secret/file.txt"),
            "/home/user/***/***/ file.txt"
        );
        assert_eq!(mask_sensitive_path("/tmp/file.txt"), "/tmp/file.txt");
    }

    #[test]
    fn test_mask_api_key() {
        assert_eq!(mask_api_key("abcdef1234567890"), "abcd...7890");
        assert_eq!(mask_api_key("short"), "***");
    }

    #[test]
    fn test_mask_signature() {
        let long_sig = "a".repeat(100);
        let masked = mask_signature(&long_sig);
        assert!(masked.contains("..."));
        assert_eq!(masked.len(), 19); // 8 + 3 + 8
    }
}
