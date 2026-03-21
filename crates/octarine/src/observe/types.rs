//! Core observability types
//!
//! This module contains the fundamental types for the observability system:
//! - [`Event`] - The core event structure
//! - [`Severity`] - Event severity levels
//! - [`EventContext`] - Who/what/where/when/why context
//! - [`TenantId`] - Validated tenant identifier
//! - [`UserId`] - Validated user identifier

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::observe::compliance::ComplianceTags;
use crate::observe::context::capture::capture_context;
use crate::observe::problem::Problem;

/// A validated tenant identifier
///
/// Constraints:
/// - 1-100 characters
/// - Alphanumeric + dash/underscore only
/// - No command injection patterns
/// - No path traversal patterns
///
/// Used in multi-tenant contexts to identify which tenant an operation belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    /// Create a new validated tenant ID
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if:
    /// - Empty or longer than 100 characters
    /// - Contains characters other than alphanumeric, dash, or underscore
    /// - Contains command injection patterns (`$(`, `` ` ``, `${`)
    /// - Contains path traversal (`..`, `/`, `\`)
    pub fn new(id: impl AsRef<str>) -> Result<Self, Problem> {
        let id = id.as_ref();

        if id.is_empty() || id.len() > 100 {
            return Err(Problem::validation("Tenant ID must be 1-100 characters"));
        }

        // Only allow alphanumeric + dash/underscore
        if !id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Problem::validation(
                "Tenant ID must be alphanumeric + dash/underscore",
            ));
        }

        // Prevent command injection
        if id.contains("$(") || id.contains('`') || id.contains("${") {
            return Err(Problem::validation(
                "Tenant ID contains command injection patterns",
            ));
        }

        // Prevent path traversal
        if id.contains("..") || id.contains('/') || id.contains('\\') {
            return Err(Problem::validation("Tenant ID contains path traversal"));
        }

        Ok(Self(id.to_string()))
    }

    /// Get the tenant ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to owned String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A validated user identifier
///
/// Constraints:
/// - 1-100 characters
/// - Alphanumeric + dash/underscore only
/// - No command injection patterns
/// - No path traversal patterns
///
/// Used to identify which user performed an operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(String);

impl UserId {
    /// Create a new validated user ID
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if:
    /// - Empty or longer than 100 characters
    /// - Contains characters other than alphanumeric, dash, or underscore
    /// - Contains command injection patterns (`$(`, `` ` ``, `${`)
    /// - Contains path traversal (`..`, `/`, `\`)
    pub fn new(id: impl AsRef<str>) -> Result<Self, Problem> {
        let id = id.as_ref();

        if id.is_empty() || id.len() > 100 {
            return Err(Problem::validation("User ID must be 1-100 characters"));
        }

        // Only allow alphanumeric + dash/underscore
        if !id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Problem::validation(
                "User ID must be alphanumeric + dash/underscore",
            ));
        }

        // Prevent command injection
        if id.contains("$(") || id.contains('`') || id.contains("${") {
            return Err(Problem::validation(
                "User ID contains command injection patterns",
            ));
        }

        // Prevent path traversal
        if id.contains("..") || id.contains('/') || id.contains('\\') {
            return Err(Problem::validation("User ID contains path traversal"));
        }

        Ok(Self(id.to_string()))
    }

    /// Get the user ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to owned String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Core observability event structure
///
/// Events are the fundamental unit of observability. They capture what happened,
/// when, where, and with what context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event ID
    pub id: Uuid,

    /// When the event occurred
    pub timestamp: DateTime<Utc>,

    /// Type of event
    pub event_type: EventType,

    /// Severity level
    pub severity: Severity,

    /// Human-readable message
    pub message: String,

    /// Structured context
    pub context: EventContext,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of observability events
///
/// Categorizes events for filtering, routing, and compliance reporting.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    // Errors
    /// Input validation failed
    ValidationError,
    /// Data conversion/transformation failed
    ConversionError,
    /// Sanitization operation failed
    SanitizationError,
    /// Authentication attempt failed
    AuthenticationError,
    /// Authorization/permission check failed
    AuthorizationError,
    /// System-level error
    SystemError,

    // Success events
    /// Input validation succeeded
    ValidationSuccess,
    /// Authentication succeeded
    AuthenticationSuccess,
    /// User login succeeded
    LoginSuccess,
    /// User login failed (distinct from auth error for audit)
    LoginFailure,
    /// Resource was created
    ResourceCreated,
    /// Resource was updated
    ResourceUpdated,
    /// Resource was deleted
    ResourceDeleted,

    // System events
    /// System/service startup
    SystemStartup,
    /// System/service shutdown
    SystemShutdown,
    /// Health check event
    HealthCheck,

    // Debug/Info
    /// Debug-level event
    Debug,
    /// Informational event
    Info,
    /// Warning event
    Warning,

    // Threshold events
    /// Metric threshold warning level exceeded
    ThresholdWarning,
    /// Metric threshold critical level exceeded
    ThresholdCritical,
    /// Metric threshold condition recovered (back to normal)
    ThresholdRecovered,
}

/// Event severity levels
///
/// Severity indicates the importance/urgency of an event.
/// Used for filtering in writers and alerting.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Debug-level events (development only)
    Debug,
    /// Informational events
    Info,
    /// Warning events (something unexpected but not an error)
    Warning,
    /// Error events (something failed)
    Error,
    /// Critical events (severe failure, immediate attention needed)
    Critical,
}

/// Event context (who/what/where/when/why)
///
/// Captures the full context of an event for compliance and debugging.
/// Includes identity (who), location (where), timing (when), and operation (what/why).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventContext {
    // WHO - Identity
    /// Tenant identifier for multi-tenant systems
    pub tenant_id: Option<TenantId>,
    /// User who triggered the event
    pub user_id: Option<UserId>,
    /// Session identifier for tracking user sessions
    pub session_id: Option<String>,

    // WHAT - Operation
    /// Name of the operation that triggered the event
    pub operation: String,
    /// Type of resource being operated on
    pub resource_type: Option<String>,
    /// Identifier of the resource being operated on
    pub resource_id: Option<String>,

    // WHERE - Location (code)
    /// Full module path where the event was generated
    pub module_path: String,
    /// Source file where the event was generated
    pub file: String,
    /// Line number where the event was generated
    pub line: u32,

    // WHERE - Location (network)
    /// Local IP address of this host/server
    /// Captured from network interfaces, TTL-cached
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub local_ip: Option<String>,

    /// Source IP address of the remote client/caller
    /// Set per-request via `set_source_ip()` or `with_source_ip()`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub source_ip: Option<String>,

    /// Full X-Forwarded-For chain if behind proxies
    /// First IP is the original client, subsequent IPs are proxies
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub source_ip_chain: Vec<String>,

    // WHEN - Already in timestamp, but correlation here
    /// Correlation ID for tracing related events
    pub correlation_id: Uuid,
    /// Parent span ID for distributed tracing
    pub parent_span_id: Option<Uuid>,

    // Compliance flags
    /// Whether this event contains PII (personally identifiable information)
    pub contains_pii: bool,
    /// Whether this event contains PHI (protected health information)
    pub contains_phi: bool,
    /// Whether this event is security-relevant for audit purposes
    pub security_relevant: bool,

    // PII redaction tracking (for audit trail)
    /// Types of PII that were detected and redacted in this event
    /// Empty if no PII was found or redaction was skipped
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub pii_types: Vec<String>,

    // Compliance framework tags
    /// Compliance control tags for audit reporting
    ///
    /// Maps this event to specific controls in SOC2, HIPAA, GDPR, and PCI-DSS.
    /// Used for compliance evidence collection and audit reporting.
    #[serde(skip_serializing_if = "ComplianceTags::is_empty")]
    #[serde(default)]
    pub compliance: ComplianceTags,
}

impl Default for EventContext {
    fn default() -> Self {
        Self {
            tenant_id: None,
            user_id: None,
            session_id: None,
            operation: String::new(),
            resource_type: None,
            resource_id: None,
            module_path: String::new(),
            file: String::new(),
            line: 0,
            local_ip: None,
            source_ip: None,
            source_ip_chain: Vec::new(),
            correlation_id: Uuid::new_v4(),
            parent_span_id: None,
            contains_pii: false,
            contains_phi: false,
            security_relevant: false,
            pii_types: Vec::new(),
            compliance: ComplianceTags::default(),
        }
    }
}

impl Event {
    /// Create a new audit event
    ///
    /// Automatically captures context from thread-local/task-local storage:
    /// - correlation_id
    /// - tenant_id
    /// - user_id
    /// - session_id
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::observe::{Event, EventType};
    /// use octarine::runtime::r#async::{set_user_id, clear_context};
    ///
    /// set_user_id("user-123");
    /// let event = Event::new(EventType::Info, "User action");
    /// // event.context.user_id will be Some("user-123")
    /// clear_context();
    /// ```
    pub fn new(event_type: EventType, message: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            severity: Self::default_severity(event_type),
            message: message.into(),
            context: capture_context(),
            metadata: HashMap::new(),
        }
    }

    /// Determine default severity from event type
    fn default_severity(event_type: EventType) -> Severity {
        use EventType::*;
        match event_type {
            Debug => Severity::Debug,
            Info | ResourceCreated | ResourceUpdated | ResourceDeleted => Severity::Info,
            ValidationSuccess | AuthenticationSuccess | LoginSuccess => Severity::Info,
            Warning | HealthCheck | ThresholdRecovered => Severity::Warning,
            ValidationError | ConversionError | SanitizationError => Severity::Warning,
            ThresholdWarning => Severity::Warning,
            AuthenticationError | AuthorizationError | LoginFailure => Severity::Error,
            ThresholdCritical => Severity::Critical,
            SystemError => Severity::Critical,
            SystemStartup | SystemShutdown => Severity::Info,
        }
    }

    /// Set the context for this event
    pub fn with_context(mut self, context: EventContext) -> Self {
        self.context = context;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ===== TenantId Tests =====

    #[test]
    fn test_tenant_id_valid() {
        assert!(TenantId::new("acme-corp").is_ok());
        assert!(TenantId::new("tenant_123").is_ok());
        assert!(TenantId::new("Tenant-ABC-123").is_ok());
        assert!(TenantId::new("a").is_ok()); // Minimum length
        assert!(TenantId::new("a".repeat(100)).is_ok()); // Maximum length
    }

    #[test]
    fn test_tenant_id_empty() {
        assert!(TenantId::new("").is_err());
    }

    #[test]
    fn test_tenant_id_too_long() {
        assert!(TenantId::new("a".repeat(101)).is_err());
    }

    #[test]
    fn test_tenant_id_invalid_characters() {
        assert!(TenantId::new("tenant.id").is_err()); // Dot
        assert!(TenantId::new("tenant id").is_err()); // Space
        assert!(TenantId::new("tenant@corp").is_err()); // At symbol
        assert!(TenantId::new("tenant/id").is_err()); // Slash
    }

    #[test]
    fn test_tenant_id_command_injection() {
        assert!(TenantId::new("tenant$(whoami)").is_err());
        assert!(TenantId::new("tenant`ls`").is_err());
        assert!(TenantId::new("tenant${USER}").is_err());
    }

    #[test]
    fn test_tenant_id_path_traversal() {
        assert!(TenantId::new("../etc/passwd").is_err());
        assert!(TenantId::new("tenant../other").is_err());
        assert!(TenantId::new("tenant/id").is_err());
        assert!(TenantId::new("tenant\\id").is_err());
    }

    #[test]
    fn test_tenant_id_as_str() {
        let id = TenantId::new("test-tenant").expect("Valid tenant ID");
        assert_eq!(id.as_str(), "test-tenant");
    }

    #[test]
    fn test_tenant_id_into_string() {
        let id = TenantId::new("test-tenant").expect("Valid tenant ID");
        assert_eq!(id.into_string(), "test-tenant");
    }

    #[test]
    fn test_tenant_id_display() {
        let id = TenantId::new("test-tenant").expect("Valid tenant ID");
        assert_eq!(format!("{}", id), "test-tenant");
    }

    #[test]
    fn test_tenant_id_as_ref() {
        let id = TenantId::new("test-tenant").expect("Valid tenant ID");
        let s: &str = id.as_ref();
        assert_eq!(s, "test-tenant");
    }

    // ===== UserId Tests =====

    #[test]
    fn test_user_id_valid() {
        assert!(UserId::new("user123").is_ok());
        assert!(UserId::new("user-abc").is_ok());
        assert!(UserId::new("User_ABC_123").is_ok());
        assert!(UserId::new("u").is_ok()); // Minimum length
        assert!(UserId::new("u".repeat(100)).is_ok()); // Maximum length
    }

    #[test]
    fn test_user_id_empty() {
        assert!(UserId::new("").is_err());
    }

    #[test]
    fn test_user_id_too_long() {
        assert!(UserId::new("u".repeat(101)).is_err());
    }

    #[test]
    fn test_user_id_invalid_characters() {
        assert!(UserId::new("user.id").is_err()); // Dot
        assert!(UserId::new("user id").is_err()); // Space
        assert!(UserId::new("user@example.com").is_err()); // At symbol
        assert!(UserId::new("user/id").is_err()); // Slash
    }

    #[test]
    fn test_user_id_command_injection() {
        assert!(UserId::new("user$(whoami)").is_err());
        assert!(UserId::new("user`ls`").is_err());
        assert!(UserId::new("user${USER}").is_err());
    }

    #[test]
    fn test_user_id_path_traversal() {
        assert!(UserId::new("../admin").is_err());
        assert!(UserId::new("user../other").is_err());
        assert!(UserId::new("user/id").is_err());
        assert!(UserId::new("user\\id").is_err());
    }

    #[test]
    fn test_user_id_as_str() {
        let id = UserId::new("testuser").expect("Valid user ID");
        assert_eq!(id.as_str(), "testuser");
    }

    #[test]
    fn test_user_id_into_string() {
        let id = UserId::new("testuser").expect("Valid user ID");
        assert_eq!(id.into_string(), "testuser");
    }

    #[test]
    fn test_user_id_display() {
        let id = UserId::new("testuser").expect("Valid user ID");
        assert_eq!(format!("{}", id), "testuser");
    }

    #[test]
    fn test_user_id_as_ref() {
        let id = UserId::new("testuser").expect("Valid user ID");
        let s: &str = id.as_ref();
        assert_eq!(s, "testuser");
    }
}
