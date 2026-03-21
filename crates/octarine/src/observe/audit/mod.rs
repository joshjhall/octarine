//! # Audit - Domain-Specific Audit Logging
//!
//! The audit module provides fluent builders for common audit patterns with
//! automatic compliance tagging for SOC2, HIPAA, GDPR, and PCI-DSS.
//!
//! ## Quick Start
//!
//! ```ignore
//! use octarine::observe::audit::{Audit, ThreatLevel, DataClassification};
//!
//! // Authentication
//! Audit::auth()
//!     .login("user@example.com")
//!     .with_mfa()
//!     .success()
//!     .emit();
//!
//! // Data access
//! Audit::data_access()
//!     .read("users")
//!     .records(100)
//!     .success()
//!     .emit();
//!
//! // Admin action
//! Audit::admin("update_config")
//!     .target("security.toml")
//!     .justification("Security patch")
//!     .success()
//!     .emit();
//!
//! // Security event
//! Audit::security("anomaly_detected")
//!     .threat_level(ThreatLevel::High)
//!     .source_ip("203.0.113.50")
//!     .blocked()
//!     .failure("Blocked suspicious request")
//!     .emit();
//!
//! // Compliance check
//! Audit::compliance(ComplianceFramework::Soc2)
//!     .control("CC6.1")
//!     .evidence("access_review")
//!     .passed()
//!     .emit();
//! ```
//!
//! ## Audit Domains
//!
//! | Domain | Builder | Use Case |
//! |--------|---------|----------|
//! | Authentication | [`Audit::auth()`] | Login, logout, password changes |
//! | Data Access | [`Audit::data_access()`] | CRUD operations, exports |
//! | Admin | [`Audit::admin()`] | Privileged operations |
//! | Security | [`Audit::security()`] | Threats, incidents, anomalies |
//! | Compliance | [`Audit::compliance()`] | Control checks, audits |
//!
//! ## Compliance Auto-Tagging
//!
//! Each domain automatically tags events with relevant compliance controls:
//!
//! - **Auth**: SOC2 CC6.1 (Logical Access), CC6.2 (User Registration)
//! - **Data Access**: SOC2 CC8.1 (Data Protection), HIPAA Technical
//! - **Admin**: SOC2 CC6.3 (Privileged Access), CC3.1 (Change Management)
//! - **Security**: SOC2 CC6.6 (Threat Protection), CC7.2 (Incident Response)
//! - **Compliance**: Framework-specific controls
//!
//! ## When to Use Audit vs Other APIs
//!
//! The observe module provides multiple APIs for different use cases:
//!
//! | Use Case | API | Example |
//! |----------|-----|---------|
//! | Domain-specific audit trails | [`Audit::auth()`], [`Audit::data_access()`], etc. | Login, data access, admin actions |
//! | Custom events with compliance | [`ObserveBuilder::for_operation()`](crate::observe::ObserveBuilder) | Custom business logic events |
//! | Simple logging | [`info()`](crate::observe::info), [`warn()`](crate::observe::warn), [`error()`](crate::observe::error) | General application logging |
//!
//! **Choose `Audit::*()` when:**
//! - You're logging authentication, data access, admin, or security events
//! - You need automatic compliance tagging (SOC2, HIPAA, etc.)
//! - You want consistent audit trail formatting across your application
//!
//! **Choose `ObserveBuilder` when:**
//! - You need custom event types not covered by the audit domains
//! - You want fine-grained control over compliance tags
//! - You're building domain-specific observability for your application
//!
//! **Choose shortcut functions when:**
//! - You just need simple logging without compliance requirements
//! - You're logging debug or operational information
//! - Performance is critical and you want minimal overhead

mod builders;
mod event;
pub mod types;

pub use builders::{
    AdminAuditBuilder, AuthAuditBuilder, ComplianceAuditBuilder, DataAccessAuditBuilder,
    SecurityAuditBuilder,
};
pub use event::AuditEvent;
pub use types::{
    AccessType, AuthType, ComplianceFramework, ComplianceResult, DataClassification, Outcome,
    SecurityAction, ThreatLevel,
};

/// Entry point for audit logging.
///
/// Provides static methods to create domain-specific audit builders.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::audit::Audit;
///
/// Audit::auth()
///     .login("user@example.com")
///     .success()
///     .emit();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Audit;

impl Audit {
    /// Create an authentication audit builder.
    ///
    /// Use this for login, logout, password changes, and session management.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Audit::auth()
    ///     .login("alice@example.com")
    ///     .with_mfa()
    ///     .success()
    ///     .emit();
    /// ```
    #[must_use]
    pub fn auth() -> AuthAuditBuilder {
        AuthAuditBuilder::new()
    }

    /// Create a data access audit builder for a read operation.
    ///
    /// Use `read`, `write`, `create`, `delete`, or `export` to set the access type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Audit::data_access()
    ///     .read("users")
    ///     .records(50)
    ///     .success()
    ///     .emit();
    /// ```
    #[must_use]
    pub fn data_access() -> DataAccessAuditBuilderInit {
        DataAccessAuditBuilderInit
    }

    /// Create an administrative action audit builder.
    ///
    /// Use this for privileged operations like configuration changes,
    /// user management, and security policy updates.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Audit::admin("update_security_policy")
    ///     .target("rate_limits.toml")
    ///     .justification("Increase rate limits for new feature")
    ///     .success()
    ///     .emit();
    /// ```
    #[must_use]
    pub fn admin(operation: &str) -> AdminAuditBuilder {
        AdminAuditBuilder::new(operation)
    }

    /// Create a security event audit builder.
    ///
    /// Use this for security incidents, threat detection, and anomaly events.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::observe::audit::ThreatLevel;
    ///
    /// Audit::security("brute_force_detected")
    ///     .threat_level(ThreatLevel::High)
    ///     .source_ip("203.0.113.50")
    ///     .blocked()
    ///     .failure("Blocked after 10 failed attempts")
    ///     .emit();
    /// ```
    #[must_use]
    pub fn security(operation: &str) -> SecurityAuditBuilder {
        SecurityAuditBuilder::new(operation)
    }

    /// Create a compliance check audit builder.
    ///
    /// Use this for compliance control checks and audit evidence collection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::observe::audit::ComplianceFramework;
    ///
    /// Audit::compliance(ComplianceFramework::Soc2)
    ///     .control("CC6.1")
    ///     .evidence("quarterly_access_review")
    ///     .passed()
    ///     .emit();
    /// ```
    #[must_use]
    pub fn compliance(framework: ComplianceFramework) -> ComplianceAuditBuilder {
        ComplianceAuditBuilder::new(framework)
    }
}

/// Intermediate type for data access builder initialization.
///
/// This allows the fluent API pattern: `Audit::data_access().read("users")`
#[derive(Debug, Clone, Copy)]
pub struct DataAccessAuditBuilderInit;

impl DataAccessAuditBuilderInit {
    /// Create a read operation audit.
    #[must_use]
    pub fn read(self, resource: &str) -> DataAccessAuditBuilder {
        DataAccessAuditBuilder::read(resource)
    }

    /// Create a create operation audit.
    #[must_use]
    pub fn create(self, resource: &str) -> DataAccessAuditBuilder {
        DataAccessAuditBuilder::create(resource)
    }

    /// Create a write/update operation audit.
    #[must_use]
    pub fn write(self, resource: &str) -> DataAccessAuditBuilder {
        DataAccessAuditBuilder::write(resource)
    }

    /// Create a delete operation audit.
    #[must_use]
    pub fn delete(self, resource: &str) -> DataAccessAuditBuilder {
        DataAccessAuditBuilder::delete(resource)
    }

    /// Create an export operation audit.
    #[must_use]
    pub fn export(self, resource: &str) -> DataAccessAuditBuilder {
        DataAccessAuditBuilder::export(resource)
    }

    /// Create a bulk operation audit.
    #[must_use]
    pub fn bulk(self, resource: &str) -> DataAccessAuditBuilder {
        DataAccessAuditBuilder::bulk(resource)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_auth() {
        let event = Audit::auth().login("test_user").success();
        assert_eq!(event.operation(), "auth.login");
    }

    #[test]
    fn test_audit_data_access() {
        let event = Audit::data_access().read("users").records(10).success();
        assert_eq!(event.operation(), "data.read");
    }

    #[test]
    fn test_audit_admin() {
        let event = Audit::admin("update_config").target("app.toml").success();
        assert_eq!(event.operation(), "admin.update_config");
    }

    #[test]
    fn test_audit_security() {
        let event = Audit::security("intrusion_attempt")
            .threat_level(ThreatLevel::Critical)
            .failure("Blocked");
        assert_eq!(event.operation(), "security.intrusion_attempt");
    }

    #[test]
    fn test_audit_compliance() {
        let event = Audit::compliance(ComplianceFramework::Soc2)
            .control("CC6.1")
            .passed();
        assert_eq!(event.operation(), "compliance.soc2");
    }
}
