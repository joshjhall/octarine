//! Context shortcuts for common use cases
//!
//! These shortcuts provide pre-configured contexts that combine
//! multiple context domains (capture, compliance, tenant, etc.).
//! For domain-specific shortcuts, see the builder/*_shortcuts.rs files.
//!
//! Follows DUAL FUNCTION pattern:
//! - `name_builder()` returns configured Builder
//! - `name()` returns built object

use crate::observe::EventContext;
use crate::observe::context::builder::ContextBuilder;

// ==========================================
// MINIMAL CONTEXT
// ==========================================

/// Returns a builder configured for minimal context (customizable)
/// Combines: no auto-capture + non-security-relevant
pub fn minimal_builder() -> ContextBuilder {
    ContextBuilder::new()
        .no_auto_capture()
        .security_relevant(false)
}

/// Returns a minimal context directly (ready to use)
pub fn minimal() -> EventContext {
    minimal_builder().build()
}

// ==========================================
// FULL CONTEXT
// ==========================================

/// Returns a builder configured for full context capture (customizable)
/// Uses all defaults (auto-capture enabled, security-relevant)
pub fn full_builder() -> ContextBuilder {
    ContextBuilder::new()
    // Everything enabled by default
}

/// Returns a full context directly (ready to use)
pub fn full() -> EventContext {
    full_builder().build()
}

// ==========================================
// SECURITY CONTEXT
// ==========================================

/// Returns a builder configured for security-relevant operations (customizable)
/// Combines: security-relevant + PII awareness
pub fn security_builder() -> ContextBuilder {
    ContextBuilder::new()
        .security_relevant(true)
        .with_pii_detected() // Assume it might contain PII
}

/// Returns a security context directly (ready to use)
pub fn security() -> EventContext {
    security_builder().build()
}

// ==========================================
// AUTHENTICATION CONTEXT
// ==========================================

/// Returns a builder configured for user authentication events (customizable)
/// Combines: user + operation + security-relevant
pub fn authentication_builder(user_id: impl AsRef<str>) -> ContextBuilder {
    ContextBuilder::new()
        .with_user(user_id)
        .with_operation("authentication")
        .security_relevant(true)
}

/// Returns an authentication context directly (ready to use)
pub fn authentication(user_id: impl AsRef<str>) -> EventContext {
    authentication_builder(user_id).build()
}

// ==========================================
// DATA ACCESS CONTEXT
// ==========================================

/// Returns a builder configured for data access events (customizable)
/// Combines: resource + operation + security-relevant
pub fn data_access_builder(
    resource_type: impl Into<String>,
    resource_id: impl Into<String>,
) -> ContextBuilder {
    ContextBuilder::new()
        .with_resource(resource_type, resource_id)
        .with_operation("data_access")
        .security_relevant(true)
}

/// Returns a data access context directly (ready to use)
pub fn data_access(
    resource_type: impl Into<String>,
    resource_id: impl Into<String>,
) -> EventContext {
    data_access_builder(resource_type, resource_id).build()
}

// ==========================================
// ANONYMOUS CONTEXT
// ==========================================

/// Returns a builder configured for anonymous context (customizable)
/// Combines: no auto-capture + cleared user info
pub fn anonymous_builder() -> ContextBuilder {
    ContextBuilder::new()
        .no_auto_capture()
        // Then explicitly clear user info
        .with_user("")
        .with_session("")
}

/// Returns an anonymous context directly (ready to use)
pub fn anonymous() -> EventContext {
    anonymous_builder().build()
}
