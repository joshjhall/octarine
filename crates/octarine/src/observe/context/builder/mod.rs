//! Context builder for configurable context capture
//!
//! Provides a builder pattern for constructing EventContext with custom settings.
//! This follows the three-layer pattern where the builder orchestrates but doesn't
//! implement business logic - it delegates to the core implementation modules.

use crate::observe::EventContext;
use crate::observe::types::{TenantId, UserId};
use uuid::Uuid;

// Domain-specific shortcuts module
mod tenant_shortcuts;

// Re-export domain-specific shortcuts (pub(in crate::observe) for internal observe module use)
pub(in crate::observe) mod shortcuts {
    // Tenant-specific shortcuts
    #[allow(unused_imports)]
    pub use super::tenant_shortcuts::*;

    // Could add other domain shortcuts here as they're created:
    // pub use super::capture_shortcuts::*;
    // pub use super::compliance_shortcuts::*;
    // pub use super::environment_shortcuts::*;
}

// Extension modules that add methods to ContextBuilder
mod capture;
mod compliance;
mod environment;
mod tenant;

/// Main context builder for constructing EventContext
#[derive(Debug, Clone)]
pub(in crate::observe) struct ContextBuilder {
    // Identity fields
    pub(super) tenant_id: Option<TenantId>,
    pub(super) user_id: Option<UserId>,
    pub(super) session_id: Option<String>,

    // Operation fields
    pub(super) operation: String,
    pub(super) resource_type: Option<String>,
    pub(super) resource_id: Option<String>,

    // Correlation
    pub(super) correlation_id: Option<Uuid>,
    pub(super) parent_span_id: Option<Uuid>,

    // Compliance flags
    pub(super) contains_pii: bool,
    pub(super) contains_phi: bool,
    pub(super) security_relevant: bool,

    // Control flags
    pub(super) auto_capture: bool,
    pub(super) include_environment: bool,
    pub(super) include_location: bool,
}

impl ContextBuilder {
    /// Create a new context builder with defaults
    pub fn new() -> Self {
        Self {
            tenant_id: None,
            user_id: None,
            session_id: None,
            operation: String::new(),
            resource_type: None,
            resource_id: None,
            correlation_id: None,
            parent_span_id: None,
            contains_pii: false,
            contains_phi: false,
            security_relevant: true, // Conservative default
            auto_capture: true,
            include_environment: true,
            include_location: true,
        }
    }

    /// Set tenant ID (validates immediately)
    ///
    /// Silently ignores invalid tenant IDs (lenient for builder pattern).
    /// For strict validation, use `TenantId::new()` directly.
    pub fn with_tenant(mut self, tenant_id: impl AsRef<str>) -> Self {
        self.tenant_id = TenantId::new(tenant_id).ok();
        self
    }

    /// Set user ID (validates immediately)
    ///
    /// Silently ignores invalid user IDs (lenient for builder pattern).
    /// For strict validation, use `UserId::new()` directly.
    pub fn with_user(mut self, user_id: impl AsRef<str>) -> Self {
        self.user_id = UserId::new(user_id).ok();
        self
    }

    /// Set session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set operation name
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = operation.into();
        self
    }

    /// Set resource being operated on
    pub fn with_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Set correlation ID for distributed tracing
    pub fn with_correlation_id(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Set parent span ID for distributed tracing
    pub fn with_parent_span(mut self, span_id: Uuid) -> Self {
        self.parent_span_id = Some(span_id);
        self
    }

    /// Mark as containing PII
    pub fn with_pii_detected(mut self) -> Self {
        self.contains_pii = true;
        self
    }

    /// Mark as containing PHI
    pub fn with_phi_detected(mut self) -> Self {
        self.contains_phi = true;
        self
    }

    /// Set security relevance
    pub fn security_relevant(mut self, relevant: bool) -> Self {
        self.security_relevant = relevant;
        self
    }

    /// Disable automatic context capture
    pub fn no_auto_capture(mut self) -> Self {
        self.auto_capture = false;
        self
    }

    /// Build the EventContext
    pub fn build(self) -> EventContext {
        // Delegate to build implementation
        super::build::build_context(super::build::ContextConfig {
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            session_id: self.session_id,
            operation: self.operation,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            correlation_id: self.correlation_id,
            parent_span_id: self.parent_span_id,
            contains_pii: self.contains_pii,
            contains_phi: self.contains_phi,
            security_relevant: self.security_relevant,
            auto_capture: self.auto_capture,
        })
    }
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}
