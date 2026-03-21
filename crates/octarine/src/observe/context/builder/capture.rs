//! Capture extensions for ContextBuilder
//!
//! Extends ContextBuilder with capture-specific methods.
//! NO business logic here - only delegation to implementation.

use super::ContextBuilder;

// Import the specific functions we're delegating to from the core implementation
use super::super::capture::{
    capture_correlation_id, capture_session_id, capture_tenant_id, capture_user_id,
};

/// Extensions for ContextBuilder related to automatic capture
impl ContextBuilder {
    /// Populate context with auto-captured tenant ID
    pub fn with_auto_tenant(mut self) -> Self {
        if let Some(tenant_id) = capture_tenant_id() {
            self.tenant_id = Some(tenant_id);
        }
        self
    }

    /// Populate context with auto-captured user ID
    pub fn with_auto_user(mut self) -> Self {
        if let Some(user_id) = capture_user_id() {
            self.user_id = Some(user_id);
        }
        self
    }

    /// Populate context with auto-captured session ID
    pub fn with_auto_session(mut self) -> Self {
        if let Some(session_id) = capture_session_id() {
            self.session_id = Some(session_id);
        }
        self
    }

    /// Populate context with auto-captured correlation ID
    pub fn with_auto_correlation(mut self) -> Self {
        self.correlation_id = Some(capture_correlation_id());
        self
    }

    /// Populate all auto-captured fields
    pub fn with_auto_capture_all(self) -> Self {
        self.with_auto_tenant()
            .with_auto_user()
            .with_auto_session()
            .with_auto_correlation()
    }
}
