//! Tenant extensions for ContextBuilder
//!
//! Extends ContextBuilder with tenant-specific methods.
//! NO business logic here - only delegation to implementation.

use super::ContextBuilder;
use crate::observe::types::TenantId;

// Import ONLY the tenant functions we're delegating to
use super::super::tenant::get_current_tenant_id;

/// Extensions for ContextBuilder related to tenant context
impl ContextBuilder {
    /// Populate context with current tenant info from thread-local storage
    pub fn with_current_tenant(mut self) -> Self {
        // Delegate to tenant domain function
        if let Some(tenant_id) = get_current_tenant_id() {
            self.tenant_id = Some(tenant_id);
        }
        self
    }

    /// Set tenant with additional metadata (simplified - only ID used by EventContext)
    ///
    /// Silently ignores invalid tenant IDs (lenient for builder pattern).
    pub fn with_tenant_info(
        mut self,
        id: impl AsRef<str>,
        _name: impl Into<String>,
        _tier: impl Into<String>,
    ) -> Self {
        // EventContext only has tenant_id field, so only use id parameter
        // name and tier parameters kept for API compatibility
        self.tenant_id = TenantId::new(id).ok();
        self
    }
}
