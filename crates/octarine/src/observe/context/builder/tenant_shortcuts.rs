//! Tenant-specific shortcuts for context building
//!
//! These shortcuts provide pre-configured builders for tenant-related
//! context operations. They focus purely on tenant domain functionality.
//!
//! Follows DUAL FUNCTION pattern:
//! - `name_builder()` returns configured Builder
//! - `name()` returns built object

use super::ContextBuilder;
use crate::observe::EventContext;

// ==========================================
// TENANT-SPECIFIC SHORTCUTS
// ==========================================

/// Returns a builder configured for a specific tenant (customizable)
pub fn for_tenant_builder(tenant_id: impl AsRef<str>) -> ContextBuilder {
    ContextBuilder::new().with_tenant(tenant_id)
}

/// Returns a tenant context directly (ready to use)
pub fn for_tenant(tenant_id: impl AsRef<str>) -> EventContext {
    for_tenant_builder(tenant_id).build()
}

/// Returns a builder with tenant captured from environment (customizable)
pub fn with_current_tenant_builder() -> ContextBuilder {
    let builder = ContextBuilder::new();
    // Try to get tenant from environment or thread local
    if let Ok(tenant) = std::env::var("TENANT_ID") {
        builder.with_tenant(tenant)
    } else {
        builder
    }
}

/// Returns a context with current tenant captured (ready to use)
pub fn with_current_tenant() -> EventContext {
    with_current_tenant_builder().build()
}

/// Returns a builder for multi-tenant context (customizable)
pub fn multi_tenant_builder(primary_tenant: impl AsRef<str>) -> ContextBuilder {
    ContextBuilder::new().with_tenant(primary_tenant)
    // Could add metadata for secondary tenants if needed
}

/// Returns a multi-tenant context (ready to use)
pub fn multi_tenant(primary_tenant: impl AsRef<str>) -> EventContext {
    multi_tenant_builder(primary_tenant).build()
}
