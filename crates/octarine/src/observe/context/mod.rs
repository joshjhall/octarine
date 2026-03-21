//! Automatic context capture for audit events
//!
//! This module handles automatic extraction of context information
//! like user identity, tenant, correlation IDs, etc.
//!
//! # Three-Layer Architecture
//!
//! - **Core**: Internal implementation (capture, tenant, environment, compliance)
//! - **Builder**: Configurable context building (future enhancement)
//! - **Functions**: Simple API for common operations

// Core implementation modules (internal only)
mod build;
pub(super) mod capture;
mod compliance;
mod environment;
mod tenant;

// Builder pattern for configurable context operations
mod builder;

// Builder exports - these are the main way to work with context
// Internal to observe module only
#[allow(unused_imports)]
pub(super) use builder::ContextBuilder;

// Export shortcuts at the appropriate level
// Use the shortcuts module in this directory for cross-domain shortcuts
pub(super) mod shortcuts;
// Domain-specific shortcuts are in builder/shortcuts
#[allow(unused_imports)]
pub(super) use builder::shortcuts as domain_shortcuts;

// Public exports - carefully selected for external use
// These are the only parts of context that should be exposed outside observe

/// Check if running in development environment
pub use environment::is_development;

/// Check if running in production environment
pub use environment::is_production;

/// Tenant context for multi-tenant applications
pub use tenant::TenantContext;

// Simple function API for external use

/// Set the tenant context for the current thread
///
/// This sets both the rich `TenantContext` AND syncs the tenant ID
/// to the runtime layer for task correlation.
///
/// # Example
/// ```ignore
/// use octarine::{tenant_set, TenantContext};
///
/// tenant_set(TenantContext {
///     tenant_id: "acme-corp".to_string(),
///     tenant_name: Some("ACME Corporation".to_string()),
///     tenant_tier: Some("enterprise".to_string()),
/// });
/// ```
pub fn set_tenant(ctx: TenantContext) {
    tenant::set_tenant_context(ctx);
}

/// Get the current tenant context (rich metadata)
///
/// Returns the full `TenantContext` if set via `tenant_set()`.
/// Returns `None` if only the simple tenant ID was set via `TaskContextBuilder`.
///
/// For just the tenant ID string, use `tenant_id()` instead.
///
/// # Example
/// ```ignore
/// use octarine::tenant_get;
///
/// if let Some(ctx) = tenant_get() {
///     println!("Tenant: {} ({})", ctx.tenant_id, ctx.tenant_tier.unwrap_or_default());
/// }
/// ```
pub fn get_tenant() -> Option<TenantContext> {
    tenant::get_tenant_context()
}

/// Get the current tenant ID from any source
///
/// This is the unified way to get the current tenant ID. It checks:
/// 1. Rich `TenantContext` (set via `tenant_set()`)
/// 2. Runtime task/thread context (set via `TaskContextBuilder`)
///
/// # Example
/// ```ignore
/// use octarine::tenant_id;
///
/// if let Some(id) = tenant_id() {
///     println!("Current tenant: {}", id);
/// }
/// ```
pub fn tenant_id() -> Option<String> {
    tenant::get_tenant_id()
}

/// Execute a function with a specific tenant context
///
/// The tenant context is automatically cleared after the function executes.
///
/// # Example
/// ```ignore
/// use octarine::{tenant_with, TenantContext};
///
/// let result = tenant_with(tenant_ctx, || {
///     // Code that runs with the tenant context
///     process_tenant_data()
/// });
/// ```
pub fn with_tenant<F, R>(ctx: TenantContext, f: F) -> R
where
    F: FnOnce() -> R,
{
    tenant::with_tenant_context(ctx, f)
}

/// Clear the current tenant context
///
/// Clears both the rich context AND the runtime tenant ID.
/// Use this when switching contexts or cleaning up.
pub fn clear_tenant() {
    tenant::clear_tenant_context();
}

// ============================================================================
// Source IP Context API
// ============================================================================

/// Set the source IP for the current request/thread
///
/// Call this at the start of request handling to track the client IP.
/// All events created in this thread will include this source IP.
///
/// # Example
/// ```ignore
/// use octarine::context::set_source_ip;
///
/// // In your HTTP middleware:
/// if let Some(ip) = request.peer_addr() {
///     set_source_ip(ip.to_string());
/// }
/// ```
pub use capture::set_source_ip;

/// Get the current source IP for the thread
///
/// Returns the source IP set via `set_source_ip` or `set_source_ip_chain`.
pub use capture::get_source_ip;

/// Set the source IP chain from X-Forwarded-For header
///
/// Use this when behind proxies/load balancers to track the full IP chain.
pub use capture::set_source_ip_chain;

/// Get the current source IP chain for the thread
///
/// Returns the full X-Forwarded-For chain set via `set_source_ip_chain`.
pub use capture::get_source_ip_chain;

/// Clear the source IP for the current thread
///
/// Call this at the end of request handling.
pub use capture::clear_source_ip;

/// Execute a function with source IP context
///
/// Automatically clears the source IP after the function completes.
pub use capture::with_source_ip;

// ============================================================================
// Local Network Context API
// ============================================================================

/// Get the current local network context (all interfaces and IPs)
///
/// This is TTL-cached (5 minutes) to handle DHCP changes.
pub use environment::get_local_network;

/// Force refresh the local network context
///
/// Call this after a known network change (e.g., VPN connect/disconnect).
pub use environment::refresh_local_network;

/// Local network context with all interfaces and IP addresses
pub use environment::LocalNetworkContext;
