//! Multi-tenant context management
//!
//! Provides unified tenant context across observe and runtime layers.
//!
//! # Architecture
//!
//! This module bridges two tenant concepts:
//! - **Rich context** (`TenantContext`): Full tenant metadata for audit/compliance
//! - **Simple ID** (from `primitives::runtime`): String ID for task correlation
//!
//! When you set a `TenantContext`, both are updated. When you read `tenant_id()`,
//! it checks the rich context first, then falls back to the runtime task context.

use crate::observe::types::TenantId;
use crate::primitives::runtime as prim_runtime;
use std::cell::RefCell;

thread_local! {
    static TENANT_CONTEXT: RefCell<Option<TenantContext>> = const { RefCell::new(None) };
}

/// Tenant context information
///
/// Rich tenant metadata for compliance and audit logging.
/// Use this when you need more than just the tenant ID.
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Unique tenant identifier
    pub tenant_id: TenantId,
    /// Human-readable tenant name
    pub tenant_name: Option<String>,
    /// Tenant tier (free, pro, enterprise)
    pub tenant_tier: Option<String>,
}

/// Set tenant context for current thread
///
/// This sets both the rich `TenantContext` AND the simple tenant ID
/// in the runtime layer, keeping them in sync.
///
/// Internal function - external users should use the module-level `set_tenant` function.
pub(super) fn set_tenant_context(ctx: TenantContext) {
    // Sync the tenant ID to runtime layer for task correlation
    // TenantId implements AsRef<str>, so we convert to String
    prim_runtime::set_tenant_id(ctx.tenant_id.as_ref());

    // Store the rich context
    TENANT_CONTEXT.with(|c| {
        *c.borrow_mut() = Some(ctx);
    });
}

/// Get current tenant context (rich metadata)
///
/// Returns the full `TenantContext` if set via `set_tenant()`.
/// Returns `None` if only the simple tenant ID was set via `TaskContextBuilder`.
///
/// Internal function for use within the observe module.
pub(super) fn get_tenant_context() -> Option<TenantContext> {
    TENANT_CONTEXT.with(|c| c.borrow().clone())
}

/// Clear tenant context
///
/// Clears both the rich context AND the runtime tenant ID.
///
/// Internal function - external users should use the module-level `clear_tenant` function.
pub(super) fn clear_tenant_context() {
    // Clear runtime layer
    prim_runtime::clear_tenant_id();

    // Clear rich context
    TENANT_CONTEXT.with(|c| {
        *c.borrow_mut() = None;
    });
}

/// Run code with specific tenant context
///
/// Internal function - external users should use the module-level `with_tenant` function.
pub(super) fn with_tenant_context<F, R>(ctx: TenantContext, f: F) -> R
where
    F: FnOnce() -> R,
{
    set_tenant_context(ctx);
    let result = f();
    clear_tenant_context();
    result
}

/// Get current tenant ID from any source
///
/// Checks in order:
/// 1. Rich `TenantContext` (set via `set_tenant()`)
/// 2. Runtime task/thread context (set via `TaskContextBuilder`)
///
/// This is the unified way to get the current tenant ID regardless of how it was set.
/// Returns a plain `String` for maximum compatibility.
pub(super) fn get_tenant_id() -> Option<String> {
    // First check rich context
    if let Some(ctx) = get_tenant_context() {
        return Some(ctx.tenant_id.to_string());
    }

    // Fall back to runtime context (task-local or thread-local)
    prim_runtime::tenant_id()
}

/// Get tenant ID from current context (for builder)
///
/// Returns the tenant ID as a `TenantId` type if available.
/// This is for internal observe use where validated types are needed.
pub(super) fn get_current_tenant_id() -> Option<TenantId> {
    // First check rich context (already validated)
    if let Some(ctx) = get_tenant_context() {
        return Some(ctx.tenant_id);
    }

    // For runtime context, we'd need to re-validate - skip for now
    // since this is only called from internal builders that will validate anyway
    None
}
