//! Context capture implementation
//!
//! Automatically captures context from thread-local storage, task-local storage,
//! and environment variables (as fallback).
//!
//! ## Context Lookup Order
//!
//! For each field, the capture functions check in order:
//! 1. Task-local storage (for async code)
//! 2. Thread-local storage (for sync code)
//! 3. Environment variables (fallback for defaults)
//!
//! This allows context to be set via:
//! - `primitives::runtime::set_user_id()` for sync code
//! - `primitives::runtime::with_context().run()` for async code
//! - Environment variables for process-wide defaults
//!
//! ## Source IP Context
//!
//! For server applications, the source IP identifies the remote client:
//! - Set via `set_source_ip()` at request start
//! - Cleared via `clear_source_ip()` at request end
//! - Supports X-Forwarded-For chains for proxy scenarios

use super::environment::{get_environment, get_local_ip};
use super::tenant::get_tenant_context;
use crate::observe::EventContext;
use crate::observe::compliance::ComplianceTags;
use crate::observe::types::{TenantId, UserId};
use crate::primitives::runtime;
use once_cell::sync::Lazy;
use std::cell::RefCell;
use uuid::Uuid;

/// Cached context values from environment variables (captured once at startup)
///
/// These serve as fallback defaults when no thread-local or task-local
/// context is set. Useful for setting process-wide defaults.
struct CachedContext {
    default_tenant_id: Option<String>,
    default_user_id: Option<String>,
    default_session_id: Option<String>,
}

/// Global cached context (captured once at startup to avoid repeated env var lookups)
static CACHED_CONTEXT: Lazy<CachedContext> = Lazy::new(|| CachedContext {
    default_tenant_id: std::env::var("TENANT_ID").ok(),
    default_user_id: std::env::var("USER_ID").ok(),
    default_session_id: std::env::var("SESSION_ID").ok(),
});

/// Capture current context automatically
///
/// Internal function for use within the observe module only.
///
/// Checks thread-local and task-local storage first, then falls back
/// to environment variables for any missing values.
pub(in crate::observe) fn capture_context() -> EventContext {
    // Get environment context (static) - TODO: use this when EventContext includes environment
    let _env = get_environment();

    // Get tenant context from observe module's thread-local (for TenantContext struct)
    let tenant = get_tenant_context();

    EventContext {
        // Identity (from task-local/thread-local, fallback to cached env vars)
        tenant_id: tenant
            .as_ref()
            .map(|t| t.tenant_id.clone())
            .or_else(capture_tenant_id),
        user_id: capture_user_id(),
        session_id: capture_session_id(),

        // Operation (will be set by caller)
        operation: String::new(),
        resource_type: None,
        resource_id: None,

        // Location - code (will be set by macro)
        module_path: String::new(),
        file: String::new(),
        line: 0,

        // Location - network
        local_ip: get_local_ip(),
        source_ip: capture_source_ip(),
        source_ip_chain: capture_source_ip_chain(),

        // Correlation
        correlation_id: capture_correlation_id(),
        parent_span_id: None,

        // Compliance flags (conservative defaults)
        contains_pii: false,
        contains_phi: false,
        security_relevant: true,
        pii_types: Vec::new(), // Will be populated by EventBuilder if PII is detected
        compliance: ComplianceTags::default(),
    }
}

/// Get current tenant ID from context
///
/// Checks in order:
/// 1. Task-local storage (for async code)
/// 2. Thread-local storage (for sync code)
/// 3. Environment variable `TENANT_ID` (fallback)
pub(super) fn capture_tenant_id() -> Option<TenantId> {
    // Check primitives runtime context first (task-local then thread-local)
    if let Some(tenant_str) = runtime::tenant_id()
        && let Ok(tenant_id) = TenantId::new(&tenant_str)
    {
        return Some(tenant_id);
    }

    // Fallback to cached env var value
    CACHED_CONTEXT
        .default_tenant_id
        .as_ref()
        .and_then(|id| TenantId::new(id).ok())
}

/// Get current user ID from context
///
/// Checks in order:
/// 1. Task-local storage (for async code)
/// 2. Thread-local storage (for sync code)
/// 3. Environment variable `USER_ID` (fallback)
pub(super) fn capture_user_id() -> Option<UserId> {
    // Check primitives runtime context first (task-local then thread-local)
    if let Some(user_str) = runtime::user_id()
        && let Ok(user_id) = UserId::new(&user_str)
    {
        return Some(user_id);
    }

    // Fallback to cached env var value
    CACHED_CONTEXT
        .default_user_id
        .as_ref()
        .and_then(|id| UserId::new(id).ok())
}

/// Get current session ID from context
///
/// Checks in order:
/// 1. Task-local storage (for async code)
/// 2. Thread-local storage (for sync code)
/// 3. Environment variable `SESSION_ID` (fallback)
pub(super) fn capture_session_id() -> Option<String> {
    // Check primitives runtime context first (task-local then thread-local)
    if let Some(session) = runtime::session_id() {
        return Some(session);
    }

    // Fallback to cached env var value
    CACHED_CONTEXT.default_session_id.clone()
}

/// Get or create correlation ID for request tracing
///
/// Uses `primitives::runtime::correlation_id()` which checks:
/// 1. Task-local storage (for async code)
/// 2. Thread-local storage (for sync code)
/// 3. Generates a new UUID as fallback
pub(super) fn capture_correlation_id() -> Uuid {
    runtime::correlation_id()
}

// ============================================================================
// Source IP Context (thread-local for request handling)
// ============================================================================

/// Thread-local source IP context
///
/// Stores the source IP and optional X-Forwarded-For chain for the current request.
#[derive(Debug, Clone, Default)]
struct SourceIpContext {
    /// Primary source IP (closest to server, or original if no proxies)
    source_ip: Option<String>,
    /// Full X-Forwarded-For chain (original client first, then proxies)
    ip_chain: Vec<String>,
}

thread_local! {
    static SOURCE_IP_CONTEXT: RefCell<SourceIpContext> = RefCell::new(SourceIpContext::default());
}

/// Capture the current source IP from thread-local storage
pub(super) fn capture_source_ip() -> Option<String> {
    SOURCE_IP_CONTEXT.with(|ctx| ctx.borrow().source_ip.clone())
}

/// Capture the current source IP chain from thread-local storage
pub(super) fn capture_source_ip_chain() -> Vec<String> {
    SOURCE_IP_CONTEXT.with(|ctx| ctx.borrow().ip_chain.clone())
}

/// Get the current source IP for the thread
///
/// Returns the source IP set via `set_source_ip` or `set_source_ip_chain`.
///
/// # Example
///
/// ```ignore
/// use octarine::{set_source_ip, get_source_ip};
///
/// set_source_ip("192.168.1.100");
/// assert_eq!(get_source_ip(), Some("192.168.1.100".to_string()));
/// ```
pub fn get_source_ip() -> Option<String> {
    capture_source_ip()
}

/// Get the current source IP chain for the thread
///
/// Returns the full X-Forwarded-For chain set via `set_source_ip_chain`.
/// Returns an empty vector if no chain was set.
///
/// # Example
///
/// ```ignore
/// use octarine::{set_source_ip_chain, get_source_ip_chain};
///
/// set_source_ip_chain(vec!["10.0.0.1".to_string(), "192.168.1.100".to_string()]);
/// let chain = get_source_ip_chain();
/// assert_eq!(chain.len(), 2);
/// ```
pub fn get_source_ip_chain() -> Vec<String> {
    capture_source_ip_chain()
}

/// Set the source IP for the current thread
///
/// Call this at the start of request handling to track the client IP.
///
/// # Example
///
/// ```ignore
/// use octarine::set_source_ip;
///
/// // In your HTTP middleware:
/// fn handle_request(req: &Request) {
///     if let Some(ip) = req.peer_addr() {
///         set_source_ip(ip.to_string());
///     }
///     // ... handle request
///     clear_source_ip();
/// }
/// ```
pub fn set_source_ip(ip: impl Into<String>) {
    let ip = ip.into();
    SOURCE_IP_CONTEXT.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.source_ip = Some(ip);
    });
}

/// Set the source IP chain from X-Forwarded-For header
///
/// The chain should be in order: original client first, then each proxy.
/// The last IP in the chain is typically the one directly connected to your server.
///
/// # Example
///
/// ```ignore
/// use octarine::set_source_ip_chain;
///
/// // Parse X-Forwarded-For: client, proxy1, proxy2
/// let chain: Vec<String> = x_forwarded_for
///     .split(',')
///     .map(|s| s.trim().to_string())
///     .collect();
///
/// set_source_ip_chain(chain);
/// ```
pub fn set_source_ip_chain(chain: Vec<String>) {
    SOURCE_IP_CONTEXT.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        // The source_ip is the last in the chain (closest to server)
        // or the first if you trust the proxy chain
        ctx.source_ip = chain.last().cloned();
        ctx.ip_chain = chain;
    });
}

/// Clear the source IP context for the current thread
///
/// Call this at the end of request handling.
pub fn clear_source_ip() {
    SOURCE_IP_CONTEXT.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.source_ip = None;
        ctx.ip_chain.clear();
    });
}

/// Execute a function with source IP context
///
/// Automatically clears the source IP after the function completes.
///
/// # Example
///
/// ```ignore
/// use octarine::with_source_ip;
///
/// with_source_ip("192.168.1.100", || {
///     // All events in here will have source_ip set
///     handle_request();
/// });
/// // Source IP is automatically cleared
/// ```
pub fn with_source_ip<F, R>(ip: impl Into<String>, f: F) -> R
where
    F: FnOnce() -> R,
{
    set_source_ip(ip);
    let result = f();
    clear_source_ip();
    result
}

/// Macro to capture file location context
#[macro_export]
macro_rules! capture_location {
    () => {{
        let mut ctx = $crate::observe::context::capture_context();
        ctx.module_path = module_path!().to_string();
        ctx.file = file!().to_string();
        ctx.line = line!();
        ctx
    }};
}
