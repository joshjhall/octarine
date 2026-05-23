//! Runtime primitives for async operations
//!
//! Pure async utilities with no observe dependencies. These provide the core
//! functionality that is wrapped by the public `runtime` module with observability.
//!
//! ## Module Structure
//!
//! - `async/` - Async runtime primitives (channels, backoff, circuit breaker, etc.)
//! - `rate_limiter/` - Rate limiting primitives (token bucket, GCRA algorithm)
//!
//! ## Features
//!
//! - **Async Utilities**: Sleep, interval, yield for async operations
//! - **Rate Limiting**: Keyed rate limiting with GCRA algorithm
//! - **Blocking Operations**: Run blocking I/O with context propagation
//! - **Configuration**: Runtime configuration types and builders
//! - **Context**: Task-local and thread-local context storage
//! - **Backoff**: Retry strategies and backoff algorithms
//! - **Circuit Breaker**: Circuit breaker configuration and state
//! - **Channel**: Channel statistics and health monitoring
//!
//! ## Architecture Note
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The public `runtime` module wraps these primitives and adds
//! logging, metrics, and event dispatching.
//!
//! ## Context API
//!
//! The context API provides correlation ID and identity propagation for both
//! sync and async code:
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::{
//!     correlation_id, set_correlation_id, with_correlation_id,
//!     tenant_id, set_tenant_id,
//! };
//!
//! // Sync code: set thread-local context
//! set_correlation_id(uuid);
//! set_tenant_id("acme-corp");
//!
//! // Get current correlation ID (checks task-local, then thread-local, then generates new)
//! let id = correlation_id();
//!
//! // Async code: run with specific correlation ID
//! with_correlation_id(uuid, async {
//!     // All code here sees the same correlation_id
//!     do_something().await;
//! }).await;
//! ```
//!
//! ## Async Utilities
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::{sleep_ms, interval};
//! use std::time::Duration;
//!
//! async {
//!     sleep_ms(100).await;
//!     let mut timer = interval(Duration::from_secs(1));
//!     timer.tick().await;
//! };
//! ```

use uuid::Uuid;

// Async runtime submodule - uses path attribute because "async" is a reserved keyword
// Exposed as pub(crate) to mirror public API: octarine::runtime::r#async::*
#[path = "async/mod.rs"]
pub(crate) mod r#async;

// Rate limiting primitives
// Exposed as pub(crate) for Layer 2 (observe) and Layer 3 (runtime)
pub(crate) mod rate_limiter;

// HTTP client primitives
// Exposed as pub(crate) for Layer 2 (observe) and Layer 3 (runtime)
pub(crate) mod http;

// Context types and internal functions for shortcut functions below
use r#async::{
    TaskContext, TaskLocal, clear_thread_context, clear_thread_correlation_id,
    clear_thread_session_id, clear_thread_tenant_id, clear_thread_user_id,
    get_thread_correlation_fallback, get_thread_correlation_id, get_thread_session_id,
    get_thread_tenant_id, get_thread_user_id, set_thread_correlation_fallback,
    set_thread_correlation_id, set_thread_session_id, set_thread_tenant_id, set_thread_user_id,
};

// =============================================================================
// Context Shortcut Functions (Public API)
// =============================================================================
//
// These functions provide a clean API for context management without exposing
// internal types like TaskLocal or TaskContext directly.

/// Get the current correlation ID
///
/// Checks in order:
/// 1. Task-local storage (for async code)
/// 2. Thread-local storage (for sync code, explicitly set)
/// 3. Thread-local fallback cache (auto-generated, populated on first miss)
/// 4. Generates a new UUID, stores it in the fallback cache, and returns it
///
/// # Performance
///
/// This function is O(1) for the common cases (task-local hit, thread-local
/// hit, fallback cache hit). The first call on a thread with no explicit
/// context setup generates one UUID and caches it; every subsequent call on
/// the same thread is then a thread-local read.
///
/// # Semantic Continuity
///
/// Because the fallback path caches its generated UUID per-thread, multiple
/// events emitted from the same thread without explicit context setup share
/// a correlation ID. This gives implicit trace continuity to code that
/// hasn't wired up an HTTP middleware or `TaskContextBuilder` scope. To
/// reset the implicit ID (for example between logical operations on a
/// long-lived worker thread) call `clear_correlation_id()`.
///
/// The fallback cache is intentionally invisible to `try_correlation_id()`
/// so callers can still distinguish "explicitly configured" from
/// "auto-generated" — useful for HTTP error responses that should only
/// include a request ID when one was actually set via middleware.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::correlation_id;
///
/// let id = correlation_id();
/// println!("Current correlation: {}", id);
/// ```
pub fn correlation_id() -> Uuid {
    // First, try task-local (for async code)
    if let Some(ctx) = TaskLocal::try_get() {
        return ctx.correlation_id;
    }

    // Second, try thread-local — explicitly set via set_correlation_id().
    if let Some(id) = get_thread_correlation_id() {
        return id;
    }

    // Third, try the per-thread fallback cache. This is populated by a
    // previous call to correlation_id() on this thread and gives semantic
    // continuity to events emitted without explicit context setup.
    if let Some(id) = get_thread_correlation_fallback() {
        return id;
    }

    // Fourth, generate a new UUID and seed the fallback cache so subsequent
    // calls on this thread return the same ID. Avoids repeated UUID
    // generation in the common "no context configured" case.
    let id = Uuid::new_v4();
    set_thread_correlation_fallback(id);
    id
}

/// Get the current correlation ID if one is set
///
/// Unlike `correlation_id()`, this returns `None` if no context is set
/// rather than generating a new UUID. It also does NOT observe the
/// per-thread fallback cache, so it is the right choice when you need to
/// know whether the caller explicitly configured a correlation ID (for
/// example, an HTTP error handler that should only include a request ID
/// when middleware has set one).
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::try_correlation_id;
///
/// if let Some(id) = try_correlation_id() {
///     println!("Has correlation: {}", id);
/// } else {
///     println!("No correlation ID set");
/// }
/// ```
pub fn try_correlation_id() -> Option<Uuid> {
    // First, try task-local (for async code)
    if let Some(ctx) = TaskLocal::try_get() {
        return Some(ctx.correlation_id);
    }

    // Second, try thread-local (for sync code)
    get_thread_correlation_id()
}

/// Set the correlation ID for the current thread (sync code)
///
/// This sets thread-local storage which is checked by `correlation_id()`.
/// For async code, use `with_correlation_id()` instead.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::{set_correlation_id, correlation_id};
/// use uuid::Uuid;
///
/// let id = Uuid::new_v4();
/// set_correlation_id(id);
/// assert_eq!(correlation_id(), id);
/// ```
pub fn set_correlation_id(id: Uuid) {
    set_thread_correlation_id(id);
}

/// Clear the thread-local correlation ID
///
/// After calling this, `correlation_id()` will fall back to generating
/// a new UUID (unless task-local context is set).
pub fn clear_correlation_id() {
    clear_thread_correlation_id();
}

/// Run a synchronous function with a specific correlation ID
///
/// The correlation ID is set before the function runs and cleared after.
/// This is useful for scoping correlation IDs in sync code.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::{with_sync_correlation_id, correlation_id};
/// use uuid::Uuid;
///
/// let id = Uuid::new_v4();
/// with_sync_correlation_id(id, || {
///     assert_eq!(correlation_id(), id);
///     // Do work here
/// });
/// ```
pub fn with_sync_correlation_id<F, R>(id: Uuid, f: F) -> R
where
    F: FnOnce() -> R,
{
    set_correlation_id(id);
    let result = f();
    clear_correlation_id();
    result
}

/// Run an async future with a specific correlation ID
///
/// The correlation ID is available throughout the async execution,
/// including across await points.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::{with_correlation_id, correlation_id};
/// use uuid::Uuid;
///
/// #[tokio::main]
/// async fn main() {
///     let id = Uuid::new_v4();
///     with_correlation_id(id, async {
///         assert_eq!(correlation_id(), id);
///         some_async_work().await;
///         assert_eq!(correlation_id(), id); // Still the same!
///     }).await;
/// }
/// ```
pub async fn with_correlation_id<F, R>(id: Uuid, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let ctx = TaskContext::with_correlation_id(id);
    TaskLocal::scope(ctx, f).await
}

/// Get the current tenant ID if set
///
/// Checks task-local first, then thread-local.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::tenant_id;
///
/// if let Some(tenant) = tenant_id() {
///     println!("Current tenant: {}", tenant);
/// }
/// ```
pub fn tenant_id() -> Option<String> {
    // First, try task-local (for async code)
    if let Some(ctx) = TaskLocal::try_get()
        && ctx.tenant_id.is_some()
    {
        return ctx.tenant_id;
    }

    // Second, try thread-local (for sync code)
    get_thread_tenant_id()
}

/// Set the tenant ID for the current thread (sync code)
///
/// For async code, use the full context API with `with_context()`.
pub fn set_tenant_id(id: impl Into<String>) {
    set_thread_tenant_id(id.into());
}

/// Clear the thread-local tenant ID
pub fn clear_tenant_id() {
    clear_thread_tenant_id();
}

/// Get the current user ID if set
///
/// Checks task-local first, then thread-local.
pub fn user_id() -> Option<String> {
    // First, try task-local (for async code)
    if let Some(ctx) = TaskLocal::try_get()
        && ctx.user_id.is_some()
    {
        return ctx.user_id;
    }

    // Second, try thread-local (for sync code)
    get_thread_user_id()
}

/// Set the user ID for the current thread (sync code)
pub fn set_user_id(id: impl Into<String>) {
    set_thread_user_id(id.into());
}

/// Clear the thread-local user ID
pub fn clear_user_id() {
    clear_thread_user_id();
}

/// Get the current session ID if set
///
/// Checks task-local first, then thread-local.
pub fn session_id() -> Option<String> {
    // First, try task-local (for async code)
    if let Some(ctx) = TaskLocal::try_get()
        && ctx.session_id.is_some()
    {
        return ctx.session_id;
    }

    // Second, try thread-local (for sync code)
    get_thread_session_id()
}

/// Set the session ID for the current thread (sync code)
pub fn set_session_id(id: impl Into<String>) {
    set_thread_session_id(id.into());
}

/// Clear the thread-local session ID
pub fn clear_session_id() {
    clear_thread_session_id();
}

/// Clear all thread-local context
///
/// Clears correlation ID, tenant ID, user ID, and session ID.
pub fn clear_context() {
    clear_thread_context();
}

/// Builder for running code with full context
#[derive(Debug)]
pub struct TaskContextBuilder {
    ctx: TaskContext,
}

impl TaskContextBuilder {
    /// Create a new task context builder
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use octarine::runtime::r#async::TaskContextBuilder;
    /// use uuid::Uuid;
    ///
    /// # async fn example() {
    /// TaskContextBuilder::new()
    ///     .correlation_id(Uuid::new_v4())
    ///     .tenant("acme-corp")
    ///     .user("user-123")
    ///     .run(async {
    ///         // Context is available here
    ///     }).await;
    /// # }
    /// ```
    pub fn new() -> Self {
        Self {
            ctx: TaskContext::new(),
        }
    }

    /// Set the correlation ID
    pub fn correlation_id(mut self, id: Uuid) -> Self {
        self.ctx = TaskContext::with_correlation_id(id);
        self
    }

    /// Set the tenant ID
    pub fn tenant(mut self, id: impl Into<String>) -> Self {
        self.ctx = self.ctx.with_tenant(id);
        self
    }

    /// Set the user ID
    pub fn user(mut self, id: impl Into<String>) -> Self {
        self.ctx = self.ctx.with_user(id);
        self
    }

    /// Set the session ID
    pub fn session(mut self, id: impl Into<String>) -> Self {
        self.ctx = self.ctx.with_session(id);
        self
    }

    /// Set the environment
    pub fn environment(mut self, env: impl Into<String>) -> Self {
        self.ctx = self.ctx.with_environment(env);
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.ctx = self.ctx.with_metadata(key, value);
        self
    }

    /// Run an async future with this context
    pub async fn run<F, R>(self, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        TaskLocal::scope(self.ctx, f).await
    }

    /// Run a sync function with this context (thread-local)
    pub fn run_sync<F, R>(self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Set thread-local context
        set_thread_correlation_id(self.ctx.correlation_id);
        if let Some(ref tenant) = self.ctx.tenant_id {
            set_thread_tenant_id(tenant.clone());
        }
        if let Some(ref user) = self.ctx.user_id {
            set_thread_user_id(user.clone());
        }
        if let Some(ref session) = self.ctx.session_id {
            set_thread_session_id(session.clone());
        }

        let result = f();

        // Clear thread-local context
        clear_thread_context();

        result
    }
}

impl Default for TaskContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests for Shortcut Functions
// =============================================================================

#[cfg(test)]
mod shortcut_tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_thread_local_correlation_id() {
        // Clear any existing context
        clear_correlation_id();

        // Calling correlation_id() seeds thread-local with a generated UUID.
        // After clear_correlation_id(), the next call generates a fresh one.
        let _id1 = correlation_id();
        clear_correlation_id();
        let _id2 = correlation_id();

        // Set a specific ID
        let specific_id = Uuid::new_v4();
        set_correlation_id(specific_id);
        assert_eq!(correlation_id(), specific_id);

        // Clear and verify fallback behavior
        clear_correlation_id();
        assert!(try_correlation_id().is_none());
    }

    #[test]
    fn test_correlation_id_fallback_is_cached() {
        // Without explicit setup, two consecutive calls on the same thread
        // must return the SAME UUID. The first call seeds thread-local;
        // the second is a thread-local hit.
        clear_correlation_id();

        let id_first = correlation_id();
        let id_second = correlation_id();

        assert_eq!(
            id_first, id_second,
            "fallback path must cache via thread-local"
        );

        // clear_correlation_id() resets the cache; next call generates a
        // fresh ID, distinct from the previously cached one.
        clear_correlation_id();
        let id_after_clear = correlation_id();
        assert_ne!(
            id_first, id_after_clear,
            "clear_correlation_id() must reset the fallback cache"
        );

        clear_correlation_id();
    }

    #[test]
    fn test_correlation_id_fallback_seeds_try_get() {
        // The per-thread fallback cache MUST be invisible to
        // try_correlation_id() so callers can distinguish "explicitly
        // configured" from "auto-generated". This is the contract that
        // lets HTTP error handlers (http/error.rs) decide whether to
        // include a request_id in the response body.
        clear_correlation_id();

        assert!(try_correlation_id().is_none());

        // Take the fallback path — caches generated ID, but does NOT
        // populate the explicit thread-local slot.
        let _generated = correlation_id();
        assert!(
            try_correlation_id().is_none(),
            "fallback cache must NOT make try_correlation_id() return Some"
        );

        clear_correlation_id();
    }

    #[test]
    fn test_correlation_id_fast_path_unchanged() {
        // When thread-local IS explicitly set, correlation_id() must still
        // return it directly without re-seeding or generating.
        clear_correlation_id();

        let explicit = Uuid::new_v4();
        set_correlation_id(explicit);

        assert_eq!(correlation_id(), explicit);
        assert_eq!(correlation_id(), explicit); // stable across calls
        assert_eq!(try_correlation_id(), Some(explicit));

        clear_correlation_id();
    }

    #[tokio::test]
    async fn test_task_local_still_takes_precedence_after_fallback_seed() {
        // Seeding thread-local via the fallback path must NOT affect
        // task-local precedence. Inside with_correlation_id() the task-local
        // value wins; outside the scope the seeded thread-local value is
        // still visible.
        clear_correlation_id();

        let seeded = correlation_id();
        let task_id = Uuid::new_v4();
        assert_ne!(seeded, task_id);

        with_correlation_id(task_id, async {
            assert_eq!(correlation_id(), task_id);
        })
        .await;

        // Back out of the task scope, the seeded thread-local value persists.
        assert_eq!(correlation_id(), seeded);

        clear_correlation_id();
    }

    #[test]
    fn test_thread_local_tenant_id() {
        clear_tenant_id();

        // Initially none
        assert!(tenant_id().is_none());

        // Set and get
        set_tenant_id("acme-corp");
        assert_eq!(tenant_id(), Some("acme-corp".to_string()));

        // Clear
        clear_tenant_id();
        assert!(tenant_id().is_none());
    }

    #[test]
    fn test_thread_local_user_id() {
        clear_user_id();

        assert!(user_id().is_none());
        set_user_id("user-123");
        assert_eq!(user_id(), Some("user-123".to_string()));
        clear_user_id();
        assert!(user_id().is_none());
    }

    #[test]
    fn test_thread_local_session_id() {
        clear_session_id();

        assert!(session_id().is_none());
        set_session_id("sess-456");
        assert_eq!(session_id(), Some("sess-456".to_string()));
        clear_session_id();
        assert!(session_id().is_none());
    }

    #[test]
    fn test_with_sync_correlation_id() {
        clear_correlation_id();

        let id = Uuid::new_v4();
        let result = with_sync_correlation_id(id, || {
            assert_eq!(correlation_id(), id);
            "done"
        });

        assert_eq!(result, "done");
        // After scope, should be cleared
        assert!(try_correlation_id().is_none());
    }

    #[test]
    fn test_clear_context() {
        // Set all context values
        set_correlation_id(Uuid::new_v4());
        set_tenant_id("tenant");
        set_user_id("user");
        set_session_id("session");

        // Clear all
        clear_context();

        // All should be none
        assert!(try_correlation_id().is_none());
        assert!(tenant_id().is_none());
        assert!(user_id().is_none());
        assert!(session_id().is_none());
    }

    #[tokio::test]
    async fn test_async_correlation_id() {
        let id = Uuid::new_v4();

        with_correlation_id(id, async {
            assert_eq!(correlation_id(), id);
            assert_eq!(try_correlation_id(), Some(id));
        })
        .await;
    }

    #[tokio::test]
    async fn test_context_builder_async() {
        let id = Uuid::new_v4();

        TaskContextBuilder::new()
            .correlation_id(id)
            .tenant("test-tenant")
            .user("test-user")
            .session("test-session")
            .run(async {
                assert_eq!(correlation_id(), id);
                assert_eq!(tenant_id(), Some("test-tenant".to_string()));
                assert_eq!(user_id(), Some("test-user".to_string()));
                assert_eq!(session_id(), Some("test-session".to_string()));
            })
            .await;
    }

    #[test]
    fn test_context_builder_sync() {
        clear_context();

        let id = Uuid::new_v4();

        let result = TaskContextBuilder::new()
            .correlation_id(id)
            .tenant("sync-tenant")
            .user("sync-user")
            .run_sync(|| {
                assert_eq!(correlation_id(), id);
                assert_eq!(tenant_id(), Some("sync-tenant".to_string()));
                assert_eq!(user_id(), Some("sync-user".to_string()));
                42
            });

        assert_eq!(result, 42);

        // Context should be cleared after run_sync
        assert!(try_correlation_id().is_none());
        assert!(tenant_id().is_none());
    }

    #[tokio::test]
    async fn test_task_local_takes_precedence_over_thread_local() {
        // Set thread-local
        let thread_id = Uuid::new_v4();
        set_correlation_id(thread_id);
        set_tenant_id("thread-tenant");

        // Task-local should take precedence
        let task_id = Uuid::new_v4();
        TaskContextBuilder::new()
            .correlation_id(task_id)
            .tenant("task-tenant")
            .run(async {
                // Should see task-local values
                assert_eq!(correlation_id(), task_id);
                assert_eq!(tenant_id(), Some("task-tenant".to_string()));
            })
            .await;

        // After task scope, thread-local should still be there
        assert_eq!(correlation_id(), thread_id);
        assert_eq!(tenant_id(), Some("thread-tenant".to_string()));

        // Clean up
        clear_context();
    }

    #[tokio::test]
    async fn test_nested_async_context() {
        let outer_id = Uuid::new_v4();
        let inner_id = Uuid::new_v4();

        with_correlation_id(outer_id, async {
            assert_eq!(correlation_id(), outer_id);

            // Nested scope with different ID
            with_correlation_id(inner_id, async {
                assert_eq!(correlation_id(), inner_id);
            })
            .await;

            // Back to outer
            assert_eq!(correlation_id(), outer_id);
        })
        .await;
    }
}
