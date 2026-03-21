//! Task context management with observability
//!
//! Provides context propagation for async operations with audit trails.
//! Context includes correlation IDs for distributed tracing and identity
//! information (user, tenant, session) for compliance tracking.
//!
//! # Example
//!
//! ```rust
//! use octarine::runtime::r#async::{TaskContextBuilder, set_user_id, correlation_id};
//! use uuid::Uuid;
//!
//! # async fn example() {
//! // Set context for a request
//! TaskContextBuilder::new()
//!     .correlation_id(Uuid::new_v4())
//!     .tenant("acme-corp")
//!     .user("user-123")
//!     .run(async {
//!         // Context is available throughout async execution
//!         let corr_id = correlation_id();
//!     }).await;
//! # }
//! ```

use uuid::Uuid;

use crate::observe;
use crate::primitives::runtime as prim;

// =============================================================================
// Correlation ID Functions
// =============================================================================

/// Get the current correlation ID
///
/// Checks in order:
/// 1. Task-local storage (for async code)
/// 2. Thread-local storage (for sync code)
/// 3. Generates a new UUID if neither is set
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::correlation_id;
///
/// let id = correlation_id();
/// println!("Current correlation: {}", id);
/// ```
#[inline]
pub fn correlation_id() -> Uuid {
    prim::correlation_id()
}

/// Get the current correlation ID if one is set
///
/// Unlike `correlation_id()`, this returns `None` if no context is set
/// rather than generating a new UUID.
#[inline]
pub fn try_correlation_id() -> Option<Uuid> {
    prim::try_correlation_id()
}

/// Set the correlation ID for the current thread (sync code)
///
/// For async code, use `with_correlation_id()` or `TaskContextBuilder` instead.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::{set_correlation_id, correlation_id};
/// use uuid::Uuid;
///
/// let id = Uuid::new_v4();
/// set_correlation_id(id);
/// assert_eq!(correlation_id(), id);
/// ```
pub fn set_correlation_id(id: Uuid) {
    observe::debug(
        "context_correlation_set",
        format!("Correlation ID set: {}", id),
    );
    prim::set_correlation_id(id);
}

/// Clear the thread-local correlation ID
pub fn clear_correlation_id() {
    observe::debug("context_correlation_cleared", "Correlation ID cleared");
    prim::clear_correlation_id();
}

/// Run a synchronous function with a specific correlation ID
///
/// The correlation ID is set before the function runs and cleared after.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::{with_sync_correlation_id, correlation_id};
/// use uuid::Uuid;
///
/// let id = Uuid::new_v4();
/// with_sync_correlation_id(id, || {
///     assert_eq!(correlation_id(), id);
/// });
/// ```
pub fn with_sync_correlation_id<F, R>(id: Uuid, f: F) -> R
where
    F: FnOnce() -> R,
{
    observe::debug(
        "context_correlation_scope_sync",
        format!("Entering sync scope with correlation: {}", id),
    );
    let result = prim::with_sync_correlation_id(id, f);
    observe::debug(
        "context_correlation_scope_sync",
        "Exiting sync correlation scope",
    );
    result
}

/// Run an async future with a specific correlation ID
///
/// The correlation ID is available throughout the async execution,
/// including across await points.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::{with_correlation_id, correlation_id};
/// use uuid::Uuid;
///
/// # tokio_test::block_on(async {
/// let id = Uuid::new_v4();
/// with_correlation_id(id, async {
///     assert_eq!(correlation_id(), id);
/// }).await;
/// # });
/// ```
pub async fn with_correlation_id<F, R>(id: Uuid, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    observe::debug(
        "context_correlation_scope_async",
        format!("Entering async scope with correlation: {}", id),
    );
    let result = prim::with_correlation_id(id, f).await;
    observe::debug(
        "context_correlation_scope_async",
        "Exiting async correlation scope",
    );
    result
}

// =============================================================================
// Tenant ID Functions
// =============================================================================

/// Get the current tenant ID if set
#[inline]
pub fn tenant_id() -> Option<String> {
    prim::tenant_id()
}

/// Set the tenant ID for the current thread (sync code)
pub fn set_tenant_id(id: impl Into<String>) {
    let id = id.into();
    observe::debug("context_tenant_set", format!("Tenant ID set: {}", id));
    prim::set_tenant_id(id);
}

/// Clear the thread-local tenant ID
pub fn clear_tenant_id() {
    observe::debug("context_tenant_cleared", "Tenant ID cleared");
    prim::clear_tenant_id();
}

// =============================================================================
// User ID Functions
// =============================================================================

/// Get the current user ID if set
#[inline]
pub fn user_id() -> Option<String> {
    prim::user_id()
}

/// Set the user ID for the current thread (sync code)
///
/// This is logged as an audit event since user context changes are
/// compliance-relevant (WHO is making the request).
pub fn set_user_id(id: impl Into<String>) {
    let id = id.into();
    // This is an info-level event because user context changes are audit-relevant
    observe::info("context_user_set", format!("User ID set: {}", id));
    prim::set_user_id(id);
}

/// Clear the thread-local user ID
pub fn clear_user_id() {
    observe::info("context_user_cleared", "User ID cleared");
    prim::clear_user_id();
}

// =============================================================================
// Session ID Functions
// =============================================================================

/// Get the current session ID if set
#[inline]
pub fn session_id() -> Option<String> {
    prim::session_id()
}

/// Set the session ID for the current thread (sync code)
pub fn set_session_id(id: impl Into<String>) {
    let id = id.into();
    observe::debug("context_session_set", format!("Session ID set: {}", id));
    prim::set_session_id(id);
}

/// Clear the thread-local session ID
pub fn clear_session_id() {
    observe::debug("context_session_cleared", "Session ID cleared");
    prim::clear_session_id();
}

// =============================================================================
// Clear All Context
// =============================================================================

/// Clear all thread-local context
///
/// Clears correlation ID, tenant ID, user ID, and session ID.
pub fn clear_context() {
    observe::debug("context_cleared", "All context cleared");
    prim::clear_context();
}

// =============================================================================
// Task Context Builder
// =============================================================================

/// Builder for running code with full context
///
/// Provides a fluent API for setting up execution context including
/// correlation ID, tenant, user, session, and custom metadata.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::TaskContextBuilder;
/// use uuid::Uuid;
///
/// # tokio_test::block_on(async {
/// TaskContextBuilder::new()
///     .correlation_id(Uuid::new_v4())
///     .tenant("acme-corp")
///     .user("user-123")
///     .run(async {
///         // Context is available here
///     }).await;
/// # });
/// ```
#[derive(Debug)]
pub struct TaskContextBuilder {
    inner: prim::TaskContextBuilder,
    correlation_id: Option<Uuid>,
    tenant_id: Option<String>,
    user_id: Option<String>,
    session_id: Option<String>,
}

impl TaskContextBuilder {
    /// Create a new task context builder
    pub fn new() -> Self {
        Self {
            inner: prim::TaskContextBuilder::new(),
            correlation_id: None,
            tenant_id: None,
            user_id: None,
            session_id: None,
        }
    }

    /// Set the correlation ID
    pub fn correlation_id(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self.inner = self.inner.correlation_id(id);
        self
    }

    /// Set the tenant ID
    pub fn tenant(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.tenant_id = Some(id.clone());
        self.inner = self.inner.tenant(id);
        self
    }

    /// Set the user ID
    pub fn user(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.user_id = Some(id.clone());
        self.inner = self.inner.user(id);
        self
    }

    /// Set the session ID
    pub fn session(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.session_id = Some(id.clone());
        self.inner = self.inner.session(id);
        self
    }

    /// Set the environment
    pub fn environment(mut self, env: impl Into<String>) -> Self {
        self.inner = self.inner.environment(env);
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.metadata(key, value);
        self
    }

    /// Run an async future with this context
    pub async fn run<F, R>(self, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        // Log context scope entry
        let ctx_summary = self.context_summary();
        observe::debug(
            "context_scope_enter",
            format!("Entering context scope: {}", ctx_summary),
        );

        let result = self.inner.run(f).await;

        observe::debug("context_scope_exit", "Exiting context scope");
        result
    }

    /// Run a sync function with this context (thread-local)
    pub fn run_sync<F, R>(self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Log context scope entry
        let ctx_summary = self.context_summary();
        observe::debug(
            "context_scope_enter_sync",
            format!("Entering sync context scope: {}", ctx_summary),
        );

        let result = self.inner.run_sync(f);

        observe::debug("context_scope_exit_sync", "Exiting sync context scope");
        result
    }

    /// Generate a summary of the context for logging
    fn context_summary(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref id) = self.correlation_id {
            parts.push(format!("correlation={}", id));
        }
        if let Some(ref id) = self.tenant_id {
            parts.push(format!("tenant={}", id));
        }
        if let Some(ref id) = self.user_id {
            parts.push(format!("user={}", id));
        }
        if let Some(ref id) = self.session_id {
            parts.push(format!("session={}", id));
        }

        if parts.is_empty() {
            "default".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl Default for TaskContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_set_and_get_correlation_id() {
        clear_context();
        let id = Uuid::new_v4();
        set_correlation_id(id);
        assert_eq!(correlation_id(), id);
        clear_correlation_id();
    }

    #[test]
    fn test_set_and_get_user_id() {
        clear_context();
        set_user_id("test-user");
        assert_eq!(user_id(), Some("test-user".to_string()));
        clear_user_id();
        assert_eq!(user_id(), None);
    }

    #[test]
    fn test_with_sync_correlation_id() {
        clear_context();
        let id = Uuid::new_v4();
        with_sync_correlation_id(id, || {
            assert_eq!(correlation_id(), id);
        });
    }

    #[tokio::test]
    async fn test_with_correlation_id_async() {
        let id = Uuid::new_v4();
        with_correlation_id(id, async {
            assert_eq!(correlation_id(), id);
        })
        .await;
    }

    #[tokio::test]
    async fn test_task_context_builder() {
        let corr_id = Uuid::new_v4();

        TaskContextBuilder::new()
            .correlation_id(corr_id)
            .tenant("test-tenant")
            .user("test-user")
            .run(async {
                assert_eq!(correlation_id(), corr_id);
                assert_eq!(tenant_id(), Some("test-tenant".to_string()));
                assert_eq!(user_id(), Some("test-user".to_string()));
            })
            .await;
    }
}
