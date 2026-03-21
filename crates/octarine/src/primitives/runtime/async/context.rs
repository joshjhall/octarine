//! Context storage for async and sync operations
//!
//! Provides context that flows through both async task boundaries and sync code,
//! using task-local storage for async and thread-local storage for sync.
#![allow(dead_code)] // Public API primitives - not all items used internally yet
//!
//! ## Features
//!
//! - **Correlation IDs**: Unique identifiers for request tracing
//! - **Multi-tenancy**: Tenant and user context propagation
//! - **Metadata**: Arbitrary key-value pairs for custom context
//! - **Async-safe**: Works across await boundaries (task-local)
//! - **Sync-safe**: Works in synchronous code (thread-local)
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The public API is exposed through shortcut functions in
//! the parent module, not directly through these types.
//!
//! ## Storage Strategy
//!
//! - **Async code**: Uses tokio's `task_local!` which flows across await points
//! - **Sync code**: Uses `thread_local!` for thread-specific context
//! - **Lookup order**: Task-local first, then thread-local, then generate new

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task_local;
use uuid::Uuid;

use crate::primitives::{Problem, Result};

// =============================================================================
// Thread-local storage for sync code
// =============================================================================

thread_local! {
    /// Thread-local correlation ID for sync code
    static THREAD_CORRELATION_ID: RefCell<Option<Uuid>> = const { RefCell::new(None) };

    /// Thread-local tenant ID for sync code
    static THREAD_TENANT_ID: RefCell<Option<String>> = const { RefCell::new(None) };

    /// Thread-local user ID for sync code
    static THREAD_USER_ID: RefCell<Option<String>> = const { RefCell::new(None) };

    /// Thread-local session ID for sync code
    static THREAD_SESSION_ID: RefCell<Option<String>> = const { RefCell::new(None) };
}

// =============================================================================
// Thread-local API (internal, used by shortcut functions)
// =============================================================================

/// Set the correlation ID for the current thread (sync code)
pub(crate) fn set_thread_correlation_id(id: Uuid) {
    THREAD_CORRELATION_ID.with(|cell| {
        *cell.borrow_mut() = Some(id);
    });
}

/// Get the correlation ID from thread-local storage
pub(crate) fn get_thread_correlation_id() -> Option<Uuid> {
    THREAD_CORRELATION_ID.with(|cell| *cell.borrow())
}

/// Clear the thread-local correlation ID
pub(crate) fn clear_thread_correlation_id() {
    THREAD_CORRELATION_ID.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Set thread-local tenant ID
pub(crate) fn set_thread_tenant_id(id: String) {
    THREAD_TENANT_ID.with(|cell| {
        *cell.borrow_mut() = Some(id);
    });
}

/// Get thread-local tenant ID
pub(crate) fn get_thread_tenant_id() -> Option<String> {
    THREAD_TENANT_ID.with(|cell| cell.borrow().clone())
}

/// Clear thread-local tenant ID
pub(crate) fn clear_thread_tenant_id() {
    THREAD_TENANT_ID.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Set thread-local user ID
pub(crate) fn set_thread_user_id(id: String) {
    THREAD_USER_ID.with(|cell| {
        *cell.borrow_mut() = Some(id);
    });
}

/// Get thread-local user ID
pub(crate) fn get_thread_user_id() -> Option<String> {
    THREAD_USER_ID.with(|cell| cell.borrow().clone())
}

/// Clear thread-local user ID
pub(crate) fn clear_thread_user_id() {
    THREAD_USER_ID.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Set thread-local session ID
pub(crate) fn set_thread_session_id(id: String) {
    THREAD_SESSION_ID.with(|cell| {
        *cell.borrow_mut() = Some(id);
    });
}

/// Get thread-local session ID
pub(crate) fn get_thread_session_id() -> Option<String> {
    THREAD_SESSION_ID.with(|cell| cell.borrow().clone())
}

/// Clear thread-local session ID
pub(crate) fn clear_thread_session_id() {
    THREAD_SESSION_ID.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Clear all thread-local context
pub(crate) fn clear_thread_context() {
    clear_thread_correlation_id();
    clear_thread_tenant_id();
    clear_thread_user_id();
    clear_thread_session_id();
}

// =============================================================================
// TaskContext (internal implementation)
// =============================================================================

/// Task-local context that flows through async operations
///
/// Provides immutable context that can be accessed from any async task
/// in the current scope. Once set, the context cannot be modified to
/// prevent tampering during request processing.
///
/// # Security Considerations
///
/// - Context is immutable once set to prevent tampering
/// - Tenant isolation is enforced by design
/// - Correlation IDs enable audit trails
#[derive(Debug, Clone)]
pub struct TaskContext {
    /// Unique identifier for this task/request
    pub correlation_id: Uuid,

    /// Tenant identifier for multi-tenant systems
    pub tenant_id: Option<String>,

    /// User identifier
    pub user_id: Option<String>,

    /// Session identifier
    pub session_id: Option<String>,

    /// Environment (dev, staging, prod)
    pub environment: String,

    /// Additional metadata
    pub metadata: Arc<HashMap<String, String>>,
}

impl TaskContext {
    /// Create a new context with a generated correlation ID
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::context::TaskContext;
    ///
    /// let ctx = TaskContext::new();
    /// assert!(ctx.tenant_id.is_none());
    /// assert!(ctx.user_id.is_none());
    /// ```
    pub fn new() -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            tenant_id: None,
            user_id: None,
            session_id: None,
            environment: String::from("unknown"),
            metadata: Arc::new(HashMap::new()),
        }
    }

    /// Create a context with a specific correlation ID
    ///
    /// Useful when you need to continue an existing trace or use
    /// an externally provided request ID.
    pub fn with_correlation_id(correlation_id: Uuid) -> Self {
        Self {
            correlation_id,
            ..Self::new()
        }
    }

    /// Builder-style method to set tenant ID
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::context::TaskContext;
    ///
    /// let ctx = TaskContext::new().with_tenant("acme-corp");
    /// assert_eq!(ctx.tenant_id, Some("acme-corp".to_string()));
    /// ```
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Builder-style method to set user ID
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Builder-style method to set session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Builder-style method to set environment
    pub fn with_environment(mut self, env: impl Into<String>) -> Self {
        self.environment = env.into();
        self
    }

    /// Add metadata to the context
    ///
    /// Metadata is stored in an Arc for efficient cloning across
    /// async boundaries.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::context::TaskContext;
    ///
    /// let ctx = TaskContext::new()
    ///     .with_metadata("request_id", "req-123")
    ///     .with_metadata("source", "api");
    ///
    /// assert_eq!(ctx.metadata.get("request_id"), Some(&"req-123".to_string()));
    /// ```
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        Arc::make_mut(&mut self.metadata).insert(key.into(), value.into());
        self
    }

    /// Get a metadata value by key
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Create a context with a correlation ID parsed from a string
    ///
    /// Useful when receiving correlation IDs from HTTP headers or other string sources.
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the string is not a valid UUID.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::context::TaskContext;
    ///
    /// let ctx = TaskContext::with_correlation_id_from_string("550e8400-e29b-41d4-a716-446655440000")?;
    /// assert!(ctx.tenant_id.is_none());
    /// # Ok::<(), octarine::primitives::Problem>(())
    /// ```
    pub fn with_correlation_id_from_string(id: &str) -> Result<Self> {
        let uuid = Uuid::parse_str(id)
            .map_err(|e| Problem::Validation(format!("Invalid correlation ID '{}': {}", id, e)))?;

        Ok(Self {
            correlation_id: uuid,
            ..Self::new()
        })
    }

    /// Merge this context with a parent context
    ///
    /// Creates a new context that inherits values from the parent but can override them.
    /// The merge behavior is:
    /// - correlation_id: Use child's (maintains tracing identity)
    /// - tenant_id: Use child's if set, otherwise parent's
    /// - user_id: Use child's if set, otherwise parent's
    /// - session_id: Use child's if set, otherwise parent's
    /// - environment: Use child's if not "unknown", otherwise parent's
    /// - metadata: Merge both, child values override parent
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::context::TaskContext;
    ///
    /// let parent = TaskContext::new()
    ///     .with_tenant("acme-corp")
    ///     .with_user("user-123")
    ///     .with_metadata("source", "api");
    ///
    /// let child = TaskContext::new()
    ///     .with_user("user-456") // Override user
    ///     .with_metadata("request_id", "req-789");
    ///
    /// let merged = child.merge_with_parent(&parent);
    /// assert_eq!(merged.tenant_id, Some("acme-corp".to_string())); // Inherited
    /// assert_eq!(merged.user_id, Some("user-456".to_string())); // Overridden
    /// assert_eq!(merged.get_metadata("source"), Some(&"api".to_string())); // Inherited
    /// assert_eq!(merged.get_metadata("request_id"), Some(&"req-789".to_string())); // Child's
    /// ```
    pub fn merge_with_parent(&self, parent: &TaskContext) -> Self {
        // Merge metadata: parent first, then child overrides
        let mut merged_metadata = (*parent.metadata).clone();
        for (key, value) in self.metadata.iter() {
            merged_metadata.insert(key.clone(), value.clone());
        }

        Self {
            // Keep child's correlation ID (maintains tracing identity)
            correlation_id: self.correlation_id,

            // Use child's values if set, otherwise parent's
            tenant_id: self.tenant_id.clone().or_else(|| parent.tenant_id.clone()),
            user_id: self.user_id.clone().or_else(|| parent.user_id.clone()),
            session_id: self
                .session_id
                .clone()
                .or_else(|| parent.session_id.clone()),

            // Use child's environment if not default
            environment: if self.environment != "unknown" {
                self.environment.clone()
            } else {
                parent.environment.clone()
            },

            metadata: Arc::new(merged_metadata),
        }
    }
}

impl Default for TaskContext {
    fn default() -> Self {
        Self::new()
    }
}

// Task-local storage for the context
task_local! {
    static TASK_CONTEXT: TaskContext;
}

/// Task-local context management
///
/// Provides static methods for accessing and managing task-local context.
pub struct TaskLocal;

impl TaskLocal {
    /// Run a future with the given context
    ///
    /// The context will be available to all code within the future,
    /// including nested async calls.
    pub async fn scope<F, R>(context: TaskContext, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        TASK_CONTEXT.scope(context, f).await
    }

    /// Get the current context if set
    ///
    /// Returns `None` if no context has been set in the current task.
    pub fn try_get() -> Option<TaskContext> {
        TASK_CONTEXT.try_with(|ctx| ctx.clone()).ok()
    }

    /// Get the current context or create a default one
    ///
    /// This is a convenience method that always returns a context,
    /// creating a new one if none exists.
    pub fn get() -> TaskContext {
        Self::try_get().unwrap_or_default()
    }

    /// Get the current correlation ID
    ///
    /// Returns a new UUID if no context is set.
    pub fn correlation_id() -> Uuid {
        Self::try_get()
            .map(|ctx| ctx.correlation_id)
            .unwrap_or_else(Uuid::new_v4)
    }

    /// Get the current tenant ID if set
    pub fn tenant_id() -> Option<String> {
        Self::try_get().and_then(|ctx| ctx.tenant_id)
    }

    /// Get the current user ID if set
    pub fn user_id() -> Option<String> {
        Self::try_get().and_then(|ctx| ctx.user_id)
    }

    /// Check if we're in an async context with task-local storage
    pub fn is_set() -> bool {
        TASK_CONTEXT.try_with(|_| ()).is_ok()
    }
}

/// Helper to run code with context
///
/// Convenience function that wraps `TaskLocal::scope`.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::context::{TaskContext, with_context, TaskLocal};
///
/// #[tokio::main]
/// async fn main() {
///     let ctx = TaskContext::new().with_tenant("acme");
///
///     with_context(ctx, async {
///         assert!(TaskLocal::is_set());
///     }).await;
/// }
/// ```
pub async fn with_context<F, R>(context: TaskContext, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    TaskLocal::scope(context, f).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn test_context_creation() {
        let context = TaskContext::new()
            .with_tenant("acme-corp")
            .with_user("user-123")
            .with_environment("test");

        assert_eq!(context.tenant_id, Some("acme-corp".to_string()));
        assert_eq!(context.user_id, Some("user-123".to_string()));
        assert_eq!(context.environment, "test");
    }

    #[tokio::test]
    async fn test_task_local_storage() {
        let context = TaskContext::new()
            .with_tenant("test-tenant")
            .with_user("test-user");

        let result = with_context(context.clone(), async {
            // Should be able to get context inside
            let ctx = TaskLocal::get();
            assert_eq!(ctx.tenant_id, Some("test-tenant".to_string()));
            assert_eq!(ctx.user_id, Some("test-user".to_string()));

            // Nested async should also have access
            nested_function().await
        })
        .await;

        assert_eq!(result, "nested-success");

        // Outside scope, context should not be set
        assert!(!TaskLocal::is_set());
    }

    async fn nested_function() -> String {
        let ctx = TaskLocal::get();
        assert_eq!(ctx.tenant_id, Some("test-tenant".to_string()));
        "nested-success".to_string()
    }

    #[tokio::test]
    async fn test_context_metadata() {
        let context = TaskContext::new()
            .with_metadata("request_id", "req-123")
            .with_metadata("source", "api");

        assert_eq!(
            context.metadata.get("request_id"),
            Some(&"req-123".to_string())
        );
        assert_eq!(context.metadata.get("source"), Some(&"api".to_string()));
    }

    #[tokio::test]
    async fn test_correlation_id() {
        let ctx = TaskContext::new();
        let id = ctx.correlation_id;

        with_context(ctx, async {
            assert_eq!(TaskLocal::correlation_id(), id);
        })
        .await;
    }

    #[tokio::test]
    async fn test_helper_methods() {
        let ctx = TaskContext::new()
            .with_tenant("tenant-1")
            .with_user("user-1");

        with_context(ctx, async {
            assert_eq!(TaskLocal::tenant_id(), Some("tenant-1".to_string()));
            assert_eq!(TaskLocal::user_id(), Some("user-1".to_string()));
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_metadata() {
        let ctx = TaskContext::new().with_metadata("key", "value");

        assert_eq!(ctx.get_metadata("key"), Some(&"value".to_string()));
        assert_eq!(ctx.get_metadata("missing"), None);
    }

    #[test]
    fn test_context_default() {
        let ctx = TaskContext::default();
        assert!(ctx.tenant_id.is_none());
        assert!(ctx.user_id.is_none());
        assert_eq!(ctx.environment, "unknown");
    }

    #[tokio::test]
    async fn test_try_get_outside_scope() {
        assert!(TaskLocal::try_get().is_none());
        assert!(!TaskLocal::is_set());
    }

    #[test]
    fn test_correlation_id_from_string_valid() {
        let result =
            TaskContext::with_correlation_id_from_string("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_ok());
        let ctx = result.expect("Expected valid UUID");
        assert_eq!(
            ctx.correlation_id.to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_correlation_id_from_string_invalid() {
        let result = TaskContext::with_correlation_id_from_string("not-a-uuid");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("Invalid correlation ID")
        );
    }

    #[test]
    fn test_merge_with_parent_basic() {
        let parent = TaskContext::new()
            .with_tenant("acme-corp")
            .with_user("user-123")
            .with_environment("prod");

        let child = TaskContext::new();

        let merged = child.merge_with_parent(&parent);
        assert_eq!(merged.tenant_id, Some("acme-corp".to_string()));
        assert_eq!(merged.user_id, Some("user-123".to_string()));
        assert_eq!(merged.environment, "prod");
    }

    #[test]
    fn test_merge_with_parent_override() {
        let parent = TaskContext::new()
            .with_tenant("acme-corp")
            .with_user("user-123");

        let child = TaskContext::new()
            .with_user("user-456")
            .with_session("session-789");

        let merged = child.merge_with_parent(&parent);
        assert_eq!(merged.tenant_id, Some("acme-corp".to_string())); // Inherited
        assert_eq!(merged.user_id, Some("user-456".to_string())); // Overridden
        assert_eq!(merged.session_id, Some("session-789".to_string())); // Child's
    }

    #[test]
    fn test_merge_with_parent_metadata() {
        let parent = TaskContext::new()
            .with_metadata("source", "api")
            .with_metadata("version", "1.0");

        let child = TaskContext::new()
            .with_metadata("request_id", "req-123")
            .with_metadata("version", "2.0"); // Override

        let merged = child.merge_with_parent(&parent);
        assert_eq!(merged.get_metadata("source"), Some(&"api".to_string()));
        assert_eq!(
            merged.get_metadata("request_id"),
            Some(&"req-123".to_string())
        );
        assert_eq!(merged.get_metadata("version"), Some(&"2.0".to_string())); // Overridden
    }

    #[test]
    fn test_merge_preserves_child_correlation_id() {
        let parent = TaskContext::new();
        let child = TaskContext::new();

        let merged = child.merge_with_parent(&parent);
        assert_eq!(merged.correlation_id, child.correlation_id);
        assert_ne!(merged.correlation_id, parent.correlation_id);
    }

    #[test]
    fn test_merge_environment_default() {
        let parent = TaskContext::new().with_environment("prod");
        let child = TaskContext::new(); // environment = "unknown"

        let merged = child.merge_with_parent(&parent);
        assert_eq!(merged.environment, "prod"); // Inherits parent's
    }

    #[test]
    fn test_merge_environment_override() {
        let parent = TaskContext::new().with_environment("prod");
        let child = TaskContext::new().with_environment("staging");

        let merged = child.merge_with_parent(&parent);
        assert_eq!(merged.environment, "staging"); // Child's value
    }
}
