//! Async utilities for runtime operations
//!
//! Provides core async primitives that encapsulate tokio interactions.
//! These utilities should be used instead of direct tokio calls to maintain
//! clean layered architecture.
//!
//! ## Available Utilities
//!
//! - **Sleep**: Async delays with various time units
//! - **Interval**: Periodic timers for batch processing
//! - **Yield**: Cooperative yielding for fair scheduling
//! - **Blocking**: Run blocking operations with context propagation
//!
//! ## Usage
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::{sleep, sleep_ms, interval, spawn_blocking};
//!
//! // Async delay
//! sleep_ms(100).await;
//!
//! // Periodic flushing
//! let mut timer = interval(Duration::from_secs(1));
//! loop {
//!     timer.tick().await;
//!     flush_batch();
//! }
//!
//! // Run blocking I/O with context propagation
//! let data = spawn_blocking(|| {
//!     std::fs::read("config.json")
//! }).await??;
//! ```

use std::time::Duration;
use tokio::task::JoinError;

/// Yield control back to the runtime
///
/// Use this to allow other tasks to make progress, especially in tight loops
/// or long-running computations.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::yield_now;
///
/// for i in 0..1000 {
///     process_item(i);
///     if i % 100 == 0 {
///         yield_now().await; // Let other tasks run
///     }
/// }
/// ```
#[allow(dead_code)] // API utility for future use
pub async fn yield_now() {
    tokio::task::yield_now().await
}

/// Sleep for a duration
///
/// Use this for async delays in production code. For tests and simple cases,
/// prefer `sleep_ms()` for readability.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::sleep;
/// use std::time::Duration;
///
/// // Wait 500ms before retry
/// sleep(Duration::from_millis(500)).await;
/// ```
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await
}

/// Sleep for a number of milliseconds
///
/// Convenience wrapper for common case of millisecond delays.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::sleep_ms;
///
/// #[tokio::test]
/// async fn test_async_operation() {
///     start_operation();
///     sleep_ms(10).await; // Wait for async processing
///     assert!(operation_completed());
/// }
/// ```
pub async fn sleep_ms(millis: u64) {
    tokio::time::sleep(Duration::from_millis(millis)).await
}

/// Sleep for a number of seconds
///
/// Convenience wrapper for longer delays.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::sleep_secs;
///
/// // Wait for service to initialize
/// sleep_secs(5).await;
/// ```
#[allow(dead_code)] // API utility for future use
pub async fn sleep_secs(secs: u64) {
    tokio::time::sleep(Duration::from_secs(secs)).await
}

/// Create an interval timer that yields periodically
///
/// Use this for periodic tasks like batch flushing, health checks,
/// metrics aggregation, etc.
///
/// Returns a tokio Interval that can be used with `tokio::select!`.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::interval;
/// use std::time::Duration;
///
/// let mut flush_timer = interval(Duration::from_secs(1));
///
/// loop {
///     tokio::select! {
///         Some(event) = rx.recv() => {
///             buffer.push(event);
///         }
///         _ = flush_timer.tick() => {
///             flush_buffer(&mut buffer);
///         }
///     }
/// }
/// ```
pub fn interval(duration: Duration) -> tokio::time::Interval {
    tokio::time::interval(duration)
}

/// Create an interval timer from milliseconds
///
/// Convenience wrapper for common case.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::interval_ms;
///
/// let mut timer = interval_ms(100); // Every 100ms
/// ```
pub fn interval_ms(millis: u64) -> tokio::time::Interval {
    tokio::time::interval(Duration::from_millis(millis))
}

/// Create an interval timer from seconds
///
/// Convenience wrapper for longer intervals.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::interval_secs;
///
/// let mut health_check = interval_secs(30); // Every 30 seconds
/// ```
#[allow(dead_code)] // API utility for future use
pub fn interval_secs(secs: u64) -> tokio::time::Interval {
    tokio::time::interval(Duration::from_secs(secs))
}

/// Get a timeout future that completes after the specified duration
///
/// Use with `tokio::select!` for operation timeouts.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::timeout;
/// use std::time::Duration;
///
/// tokio::select! {
///     result = long_operation() => {
///         handle_result(result);
///     }
///     _ = timeout(Duration::from_secs(30)) => {
///         handle_timeout();
///     }
/// }
/// ```
pub async fn timeout(duration: Duration) {
    tokio::time::sleep(duration).await
}

/// Get current instant for timing operations
///
/// Returns a tokio-compatible instant for measuring elapsed time.
#[allow(dead_code)] // API utility for future use
pub fn now() -> std::time::Instant {
    std::time::Instant::now()
}

// =============================================================================
// Blocking Operations with Context Propagation
// =============================================================================

/// Run a blocking operation on a dedicated thread pool with context propagation
///
/// Use this for CPU-intensive work or blocking I/O operations that shouldn't
/// block the async runtime. Context (correlation ID, tenant, user, session) is
/// automatically propagated to the blocking thread and cleaned up after.
///
/// # Why Use This Instead of `tokio::task::spawn_blocking`?
///
/// 1. **Context Propagation**: Correlation IDs and other context flow automatically
/// 2. **Centralized Runtime**: All tokio interactions go through primitives
/// 3. **Observability Ready**: Can add metrics/tracing in one place
/// 4. **Testability**: Can mock the runtime in tests
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::spawn_blocking;
///
/// // Read a file without blocking the async runtime
/// let contents = spawn_blocking(|| {
///     std::fs::read_to_string("large_file.txt")
/// }).await??;
///
/// // CPU-intensive computation
/// let result = spawn_blocking(|| {
///     compute_hash(&large_data)
/// }).await?;
/// ```
///
/// # Context Propagation
///
/// The current correlation ID, tenant ID, user ID, and session ID are
/// captured before spawning and restored in the blocking thread:
///
/// ```rust,ignore
/// use octarine::primitives::runtime::{spawn_blocking, set_correlation_id, correlation_id};
/// use uuid::Uuid;
///
/// let id = Uuid::new_v4();
/// set_correlation_id(id);
///
/// spawn_blocking(|| {
///     // correlation_id() returns the same ID here!
///     assert_eq!(correlation_id(), id);
///     do_work();
/// }).await?;
/// ```
///
/// # Errors
///
/// Returns `JoinError` if the blocking task panics or is cancelled.
#[allow(dead_code)] // Public API - will be used by primitives/io and external code
pub async fn spawn_blocking<F, R>(f: F) -> Result<R, JoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    // Import context functions from runtime module
    use crate::primitives::runtime::{
        clear_context, session_id, set_correlation_id, set_session_id, set_tenant_id, set_user_id,
        tenant_id, try_correlation_id, user_id,
    };

    // Capture current context before spawning
    let correlation = try_correlation_id();
    let tenant = tenant_id();
    let user = user_id();
    let session = session_id();

    tokio::task::spawn_blocking(move || {
        // Restore context in the blocking thread
        if let Some(id) = correlation {
            set_correlation_id(id);
        }
        if let Some(t) = tenant {
            set_tenant_id(t);
        }
        if let Some(u) = user {
            set_user_id(u);
        }
        if let Some(s) = session {
            set_session_id(s);
        }

        // Run the user's function
        let result = f();

        // Clean up thread-local context (important for thread pool reuse)
        clear_context();

        result
    })
    .await
}

/// Run a blocking operation that returns a Result, flattening the JoinError
///
/// Convenience wrapper for the common case where the blocking operation
/// itself returns a `Result`. The `JoinError` is converted to your error type.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::spawn_blocking_result;
/// use std::io;
///
/// async fn read_file(path: &str) -> io::Result<String> {
///     let path = path.to_owned();
///     spawn_blocking_result(move || {
///         std::fs::read_to_string(&path)
///     }).await
/// }
/// ```
///
/// # Type Parameters
///
/// - `F`: The blocking function to run
/// - `T`: The success type of the Result
/// - `E`: The error type, which must implement `From<JoinError>`
#[allow(dead_code)] // Public API - will be used by primitives/io and external code
pub async fn spawn_blocking_result<F, T, E>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static + From<JoinError>,
{
    match spawn_blocking(f).await {
        Ok(result) => result,
        Err(join_error) => Err(E::from(join_error)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn test_sleep_ms() {
        let start = now();
        sleep_ms(10).await;
        let elapsed = start.elapsed();
        // Allow 20% margin for OS scheduler jitter
        assert!(elapsed.as_millis() >= 8);
    }

    #[tokio::test]
    async fn test_sleep_secs() {
        let start = now();
        // Just test it compiles and runs, don't actually wait seconds
        tokio::time::timeout(Duration::from_millis(1), sleep_secs(1))
            .await
            .ok();
        // Should have been interrupted
        assert!(start.elapsed().as_millis() < 100);
    }

    #[tokio::test]
    async fn test_yield_now() {
        // Should not block
        yield_now().await;
    }

    #[tokio::test]
    async fn test_interval() {
        let mut timer = interval_ms(10);

        // First tick is immediate
        timer.tick().await;

        let start = now();
        timer.tick().await;
        let elapsed = start.elapsed();

        // Allow for some timing variance - at least 5ms should have elapsed
        assert!(
            elapsed.as_millis() >= 5,
            "Expected at least 5ms elapsed, got {}ms",
            elapsed.as_millis()
        );
    }

    #[tokio::test]
    async fn test_timeout() {
        let start = now();
        timeout(Duration::from_millis(10)).await;
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() >= 10);
    }

    #[tokio::test]
    async fn test_spawn_blocking_basic() {
        let result = spawn_blocking(|| {
            // Simulate blocking work
            std::thread::sleep(Duration::from_millis(1));
            42
        })
        .await
        .expect("spawn_blocking should succeed");

        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_spawn_blocking_context_propagation() {
        use crate::primitives::runtime::{
            clear_context, correlation_id, session_id, set_correlation_id, set_session_id,
            set_tenant_id, set_user_id, tenant_id, user_id,
        };
        use std::sync::mpsc;
        use uuid::Uuid;

        // Clear any existing context first
        clear_context();

        // Set up context in the async task
        let test_correlation = Uuid::new_v4();
        let test_tenant = "test-tenant-123".to_string();
        let test_user = "test-user-456".to_string();
        let test_session = "test-session-789".to_string();

        set_correlation_id(test_correlation);
        set_tenant_id(&test_tenant);
        set_user_id(&test_user);
        set_session_id(&test_session);

        // Channel to capture context values from blocking thread
        let (tx, rx) = mpsc::channel();

        spawn_blocking(move || {
            // Capture context in blocking thread
            let captured = (correlation_id(), tenant_id(), user_id(), session_id());
            tx.send(captured).expect("send should work");
        })
        .await
        .expect("spawn_blocking should succeed");

        let (captured_correlation, captured_tenant, captured_user, captured_session) =
            rx.recv().expect("should receive captured context");

        // Verify context was propagated
        assert_eq!(captured_correlation, test_correlation);
        assert_eq!(captured_tenant, Some(test_tenant));
        assert_eq!(captured_user, Some(test_user));
        assert_eq!(captured_session, Some(test_session));

        // Clean up
        clear_context();
    }

    #[tokio::test]
    async fn test_spawn_blocking_no_context() {
        use crate::primitives::runtime::{clear_context, try_correlation_id};

        // Ensure no context is set
        clear_context();

        let result = spawn_blocking(|| {
            // Should work even without context
            "no context needed"
        })
        .await
        .expect("spawn_blocking should succeed");

        assert_eq!(result, "no context needed");

        // Context should still be clear
        assert!(try_correlation_id().is_none());
    }

    #[tokio::test]
    async fn test_spawn_blocking_result_success() {
        let result: Result<i32, std::io::Error> = spawn_blocking_result(|| Ok(123)).await;

        assert_eq!(result.expect("should be Ok"), 123);
    }

    #[tokio::test]
    async fn test_spawn_blocking_result_error() {
        let result: Result<i32, std::io::Error> = spawn_blocking_result(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "test error",
            ))
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should be Err").kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[tokio::test]
    async fn test_spawn_blocking_returns_value() {
        // Test that complex return types work
        let result = spawn_blocking(|| vec![1, 2, 3, 4, 5])
            .await
            .expect("should succeed");

        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_spawn_blocking_moves_ownership() {
        let data = [1, 2, 3]; // Array instead of vec to satisfy clippy

        let result = spawn_blocking(move || {
            // data is moved into the closure
            data.iter().sum::<i32>()
        })
        .await
        .expect("should succeed");

        assert_eq!(result, 6);
    }
}
