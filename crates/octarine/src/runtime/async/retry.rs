//! Retry operations with observability
//!
//! Provides retry functionality that wraps operations with configurable policies
//! and comprehensive logging, metrics, and error context.

// Allow arithmetic operations - counters and attempt numbers are bounded and safe
#![allow(clippy::arithmetic_side_effects)]

use crate::observe::{self, Problem, Result};
use crate::primitives::runtime::r#async::sleep_ms;

use super::RetryPolicy;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// Health Check Thresholds
// ============================================================================

/// Minimum operations before health assessment is statistically meaningful.
const MIN_OPERATIONS_FOR_HEALTH: u64 = 10;

/// Success rate threshold for healthy status (50%).
const HEALTHY_SUCCESS_RATE: f64 = 0.5;

/// Average attempts threshold for healthy status.
const HEALTHY_AVG_ATTEMPTS: f64 = 3.0;

/// Success rate threshold below which system is degraded (70%).
const DEGRADED_SUCCESS_RATE: f64 = 0.7;

/// Average attempts threshold above which system is degraded.
const DEGRADED_AVG_ATTEMPTS: f64 = 2.0;

// ============================================================================
// Jitter Configuration
// ============================================================================

/// Jitter increase per retry attempt (10%).
const JITTER_PER_ATTEMPT: f64 = 0.1;

/// Maximum jitter factor (50%).
const MAX_JITTER_FACTOR: f64 = 0.5;

/// Global retry statistics
static RETRY_STATS: RetryStats = RetryStats::new();

struct RetryStats {
    total_operations: AtomicU64,
    total_attempts: AtomicU64,
    total_successes: AtomicU64,
    total_failures: AtomicU64,
    total_time_ms: AtomicU64,
}

impl RetryStats {
    const fn new() -> Self {
        Self {
            total_operations: AtomicU64::new(0),
            total_attempts: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            total_time_ms: AtomicU64::new(0),
        }
    }
}

/// Statistics about retry operations
#[derive(Debug, Clone)]
pub struct RetryStatistics {
    /// Total operations attempted (with retries)
    pub total_operations: u64,
    /// Total retry attempts across all operations
    pub total_attempts: u64,
    /// Total successful operations
    pub total_successes: u64,
    /// Total failed operations (exhausted retries)
    pub total_failures: u64,
    /// Total time spent in retry operations (ms)
    pub total_time_ms: u64,
    /// Average attempts per operation
    pub avg_attempts: f64,
    /// Success rate (0.0 to 1.0)
    pub success_rate: f64,
}

impl RetryStatistics {
    /// Get the failure rate (0.0 to 1.0)
    pub fn failure_rate(&self) -> f64 {
        1.0 - self.success_rate
    }

    /// Get average retry duration in milliseconds
    pub fn avg_duration_ms(&self) -> f64 {
        if self.total_operations == 0 {
            return 0.0;
        }
        self.total_time_ms as f64 / self.total_operations as f64
    }

    /// Check if the retry system is healthy
    ///
    /// Healthy if success rate > 50% and average attempts < 3
    pub fn is_healthy(&self) -> bool {
        if self.total_operations < MIN_OPERATIONS_FOR_HEALTH {
            return true; // Not enough data
        }
        self.success_rate > HEALTHY_SUCCESS_RATE && self.avg_attempts < HEALTHY_AVG_ATTEMPTS
    }

    /// Check if the retry system is degraded
    ///
    /// Degraded if success rate < 70% or average attempts > 2
    pub fn is_degraded(&self) -> bool {
        if self.total_operations < MIN_OPERATIONS_FOR_HEALTH {
            return false; // Not enough data
        }
        self.success_rate < DEGRADED_SUCCESS_RATE || self.avg_attempts > DEGRADED_AVG_ATTEMPTS
    }
}

/// Result of a retry operation with metadata
#[derive(Debug)]
pub struct RetryResult<T> {
    /// The result value (if successful)
    pub value: T,
    /// Number of attempts made
    pub attempts: u32,
    /// Total time spent (including delays)
    pub total_time: Duration,
    /// Whether retries were needed
    pub retried: bool,
}

/// Execute an operation with retry policy and full observability
///
/// This function wraps an async operation with retry logic, logging each attempt,
/// recording metrics, and providing rich error context on failure.
///
/// # Arguments
///
/// * `operation_name` - Name for logging and metrics
/// * `policy` - Retry policy configuration
/// * `operation` - The async operation to execute
///
/// # Returns
///
/// Returns `Ok(RetryResult)` with the value and metadata, or `Err(Problem)` with
/// full context including attempt count and timing.
///
/// # Examples
///
/// ```rust
/// use octarine::runtime::r#async::{retry, RetryPolicy};
/// use octarine::Problem;
///
/// async fn fetch_api() -> Result<String, Problem> {
///     Ok("success".to_string())
/// }
///
/// # tokio_test::block_on(async {
/// let result = retry("fetch_api", RetryPolicy::default(), fetch_api).await.unwrap();
/// assert_eq!(result.attempts, 1);
/// # });
/// ```
pub async fn retry<F, Fut, T, E>(
    operation_name: &str,
    policy: RetryPolicy,
    mut operation: F,
) -> Result<RetryResult<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Display + std::fmt::Debug,
{
    // Validate policy
    policy.validate()?;

    let start = Instant::now();
    RETRY_STATS.total_operations.fetch_add(1, Ordering::Relaxed);

    let mut last_error: Option<String> = None;
    let mut attempt = 0;
    let total_start = Instant::now();

    // Check for total timeout
    let deadline = policy.max_total_time.map(|d| Instant::now() + d);

    while attempt < policy.max_attempts {
        // Check deadline
        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            observe::warn(
                "retry_timeout",
                format!(
                    "{}: Total timeout exceeded after {} attempts",
                    operation_name, attempt
                ),
            );
            break;
        }

        RETRY_STATS.total_attempts.fetch_add(1, Ordering::Relaxed);
        attempt += 1;

        // Log attempt
        if attempt > 1 {
            observe::debug(
                "retry_attempt",
                format!(
                    "{}: Attempt {}/{} (previous failed: {})",
                    operation_name,
                    attempt,
                    policy.max_attempts,
                    last_error.as_deref().unwrap_or("unknown")
                ),
            );
        }

        // Execute operation
        let op_start = Instant::now();
        match operation().await {
            Ok(value) => {
                let total_time = start.elapsed();
                let op_time = op_start.elapsed();

                // Log success
                if attempt > 1 {
                    observe::info(
                        "retry_success",
                        format!(
                            "{}: Succeeded on attempt {} after {:?} (operation: {:?})",
                            operation_name, attempt, total_time, op_time
                        ),
                    );
                }

                // Update stats
                RETRY_STATS.total_successes.fetch_add(1, Ordering::Relaxed);
                RETRY_STATS
                    .total_time_ms
                    .fetch_add(total_time.as_millis() as u64, Ordering::Relaxed);

                return Ok(RetryResult {
                    value,
                    attempts: attempt,
                    total_time,
                    retried: attempt > 1,
                });
            }
            Err(e) => {
                let err_msg = format!("{}", e);
                last_error = Some(err_msg.clone());

                // Log failure (warn level since retry is being triggered)
                observe::warn(
                    "retry_failure",
                    format!(
                        "{}: Attempt {} failed: {}",
                        operation_name, attempt, err_msg
                    ),
                );

                // Check if we should retry
                if attempt >= policy.max_attempts {
                    break;
                }

                // Calculate delay
                let delay = if policy.jitter {
                    // Use simple random factor for jitter
                    let jitter_factor =
                        (attempt as f64 * JITTER_PER_ATTEMPT).min(MAX_JITTER_FACTOR);
                    policy.backoff.delay_with_jitter(attempt - 1, jitter_factor)
                } else {
                    policy.backoff.delay(attempt - 1)
                };

                // Log delay
                observe::trace(
                    "retry_delay",
                    format!(
                        "{}: Waiting {:?} before attempt {}",
                        operation_name,
                        delay,
                        attempt + 1
                    ),
                );

                // Wait
                sleep_ms(delay.as_millis() as u64).await;
            }
        }
    }

    // All attempts failed
    let total_time = total_start.elapsed();
    RETRY_STATS.total_failures.fetch_add(1, Ordering::Relaxed);
    RETRY_STATS
        .total_time_ms
        .fetch_add(total_time.as_millis() as u64, Ordering::Relaxed);

    // Log failure
    observe::error(
        "retry_exhausted",
        format!(
            "{}: All {} attempts failed after {:?}. Last error: {}",
            operation_name,
            attempt,
            total_time,
            last_error.as_deref().unwrap_or("unknown")
        ),
    );

    Err(Problem::OperationFailed(format!(
        "{}: Failed after {} attempts ({:?}). Last error: {}",
        operation_name,
        attempt,
        total_time,
        last_error.unwrap_or_else(|| "unknown".to_string())
    )))
}

/// Execute an operation with retry and additional context
///
/// Like `retry()` but adds custom context to the operation for better logging.
///
/// # Examples
///
/// ```rust
/// use octarine::runtime::r#async::{retry_with_context, RetryPolicy};
/// use octarine::Problem;
///
/// # tokio_test::block_on(async {
/// let result = retry_with_context(
///     "fetch_user",
///     RetryPolicy::default(),
///     &[("user_id", "123"), ("tenant", "acme")],
///     || async { Ok::<_, Problem>("user data".to_string()) },
/// ).await.unwrap();
/// assert_eq!(result.attempts, 1);
/// # });
/// ```
pub async fn retry_with_context<F, Fut, T, E>(
    operation_name: &str,
    policy: RetryPolicy,
    context: &[(&str, &str)],
    operation: F,
) -> Result<RetryResult<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Display + std::fmt::Debug,
{
    // Format context for logging
    let ctx_str: String = context
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(", ");

    let full_name = if ctx_str.is_empty() {
        operation_name.to_string()
    } else {
        format!("{}[{}]", operation_name, ctx_str)
    };

    retry(&full_name, policy, operation).await
}

/// Get retry statistics
///
/// Returns statistics about all retry operations performed.
pub fn retry_stats() -> RetryStatistics {
    let total_operations = RETRY_STATS.total_operations.load(Ordering::Relaxed);
    let total_attempts = RETRY_STATS.total_attempts.load(Ordering::Relaxed);
    let total_successes = RETRY_STATS.total_successes.load(Ordering::Relaxed);
    let total_failures = RETRY_STATS.total_failures.load(Ordering::Relaxed);
    let total_time_ms = RETRY_STATS.total_time_ms.load(Ordering::Relaxed);

    let avg_attempts = if total_operations > 0 {
        total_attempts as f64 / total_operations as f64
    } else {
        0.0
    };

    let success_rate = if total_operations > 0 {
        total_successes as f64 / total_operations as f64
    } else {
        1.0
    };

    RetryStatistics {
        total_operations,
        total_attempts,
        total_successes,
        total_failures,
        total_time_ms,
        avg_attempts,
        success_rate,
    }
}

/// Check if retry system is healthy
///
/// Returns true if success rate is above 50% and average attempts below 3.
pub fn retry_is_healthy() -> bool {
    let stats = retry_stats();
    if stats.total_operations < 10 {
        return true; // Not enough data
    }
    stats.success_rate > 0.5 && stats.avg_attempts < 3.0
}

/// Check if retry system is degraded
///
/// Returns true if success rate is below 70% or average attempts above 2.
pub fn retry_is_degraded() -> bool {
    let stats = retry_stats();
    if stats.total_operations < 10 {
        return false; // Not enough data
    }
    stats.success_rate < 0.7 || stats.avg_attempts > 2.0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[tokio::test]
    async fn test_retry_success_first_attempt() {
        let result = retry(
            "test_op",
            RetryPolicy::fixed(3, Duration::from_millis(10)),
            || async { Ok::<_, &str>("success") },
        )
        .await;

        assert!(result.is_ok());
        let res = result.expect("Retry should succeed on first attempt");
        assert_eq!(res.value, "success");
        assert_eq!(res.attempts, 1);
        assert!(!res.retried);
    }

    #[tokio::test]
    async fn test_retry_success_after_failures() {
        let attempt_count = AtomicU32::new(0);

        let result = retry(
            "test_retry",
            RetryPolicy::fixed(5, Duration::from_millis(1)),
            || {
                let count = attempt_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count < 2 {
                        Err("transient error")
                    } else {
                        Ok("success")
                    }
                }
            },
        )
        .await;

        assert!(result.is_ok());
        let res = result.expect("Retry should eventually succeed");
        assert_eq!(res.value, "success");
        assert_eq!(res.attempts, 3);
        assert!(res.retried);
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let result = retry(
            "test_fail",
            RetryPolicy::fixed(3, Duration::from_millis(1)),
            || async { Err::<(), _>("always fails") },
        )
        .await;

        assert!(result.is_err());
        let err = result.expect_err("Retry should fail after exhausting attempts");
        assert!(err.to_string().contains("Failed after 3 attempts"));
    }

    #[tokio::test]
    async fn test_retry_with_context() {
        let result = retry_with_context(
            "test_op",
            RetryPolicy::fixed(1, Duration::from_millis(1)),
            &[("user", "123")],
            || async { Ok::<_, &str>("done") },
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_retry_stats() {
        // Just verify stats don't panic
        let stats = retry_stats();
        assert!(stats.success_rate >= 0.0 && stats.success_rate <= 1.0);
    }

    #[test]
    fn test_statistics_health_with_insufficient_data() {
        // With fewer than MIN_OPERATIONS_FOR_HEALTH operations, system is considered healthy
        let stats = RetryStatistics {
            total_operations: MIN_OPERATIONS_FOR_HEALTH - 1,
            total_attempts: 5,
            total_successes: 0, // 0% success rate
            total_failures: 5,
            total_time_ms: 100,
            avg_attempts: 5.0, // Very high
            success_rate: 0.0, // Very bad
        };
        // Should still be considered healthy due to insufficient data
        assert!(stats.is_healthy());
        assert!(!stats.is_degraded());
    }

    #[test]
    fn test_statistics_degraded_detection() {
        let stats = RetryStatistics {
            total_operations: MIN_OPERATIONS_FOR_HEALTH + 10,
            total_attempts: 50,
            total_successes: 10,
            total_failures: 10,
            total_time_ms: 1000,
            avg_attempts: 2.5, // Above DEGRADED_AVG_ATTEMPTS
            success_rate: 0.5, // Below DEGRADED_SUCCESS_RATE
        };
        assert!(stats.is_degraded());
    }

    #[test]
    fn test_statistics_healthy_detection() {
        // With sufficient data and good metrics, should be healthy
        let stats = RetryStatistics {
            total_operations: MIN_OPERATIONS_FOR_HEALTH + 10,
            total_attempts: 25,
            total_successes: 20,
            total_failures: 0,
            total_time_ms: 500,
            avg_attempts: 1.25, // Below HEALTHY_AVG_ATTEMPTS
            success_rate: 0.8,  // Above HEALTHY_SUCCESS_RATE
        };
        assert!(stats.is_healthy());
        assert!(!stats.is_degraded());
    }

    #[test]
    fn test_statistics_failure_rate() {
        let stats = RetryStatistics {
            total_operations: 100,
            total_attempts: 150,
            total_successes: 70,
            total_failures: 30,
            total_time_ms: 1000,
            avg_attempts: 1.5,
            success_rate: 0.7,
        };
        // failure_rate should be 1 - success_rate
        assert!((stats.failure_rate() - 0.3).abs() < f64::EPSILON);
    }
}
