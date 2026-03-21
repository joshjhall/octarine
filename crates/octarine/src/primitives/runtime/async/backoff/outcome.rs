//! Retry outcome types
//!
//! Represents the result of a retry operation.

use super::stats::RetryStats;
use crate::primitives::{Problem, Result};

/// Outcome of a retry operation
///
/// Represents the final state after a retry sequence completes, including
/// whether it succeeded, failed after exhausting attempts, or timed out.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::backoff::RetryOutcome;
///
/// let outcome = RetryOutcome::Success {
///     value: 42,
///     stats: RetryStats::default(),
/// };
///
/// assert!(outcome.is_success());
/// assert_eq!(outcome.into_value(), Some(42));
/// ```
#[derive(Debug)]
pub enum RetryOutcome<T> {
    /// Operation succeeded
    Success {
        /// The successful result
        value: T,
        /// Statistics about the retry attempts
        stats: RetryStats,
    },

    /// All attempts exhausted without success
    Exhausted {
        /// The last error message
        last_error: String,
        /// Statistics about the retry attempts
        stats: RetryStats,
    },

    /// Total time limit exceeded
    TimedOut {
        /// Statistics about the retry attempts before timeout
        stats: RetryStats,
    },
}

impl<T> RetryOutcome<T> {
    /// Returns true if the operation succeeded
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, RetryOutcome::Success { .. })
    }

    /// Returns true if all attempts were exhausted
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        matches!(self, RetryOutcome::Exhausted { .. })
    }

    /// Returns true if the operation timed out
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        matches!(self, RetryOutcome::TimedOut { .. })
    }

    /// Returns the value if successful, None otherwise
    #[must_use]
    pub fn into_value(self) -> Option<T> {
        match self {
            RetryOutcome::Success { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Returns the stats regardless of outcome
    #[must_use]
    pub fn stats(&self) -> &RetryStats {
        match self {
            RetryOutcome::Success { stats, .. }
            | RetryOutcome::Exhausted { stats, .. }
            | RetryOutcome::TimedOut { stats } => stats,
        }
    }

    /// Convert to Result, using Problem::Runtime for failures
    pub fn into_result(self) -> Result<T> {
        match self {
            RetryOutcome::Success { value, .. } => Ok(value),
            RetryOutcome::Exhausted {
                last_error, stats, ..
            } => Err(Problem::Runtime(format!(
                "All {} attempts failed. Last error: {}",
                stats.attempts, last_error
            ))),
            RetryOutcome::TimedOut { stats } => Err(Problem::Runtime(format!(
                "Retry timed out after {} attempts ({:?})",
                stats.attempts, stats.total_duration
            ))),
        }
    }
}

impl<T> std::fmt::Display for RetryOutcome<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetryOutcome::Success { stats, .. } => {
                write!(f, "Success after {} attempt(s)", stats.attempts)
            }
            RetryOutcome::Exhausted {
                last_error, stats, ..
            } => {
                write!(
                    f,
                    "Exhausted after {} attempt(s): {}",
                    stats.attempts, last_error
                )
            }
            RetryOutcome::TimedOut { stats } => {
                write!(
                    f,
                    "Timed out after {} attempt(s) ({:?})",
                    stats.attempts, stats.total_duration
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_retry_outcome_success() {
        let stats = RetryStats {
            attempts: 2,
            succeeded: true,
            ..Default::default()
        };

        let outcome = RetryOutcome::Success {
            value: 42,
            stats: stats.clone(),
        };

        assert!(outcome.is_success());
        assert!(!outcome.is_exhausted());
        assert!(!outcome.is_timed_out());
        assert_eq!(outcome.stats().attempts, 2);
        assert_eq!(outcome.into_value(), Some(42));
    }

    #[test]
    fn test_retry_outcome_exhausted() {
        let stats = RetryStats {
            attempts: 3,
            succeeded: false,
            ..Default::default()
        };

        let outcome: RetryOutcome<i32> = RetryOutcome::Exhausted {
            last_error: "connection failed".into(),
            stats,
        };

        assert!(!outcome.is_success());
        assert!(outcome.is_exhausted());
        assert!(!outcome.is_timed_out());
        assert_eq!(outcome.into_value(), None);
    }

    #[test]
    fn test_retry_outcome_timed_out() {
        let stats = RetryStats {
            attempts: 2,
            total_duration: Duration::from_secs(60),
            ..Default::default()
        };

        let outcome: RetryOutcome<i32> = RetryOutcome::TimedOut { stats };

        assert!(!outcome.is_success());
        assert!(!outcome.is_exhausted());
        assert!(outcome.is_timed_out());
        assert_eq!(outcome.stats().total_duration, Duration::from_secs(60));
    }

    #[test]
    fn test_retry_outcome_into_result_success() {
        let outcome: RetryOutcome<i32> = RetryOutcome::Success {
            value: 42,
            stats: RetryStats::default(),
        };
        let result = outcome.into_result();
        assert!(result.is_ok());
        assert_eq!(result.expect("should succeed"), 42);
    }

    #[test]
    fn test_retry_outcome_into_result_exhausted() {
        let outcome: RetryOutcome<i32> = RetryOutcome::Exhausted {
            last_error: "test error".into(),
            stats: RetryStats {
                attempts: 3,
                ..Default::default()
            },
        };
        let result = outcome.into_result();
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("All 3 attempts failed"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_retry_outcome_into_result_timed_out() {
        let outcome: RetryOutcome<i32> = RetryOutcome::TimedOut {
            stats: RetryStats {
                attempts: 2,
                total_duration: Duration::from_secs(60),
                ..Default::default()
            },
        };
        let result = outcome.into_result();
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("timed out"));
        assert!(err.to_string().contains("2 attempts"));
    }

    #[test]
    fn test_retry_outcome_display() {
        // Success
        let success: RetryOutcome<i32> = RetryOutcome::Success {
            value: 42,
            stats: RetryStats {
                attempts: 3,
                ..Default::default()
            },
        };
        assert_eq!(success.to_string(), "Success after 3 attempt(s)");

        // Exhausted
        let exhausted: RetryOutcome<i32> = RetryOutcome::Exhausted {
            last_error: "connection failed".into(),
            stats: RetryStats {
                attempts: 5,
                ..Default::default()
            },
        };
        assert_eq!(
            exhausted.to_string(),
            "Exhausted after 5 attempt(s): connection failed"
        );

        // Timed out
        let timed_out: RetryOutcome<i32> = RetryOutcome::TimedOut {
            stats: RetryStats {
                attempts: 2,
                total_duration: Duration::from_secs(60),
                ..Default::default()
            },
        };
        assert!(
            timed_out
                .to_string()
                .contains("Timed out after 2 attempt(s)")
        );
    }
}
