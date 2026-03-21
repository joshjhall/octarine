//! Rate limiter types
//!
//! Core types for rate limiting operations.

#![allow(dead_code)] // Layer 1 primitives - will be used by Layer 3

use std::time::Duration;
use thiserror::Error;

/// Decision from a rate limit check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Request is allowed
    Allow,
    /// Request is denied - should wait before retrying
    Deny {
        /// How long to wait before retrying
        retry_after: Duration,
    },
}

impl Decision {
    /// Returns true if the request is allowed
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Returns true if the request is denied
    #[inline]
    pub fn is_denied(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    /// Returns the retry-after duration if denied, None if allowed
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Decision::Allow => None,
            Decision::Deny { retry_after } => Some(*retry_after),
        }
    }
}

/// Error type for rate limiter operations
#[derive(Debug, Error)]
pub enum RateLimitError {
    /// Invalid quota configuration
    #[error("invalid quota: {message}")]
    InvalidQuota {
        /// Description of what made the quota invalid
        message: String,
    },

    /// Rate limiter is not available
    #[error("rate limiter unavailable: {message}")]
    Unavailable {
        /// Description of why the limiter is unavailable
        message: String,
    },
}

impl RateLimitError {
    /// Create an invalid quota error
    pub fn invalid_quota(message: impl Into<String>) -> Self {
        Self::InvalidQuota {
            message: message.into(),
        }
    }

    /// Create an unavailable error
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable {
            message: message.into(),
        }
    }
}

impl From<RateLimitError> for crate::primitives::types::Problem {
    fn from(err: RateLimitError) -> Self {
        match err {
            RateLimitError::InvalidQuota { message } => {
                Self::Config(format!("rate limit quota: {message}"))
            }
            RateLimitError::Unavailable { message } => {
                Self::OperationFailed(format!("rate limiter: {message}"))
            }
        }
    }
}

/// Statistics for a rate limiter
#[derive(Debug, Clone, Default)]
pub struct RateLimiterStats {
    /// Total number of checks performed
    pub total_checks: u64,
    /// Number of allowed requests
    pub allowed: u64,
    /// Number of denied requests
    pub denied: u64,
}

impl RateLimiterStats {
    /// Calculate the denial rate (0.0 to 1.0)
    pub fn denial_rate(&self) -> f64 {
        if self.total_checks == 0 {
            0.0
        } else {
            self.denied as f64 / self.total_checks as f64
        }
    }

    /// Calculate the allow rate (0.0 to 1.0)
    pub fn allow_rate(&self) -> f64 {
        if self.total_checks == 0 {
            1.0
        } else {
            self.allowed as f64 / self.total_checks as f64
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_decision_allow() {
        let decision = Decision::Allow;
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(decision.retry_after().is_none());
    }

    #[test]
    fn test_decision_deny() {
        let decision = Decision::Deny {
            retry_after: Duration::from_secs(5),
        };
        assert!(!decision.is_allowed());
        assert!(decision.is_denied());
        assert_eq!(decision.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn test_stats_rates() {
        let stats = RateLimiterStats {
            total_checks: 100,
            allowed: 80,
            denied: 20,
        };
        assert!((stats.denial_rate() - 0.2).abs() < f64::EPSILON);
        assert!((stats.allow_rate() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stats_empty() {
        let stats = RateLimiterStats::default();
        assert!((stats.denial_rate() - 0.0).abs() < f64::EPSILON);
        assert!((stats.allow_rate() - 1.0).abs() < f64::EPSILON);
    }
}
