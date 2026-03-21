//! Account lockout primitives (Layer 1)
//!
//! Provides brute-force protection with exponential backoff.
//! Implements OWASP ASVS V2.2 controls.

pub mod config;
mod status;

pub use config::{LockoutConfig, LockoutConfigBuilder, LockoutIdentifier};
pub use status::{FailureRecord, LockoutStatus};

use std::time::Duration;

// ============================================================================
// Lockout Decision
// ============================================================================

/// Result of a lockout check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockoutDecision {
    /// Account is not locked, authentication can proceed
    Allowed,
    /// Account is locked, authentication should be rejected
    Locked {
        /// When the lockout expires
        until: std::time::Instant,
        /// Remaining lockout duration
        remaining: Duration,
        /// Number of consecutive failures
        failure_count: u32,
    },
}

impl LockoutDecision {
    /// Check if authentication is allowed
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Check if account is locked
    #[must_use]
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked { .. })
    }

    /// Get remaining lockout duration if locked
    #[must_use]
    pub fn remaining_duration(&self) -> Option<Duration> {
        match self {
            Self::Locked { remaining, .. } => Some(*remaining),
            Self::Allowed => None,
        }
    }
}

// ============================================================================
// Lockout Logic
// ============================================================================

/// Evaluate lockout status and decide whether access should be allowed
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // Safe: adding duration to instant
pub fn evaluate_lockout(status: &LockoutStatus, config: &LockoutConfig) -> LockoutDecision {
    // If currently locked, check if lockout has expired
    if let Some(locked_until) = status.locked_until {
        let now = std::time::Instant::now();
        if now < locked_until {
            return LockoutDecision::Locked {
                until: locked_until,
                remaining: locked_until.duration_since(now),
                failure_count: status.consecutive_failures,
            };
        }
        // Lockout has expired, account is unlocked
    }

    // Check if we should apply a new lockout based on failures in window
    let recent_failures = status.failures_in_window(config.attempt_window);

    if recent_failures >= config.max_attempts {
        // Calculate lockout duration with exponential backoff
        let lockout_duration = calculate_backoff_duration(
            status.consecutive_failures,
            config.base_lockout_duration,
            config.max_lockout_duration,
            config.backoff_multiplier,
        );

        let locked_until = std::time::Instant::now() + lockout_duration;

        return LockoutDecision::Locked {
            until: locked_until,
            remaining: lockout_duration,
            failure_count: status.consecutive_failures,
        };
    }

    LockoutDecision::Allowed
}

/// Calculate backoff duration with exponential growth
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // Safe: bounded by max_duration
pub fn calculate_backoff_duration(
    failure_count: u32,
    base_duration: Duration,
    max_duration: Duration,
    multiplier: f32,
) -> Duration {
    if failure_count == 0 {
        return base_duration;
    }

    // Calculate exponential backoff: base * multiplier^(failures-1)
    // Cap the exponent to prevent overflow
    let exponent = failure_count.saturating_sub(1).min(20);
    let factor = multiplier.powi(exponent as i32);

    let base_millis = base_duration.as_millis() as f64;
    let result_millis = (base_millis * factor as f64).min(max_duration.as_millis() as f64);

    Duration::from_millis(result_millis as u64)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_lockout_decision_allowed() {
        let decision = LockoutDecision::Allowed;
        assert!(decision.is_allowed());
        assert!(!decision.is_locked());
        assert!(decision.remaining_duration().is_none());
    }

    #[test]
    fn test_lockout_decision_locked() {
        let decision = LockoutDecision::Locked {
            until: std::time::Instant::now() + Duration::from_secs(60),
            remaining: Duration::from_secs(60),
            failure_count: 5,
        };
        assert!(!decision.is_allowed());
        assert!(decision.is_locked());
        assert!(decision.remaining_duration().is_some());
    }

    #[test]
    fn test_calculate_backoff_duration() {
        let base = Duration::from_secs(60);
        let max = Duration::from_secs(3600);
        let multiplier = 2.0;

        // First failure: base duration
        assert_eq!(calculate_backoff_duration(0, base, max, multiplier), base);
        assert_eq!(calculate_backoff_duration(1, base, max, multiplier), base);

        // Second failure: base * 2
        let second = calculate_backoff_duration(2, base, max, multiplier);
        assert_eq!(second, Duration::from_secs(120));

        // Third failure: base * 4
        let third = calculate_backoff_duration(3, base, max, multiplier);
        assert_eq!(third, Duration::from_secs(240));

        // Should cap at max
        let capped = calculate_backoff_duration(20, base, max, multiplier);
        assert_eq!(capped, max);
    }

    #[test]
    fn test_evaluate_lockout_allowed() {
        let status = LockoutStatus::new();
        let config = LockoutConfig::default();

        let decision = evaluate_lockout(&status, &config);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_evaluate_lockout_after_max_failures() {
        let config = LockoutConfig::default();
        let mut status = LockoutStatus::new();

        // Record max_attempts failures
        for _ in 0..config.max_attempts {
            status.record_failure();
        }

        let decision = evaluate_lockout(&status, &config);
        assert!(decision.is_locked());
    }
}
