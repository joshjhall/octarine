//! Circuit breaker statistics
//!
//! Provides a snapshot of current circuit breaker state and counters.

use super::state::CircuitState;

/// Statistics for circuit breaker
///
/// Provides a snapshot of current circuit breaker state and counters.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::circuit_breaker::{CircuitBreakerStats, CircuitState};
///
/// let stats = CircuitBreakerStats {
///     state: CircuitState::Closed,
///     failure_count: 2,
///     success_count: 10,
///     total_count: 12,
///     success_rate: 0.833,
/// };
///
/// assert!(stats.is_healthy());
/// ```
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    /// Current state of the circuit
    pub state: CircuitState,

    /// Number of failures in current window
    pub failure_count: u32,

    /// Number of successes in current window
    pub success_count: u32,

    /// Total number of operations ever executed
    pub total_count: u64,

    /// Current success rate (0.0 to 1.0)
    pub success_rate: f32,
}

impl CircuitBreakerStats {
    /// Check if circuit is in a healthy state
    pub fn is_healthy(&self) -> bool {
        self.state == CircuitState::Closed
    }

    /// Check if circuit is tripped (open or half-open)
    pub fn is_tripped(&self) -> bool {
        self.state != CircuitState::Closed
    }

    /// Get failure rate (1.0 - success_rate)
    pub fn failure_rate(&self) -> f32 {
        1.0 - self.success_rate
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_stats_is_healthy() {
        let healthy = CircuitBreakerStats {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 10,
            total_count: 10,
            success_rate: 1.0,
        };
        assert!(healthy.is_healthy());
        assert!(!healthy.is_tripped());

        let tripped = CircuitBreakerStats {
            state: CircuitState::Open,
            failure_count: 5,
            success_count: 0,
            total_count: 5,
            success_rate: 0.0,
        };
        assert!(!tripped.is_healthy());
        assert!(tripped.is_tripped());
    }

    #[test]
    fn test_stats_failure_rate() {
        let stats = CircuitBreakerStats {
            state: CircuitState::Closed,
            failure_count: 2,
            success_count: 8,
            total_count: 10,
            success_rate: 0.8,
        };
        assert!((stats.failure_rate() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_stats_clone() {
        let stats1 = CircuitBreakerStats {
            state: CircuitState::HalfOpen,
            failure_count: 3,
            success_count: 7,
            total_count: 100,
            success_rate: 0.7,
        };
        let stats2 = stats1.clone();
        assert_eq!(stats1.state, stats2.state);
        assert_eq!(stats1.total_count, stats2.total_count);
    }
}
