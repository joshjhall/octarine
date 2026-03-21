//! Circuit breaker with observability
//!
//! Provides circuit breaker pattern implementation with comprehensive logging,
//! metrics, and state transition events.

// Allow arithmetic operations - counters are bounded and safe
#![allow(clippy::arithmetic_side_effects)]

use crate::observe::{self, Problem, Result};
use crate::primitives::runtime::r#async::{
    CircuitBreaker as PrimitiveCircuitBreaker, CircuitBreakerConfig as PrimitiveConfig,
    CircuitState as PrimitiveState,
};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// Health Check Thresholds
// ============================================================================

/// Rejection rate threshold above which system is degraded (10%).
const DEGRADED_REJECTION_RATE: f64 = 0.1;

/// Global circuit breaker statistics
static CB_STATS: CircuitBreakerStats = CircuitBreakerStats::new();

struct CircuitBreakerStats {
    total_calls: AtomicU64,
    total_successes: AtomicU64,
    total_failures: AtomicU64,
    total_rejected: AtomicU64,
    total_trips: AtomicU64,
    total_recoveries: AtomicU64,
}

impl CircuitBreakerStats {
    const fn new() -> Self {
        Self {
            total_calls: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
            total_trips: AtomicU64::new(0),
            total_recoveries: AtomicU64::new(0),
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed (normal operation)
    Closed,
    /// Circuit is open (rejecting calls)
    Open,
    /// Circuit is half-open (testing recovery)
    HalfOpen,
}

impl From<PrimitiveState> for CircuitState {
    fn from(state: PrimitiveState) -> Self {
        match state {
            PrimitiveState::Closed => CircuitState::Closed,
            PrimitiveState::Open => CircuitState::Open,
            PrimitiveState::HalfOpen => CircuitState::HalfOpen,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Default)]
pub struct CircuitBreakerConfig {
    inner: PrimitiveConfig,
}

impl CircuitBreakerConfig {
    /// Create a new configuration with custom settings
    pub fn new(
        failure_threshold: u32,
        success_threshold: f32,
        timeout: Duration,
        window: Duration,
    ) -> Self {
        Self {
            inner: PrimitiveConfig::new()
                .with_failure_threshold(failure_threshold)
                .with_success_threshold(success_threshold)
                .with_reset_timeout(timeout)
                .with_window_duration(window),
        }
    }

    /// Configuration optimized for high availability services
    ///
    /// - Failure threshold: 3 (trip after 3 failures)
    /// - Success threshold: 80% (require strong recovery)
    /// - Timeout: 60 seconds
    /// - Window: 30 seconds
    pub fn high_availability() -> Self {
        Self {
            inner: PrimitiveConfig::high_availability(),
        }
    }

    /// Configuration optimized for database connections
    ///
    /// - Failure threshold: 10 (more tolerant)
    /// - Success threshold: 50%
    /// - Timeout: 15 seconds
    /// - Window: 60 seconds
    pub fn database() -> Self {
        Self {
            inner: PrimitiveConfig::fault_tolerant(),
        }
    }

    /// Configuration for external API calls
    ///
    /// Same as high_availability but with different name for clarity
    pub fn external_api() -> Self {
        Self {
            inner: PrimitiveConfig::high_availability(),
        }
    }

    /// Configuration for aggressive protection (fail fast)
    ///
    /// - Failure threshold: 1 (trip immediately)
    /// - Success threshold: 95% (require very strong recovery)
    /// - Timeout: 120 seconds
    /// - Window: 60 seconds
    pub fn aggressive() -> Self {
        Self {
            inner: PrimitiveConfig::aggressive(),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        self.inner.validate()
    }
}

/// Statistics about circuit breaker operations
#[derive(Debug, Clone)]
pub struct CircuitBreakerStatistics {
    /// Total calls attempted
    pub total_calls: u64,
    /// Total successful calls
    pub total_successes: u64,
    /// Total failed calls
    pub total_failures: u64,
    /// Total calls rejected (circuit open)
    pub total_rejected: u64,
    /// Total times circuit tripped open
    pub total_trips: u64,
    /// Total times circuit recovered
    pub total_recoveries: u64,
    /// Success rate (0.0 to 1.0)
    pub success_rate: f64,
    /// Rejection rate (0.0 to 1.0)
    pub rejection_rate: f64,
}

impl CircuitBreakerStatistics {
    /// Get the failure rate (0.0 to 1.0)
    pub fn failure_rate(&self) -> f64 {
        1.0 - self.success_rate
    }

    /// Get total calls that actually executed (not rejected)
    pub fn total_executed(&self) -> u64 {
        self.total_successes + self.total_failures
    }

    /// Check if circuit breakers are healthy overall
    ///
    /// Healthy if rejection rate < 5% and no recent trips
    pub fn is_healthy(&self) -> bool {
        self.rejection_rate < 0.05 && self.total_trips == 0
    }

    /// Check if circuit breakers are degraded
    ///
    /// Degraded if rejection rate > 10% or any trips occurred
    pub fn is_degraded(&self) -> bool {
        self.rejection_rate > DEGRADED_REJECTION_RATE || self.total_trips > 0
    }

    /// Calculate recovery ratio (recoveries / trips)
    ///
    /// Higher is better - indicates circuits are recovering successfully
    pub fn recovery_ratio(&self) -> f64 {
        if self.total_trips == 0 {
            return 1.0;
        }
        self.total_recoveries as f64 / self.total_trips as f64
    }
}

/// Circuit breaker with observability
///
/// Wraps operations with circuit breaker protection and comprehensive logging.
pub struct CircuitBreaker {
    name: String,
    inner: PrimitiveCircuitBreaker,
    last_state: std::sync::atomic::AtomicU8,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given name and configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(name: &str, config: CircuitBreakerConfig) -> Result<Self> {
        config.validate()?;

        observe::debug(
            "circuit_breaker_created",
            format!("Circuit breaker '{}' created", name),
        );

        Ok(Self {
            name: name.to_string(),
            inner: PrimitiveCircuitBreaker::with_config(config.inner),
            last_state: std::sync::atomic::AtomicU8::new(0), // Closed
        })
    }

    /// Create with default configuration
    ///
    /// This always succeeds as the default config is valid.
    pub fn with_defaults(name: &str) -> Self {
        // Default config is always valid, so unwrap is safe here
        #[allow(clippy::expect_used)]
        Self::new(name, CircuitBreakerConfig::default())
            .expect("Default CircuitBreakerConfig should always be valid")
    }

    /// Get the current state
    pub fn state(&self) -> CircuitState {
        self.inner.state().into()
    }

    /// Execute an operation with circuit breaker protection
    ///
    /// # Arguments
    ///
    /// * `operation_name` - Name for logging
    /// * `operation` - The async operation to execute
    ///
    /// # Returns
    ///
    /// Returns the operation result or an error if the circuit is open.
    pub async fn execute<F, Fut, T>(&self, operation_name: &str, operation: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        CB_STATS.total_calls.fetch_add(1, Ordering::Relaxed);

        // Check if circuit allows the call
        if !self.inner.can_proceed() {
            CB_STATS.total_rejected.fetch_add(1, Ordering::Relaxed);

            observe::error(
                "circuit_breaker_rejected",
                format!(
                    "{}:{}: Call rejected - circuit is {:?}",
                    self.name,
                    operation_name,
                    self.state()
                ),
            );

            return Err(Problem::OperationFailed(format!(
                "Circuit breaker '{}' is open - call to '{}' rejected",
                self.name, operation_name
            )));
        }

        // Log state transitions
        self.check_state_transition();

        let start = Instant::now();

        // Execute the operation
        match operation().await {
            Ok(value) => {
                let elapsed = start.elapsed();
                self.inner.record_success();
                CB_STATS.total_successes.fetch_add(1, Ordering::Relaxed);

                observe::trace(
                    "circuit_breaker_success",
                    format!("{}:{}: Success ({:?})", self.name, operation_name, elapsed),
                );

                // Check for recovery
                self.check_state_transition();

                Ok(value)
            }
            Err(e) => {
                let elapsed = start.elapsed();
                self.inner.record_failure();
                CB_STATS.total_failures.fetch_add(1, Ordering::Relaxed);

                observe::debug(
                    "circuit_breaker_failure",
                    format!(
                        "{}:{}: Failed ({:?}): {}",
                        self.name, operation_name, elapsed, e
                    ),
                );

                // Check for trip
                self.check_state_transition();

                Err(e)
            }
        }
    }

    /// Check and log state transitions
    fn check_state_transition(&self) {
        let current = match self.state() {
            CircuitState::Closed => 0,
            CircuitState::Open => 1,
            CircuitState::HalfOpen => 2,
        };

        let previous = self.last_state.swap(current, Ordering::SeqCst);

        if previous != current {
            let prev_state = match previous {
                0 => "Closed",
                1 => "Open",
                _ => "HalfOpen",
            };
            let curr_state = match current {
                0 => "Closed",
                1 => "Open",
                _ => "HalfOpen",
            };

            // Log transition
            let level = if current == 1 { "warn" } else { "info" };
            let msg = format!(
                "Circuit breaker '{}' state: {} -> {}",
                self.name, prev_state, curr_state
            );

            if level == "warn" {
                observe::warn("circuit_breaker_trip", &msg);
                CB_STATS.total_trips.fetch_add(1, Ordering::Relaxed);
            } else {
                observe::info("circuit_breaker_recovery", &msg);
                if current == 0 && previous == 2 {
                    CB_STATS.total_recoveries.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Check if the circuit breaker allows calls
    pub fn is_available(&self) -> bool {
        self.inner.can_proceed()
    }

    /// Check if circuit breaker is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.state(), CircuitState::Closed)
    }

    /// Check if circuit breaker is degraded
    pub fn is_degraded(&self) -> bool {
        matches!(self.state(), CircuitState::Open | CircuitState::HalfOpen)
    }
}

/// Get global circuit breaker statistics
pub fn circuit_breaker_stats() -> CircuitBreakerStatistics {
    let total_calls = CB_STATS.total_calls.load(Ordering::Relaxed);
    let total_successes = CB_STATS.total_successes.load(Ordering::Relaxed);
    let total_failures = CB_STATS.total_failures.load(Ordering::Relaxed);
    let total_rejected = CB_STATS.total_rejected.load(Ordering::Relaxed);
    let total_trips = CB_STATS.total_trips.load(Ordering::Relaxed);
    let total_recoveries = CB_STATS.total_recoveries.load(Ordering::Relaxed);

    let success_rate = if total_calls > 0 {
        total_successes as f64 / total_calls as f64
    } else {
        1.0
    };

    let rejection_rate = if total_calls > 0 {
        total_rejected as f64 / total_calls as f64
    } else {
        0.0
    };

    CircuitBreakerStatistics {
        total_calls,
        total_successes,
        total_failures,
        total_rejected,
        total_trips,
        total_recoveries,
        success_rate,
        rejection_rate,
    }
}

/// Check if circuit breakers are healthy overall
///
/// Returns true if rejection rate is below 5% and no circuits have tripped.
pub fn circuit_breakers_healthy() -> bool {
    circuit_breaker_stats().is_healthy()
}

/// Check if circuit breakers are degraded
///
/// Returns true if rejection rate exceeds 10% or any circuit has tripped.
pub fn circuit_breakers_is_degraded() -> bool {
    circuit_breaker_stats().is_degraded()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_success() {
        let cb = CircuitBreaker::with_defaults("test");

        let result = cb
            .execute("op", || async { Ok::<_, Problem>("success".to_string()) })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.expect("Result should be Ok"), "success");
        assert!(cb.is_healthy());
    }

    #[tokio::test]
    async fn test_circuit_breaker_trips() {
        let config = CircuitBreakerConfig::new(
            2,                        // failure_threshold
            0.5,                      // success_threshold (f32)
            Duration::from_secs(300), // timeout - long enough to not transition during test
            Duration::from_secs(60),  // window
        );
        let cb = CircuitBreaker::new("test_trip", config)
            .expect("Valid test config should create circuit breaker");

        // Cause failures to trip the circuit
        for _ in 0..3 {
            let _ = cb
                .execute("fail_op", || async {
                    Err::<(), _>(Problem::OperationFailed("test failure".into()))
                })
                .await;
        }

        // Circuit should be open
        assert_eq!(cb.state(), CircuitState::Open);

        // Call should be rejected while circuit is open
        let result = cb
            .execute("rejected_op", || async { Ok::<_, Problem>("success") })
            .await;

        assert!(result.is_err(), "Open circuit should reject calls");
        assert!(
            result
                .expect_err("Result should be Err when circuit is open")
                .to_string()
                .contains("rejected")
        );
    }

    #[tokio::test]
    async fn test_circuit_breaker_trips_on_failure() {
        let config = CircuitBreakerConfig::new(
            1,   // failure_threshold
            0.5, // success_threshold
            Duration::from_millis(100),
            Duration::from_secs(60),
        );
        let cb = CircuitBreaker::new("test_trip", config)
            .expect("Valid test config should create circuit breaker");

        // Trip it with a failure
        let _ = cb
            .execute("fail", || async {
                Err::<(), _>(Problem::OperationFailed("fail".into()))
            })
            .await;

        // Should be open now
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(cb.is_degraded());
    }

    #[test]
    fn test_config_presets() {
        assert!(CircuitBreakerConfig::high_availability().validate().is_ok());
        assert!(CircuitBreakerConfig::database().validate().is_ok());
        assert!(CircuitBreakerConfig::external_api().validate().is_ok());
        assert!(CircuitBreakerConfig::aggressive().validate().is_ok());
    }

    #[test]
    fn test_stats() {
        let stats = circuit_breaker_stats();
        assert!(stats.success_rate >= 0.0 && stats.success_rate <= 1.0);
    }

    #[test]
    fn test_statistics_degraded_detection() {
        // Stats with high rejection rate should be degraded
        let stats = CircuitBreakerStatistics {
            total_calls: 100,
            total_successes: 70,
            total_failures: 10,
            total_rejected: 20, // 20% rejection rate > DEGRADED_REJECTION_RATE
            total_trips: 0,
            total_recoveries: 0,
            success_rate: 0.7,
            rejection_rate: 0.2,
        };
        assert!(stats.is_degraded());

        // Stats with any trips should also be degraded
        let stats_with_trips = CircuitBreakerStatistics {
            total_calls: 100,
            total_successes: 90,
            total_failures: 10,
            total_rejected: 0,
            total_trips: 1, // Any trips make it degraded
            total_recoveries: 0,
            success_rate: 0.9,
            rejection_rate: 0.0,
        };
        assert!(stats_with_trips.is_degraded());
    }

    #[test]
    fn test_statistics_healthy_state() {
        // Stats with low rejection and no trips should be healthy
        let stats = CircuitBreakerStatistics {
            total_calls: 100,
            total_successes: 96,
            total_failures: 2,
            total_rejected: 2, // 2% < 5% threshold
            total_trips: 0,
            total_recoveries: 0,
            success_rate: 0.96,
            rejection_rate: 0.02,
        };
        assert!(stats.is_healthy());
        assert!(!stats.is_degraded());
    }
}
