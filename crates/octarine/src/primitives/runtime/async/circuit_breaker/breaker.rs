//! Circuit breaker implementation
//!
//! Core circuit breaker for protecting against cascading failures.

use parking_lot::RwLock;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use super::config::CircuitBreakerConfig;
use super::state::CircuitState;
use super::stats::CircuitBreakerStats;
use crate::primitives::{Problem, Result};

/// Circuit breaker for protecting against cascading failures
///
/// The circuit breaker monitors operations and automatically stops calling
/// failing services to prevent cascading failures. After a timeout, it tests
/// if the service has recovered.
///
/// This is a **primitive** implementation with no observe dependencies.
/// Higher layers can wrap this with metrics and logging.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
///
/// let breaker = CircuitBreaker::new();
///
/// // Execute operation through circuit breaker
/// let result = breaker.execute(async {
///     // Your async operation here
///     Ok::<_, octarine::primitives::Problem>("success")
/// }).await;
///
/// // Check if circuit allows requests
/// if breaker.can_proceed() {
///     // Execute operation
/// }
/// ```
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<AtomicU32>,
    success_count: Arc<AtomicU32>,
    total_count: Arc<AtomicU64>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    window_start: Arc<RwLock<Instant>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default configuration
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
    ///
    /// let config = CircuitBreakerConfig::high_availability();
    /// let breaker = CircuitBreaker::with_config(config);
    /// ```
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(AtomicU32::new(0)),
            success_count: Arc::new(AtomicU32::new(0)),
            total_count: Arc::new(AtomicU64::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            window_start: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Get the current state of the circuit breaker
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Check if the circuit breaker allows requests to proceed
    ///
    /// Returns true if requests should be allowed, false if they should be rejected.
    pub fn can_proceed(&self) -> bool {
        self.transition_state_if_needed();

        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state (every 10th request)
                self.total_count.load(Ordering::Relaxed).is_multiple_of(10)
            }
        }
    }

    /// Execute an operation through the circuit breaker
    ///
    /// If the circuit is open, returns an error immediately without executing.
    /// Otherwise, executes the operation and records success/failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::circuit_breaker::CircuitBreaker;
    ///
    /// let breaker = CircuitBreaker::new();
    ///
    /// let result = breaker.execute(async {
    ///     // Call external service
    ///     call_service().await
    /// }).await;
    /// ```
    pub async fn execute<F, T>(&self, f: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        // Check state and potentially transition
        self.transition_state_if_needed();

        // Check if we can proceed
        if !self.can_proceed() {
            let state = self.state();
            return Err(Problem::OperationFailed(format!(
                "Circuit is {:?}, requests are being rejected",
                state
            )));
        }

        // Execute the operation
        self.total_count.fetch_add(1, Ordering::Relaxed);

        match f.await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(err) => {
                self.record_failure();
                Err(err)
            }
        }
    }

    /// Record a successful operation
    ///
    /// Call this after a successful operation if not using `execute()`.
    pub fn record_success(&self) {
        self.success_count.fetch_add(1, Ordering::Relaxed);

        // Check if we should close from half-open
        if self.state() == CircuitState::HalfOpen {
            let success = self.success_count.load(Ordering::Relaxed);
            let total = self.get_window_count();

            if total >= self.config.min_requests {
                let success_rate = success as f32 / total as f32;
                if success_rate >= self.config.success_threshold {
                    self.close();
                }
            }
        }
    }

    /// Record a failed operation
    ///
    /// Call this after a failed operation if not using `execute()`.
    pub fn record_failure(&self) {
        let failure_count = self
            .failure_count
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        *self.last_failure_time.write() = Some(Instant::now());

        // Check if we should open the circuit
        if failure_count >= self.config.failure_threshold {
            self.open();
        }
    }

    /// Get current statistics for the circuit breaker
    #[allow(dead_code)] // API method for future use
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            state: self.state(),
            failure_count: self.failure_count.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
            total_count: self.total_count.load(Ordering::Relaxed),
            success_rate: {
                let total = self.get_window_count();
                if total > 0 {
                    self.success_count.load(Ordering::Relaxed) as f32 / total as f32
                } else {
                    1.0
                }
            },
        }
    }

    /// Open the circuit (reject all requests)
    fn open(&self) {
        let mut state = self.state.write();
        if *state != CircuitState::Open {
            *state = CircuitState::Open;
        }
    }

    /// Close the circuit (allow all requests)
    fn close(&self) {
        let mut state = self.state.write();
        if *state != CircuitState::Closed {
            *state = CircuitState::Closed;
            self.reset_counts();
        }
    }

    /// Transition to half-open state
    fn half_open(&self) {
        let mut state = self.state.write();
        if *state == CircuitState::Open {
            *state = CircuitState::HalfOpen;
            self.reset_counts();
        }
    }

    /// Check and update state based on current conditions
    pub(crate) fn transition_state_if_needed(&self) {
        // Reset window if needed
        self.reset_window_if_expired();

        match self.state() {
            CircuitState::Open => {
                // Check if we should try half-open
                if let Some(last_failure) = *self.last_failure_time.read()
                    && last_failure.elapsed() >= self.config.reset_timeout
                {
                    self.half_open();
                }
            }
            CircuitState::HalfOpen => {
                // State transitions handled in record_success/failure
            }
            CircuitState::Closed => {
                // Check failure threshold
                let failures = self.failure_count.load(Ordering::Relaxed);
                if failures >= self.config.failure_threshold {
                    self.open();
                }
            }
        }
    }

    /// Check if window should be reset
    fn reset_window_if_expired(&self) {
        let mut window_start = self.window_start.write();
        if window_start.elapsed() >= self.config.window_duration {
            *window_start = Instant::now();
            self.reset_counts();
        }
    }

    /// Reset counts
    fn reset_counts(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
    }

    /// Get count within current window
    fn get_window_count(&self) -> u32 {
        self.success_count
            .load(Ordering::Relaxed)
            .saturating_add(self.failure_count.load(Ordering::Relaxed))
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CircuitBreaker {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            failure_count: Arc::clone(&self.failure_count),
            success_count: Arc::clone(&self.success_count),
            total_count: Arc::clone(&self.total_count),
            last_failure_time: Arc::clone(&self.last_failure_time),
            window_start: Arc::clone(&self.window_start),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_circuit_breaker_new() {
        let cb = CircuitBreaker::new();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.can_proceed());
    }

    #[test]
    fn test_circuit_breaker_record_success() {
        let cb = CircuitBreaker::new();
        cb.record_success();
        cb.record_success();

        let stats = cb.stats();
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.failure_count, 0);
    }

    #[test]
    fn test_circuit_breaker_record_failure() {
        let cb = CircuitBreaker::new();
        cb.record_failure();
        cb.record_failure();

        let stats = cb.stats();
        assert_eq!(stats.failure_count, 2);
        assert_eq!(stats.success_count, 0);
    }

    #[test]
    fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig::new().with_failure_threshold(3);
        let cb = CircuitBreaker::with_config(config);

        // Record failures up to threshold
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure(); // This should trigger open
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_proceed());
    }

    #[tokio::test]
    async fn test_circuit_breaker_execute_success() {
        let cb = CircuitBreaker::new();

        let result = cb.execute(async { Ok::<_, Problem>("success") }).await;

        assert!(result.is_ok());
        assert_eq!(result.expect("Expected success"), "success");

        let stats = cb.stats();
        assert_eq!(stats.success_count, 1);
        assert_eq!(stats.total_count, 1);
    }

    #[tokio::test]
    async fn test_circuit_breaker_execute_failure() {
        let cb = CircuitBreaker::new();

        let result: Result<()> = cb
            .execute(async { Err(Problem::OperationFailed("test failure".into())) })
            .await;

        assert!(result.is_err());

        let stats = cb.stats();
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.total_count, 1);
    }

    #[tokio::test]
    async fn test_circuit_breaker_rejects_when_open() {
        let config = CircuitBreakerConfig::new().with_failure_threshold(2);
        let cb = CircuitBreaker::with_config(config);

        // Open the circuit
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Should reject without executing
        let result = cb
            .execute(async { Ok::<_, Problem>("should not run") })
            .await;

        assert!(result.is_err());
        let err = result.expect_err("Expected circuit open error");
        assert!(err.to_string().contains("Circuit"));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_transition() {
        use std::time::Duration;

        let config = CircuitBreakerConfig::new()
            .with_failure_threshold(2)
            .with_reset_timeout(Duration::from_millis(10));
        let cb = CircuitBreaker::with_config(config);

        // Open the circuit
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Check state should transition to half-open
        cb.transition_state_if_needed();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_breaker_stats() {
        let cb = CircuitBreaker::new();

        cb.record_success();
        cb.record_success();
        cb.record_failure();

        let stats = cb.stats();
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.failure_count, 1);
        assert!(stats.success_rate > 0.6);
        assert!(stats.is_healthy());
    }

    #[test]
    fn test_circuit_breaker_clone_shares_state() {
        let cb1 = CircuitBreaker::new();
        let cb2 = cb1.clone();

        cb1.record_failure();

        // Both should see the same state
        assert_eq!(cb1.stats().failure_count, 1);
        assert_eq!(cb2.stats().failure_count, 1);
    }

    #[test]
    fn test_circuit_breaker_default() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_with_preset() {
        let config = CircuitBreakerConfig::high_availability();
        let cb = CircuitBreaker::with_config(config);

        // Should open after 3 failures
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
