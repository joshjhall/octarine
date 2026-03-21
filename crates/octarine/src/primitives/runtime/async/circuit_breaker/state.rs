//! Circuit breaker state
//!
//! Represents the three states in the circuit breaker state machine.

/// State of the circuit breaker
///
/// Represents the three states in the circuit breaker state machine:
/// - **Closed**: Normal operation, requests flow through
/// - **Open**: Circuit tripped, requests are rejected immediately
/// - **HalfOpen**: Testing if service recovered, limited requests allowed
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::circuit_breaker::CircuitState;
///
/// let state = CircuitState::Closed;
/// assert!(state.allows_requests());
///
/// let state = CircuitState::Open;
/// assert!(!state.allows_requests());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally
    ///
    /// This is the healthy state where all requests are allowed through.
    /// Failures are counted, and if they exceed the threshold, the circuit opens.
    Closed,

    /// Circuit is open, requests are rejected
    ///
    /// This state prevents further load on a failing service.
    /// After the reset timeout, transitions to HalfOpen to test recovery.
    Open,

    /// Circuit is half-open, testing if service recovered
    ///
    /// Limited requests are allowed through to test service health.
    /// Success leads to Closed; failure leads back to Open.
    HalfOpen,
}

impl CircuitState {
    /// Check if this state allows requests to proceed
    ///
    /// - Closed: Always allows
    /// - Open: Never allows
    /// - HalfOpen: Allows limited requests (implementation decides)
    pub fn allows_requests(&self) -> bool {
        match self {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => true, // Limited by implementation
        }
    }

    /// Get numeric value for metrics (0=Closed, 1=HalfOpen, 2=Open)
    pub fn as_metric_value(&self) -> f64 {
        match self {
            CircuitState::Closed => 0.0,
            CircuitState::HalfOpen => 1.0,
            CircuitState::Open => 2.0,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_circuit_state_allows_requests() {
        assert!(CircuitState::Closed.allows_requests());
        assert!(!CircuitState::Open.allows_requests());
        assert!(CircuitState::HalfOpen.allows_requests());
    }

    #[test]
    fn test_circuit_state_metric_values() {
        assert_eq!(CircuitState::Closed.as_metric_value(), 0.0);
        assert_eq!(CircuitState::HalfOpen.as_metric_value(), 1.0);
        assert_eq!(CircuitState::Open.as_metric_value(), 2.0);
    }

    #[test]
    fn test_circuit_state_equality() {
        assert_eq!(CircuitState::Closed, CircuitState::Closed);
        assert_ne!(CircuitState::Closed, CircuitState::Open);
        assert_ne!(CircuitState::Open, CircuitState::HalfOpen);
    }
}
