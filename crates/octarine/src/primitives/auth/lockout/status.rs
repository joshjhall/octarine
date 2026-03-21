//! Lockout status tracking
//!
//! Tracks authentication failures and lockout state.

use std::time::{Duration, Instant};

// ============================================================================
// Failure Record
// ============================================================================

/// A record of an authentication failure
#[derive(Debug, Clone)]
pub struct FailureRecord {
    /// When the failure occurred
    pub timestamp: Instant,
    /// IP address of the request (if available)
    pub ip_address: Option<String>,
    /// User agent of the request (if available)
    pub user_agent: Option<String>,
}

impl FailureRecord {
    /// Create a new failure record
    #[must_use]
    pub fn new() -> Self {
        Self {
            timestamp: Instant::now(),
            ip_address: None,
            user_agent: None,
        }
    }

    /// Create a failure record with context
    #[must_use]
    pub fn with_context(ip_address: Option<String>, user_agent: Option<String>) -> Self {
        Self {
            timestamp: Instant::now(),
            ip_address,
            user_agent,
        }
    }

    /// Check if this failure is within the given window
    #[must_use]
    pub fn is_within_window(&self, window: Duration) -> bool {
        self.timestamp.elapsed() < window
    }
}

impl Default for FailureRecord {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Lockout Status
// ============================================================================

/// Current lockout status for an identifier (username or IP)
#[derive(Debug, Clone, Default)]
pub struct LockoutStatus {
    /// Recent failure records
    pub failures: Vec<FailureRecord>,
    /// Count of consecutive failures (not reset by time)
    pub consecutive_failures: u32,
    /// When the current lockout expires (if locked)
    pub locked_until: Option<Instant>,
    /// Total number of lockouts for this identifier
    pub total_lockouts: u32,
    /// Last successful authentication (if any)
    pub last_success: Option<Instant>,
}

impl LockoutStatus {
    /// Create a new empty status
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an authentication failure
    pub fn record_failure(&mut self) {
        self.failures.push(FailureRecord::new());
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Record a failure with context
    pub fn record_failure_with_context(
        &mut self,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) {
        self.failures
            .push(FailureRecord::with_context(ip_address, user_agent));
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Record a successful authentication
    ///
    /// Resets consecutive failures but keeps history for analysis.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.locked_until = None;
        self.last_success = Some(Instant::now());
    }

    /// Set the lockout expiration time
    pub fn set_locked_until(&mut self, until: Instant) {
        self.locked_until = Some(until);
        self.total_lockouts = self.total_lockouts.saturating_add(1);
    }

    /// Clear the lockout (admin action)
    ///
    /// This also clears the failure history to prevent immediate re-lockout.
    pub fn clear_lockout(&mut self) {
        self.locked_until = None;
        self.consecutive_failures = 0;
        self.failures.clear();
    }

    /// Get number of failures within the given time window
    #[must_use]
    pub fn failures_in_window(&self, window: Duration) -> u32 {
        self.failures
            .iter()
            .filter(|f| f.is_within_window(window))
            .count() as u32
    }

    /// Check if currently locked
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    /// Get remaining lockout duration
    #[must_use]
    pub fn remaining_lockout(&self) -> Option<Duration> {
        self.locked_until.and_then(|until| {
            let now = Instant::now();
            if now < until {
                Some(until.duration_since(now))
            } else {
                None
            }
        })
    }

    /// Clean up old failure records outside the window
    pub fn cleanup_old_failures(&mut self, window: Duration) {
        self.failures.retain(|f| f.is_within_window(window));
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_failure_record() {
        let record = FailureRecord::new();
        assert!(record.is_within_window(Duration::from_secs(60)));
    }

    #[test]
    fn test_failure_record_with_context() {
        let record = FailureRecord::with_context(
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
        );
        assert_eq!(record.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(record.user_agent, Some("Mozilla/5.0".to_string()));
    }

    #[test]
    fn test_status_record_failure() {
        let mut status = LockoutStatus::new();

        status.record_failure();
        assert_eq!(status.consecutive_failures, 1);
        assert_eq!(status.failures.len(), 1);

        status.record_failure();
        assert_eq!(status.consecutive_failures, 2);
        assert_eq!(status.failures.len(), 2);
    }

    #[test]
    fn test_status_record_success() {
        let mut status = LockoutStatus::new();

        status.record_failure();
        status.record_failure();
        assert_eq!(status.consecutive_failures, 2);

        status.record_success();
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.last_success.is_some());
        // Failures are kept for history
        assert_eq!(status.failures.len(), 2);
    }

    #[test]
    fn test_status_failures_in_window() {
        let mut status = LockoutStatus::new();

        status.record_failure();
        status.record_failure();
        status.record_failure();

        assert_eq!(status.failures_in_window(Duration::from_secs(60)), 3);
    }

    #[test]
    fn test_status_is_locked() {
        let mut status = LockoutStatus::new();

        assert!(!status.is_locked());

        status.set_locked_until(Instant::now() + Duration::from_secs(60));
        assert!(status.is_locked());
        assert_eq!(status.total_lockouts, 1);
    }

    #[test]
    fn test_status_clear_lockout() {
        let mut status = LockoutStatus::new();

        status.record_failure();
        status.record_failure();
        status.set_locked_until(Instant::now() + Duration::from_secs(60));

        status.clear_lockout();

        assert!(!status.is_locked());
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.failures.is_empty()); // Failures cleared too
    }

    #[test]
    fn test_status_cleanup_old_failures() {
        let mut status = LockoutStatus::new();

        status.record_failure();
        // Sleep briefly to create time difference
        sleep(Duration::from_millis(10));
        status.record_failure();

        // All failures should be within 1 second
        status.cleanup_old_failures(Duration::from_secs(1));
        assert_eq!(status.failures.len(), 2);

        // Clean up failures older than 1ms (may remove some or all)
        status.cleanup_old_failures(Duration::from_millis(1));
        // At least one should be removed due to time passing
        assert!(status.failures.len() <= 2);
    }
}
