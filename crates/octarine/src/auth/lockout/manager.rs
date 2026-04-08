//! Lockout manager with observe integration
//!
//! Provides account lockout management with audit logging.

use std::sync::Arc;

use crate::observe;
use crate::primitives::auth::lockout::{
    LockoutConfig, LockoutDecision, LockoutStatus, calculate_backoff_duration, evaluate_lockout,
};
use crate::primitives::types::Problem;

use super::store::LockoutStore;

// ============================================================================
// Lockout Manager
// ============================================================================

/// Lockout manager with audit logging
///
/// Manages account lockout with automatic observe events for compliance.
pub struct LockoutManager<S: LockoutStore> {
    /// Lockout storage backend
    store: Arc<S>,
    /// Lockout configuration
    config: LockoutConfig,
}

impl<S: LockoutStore> LockoutManager<S> {
    /// Create a new lockout manager with the given store and config
    pub fn new(store: Arc<S>, config: LockoutConfig) -> Self {
        Self { store, config }
    }

    /// Check if an identifier is locked out
    ///
    /// Returns the lockout decision without recording any events.
    ///
    /// # Audit Events
    ///
    /// - `auth.lockout.checked` (DEBUG)
    pub fn check(&self, identifier: &str) -> Result<LockoutDecision, Problem> {
        let status = self.store.get(identifier)?;
        let decision = evaluate_lockout(&status, &self.config);

        observe::debug(
            "auth.lockout.checked",
            format!(
                "Lockout check for {}: {}",
                identifier,
                if decision.is_locked() {
                    "locked"
                } else {
                    "allowed"
                }
            ),
        );

        Ok(decision)
    }

    /// Record an authentication failure
    ///
    /// Updates the failure count and potentially triggers a lockout.
    ///
    /// # Audit Events
    ///
    /// - `auth.lockout.failure_recorded` (INFO)
    /// - `auth.lockout.triggered` (WARN) if lockout is triggered
    pub fn record_failure(&self, identifier: &str) -> Result<LockoutDecision, Problem> {
        self.record_failure_with_context(identifier, None, None)
    }

    /// Record an authentication failure with context
    ///
    /// # Arguments
    ///
    /// * `identifier` - Username or IP to record failure for
    /// * `ip_address` - Client IP address (for logging)
    /// * `user_agent` - Client user agent (for logging)
    pub fn record_failure_with_context(
        &self,
        identifier: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LockoutDecision, Problem> {
        let mut status = self.store.get(identifier)?;

        // Record the failure
        status.record_failure_with_context(
            ip_address.map(String::from),
            user_agent.map(String::from),
        );

        // Check if we should trigger a lockout
        let decision = evaluate_lockout(&status, &self.config);

        // If locked, update the locked_until timestamp
        if let LockoutDecision::Locked { until, .. } = &decision {
            status.set_locked_until(*until);
        }

        // Save updated status
        self.store.update(identifier, &status)?;

        // Log the failure
        observe::info(
            "auth.lockout.failure_recorded",
            format!(
                "Authentication failure for {} (attempt {} in window, {} consecutive)",
                identifier,
                status.failures_in_window(self.config.attempt_window),
                status.consecutive_failures
            ),
        );

        // Log lockout if triggered
        if let LockoutDecision::Locked {
            remaining,
            failure_count,
            ..
        } = &decision
        {
            observe::warn(
                "auth.lockout.triggered",
                format!(
                    "Account locked for {}: {} consecutive failures, locked for {:?}",
                    identifier, failure_count, remaining
                ),
            );
        }

        Ok(decision)
    }

    /// Record a successful authentication
    ///
    /// Clears consecutive failure count but keeps history for analysis.
    ///
    /// # Audit Events
    ///
    /// - `auth.lockout.success` (DEBUG)
    pub fn record_success(&self, identifier: &str) -> Result<(), Problem> {
        let mut status = self.store.get(identifier)?;

        let was_locked = status.is_locked();
        status.record_success();

        self.store.update(identifier, &status)?;

        if was_locked {
            observe::info(
                "auth.lockout.cleared",
                format!("Lockout cleared for {} after successful auth", identifier),
            );
        } else {
            observe::debug(
                "auth.lockout.success",
                format!("Successful auth recorded for {}", identifier),
            );
        }

        Ok(())
    }

    /// Manually clear a lockout (admin action)
    ///
    /// # Audit Events
    ///
    /// - `auth.lockout.admin_cleared` (INFO)
    pub fn clear_lockout(&self, identifier: &str) -> Result<bool, Problem> {
        let mut status = self.store.get(identifier)?;

        if !status.is_locked() && status.consecutive_failures == 0 {
            return Ok(false);
        }

        status.clear_lockout();
        self.store.update(identifier, &status)?;

        observe::info(
            "auth.lockout.admin_cleared",
            format!("Lockout manually cleared for {}", identifier),
        );

        Ok(true)
    }

    /// Get the current lockout status for an identifier
    pub fn get_status(&self, identifier: &str) -> Result<LockoutStatus, Problem> {
        self.store.get(identifier)
    }

    /// Get remaining lockout duration if locked
    pub fn remaining_lockout(
        &self,
        identifier: &str,
    ) -> Result<Option<std::time::Duration>, Problem> {
        let status = self.store.get(identifier)?;
        Ok(status.remaining_lockout())
    }

    /// Clean up old failure records
    ///
    /// Should be called periodically (e.g., every 5 minutes).
    ///
    /// # Audit Events
    ///
    /// - `auth.lockout.cleanup` (DEBUG) if any records were cleaned
    pub fn cleanup_old_records(&self) -> Result<usize, Problem> {
        let count = self.store.cleanup_old_records(self.config.attempt_window)?;

        if count > 0 {
            observe::debug(
                "auth.lockout.cleanup",
                format!("Cleaned up {} old failure records", count),
            );
        }

        Ok(count)
    }

    /// Calculate what the lockout duration would be for a given failure count
    #[must_use]
    pub fn calculate_lockout_duration(&self, failure_count: u32) -> std::time::Duration {
        calculate_backoff_duration(
            failure_count,
            self.config.base_lockout_duration,
            self.config.max_lockout_duration,
            self.config.backoff_multiplier,
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::lockout::MemoryLockoutStore;

    fn create_manager() -> LockoutManager<MemoryLockoutStore> {
        let store = Arc::new(MemoryLockoutStore::new());
        let config = LockoutConfig::default();
        LockoutManager::new(store, config)
    }

    #[test]
    fn test_check_not_locked() {
        let manager = create_manager();

        let decision = manager.check("user1").expect("check should succeed");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_record_failure() {
        let manager = create_manager();

        let decision = manager
            .record_failure("user1")
            .expect("record should succeed");
        assert!(decision.is_allowed()); // Not locked after 1 failure

        let status = manager.get_status("user1").expect("status should succeed");
        assert_eq!(status.consecutive_failures, 1);
    }

    #[test]
    fn test_lockout_after_max_failures() {
        let store = Arc::new(MemoryLockoutStore::new());
        let config = LockoutConfig::builder().max_attempts(3).build();
        let manager = LockoutManager::new(store, config);

        // Record 3 failures (max_attempts)
        manager.record_failure("user1").expect("record");
        manager.record_failure("user1").expect("record");
        let decision = manager.record_failure("user1").expect("record");

        assert!(decision.is_locked());
    }

    #[test]
    fn test_record_success_clears_consecutive() {
        let manager = create_manager();

        manager.record_failure("user1").expect("record");
        manager.record_failure("user1").expect("record");

        let status = manager.get_status("user1").expect("status");
        assert_eq!(status.consecutive_failures, 2);

        manager.record_success("user1").expect("success");

        let status = manager.get_status("user1").expect("status");
        assert_eq!(status.consecutive_failures, 0);
    }

    #[test]
    fn test_clear_lockout() {
        let store = Arc::new(MemoryLockoutStore::new());
        let config = LockoutConfig::builder().max_attempts(2).build();
        let manager = LockoutManager::new(store, config);

        // Trigger lockout
        manager.record_failure("user1").expect("record");
        let decision = manager.record_failure("user1").expect("record");
        assert!(decision.is_locked());

        // Clear lockout
        let cleared = manager.clear_lockout("user1").expect("clear");
        assert!(cleared);

        // Should be allowed now
        let decision = manager.check("user1").expect("check");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_remaining_lockout() {
        let store = Arc::new(MemoryLockoutStore::new());
        let config = LockoutConfig::builder().max_attempts(2).build();
        let manager = LockoutManager::new(store, config);

        // Before lockout
        let remaining = manager.remaining_lockout("user1").expect("remaining");
        assert!(remaining.is_none());

        // Trigger lockout
        manager.record_failure("user1").expect("record");
        manager.record_failure("user1").expect("record");

        // Should have remaining time
        let remaining = manager.remaining_lockout("user1").expect("remaining");
        assert!(remaining.is_some());
    }

    #[test]
    fn test_record_failure_with_context() {
        let manager = create_manager();

        let decision = manager
            .record_failure_with_context("user1", Some("192.168.1.1"), Some("Mozilla/5.0"))
            .expect("record should succeed");

        assert!(decision.is_allowed());

        let status = manager.get_status("user1").expect("status");
        assert_eq!(status.failures.len(), 1);
        assert_eq!(
            status
                .failures
                .first()
                .expect("should have failure")
                .ip_address,
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_calculate_lockout_duration() {
        let store = Arc::new(MemoryLockoutStore::new());
        let config = LockoutConfig::builder()
            .base_lockout_duration(std::time::Duration::from_secs(60))
            .max_lockout_duration(std::time::Duration::from_secs(3600))
            .backoff_multiplier(2.0)
            .build();
        let manager = LockoutManager::new(store, config);

        // Zero failures should return base duration
        let d0 = manager.calculate_lockout_duration(0);
        assert_eq!(d0, std::time::Duration::from_secs(60));

        // 1 failure: base * 2^0 = 60s
        let d1 = manager.calculate_lockout_duration(1);
        assert_eq!(d1, std::time::Duration::from_secs(60));

        // 2 failures: base * 2^1 = 120s
        let d2 = manager.calculate_lockout_duration(2);
        assert_eq!(d2, std::time::Duration::from_secs(120));

        // 3 failures: base * 2^2 = 240s
        let d3 = manager.calculate_lockout_duration(3);
        assert_eq!(d3, std::time::Duration::from_secs(240));

        // High failure count should be capped at max_lockout_duration
        let d_high = manager.calculate_lockout_duration(100);
        assert!(d_high <= std::time::Duration::from_secs(3600));
    }
}
