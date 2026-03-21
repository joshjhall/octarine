//! Lockout configuration
//!
//! Implements OWASP ASVS V2.2 lockout requirements.

use std::time::Duration;

// ============================================================================
// Lockout Config
// ============================================================================

/// Account lockout configuration
///
/// Follows OWASP ASVS V2.2 requirements for brute-force protection.
#[derive(Debug, Clone)]
pub struct LockoutConfig {
    /// Maximum failed attempts before lockout (ASVS V2.2.1)
    ///
    /// Default: 5 attempts
    pub max_attempts: u32,

    /// Time window for counting attempts
    ///
    /// Failures older than this are not counted.
    /// Default: 15 minutes
    pub attempt_window: Duration,

    /// Base lockout duration after first lockout
    ///
    /// Default: 1 minute
    pub base_lockout_duration: Duration,

    /// Maximum lockout duration
    ///
    /// Lockout duration won't exceed this even with exponential backoff.
    /// Default: 1 hour
    pub max_lockout_duration: Duration,

    /// Multiplier for exponential backoff
    ///
    /// Each subsequent lockout is multiplied by this factor.
    /// Default: 2.0
    pub backoff_multiplier: f32,

    /// Whether to lock by username, IP, or both
    ///
    /// Default: Username only
    pub lock_by: LockoutIdentifier,

    /// Whether to notify user on lockout
    ///
    /// Default: true
    pub notify_on_lockout: bool,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            attempt_window: Duration::from_secs(15 * 60), // 15 minutes
            base_lockout_duration: Duration::from_secs(60), // 1 minute
            max_lockout_duration: Duration::from_secs(3600), // 1 hour
            backoff_multiplier: 2.0,
            lock_by: LockoutIdentifier::Username,
            notify_on_lockout: true,
        }
    }
}

impl LockoutConfig {
    /// Create a new config with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for custom configuration
    #[must_use]
    pub fn builder() -> LockoutConfigBuilder {
        LockoutConfigBuilder::new()
    }

    /// Create a strict config for high-security applications
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_attempts: 3,
            attempt_window: Duration::from_secs(30 * 60), // 30 minutes
            base_lockout_duration: Duration::from_secs(5 * 60), // 5 minutes
            max_lockout_duration: Duration::from_secs(24 * 3600), // 24 hours
            backoff_multiplier: 3.0,
            lock_by: LockoutIdentifier::Both,
            notify_on_lockout: true,
        }
    }

    /// Create a lenient config for development/testing
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            max_attempts: 10,
            attempt_window: Duration::from_secs(5 * 60), // 5 minutes
            base_lockout_duration: Duration::from_secs(30), // 30 seconds
            max_lockout_duration: Duration::from_secs(5 * 60), // 5 minutes
            backoff_multiplier: 1.5,
            lock_by: LockoutIdentifier::Username,
            notify_on_lockout: false,
        }
    }
}

// ============================================================================
// Lockout Identifier
// ============================================================================

/// What to use as the lockout identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockoutIdentifier {
    /// Lock by username only
    #[default]
    Username,
    /// Lock by IP address only
    IpAddress,
    /// Lock by both username and IP (most strict)
    Both,
}

// ============================================================================
// Lockout Config Builder
// ============================================================================

/// Builder for creating custom lockout configurations
#[derive(Debug, Clone)]
pub struct LockoutConfigBuilder {
    config: LockoutConfig,
}

impl Default for LockoutConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LockoutConfigBuilder {
    /// Create a new builder with default config
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: LockoutConfig::default(),
        }
    }

    /// Set maximum failed attempts before lockout
    #[must_use]
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.config.max_attempts = attempts;
        self
    }

    /// Set time window for counting attempts
    #[must_use]
    pub fn attempt_window(mut self, window: Duration) -> Self {
        self.config.attempt_window = window;
        self
    }

    /// Set base lockout duration
    #[must_use]
    pub fn base_lockout_duration(mut self, duration: Duration) -> Self {
        self.config.base_lockout_duration = duration;
        self
    }

    /// Set maximum lockout duration
    #[must_use]
    pub fn max_lockout_duration(mut self, duration: Duration) -> Self {
        self.config.max_lockout_duration = duration;
        self
    }

    /// Set backoff multiplier
    #[must_use]
    pub fn backoff_multiplier(mut self, multiplier: f32) -> Self {
        self.config.backoff_multiplier = multiplier;
        self
    }

    /// Set what to lock by
    #[must_use]
    pub fn lock_by(mut self, identifier: LockoutIdentifier) -> Self {
        self.config.lock_by = identifier;
        self
    }

    /// Set whether to notify on lockout
    #[must_use]
    pub fn notify_on_lockout(mut self, notify: bool) -> Self {
        self.config.notify_on_lockout = notify;
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> LockoutConfig {
        self.config
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LockoutConfig::default();

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.attempt_window, Duration::from_secs(15 * 60));
        assert_eq!(config.base_lockout_duration, Duration::from_secs(60));
        assert_eq!(config.max_lockout_duration, Duration::from_secs(3600));
        assert!((config.backoff_multiplier - 2.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_strict_config() {
        let config = LockoutConfig::strict();

        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.lock_by, LockoutIdentifier::Both);
    }

    #[test]
    fn test_builder() {
        let config = LockoutConfig::builder()
            .max_attempts(3)
            .attempt_window(Duration::from_secs(300))
            .base_lockout_duration(Duration::from_secs(120))
            .lock_by(LockoutIdentifier::IpAddress)
            .build();

        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.attempt_window, Duration::from_secs(300));
        assert_eq!(config.base_lockout_duration, Duration::from_secs(120));
        assert_eq!(config.lock_by, LockoutIdentifier::IpAddress);
    }
}
