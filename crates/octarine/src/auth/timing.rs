//! Account enumeration prevention utilities
//!
//! Provides constant-time response helpers to prevent timing-based
//! account enumeration attacks (ASVS V2.9.1).
//!
//! # Problem
//!
//! Attackers can enumerate valid usernames/emails by measuring response times:
//! - Fast response = user doesn't exist (no password check needed)
//! - Slow response = user exists (password hash was computed)
//!
//! # Solution
//!
//! Always perform the same amount of work regardless of whether the user
//! exists, or add artificial delays to normalize response times.
//!
//! # Example
//!
//! ```ignore
//! use octarine::auth::timing::{constant_time_response, ConstantTimeConfig};
//!
//! async fn login(email: &str, password: &str) -> Result<Session, Error> {
//!     let config = ConstantTimeConfig::default();
//!
//!     constant_time_response(&config, async {
//!         // This block always takes the same time to complete
//!         let user = find_user(email).await;
//!
//!         match user {
//!             Some(u) => verify_password(password, &u.password_hash),
//!             None => {
//!                 // Fake password check to normalize timing
//!                 let _ = argon2_verify("dummy", DUMMY_HASH);
//!                 Err(AuthError::InvalidCredentials)
//!             }
//!         }
//!     }).await
//! }
//! ```

use std::future::Future;
use std::time::{Duration, Instant};

use crate::observe;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for constant-time responses
#[derive(Debug, Clone)]
pub struct ConstantTimeConfig {
    /// Minimum response time for operations
    ///
    /// All responses will take at least this long.
    pub min_duration: Duration,
    /// Maximum response time before logging a warning
    ///
    /// If an operation exceeds this, it won't be artificially extended.
    pub max_duration: Duration,
}

impl Default for ConstantTimeConfig {
    fn default() -> Self {
        Self {
            min_duration: Duration::from_millis(250),
            max_duration: Duration::from_secs(5),
        }
    }
}

impl ConstantTimeConfig {
    /// Create a new constant-time config builder
    #[must_use]
    pub fn builder() -> ConstantTimeConfigBuilder {
        ConstantTimeConfigBuilder::default()
    }
}

/// Builder for constant-time configuration
#[derive(Debug, Default)]
pub struct ConstantTimeConfigBuilder {
    min_duration: Option<Duration>,
    max_duration: Option<Duration>,
}

impl ConstantTimeConfigBuilder {
    /// Set the minimum response duration
    #[must_use]
    pub fn min_duration(mut self, duration: Duration) -> Self {
        self.min_duration = Some(duration);
        self
    }

    /// Set the maximum response duration before warning
    #[must_use]
    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = Some(duration);
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> ConstantTimeConfig {
        ConstantTimeConfig {
            min_duration: self.min_duration.unwrap_or(Duration::from_millis(250)),
            max_duration: self.max_duration.unwrap_or(Duration::from_secs(5)),
        }
    }
}

// ============================================================================
// Constant-Time Response
// ============================================================================

/// Execute an operation with constant-time response
///
/// Ensures the operation takes at least `config.min_duration` to complete,
/// preventing timing-based enumeration attacks.
///
/// # Arguments
///
/// * `config` - Timing configuration
/// * `operation` - The async operation to execute
///
/// # Returns
///
/// The result of the operation.
///
/// # Example
///
/// ```ignore
/// use octarine::auth::timing::{constant_time_response, ConstantTimeConfig};
///
/// let config = ConstantTimeConfig::default();
/// let result = constant_time_response(&config, async {
///     authenticate_user(email, password).await
/// }).await;
/// ```
pub async fn constant_time_response<F, T>(config: &ConstantTimeConfig, operation: F) -> T
where
    F: Future<Output = T>,
{
    let start = Instant::now();
    let result = operation.await;
    let elapsed = start.elapsed();

    // If operation was faster than minimum, add delay
    if elapsed < config.min_duration {
        let remaining = config.min_duration.saturating_sub(elapsed);
        tokio::time::sleep(remaining).await;
    } else if elapsed > config.max_duration {
        // Log warning for slow operations
        observe::warn(
            "auth.timing.slow_operation",
            format!(
                "Auth operation took {:?}, exceeding max of {:?}",
                elapsed, config.max_duration
            ),
        );
    }

    result
}

/// Execute a synchronous operation with constant-time response
///
/// Blocking version for non-async code.
///
/// # Arguments
///
/// * `config` - Timing configuration
/// * `operation` - The operation to execute
///
/// # Returns
///
/// The result of the operation.
pub fn constant_time_response_sync<F, T>(config: &ConstantTimeConfig, operation: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = operation();
    let elapsed = start.elapsed();

    // If operation was faster than minimum, add delay
    if elapsed < config.min_duration {
        let remaining = config.min_duration.saturating_sub(elapsed);
        std::thread::sleep(remaining);
    } else if elapsed > config.max_duration {
        observe::warn(
            "auth.timing.slow_operation",
            format!(
                "Auth operation took {:?}, exceeding max of {:?}",
                elapsed, config.max_duration
            ),
        );
    }

    result
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
        let config = ConstantTimeConfig::default();
        assert_eq!(config.min_duration, Duration::from_millis(250));
        assert_eq!(config.max_duration, Duration::from_secs(5));
    }

    #[test]
    fn test_config_builder() {
        let config = ConstantTimeConfig::builder()
            .min_duration(Duration::from_millis(100))
            .max_duration(Duration::from_secs(10))
            .build();

        assert_eq!(config.min_duration, Duration::from_millis(100));
        assert_eq!(config.max_duration, Duration::from_secs(10));
    }

    #[test]
    fn test_constant_time_response_sync_fast() {
        let config = ConstantTimeConfig::builder()
            .min_duration(Duration::from_millis(50))
            .build();

        let start = Instant::now();
        let result = constant_time_response_sync(&config, || 42);
        let elapsed = start.elapsed();

        assert_eq!(result, 42);
        // Allow 20% margin for OS scheduler jitter
        assert!(elapsed >= Duration::from_millis(40));
    }

    #[test]
    fn test_constant_time_response_sync_slow() {
        let config = ConstantTimeConfig::builder()
            .min_duration(Duration::from_millis(10))
            .max_duration(Duration::from_millis(100))
            .build();

        let start = Instant::now();
        let result = constant_time_response_sync(&config, || {
            std::thread::sleep(Duration::from_millis(20));
            42
        });
        let elapsed = start.elapsed();

        assert_eq!(result, 42);
        // Allow margins for OS scheduler jitter and CI load
        assert!(elapsed >= Duration::from_millis(16));
        assert!(elapsed < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_constant_time_response_async_fast() {
        let config = ConstantTimeConfig::builder()
            .min_duration(Duration::from_millis(50))
            .build();

        let start = Instant::now();
        let result = constant_time_response(&config, async { 42 }).await;
        let elapsed = start.elapsed();

        assert_eq!(result, 42);
        // Allow 20% margin for OS scheduler jitter
        assert!(elapsed >= Duration::from_millis(40));
    }

    #[test]
    fn test_constant_time_response_sync_slow_warning() {
        // Configure a very short max_duration so the operation exceeds it
        let config = ConstantTimeConfig::builder()
            .min_duration(Duration::from_millis(1))
            .max_duration(Duration::from_millis(5))
            .build();

        // Operation that takes longer than max_duration triggers the warn path
        let result = constant_time_response_sync(&config, || {
            std::thread::sleep(Duration::from_millis(20));
            99
        });

        // The warn path should not prevent the result from being returned
        assert_eq!(result, 99);
    }
}
