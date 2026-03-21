//! Environment builder for convenient access to all environment variable functions
//!
//! The EnvironmentBuilder provides a unified interface for detection
//! and validation of environment variable names.

use super::MAX_ENV_VAR_LENGTH;
use super::{detection, validation};
use crate::primitives::types::Problem;

/// Builder for environment variable validation and detection
///
/// Provides configurable access to all environment variable functions with optional
/// custom limits.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::environment::EnvironmentBuilder;
///
/// let env = EnvironmentBuilder::new();
///
/// // Detection (bool)
/// if env.is_valid_env_var("MY_CONFIG") {
///     println!("Valid!");
/// }
///
/// // Validation (Result)
/// env.validate_env_var("MY_CONFIG")?;
/// ```
#[derive(Debug, Clone)]
pub struct EnvironmentBuilder {
    max_length: usize,
    check_reserved: bool,
    check_injection: bool,
}

impl Default for EnvironmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvironmentBuilder {
    /// Create a new EnvironmentBuilder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_length: MAX_ENV_VAR_LENGTH,
            check_reserved: true,
            check_injection: true,
        }
    }

    /// Create a permissive builder that doesn't check reserved vars
    #[must_use]
    pub fn permissive() -> Self {
        Self::new().without_reserved_check()
    }

    /// Set custom maximum variable name length
    #[must_use]
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    /// Disable reserved variable checking
    #[must_use]
    pub fn without_reserved_check(mut self) -> Self {
        self.check_reserved = false;
        self
    }

    /// Disable injection pattern checking
    #[must_use]
    pub fn without_injection_check(mut self) -> Self {
        self.check_injection = false;
        self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Check if a variable name is reserved
    #[must_use]
    pub fn is_reserved_var(&self, name: &str) -> bool {
        detection::is_reserved_var(name)
    }

    /// Check if a variable is critical (security-sensitive)
    #[must_use]
    pub fn is_critical_var(&self, name: &str) -> bool {
        detection::is_critical_var(name)
    }

    // ========================================================================
    // Detection Methods (bool)
    // ========================================================================

    /// Check if an environment variable name is valid (returns bool)
    #[must_use]
    pub fn is_valid_env_var(&self, name: &str) -> bool {
        detection::is_valid_env_var_with_config(
            name,
            self.max_length,
            self.check_reserved,
            self.check_injection,
        )
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate an environment variable name (returns Result)
    pub fn validate_env_var(&self, name: &str) -> Result<(), Problem> {
        validation::validate_env_var_with_config(
            name,
            self.max_length,
            self.check_reserved,
            self.check_injection,
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_default() {
        let env = EnvironmentBuilder::new();
        assert!(env.is_valid_env_var("MY_VAR"));
        assert!(!env.is_valid_env_var("PATH"));
    }

    #[test]
    fn test_builder_custom_length() {
        let env = EnvironmentBuilder::new().with_max_length(10);

        assert!(env.is_valid_env_var("SHORT"));
        assert!(!env.is_valid_env_var("THIS_IS_TOO_LONG"));
    }

    #[test]
    fn test_builder_without_reserved_check() {
        let env = EnvironmentBuilder::new().without_reserved_check();

        // Now reserved vars are allowed
        assert!(env.is_valid_env_var("PATH"));
        assert!(env.is_valid_env_var("HOME"));
    }

    #[test]
    fn test_builder_permissive() {
        let env = EnvironmentBuilder::permissive();

        assert!(env.is_valid_env_var("PATH"));
        assert!(env.is_valid_env_var("LD_PRELOAD"));
    }

    #[test]
    fn test_builder_validation() {
        let env = EnvironmentBuilder::new();

        assert!(env.validate_env_var("MY_VAR").is_ok());
        assert!(env.validate_env_var("PATH").is_err());
        assert!(env.validate_env_var("").is_err());
    }

    #[test]
    fn test_is_reserved_var() {
        let env = EnvironmentBuilder::new();

        assert!(env.is_reserved_var("PATH"));
        assert!(env.is_reserved_var("HOME"));
        assert!(!env.is_reserved_var("MY_VAR"));
    }

    #[test]
    fn test_is_critical_var() {
        let env = EnvironmentBuilder::new();

        assert!(env.is_critical_var("LD_PRELOAD"));
        assert!(env.is_critical_var("PATH"));
        assert!(!env.is_critical_var("HOME")); // Reserved but not critical
    }
}
