//! Generic builder for convenient access to all generic identifier functions
//!
//! The GenericBuilder provides a unified interface for detection
//! and validation of generic identifiers.

use super::MAX_IDENTIFIER_LENGTH;
use super::{detection, validation};
use crate::primitives::types::Problem;

/// Builder for generic identifier validation and detection
///
/// Provides configurable access to all generic identifier functions with optional
/// custom limits.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::generic::GenericBuilder;
///
/// let generator = GenericBuilder::new();
///
/// // Detection (bool)
/// if generator.is_valid_identifier("api-key-123") {
///     println!("Valid!");
/// }
///
/// // Validation (Result)
/// generator.validate_identifier("api-key-123")?;
/// ```
#[derive(Debug, Clone)]
pub struct GenericBuilder {
    max_length: usize,
    check_injection: bool,
}

impl Default for GenericBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericBuilder {
    /// Create a new GenericBuilder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_length: MAX_IDENTIFIER_LENGTH,
            check_injection: true,
        }
    }

    /// Create a permissive builder without injection checking
    #[must_use]
    pub fn permissive() -> Self {
        Self::new().without_injection_check()
    }

    /// Set custom maximum identifier length
    #[must_use]
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    /// Disable injection pattern checking
    #[must_use]
    pub fn without_injection_check(mut self) -> Self {
        self.check_injection = false;
        self
    }

    // ========================================================================
    // Detection Methods (bool)
    // ========================================================================

    /// Check if a generic identifier is valid (returns bool)
    #[must_use]
    pub fn is_valid_identifier(&self, name: &str) -> bool {
        detection::is_valid_identifier_with_config(name, self.max_length, self.check_injection)
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate a generic identifier (returns Result)
    pub fn validate_identifier(&self, name: &str) -> Result<(), Problem> {
        validation::validate_identifier_with_config(name, self.max_length, self.check_injection)
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
        let generator = GenericBuilder::new();
        assert!(generator.is_valid_identifier("api-key-123"));
        assert!(!generator.is_valid_identifier("$(cmd)"));
    }

    #[test]
    fn test_builder_custom_length() {
        let generator = GenericBuilder::new().with_max_length(10);

        assert!(generator.is_valid_identifier("short"));
        assert!(!generator.is_valid_identifier("this-is-too-long"));
    }

    #[test]
    fn test_builder_permissive() {
        let generator = GenericBuilder::permissive();

        // Injection check disabled, but still validates format
        assert!(generator.is_valid_identifier("normal-id"));
    }

    #[test]
    fn test_builder_validation() {
        let generator = GenericBuilder::new();

        assert!(generator.validate_identifier("api-key-v2").is_ok());
        assert!(generator.validate_identifier("").is_err());
        assert!(generator.validate_identifier("$(cmd)").is_err());
    }

    #[test]
    fn test_chaining() {
        let generator = GenericBuilder::new()
            .with_max_length(50)
            .without_injection_check();

        assert!(generator.is_valid_identifier(&"a".repeat(50)));
        assert!(!generator.is_valid_identifier(&"a".repeat(51)));
    }
}
