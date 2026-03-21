//! Generic identifier validation and detection
//!
//! Pure functions for validating generic identifiers with configurable rules.
//! More flexible than specialized validators (database, environment).
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies (uses Problem type from primitives::types)
//! - Returns data, no side effects
//! - Used for API keys, config keys, variable names, etc.
//!
//! # Flexibility
//!
//! Unlike specialized validators, this validator:
//! - Allows hyphens in addition to underscores
//! - Configurable uppercase/lowercase rules
//! - Optional injection checking
//! - Customizable length limits
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::generic::GenericBuilder;
//!
//! let generator = GenericBuilder::new();
//!
//! // Detection (bool)
//! if generator.is_valid_identifier("api-key-123") {
//!     println!("Valid identifier");
//! }
//!
//! // Validation (Result)
//! generator.validate_identifier("api-key-123")?;
//! ```

// Internal modules - not directly accessible outside generic/
mod detection;
mod validation;

// Public builder module
pub mod builder;

// Re-export builder for convenience
pub use builder::GenericBuilder;

/// Default maximum length for generic identifiers
pub const MAX_IDENTIFIER_LENGTH: usize = 200;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_module_integration() {
        // Detection
        assert!(detection::is_valid_identifier("api-key-123"));
        assert!(detection::is_valid_identifier("my_identifier"));
        assert!(!detection::is_valid_identifier("123identifier")); // starts with number
        assert!(!detection::is_valid_identifier("id--comment")); // SQL comment pattern

        // Validation
        assert!(validation::validate_identifier("api-key-123").is_ok());
        assert!(validation::validate_identifier("").is_err());
    }

    #[test]
    fn test_builder_integration() {
        let generator = GenericBuilder::new();

        // Detection via builder (bool)
        assert!(generator.is_valid_identifier("my-api-key"));
        assert!(!generator.is_valid_identifier("$(whoami)"));

        // Validation via builder (Result)
        assert!(generator.validate_identifier("api_key_v2").is_ok());
    }

    #[test]
    fn test_flexibility() {
        // Generic allows hyphens (unlike database/environment)
        assert!(detection::is_valid_identifier("kebab-case-name"));
        assert!(detection::is_valid_identifier("api-key-v2"));

        // But still blocks injection
        assert!(!detection::is_valid_identifier("id';DROP"));
        assert!(!detection::is_valid_identifier("id$(cmd)"));
    }
}
