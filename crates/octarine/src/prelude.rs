//! Octarine prelude - common imports for consuming applications
//!
//! The prelude provides the most commonly used types and facades for working
//! with octarine's security, data, and identifier operations.
//!
//! # Usage
//!
//! ```rust
//! use octarine::prelude::*;
//!
//! // Access the three facades
//! let security = Security::new();
//! let data = Data::new();
//! let identifiers = Identifiers::new();
//!
//! // Use common types
//! fn validate_input(input: &str) -> Result<()> {
//!     if input.is_empty() {
//!         return Err(fail_validation("input", "cannot be empty"));
//!     }
//!     info("validation", "Input validated successfully");
//!     Ok(())
//! }
//! ```
//!
//! # Three Orthogonal Concerns
//!
//! The prelude exposes three facades, one for each orthogonal concern:
//!
//! | Facade | Concern | Question |
//! |--------|---------|----------|
//! | `Security` | THREATS | "Is this dangerous?" |
//! | `Data` | FORMAT | "How should this be structured?" |
//! | `Identifiers` | CLASSIFICATION | "What is it? Is it PII?" |
//!
//! # Example: Hex (Ingestion Server)
//!
//! ```rust,ignore
//! use octarine::prelude::*;
//!
//! fn ingest_repository(repo_url: &str, file_path: &str) -> Result<()> {
//!     let security = Security::new();
//!     let identifiers = Identifiers::new();
//!
//!     // Validate git clone URL (SSRF prevention)
//!     security.network().validate_ssrf_safe(repo_url)?;
//!
//!     // Validate file paths (traversal prevention)
//!     security.paths().validate_path(file_path)?;
//!
//!     // Check for credentials in source code
//!     if identifiers.credentials().is_api_key(source_code) {
//!         warn("pii", "API key detected in source");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Example: L-Space (Data Server)
//!
//! ```rust,ignore
//! use octarine::prelude::*;
//!
//! fn search_patterns(query: &str) -> Result<Vec<Pattern>> {
//!     let security = Security::new();
//!     let data = Data::new();
//!
//!     // Validate search query (SQL injection prevention)
//!     security.queries().validate_sql_parameter(query)?;
//!
//!     // Sanitize text for logging
//!     let safe_query = data.text().sanitize_for_log(query);
//!     info("search", &format!("Searching for: {}", safe_query));
//!
//!     // ... perform search ...
//!     Ok(vec![])
//! }
//! ```
//!
//! # Example: Vimes (CLI)
//!
//! ```rust,ignore
//! use octarine::prelude::*;
//!
//! fn display_results(results: &str) -> Result<()> {
//!     let identifiers = Identifiers::new();
//!
//!     // Redact PII from output
//!     let safe_output = if identifiers.personal().is_pii_present(results) {
//!         identifiers.personal().redact_pii(results)
//!     } else {
//!         results.to_string()
//!     };
//!
//!     println!("{}", safe_output);
//!     Ok(())
//! }
//! ```

// ============================================================================
// Three Facades (one per orthogonal concern)
// ============================================================================

/// Security facade for threat detection (THREATS concern)
pub use crate::security::Security;

/// Data facade for normalization and formatting (FORMAT concern)
pub use crate::data::Data;

/// Identifiers facade for PII detection (CLASSIFICATION concern)
pub use crate::identifiers::Identifiers;

// ============================================================================
// Core Types
// ============================================================================

/// Error type with audit trail and context
pub use crate::observe::Problem;

/// Result type alias using Problem
pub use crate::observe::Result;

// ============================================================================
// Logging Functions
// ============================================================================

/// Log debug-level message
pub use crate::observe::debug;

/// Log trace-level message
pub use crate::observe::trace;

/// Log info-level message
pub use crate::observe::info;

/// Log warning-level message
pub use crate::observe::warn;

/// Log error-level message
pub use crate::observe::error;

// ============================================================================
// Success Helpers
// ============================================================================

/// Log successful operation
pub use crate::observe::success;

/// Log successful authentication
pub use crate::observe::auth_success;

/// Log successful validation
pub use crate::observe::validation_success;

// ============================================================================
// Error Helpers (return Problem)
// ============================================================================

/// Create a general failure Problem
pub use crate::observe::fail;

/// Create a validation failure Problem
pub use crate::observe::fail_validation;

/// Create a security failure Problem
pub use crate::observe::fail_security;

/// Create a permission failure Problem
pub use crate::observe::fail_permission;

/// Mark code as todo (creates Problem)
pub use crate::observe::todo;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_facades_accessible() {
        let security = Security::new();
        let data = Data::new();
        let identifiers = Identifiers::new();

        // Verify facades work
        let _ = security.paths();
        let _ = data.text("test input");
        let _ = identifiers.personal();
    }

    #[test]
    fn test_prelude_logging_accessible() {
        // Just verify these compile - actual logging is tested elsewhere
        info("test", "info message");
        warn("test", "warn message");
        debug("test", "debug message");
    }

    #[test]
    fn test_prelude_error_helpers() {
        // Just verify the error helper is callable and returns a Problem
        let _err = fail_validation("field", "must not be empty");
    }

    #[test]
    fn test_prelude_result_type() {
        fn example_fn() -> Result<()> {
            Ok(())
        }
        assert!(example_fn().is_ok());
    }
}
