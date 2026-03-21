// Allow dead code and unused imports - this module provides API primitives
// that may not all be consumed yet.
#![allow(dead_code)]
#![allow(unused_imports)]

//! Security domain for path operations
//!
//! This module provides OWASP-compliant security detection, validation,
//! and sanitization for filesystem paths.
//!
//! ## Architecture
//!
//! The security domain is organized into three layers:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  SecurityBuilder                                                │
//! │  (Unified API for all security operations)                      │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │   detection     │ │   validation    │ │  sanitization   │
//! │                 │ │                 │ │                 │
//! │ - detect_threats│ │ - validate_*    │ │ - sanitize_*    │
//! │ - has_*         │ │ - validate_*    │ │ - remove_*      │
//! │                 │ │   _strict       │ │                 │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```
//!
//! ## Security Threats Covered
//!
//! | Threat | CWE | Description |
//! |--------|-----|-------------|
//! | Traversal | CWE-22 | Directory traversal (`..`) |
//! | EncodedTraversal | CWE-22 | URL-encoded traversal (`%2e%2e`) |
//! | CommandInjection | CWE-78 | Shell command execution (`$()`, backticks) |
//! | VariableExpansion | CWE-78 | Environment variable leak (`$VAR`) |
//! | ShellMetacharacters | CWE-78 | Command chaining (`;`, `|`, `&`) |
//! | NullByte | CWE-158 | String truncation (`\0`) |
//! | ControlCharacters | CWE-707 | Parsing/logging attacks |
//! | DoubleEncoding | CWE-175 | Bypass attacks (`%252e`) |
//!
//! ## Quick Start
//!
//! ```ignore
//! use octarine::primitives::paths::security::SecurityBuilder;
//!
//! let security = SecurityBuilder::new();
//!
//! // Check if path is safe
//! if security.is_secure(user_input) {
//!     // Safe to use
//! } else {
//!     // Handle threat
//!     let threats = security.detect_threats(user_input);
//!     for threat in &threats {
//!         eprintln!("Detected: {}", threat);
//!     }
//! }
//! # let user_input = "safe";
//! ```
//!
//! ## Module Functions vs Builder
//!
//! You can use either the module functions directly or the builder API:
//!
//! ```ignore
//! use octarine::primitives::paths::security::{detection, validation, sanitization};
//! use octarine::primitives::paths::security::SecurityBuilder;
//!
//! // Using module functions directly
//! let is_safe = !detection::has_threat("../secret");
//! let validated = validation::validate_secure_strict("path");
//! let clean = sanitization::sanitize("../etc/passwd");
//!
//! // Using builder (same functionality)
//! let security = SecurityBuilder::new();
//! let is_safe = !security.is_threat_present("../secret");
//! let validated = security.validate_path("path");
//! let clean = security.sanitize("../etc/passwd");
//! ```

pub mod builder;
pub mod detection;
pub mod sanitization;
pub mod validation;

// Re-export builder for convenience
pub use builder::SecurityBuilder;

// Re-export validation result type
pub use validation::ValidationResult;

// Re-export sanitization result type
pub use sanitization::SanitizationResult;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::primitives::data::paths::types::{PathSanitizationStrategy, SecurityThreat};

    #[test]
    fn test_module_integration() {
        // Detection
        assert!(detection::is_threat_present("../$(whoami)"));
        let threats = detection::detect_threats("../$(whoami)");
        assert!(threats.contains(&SecurityThreat::Traversal));
        assert!(threats.contains(&SecurityThreat::CommandInjection));

        // Validation
        assert!(!validation::validate_secure("../secret"));
        assert!(validation::validate_secure_strict("safe/path").is_ok());

        // Sanitization
        let clean = sanitization::sanitize("../etc/passwd").expect("test");
        assert!(!clean.contains(".."));
    }

    #[test]
    fn test_builder_integration() {
        let security = SecurityBuilder::new();

        // All operations through builder
        assert!(security.is_threat_present("../$(whoami)"));
        assert!(security.is_secure("safe/path.txt"));
        assert!(security.validate_path("safe/path").is_ok());

        let clean = security.sanitize("../etc/passwd").expect("test");
        assert!(!clean.contains(".."));
    }

    #[test]
    fn test_strategies() {
        let security = SecurityBuilder::new();

        // Strict rejects
        assert!(
            security
                .sanitize_with("../etc", PathSanitizationStrategy::Strict)
                .is_err()
        );

        // Clean removes
        let clean = security
            .sanitize_with("../etc", PathSanitizationStrategy::Clean)
            .expect("test");
        assert!(!clean.contains(".."));

        // Escape escapes
        let escaped = security
            .sanitize_with("../etc", PathSanitizationStrategy::Escape)
            .expect("test");
        assert!(escaped.contains("[DOT_DOT]"));
    }

    #[test]
    fn test_comprehensive_threat_detection() {
        // All threat types should be detected
        assert!(detection::is_traversal_present("../"));
        assert!(detection::is_encoded_traversal_present("%2e%2e"));
        assert!(detection::is_command_injection_present("$(cmd)"));
        assert!(detection::is_variable_expansion_present("$HOME"));
        assert!(detection::is_shell_metacharacters_present("file;ls"));
        assert!(detection::is_null_bytes_present("file\0"));
        assert!(detection::is_control_characters_present("file\n"));
        assert!(detection::is_double_encoding_present("%252e"));
        assert!(detection::is_absolute_path_present("/etc"));
    }
}
