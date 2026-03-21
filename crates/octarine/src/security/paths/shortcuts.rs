//! Shortcut functions for path security operations
//!
//! Convenience functions that provide quick access to common security operations
//! without needing to instantiate a builder.

// Allow dead_code: These are public API functions that will be used by consumers
#![allow(dead_code)]

use crate::observe::Problem;

use super::builder::SecurityBuilder;
use super::types::SecurityThreat;

// ============================================================================
// Detection Shortcuts
// ============================================================================

/// Check if path contains any security threat
///
/// # Example
///
/// ```ignore
/// use octarine::security::paths::is_threat_present;
///
/// if is_threat_present("../etc/passwd") {
///     // Handle threat
/// }
/// ```
#[must_use]
pub fn is_threat_present(path: &str) -> bool {
    SecurityBuilder::silent().is_threat_present(path)
}

/// Detect all security threats in a path
///
/// Returns a list of all detected threats.
#[must_use]
pub fn detect_threats(path: &str) -> Vec<SecurityThreat> {
    SecurityBuilder::silent().detect_threats(path)
}

/// Check if path is secure (no threats)
#[must_use]
pub fn is_secure(path: &str) -> bool {
    SecurityBuilder::silent().is_secure(path)
}

/// Check if path contains path traversal patterns (..)
#[must_use]
pub fn is_path_traversal_present(path: &str) -> bool {
    SecurityBuilder::silent().is_traversal_present(path)
}

/// Check if path contains encoded traversal patterns (%2e%2e)
#[must_use]
pub fn is_encoded_traversal_present(path: &str) -> bool {
    SecurityBuilder::silent().is_encoded_traversal_present(path)
}

/// Check if path contains command injection patterns
#[must_use]
pub fn is_command_injection_present(path: &str) -> bool {
    SecurityBuilder::silent().is_command_injection_present(path)
}

/// Check if path contains variable expansion patterns
#[must_use]
pub fn is_variable_expansion_present(path: &str) -> bool {
    SecurityBuilder::silent().is_variable_expansion_present(path)
}

/// Check if path contains shell metacharacters
#[must_use]
pub fn is_shell_metacharacters_present(path: &str) -> bool {
    SecurityBuilder::silent().is_shell_metacharacters_present(path)
}

/// Check if path contains null bytes
#[must_use]
pub fn is_null_bytes_present(path: &str) -> bool {
    SecurityBuilder::silent().is_null_bytes_present(path)
}

/// Check if path contains any injection pattern
#[must_use]
pub fn is_injection_present(path: &str) -> bool {
    SecurityBuilder::silent().is_injection_present(path)
}

// ============================================================================
// Validation Shortcuts
// ============================================================================

/// Validate a path is secure (no threats)
///
/// Returns `Ok(())` if safe, `Err` with details if threats found.
pub fn validate_secure(path: &str) -> Result<(), Problem> {
    SecurityBuilder::silent().validate_path(path)
}

/// Validate path has no traversal
pub fn validate_no_traversal(path: &str) -> Result<(), Problem> {
    SecurityBuilder::silent().validate_no_traversal(path)
}

/// Validate path has no injection
pub fn validate_no_injection(path: &str) -> Result<(), Problem> {
    SecurityBuilder::silent().validate_no_injection(path)
}

// ============================================================================
// Sanitization Shortcuts
// ============================================================================

/// Sanitize a path by removing security threats
///
/// Uses the default "Clean" strategy.
pub fn sanitize_path(path: &str) -> Result<String, Problem> {
    SecurityBuilder::silent().sanitize(path)
}

/// Strip traversal patterns from path
#[must_use]
pub fn strip_traversal(path: &str) -> String {
    SecurityBuilder::silent().strip_traversal(path)
}

/// Strip null bytes from path
#[must_use]
pub fn strip_null_bytes(path: &str) -> String {
    SecurityBuilder::silent().strip_null_bytes(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_threat_present() {
        assert!(is_threat_present("../etc/passwd"));
        assert!(is_threat_present("$(whoami)"));
        assert!(!is_threat_present("safe/path.txt"));
    }

    #[test]
    fn test_is_secure() {
        assert!(is_secure("safe/path.txt"));
        assert!(!is_secure("../secret"));
    }

    #[test]
    fn test_validate_secure() {
        assert!(validate_secure("safe/path").is_ok());
        assert!(validate_secure("../secret").is_err());
    }

    #[test]
    fn test_sanitize_path() {
        let clean = sanitize_path("../etc/passwd").expect("should sanitize");
        assert!(!clean.contains(".."));
    }
}
