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

    #[test]
    fn test_detect_threats() {
        let threats = detect_threats("../etc/$(whoami)");
        assert!(!threats.is_empty());

        let safe_threats = detect_threats("safe/path.txt");
        assert!(safe_threats.is_empty());
    }

    #[test]
    fn test_is_path_traversal_present() {
        assert!(is_path_traversal_present("../etc/passwd"));
        assert!(!is_path_traversal_present("safe/path.txt"));
    }

    #[test]
    fn test_is_encoded_traversal_present() {
        assert!(is_encoded_traversal_present("%2e%2e/secret"));
        assert!(!is_encoded_traversal_present("safe/path.txt"));
    }

    #[test]
    fn test_is_command_injection_present() {
        // Detects $(, `, ${ — not `;` (that's a shell metacharacter).
        assert!(is_command_injection_present("file$(whoami).txt"));
        assert!(!is_command_injection_present("safe.txt"));
    }

    #[test]
    fn test_is_variable_expansion_present() {
        assert!(is_variable_expansion_present("$HOME/secret"));
        assert!(!is_variable_expansion_present("safe.txt"));
    }

    #[test]
    fn test_is_shell_metacharacters_present() {
        assert!(is_shell_metacharacters_present("a|b"));
        assert!(!is_shell_metacharacters_present("safe.txt"));
    }

    #[test]
    fn test_is_null_bytes_present() {
        assert!(is_null_bytes_present("file\0name"));
        assert!(!is_null_bytes_present("safe.txt"));
    }

    #[test]
    fn test_is_injection_present() {
        assert!(is_injection_present("$(whoami)"));
        assert!(!is_injection_present("safe.txt"));
    }

    #[test]
    fn test_validate_no_traversal() {
        assert!(validate_no_traversal("safe/path.txt").is_ok());
        assert!(validate_no_traversal("../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_no_injection() {
        assert!(validate_no_injection("safe.txt").is_ok());
        assert!(validate_no_injection("$(whoami)").is_err());
    }

    #[test]
    fn test_strip_traversal() {
        let cleaned = strip_traversal("../etc/passwd");
        assert!(!cleaned.contains(".."));
        // Safe paths are preserved.
        assert_eq!(strip_traversal("safe/path.txt"), "safe/path.txt");
    }

    #[test]
    fn test_strip_null_bytes() {
        let cleaned = strip_null_bytes("file\0name");
        assert!(!cleaned.contains('\0'));
        // Safe paths are preserved.
        assert_eq!(strip_null_bytes("safe.txt"), "safe.txt");
    }
}
