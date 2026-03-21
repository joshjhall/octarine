//! Targeted validation shortcuts
//!
//! Convenience functions for specific security validations.

use crate::observe::Problem;

use super::detection::{is_command_injection_present, is_path_traversal_present};
use super::manipulation::clean_path_components;
use super::validation::validate_path;

// ============================================================
// TARGETED VALIDATION SHORTCUTS
// ============================================================

/// Validate that a path has no traversal patterns (../)
///
/// Returns `Ok(())` if the path is safe from traversal, `Err` otherwise.
pub fn validate_path_no_traversal(path: &str) -> Result<(), Problem> {
    if is_path_traversal_present(path) {
        return Err(Problem::validation(
            "Path contains traversal patterns (../)",
        ));
    }
    Ok(())
}

/// Validate that a path has no command injection patterns
///
/// Returns `Ok(())` if the path is safe from injection, `Err` otherwise.
pub fn validate_path_no_injection(path: &str) -> Result<(), Problem> {
    if is_command_injection_present(path) {
        return Err(Problem::validation(
            "Path contains command injection patterns",
        ));
    }
    Ok(())
}

/// Normalize and validate a path (secure version)
///
/// Cleans path components (resolves . and ..) then validates for security threats.
/// Returns the normalized path if safe, error otherwise.
pub fn normalize_path_secure(path: &str) -> Result<String, Problem> {
    let normalized = clean_path_components(path);
    validate_path(&normalized)?;
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_targeted_validation() {
        assert!(validate_path_no_traversal("safe/path").is_ok());
        assert!(validate_path_no_traversal("../secret").is_err());
        assert!(validate_path_no_injection("safe/path").is_ok());
        assert!(validate_path_no_injection("$(whoami)").is_err());
    }
}
