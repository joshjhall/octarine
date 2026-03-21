//! Validation shortcuts
//!
//! Convenience functions for path validation operations.

use crate::observe::Problem;

use super::super::PathBuilder;

// ============================================================
// VALIDATION SHORTCUTS
// ============================================================

/// Validate a path - rejects any security threats
///
/// Returns `Ok(())` if the path is safe, `Err` if it contains threats.
/// Use this for user-provided paths or untrusted input.
///
/// For a boolean check, use [`is_valid_path`] instead.
pub fn validate_path(path: &str) -> Result<(), Problem> {
    PathBuilder::new().validate_path(path)
}

/// Check if a path is valid (no security threats)
///
/// Returns `true` if the path passes validation, `false` otherwise.
/// For strict validation that returns errors, use [`validate_path`].
pub fn is_valid_path(path: &str) -> bool {
    PathBuilder::new().validate_path(path).is_ok()
}

/// Validate a path is within a boundary
///
/// Ensures the path stays within the specified directory.
pub fn validate_path_in_boundary(path: &str, boundary: &str) -> Result<(), Problem> {
    PathBuilder::new().boundary(boundary).validate_path(path)
}

/// Validate a filename
///
/// Checks that the filename is safe for filesystem operations.
pub fn validate_filename(filename: &str) -> Result<(), Problem> {
    PathBuilder::new().validate_filename(filename)
}

/// Validate a filename for uploads
///
/// Stricter validation for user-uploaded files.
pub fn validate_upload_filename(filename: &str) -> Result<(), Problem> {
    PathBuilder::new().validate_upload_filename(filename)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validation_shortcuts() {
        assert!(validate_path("safe/path.txt").is_ok());
        assert!(validate_path("safe/path").is_ok());
        assert!(validate_path("../secret").is_err());
        assert!(is_valid_path("safe/path"));
        assert!(!is_valid_path("../secret"));
        assert!(validate_filename("document.pdf").is_ok());
        assert!(validate_filename("../file.txt").is_err());
    }
}
