//! Shell escaping functions
//!
//! Functions for safely escaping filenames for shell use.

use super::super::detection;
use crate::primitives::types::Problem;

use super::SanitizationResult;

// ============================================================================
// Shell Escaping Functions
// ============================================================================

/// Escape filename for safe shell use
///
/// Wraps in single quotes and escapes any internal single quotes.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::shell_escape("file.txt"), "'file.txt'");
/// assert_eq!(sanitization::shell_escape("file's.txt"), "'file'\\''s.txt'");
/// ```
#[must_use]
pub fn shell_escape(filename: &str) -> String {
    // Single quote escaping: replace ' with '\''
    let escaped = filename.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

/// Escape filename for safe shell use (strict)
///
/// Returns error if filename contains dangerous patterns that
/// shouldn't be used even when escaped.
pub fn shell_escape_strict(filename: &str) -> SanitizationResult {
    // Validate first
    if detection::is_null_bytes_present(filename) {
        return Err(Problem::validation("Filename contains null bytes"));
    }
    if detection::is_control_characters_present(filename) {
        return Err(Problem::validation("Filename contains control characters"));
    }

    Ok(shell_escape(filename))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("file.txt"), "'file.txt'");
        assert_eq!(shell_escape("file's.txt"), "'file'\\''s.txt'");
        assert_eq!(shell_escape("file name.txt"), "'file name.txt'");
    }

    #[test]
    fn test_shell_escape_strict() {
        assert!(shell_escape_strict("file.txt").is_ok());
        assert!(shell_escape_strict("file\0.txt").is_err());
        assert!(shell_escape_strict("file\n.txt").is_err());
    }
}
