//! Composite sanitization functions
//!
//! High-level functions that combine multiple sanitization operations.

use super::super::detection;
use crate::primitives::types::Problem;

use super::{SanitizationResult, is_bidi_char, sanitize};

// ============================================================================
// Composite Sanitization
// ============================================================================

/// Sanitize filename removing all dangerous patterns
///
/// Comprehensive sanitization that removes:
/// - Null bytes
/// - Control characters
/// - Path separators
/// - Shell metacharacters
/// - Bidirectional control
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// let result = sanitization::sanitize_all_threats("../$(cmd)\0file;rm.txt");
/// assert_eq!(result.expect("test"), "cmdfilerm.txt");
/// ```
pub fn sanitize_all_threats(filename: &str) -> SanitizationResult {
    if detection::is_empty(filename) {
        return Err(Problem::validation("Filename cannot be empty"));
    }

    let mut result: String = filename
        .chars()
        .filter(|&c| {
            !c.is_ascii_control()
                && c != '\0'
                && c != '/'
                && c != '\\'
                && !detection::DANGEROUS_SHELL_CHARS.contains(&c)
                && !is_bidi_char(c)
        })
        .collect();

    // Remove leading .. sequences (parent directory references)
    while result.starts_with("..") {
        result = result[2..].to_string();
        // Also remove any leading dots that remain
        result = result.trim_start_matches('.').to_string();
    }

    // Remove embedded .. sequences
    while result.contains("..") {
        result = result.replace("..", ".");
    }

    if result.is_empty() || result == "." {
        return Err(Problem::validation(
            "Filename is empty after removing threats",
        ));
    }

    // Handle reserved names
    if detection::is_reserved_name(&result) {
        return Ok(format!("_{}", result));
    }

    Ok(result)
}

/// Generate a safe filename from any input
///
/// Always returns a valid filename, using fallback if necessary.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::to_safe_filename("file.txt"), "file.txt");
/// assert_eq!(sanitization::to_safe_filename(""), "unnamed");
/// assert_eq!(sanitization::to_safe_filename("///"), "unnamed");
/// ```
#[must_use]
pub fn to_safe_filename(filename: &str) -> String {
    sanitize(filename).unwrap_or_else(|_| "unnamed".to_string())
}

/// Generate a safe filename with custom fallback
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::to_safe_filename_or("", "default.txt"), "default.txt");
/// ```
#[must_use]
pub fn to_safe_filename_or(filename: &str, fallback: &str) -> String {
    sanitize(filename).unwrap_or_else(|_| fallback.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_sanitize_all_threats() {
        assert_eq!(
            sanitize_all_threats("../$(cmd)\0file;rm.txt").expect("test"),
            "cmdfilerm.txt"
        );
        assert_eq!(
            sanitize_all_threats("file\u{202E}.txt").expect("test"),
            "file.txt"
        );
        assert!(sanitize_all_threats("").is_err());
        assert!(sanitize_all_threats("///").is_err());
    }

    #[test]
    fn test_to_safe_filename() {
        assert_eq!(to_safe_filename("file.txt"), "file.txt");
        assert_eq!(to_safe_filename(""), "unnamed");
        assert_eq!(to_safe_filename("///"), "unnamed");
        assert_eq!(to_safe_filename("\0\0\0"), "unnamed");
    }

    #[test]
    fn test_to_safe_filename_or() {
        assert_eq!(to_safe_filename_or("file.txt", "default.txt"), "file.txt");
        assert_eq!(to_safe_filename_or("", "default.txt"), "default.txt");
    }
}
