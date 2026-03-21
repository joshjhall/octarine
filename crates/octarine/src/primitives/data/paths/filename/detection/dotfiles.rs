//! Dot file detection functions
//!
//! Functions to detect hidden (dot) files.

use super::reserved::is_directory_ref;

// ============================================================================
// Dot File Detection
// ============================================================================

/// Check if filename is a dot file (hidden file)
///
/// Dot files start with a period and are hidden on Unix systems.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_dot_file(".gitignore"));
/// assert!(detection::is_dot_file(".hidden"));
/// assert!(!detection::is_dot_file("file.txt"));
/// assert!(!detection::is_dot_file(".")); // Current dir, not a dot file
/// assert!(!detection::is_dot_file("..")); // Parent dir, not a dot file
/// ```
#[must_use]
pub fn is_dot_file(filename: &str) -> bool {
    filename.starts_with('.')
        && filename.len() > 1
        && !is_directory_ref(filename)
        && filename.chars().nth(1) != Some('.')
}

/// Check if filename starts with a dot (more lenient than is_dot_file)
#[must_use]
pub fn starts_with_dot(filename: &str) -> bool {
    filename.starts_with('.') && !is_directory_ref(filename)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_dot_file() {
        assert!(is_dot_file(".gitignore"));
        assert!(is_dot_file(".hidden"));
        assert!(is_dot_file(".config"));
        assert!(!is_dot_file(".")); // Current dir
        assert!(!is_dot_file("..")); // Parent dir
        assert!(!is_dot_file("file.txt"));
        assert!(!is_dot_file("..file")); // Starts with ..
    }

    #[test]
    fn test_starts_with_dot() {
        assert!(starts_with_dot(".gitignore"));
        assert!(starts_with_dot(".hidden"));
        assert!(starts_with_dot("..file")); // More lenient
        assert!(!starts_with_dot("."));
        assert!(!starts_with_dot(".."));
        assert!(!starts_with_dot("file.txt"));
    }
}
