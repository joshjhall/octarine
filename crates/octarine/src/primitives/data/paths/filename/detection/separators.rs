//! Path separator detection functions
//!
//! Functions to detect path separators in filenames.

// ============================================================================
// Path Separator Detection
// ============================================================================

/// Check if filename contains path separators
///
/// Detects both Unix (`/`) and Windows (`\`) path separators.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_path_separators_present("foo/bar"));
/// assert!(detection::is_path_separators_present("foo\\bar"));
/// assert!(!detection::is_path_separators_present("filename.txt"));
/// ```
#[must_use]
pub fn is_path_separators_present(filename: &str) -> bool {
    filename.contains('/') || filename.contains('\\')
}

/// Check if filename contains Unix path separator
#[must_use]
pub fn is_unix_separator_present(filename: &str) -> bool {
    filename.contains('/')
}

/// Check if filename contains Windows path separator
#[must_use]
pub fn is_windows_separator_present(filename: &str) -> bool {
    filename.contains('\\')
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_path_separators_present() {
        assert!(is_path_separators_present("foo/bar"));
        assert!(is_path_separators_present("foo\\bar"));
        assert!(is_path_separators_present("path/to/file.txt"));
        assert!(!is_path_separators_present("filename.txt"));
        assert!(!is_path_separators_present("file-name.txt"));
    }

    #[test]
    fn test_unix_windows_separators() {
        assert!(is_unix_separator_present("foo/bar"));
        assert!(!is_unix_separator_present("foo\\bar"));
        assert!(is_windows_separator_present("foo\\bar"));
        assert!(!is_windows_separator_present("foo/bar"));
    }
}
