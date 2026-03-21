//! Additional format shortcuts
//!
//! Convenience functions for path format operations.

use super::super::FormatBuilder;

// ============================================================
// ADDITIONAL FORMAT SHORTCUTS
// ============================================================

/// Check if path has mixed separators (both / and \)
pub fn is_mixed_separators_present(path: &str) -> bool {
    FormatBuilder::new().is_mixed_separators_present(path)
}

/// Check if path has any format issues
pub fn is_format_issues_present(path: &str) -> bool {
    FormatBuilder::new().is_format_issues_present(path)
}

/// Convert path to portable format (relative, forward slashes)
pub fn to_portable_path(path: &str) -> String {
    FormatBuilder::new().convert_to_portable(path).into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_format_shortcuts() {
        assert!(is_mixed_separators_present("path/to\\file"));
        assert!(!is_mixed_separators_present("path/to/file"));
    }
}
