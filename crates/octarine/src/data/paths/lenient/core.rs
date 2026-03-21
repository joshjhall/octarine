//! Core lenient sanitization functions
//!
//! These always return a valid value - they catch errors and return safe defaults.

use crate::primitives::data::paths::{
    FilenameBuilder, FormatBuilder, PathBuilder as PrimitivePathBuilder,
};
use crate::primitives::security::paths::SecurityBuilder;

/// Clean a path - always returns a safe value
///
/// Unlike `sanitize_path` which returns an error on threats,
/// this function removes threats and returns a cleaned path.
/// If the path is completely invalid, returns an empty string.
pub(in crate::data::paths) fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let security = SecurityBuilder::new();

    // Try to sanitize - if it fails, do manual cleaning
    match security.sanitize(path) {
        Ok(cleaned) => cleaned,
        Err(_) => {
            // Manual cleaning: remove known dangerous patterns
            let mut result = path.to_string();

            // Remove null bytes
            result = result.replace('\0', "");

            // Remove command injection patterns
            result = result.replace("$(", "");
            result = result.replace(")", "");
            result = result.replace("`", "");

            // Remove shell metacharacters
            for c in [';', '|', '&', '>', '<', '\n', '\r'] {
                result = result.replace(c, "");
            }

            // Collapse path traversal (not ideal, but better than failing)
            while result.contains("..") {
                result = result.replace("..", ".");
            }

            // Normalize separators
            result = result.replace('\\', "/");

            // Collapse multiple slashes
            while result.contains("//") {
                result = result.replace("//", "/");
            }

            result
        }
    }
}

/// Clean a user-provided path - always returns a safe value
///
/// More aggressive cleaning for untrusted user input.
pub(in crate::data::paths) fn clean_user_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // First do basic cleaning
    let cleaned = clean_path(path);

    // Additional user path cleaning:
    // - Remove leading slashes (prevent absolute path injection)
    let mut result = cleaned.trim_start_matches('/').to_string();

    // - Remove Windows drive letters
    if result.len() >= 2 && result.chars().nth(1) == Some(':') {
        result = result[2..].to_string();
        result = result
            .trim_start_matches('/')
            .trim_start_matches('\\')
            .to_string();
    }

    // - Ensure no path traversal remains
    let parts: Vec<&str> = result
        .split('/')
        .filter(|p| *p != ".." && !p.is_empty())
        .collect();
    parts.join("/")
}

/// Clean a filename - always returns a safe filename
///
/// Removes dangerous characters and ensures a valid filename.
/// If the input is completely invalid, returns "unnamed".
pub(in crate::data::paths) fn clean_filename(filename: &str) -> String {
    if filename.is_empty() {
        return "unnamed".to_string();
    }

    let fb = FilenameBuilder::new();

    // Try the builder's safe filename function
    let safe = fb.to_safe_filename(filename);

    if safe.is_empty() {
        return "unnamed".to_string();
    }

    safe
}

/// Clean path separators - normalize to Unix style
///
/// Converts backslashes to forward slashes and collapses multiples.
pub(in crate::data::paths) fn clean_separators(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let format = FormatBuilder::new();
    let normalized = format.convert_to_unix(path);

    // Also normalize using primitives
    let path_builder = PrimitivePathBuilder::new();
    path_builder.normalize_unix(&normalized)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_clean_path_safe_input() {
        assert_eq!(clean_path("safe/path.txt"), "safe/path.txt");
        assert_eq!(clean_path("/absolute/path"), "/absolute/path");
    }

    #[test]
    fn test_clean_path_removes_traversal() {
        let result = clean_path("../../../etc/passwd");
        assert!(!result.contains(".."));
    }

    #[test]
    fn test_clean_path_removes_injection() {
        let result = clean_path("$(whoami)/file");
        // Removes command substitution syntax but may keep the command name
        assert!(!result.contains("$("));
        assert!(!result.contains(")"));
    }

    #[test]
    fn test_clean_path_removes_null_bytes() {
        let result = clean_path("file\0.txt");
        assert!(!result.contains('\0'));
    }

    #[test]
    fn test_clean_path_empty() {
        assert_eq!(clean_path(""), "");
    }

    #[test]
    fn test_clean_user_path_removes_absolute() {
        let result = clean_user_path("/etc/passwd");
        assert!(!result.starts_with('/'));
    }

    #[test]
    fn test_clean_user_path_removes_traversal() {
        let result = clean_user_path("../../../etc/passwd");
        assert!(!result.contains(".."));
    }

    #[test]
    fn test_clean_filename_valid() {
        assert_eq!(clean_filename("document.pdf"), "document.pdf");
    }

    #[test]
    fn test_clean_filename_removes_dangerous() {
        let result = clean_filename("file<>:\"|?*.txt");
        // The underlying primitive removes most dangerous chars
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
        // Note: some chars may be kept depending on platform
    }

    #[test]
    fn test_clean_filename_empty() {
        assert_eq!(clean_filename(""), "unnamed");
    }

    #[test]
    fn test_clean_separators() {
        assert_eq!(clean_separators("path\\to\\file"), "path/to/file");
        assert_eq!(clean_separators("path//double//slash"), "path/double/slash");
    }
}
