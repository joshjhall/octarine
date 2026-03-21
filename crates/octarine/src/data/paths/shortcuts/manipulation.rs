//! Path manipulation shortcuts
//!
//! Convenience functions for path manipulation and construction.

use crate::primitives::data::paths::{FormatBuilder, PathBuilder as PrimitivePathBuilder};

use super::super::PathBuilder;

// ============================================================
// PATH MANIPULATION SHORTCUTS
// ============================================================

/// Join two path segments
pub fn join_path(base: &str, path: &str) -> String {
    PathBuilder::new().join(base, path)
}

/// Get parent directory
pub fn parent_path(path: &str) -> Option<&str> {
    PrimitivePathBuilder::new().find_parent(path)
}

/// Get filename from path
pub fn filename(path: &str) -> &str {
    PrimitivePathBuilder::new().filename(path)
}

/// Get file extension
pub fn extension(path: &str) -> Option<&str> {
    PrimitivePathBuilder::new().find_extension(path)
}

/// Get filename stem (without extension)
pub fn stem(path: &str) -> &str {
    PrimitivePathBuilder::new().stem(path)
}

/// Clean a path by resolving . and ..
///
/// This is a pure path manipulation - does not access filesystem.
pub fn clean_path_components(path: &str) -> String {
    PrimitivePathBuilder::new().clean_path(path)
}

/// Convert a relative path to absolute by resolving against a base
pub fn to_absolute_path(base: &str, path: &str) -> String {
    PrimitivePathBuilder::new().to_absolute_path(base, path)
}

/// Convert an absolute path to a relative path from one location to another
pub fn to_relative_path(from: &str, to: &str) -> String {
    PrimitivePathBuilder::new().to_relative_path(from, to)
}

/// Normalize path to Unix format
pub fn normalize_path(path: &str) -> String {
    PrimitivePathBuilder::new().normalize_unix(path)
}

// ============================================================
// FORMAT CONVERSION SHORTCUTS
// ============================================================

/// Convert path to Unix format
pub fn to_unix_path(path: &str) -> String {
    FormatBuilder::new().convert_to_unix(path).into_owned()
}

/// Convert path to Windows format
pub fn to_windows_path(path: &str) -> String {
    FormatBuilder::new().convert_to_windows(path).into_owned()
}

/// Convert Windows path to WSL path
pub fn to_wsl_path(path: &str) -> Option<String> {
    FormatBuilder::new().convert_to_wsl(path)
}

/// Convert WSL path to Windows path
pub fn wsl_to_windows_path(path: &str) -> Option<String> {
    FormatBuilder::new().wsl_to_windows(path)
}

/// Get ancestors of a path
///
/// Returns a vector of parent paths from immediate parent to root.
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::ancestors;
/// let result = ancestors("a/b/c/file.txt");
/// assert_eq!(result, vec!["a/b/c", "a/b", "a"]);
/// ```
pub fn ancestors(path: &str) -> Vec<&str> {
    PrimitivePathBuilder::new().ancestors(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_manipulation_shortcuts() {
        assert_eq!(join_path("base", "file.txt"), "base/file.txt");
        assert_eq!(parent_path("/home/user/file.txt"), Some("/home/user"));
        assert_eq!(filename("/home/user/file.txt"), "file.txt");
        assert_eq!(extension("file.txt"), Some("txt"));
    }
}
