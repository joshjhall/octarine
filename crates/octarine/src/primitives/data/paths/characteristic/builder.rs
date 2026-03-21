//! CharacteristicBuilder for path property detection
//!
//! Provides a builder-style API for detecting path characteristics.
//! This is a convenience wrapper around the detection functions.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::primitives::paths::characteristic::CharacteristicBuilder;
//!
//! let builder = CharacteristicBuilder::new();
//!
//! // Absolute/Relative
//! assert!(builder.is_absolute("/etc/passwd"));
//! assert!(builder.is_relative("path/to/file"));
//!
//! // Hidden
//! assert!(builder.is_hidden(".gitignore"));
//!
//! // Path Type
//! let path_type = builder.detect_path_type("C:\\Windows");
//!
//! // Platform
//! let platform = builder.detect_platform("/home/user");
//! ```

use super::super::types::{PathType, Platform};
use super::detection;

/// Builder for path characteristic detection
///
/// A stateless builder that provides a convenient API for accessing
/// path characteristic detection functions.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::paths::characteristic::CharacteristicBuilder;
///
/// let builder = CharacteristicBuilder::new();
///
/// // Check path properties
/// if builder.is_absolute("/etc/passwd") {
///     println!("Path is absolute");
/// }
///
/// // Get detailed type
/// let path_type = builder.detect_path_type("C:\\Windows");
/// println!("Path type: {:?}", path_type);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CharacteristicBuilder;

impl CharacteristicBuilder {
    /// Create a new CharacteristicBuilder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ==================== Absolute/Relative ====================

    /// Check if path is absolute
    ///
    /// See [`detection::is_absolute`] for details.
    #[must_use]
    pub fn is_absolute(&self, path: &str) -> bool {
        detection::is_absolute(path)
    }

    /// Check if path is relative
    ///
    /// See [`detection::is_relative`] for details.
    #[must_use]
    pub fn is_relative(&self, path: &str) -> bool {
        detection::is_relative(path)
    }

    // ==================== Hidden ====================

    /// Check if path refers to a hidden file
    ///
    /// See [`detection::is_hidden`] for details.
    #[must_use]
    pub fn is_hidden(&self, path: &str) -> bool {
        detection::is_hidden(path)
    }

    /// Check if any component in the path is hidden
    ///
    /// See [`detection::is_hidden_component_present`] for details.
    #[must_use]
    pub fn is_hidden_component_present(&self, path: &str) -> bool {
        detection::is_hidden_component_present(path)
    }

    // ==================== Path Type ====================

    /// Detect the type/format of a path
    ///
    /// See [`detection::detect_path_type`] for details.
    #[must_use]
    pub fn detect_path_type(&self, path: &str) -> PathType {
        detection::detect_path_type(path)
    }

    // ==================== Platform ====================

    /// Detect the platform a path was formatted for
    ///
    /// See [`detection::detect_platform`] for details.
    #[must_use]
    pub fn detect_platform(&self, path: &str) -> Platform {
        detection::detect_platform(path)
    }

    /// Check if path uses Windows format
    ///
    /// See [`detection::is_windows_path`] for details.
    #[must_use]
    pub fn is_windows_path(&self, path: &str) -> bool {
        detection::is_windows_path(path)
    }

    /// Check if path uses Unix format
    ///
    /// See [`detection::is_unix_path`] for details.
    #[must_use]
    pub fn is_unix_path(&self, path: &str) -> bool {
        detection::is_unix_path(path)
    }

    /// Check if path is portable (works on both Windows and Unix)
    ///
    /// See [`detection::is_portable`] for details.
    #[must_use]
    pub fn is_portable(&self, path: &str) -> bool {
        detection::is_portable(path)
    }

    // ==================== Separators ====================

    /// Check if path has forward slashes
    ///
    /// See [`detection::is_forward_slashes_present`] for details.
    #[must_use]
    pub fn is_forward_slashes_present(&self, path: &str) -> bool {
        detection::is_forward_slashes_present(path)
    }

    /// Check if path has backslashes
    ///
    /// See [`detection::is_backslashes_present`] for details.
    #[must_use]
    pub fn is_backslashes_present(&self, path: &str) -> bool {
        detection::is_backslashes_present(path)
    }

    /// Check if path has mixed separators
    ///
    /// See [`detection::is_mixed_separators_present`] for details.
    #[must_use]
    pub fn is_mixed_separators_present(&self, path: &str) -> bool {
        detection::is_mixed_separators_present(path)
    }

    // ==================== Extensions ====================

    /// Check if path has a file extension
    ///
    /// See [`detection::is_extension_present`] for details.
    #[must_use]
    pub fn is_extension_present(&self, path: &str) -> bool {
        detection::is_extension_present(path)
    }

    /// Find the file extension
    ///
    /// See [`detection::find_extension`] for details.
    #[must_use]
    pub fn find_extension<'a>(&self, path: &'a str) -> Option<&'a str> {
        detection::find_extension(path)
    }

    /// Check if path has a specific extension (case-insensitive)
    ///
    /// See [`detection::is_extension_found`] for details.
    #[must_use]
    pub fn is_extension_found(&self, path: &str, ext: &str) -> bool {
        detection::is_extension_found(path, ext)
    }

    // ==================== Directory ====================

    /// Check if path ends with a directory separator
    ///
    /// See [`detection::is_directory_path`] for details.
    #[must_use]
    pub fn is_directory_path(&self, path: &str) -> bool {
        detection::is_directory_path(path)
    }

    /// Check if path is just a filename (no directory components)
    ///
    /// See [`detection::is_filename_only`] for details.
    #[must_use]
    pub fn is_filename_only(&self, path: &str) -> bool {
        detection::is_filename_only(path)
    }

    // ==================== Depth ====================

    /// Calculate the depth of the path (meaningful components)
    ///
    /// See [`detection::calculate_path_depth`] for details.
    #[must_use]
    pub fn calculate_path_depth(&self, path: &str) -> usize {
        detection::calculate_path_depth(path)
    }

    /// Calculate the total depth including all components
    ///
    /// See [`detection::calculate_total_depth`] for details.
    #[must_use]
    pub fn calculate_total_depth(&self, path: &str) -> usize {
        detection::calculate_total_depth(path)
    }

    // ==================== Special Paths ====================

    /// Check if path starts with current directory reference
    ///
    /// See [`detection::starts_with_current_dir`] for details.
    #[must_use]
    pub fn starts_with_current_dir(&self, path: &str) -> bool {
        detection::starts_with_current_dir(path)
    }

    /// Check if path starts with parent directory reference
    ///
    /// See [`detection::starts_with_parent_dir`] for details.
    #[must_use]
    pub fn starts_with_parent_dir(&self, path: &str) -> bool {
        detection::starts_with_parent_dir(path)
    }

    /// Check if path starts with home directory reference
    ///
    /// See [`detection::starts_with_home_dir`] for details.
    #[must_use]
    pub fn starts_with_home_dir(&self, path: &str) -> bool {
        detection::starts_with_home_dir(path)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = CharacteristicBuilder::new();
        // Builder is stateless, just verify it can be created
        assert!(builder.is_relative("test"));
    }

    #[test]
    fn test_absolute_relative() {
        let builder = CharacteristicBuilder::new();

        assert!(builder.is_absolute("/etc/passwd"));
        assert!(builder.is_absolute("C:\\Windows"));
        assert!(builder.is_relative("relative/path"));
        assert!(builder.is_relative("file.txt"));
    }

    #[test]
    fn test_hidden() {
        let builder = CharacteristicBuilder::new();

        assert!(builder.is_hidden(".gitignore"));
        assert!(builder.is_hidden("/path/to/.hidden"));
        assert!(!builder.is_hidden("visible.txt"));
        assert!(!builder.is_hidden("."));
        assert!(!builder.is_hidden(".."));

        assert!(builder.is_hidden_component_present(".git/config"));
        assert!(!builder.is_hidden_component_present("visible/path"));
    }

    #[test]
    fn test_path_type() {
        let builder = CharacteristicBuilder::new();

        assert_eq!(builder.detect_path_type("/etc"), PathType::UnixAbsolute);
        assert_eq!(
            builder.detect_path_type("C:\\Windows"),
            PathType::WindowsAbsolute
        );
        assert_eq!(
            builder.detect_path_type("\\\\server\\share"),
            PathType::WindowsUnc
        );
        assert_eq!(
            builder.detect_path_type("relative/path"),
            PathType::UnixRelative
        );
    }

    #[test]
    fn test_platform() {
        let builder = CharacteristicBuilder::new();

        assert_eq!(builder.detect_platform("C:\\Windows"), Platform::Windows);
        assert_eq!(builder.detect_platform("/home/user"), Platform::Unix);
        assert!(builder.is_windows_path("C:\\Windows"));
        assert!(builder.is_unix_path("/home/user"));
        assert!(builder.is_portable("relative/path"));
    }

    #[test]
    fn test_extensions() {
        let builder = CharacteristicBuilder::new();

        assert!(builder.is_extension_present("file.txt"));
        assert!(!builder.is_extension_present(".gitignore"));
        assert_eq!(builder.find_extension("file.txt"), Some("txt"));
        assert!(builder.is_extension_found("file.TXT", "txt"));
    }

    #[test]
    fn test_directory() {
        let builder = CharacteristicBuilder::new();

        assert!(builder.is_directory_path("path/"));
        assert!(!builder.is_directory_path("path/file"));
        assert!(builder.is_filename_only("file.txt"));
        assert!(!builder.is_filename_only("path/file.txt"));
    }

    #[test]
    fn test_depth() {
        let builder = CharacteristicBuilder::new();

        assert_eq!(builder.calculate_path_depth("path/to/file"), 3);
        assert_eq!(builder.calculate_path_depth("./file"), 1);
        assert_eq!(builder.calculate_total_depth("./file"), 2);
    }

    #[test]
    fn test_special_paths() {
        let builder = CharacteristicBuilder::new();

        assert!(builder.starts_with_current_dir("./file"));
        assert!(builder.starts_with_parent_dir("../file"));
        assert!(builder.starts_with_home_dir("~/Documents"));
    }

    #[test]
    fn test_separators() {
        let builder = CharacteristicBuilder::new();

        assert!(builder.is_forward_slashes_present("path/to/file"));
        assert!(builder.is_backslashes_present("path\\to\\file"));
        assert!(builder.is_mixed_separators_present("path/to\\file"));
    }
}
