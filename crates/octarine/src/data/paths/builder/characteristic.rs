//! Path characteristic operations builder with observability
//!
//! Wraps `primitives::data::paths::CharacteristicBuilder` with observe instrumentation.
//!
//! Provides path type detection, platform detection, and characteristic analysis.
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::CharacteristicBuilder;
//!
//! let chars = CharacteristicBuilder::new();
//!
//! // Path type detection
//! assert!(chars.is_absolute("/etc/passwd"));
//! assert!(chars.is_relative("relative/path"));
//!
//! // Platform detection
//! assert!(chars.is_unix_path("/home/user"));
//! assert!(chars.is_windows_path("C:\\Windows"));
//!
//! // Portability
//! assert!(chars.is_portable("relative/path"));
//! ```

use crate::observe::metrics::{MetricName, increment};
use crate::primitives::data::paths::CharacteristicBuilder as PrimitiveCharacteristicBuilder;

use crate::data::paths::types::{PathType, Platform};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn path_type_detected() -> MetricName {
        MetricName::new("data.paths.characteristic.path_type_detected").expect("valid metric name")
    }

    pub fn platform_detected() -> MetricName {
        MetricName::new("data.paths.characteristic.platform_detected").expect("valid metric name")
    }
}

/// Path characteristic operations builder with observability
///
/// Provides path analysis and detection with audit trail.
#[derive(Debug, Clone, Default)]
pub struct CharacteristicBuilder {
    emit_events: bool,
}

impl CharacteristicBuilder {
    /// Create a new characteristic builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Path Type Detection
    // ========================================================================

    /// Detect the type of a path
    #[must_use]
    pub fn detect_path_type(&self, path: &str) -> PathType {
        let path_type = PrimitiveCharacteristicBuilder::new()
            .detect_path_type(path)
            .into();
        if self.emit_events {
            increment(metric_names::path_type_detected());
        }
        path_type
    }

    /// Detect the platform of a path
    #[must_use]
    pub fn detect_platform(&self, path: &str) -> Platform {
        let platform = PrimitiveCharacteristicBuilder::new()
            .detect_platform(path)
            .into();
        if self.emit_events {
            increment(metric_names::platform_detected());
        }
        platform
    }

    /// Check if path is absolute
    #[must_use]
    pub fn is_absolute(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_absolute(path)
    }

    /// Check if path is relative
    #[must_use]
    pub fn is_relative(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_relative(path)
    }

    // ========================================================================
    // Platform Detection
    // ========================================================================

    /// Check if path is Unix-style
    #[must_use]
    pub fn is_unix_path(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_unix_path(path)
    }

    /// Check if path is Windows-style
    #[must_use]
    pub fn is_windows_path(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_windows_path(path)
    }

    /// Check if path is portable (works on both Unix and Windows)
    #[must_use]
    pub fn is_portable(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_portable(path)
    }

    // ========================================================================
    // Hidden File Detection
    // ========================================================================

    /// Check if file is hidden (starts with .)
    #[must_use]
    pub fn is_hidden(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_hidden(path)
    }

    /// Check if path has hidden component
    #[must_use]
    pub fn is_hidden_component_present(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_hidden_component_present(path)
    }

    // ========================================================================
    // Extension Detection
    // ========================================================================

    /// Check if path has extension
    #[must_use]
    pub fn is_extension_present(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_extension_present(path)
    }

    /// Find extension from path
    #[must_use]
    pub fn find_extension<'a>(&self, path: &'a str) -> Option<&'a str> {
        PrimitiveCharacteristicBuilder::new().find_extension(path)
    }

    // ========================================================================
    // Path Analysis
    // ========================================================================

    /// Calculate path depth (number of components)
    #[must_use]
    pub fn calculate_path_depth(&self, path: &str) -> usize {
        PrimitiveCharacteristicBuilder::new().calculate_path_depth(path)
    }

    /// Calculate total depth including root for absolute paths
    #[must_use]
    pub fn calculate_total_depth(&self, path: &str) -> usize {
        PrimitiveCharacteristicBuilder::new().calculate_total_depth(path)
    }

    /// Check if path has only ASCII characters
    #[must_use]
    pub fn is_ascii_only(&self, path: &str) -> bool {
        path.is_ascii()
    }

    /// Check if path is empty
    #[must_use]
    pub fn is_empty(&self, path: &str) -> bool {
        path.is_empty()
    }

    // ========================================================================
    // Separator Detection
    // ========================================================================

    /// Check if path has forward slashes
    #[must_use]
    pub fn is_forward_slashes_present(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_forward_slashes_present(path)
    }

    /// Check if path has backslashes
    #[must_use]
    pub fn is_backslashes_present(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_backslashes_present(path)
    }

    /// Check if path has mixed separators (both / and \)
    #[must_use]
    pub fn is_mixed_separators_present(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_mixed_separators_present(path)
    }

    // ========================================================================
    // Extension Matching
    // ========================================================================

    /// Check if path has a specific extension
    #[must_use]
    pub fn is_extension_found(&self, path: &str, ext: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_extension_found(path, ext)
    }

    // ========================================================================
    // Path Structure Detection
    // ========================================================================

    /// Check if path looks like a directory (ends with separator)
    #[must_use]
    pub fn is_directory_path(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_directory_path(path)
    }

    /// Check if path is just a filename (no directory components)
    #[must_use]
    pub fn is_filename_only(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().is_filename_only(path)
    }

    // ========================================================================
    // Prefix Detection
    // ========================================================================

    /// Check if path starts with current directory (./)
    #[must_use]
    pub fn starts_with_current_dir(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().starts_with_current_dir(path)
    }

    /// Check if path starts with parent directory (..)
    #[must_use]
    pub fn starts_with_parent_dir(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().starts_with_parent_dir(path)
    }

    /// Check if path starts with home directory (~)
    #[must_use]
    pub fn starts_with_home_dir(&self, path: &str) -> bool {
        PrimitiveCharacteristicBuilder::new().starts_with_home_dir(path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = CharacteristicBuilder::new();
        assert!(builder.emit_events);

        let silent = CharacteristicBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = CharacteristicBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_path_type_detection() {
        let chars = CharacteristicBuilder::silent();

        assert_eq!(
            chars.detect_path_type("/etc/passwd"),
            PathType::UnixAbsolute
        );
        assert_eq!(
            chars.detect_path_type("C:\\Windows"),
            PathType::WindowsAbsolute
        );
        assert_eq!(
            chars.detect_path_type("relative/path"),
            PathType::UnixRelative
        );
    }

    #[test]
    fn test_absolute_relative() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.is_absolute("/etc/passwd"));
        assert!(chars.is_absolute("C:\\Windows"));
        assert!(chars.is_relative("relative/path"));
        assert!(!chars.is_relative("/absolute"));
    }

    #[test]
    fn test_platform_detection() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.is_unix_path("/home/user"));
        assert!(chars.is_windows_path("C:\\Windows"));
        assert!(chars.is_portable("relative/path"));
        assert!(!chars.is_portable("/absolute/path"));
    }

    #[test]
    fn test_hidden_detection() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.is_hidden(".gitignore"));
        assert!(!chars.is_hidden("visible.txt"));
        assert!(chars.is_hidden_component_present(".git/config"));
    }

    #[test]
    fn test_extension_detection() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.is_extension_present("file.txt"));
        assert!(!chars.is_extension_present("file"));
        assert_eq!(chars.find_extension("file.txt"), Some("txt"));
    }

    #[test]
    fn test_calculate_path_depth() {
        let chars = CharacteristicBuilder::silent();

        assert_eq!(chars.calculate_path_depth("a/b/c"), 3);
        assert_eq!(chars.calculate_path_depth("file.txt"), 1);
        assert_eq!(chars.calculate_path_depth("a/b/c/d/e"), 5);
    }

    #[test]
    fn test_separator_detection() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.is_forward_slashes_present("a/b/c"));
        assert!(!chars.is_forward_slashes_present("a\\b\\c"));
        assert!(chars.is_backslashes_present("a\\b\\c"));
        assert!(!chars.is_backslashes_present("a/b/c"));
        assert!(chars.is_mixed_separators_present("a/b\\c"));
        assert!(!chars.is_mixed_separators_present("a/b/c"));
    }

    #[test]
    fn test_specific_extension() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.is_extension_found("file.txt", "txt"));
        assert!(chars.is_extension_found("file.TXT", "txt"));
        assert!(!chars.is_extension_found("file.txt", "pdf"));
    }

    #[test]
    fn test_path_structure() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.is_directory_path("dir/"));
        assert!(!chars.is_directory_path("file.txt"));
        assert!(chars.is_filename_only("file.txt"));
        assert!(!chars.is_filename_only("dir/file.txt"));
    }

    #[test]
    fn test_prefix_detection() {
        let chars = CharacteristicBuilder::silent();

        assert!(chars.starts_with_current_dir("./file"));
        assert!(!chars.starts_with_current_dir("file"));
        assert!(chars.starts_with_parent_dir("../file"));
        assert!(!chars.starts_with_parent_dir("file"));
        assert!(chars.starts_with_home_dir("~/file"));
        assert!(!chars.starts_with_home_dir("file"));
    }

    #[test]
    fn test_calculate_total_depth() {
        let chars = CharacteristicBuilder::silent();

        // Relative paths: same as calculate_path_depth
        assert_eq!(chars.calculate_total_depth("a/b/c"), 3);
        // Absolute paths: includes root
        assert!(chars.calculate_total_depth("/a/b/c") >= 3);
    }
}
