//! Path characteristic detection
//!
//! Detects path properties: absolute/relative, hidden, platform, extension, etc.
//!
//! ## Design Principles
//!
//! 1. **Detection Only**: No validation or sanitization
//! 2. **No Logging**: Pure functions, no trace/debug calls (Layer 1)
//! 3. **Cross-Platform**: Detects both Unix and Windows formats
//! 4. **Delegates to Common**: Uses common module for low-level operations
//!
//! ## Usage
//!
//! ### Direct Function Access
//!
//! ```rust,ignore
//! use crate::primitives::paths::characteristic::{is_absolute, is_hidden, detect_path_type};
//!
//! // Check path properties
//! assert!(is_absolute("/etc/passwd"));
//! assert!(is_hidden(".gitignore"));
//! assert_eq!(detect_path_type("C:\\Windows"), PathType::WindowsAbsolute);
//! ```
//!
//! ### Builder Pattern
//!
//! ```rust,ignore
//! use crate::primitives::paths::characteristic::CharacteristicBuilder;
//!
//! let builder = CharacteristicBuilder::new();
//!
//! // All detection functions accessible via builder
//! assert!(builder.is_absolute("/etc/passwd"));
//! assert!(builder.is_hidden(".gitignore"));
//! ```
//!
//! ## Categories
//!
//! - **Absolute/Relative**: `is_absolute()`, `is_relative()`
//! - **Hidden**: `is_hidden()`, `is_hidden_component_present()`
//! - **Path Type**: `detect_path_type()`
//! - **Platform**: `detect_platform()`, `is_windows_path()`, `is_unix_path()`, `is_portable()`
//! - **Separators**: `is_forward_slashes_present()`, `is_backslashes_present()`, `is_mixed_separators_present()`
//! - **Extensions**: `is_extension_present()`, `get_extension()`, `is_extension_found()`
//! - **Directory**: `is_directory_path()`, `is_filename_only()`
//! - **Depth**: `path_depth()`, `total_depth()`
//! - **Special Paths**: `starts_with_current_dir()`, `starts_with_parent_dir()`, `starts_with_home_dir()`

pub(crate) mod builder;
pub(crate) mod detection;

// Re-export builder
pub use builder::CharacteristicBuilder;

// Re-export commonly used detection functions
pub use detection::{
    // Depth
    calculate_path_depth,
    calculate_total_depth,
    // Path Type
    detect_path_type,
    // Platform
    detect_platform,
    // Extensions
    find_extension,
    // Absolute/Relative
    is_absolute,
    // Separators
    is_backslashes_present,
    // Directory
    is_directory_path,
    is_extension_found,
    is_extension_present,
    is_filename_only,
    is_forward_slashes_present,
    is_hidden,
    // Hidden
    is_hidden_component_present,
    is_mixed_separators_present,
    is_portable,
    is_relative,
    is_unix_path,
    is_windows_path,
    // Special Paths
    starts_with_current_dir,
    starts_with_home_dir,
    starts_with_parent_dir,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::types::{PathType, Platform};
    use super::*;

    /// Integration test: Verify module exports work correctly
    #[test]
    fn test_module_exports() {
        // All functions should be accessible directly
        assert!(is_absolute("/etc/passwd"));
        assert!(is_relative("relative/path"));
        assert!(is_hidden(".hidden"));
        assert!(!is_hidden_component_present("visible/path"));
        assert_eq!(detect_path_type("/etc"), PathType::UnixAbsolute);
        assert_eq!(detect_platform("/home"), Platform::Unix);
        assert!(is_portable("path/to/file"));
        assert!(is_unix_path("/home"));
        assert!(is_windows_path("C:\\Windows"));
        assert!(is_forward_slashes_present("path/file"));
        assert!(is_backslashes_present("path\\file"));
        assert!(!is_mixed_separators_present("path/file"));
        assert!(is_extension_present("file.txt"));
        assert_eq!(find_extension("file.txt"), Some("txt"));
        assert!(is_extension_found("file.TXT", "txt"));
        assert!(is_directory_path("path/"));
        assert!(is_filename_only("file.txt"));
        assert_eq!(calculate_path_depth("a/b/c"), 3);
        assert!(starts_with_current_dir("./file"));
        assert!(starts_with_parent_dir("../file"));
        assert!(starts_with_home_dir("~/file"));
    }

    /// Integration test: Builder provides same functionality
    #[test]
    fn test_builder_exports() {
        let builder = CharacteristicBuilder::new();

        // Builder should provide same results as direct functions
        assert_eq!(builder.is_absolute("/etc"), is_absolute("/etc"));
        assert_eq!(builder.is_relative("rel"), is_relative("rel"));
        assert_eq!(builder.is_hidden(".git"), is_hidden(".git"));
        assert_eq!(builder.detect_path_type("C:\\"), detect_path_type("C:\\"));
        assert_eq!(builder.detect_platform("/home"), detect_platform("/home"));
    }

    /// Integration test: Edge cases handled consistently
    #[test]
    fn test_edge_cases() {
        // Empty string
        assert!(!is_absolute(""));
        assert!(is_relative(""));
        assert!(!is_hidden(""));
        assert_eq!(detect_path_type(""), PathType::Unknown);
        assert_eq!(detect_platform(""), Platform::Auto);
        assert_eq!(calculate_path_depth(""), 0);

        // Single characters
        assert!(is_absolute("/"));
        assert!(is_absolute("\\"));
        assert!(!is_hidden("."));
        assert!(!is_hidden(".."));

        // Unicode paths
        assert!(is_relative("путь/к/файлу"));
        assert!(is_unix_path("путь/к/файлу"));
    }
}
