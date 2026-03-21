//! Path characteristic detection
//!
//! Pure functions for detecting path properties and characteristics.
//! These functions answer questions like "Is this path absolute?",
//! "Is this a hidden file?", "What platform is this path format?"
//!
//! ## Design Principles
//!
//! 1. **Detection Only**: No validation or sanitization
//! 2. **No Logging**: Pure functions, no trace/debug calls
//! 3. **Cross-Platform**: Detects both Unix and Windows formats
//! 4. **Delegates to Common**: Uses common module for low-level checks
//!
//! ## Security Standards
//!
//! While this module is about characteristics (not security), it supports
//! security operations by accurately detecting path properties:
//! - **CWE-22**: Path type detection helps identify traversal vectors
//! - Platform detection prevents bypass through format confusion

use super::super::common;
use super::super::types::{PathType, Platform};

// ============================================================================
// Absolute vs Relative
// ============================================================================

/// Check if path is absolute
///
/// Detects absolute paths on any platform:
/// - Unix: Starts with `/`
/// - Windows: Drive letter (C:\) or UNC path (\\server\share)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_absolute("/etc/passwd"));
/// assert!(detection::is_absolute("C:\\Windows"));
/// assert!(detection::is_absolute("\\\\server\\share"));
/// assert!(!detection::is_absolute("relative/path"));
/// assert!(!detection::is_absolute("")); // Empty is not absolute
/// ```
#[must_use]
pub fn is_absolute(path: &str) -> bool {
    common::is_absolute(path)
}

/// Check if path is relative (not absolute)
///
/// A path is relative if it doesn't start from a root location.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_relative("relative/path"));
/// assert!(detection::is_relative("./current"));
/// assert!(detection::is_relative("../parent"));
/// assert!(detection::is_relative("file.txt"));
/// assert!(detection::is_relative("")); // Empty is relative
/// assert!(!detection::is_relative("/etc/passwd"));
/// ```
#[must_use]
pub fn is_relative(path: &str) -> bool {
    common::is_relative(path)
}

// ============================================================================
// Hidden Files
// ============================================================================

/// Check if path refers to a hidden file or directory
///
/// On Unix, hidden files start with a dot (`.`).
/// On Windows, hidden files are a filesystem attribute (not detectable from path alone).
///
/// This checks only the final filename component.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_hidden(".gitignore"));
/// assert!(detection::is_hidden(".bashrc"));
/// assert!(detection::is_hidden("/home/user/.config"));
/// assert!(detection::is_hidden("dir/.hidden"));
/// assert!(!detection::is_hidden("visible.txt"));
/// assert!(!detection::is_hidden(".")); // Current dir reference
/// assert!(!detection::is_hidden("..")); // Parent dir reference
/// assert!(!detection::is_hidden(".config/file")); // file is not hidden
/// ```
#[must_use]
pub fn is_hidden(path: &str) -> bool {
    let filename = common::filename(path);
    filename.starts_with('.') && filename != "." && filename != ".."
}

/// Check if any component in the path is hidden
///
/// Returns true if any directory or file in the path is hidden (starts with dot).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_hidden_component_present(".git/config"));
/// assert!(detection::is_hidden_component_present("dir/.hidden/file"));
/// assert!(detection::is_hidden_component_present("/home/user/.config/app"));
/// assert!(!detection::is_hidden_component_present("visible/path/file"));
/// assert!(!detection::is_hidden_component_present("./relative")); // . is not hidden
/// assert!(!detection::is_hidden_component_present("../parent")); // .. is not hidden
/// ```
#[must_use]
pub fn is_hidden_component_present(path: &str) -> bool {
    common::split(path).iter().any(|component| {
        !component.is_empty()
            && component.starts_with('.')
            && *component != "."
            && *component != ".."
    })
}

// ============================================================================
// Path Type Detection
// ============================================================================

/// Detect the type/format of a path
///
/// Returns the most specific PathType that matches:
/// - `UnixAbsolute`: `/etc/passwd`
/// - `UnixRelative`: `path/to/file`
/// - `WindowsAbsolute`: `C:\Windows`
/// - `WindowsUnc`: `\\server\share`
/// - `WindowsRelative`: `path\to\file`
/// - `Unknown`: empty or unrecognized
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
/// use octarine::primitives::paths::types::PathType;
///
/// assert_eq!(detection::detect_path_type("/etc"), PathType::UnixAbsolute);
/// assert_eq!(detection::detect_path_type("C:\\Windows"), PathType::WindowsAbsolute);
/// assert_eq!(detection::detect_path_type("\\\\server\\share"), PathType::WindowsUnc);
/// assert_eq!(detection::detect_path_type("relative\\path"), PathType::WindowsRelative);
/// assert_eq!(detection::detect_path_type("relative/path"), PathType::UnixRelative);
/// assert_eq!(detection::detect_path_type(""), PathType::Unknown);
/// ```
#[must_use]
pub fn detect_path_type(path: &str) -> PathType {
    if path.is_empty() {
        return PathType::Unknown;
    }

    // Check for Windows UNC path first (most specific)
    if common::is_unc_path(path) {
        return PathType::WindowsUnc;
    }

    // Check for Windows drive letter
    if common::is_drive_letter_present(path) {
        return PathType::WindowsAbsolute;
    }

    // Check for Unix absolute
    if path.starts_with('/') {
        return PathType::UnixAbsolute;
    }

    // Check for Windows-style (backslashes only, no forward slashes)
    if common::is_windows_style(path) {
        return PathType::WindowsRelative;
    }

    // Default to Unix relative (forward slashes or no separators)
    PathType::UnixRelative
}

// ============================================================================
// Platform Detection
// ============================================================================

/// Detect the platform a path was formatted for
///
/// Returns `Platform::Windows` for paths with drive letters, UNC prefixes,
/// or backslash-only separators. Returns `Platform::Unix` for paths with
/// forward slashes or no separators. Returns `Platform::Auto` for empty paths.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
/// use octarine::primitives::paths::types::Platform;
///
/// assert_eq!(detection::detect_platform("C:\\Windows"), Platform::Windows);
/// assert_eq!(detection::detect_platform("\\\\server\\share"), Platform::Windows);
/// assert_eq!(detection::detect_platform("/home/user"), Platform::Unix);
/// assert_eq!(detection::detect_platform("relative/path"), Platform::Unix);
/// assert_eq!(detection::detect_platform(""), Platform::Auto);
/// ```
#[must_use]
pub fn detect_platform(path: &str) -> Platform {
    match detect_path_type(path) {
        PathType::WindowsAbsolute | PathType::WindowsUnc | PathType::WindowsRelative => {
            Platform::Windows
        }
        PathType::UnixAbsolute | PathType::UnixRelative => Platform::Unix,
        PathType::Unknown => Platform::Auto,
    }
}

/// Check if path uses Windows format
///
/// Returns true for paths with drive letters, UNC prefixes, or backslash-only separators.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_windows_path("C:\\Windows"));
/// assert!(detection::is_windows_path("\\\\server\\share"));
/// assert!(detection::is_windows_path("path\\to\\file"));
/// assert!(!detection::is_windows_path("/home/user"));
/// assert!(!detection::is_windows_path("path/to/file"));
/// ```
#[must_use]
pub fn is_windows_path(path: &str) -> bool {
    matches!(detect_platform(path), Platform::Windows)
}

/// Check if path uses Unix format
///
/// Returns true for paths with forward slashes or no separators (not Windows-style).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_unix_path("/home/user"));
/// assert!(detection::is_unix_path("path/to/file"));
/// assert!(detection::is_unix_path("file.txt")); // No separators = Unix by default
/// assert!(!detection::is_unix_path("C:\\Windows"));
/// assert!(!detection::is_unix_path("path\\to\\file"));
/// ```
#[must_use]
pub fn is_unix_path(path: &str) -> bool {
    matches!(detect_platform(path), Platform::Unix)
}

/// Check if path is portable (works on both Windows and Unix)
///
/// A portable path:
/// - Uses only forward slashes
/// - No drive letters
/// - No UNC paths
/// - Is relative
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_portable("path/to/file.txt"));
/// assert!(detection::is_portable("relative/path"));
/// assert!(detection::is_portable("file.txt"));
/// assert!(!detection::is_portable("C:\\Windows")); // Drive letter
/// assert!(!detection::is_portable("/absolute/path")); // Absolute
/// assert!(!detection::is_portable("path\\with\\backslash")); // Backslash
/// ```
#[must_use]
pub fn is_portable(path: &str) -> bool {
    common::is_portable(path)
}

// ============================================================================
// Separator Detection
// ============================================================================

/// Check if path uses forward slashes
#[must_use]
pub fn is_forward_slashes_present(path: &str) -> bool {
    common::is_forward_slashes_present(path)
}

/// Check if path uses backslashes
#[must_use]
pub fn is_backslashes_present(path: &str) -> bool {
    common::is_backslashes_present(path)
}

/// Check if path has mixed separators (both forward and backslashes)
///
/// Mixed separators can cause parsing issues and security filter bypasses.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_mixed_separators_present("path/to\\file"));
/// assert!(detection::is_mixed_separators_present("C:\\Users/Documents"));
/// assert!(!detection::is_mixed_separators_present("path/to/file"));
/// assert!(!detection::is_mixed_separators_present("path\\to\\file"));
/// ```
#[must_use]
pub fn is_mixed_separators_present(path: &str) -> bool {
    common::is_mixed_separators_present(path)
}

// ============================================================================
// Extension Detection
// ============================================================================

/// Check if path has a file extension
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_extension_present("file.txt"));
/// assert!(detection::is_extension_present("archive.tar.gz"));
/// assert!(!detection::is_extension_present("file_no_ext"));
/// assert!(!detection::is_extension_present(".gitignore")); // Hidden file, no extension
/// ```
#[must_use]
pub fn is_extension_present(path: &str) -> bool {
    common::find_extension(path).is_some()
}

/// Find the file extension (without leading dot)
///
/// Returns `None` for files without extensions, including hidden files
/// like `.gitignore` that have no extension after the dot.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert_eq!(detection::find_extension("file.txt"), Some("txt"));
/// assert_eq!(detection::find_extension("archive.tar.gz"), Some("gz"));
/// assert_eq!(detection::find_extension(".gitignore"), None); // Hidden, no extension
/// assert_eq!(detection::find_extension("noextension"), None);
/// assert_eq!(detection::find_extension("trailing."), None); // Empty extension
/// ```
#[must_use]
pub fn find_extension(path: &str) -> Option<&str> {
    common::find_extension(path)
}

/// Check if path has a specific extension (case-insensitive)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_extension_found("file.TXT", "txt"));
/// assert!(detection::is_extension_found("file.txt", "TXT"));
/// assert!(!detection::is_extension_found("file.txt", "pdf"));
/// ```
#[must_use]
pub fn is_extension_found(path: &str, ext: &str) -> bool {
    common::is_extension_found(path, ext)
}

// ============================================================================
// Directory Detection
// ============================================================================

/// Check if path ends with a directory separator
///
/// This is a syntactic check - it doesn't access the filesystem.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_directory_path("path/to/dir/"));
/// assert!(detection::is_directory_path("path\\to\\dir\\"));
/// assert!(!detection::is_directory_path("path/to/file"));
/// assert!(!detection::is_directory_path("file.txt"));
/// ```
#[must_use]
pub fn is_directory_path(path: &str) -> bool {
    path.ends_with('/') || path.ends_with('\\')
}

/// Check if path is just a filename (no directory components)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::is_filename_only("file.txt"));
/// assert!(detection::is_filename_only(".gitignore"));
/// assert!(!detection::is_filename_only("path/file.txt"));
/// assert!(!detection::is_filename_only("/file.txt"));
/// ```
#[must_use]
pub fn is_filename_only(path: &str) -> bool {
    !path.contains('/') && !path.contains('\\')
}

// ============================================================================
// Depth Calculation
// ============================================================================

/// Calculate the depth of the path (number of meaningful components)
///
/// Excludes empty components and `.`/`..` references.
/// This is useful for security depth limiting.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert_eq!(detection::calculate_path_depth("path/to/file.txt"), 3);
/// assert_eq!(detection::calculate_path_depth("file.txt"), 1);
/// assert_eq!(detection::calculate_path_depth("/root"), 1); // Ignores empty from leading /
/// assert_eq!(detection::calculate_path_depth("./file"), 1); // Ignores .
/// assert_eq!(detection::calculate_path_depth("../parent/file"), 2); // Ignores ..
/// assert_eq!(detection::calculate_path_depth(""), 0);
/// ```
#[must_use]
pub fn calculate_path_depth(path: &str) -> usize {
    common::split(path)
        .iter()
        .filter(|s| !s.is_empty() && **s != "." && **s != "..")
        .count()
}

/// Calculate the total depth including all components
///
/// This counts all non-empty components including `.` and `..`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert_eq!(detection::calculate_total_depth("path/to/file.txt"), 3);
/// assert_eq!(detection::calculate_total_depth("./path/file"), 3); // Includes .
/// assert_eq!(detection::calculate_total_depth("../parent/file"), 3); // Includes ..
/// ```
#[must_use]
pub fn calculate_total_depth(path: &str) -> usize {
    common::split(path).iter().filter(|s| !s.is_empty()).count()
}

// ============================================================================
// Special Path Detection
// ============================================================================

/// Check if path starts with current directory reference (`./` or `.\`)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::starts_with_current_dir("./file.txt"));
/// assert!(detection::starts_with_current_dir(".\\file.txt"));
/// assert!(detection::starts_with_current_dir("."));
/// assert!(!detection::starts_with_current_dir("file.txt"));
/// assert!(!detection::starts_with_current_dir(".hidden")); // Hidden file, not current dir
/// ```
#[must_use]
pub fn starts_with_current_dir(path: &str) -> bool {
    common::starts_with_current_dir(path)
}

/// Check if path starts with parent directory reference (`../` or `..\`)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::starts_with_parent_dir("../file.txt"));
/// assert!(detection::starts_with_parent_dir("..\\file.txt"));
/// assert!(detection::starts_with_parent_dir(".."));
/// assert!(!detection::starts_with_parent_dir("file.txt"));
/// assert!(!detection::starts_with_parent_dir("..hidden")); // Not parent reference
/// ```
#[must_use]
pub fn starts_with_parent_dir(path: &str) -> bool {
    common::starts_with_parent_dir(path)
}

/// Check if path starts with home directory reference (`~/` or `~\`)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::characteristic::detection;
///
/// assert!(detection::starts_with_home_dir("~/Documents"));
/// assert!(detection::starts_with_home_dir("~/.config"));
/// assert!(detection::starts_with_home_dir("~"));
/// assert!(!detection::starts_with_home_dir("/home/user"));
/// assert!(!detection::starts_with_home_dir("~user")); // User home, not current user
/// ```
#[must_use]
pub fn starts_with_home_dir(path: &str) -> bool {
    common::starts_with_home_dir(path)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Absolute/Relative Tests =====

    #[test]
    fn test_is_absolute_unix() {
        assert!(is_absolute("/"));
        assert!(is_absolute("/etc/passwd"));
        assert!(is_absolute("/home/user/file.txt"));
    }

    #[test]
    fn test_is_absolute_windows() {
        assert!(is_absolute("C:\\"));
        assert!(is_absolute("C:\\Windows\\System32"));
        assert!(is_absolute("D:/Program Files"));
        assert!(is_absolute("\\\\server\\share"));
        assert!(is_absolute("\\\\server\\share\\path"));
    }

    #[test]
    fn test_is_relative() {
        assert!(is_relative("relative/path"));
        assert!(is_relative("./current"));
        assert!(is_relative("../parent"));
        assert!(is_relative("file.txt"));
        assert!(is_relative("")); // Empty is relative
    }

    // ===== Hidden Tests =====

    #[test]
    fn test_is_hidden() {
        assert!(is_hidden(".gitignore"));
        assert!(is_hidden(".bashrc"));
        assert!(is_hidden("/home/user/.config"));
        assert!(is_hidden("dir/.hidden"));
        assert!(!is_hidden("visible.txt"));
        assert!(!is_hidden(".")); // Current dir
        assert!(!is_hidden("..")); // Parent dir
        assert!(!is_hidden(".config/file")); // file is not hidden
    }

    #[test]
    fn test_is_hidden_component_present() {
        assert!(is_hidden_component_present(".git/config"));
        assert!(is_hidden_component_present("dir/.hidden/file"));
        assert!(is_hidden_component_present("/home/user/.config/app"));
        assert!(is_hidden_component_present(".hidden"));
        assert!(!is_hidden_component_present("visible/path/file"));
        assert!(!is_hidden_component_present("./relative")); // . is not hidden
        assert!(!is_hidden_component_present("../parent")); // .. is not hidden
    }

    // ===== Path Type Tests =====

    #[test]
    fn test_detect_path_type() {
        assert_eq!(detect_path_type("/etc"), PathType::UnixAbsolute);
        assert_eq!(detect_path_type("C:\\Windows"), PathType::WindowsAbsolute);
        assert_eq!(detect_path_type("\\\\server\\share"), PathType::WindowsUnc);
        assert_eq!(
            detect_path_type("relative\\path"),
            PathType::WindowsRelative
        );
        assert_eq!(detect_path_type("relative/path"), PathType::UnixRelative);
        assert_eq!(detect_path_type("file.txt"), PathType::UnixRelative);
        assert_eq!(detect_path_type(""), PathType::Unknown);
    }

    // ===== Platform Tests =====

    #[test]
    fn test_detect_platform() {
        assert_eq!(detect_platform("C:\\Windows"), Platform::Windows);
        assert_eq!(detect_platform("\\\\server\\share"), Platform::Windows);
        assert_eq!(detect_platform("path\\to\\file"), Platform::Windows);
        assert_eq!(detect_platform("/home/user"), Platform::Unix);
        assert_eq!(detect_platform("path/to/file"), Platform::Unix);
        assert_eq!(detect_platform(""), Platform::Auto);
    }

    #[test]
    fn test_is_windows_path() {
        assert!(is_windows_path("C:\\Windows"));
        assert!(is_windows_path("\\\\server\\share"));
        assert!(is_windows_path("path\\to\\file"));
        assert!(!is_windows_path("/home/user"));
        assert!(!is_windows_path("path/to/file"));
    }

    #[test]
    fn test_is_unix_path() {
        assert!(is_unix_path("/home/user"));
        assert!(is_unix_path("path/to/file"));
        assert!(is_unix_path("file.txt"));
        assert!(!is_unix_path("C:\\Windows"));
        assert!(!is_unix_path("path\\to\\file"));
    }

    #[test]
    fn test_is_portable() {
        assert!(is_portable("path/to/file.txt"));
        assert!(is_portable("relative/path"));
        assert!(is_portable("file.txt"));
        assert!(!is_portable("C:\\Windows"));
        assert!(!is_portable("/absolute/path"));
        assert!(!is_portable("path\\with\\backslash"));
    }

    // ===== Extension Tests =====

    #[test]
    fn test_find_extension() {
        assert_eq!(find_extension("file.txt"), Some("txt"));
        assert_eq!(find_extension("archive.tar.gz"), Some("gz"));
        assert_eq!(find_extension(".gitignore"), None); // Hidden, no extension
        assert_eq!(find_extension("noextension"), None);
    }

    #[test]
    fn test_is_extension_present() {
        assert!(is_extension_present("file.txt"));
        assert!(is_extension_present("archive.tar.gz"));
        assert!(!is_extension_present("file_no_ext"));
        assert!(!is_extension_present(".gitignore"));
    }

    #[test]
    fn test_is_extension_found() {
        assert!(is_extension_found("file.TXT", "txt"));
        assert!(is_extension_found("file.txt", "TXT"));
        assert!(!is_extension_found("file.txt", "pdf"));
    }

    // ===== Directory Tests =====

    #[test]
    fn test_is_directory_path() {
        assert!(is_directory_path("path/to/dir/"));
        assert!(is_directory_path("path\\to\\dir\\"));
        assert!(!is_directory_path("path/to/file"));
        assert!(!is_directory_path("file.txt"));
    }

    #[test]
    fn test_is_filename_only() {
        assert!(is_filename_only("file.txt"));
        assert!(is_filename_only(".gitignore"));
        assert!(!is_filename_only("path/file.txt"));
        assert!(!is_filename_only("/file.txt"));
    }

    // ===== Depth Tests =====

    #[test]
    fn test_calculate_path_depth() {
        assert_eq!(calculate_path_depth("path/to/file.txt"), 3);
        assert_eq!(calculate_path_depth("file.txt"), 1);
        assert_eq!(calculate_path_depth("/root"), 1); // Ignores empty from leading /
        assert_eq!(calculate_path_depth("./file"), 1); // Ignores .
        assert_eq!(calculate_path_depth(""), 0);
    }

    #[test]
    fn test_calculate_total_depth() {
        assert_eq!(calculate_total_depth("path/to/file.txt"), 3);
        assert_eq!(calculate_total_depth("./path/file"), 3); // Includes .
        assert_eq!(calculate_total_depth("../parent/file"), 3); // Includes ..
    }

    // ===== Special Path Tests =====

    #[test]
    fn test_starts_with_current_dir() {
        assert!(starts_with_current_dir("./file.txt"));
        assert!(starts_with_current_dir(".\\file.txt"));
        assert!(starts_with_current_dir("."));
        assert!(!starts_with_current_dir("file.txt"));
        assert!(!starts_with_current_dir(".hidden"));
    }

    #[test]
    fn test_starts_with_parent_dir() {
        assert!(starts_with_parent_dir("../file.txt"));
        assert!(starts_with_parent_dir("..\\file.txt"));
        assert!(starts_with_parent_dir(".."));
        assert!(!starts_with_parent_dir("file.txt"));
        assert!(!starts_with_parent_dir("..hidden"));
    }

    #[test]
    fn test_starts_with_home_dir() {
        assert!(starts_with_home_dir("~/Documents"));
        assert!(starts_with_home_dir("~/.config"));
        assert!(starts_with_home_dir("~"));
        assert!(!starts_with_home_dir("/home/user"));
        assert!(!starts_with_home_dir("~user"));
    }

    // ===== Edge Cases =====

    #[test]
    fn test_empty_path() {
        assert!(!is_absolute(""));
        assert!(is_relative(""));
        assert!(!is_hidden(""));
        assert_eq!(detect_path_type(""), PathType::Unknown);
        assert_eq!(detect_platform(""), Platform::Auto);
        assert_eq!(calculate_path_depth(""), 0);
    }

    #[test]
    fn test_separators() {
        assert!(is_forward_slashes_present("path/to/file"));
        assert!(!is_forward_slashes_present("path\\to\\file"));
        assert!(is_backslashes_present("path\\to\\file"));
        assert!(!is_backslashes_present("path/to/file"));
        assert!(is_mixed_separators_present("path/to\\file"));
        assert!(!is_mixed_separators_present("path/to/file"));
    }
}
