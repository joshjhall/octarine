//! Platform-specific path patterns
//!
//! Detection functions for platform-specific path characteristics.
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Windows paths: Drive letters, UNC paths, backslashes
//! - Unix paths: Forward slashes, root paths
//! - Cross-platform: Mixed separators, portable paths
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Detection Only**: Returns bool, no Result types
//! 3. **Reusable**: Used by validation and conversion layers

use std::path::Path;

// ============================================================================
// Separator Detection
// ============================================================================

/// Check if path uses forward slashes
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_forward_slashes_present("path/to/file"));
/// assert!(!platform::is_forward_slashes_present("path\\to\\file"));
/// ```
#[must_use]
pub fn is_forward_slashes_present(path: &str) -> bool {
    path.contains('/')
}

/// Check if path uses backslashes
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_backslashes_present("path\\to\\file"));
/// assert!(!platform::is_backslashes_present("path/to/file"));
/// ```
#[must_use]
pub fn is_backslashes_present(path: &str) -> bool {
    path.contains('\\')
}

/// Check if path uses mixed separators
///
/// Mixed separators can confuse parsers and security filters.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_mixed_separators_present("path/to\\file"));
/// assert!(!platform::is_mixed_separators_present("path/to/file"));
/// assert!(!platform::is_mixed_separators_present("path\\to\\file"));
/// ```
#[must_use]
pub fn is_mixed_separators_present(path: &str) -> bool {
    is_forward_slashes_present(path) && is_backslashes_present(path)
}

// ============================================================================
// Windows Path Detection
// ============================================================================

/// Check if path has a Windows drive letter prefix
///
/// Detects patterns like `C:`, `D:\`, `E:/`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_drive_letter_present("C:\\Windows"));
/// assert!(platform::is_drive_letter_present("D:/Users"));
/// assert!(platform::is_drive_letter_present("E:file.txt")); // Drive-relative
/// assert!(!platform::is_drive_letter_present("/unix/path"));
/// ```
#[must_use]
pub fn is_drive_letter_present(path: &str) -> bool {
    if path.len() >= 2 {
        let mut chars = path.chars();
        if let (Some(first), Some(second)) = (chars.next(), chars.next()) {
            return first.is_ascii_alphabetic() && second == ':';
        }
    }
    false
}

/// Check if path is a Windows UNC path
///
/// UNC paths start with `\\` or `//` followed by a server name.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_unc_path("\\\\server\\share"));
/// assert!(platform::is_unc_path("//server/share"));
/// assert!(!platform::is_unc_path("\\single\\backslash"));
/// assert!(!platform::is_unc_path("/unix/path"));
/// ```
#[must_use]
pub fn is_unc_path(path: &str) -> bool {
    path.starts_with("\\\\") || path.starts_with("//")
}

/// Check if path appears to be Windows-style
///
/// Detects paths that use Windows conventions:
/// - Drive letters (C:, D:, etc.)
/// - UNC paths (\\server\share)
/// - Backslash separators only (no forward slashes)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_windows_style("C:\\Windows\\System32"));
/// assert!(platform::is_windows_style("\\\\server\\share"));
/// assert!(platform::is_windows_style("path\\to\\file"));
/// assert!(!platform::is_windows_style("/unix/path"));
/// assert!(!platform::is_windows_style("path/to/file"));
/// ```
#[must_use]
pub fn is_windows_style(path: &str) -> bool {
    is_drive_letter_present(path)
        || is_unc_path(path)
        || (is_backslashes_present(path) && !is_forward_slashes_present(path))
}

// ============================================================================
// Unix Path Detection
// ============================================================================

/// Check if path appears to be Unix-style
///
/// Detects paths that use Unix conventions:
/// - Forward slash separators only
/// - No drive letters
/// - No UNC paths
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_unix_style("/home/user"));
/// assert!(platform::is_unix_style("path/to/file"));
/// assert!(!platform::is_unix_style("C:\\Windows"));
/// assert!(!platform::is_unix_style("path\\to\\file"));
/// ```
#[must_use]
pub fn is_unix_style(path: &str) -> bool {
    !is_drive_letter_present(path)
        && !is_unc_path(path)
        && (is_forward_slashes_present(path) || !is_backslashes_present(path))
        && !is_backslashes_present(path)
}

// ============================================================================
// Path Type Detection
// ============================================================================

/// Check if path is absolute (platform-aware)
///
/// Detects absolute paths on any platform:
/// - Unix: Starts with `/`
/// - Windows: Drive letter or UNC path
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_absolute("/etc/passwd"));
/// assert!(platform::is_absolute("C:\\Windows"));
/// assert!(platform::is_absolute("\\\\server\\share"));
/// assert!(!platform::is_absolute("relative/path"));
/// ```
#[must_use]
pub fn is_absolute(path: &str) -> bool {
    // Use std::path for platform-native check
    if Path::new(path).is_absolute() {
        return true;
    }

    // Additional checks for cross-platform detection
    path.starts_with('/')
        || path.starts_with('\\')
        || is_drive_letter_present(path)
        || is_unc_path(path)
}

/// Check if path is relative
///
/// A path is relative if it's not absolute.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_relative("relative/path"));
/// assert!(platform::is_relative("./current"));
/// assert!(platform::is_relative("../parent"));
/// assert!(!platform::is_relative("/etc/passwd"));
/// ```
#[must_use]
pub fn is_relative(path: &str) -> bool {
    !is_absolute(path)
}

// ============================================================================
// Special Path Detection
// ============================================================================

/// Check if path starts with current directory reference
///
/// Detects paths starting with `./` or `.\`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::starts_with_current_dir("./file.txt"));
/// assert!(platform::starts_with_current_dir(".\\file.txt"));
/// assert!(platform::starts_with_current_dir("."));
/// assert!(!platform::starts_with_current_dir("file.txt"));
/// ```
#[must_use]
pub fn starts_with_current_dir(path: &str) -> bool {
    path == "." || path.starts_with("./") || path.starts_with(".\\")
}

/// Check if path starts with parent directory reference
///
/// Detects paths starting with `../` or `..\`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::starts_with_parent_dir("../file.txt"));
/// assert!(platform::starts_with_parent_dir("..\\file.txt"));
/// assert!(platform::starts_with_parent_dir(".."));
/// assert!(!platform::starts_with_parent_dir("file.txt"));
/// ```
#[must_use]
pub fn starts_with_parent_dir(path: &str) -> bool {
    path == ".." || path.starts_with("../") || path.starts_with("..\\")
}

/// Check if path starts with home directory reference (tilde)
///
/// Detects paths starting with `~/` or `~\` (Unix home expansion).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::starts_with_home_dir("~/Documents"));
/// assert!(platform::starts_with_home_dir("~/.config"));
/// assert!(!platform::starts_with_home_dir("/home/user"));
/// ```
#[must_use]
pub fn starts_with_home_dir(path: &str) -> bool {
    path == "~" || path.starts_with("~/") || path.starts_with("~\\")
}

// ============================================================================
// Portable Path Detection
// ============================================================================

/// Check if path is portable (works on both Windows and Unix)
///
/// A portable path:
/// - Uses only forward slashes
/// - No drive letters
/// - No UNC paths
/// - Is relative
/// - No Windows-invalid characters
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::platform;
///
/// assert!(platform::is_portable("path/to/file.txt"));
/// assert!(platform::is_portable("relative/path"));
/// assert!(!platform::is_portable("C:\\Windows")); // Drive letter
/// assert!(!platform::is_portable("/absolute/path")); // Absolute
/// assert!(!platform::is_portable("path\\with\\backslash")); // Backslash
/// ```
#[must_use]
pub fn is_portable(path: &str) -> bool {
    !is_drive_letter_present(path)
        && !is_unc_path(path)
        && !is_backslashes_present(path)
        && !path.starts_with('/')
        && !path.starts_with('\\')
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Separator tests
    #[test]
    fn test_is_forward_slashes_present() {
        assert!(is_forward_slashes_present("path/to/file"));
        assert!(is_forward_slashes_present("/"));
        assert!(!is_forward_slashes_present("path\\to\\file"));
        assert!(!is_forward_slashes_present("file.txt"));
    }

    #[test]
    fn test_is_backslashes_present() {
        assert!(is_backslashes_present("path\\to\\file"));
        assert!(is_backslashes_present("\\"));
        assert!(!is_backslashes_present("path/to/file"));
        assert!(!is_backslashes_present("file.txt"));
    }

    #[test]
    fn test_is_mixed_separators_present() {
        assert!(is_mixed_separators_present("path/to\\file"));
        assert!(is_mixed_separators_present("C:\\Users/Documents"));
        assert!(!is_mixed_separators_present("path/to/file"));
        assert!(!is_mixed_separators_present("path\\to\\file"));
        assert!(!is_mixed_separators_present("file.txt"));
    }

    // Windows path tests
    #[test]
    fn test_is_drive_letter_present() {
        assert!(is_drive_letter_present("C:\\Windows"));
        assert!(is_drive_letter_present("D:/Users"));
        assert!(is_drive_letter_present("E:file.txt")); // Drive-relative
        assert!(is_drive_letter_present("c:\\lowercase")); // Lowercase
        assert!(!is_drive_letter_present("/unix/path"));
        assert!(!is_drive_letter_present("relative/path"));
        assert!(!is_drive_letter_present("1:\\invalid")); // Not a letter
    }

    #[test]
    fn test_is_unc_path() {
        assert!(is_unc_path("\\\\server\\share"));
        assert!(is_unc_path("\\\\server\\share\\path"));
        assert!(is_unc_path("//server/share")); // Forward slash UNC
        assert!(!is_unc_path("\\single\\backslash"));
        assert!(!is_unc_path("/unix/path"));
        assert!(!is_unc_path("relative"));
    }

    #[test]
    fn test_is_windows_style() {
        assert!(is_windows_style("C:\\Windows\\System32"));
        assert!(is_windows_style("D:\\"));
        assert!(is_windows_style("\\\\server\\share"));
        assert!(is_windows_style("path\\to\\file")); // Backslash only
        assert!(!is_windows_style("/unix/path"));
        assert!(!is_windows_style("path/to/file"));
    }

    // Unix path tests
    #[test]
    fn test_is_unix_style() {
        assert!(is_unix_style("/home/user"));
        assert!(is_unix_style("/"));
        assert!(is_unix_style("path/to/file"));
        assert!(is_unix_style("file.txt")); // No separators = Unix by default
        assert!(!is_unix_style("C:\\Windows"));
        assert!(!is_unix_style("path\\to\\file"));
        assert!(!is_unix_style("path/to\\mixed"));
    }

    // Absolute/relative tests
    #[test]
    fn test_is_absolute_unix() {
        assert!(is_absolute("/etc/passwd"));
        assert!(is_absolute("/"));
        assert!(is_absolute("/home/user/file.txt"));
    }

    #[test]
    fn test_is_absolute_windows() {
        assert!(is_absolute("C:\\Windows"));
        assert!(is_absolute("D:/Users"));
        assert!(is_absolute("\\\\server\\share"));
        assert!(is_absolute("\\path")); // Root-relative on Windows
    }

    #[test]
    fn test_is_relative() {
        assert!(is_relative("relative/path"));
        assert!(is_relative("./current"));
        assert!(is_relative("../parent"));
        assert!(is_relative("file.txt"));
        assert!(!is_relative("/etc/passwd"));
        assert!(!is_relative("C:\\Windows"));
    }

    // Special path tests
    #[test]
    fn test_starts_with_current_dir() {
        assert!(starts_with_current_dir("./file.txt"));
        assert!(starts_with_current_dir(".\\file.txt"));
        assert!(starts_with_current_dir("."));
        assert!(starts_with_current_dir("./path/to/file"));
        assert!(!starts_with_current_dir("file.txt"));
        assert!(!starts_with_current_dir("../parent"));
        assert!(!starts_with_current_dir(".hidden")); // Hidden file, not current dir
    }

    #[test]
    fn test_starts_with_parent_dir() {
        assert!(starts_with_parent_dir("../file.txt"));
        assert!(starts_with_parent_dir("..\\file.txt"));
        assert!(starts_with_parent_dir(".."));
        assert!(starts_with_parent_dir("../../grandparent"));
        assert!(!starts_with_parent_dir("file.txt"));
        assert!(!starts_with_parent_dir("./current"));
        assert!(!starts_with_parent_dir("..hidden")); // Not parent reference
    }

    #[test]
    fn test_starts_with_home_dir() {
        assert!(starts_with_home_dir("~/Documents"));
        assert!(starts_with_home_dir("~/.config"));
        assert!(starts_with_home_dir("~"));
        assert!(starts_with_home_dir("~\\Windows")); // Windows-style
        assert!(!starts_with_home_dir("/home/user"));
        assert!(!starts_with_home_dir("~user")); // User home, not current
    }

    // Portable path tests
    #[test]
    fn test_is_portable() {
        assert!(is_portable("path/to/file.txt"));
        assert!(is_portable("relative/path"));
        assert!(is_portable("file.txt"));
        assert!(is_portable("./current/dir"));
        assert!(is_portable("../parent/dir"));
        assert!(!is_portable("C:\\Windows")); // Drive letter
        assert!(!is_portable("/absolute/path")); // Absolute
        assert!(!is_portable("path\\with\\backslash")); // Backslash
        assert!(!is_portable("\\\\unc\\path")); // UNC
    }

    // Edge cases
    #[test]
    fn test_empty_string() {
        assert!(!is_forward_slashes_present(""));
        assert!(!is_backslashes_present(""));
        assert!(!is_mixed_separators_present(""));
        assert!(!is_drive_letter_present(""));
        assert!(!is_unc_path(""));
        assert!(!is_absolute(""));
        assert!(is_relative(""));
        assert!(is_portable(""));
    }

    #[test]
    fn test_single_characters() {
        assert!(is_forward_slashes_present("/"));
        assert!(is_backslashes_present("\\"));
        assert!(!is_drive_letter_present("C")); // Missing colon
        assert!(is_absolute("/"));
        assert!(is_absolute("\\"));
    }
}
