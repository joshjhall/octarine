//! Path format detection
//!
//! Pure detection functions for identifying path format characteristics.
//! Answers questions like "What separator style?" and "What format issues?"
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Design Philosophy
//!
//! Detection functions **identify** format characteristics but do NOT
//! transform or validate paths. Use conversion functions to transform.
//!
//! # Features
//!
//! - **Separator style detection**: Unix vs Windows vs Mixed
//! - **Format issue detection**: Redundant separators, leading dot-slash
//! - **Path format detection**: Unix, Windows, WSL, PowerShell, Portable

use std::borrow::Cow;

/// Maximum reasonable path length (4096 bytes)
///
/// This is a common limit across many filesystems:
/// - Linux: 4096 (PATH_MAX)
/// - Windows: 260 (MAX_PATH) but can be 32767 with long path support
/// - macOS: 1024 (MAXPATHLEN)
///
/// We use 4096 as a conservative limit that works across platforms.
pub const MAX_PATH_LENGTH: usize = 4096;

/// Path format enumeration
///
/// Represents the detected format/style of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PathFormat {
    /// Unix-style paths with forward slashes
    Unix,
    /// Windows-style paths with backslashes and optional drive letter
    Windows,
    /// PowerShell-style (Windows with forward slashes)
    PowerShell,
    /// WSL mount paths (/mnt/c/...)
    Wsl,
    /// Portable relative paths (no platform-specific elements)
    #[default]
    Portable,
}

impl PathFormat {
    /// Check if this format is Unix-like
    #[must_use]
    pub const fn is_unix_like(&self) -> bool {
        matches!(self, Self::Unix | Self::Wsl | Self::Portable)
    }

    /// Check if this format is Windows-like
    #[must_use]
    pub const fn is_windows_like(&self) -> bool {
        matches!(self, Self::Windows | Self::PowerShell)
    }

    /// Get the primary separator for this format
    #[must_use]
    pub const fn separator(&self) -> char {
        match self {
            Self::Windows => '\\',
            _ => '/',
        }
    }
}

impl std::fmt::Display for PathFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix => write!(f, "Unix"),
            Self::Windows => write!(f, "Windows"),
            Self::PowerShell => write!(f, "PowerShell"),
            Self::Wsl => write!(f, "WSL"),
            Self::Portable => write!(f, "Portable"),
        }
    }
}

/// Separator style enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SeparatorStyle {
    /// Forward slashes only (/)
    Forward,
    /// Backslashes only (\)
    Back,
    /// Both forward and back slashes
    Mixed,
    /// No separators present
    #[default]
    None,
}

impl SeparatorStyle {
    /// Check if this style has any separators
    #[must_use]
    pub const fn has_separators(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Check if this is a consistent style (not mixed)
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        !matches!(self, Self::Mixed)
    }
}

// ============================================================================
// Basic Detection Functions (re-exports from common with new ones)
// ============================================================================

/// Check if path has mixed separators (both / and \)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_mixed_separators_present("path/to\\file"));
/// assert!(!detection::is_mixed_separators_present("path/to/file"));
/// ```
#[inline]
#[must_use]
pub fn is_mixed_separators_present(path: &str) -> bool {
    path.contains('/') && path.contains('\\')
}

/// Check if path has redundant separators (//)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_redundant_separators_present("path//to/file"));
/// assert!(!detection::is_redundant_separators_present("path/to/file"));
/// ```
#[inline]
#[must_use]
pub fn is_redundant_separators_present(path: &str) -> bool {
    path.contains("//") || path.contains("\\\\")
}

/// Check if path has trailing separator
///
/// Note: Root paths (`/` or `\`) are not considered to have trailing separators.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_trailing_separator_present("path/to/dir/"));
/// assert!(!detection::is_trailing_separator_present("/"));
/// ```
#[inline]
#[must_use]
pub fn is_trailing_separator_present(path: &str) -> bool {
    path.len() > 1 && (path.ends_with('/') || path.ends_with('\\'))
}

/// Check if path has leading dot-slash (./)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_leading_dot_slash_present("./path/to/file"));
/// assert!(detection::is_leading_dot_slash_present(".\\path\\to\\file"));
/// assert!(!detection::is_leading_dot_slash_present("path/to/file"));
/// ```
#[inline]
#[must_use]
pub fn is_leading_dot_slash_present(path: &str) -> bool {
    path.starts_with("./") || path.starts_with(".\\")
}

/// Check if path has Windows separators (backslashes)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_windows_separators_present("path\\to\\file"));
/// assert!(!detection::is_windows_separators_present("path/to/file"));
/// ```
#[inline]
#[must_use]
pub fn is_windows_separators_present(path: &str) -> bool {
    path.contains('\\')
}

/// Check if path has POSIX separators (forward slashes)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_posix_separators_present("path/to/file"));
/// assert!(!detection::is_posix_separators_present("path\\to\\file"));
/// ```
#[inline]
#[must_use]
pub fn is_posix_separators_present(path: &str) -> bool {
    path.contains('/')
}

/// Check if path exceeds reasonable length limit
///
/// Returns true if the path exceeds MAX_PATH_LENGTH (4096 bytes).
/// This can indicate malicious input, filesystem limitations, or resource exhaustion attacks.
#[inline]
#[must_use]
pub fn exceeds_length_limit(path: &str) -> bool {
    path.len() > MAX_PATH_LENGTH
}

// ============================================================================
// Format Detection Functions
// ============================================================================

/// Detect the separator style used in a path
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection::{detect_separator_style, SeparatorStyle};
///
/// assert_eq!(detect_separator_style("path/to/file"), SeparatorStyle::Forward);
/// assert_eq!(detect_separator_style("path\\to\\file"), SeparatorStyle::Back);
/// assert_eq!(detect_separator_style("path/to\\file"), SeparatorStyle::Mixed);
/// assert_eq!(detect_separator_style("file.txt"), SeparatorStyle::None);
/// ```
#[must_use]
pub fn detect_separator_style(path: &str) -> SeparatorStyle {
    let has_forward = path.contains('/');
    let has_back = path.contains('\\');

    match (has_forward, has_back) {
        (true, true) => SeparatorStyle::Mixed,
        (true, false) => SeparatorStyle::Forward,
        (false, true) => SeparatorStyle::Back,
        (false, false) => SeparatorStyle::None,
    }
}

/// Check if path starts with a Windows drive letter (e.g., C:)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_drive_letter_present("C:\\Windows"));
/// assert!(detection::is_drive_letter_present("D:/data"));
/// assert!(!detection::is_drive_letter_present("/home/user"));
/// ```
#[must_use]
pub fn is_drive_letter_present(path: &str) -> bool {
    let bytes = path.as_bytes();
    if let (Some(&first), Some(&second)) = (bytes.first(), bytes.get(1)) {
        first.is_ascii_alphabetic() && second == b':'
    } else {
        false
    }
}

/// Check if path is a UNC path (\\server\share)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_unc_path("\\\\server\\share"));
/// assert!(!detection::is_unc_path("C:\\Windows"));
/// ```
#[must_use]
pub fn is_unc_path(path: &str) -> bool {
    path.starts_with("\\\\") || path.starts_with("//")
}

/// Check if path is a WSL mount path (/mnt/c/...)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_wsl_path("/mnt/c/Users"));
/// assert!(detection::is_wsl_path("/mnt/d/data"));
/// assert!(!detection::is_wsl_path("/home/user"));
/// ```
#[must_use]
pub fn is_wsl_path(path: &str) -> bool {
    if !path.starts_with("/mnt/") || path.len() < 6 {
        return false;
    }

    // Get the character after /mnt/
    let bytes = path.as_bytes();
    let drive_char = bytes.get(5).copied();

    // Must be a single letter
    if let Some(ch) = drive_char
        && ch.is_ascii_alphabetic()
    {
        // Must be followed by / or end of string
        let next = bytes.get(6).copied();
        return next.is_none() || next == Some(b'/');
    }

    false
}

/// Detect the format of a path
///
/// Analyzes path characteristics to determine its format type.
///
/// # Detection Rules
///
/// 1. WSL paths: Start with `/mnt/` followed by drive letter
/// 2. Windows paths: Have drive letter or backslashes
/// 3. PowerShell paths: Have drive letter with forward slashes
/// 4. Unix paths: Start with `/` (absolute)
/// 5. Portable: Relative paths without platform-specific elements
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection::{detect_format, PathFormat};
///
/// assert_eq!(detect_format("/mnt/c/Users"), PathFormat::Wsl);
/// assert_eq!(detect_format("C:\\Windows"), PathFormat::Windows);
/// assert_eq!(detect_format("C:/Windows"), PathFormat::PowerShell);
/// assert_eq!(detect_format("/etc/passwd"), PathFormat::Unix);
/// assert_eq!(detect_format("relative/path"), PathFormat::Portable);
/// ```
#[must_use]
pub fn detect_format(path: &str) -> PathFormat {
    // Empty paths are portable
    if path.is_empty() {
        return PathFormat::Portable;
    }

    // Check for WSL paths first
    if is_wsl_path(path) {
        return PathFormat::Wsl;
    }

    // Check for Windows paths
    if is_drive_letter_present(path) {
        // Drive letter with forward slashes = PowerShell
        if !path.contains('\\') {
            return PathFormat::PowerShell;
        }
        return PathFormat::Windows;
    }

    // Check for backslash-only paths (Windows without drive)
    if path.contains('\\') && !path.contains('/') {
        return PathFormat::Windows;
    }

    // Check for Unix absolute paths
    if path.starts_with('/') {
        return PathFormat::Unix;
    }

    // Default to portable for relative paths
    PathFormat::Portable
}

/// Check if path has any format issues requiring normalization
///
/// Detects:
/// - Mixed separators
/// - Redundant separators
/// - Trailing separators (except root)
/// - Leading dot-slash
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_format_issues_present("path//to\\file/"));
/// assert!(!detection::is_format_issues_present("path/to/file"));
/// ```
#[must_use]
pub fn is_format_issues_present(path: &str) -> bool {
    is_mixed_separators_present(path)
        || is_redundant_separators_present(path)
        || is_trailing_separator_present(path)
        || is_leading_dot_slash_present(path)
}

/// Check if path is in a consistent format
///
/// Returns true if the path:
/// - Uses only one separator style (or none)
/// - Has no redundant separators
/// - Has no unnecessary leading dot-slash
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert!(detection::is_consistent_format("path/to/file"));
/// assert!(detection::is_consistent_format("path\\to\\file"));
/// assert!(!detection::is_consistent_format("path/to\\file"));
/// ```
#[must_use]
pub fn is_consistent_format(path: &str) -> bool {
    !is_format_issues_present(path)
}

/// Find the drive letter from a Windows path
///
/// Returns the uppercase drive letter if present, or None.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert_eq!(detection::find_drive_letter("C:\\Windows"), Some('C'));
/// assert_eq!(detection::find_drive_letter("d:/data"), Some('D'));
/// assert_eq!(detection::find_drive_letter("/home/user"), None);
/// ```
#[must_use]
pub fn find_drive_letter(path: &str) -> Option<char> {
    if is_drive_letter_present(path) {
        path.chars().next().map(|c| c.to_ascii_uppercase())
    } else {
        None
    }
}

/// Find the drive letter from a WSL path
///
/// Returns the uppercase drive letter from a /mnt/X/ path, or None.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::detection;
///
/// assert_eq!(detection::find_wsl_drive_letter("/mnt/c/Users"), Some('C'));
/// assert_eq!(detection::find_wsl_drive_letter("/mnt/D/data"), Some('D'));
/// assert_eq!(detection::find_wsl_drive_letter("/home/user"), None);
/// ```
#[must_use]
pub fn find_wsl_drive_letter(path: &str) -> Option<char> {
    if is_wsl_path(path) {
        path.chars().nth(5).map(|c| c.to_ascii_uppercase())
    } else {
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // PathFormat tests
    #[test]
    fn test_path_format_is_unix_like() {
        assert!(PathFormat::Unix.is_unix_like());
        assert!(PathFormat::Wsl.is_unix_like());
        assert!(PathFormat::Portable.is_unix_like());
        assert!(!PathFormat::Windows.is_unix_like());
        assert!(!PathFormat::PowerShell.is_unix_like());
    }

    #[test]
    fn test_path_format_is_windows_like() {
        assert!(PathFormat::Windows.is_windows_like());
        assert!(PathFormat::PowerShell.is_windows_like());
        assert!(!PathFormat::Unix.is_windows_like());
        assert!(!PathFormat::Wsl.is_windows_like());
        assert!(!PathFormat::Portable.is_windows_like());
    }

    #[test]
    fn test_path_format_separator() {
        assert_eq!(PathFormat::Unix.separator(), '/');
        assert_eq!(PathFormat::Windows.separator(), '\\');
        assert_eq!(PathFormat::PowerShell.separator(), '/');
        assert_eq!(PathFormat::Wsl.separator(), '/');
        assert_eq!(PathFormat::Portable.separator(), '/');
    }

    // SeparatorStyle tests
    #[test]
    fn test_separator_style() {
        assert!(SeparatorStyle::Forward.has_separators());
        assert!(SeparatorStyle::Back.has_separators());
        assert!(SeparatorStyle::Mixed.has_separators());
        assert!(!SeparatorStyle::None.has_separators());

        assert!(SeparatorStyle::Forward.is_consistent());
        assert!(SeparatorStyle::Back.is_consistent());
        assert!(!SeparatorStyle::Mixed.is_consistent());
        assert!(SeparatorStyle::None.is_consistent());
    }

    // Basic detection tests
    #[test]
    fn test_is_mixed_separators_present() {
        assert!(is_mixed_separators_present("path/to\\file"));
        assert!(is_mixed_separators_present("C:\\Users/file"));
        assert!(!is_mixed_separators_present("path/to/file"));
        assert!(!is_mixed_separators_present("path\\to\\file"));
        assert!(!is_mixed_separators_present(""));
    }

    #[test]
    fn test_is_redundant_separators_present() {
        assert!(is_redundant_separators_present("path//to/file"));
        assert!(is_redundant_separators_present("path\\\\to\\file"));
        assert!(!is_redundant_separators_present("path/to/file"));
        assert!(!is_redundant_separators_present(""));
    }

    #[test]
    fn test_is_trailing_separator_present() {
        assert!(is_trailing_separator_present("path/to/dir/"));
        assert!(is_trailing_separator_present("path\\to\\dir\\"));
        assert!(!is_trailing_separator_present("path/to/file"));
        assert!(!is_trailing_separator_present("/")); // Root
        assert!(!is_trailing_separator_present("\\"));
        assert!(!is_trailing_separator_present(""));
    }

    #[test]
    fn test_is_leading_dot_slash_present() {
        assert!(is_leading_dot_slash_present("./path/to/file"));
        assert!(is_leading_dot_slash_present(".\\path\\to\\file"));
        assert!(!is_leading_dot_slash_present("path/to/file"));
        assert!(!is_leading_dot_slash_present("../path"));
        assert!(!is_leading_dot_slash_present(""));
    }

    #[test]
    fn test_is_windows_separators_present() {
        assert!(is_windows_separators_present("path\\to\\file"));
        assert!(is_windows_separators_present("C:\\Windows"));
        assert!(!is_windows_separators_present("path/to/file"));
        assert!(!is_windows_separators_present(""));
    }

    #[test]
    fn test_is_posix_separators_present() {
        assert!(is_posix_separators_present("path/to/file"));
        assert!(is_posix_separators_present("/etc/passwd"));
        assert!(!is_posix_separators_present("path\\to\\file"));
        assert!(!is_posix_separators_present(""));
    }

    #[test]
    fn test_exceeds_length_limit() {
        assert!(!exceeds_length_limit("short/path"));
        assert!(!exceeds_length_limit(&"a".repeat(4096)));
        assert!(exceeds_length_limit(&"a".repeat(4097)));
    }

    // Format detection tests
    #[test]
    fn test_detect_separator_style() {
        assert_eq!(
            detect_separator_style("path/to/file"),
            SeparatorStyle::Forward
        );
        assert_eq!(
            detect_separator_style("path\\to\\file"),
            SeparatorStyle::Back
        );
        assert_eq!(
            detect_separator_style("path/to\\file"),
            SeparatorStyle::Mixed
        );
        assert_eq!(detect_separator_style("file.txt"), SeparatorStyle::None);
        assert_eq!(detect_separator_style(""), SeparatorStyle::None);
    }

    #[test]
    fn test_is_drive_letter_present() {
        assert!(is_drive_letter_present("C:\\Windows"));
        assert!(is_drive_letter_present("D:/data"));
        assert!(is_drive_letter_present("c:"));
        assert!(is_drive_letter_present("Z:\\"));
        assert!(!is_drive_letter_present("/home/user"));
        assert!(!is_drive_letter_present("relative/path"));
        assert!(!is_drive_letter_present(""));
        assert!(!is_drive_letter_present("C"));
    }

    #[test]
    fn test_is_unc_path() {
        assert!(is_unc_path("\\\\server\\share"));
        assert!(is_unc_path("//server/share"));
        assert!(!is_unc_path("C:\\Windows"));
        assert!(!is_unc_path("/home/user"));
        assert!(!is_unc_path(""));
    }

    #[test]
    fn test_is_wsl_path() {
        assert!(is_wsl_path("/mnt/c/Users"));
        assert!(is_wsl_path("/mnt/d/data"));
        assert!(is_wsl_path("/mnt/e/"));
        assert!(is_wsl_path("/mnt/c"));
        assert!(!is_wsl_path("/mnt/invalid")); // Two letters
        assert!(!is_wsl_path("/mnt/"));
        assert!(!is_wsl_path("/home/user"));
        assert!(!is_wsl_path(""));
    }

    #[test]
    fn test_detect_format_wsl() {
        assert_eq!(detect_format("/mnt/c/Users"), PathFormat::Wsl);
        assert_eq!(detect_format("/mnt/d/projects"), PathFormat::Wsl);
        assert_eq!(detect_format("/mnt/e/backup"), PathFormat::Wsl);
    }

    #[test]
    fn test_detect_format_windows() {
        assert_eq!(detect_format("C:\\Windows\\System32"), PathFormat::Windows);
        assert_eq!(detect_format("D:\\data\\file.txt"), PathFormat::Windows);
        assert_eq!(detect_format("path\\to\\file"), PathFormat::Windows);
    }

    #[test]
    fn test_detect_format_powershell() {
        assert_eq!(detect_format("C:/Windows/System32"), PathFormat::PowerShell);
        assert_eq!(detect_format("D:/data/file.txt"), PathFormat::PowerShell);
    }

    #[test]
    fn test_detect_format_unix() {
        assert_eq!(detect_format("/etc/passwd"), PathFormat::Unix);
        assert_eq!(detect_format("/home/user/file"), PathFormat::Unix);
        assert_eq!(detect_format("/var/log"), PathFormat::Unix);
    }

    #[test]
    fn test_detect_format_portable() {
        assert_eq!(detect_format("relative/path"), PathFormat::Portable);
        assert_eq!(detect_format("file.txt"), PathFormat::Portable);
        assert_eq!(detect_format("./current"), PathFormat::Portable);
        assert_eq!(detect_format(""), PathFormat::Portable);
    }

    #[test]
    fn test_is_format_issues_present() {
        assert!(is_format_issues_present("path//to/file"));
        assert!(is_format_issues_present("path/to\\file"));
        assert!(is_format_issues_present("path/to/dir/"));
        assert!(is_format_issues_present("./path/to/file"));
        assert!(!is_format_issues_present("path/to/file"));
        assert!(!is_format_issues_present("/etc/passwd"));
    }

    #[test]
    fn test_is_consistent_format() {
        assert!(is_consistent_format("path/to/file"));
        assert!(is_consistent_format("path\\to\\file"));
        assert!(is_consistent_format("/etc/passwd"));
        assert!(!is_consistent_format("path/to\\file"));
        assert!(!is_consistent_format("path//file"));
    }

    #[test]
    fn test_find_drive_letter() {
        assert_eq!(find_drive_letter("C:\\Windows"), Some('C'));
        assert_eq!(find_drive_letter("d:/data"), Some('D'));
        assert_eq!(find_drive_letter("e:"), Some('E'));
        assert_eq!(find_drive_letter("/home/user"), None);
        assert_eq!(find_drive_letter(""), None);
    }

    #[test]
    fn test_find_wsl_drive_letter() {
        assert_eq!(find_wsl_drive_letter("/mnt/c/Users"), Some('C'));
        assert_eq!(find_wsl_drive_letter("/mnt/D/data"), Some('D'));
        assert_eq!(find_wsl_drive_letter("/home/user"), None);
        assert_eq!(find_wsl_drive_letter(""), None);
    }
}
