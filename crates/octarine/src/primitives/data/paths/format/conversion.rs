//! Path format conversion
//!
//! Pure conversion functions for transforming paths between formats.
//! Handles Unix, Windows, WSL, and PowerShell path formats.
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns transformed data only
//!
//! # Design Philosophy
//!
//! - **Zero-copy where possible**: Uses `Cow<str>` for efficiency
//! - **Format-preserving**: Only changes format, not security-relevant content
//! - **Lossless when possible**: Round-trip conversions preserve information
//!
//! # Supported Conversions
//!
//! - Unix ↔ Windows separator conversion
//! - Windows drive letter ↔ WSL mount path
//! - Portable format conversion
//! - Separator normalization

use std::borrow::Cow;

use super::detection::{
    PathFormat, SeparatorStyle, detect_separator_style, find_drive_letter, find_wsl_drive_letter,
    is_drive_letter_present, is_wsl_path,
};

// ============================================================================
// Separator Conversion
// ============================================================================

/// Convert path to Unix-style (forward slashes)
///
/// Converts all backslashes to forward slashes.
/// Returns `Cow::Borrowed` if no changes needed.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::to_unix("path\\to\\file"), "path/to/file");
/// assert_eq!(conversion::to_unix("path/to/file"), "path/to/file"); // unchanged
/// ```
#[must_use]
pub fn to_unix(path: &str) -> Cow<'_, str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}

/// Convert path to Windows-style (backslashes)
///
/// Converts all forward slashes to backslashes.
/// Returns `Cow::Borrowed` if no changes needed.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::to_windows("path/to/file"), "path\\to\\file");
/// assert_eq!(conversion::to_windows("path\\to\\file"), "path\\to\\file"); // unchanged
/// ```
#[must_use]
pub fn to_windows(path: &str) -> Cow<'_, str> {
    if path.contains('/') {
        Cow::Owned(path.replace('/', "\\"))
    } else {
        Cow::Borrowed(path)
    }
}

/// Convert path to native platform style
///
/// On Unix: converts to forward slashes
/// On Windows: converts to backslashes
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// // On Unix: "path\\to\\file" -> "path/to/file"
/// // On Windows: "path/to/file" -> "path\\to\\file"
/// let native = conversion::to_native("path/to/file");
/// ```
#[must_use]
pub fn to_native(path: &str) -> Cow<'_, str> {
    #[cfg(windows)]
    {
        to_windows(path)
    }
    #[cfg(not(windows))]
    {
        to_unix(path)
    }
}

// ============================================================================
// Separator Normalization
// ============================================================================

/// Normalize separators to a single style
///
/// Converts mixed separators to the dominant style.
/// If equal, defaults to forward slashes.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::normalize_separators("path/to\\file/test"), "path/to/file/test");
/// assert_eq!(conversion::normalize_separators("path\\to/file\\test"), "path\\to\\file\\test");
/// ```
#[must_use]
pub fn normalize_separators(path: &str) -> Cow<'_, str> {
    let style = detect_separator_style(path);

    match style {
        SeparatorStyle::Mixed => {
            // Count separators
            let forward_count = path.chars().filter(|&c| c == '/').count();
            let back_count = path.chars().filter(|&c| c == '\\').count();

            // Use the dominant style, default to forward
            if back_count > forward_count {
                to_windows(path)
            } else {
                to_unix(path)
            }
        }
        _ => Cow::Borrowed(path),
    }
}

// ============================================================================
// Redundant Separator Stripping
// ============================================================================

/// Strip redundant separators from path
///
/// Converts sequences of separators to single separators.
/// Preserves UNC path prefix (\\server).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::strip_redundant_separators("path//to///file"), "path/to/file");
/// assert_eq!(conversion::strip_redundant_separators("\\\\server\\\\share"), "\\\\server\\share");
/// ```
#[must_use]
pub fn strip_redundant_separators(path: &str) -> Cow<'_, str> {
    if !path.contains("//") && !path.contains("\\\\") {
        return Cow::Borrowed(path);
    }

    // Handle UNC path prefix specially
    let (prefix, rest) = if let Some(stripped) = path.strip_prefix("\\\\") {
        ("\\\\", stripped)
    } else if let Some(stripped) = path.strip_prefix("//") {
        ("//", stripped)
    } else {
        ("", path)
    };

    let mut result = String::with_capacity(path.len());
    if !prefix.is_empty() {
        result.push_str(prefix);
    }

    let mut prev_was_separator = false;
    for ch in rest.chars() {
        let is_separator = ch == '/' || ch == '\\';
        if is_separator {
            if !prev_was_separator {
                result.push(ch);
            }
            prev_was_separator = true;
        } else {
            result.push(ch);
            prev_was_separator = false;
        }
    }

    Cow::Owned(result)
}

// ============================================================================
// Trailing Separator Handling
// ============================================================================

/// Strip trailing separator from path
///
/// Removes trailing `/` or `\` from path.
/// Does not modify root paths (`/` or `\`).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::strip_trailing_separator("path/to/dir/"), "path/to/dir");
/// assert_eq!(conversion::strip_trailing_separator("/"), "/"); // Root unchanged
/// ```
#[must_use]
pub fn strip_trailing_separator(path: &str) -> &str {
    if path.len() > 1 {
        path.strip_suffix('/')
            .unwrap_or_else(|| path.strip_suffix('\\').unwrap_or(path))
    } else {
        path
    }
}

/// Ensure path has trailing separator
///
/// Adds trailing separator if not present.
/// Uses the dominant separator style in the path.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::ensure_trailing_separator("path/to/dir"), "path/to/dir/");
/// assert_eq!(conversion::ensure_trailing_separator("path\\to\\dir"), "path\\to\\dir\\");
/// ```
#[must_use]
pub fn ensure_trailing_separator(path: &str) -> Cow<'_, str> {
    if path.ends_with('/') || path.ends_with('\\') {
        Cow::Borrowed(path)
    } else if path.contains('\\') && !path.contains('/') {
        Cow::Owned(format!("{}\\", path))
    } else {
        Cow::Owned(format!("{}/", path))
    }
}

// ============================================================================
// Leading Dot-Slash Handling
// ============================================================================

/// Strip leading dot-slash from path
///
/// Removes `./` or `.\` prefix from relative paths.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::strip_leading_dot_slash("./path/to/file"), "path/to/file");
/// assert_eq!(conversion::strip_leading_dot_slash(".\\path\\to\\file"), "path\\to\\file");
/// ```
#[must_use]
pub fn strip_leading_dot_slash(path: &str) -> &str {
    path.strip_prefix("./")
        .unwrap_or_else(|| path.strip_prefix(".\\").unwrap_or(path))
}

// ============================================================================
// Windows Drive Letter Conversions
// ============================================================================

/// Convert Windows drive path to WSL format
///
/// Converts `C:\path` to `/mnt/c/path`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::windows_drive_to_wsl("C:\\Users\\file.txt"), Some("/mnt/c/Users/file.txt".to_string()));
/// assert_eq!(conversion::windows_drive_to_wsl("D:/data"), Some("/mnt/d/data".to_string()));
/// assert_eq!(conversion::windows_drive_to_wsl("/home/user"), None);
/// ```
#[must_use]
pub fn windows_drive_to_wsl(path: &str) -> Option<String> {
    let drive = find_drive_letter(path)?;
    let drive_lower = drive.to_ascii_lowercase();

    // Get the rest of the path after the drive letter and colon
    let rest = if path.len() > 2 {
        let after_colon = &path[2..];
        // Remove leading separator if present
        let trimmed = after_colon
            .strip_prefix('/')
            .or_else(|| after_colon.strip_prefix('\\'))
            .unwrap_or(after_colon);
        // Convert to forward slashes
        trimmed.replace('\\', "/")
    } else {
        String::new()
    };

    if rest.is_empty() {
        Some(format!("/mnt/{}", drive_lower))
    } else {
        Some(format!("/mnt/{}/{}", drive_lower, rest))
    }
}

/// Convert Windows drive path to Unix format (without drive letter)
///
/// Converts `C:\path` to `/path` (removing drive letter).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::windows_drive_to_unix("C:\\Users\\file.txt"), Some("/Users/file.txt".to_string()));
/// assert_eq!(conversion::windows_drive_to_unix("D:/data/file"), Some("/data/file".to_string()));
/// assert_eq!(conversion::windows_drive_to_unix("/home/user"), None);
/// ```
#[must_use]
pub fn windows_drive_to_unix(path: &str) -> Option<String> {
    if !is_drive_letter_present(path) {
        return None;
    }

    // Get the rest of the path after the drive letter and colon
    let rest = if path.len() > 2 {
        let after_colon = &path[2..];
        // Convert to forward slashes
        let converted = after_colon.replace('\\', "/");
        // Ensure leading slash
        if converted.starts_with('/') {
            converted
        } else {
            format!("/{}", converted)
        }
    } else {
        "/".to_string()
    };

    Some(rest)
}

/// Convert WSL path to Windows drive format
///
/// Converts `/mnt/c/path` to `C:\path`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::wsl_to_windows_drive("/mnt/c/Users/file.txt"), Some("C:\\Users\\file.txt".to_string()));
/// assert_eq!(conversion::wsl_to_windows_drive("/mnt/d/data"), Some("D:\\data".to_string()));
/// assert_eq!(conversion::wsl_to_windows_drive("/home/user"), None);
/// ```
#[must_use]
pub fn wsl_to_windows_drive(path: &str) -> Option<String> {
    let drive = find_wsl_drive_letter(path)?;
    let drive_upper = drive.to_ascii_uppercase();

    // Get the rest of the path after /mnt/X/
    let rest = if path.len() > 6 {
        let after_drive = &path[6..];
        // Remove leading slash if present
        let trimmed = after_drive.strip_prefix('/').unwrap_or(after_drive);
        // Convert to backslashes
        trimmed.replace('/', "\\")
    } else {
        String::new()
    };

    if rest.is_empty() {
        Some(format!("{}:\\", drive_upper))
    } else {
        Some(format!("{}:\\{}", drive_upper, rest))
    }
}

/// Convert Unix path to Windows format
///
/// Converts `/path/to/file` to `\path\to\file`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::unix_to_windows_path("/home/user/file"), "\\home\\user\\file");
/// ```
#[must_use]
pub fn unix_to_windows_path(path: &str) -> Cow<'_, str> {
    to_windows(path)
}

// ============================================================================
// Portable Format Conversion
// ============================================================================

/// Convert path to portable format
///
/// Removes platform-specific elements:
/// - Converts to forward slashes
/// - Removes drive letters
/// - Removes redundant separators
/// - Removes trailing separators
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion;
///
/// assert_eq!(conversion::to_portable("C:\\Users\\file.txt"), "Users/file.txt");
/// assert_eq!(conversion::to_portable("/mnt/c/Users/file"), "Users/file");
/// assert_eq!(conversion::to_portable("path//to\\file/"), "path/to/file");
/// ```
#[must_use]
pub fn to_portable(path: &str) -> Cow<'_, str> {
    // Handle empty paths
    if path.is_empty() {
        return Cow::Borrowed(path);
    }

    // Convert to Unix style first
    let result = to_unix(path);

    // Remove drive letter if present
    let result = if is_drive_letter_present(&result) {
        let rest = &result[2..];
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        Cow::Owned(rest.to_string())
    } else if is_wsl_path(&result) {
        // Remove /mnt/X/ prefix
        if result.len() > 6 {
            let rest = &result[6..];
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            Cow::Owned(rest.to_string())
        } else {
            Cow::Owned(String::new())
        }
    } else {
        result
    };

    // Remove redundant separators
    let result = match strip_redundant_separators(&result) {
        Cow::Borrowed(_) => result,
        Cow::Owned(s) => Cow::Owned(s),
    };

    // Remove trailing separator
    let trimmed = strip_trailing_separator(&result);
    if trimmed.len() != result.len() {
        Cow::Owned(trimmed.to_string())
    } else {
        result
    }
}

// ============================================================================
// Full Format Conversion
// ============================================================================

/// Convert path to target format
///
/// Converts a path to the specified target format.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::conversion::{convert_to_format, PathFormat};
///
/// let result = convert_to_format("C:\\Users\\file.txt", PathFormat::Wsl);
/// assert_eq!(result, "/mnt/c/Users/file.txt");
/// ```
#[must_use]
pub fn convert_to_format(path: &str, target: PathFormat) -> Cow<'_, str> {
    match target {
        PathFormat::Unix => {
            if is_drive_letter_present(path) {
                windows_drive_to_unix(path)
                    .map(Cow::Owned)
                    .unwrap_or_else(|| to_unix(path))
            } else {
                to_unix(path)
            }
        }
        PathFormat::Windows => {
            if is_wsl_path(path) {
                wsl_to_windows_drive(path)
                    .map(Cow::Owned)
                    .unwrap_or_else(|| to_windows(path))
            } else {
                to_windows(path)
            }
        }
        PathFormat::PowerShell => {
            // PowerShell accepts forward slashes
            if is_wsl_path(path) {
                if let Some(drive) = find_wsl_drive_letter(path) {
                    let rest = if path.len() > 6 {
                        let after_drive = &path[6..];
                        after_drive.strip_prefix('/').unwrap_or(after_drive)
                    } else {
                        ""
                    };
                    if rest.is_empty() {
                        Cow::Owned(format!("{}:/", drive.to_ascii_uppercase()))
                    } else {
                        Cow::Owned(format!("{}:/{}", drive.to_ascii_uppercase(), rest))
                    }
                } else {
                    to_unix(path)
                }
            } else {
                to_unix(path)
            }
        }
        PathFormat::Wsl => {
            if is_drive_letter_present(path) {
                windows_drive_to_wsl(path)
                    .map(Cow::Owned)
                    .unwrap_or_else(|| to_unix(path))
            } else {
                to_unix(path)
            }
        }
        PathFormat::Portable => to_portable(path),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Basic separator conversion tests
    #[test]
    fn test_to_unix() {
        assert_eq!(to_unix("path\\to\\file").as_ref(), "path/to/file");
        assert_eq!(
            to_unix("C:\\Windows\\System32").as_ref(),
            "C:/Windows/System32"
        );
        // No change - should be borrowed
        let result = to_unix("path/to/file");
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), "path/to/file");
    }

    #[test]
    fn test_to_windows() {
        assert_eq!(to_windows("path/to/file").as_ref(), "path\\to\\file");
        assert_eq!(to_windows("/home/user").as_ref(), "\\home\\user");
        // No change - should be borrowed
        let result = to_windows("path\\to\\file");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_normalize_separators() {
        // More forward slashes
        assert_eq!(
            normalize_separators("path/to\\file/test").as_ref(),
            "path/to/file/test"
        );
        // More backslashes
        assert_eq!(
            normalize_separators("path\\to/file\\test").as_ref(),
            "path\\to\\file\\test"
        );
        // Equal - defaults to forward
        assert_eq!(
            normalize_separators("path/to\\file").as_ref(),
            "path/to/file"
        );
        // No change
        let result = normalize_separators("path/to/file");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // Redundant separator tests
    #[test]
    fn test_strip_redundant_separators() {
        assert_eq!(
            strip_redundant_separators("path//to///file").as_ref(),
            "path/to/file"
        );
        assert_eq!(
            strip_redundant_separators("path\\\\to\\\\\\file").as_ref(),
            "path\\to\\file"
        );
        // UNC preservation
        assert_eq!(
            strip_redundant_separators("\\\\server\\\\share").as_ref(),
            "\\\\server\\share"
        );
        assert_eq!(
            strip_redundant_separators("//server//share").as_ref(),
            "//server/share"
        );
        // No change
        let result = strip_redundant_separators("path/to/file");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // Trailing separator tests
    #[test]
    fn test_strip_trailing_separator() {
        assert_eq!(strip_trailing_separator("path/to/dir/"), "path/to/dir");
        assert_eq!(strip_trailing_separator("path\\to\\dir\\"), "path\\to\\dir");
        assert_eq!(strip_trailing_separator("/"), "/"); // Root unchanged
        assert_eq!(strip_trailing_separator("\\"), "\\");
        assert_eq!(strip_trailing_separator("path"), "path");
    }

    #[test]
    fn test_ensure_trailing_separator() {
        assert_eq!(
            ensure_trailing_separator("path/to/dir").as_ref(),
            "path/to/dir/"
        );
        assert_eq!(
            ensure_trailing_separator("path\\to\\dir").as_ref(),
            "path\\to\\dir\\"
        );
        // Already has trailing
        let result = ensure_trailing_separator("path/to/dir/");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // Leading dot-slash tests
    #[test]
    fn test_strip_leading_dot_slash() {
        assert_eq!(strip_leading_dot_slash("./path/to/file"), "path/to/file");
        assert_eq!(
            strip_leading_dot_slash(".\\path\\to\\file"),
            "path\\to\\file"
        );
        assert_eq!(strip_leading_dot_slash("path/to/file"), "path/to/file");
        assert_eq!(strip_leading_dot_slash("../parent"), "../parent");
    }

    // Drive letter conversion tests
    #[test]
    fn test_windows_drive_to_wsl() {
        assert_eq!(
            windows_drive_to_wsl("C:\\Users\\file.txt"),
            Some("/mnt/c/Users/file.txt".to_string())
        );
        assert_eq!(
            windows_drive_to_wsl("D:/data/file"),
            Some("/mnt/d/data/file".to_string())
        );
        assert_eq!(windows_drive_to_wsl("E:"), Some("/mnt/e".to_string()));
        assert_eq!(windows_drive_to_wsl("/home/user"), None);
    }

    #[test]
    fn test_windows_drive_to_unix() {
        assert_eq!(
            windows_drive_to_unix("C:\\Users\\file.txt"),
            Some("/Users/file.txt".to_string())
        );
        assert_eq!(
            windows_drive_to_unix("D:/data/file"),
            Some("/data/file".to_string())
        );
        assert_eq!(windows_drive_to_unix("C:"), Some("/".to_string()));
        assert_eq!(windows_drive_to_unix("/home/user"), None);
    }

    #[test]
    fn test_wsl_to_windows_drive() {
        assert_eq!(
            wsl_to_windows_drive("/mnt/c/Users/file.txt"),
            Some("C:\\Users\\file.txt".to_string())
        );
        assert_eq!(
            wsl_to_windows_drive("/mnt/d/data"),
            Some("D:\\data".to_string())
        );
        assert_eq!(wsl_to_windows_drive("/mnt/e"), Some("E:\\".to_string()));
        assert_eq!(wsl_to_windows_drive("/home/user"), None);
    }

    // Portable format tests
    #[test]
    fn test_to_portable() {
        assert_eq!(
            to_portable("C:\\Users\\file.txt").as_ref(),
            "Users/file.txt"
        );
        assert_eq!(to_portable("/mnt/c/Users/file").as_ref(), "Users/file");
        assert_eq!(to_portable("path//to\\file/").as_ref(), "path/to/file");
        assert_eq!(to_portable("/absolute/path").as_ref(), "/absolute/path");
        assert_eq!(to_portable("relative/path").as_ref(), "relative/path");
        assert_eq!(to_portable("").as_ref(), "");
    }

    // Full format conversion tests
    #[test]
    fn test_convert_to_format_unix() {
        assert_eq!(
            convert_to_format("C:\\Users\\file", PathFormat::Unix).as_ref(),
            "/Users/file"
        );
        assert_eq!(
            convert_to_format("path\\to\\file", PathFormat::Unix).as_ref(),
            "path/to/file"
        );
    }

    #[test]
    fn test_convert_to_format_windows() {
        assert_eq!(
            convert_to_format("/mnt/c/Users/file", PathFormat::Windows).as_ref(),
            "C:\\Users\\file"
        );
        assert_eq!(
            convert_to_format("path/to/file", PathFormat::Windows).as_ref(),
            "path\\to\\file"
        );
    }

    #[test]
    fn test_convert_to_format_powershell() {
        assert_eq!(
            convert_to_format("/mnt/c/Users/file", PathFormat::PowerShell).as_ref(),
            "C:/Users/file"
        );
        assert_eq!(
            convert_to_format("path\\to\\file", PathFormat::PowerShell).as_ref(),
            "path/to/file"
        );
    }

    #[test]
    fn test_convert_to_format_wsl() {
        assert_eq!(
            convert_to_format("C:\\Users\\file", PathFormat::Wsl).as_ref(),
            "/mnt/c/Users/file"
        );
        assert_eq!(
            convert_to_format("D:/data", PathFormat::Wsl).as_ref(),
            "/mnt/d/data"
        );
    }

    #[test]
    fn test_convert_to_format_portable() {
        assert_eq!(
            convert_to_format("C:\\Users\\file", PathFormat::Portable).as_ref(),
            "Users/file"
        );
        assert_eq!(
            convert_to_format("/mnt/c/data", PathFormat::Portable).as_ref(),
            "data"
        );
    }

    // Round-trip tests
    #[test]
    fn test_round_trip_windows_wsl() {
        let original = "C:\\Users\\file.txt";
        let wsl = windows_drive_to_wsl(original).expect("valid Windows path");
        let back = wsl_to_windows_drive(&wsl).expect("valid WSL path");
        assert_eq!(back, original);
    }

    #[test]
    fn test_round_trip_wsl_windows() {
        let original = "/mnt/d/projects/app";
        let windows = wsl_to_windows_drive(original).expect("valid WSL path");
        let back = windows_drive_to_wsl(&windows).expect("valid Windows path");
        assert_eq!(back, original);
    }

    // Edge cases
    #[test]
    fn test_empty_paths() {
        assert_eq!(to_unix("").as_ref(), "");
        assert_eq!(to_windows("").as_ref(), "");
        assert_eq!(to_portable("").as_ref(), "");
    }

    #[test]
    fn test_single_character_paths() {
        assert_eq!(to_unix("/").as_ref(), "/");
        assert_eq!(to_windows("/").as_ref(), "\\");
        assert_eq!(strip_trailing_separator("/"), "/");
    }

    // Security preservation tests
    #[test]
    fn test_preserves_traversal() {
        // Conversion must NOT remove traversal patterns
        let result = to_unix("path\\..\\..\\etc");
        assert!(result.contains(".."));
        assert_eq!(result.as_ref(), "path/../../etc");
    }

    #[test]
    fn test_preserves_injection() {
        // Conversion must NOT remove injection patterns
        let result = to_unix("path\\$(whoami)\\file");
        assert!(result.contains("$("));
        assert_eq!(result.as_ref(), "path/$(whoami)/file");
    }
}
