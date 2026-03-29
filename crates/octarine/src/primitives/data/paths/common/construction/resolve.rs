// Allow clippy lints that are overly strict for this utility module
#![allow(clippy::unnecessary_map_or)]

//! Path resolution utilities
//!
//! Functions for resolving relative paths and making paths absolute.
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Relative to absolute resolution
//! - `.` and `..` resolution (without filesystem access)
//! - Path simplification
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **No Filesystem Access**: Works on strings only, no I/O
//! 3. **Preserves Semantics**: Resolves `.` and `..` logically
//!
//! ## Important: Logical vs Physical Resolution
//!
//! These functions perform **logical** path resolution (string manipulation).
//! They do NOT access the filesystem, so:
//! - Symlinks are not followed
//! - Path existence is not verified
//! - Current directory is not queried
//!
//! For physical resolution, use `std::fs::canonicalize()`.

use super::components::{filename, find_parent, split};
use std::path::{Component, Path};

// ============================================================================
// Logical Path Resolution
// ============================================================================

/// Clean a path by resolving `.` and `..` components
///
/// Performs logical resolution without filesystem access.
/// Does NOT verify path exists or follow symlinks.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::resolve;
///
/// assert_eq!(resolve::clean_path("path/to/../other/./file"), "path/other/file");
/// assert_eq!(resolve::clean_path("./file"), "file");
/// assert_eq!(resolve::clean_path("a/b/c/../../d"), "a/d");
/// ```
///
/// # Edge Cases
///
/// - Leading `..` is preserved (can't resolve beyond root)
/// - Absolute paths are preserved
/// - Empty path returns empty string
#[must_use]
pub fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let mut components: Vec<&str> = Vec::new();
    let is_absolute = path.starts_with('/') || path.starts_with('\\');
    let uses_backslash = path.contains('\\') && !path.contains('/');

    for part in split(path) {
        match part {
            "" | "." => {
                // Skip empty and current directory
                continue;
            }
            ".." => {
                // Try to go up one level
                if components.is_empty() || components.last() == Some(&"..") {
                    // Can't go up further, or already have leading ..
                    if !is_absolute {
                        components.push("..");
                    }
                    // For absolute paths, just skip (can't go above root)
                } else {
                    components.pop();
                }
            }
            _ => {
                components.push(part);
            }
        }
    }

    // Reconstruct path
    let separator = if uses_backslash { "\\" } else { "/" };
    let mut result = components.join(separator);

    if is_absolute {
        result = format!("{}{}", separator, result);
    }

    if result.is_empty() && !path.is_empty() {
        // Path simplified to current directory
        return ".".to_string();
    }

    result
}

/// Convert a relative path to absolute by resolving against a base path
///
/// If `path` is absolute, returns it unchanged.
/// Otherwise, joins `base` and `path` and cleans the result.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::resolve;
///
/// assert_eq!(
///     resolve::to_absolute_path("/home/user", "documents/file.txt"),
///     "/home/user/documents/file.txt"
/// );
///
/// assert_eq!(
///     resolve::to_absolute_path("/home/user/dir", "../other/file.txt"),
///     "/home/other/file.txt"
/// );
///
/// // Absolute path returns unchanged
/// assert_eq!(
///     resolve::to_absolute_path("/home/user", "/etc/passwd"),
///     "/etc/passwd"
/// );
/// ```
#[must_use]
pub fn to_absolute_path(base: &str, path: &str) -> String {
    // Check if path is absolute
    if path.starts_with('/')
        || path.starts_with('\\')
        || (path.len() >= 2
            && path
                .chars()
                .next()
                .map_or(false, |c| c.is_ascii_alphabetic())
            && path.chars().nth(1) == Some(':'))
    {
        return clean_path(path);
    }

    // Join and clean
    let uses_backslash = base.contains('\\') && !base.contains('/');
    let separator = if uses_backslash { "\\" } else { "/" };

    let combined = format!("{}{}{}", base, separator, path);
    clean_path(&combined)
}

/// Convert an absolute path to a relative path from one location to another
///
/// Returns a relative path from `from` to `to`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::resolve;
///
/// assert_eq!(
///     resolve::to_relative_path("/home/user/docs", "/home/user/pics"),
///     "../pics"
/// );
///
/// assert_eq!(
///     resolve::to_relative_path("/a/b/c", "/a/b/c/d/e"),
///     "d/e"
/// );
/// ```
#[must_use]
pub fn to_relative_path(from: &str, to: &str) -> String {
    let from_parts: Vec<&str> = split(from).into_iter().filter(|s| !s.is_empty()).collect();
    let to_parts: Vec<&str> = split(to).into_iter().filter(|s| !s.is_empty()).collect();

    // Find common prefix length
    let common_len = from_parts
        .iter()
        .zip(to_parts.iter())
        .take_while(|(a, b)| a == b)
        .count();

    // Build relative path
    let ups = from_parts.len().saturating_sub(common_len);
    let mut result: Vec<&str> = vec![".."; ups];
    result.extend(to_parts.iter().skip(common_len));

    if result.is_empty() {
        ".".to_string()
    } else {
        result.join("/")
    }
}

// ============================================================================
// Path Component Resolution using std::path
// ============================================================================

/// Clean path using std::path::Components
///
/// Uses the standard library's path component iteration for
/// platform-native behavior.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::resolve;
///
/// let result = resolve::clean_path_std("path/to/../other");
/// // Platform-native path handling
/// ```
#[must_use]
pub fn clean_path_std(path: &str) -> String {
    let mut components: Vec<String> = Vec::new();

    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {
                // Skip current directory
            }
            Component::ParentDir => {
                if components.is_empty() || components.last().map_or(false, |s| s == "..") {
                    components.push("..".to_string());
                } else {
                    components.pop();
                }
            }
            Component::Normal(s) => {
                if let Some(s) = s.to_str() {
                    components.push(s.to_string());
                }
            }
            Component::RootDir => {
                components.clear();
                components.push("/".to_string());
            }
            Component::Prefix(p) => {
                components.clear();
                if let Some(s) = p.as_os_str().to_str() {
                    components.push(s.to_string());
                }
            }
        }
    }

    if components.is_empty() {
        ".".to_string()
    } else if components.len() == 1 && components.first().map(String::as_str) == Some("/") {
        "/".to_string()
    } else if components.first().map(String::as_str) == Some("/") {
        format!("/{}", components.get(1..).unwrap_or(&[]).join("/"))
    } else {
        components.join("/")
    }
}

// ============================================================================
// Extension Operations
// ============================================================================

/// Replace the extension of a path
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::resolve;
///
/// assert_eq!(resolve::with_extension("file.txt", "md"), "file.md");
/// assert_eq!(resolve::with_extension("file", "txt"), "file.txt");
/// assert_eq!(resolve::with_extension("path/file.txt", "md"), "path/file.md");
/// ```
#[must_use]
pub fn with_extension(path: &str, new_ext: &str) -> String {
    let parent_dir = find_parent(path).unwrap_or("");
    let name = filename(path);

    // Find extension start
    let stem = if name.starts_with('.') && !name.get(1..).unwrap_or("").contains('.') {
        // Hidden file without extension
        name
    } else if let Some(pos) = name.rfind('.') {
        if pos == 0 {
            name
        } else {
            name.get(..pos).unwrap_or(name)
        }
    } else {
        name
    };

    // Build new path
    let new_name = if new_ext.is_empty() {
        stem.to_string()
    } else {
        format!("{}.{}", stem, new_ext)
    };

    if parent_dir.is_empty() {
        new_name
    } else {
        let sep = if path.contains('\\') && !path.contains('/') {
            '\\'
        } else {
            '/'
        };
        format!("{}{}{}", parent_dir, sep, new_name)
    }
}

/// Add an extension to a path
///
/// Appends the extension without removing existing one.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::resolve;
///
/// assert_eq!(resolve::add_extension("file.tar", "gz"), "file.tar.gz");
/// assert_eq!(resolve::add_extension("file", "txt"), "file.txt");
/// ```
#[must_use]
pub fn add_extension(path: &str, ext: &str) -> String {
    if ext.is_empty() {
        path.to_string()
    } else {
        format!("{}.{}", path, ext)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // clean_path tests
    #[test]
    fn test_clean_path_current_dir() {
        assert_eq!(clean_path("./file"), "file");
        assert_eq!(clean_path("path/./to/./file"), "path/to/file");
        assert_eq!(clean_path("."), ".");
    }

    #[test]
    fn test_clean_path_parent_dir() {
        assert_eq!(clean_path("path/to/../file"), "path/file");
        assert_eq!(clean_path("a/b/c/../../d"), "a/d");
        assert_eq!(clean_path("a/b/../.."), ".");
    }

    #[test]
    fn test_clean_path_leading_parent() {
        assert_eq!(clean_path("../file"), "../file");
        assert_eq!(clean_path("../../file"), "../../file");
        assert_eq!(clean_path("../a/../b"), "../b");
    }

    #[test]
    fn test_clean_path_absolute() {
        assert_eq!(clean_path("/path/to/../file"), "/path/file");
        assert_eq!(clean_path("/.."), "/"); // Can't go above root
        assert_eq!(clean_path("/../../../file"), "/file");
    }

    #[test]
    fn test_clean_path_complex() {
        assert_eq!(clean_path("a/b/c/../d/./e/../f"), "a/b/d/f");
        assert_eq!(clean_path("./a/../b/./c"), "b/c");
    }

    // to_absolute_path tests
    #[test]
    fn test_to_absolute_path_basic() {
        assert_eq!(
            to_absolute_path("/home/user", "documents/file.txt"),
            "/home/user/documents/file.txt"
        );
        assert_eq!(
            to_absolute_path("/home/user", "./file.txt"),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_to_absolute_path_with_parent() {
        // /home/user/dir + ../other/file.txt = /home/user/dir/../other/file.txt
        // Cleaned: /home/user/other/file.txt (.. cancels dir)
        assert_eq!(
            to_absolute_path("/home/user/dir", "../other/file.txt"),
            "/home/user/other/file.txt"
        );
        assert_eq!(
            to_absolute_path("/home/user", "../../file.txt"),
            "/file.txt"
        );
    }

    #[test]
    fn test_to_absolute_path_already_absolute() {
        assert_eq!(to_absolute_path("/home/user", "/etc/passwd"), "/etc/passwd");
    }

    // to_relative_path tests
    #[test]
    fn test_to_relative_path_sibling() {
        assert_eq!(
            to_relative_path("/home/user/docs", "/home/user/pics"),
            "../pics"
        );
    }

    #[test]
    fn test_to_relative_path_child() {
        assert_eq!(to_relative_path("/a/b/c", "/a/b/c/d/e"), "d/e");
    }

    #[test]
    fn test_to_relative_path_same() {
        assert_eq!(to_relative_path("/a/b/c", "/a/b/c"), ".");
    }

    #[test]
    fn test_to_relative_path_distant() {
        assert_eq!(to_relative_path("/a/b/c", "/d/e/f"), "../../../d/e/f");
    }

    // Extension tests
    #[test]
    fn test_with_extension() {
        assert_eq!(with_extension("file.txt", "md"), "file.md");
        assert_eq!(with_extension("file", "txt"), "file.txt");
        assert_eq!(with_extension("path/file.txt", "md"), "path/file.md");
        assert_eq!(with_extension("file.tar.gz", "bz2"), "file.tar.bz2");
    }

    #[test]
    fn test_with_extension_remove() {
        assert_eq!(with_extension("file.txt", ""), "file");
        assert_eq!(with_extension("path/file.txt", ""), "path/file");
    }

    #[test]
    fn test_with_extension_hidden() {
        assert_eq!(with_extension(".hidden", "txt"), ".hidden.txt");
        assert_eq!(with_extension(".config.json", "yaml"), ".config.yaml");
    }

    #[test]
    fn test_add_extension() {
        assert_eq!(add_extension("file.tar", "gz"), "file.tar.gz");
        assert_eq!(add_extension("file", "txt"), "file.txt");
        assert_eq!(add_extension("file", ""), "file");
    }

    // Edge cases
    #[test]
    fn test_clean_path_empty() {
        assert_eq!(clean_path(""), "");
    }

    #[test]
    fn test_clean_path_windows_style() {
        assert_eq!(clean_path("path\\to\\..\\file"), "path\\file");
    }

    #[test]
    fn test_clean_path_std_basic() {
        assert_eq!(clean_path_std("path/to/../file"), "path/file");
        assert_eq!(clean_path_std("./file"), "file");
    }
}
