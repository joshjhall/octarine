// Allow clippy lints that are overly strict for this utility module
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::manual_strip)]

//! Path component extraction utilities
//!
//! Functions for extracting parts of paths (parent, filename, extension, etc.).
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Parent directory extraction
//! - Filename extraction
//! - Extension extraction/manipulation
//! - Path splitting
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Platform-Aware**: Handles both Unix and Windows separators
//! 3. **Zero-Copy Where Possible**: Uses `&str` slices

use std::path::Path;

// ============================================================================
// Parent Directory
// ============================================================================

/// Find the parent directory of a path
///
/// Returns the path without the last component.
/// Returns `None` for root paths or paths with no parent.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::find_parent("path/to/file.txt"), Some("path/to"));
/// assert_eq!(components::find_parent("file.txt"), None);
/// assert_eq!(components::find_parent("/home"), Some("/"));
/// assert_eq!(components::find_parent("/"), None);
/// ```
#[must_use]
pub fn find_parent(path: &str) -> Option<&str> {
    // Handle empty path
    if path.is_empty() {
        return None;
    }

    // Handle root path (just "/" or "\")
    if path == "/" || path == "\\" {
        return None;
    }

    // Find the last separator
    let last_sep = path.rfind('/').or_else(|| path.rfind('\\'));

    match last_sep {
        Some(0) => Some("/"), // Path like "/home" -> parent is "/"
        Some(pos) => path.get(..pos),
        None => None, // No separator, no parent
    }
}

/// Get all ancestor paths (parent, grandparent, etc.)
///
/// Returns a vector of all ancestor paths from immediate parent to root.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// let ancestors = components::ancestors("path/to/deep/file.txt");
/// assert_eq!(ancestors, vec!["path/to/deep", "path/to", "path"]);
/// ```
#[must_use]
pub fn ancestors(path: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut current = path;

    while let Some(p) = find_parent(current) {
        result.push(p);
        current = p;
    }

    result
}

// ============================================================================
// Filename
// ============================================================================

/// Get the filename (last component) of a path
///
/// Returns the part after the last separator.
/// For paths ending with a separator, returns an empty string.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::filename("path/to/file.txt"), "file.txt");
/// assert_eq!(components::filename("file.txt"), "file.txt");
/// assert_eq!(components::filename("path/to/"), "");
/// ```
#[must_use]
pub fn filename(path: &str) -> &str {
    // Find the last separator
    let last_sep = path.rfind('/').or_else(|| path.rfind('\\'));

    match last_sep {
        Some(pos) => path.get(pos.saturating_add(1)..).unwrap_or(""),
        None => path, // No separator, entire path is filename
    }
}

/// Get the filename without extension (stem)
///
/// Returns the filename with the extension removed.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::stem("path/to/file.txt"), "file");
/// assert_eq!(components::stem("file.tar.gz"), "file.tar");
/// assert_eq!(components::stem("file"), "file");
/// assert_eq!(components::stem(".hidden"), ".hidden"); // Hidden files
/// ```
#[must_use]
pub fn stem(path: &str) -> &str {
    let name = filename(path);

    // Handle hidden files (starting with dot)
    if name.starts_with('.') && !name.get(1..).unwrap_or("").contains('.') {
        return name; // .hidden has no extension
    }

    // Find the last dot
    match name.rfind('.') {
        Some(0) => name, // .hidden or similar
        Some(pos) => name.get(..pos).unwrap_or(name),
        None => name, // No extension
    }
}

// ============================================================================
// Extension
// ============================================================================

/// Find the file extension
///
/// Returns the part after the last dot in the filename.
/// Returns `None` if no extension.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::find_extension("file.txt"), Some("txt"));
/// assert_eq!(components::find_extension("file.tar.gz"), Some("gz"));
/// assert_eq!(components::find_extension("file"), None);
/// assert_eq!(components::find_extension(".hidden"), None); // Hidden file, no extension
/// ```
#[must_use]
pub fn find_extension(path: &str) -> Option<&str> {
    let name = filename(path);

    // Handle hidden files (starting with dot)
    if name.starts_with('.') && !name.get(1..).unwrap_or("").contains('.') {
        return None; // .hidden has no extension
    }

    // Find the last dot
    match name.rfind('.') {
        Some(0) => None, // .hidden or similar
        Some(pos) => name.get(pos.saturating_add(1)..),
        None => None, // No extension
    }
}

/// Check if path has a specific extension (case-insensitive)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert!(components::is_extension_found("file.TXT", "txt"));
/// assert!(components::is_extension_found("file.txt", "TXT"));
/// assert!(!components::is_extension_found("file.txt", "pdf"));
/// ```
#[must_use]
pub fn is_extension_found(path: &str, ext: &str) -> bool {
    find_extension(path)
        .map(|e| e.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

/// Get all extensions from a multi-extension filename
///
/// Returns all extensions for files like `.tar.gz`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::extensions("file.tar.gz"), vec!["tar", "gz"]);
/// assert_eq!(components::extensions("file.txt"), vec!["txt"]);
/// assert_eq!(components::extensions("file"), Vec::<&str>::new());
/// ```
#[must_use]
pub fn extensions(path: &str) -> Vec<&str> {
    let name = filename(path);

    // Handle hidden files
    let name = if name.starts_with('.') {
        name.get(1..).unwrap_or("")
    } else {
        name
    };

    // Split by dots and skip the first part (the stem)
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() > 1 {
        parts.get(1..).unwrap_or(&[]).to_vec()
    } else {
        Vec::new()
    }
}

// ============================================================================
// Path Splitting
// ============================================================================

/// Split path into individual components
///
/// Returns a vector of path components (directories and filename).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::split("path/to/file.txt"), vec!["path", "to", "file.txt"]);
/// assert_eq!(components::split("/root/dir"), vec!["", "root", "dir"]);
/// ```
#[must_use]
pub fn split(path: &str) -> Vec<&str> {
    // Handle both Unix and Windows separators
    if path.contains('\\') && !path.contains('/') {
        path.split('\\').collect()
    } else {
        path.split('/').collect()
    }
}

/// Split path into parent and filename
///
/// Returns `(parent, filename)` tuple.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::split_last("path/to/file.txt"), (Some("path/to"), "file.txt"));
/// assert_eq!(components::split_last("file.txt"), (None, "file.txt"));
/// ```
#[must_use]
pub fn split_last(path: &str) -> (Option<&str>, &str) {
    (find_parent(path), filename(path))
}

// ============================================================================
// Depth Calculation
// ============================================================================

/// Calculate the depth of a path (number of components)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::depth("path/to/file.txt"), 3);
/// assert_eq!(components::depth("file.txt"), 1);
/// assert_eq!(components::depth("/root"), 2); // "" and "root"
/// ```
#[must_use]
pub fn depth(path: &str) -> usize {
    if path.is_empty() {
        return 0;
    }
    split(path).len()
}

/// Calculate the depth excluding empty components
///
/// More useful for security depth limiting.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::components;
///
/// assert_eq!(components::effective_depth("path/to/file.txt"), 3);
/// assert_eq!(components::effective_depth("/root"), 1); // Just "root"
/// assert_eq!(components::effective_depth("path//double"), 2); // Ignores empty
/// ```
#[must_use]
pub fn effective_depth(path: &str) -> usize {
    split(path).iter().filter(|s| !s.is_empty()).count()
}

// ============================================================================
// Using std::path
// ============================================================================

/// Get parent directory using std::path
///
/// Platform-native implementation.
#[must_use]
pub fn parent_std(path: &str) -> Option<&std::path::Path> {
    Path::new(path).parent()
}

/// Get filename using std::path
///
/// Platform-native implementation.
#[must_use]
pub fn filename_std(path: &str) -> Option<&std::ffi::OsStr> {
    Path::new(path).file_name()
}

/// Get extension using std::path
///
/// Platform-native implementation.
#[must_use]
pub fn extension_std(path: &str) -> Option<&std::ffi::OsStr> {
    Path::new(path).extension()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Parent tests
    #[test]
    fn test_find_parent_basic() {
        assert_eq!(find_parent("path/to/file.txt"), Some("path/to"));
        assert_eq!(find_parent("path/file"), Some("path"));
        assert_eq!(find_parent("a/b"), Some("a"));
    }

    #[test]
    fn test_find_parent_windows() {
        assert_eq!(find_parent("path\\to\\file.txt"), Some("path\\to"));
    }

    #[test]
    fn test_find_parent_no_parent() {
        assert_eq!(find_parent("file.txt"), None);
        assert_eq!(find_parent(""), None);
        assert_eq!(find_parent("/"), None);
    }

    #[test]
    fn test_ancestors() {
        let result = ancestors("path/to/deep/file.txt");
        assert_eq!(result, vec!["path/to/deep", "path/to", "path"]);
    }

    #[test]
    fn test_ancestors_shallow() {
        let result = ancestors("path/file.txt");
        assert_eq!(result, vec!["path"]);
    }

    #[test]
    fn test_ancestors_no_parent() {
        let result = ancestors("file.txt");
        assert!(result.is_empty());
    }

    // Filename tests
    #[test]
    fn test_filename_basic() {
        assert_eq!(filename("path/to/file.txt"), "file.txt");
        assert_eq!(filename("file.txt"), "file.txt");
        assert_eq!(filename("path/"), "");
    }

    #[test]
    fn test_filename_windows() {
        assert_eq!(filename("path\\to\\file.txt"), "file.txt");
    }

    #[test]
    fn test_stem_basic() {
        assert_eq!(stem("path/to/file.txt"), "file");
        assert_eq!(stem("file.tar.gz"), "file.tar");
        assert_eq!(stem("file"), "file");
    }

    #[test]
    fn test_stem_hidden_files() {
        assert_eq!(stem(".hidden"), ".hidden"); // No extension
        assert_eq!(stem(".config.json"), ".config"); // Has extension
    }

    // Extension tests
    #[test]
    fn test_find_extension_basic() {
        assert_eq!(find_extension("file.txt"), Some("txt"));
        assert_eq!(find_extension("file.tar.gz"), Some("gz"));
        assert_eq!(find_extension("file"), None);
    }

    #[test]
    fn test_find_extension_hidden() {
        assert_eq!(find_extension(".hidden"), None);
        assert_eq!(find_extension(".config.json"), Some("json"));
    }

    #[test]
    fn test_is_extension_found() {
        assert!(is_extension_found("file.TXT", "txt"));
        assert!(is_extension_found("file.txt", "TXT"));
        assert!(is_extension_found("FILE.TXT", "txt"));
        assert!(!is_extension_found("file.txt", "pdf"));
        assert!(!is_extension_found("file", "txt"));
    }

    #[test]
    fn test_extensions_multiple() {
        assert_eq!(extensions("file.tar.gz"), vec!["tar", "gz"]);
        assert_eq!(extensions("file.txt"), vec!["txt"]);
        assert_eq!(extensions("file"), Vec::<&str>::new());
        assert_eq!(extensions(".hidden"), Vec::<&str>::new());
        // .config.json: strip leading dot -> config.json, split by . -> ["config", "json"]
        // extensions returns parts after stem, so ["json"]
        assert_eq!(extensions(".config.json"), vec!["json"]);
    }

    // Split tests
    #[test]
    fn test_split_basic() {
        assert_eq!(split("path/to/file.txt"), vec!["path", "to", "file.txt"]);
        assert_eq!(split("file.txt"), vec!["file.txt"]);
    }

    #[test]
    fn test_split_absolute() {
        assert_eq!(split("/root/dir"), vec!["", "root", "dir"]);
    }

    #[test]
    fn test_split_windows() {
        assert_eq!(split("path\\to\\file.txt"), vec!["path", "to", "file.txt"]);
    }

    #[test]
    fn test_split_last() {
        assert_eq!(
            split_last("path/to/file.txt"),
            (Some("path/to"), "file.txt")
        );
        assert_eq!(split_last("file.txt"), (None, "file.txt"));
    }

    // Depth tests
    #[test]
    fn test_depth() {
        assert_eq!(depth("path/to/file.txt"), 3);
        assert_eq!(depth("file.txt"), 1);
        assert_eq!(depth(""), 0);
    }

    #[test]
    fn test_effective_depth() {
        assert_eq!(effective_depth("path/to/file.txt"), 3);
        assert_eq!(effective_depth("/root"), 1); // Ignores empty from leading /
        assert_eq!(effective_depth("path//double"), 2); // Ignores empty between //
    }

    // Edge cases
    #[test]
    fn test_empty_path() {
        assert_eq!(find_parent(""), None);
        assert_eq!(filename(""), "");
        assert_eq!(stem(""), "");
        assert_eq!(find_extension(""), None);
        assert_eq!(depth(""), 0);
    }

    #[test]
    fn test_root_paths() {
        assert_eq!(find_parent("/"), None);
        assert_eq!(filename("/"), "");
        assert_eq!(find_parent("\\"), None);
    }
}
