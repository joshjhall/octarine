//! Extension detection functions
//!
//! Functions to detect and analyze file extensions.

// Allow indexing in this module - bounds are checked appropriately
#![allow(clippy::indexing_slicing)]

use super::constants::DANGEROUS_EXTENSIONS;

// ============================================================================
// Extension Detection
// ============================================================================

/// Check if filename has an extension
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_extension_present("file.txt"));
/// assert!(detection::is_extension_present("file.tar.gz"));
/// assert!(!detection::is_extension_present("file"));
/// assert!(!detection::is_extension_present(".gitignore")); // Hidden file, no extension
/// ```
#[must_use]
pub fn is_extension_present(filename: &str) -> bool {
    find_extension(filename).is_some()
}

/// Find the extension of a filename
///
/// Returns the extension without the leading dot, or None if no extension.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert_eq!(detection::find_extension("file.txt"), Some("txt"));
/// assert_eq!(detection::find_extension("file.tar.gz"), Some("gz"));
/// assert_eq!(detection::find_extension("file"), None);
/// assert_eq!(detection::find_extension(".gitignore"), None);
/// ```
#[must_use]
pub fn find_extension(filename: &str) -> Option<&str> {
    // Handle dot files - they don't have extensions
    if filename.starts_with('.') && !filename[1..].contains('.') {
        return None;
    }

    filename.rfind('.').and_then(|pos| {
        if pos == 0 {
            None
        } else {
            // pos + 1 is safe: pos < filename.len() (from rfind) and pos > 0 (checked above)
            let start = pos.saturating_add(1);
            Some(&filename[start..])
        }
    })
}

/// Get the stem of a filename (name without extension)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert_eq!(detection::stem("file.txt"), "file");
/// assert_eq!(detection::stem("file.tar.gz"), "file.tar");
/// assert_eq!(detection::stem("file"), "file");
/// assert_eq!(detection::stem(".gitignore"), ".gitignore");
/// ```
#[must_use]
pub fn stem(filename: &str) -> &str {
    // Handle dot files
    if filename.starts_with('.') && !filename[1..].contains('.') {
        return filename;
    }

    match filename.rfind('.') {
        Some(pos) if pos > 0 => &filename[..pos],
        _ => filename,
    }
}

/// Check if filename has multiple extensions (double extension)
///
/// Double extensions can be used to hide true file type (e.g., `file.txt.exe`).
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_double_extension_present("file.txt.exe"));
/// assert!(detection::is_double_extension_present("file.tar.gz"));
/// assert!(!detection::is_double_extension_present("file.txt"));
/// assert!(!detection::is_double_extension_present("file"));
/// ```
#[must_use]
pub fn is_double_extension_present(filename: &str) -> bool {
    let start = if filename.starts_with('.') { 1 } else { 0 };
    filename[start..].matches('.').count() >= 2
}

/// Check if filename has a dangerous extension
///
/// Dangerous extensions include executable types that could run code.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_dangerous_extension_present("file.exe"));
/// assert!(detection::is_dangerous_extension_present("file.bat"));
/// assert!(detection::is_dangerous_extension_present("file.ps1"));
/// assert!(!detection::is_dangerous_extension_present("file.txt"));
/// ```
#[must_use]
pub fn is_dangerous_extension_present(filename: &str) -> bool {
    find_extension(filename)
        .map(|ext| {
            let lower = ext.to_ascii_lowercase();
            DANGEROUS_EXTENSIONS.contains(&lower.as_str())
        })
        .unwrap_or(false)
}

/// Check if extension matches expected value (case-insensitive)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_extension_found("file.TXT", "txt"));
/// assert!(detection::is_extension_found("file.txt", "TXT"));
/// assert!(!detection::is_extension_found("file.txt", "pdf"));
/// ```
#[must_use]
pub fn is_extension_found(filename: &str, expected: &str) -> bool {
    find_extension(filename)
        .map(|ext| ext.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

/// Check if extension is in allowed list (case-insensitive)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// let allowed = &["txt", "pdf", "doc"];
/// assert!(detection::is_extension_in_list("file.txt", allowed));
/// assert!(detection::is_extension_in_list("file.TXT", allowed));
/// assert!(!detection::is_extension_in_list("file.exe", allowed));
/// ```
#[must_use]
pub fn is_extension_in_list(filename: &str, allowed: &[&str]) -> bool {
    find_extension(filename)
        .map(|ext| {
            let lower = ext.to_ascii_lowercase();
            allowed.iter().any(|a| a.eq_ignore_ascii_case(&lower))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_extension_present() {
        assert!(is_extension_present("file.txt"));
        assert!(is_extension_present("file.tar.gz"));
        assert!(!is_extension_present("file"));
        assert!(!is_extension_present(".gitignore")); // Hidden file
        assert!(is_extension_present(".git.config")); // Hidden with extension
    }

    #[test]
    fn test_find_extension() {
        assert_eq!(find_extension("file.txt"), Some("txt"));
        assert_eq!(find_extension("file.tar.gz"), Some("gz"));
        assert_eq!(find_extension("FILE.TXT"), Some("TXT"));
        assert_eq!(find_extension("file"), None);
        assert_eq!(find_extension(".gitignore"), None);
        assert_eq!(find_extension(".git.config"), Some("config"));
    }

    #[test]
    fn test_stem() {
        assert_eq!(stem("file.txt"), "file");
        assert_eq!(stem("file.tar.gz"), "file.tar");
        assert_eq!(stem("file"), "file");
        assert_eq!(stem(".gitignore"), ".gitignore");
        assert_eq!(stem(".git.config"), ".git");
    }

    #[test]
    fn test_is_double_extension_present() {
        assert!(is_double_extension_present("file.txt.exe"));
        assert!(is_double_extension_present("file.tar.gz"));
        assert!(is_double_extension_present("file.a.b.c"));
        assert!(!is_double_extension_present("file.txt"));
        assert!(!is_double_extension_present("file"));
        assert!(!is_double_extension_present(".gitignore"));
    }

    #[test]
    fn test_is_dangerous_extension_present() {
        assert!(is_dangerous_extension_present("file.exe"));
        assert!(is_dangerous_extension_present("file.EXE"));
        assert!(is_dangerous_extension_present("file.bat"));
        assert!(is_dangerous_extension_present("file.ps1"));
        assert!(is_dangerous_extension_present("file.vbs"));
        assert!(!is_dangerous_extension_present("file.txt"));
        assert!(!is_dangerous_extension_present("file.pdf"));
    }

    #[test]
    fn test_is_extension_found() {
        assert!(is_extension_found("file.txt", "txt"));
        assert!(is_extension_found("file.TXT", "txt"));
        assert!(is_extension_found("file.txt", "TXT"));
        assert!(!is_extension_found("file.txt", "pdf"));
        assert!(!is_extension_found("file", "txt"));
    }

    #[test]
    fn test_is_extension_in_list() {
        let allowed = &["txt", "pdf", "doc"];
        assert!(is_extension_in_list("file.txt", allowed));
        assert!(is_extension_in_list("file.TXT", allowed));
        assert!(is_extension_in_list("file.pdf", allowed));
        assert!(!is_extension_in_list("file.exe", allowed));
        assert!(!is_extension_in_list("file", allowed));
    }
}
