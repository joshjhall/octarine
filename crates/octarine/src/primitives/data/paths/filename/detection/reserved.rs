//! Reserved name detection functions
//!
//! Functions to detect Windows reserved names and directory references.

use super::constants::RESERVED_WINDOWS_NAMES;

// ============================================================================
// Reserved Name Detection
// ============================================================================

/// Check if filename is a Windows reserved name
///
/// Windows reserves certain names for devices: CON, PRN, AUX, NUL,
/// COM1-COM9, LPT1-LPT9. These cannot be used as filenames.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_reserved_name("CON"));
/// assert!(detection::is_reserved_name("con"));
/// assert!(detection::is_reserved_name("NUL.txt"));
/// assert!(detection::is_reserved_name("COM1"));
/// assert!(!detection::is_reserved_name("file.txt"));
/// ```
#[must_use]
pub fn is_reserved_name(filename: &str) -> bool {
    // Get the stem (without extension)
    let stem = filename.split('.').next().unwrap_or(filename);
    let upper = stem.to_ascii_uppercase();
    RESERVED_WINDOWS_NAMES.contains(&upper.as_str())
}

/// Check if filename is a current directory reference
#[must_use]
pub fn is_current_dir(filename: &str) -> bool {
    filename == "."
}

/// Check if filename is a parent directory reference
#[must_use]
pub fn is_parent_dir(filename: &str) -> bool {
    filename == ".."
}

/// Check if filename is a directory reference (. or ..)
#[must_use]
pub fn is_directory_ref(filename: &str) -> bool {
    is_current_dir(filename) || is_parent_dir(filename)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_reserved_name() {
        // Case-insensitive
        assert!(is_reserved_name("CON"));
        assert!(is_reserved_name("con"));
        assert!(is_reserved_name("Con"));
        assert!(is_reserved_name("NUL"));
        assert!(is_reserved_name("PRN"));
        assert!(is_reserved_name("AUX"));
        assert!(is_reserved_name("COM1"));
        assert!(is_reserved_name("COM9"));
        assert!(is_reserved_name("LPT1"));
        assert!(is_reserved_name("LPT9"));

        // With extension still reserved
        assert!(is_reserved_name("NUL.txt"));
        assert!(is_reserved_name("CON.log"));

        // Not reserved
        assert!(!is_reserved_name("file.txt"));
        assert!(!is_reserved_name("CONN")); // Not CON
        assert!(!is_reserved_name("COM10")); // Only COM1-9
    }

    #[test]
    fn test_directory_refs() {
        assert!(is_current_dir("."));
        assert!(!is_current_dir(".."));
        assert!(!is_current_dir("file.txt"));

        assert!(is_parent_dir(".."));
        assert!(!is_parent_dir("."));
        assert!(!is_parent_dir("file.txt"));

        assert!(is_directory_ref("."));
        assert!(is_directory_ref(".."));
        assert!(!is_directory_ref("..."));
        assert!(!is_directory_ref("file.txt"));
    }
}
