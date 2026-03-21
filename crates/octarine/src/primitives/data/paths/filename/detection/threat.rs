//! Comprehensive threat detection functions
//!
//! High-level functions that check for multiple security threats.

use std::borrow::Cow;

use super::{
    characters::is_dangerous_shell_chars_present,
    characters::{is_control_characters_present, is_null_bytes_present},
    extensions::{is_dangerous_extension_present, is_double_extension_present},
    injection::{is_command_substitution_present, is_variable_expansion_present},
    length::is_empty,
    reserved::{is_directory_ref, is_reserved_name},
    separators::is_path_separators_present,
    unicode::{is_bidi_control_present, is_homoglyphs_present},
};

// ============================================================================
// Comprehensive Threat Detection
// ============================================================================

/// Check if filename has any security threat
///
/// Comprehensive check for all dangerous patterns.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// // All of these are threats
/// assert!(detection::is_threat_present("../file.txt"));
/// assert!(detection::is_threat_present("file\0.txt"));
/// assert!(detection::is_threat_present("$(cmd).txt"));
/// assert!(detection::is_threat_present("CON.txt"));
///
/// // Safe filename
/// assert!(!detection::is_threat_present("file.txt"));
/// ```
#[must_use]
pub fn is_threat_present(filename: &str) -> bool {
    is_empty(filename)
        || is_null_bytes_present(filename)
        || is_control_characters_present(filename)
        || is_path_separators_present(filename)
        || is_directory_ref(filename)
        || is_command_substitution_present(filename)
        || is_reserved_name(filename)
        || is_bidi_control_present(filename)
}

/// Detect all security issues in a filename
///
/// Returns a list of all detected security issues.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// let issues = detection::detect_all_issues("../$(cmd)\0.txt");
/// assert!(issues.contains(&"path_separator"));
/// assert!(issues.contains(&"command_substitution"));
/// assert!(issues.contains(&"null_byte"));
/// ```
#[must_use]
pub fn detect_all_issues(filename: &str) -> Vec<&'static str> {
    let mut issues = Vec::new();

    if is_empty(filename) {
        issues.push("empty");
    }
    if is_null_bytes_present(filename) {
        issues.push("null_byte");
    }
    if is_control_characters_present(filename) {
        issues.push("control_character");
    }
    if is_path_separators_present(filename) {
        issues.push("path_separator");
    }
    if is_directory_ref(filename) {
        issues.push("directory_reference");
    }
    if is_command_substitution_present(filename) {
        issues.push("command_substitution");
    }
    if is_variable_expansion_present(filename) {
        issues.push("variable_expansion");
    }
    if is_dangerous_shell_chars_present(filename) {
        issues.push("shell_metacharacter");
    }
    if is_reserved_name(filename) {
        issues.push("reserved_name");
    }
    if is_dangerous_extension_present(filename) {
        issues.push("dangerous_extension");
    }
    if is_double_extension_present(filename) {
        issues.push("double_extension");
    }
    if is_bidi_control_present(filename) {
        issues.push("bidi_control");
    }
    if is_homoglyphs_present(filename) {
        issues.push("homoglyph");
    }

    issues
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Normalize filename to lowercase for comparison
#[must_use]
pub fn normalize_case(filename: &str) -> Cow<'_, str> {
    if filename
        .chars()
        .all(|c| c.is_lowercase() || !c.is_alphabetic())
    {
        Cow::Borrowed(filename)
    } else {
        Cow::Owned(filename.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_threat_present() {
        // All threats
        assert!(is_threat_present(""));
        assert!(is_threat_present("file\0.txt"));
        assert!(is_threat_present("file\n.txt"));
        assert!(is_threat_present("../file.txt"));
        assert!(is_threat_present("foo/bar.txt"));
        assert!(is_threat_present("."));
        assert!(is_threat_present(".."));
        assert!(is_threat_present("$(cmd).txt"));
        assert!(is_threat_present("CON"));
        assert!(is_threat_present("file\u{202E}.txt"));

        // Safe
        assert!(!is_threat_present("file.txt"));
        assert!(!is_threat_present("file-name_123.txt"));
        assert!(!is_threat_present(".gitignore"));
    }

    #[test]
    fn test_detect_all_issues() {
        let issues = detect_all_issues("../$(cmd)\0.txt");
        assert!(issues.contains(&"path_separator"));
        assert!(issues.contains(&"command_substitution"));
        assert!(issues.contains(&"null_byte"));
        assert!(issues.contains(&"shell_metacharacter"));

        let safe_issues = detect_all_issues("file.txt");
        assert!(safe_issues.is_empty());
    }

    #[test]
    fn test_normalize_case() {
        assert_eq!(normalize_case("file.txt").as_ref(), "file.txt");
        assert_eq!(normalize_case("FILE.TXT").as_ref(), "file.txt");
        assert_eq!(normalize_case("File.Txt").as_ref(), "file.txt");
        assert_eq!(normalize_case("123.txt").as_ref(), "123.txt");
    }
}
