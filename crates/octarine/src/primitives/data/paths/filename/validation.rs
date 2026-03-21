//! Filename validation functions
//!
//! Provides validation functions for filenames with dual API pattern:
//! - Lenient functions return `bool`
//! - Strict functions return `Result<(), Problem>`
//!
//! ## Validation Philosophy
//!
//! Validation functions:
//! - Use detection functions first (DRY principle)
//! - Enforce security policy (reject threats)
//! - Return clear error messages
//! - Do NOT modify input (use sanitization for that)
//!
//! ## Security Checks
//!
//! | Check | Risk | Recommendation |
//! |-------|------|----------------|
//! | Null bytes | C string truncation | Always validate |
//! | Control characters | Log injection | Always validate |
//! | Path separators | Directory traversal | Always validate |
//! | Reserved names | Windows DoS | Validate for cross-platform |
//! | Dangerous extensions | Code execution | Validate for uploads |
//! | Command injection | Code execution | Always validate |
//! | Length limits | DoS | Configure per context |

use super::detection;
use crate::primitives::types::Problem;

// ============================================================================
// Result Type
// ============================================================================

/// Result type for filename validation operations
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Constants
// ============================================================================

/// Default maximum filename length (255 is common filesystem limit)
pub const DEFAULT_MAX_LENGTH: usize = 255;

/// Minimum filename length (at least 1 character)
pub const MIN_LENGTH: usize = 1;

// ============================================================================
// Core Validation Functions
// ============================================================================

/// Check if filename is valid (lenient)
///
/// Checks for critical security issues only:
/// - Not empty
/// - No null bytes
/// - No control characters
/// - No path separators
/// - Not a directory reference
/// - No command substitution
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::validation;
///
/// assert!(validation::is_valid("file.txt"));
/// assert!(validation::is_valid(".gitignore"));
/// assert!(!validation::is_valid(""));
/// assert!(!validation::is_valid("../file.txt"));
/// assert!(!validation::is_valid("$(cmd).txt"));
/// ```
#[must_use]
pub fn is_valid(filename: &str) -> bool {
    !detection::is_empty(filename)
        && !detection::is_null_bytes_present(filename)
        && !detection::is_control_characters_present(filename)
        && !detection::is_path_separators_present(filename)
        && !detection::is_directory_ref(filename)
        && !detection::is_command_substitution_present(filename)
}

/// Validate filename (strict)
///
/// Returns detailed error for validation failures.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::validation;
///
/// assert!(validation::validate_strict("file.txt").is_ok());
///
/// let err = validation::validate_strict("").expect_err("test");
/// assert!(err.to_string().contains("empty"));
/// ```
pub fn validate_strict(filename: &str) -> ValidationResult {
    if detection::is_empty(filename) {
        return Err(Problem::validation("Filename cannot be empty"));
    }
    if detection::is_null_bytes_present(filename) {
        return Err(Problem::validation("Filename contains null bytes"));
    }
    if detection::is_control_characters_present(filename) {
        return Err(Problem::validation("Filename contains control characters"));
    }
    if detection::is_path_separators_present(filename) {
        return Err(Problem::validation(
            "Filename contains path separators - use path functions for paths",
        ));
    }
    if detection::is_directory_ref(filename) {
        return Err(Problem::validation(
            "Filename cannot be a directory reference (. or ..)",
        ));
    }
    if detection::is_command_substitution_present(filename) {
        return Err(Problem::validation(
            "Filename contains command substitution patterns",
        ));
    }
    Ok(())
}

// ============================================================================
// Character Validation
// ============================================================================

/// Check if filename has no null bytes (lenient)
#[must_use]
pub fn is_null_bytes_absent(filename: &str) -> bool {
    !detection::is_null_bytes_present(filename)
}

/// Validate filename has no null bytes (strict)
pub fn validate_no_null_bytes(filename: &str) -> ValidationResult {
    if detection::is_null_bytes_present(filename) {
        return Err(Problem::validation("Filename contains null bytes"));
    }
    Ok(())
}

/// Check if filename has no control characters (lenient)
#[must_use]
pub fn is_control_characters_absent(filename: &str) -> bool {
    !detection::is_control_characters_present(filename)
}

/// Validate filename has no control characters (strict)
pub fn validate_no_control_characters(filename: &str) -> ValidationResult {
    if detection::is_control_characters_present(filename) {
        return Err(Problem::validation("Filename contains control characters"));
    }
    Ok(())
}

/// Check if filename has no dangerous shell characters (lenient)
#[must_use]
pub fn is_shell_chars_absent(filename: &str) -> bool {
    !detection::is_dangerous_shell_chars_present(filename)
}

/// Validate filename has no dangerous shell characters (strict)
pub fn validate_no_shell_chars(filename: &str) -> ValidationResult {
    if detection::is_dangerous_shell_chars_present(filename) {
        return Err(Problem::validation(
            "Filename contains dangerous shell characters",
        ));
    }
    Ok(())
}

// ============================================================================
// Path Separator Validation
// ============================================================================

/// Check if filename has no path separators (lenient)
#[must_use]
pub fn is_path_separators_absent(filename: &str) -> bool {
    !detection::is_path_separators_present(filename)
}

/// Validate filename has no path separators (strict)
pub fn validate_no_path_separators(filename: &str) -> ValidationResult {
    if detection::is_path_separators_present(filename) {
        return Err(Problem::validation(
            "Filename contains path separators - use path functions for paths",
        ));
    }
    Ok(())
}

/// Check if filename is not a directory reference (lenient)
#[must_use]
pub fn is_not_directory_ref(filename: &str) -> bool {
    !detection::is_directory_ref(filename)
}

/// Validate filename is not a directory reference (strict)
pub fn validate_not_directory_ref(filename: &str) -> ValidationResult {
    if detection::is_directory_ref(filename) {
        return Err(Problem::validation(
            "Filename cannot be a directory reference (. or ..)",
        ));
    }
    Ok(())
}

// ============================================================================
// Command Injection Validation
// ============================================================================

/// Check if filename has no command injection patterns (lenient)
#[must_use]
pub fn is_command_injection_absent(filename: &str) -> bool {
    !detection::is_command_substitution_present(filename)
        && !detection::is_variable_expansion_present(filename)
}

/// Validate filename has no command injection patterns (strict)
pub fn validate_no_command_injection(filename: &str) -> ValidationResult {
    if detection::is_command_substitution_present(filename) {
        return Err(Problem::validation(
            "Filename contains command substitution patterns",
        ));
    }
    if detection::is_variable_expansion_present(filename) {
        return Err(Problem::validation(
            "Filename contains variable expansion patterns",
        ));
    }
    Ok(())
}

/// Check if filename has no injection patterns (comprehensive, lenient)
#[must_use]
pub fn is_injection_absent(filename: &str) -> bool {
    !detection::is_injection_pattern_present(filename)
}

/// Validate filename has no injection patterns (comprehensive, strict)
pub fn validate_no_injection(filename: &str) -> ValidationResult {
    if detection::is_command_substitution_present(filename) {
        return Err(Problem::validation(
            "Filename contains command substitution patterns",
        ));
    }
    if detection::is_variable_expansion_present(filename) {
        return Err(Problem::validation(
            "Filename contains variable expansion patterns",
        ));
    }
    if detection::is_dangerous_shell_chars_present(filename) {
        return Err(Problem::validation(
            "Filename contains dangerous shell characters",
        ));
    }
    Ok(())
}

// ============================================================================
// Reserved Name Validation
// ============================================================================

/// Check if filename is not a Windows reserved name (lenient)
#[must_use]
pub fn is_not_reserved_name(filename: &str) -> bool {
    !detection::is_reserved_name(filename)
}

/// Validate filename is not a Windows reserved name (strict)
pub fn validate_not_reserved_name(filename: &str) -> ValidationResult {
    if detection::is_reserved_name(filename) {
        return Err(Problem::validation(format!(
            "Filename '{}' is a Windows reserved name",
            detection::stem(filename)
        )));
    }
    Ok(())
}

/// Check if filename has no Windows reserved characters (lenient)
#[must_use]
pub fn is_reserved_windows_chars_absent(filename: &str) -> bool {
    !detection::is_reserved_windows_chars_present(filename)
}

/// Validate filename has no Windows reserved characters (strict)
pub fn validate_no_reserved_windows_chars(filename: &str) -> ValidationResult {
    if detection::is_reserved_windows_chars_present(filename) {
        return Err(Problem::validation(
            "Filename contains characters reserved on Windows: < > : \" | ? *",
        ));
    }
    Ok(())
}

// ============================================================================
// Extension Validation
// ============================================================================

/// Check if filename has no dangerous extension (lenient)
#[must_use]
pub fn is_extension_safe(filename: &str) -> bool {
    !detection::is_dangerous_extension_present(filename)
}

/// Validate filename has no dangerous extension (strict)
pub fn validate_safe_extension(filename: &str) -> ValidationResult {
    if detection::is_dangerous_extension_present(filename) {
        let ext = detection::find_extension(filename).unwrap_or("unknown");
        return Err(Problem::validation(format!(
            "Filename has dangerous extension '.{}' that could execute code",
            ext
        )));
    }
    Ok(())
}

/// Check if filename extension is in allowed list (lenient)
#[must_use]
pub fn is_extension_allowed(filename: &str, allowed: &[&str]) -> bool {
    detection::is_extension_in_list(filename, allowed)
}

/// Validate filename extension is in allowed list (strict)
pub fn validate_allowed_extension(filename: &str, allowed: &[&str]) -> ValidationResult {
    if !detection::is_extension_in_list(filename, allowed) {
        let ext = detection::find_extension(filename);
        return Err(Problem::validation(format!(
            "Filename extension '{}' not in allowed list: {:?}",
            ext.unwrap_or("(none)"),
            allowed
        )));
    }
    Ok(())
}

/// Check if filename has no double extension (lenient)
#[must_use]
pub fn is_double_extension_absent(filename: &str) -> bool {
    !detection::is_double_extension_present(filename)
}

/// Validate filename has no double extension (strict)
pub fn validate_no_double_extension(filename: &str) -> ValidationResult {
    if detection::is_double_extension_present(filename) {
        return Err(Problem::validation(
            "Filename has multiple extensions which can hide true file type",
        ));
    }
    Ok(())
}

// ============================================================================
// Length Validation
// ============================================================================

/// Check if filename is not empty (lenient)
#[must_use]
pub fn is_not_empty(filename: &str) -> bool {
    !detection::is_empty(filename)
}

/// Validate filename is not empty (strict)
pub fn validate_not_empty(filename: &str) -> ValidationResult {
    if detection::is_empty(filename) {
        return Err(Problem::validation("Filename cannot be empty"));
    }
    Ok(())
}

/// Check if filename is within length limit (lenient)
#[must_use]
pub fn is_within_length(filename: &str, max_length: usize) -> bool {
    !detection::exceeds_length(filename, max_length)
}

/// Validate filename is within length limit (strict)
pub fn validate_within_length(filename: &str, max_length: usize) -> ValidationResult {
    if detection::exceeds_length(filename, max_length) {
        return Err(Problem::validation(format!(
            "Filename exceeds maximum length of {} characters (actual: {})",
            max_length,
            filename.len()
        )));
    }
    Ok(())
}

/// Check if filename has valid length (lenient)
#[must_use]
pub fn is_length_valid(filename: &str) -> bool {
    !detection::is_empty(filename) && !detection::exceeds_length(filename, DEFAULT_MAX_LENGTH)
}

/// Validate filename has valid length (strict)
pub fn validate_length(filename: &str) -> ValidationResult {
    validate_not_empty(filename)?;
    validate_within_length(filename, DEFAULT_MAX_LENGTH)
}

// ============================================================================
// Unicode Validation
// ============================================================================

/// Check if filename is ASCII only (lenient)
#[must_use]
pub fn is_ascii_only(filename: &str) -> bool {
    !detection::is_non_ascii_present(filename)
}

/// Validate filename is ASCII only (strict)
pub fn validate_ascii_only(filename: &str) -> ValidationResult {
    if detection::is_non_ascii_present(filename) {
        return Err(Problem::validation(
            "Filename contains non-ASCII characters",
        ));
    }
    Ok(())
}

/// Check if filename has no Unicode homoglyphs (lenient)
#[must_use]
pub fn is_homoglyphs_absent(filename: &str) -> bool {
    !detection::is_homoglyphs_present(filename)
}

/// Validate filename has no Unicode homoglyphs (strict)
pub fn validate_no_homoglyphs(filename: &str) -> ValidationResult {
    if detection::is_homoglyphs_present(filename) {
        return Err(Problem::validation(
            "Filename contains Unicode homoglyphs that could enable spoofing",
        ));
    }
    Ok(())
}

/// Check if filename has no bidirectional control characters (lenient)
#[must_use]
pub fn is_bidi_control_absent(filename: &str) -> bool {
    !detection::is_bidi_control_present(filename)
}

/// Validate filename has no bidirectional control characters (strict)
pub fn validate_no_bidi_control(filename: &str) -> ValidationResult {
    if detection::is_bidi_control_present(filename) {
        return Err(Problem::validation(
            "Filename contains bidirectional control characters that could hide true name",
        ));
    }
    Ok(())
}

// ============================================================================
// Pattern Validation
// ============================================================================

/// Check if filename matches pattern (lenient)
#[must_use]
pub fn is_pattern_found(filename: &str, pattern: &str) -> bool {
    detection::is_pattern_found(filename, pattern)
}

/// Validate filename matches pattern (strict)
pub fn validate_pattern_found(filename: &str, pattern: &str) -> ValidationResult {
    if !detection::is_pattern_found(filename, pattern) {
        return Err(Problem::validation(format!(
            "Filename '{}' does not match required pattern '{}'",
            filename, pattern
        )));
    }
    Ok(())
}

// ============================================================================
// Composite Validation Functions
// ============================================================================

/// Check if filename is safe for filesystem use (lenient)
///
/// Comprehensive check for filesystem safety:
/// - Valid (no null bytes, control chars, path separators)
/// - Not a reserved Windows name
/// - Valid length
/// - No bidirectional control characters
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::validation;
///
/// assert!(validation::is_safe("file.txt"));
/// assert!(!validation::is_safe("CON"));
/// assert!(!validation::is_safe("../file.txt"));
/// ```
#[must_use]
pub fn is_safe(filename: &str) -> bool {
    is_valid(filename)
        && is_not_reserved_name(filename)
        && is_length_valid(filename)
        && is_bidi_control_absent(filename)
}

/// Validate filename is safe for filesystem use (strict)
///
/// Comprehensive validation for filesystem safety.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::validation;
///
/// assert!(validation::validate_safe_strict("file.txt").is_ok());
///
/// let err = validation::validate_safe_strict("CON").expect_err("test");
/// assert!(err.to_string().contains("reserved"));
/// ```
pub fn validate_safe_strict(filename: &str) -> ValidationResult {
    validate_strict(filename)?;
    validate_not_reserved_name(filename)?;
    validate_length(filename)?;
    validate_no_bidi_control(filename)?;
    Ok(())
}

/// Check if filename is safe for cross-platform use (lenient)
///
/// Most restrictive check for cross-platform compatibility:
/// - Safe for filesystem
/// - No Windows reserved characters
/// - ASCII only (safest for all filesystems)
/// - No homoglyphs
#[must_use]
pub fn is_cross_platform_safe(filename: &str) -> bool {
    is_safe(filename)
        && is_reserved_windows_chars_absent(filename)
        && is_ascii_only(filename)
        && is_homoglyphs_absent(filename)
}

/// Validate filename is safe for cross-platform use (strict)
pub fn validate_cross_platform_strict(filename: &str) -> ValidationResult {
    validate_safe_strict(filename)?;
    validate_no_reserved_windows_chars(filename)?;
    validate_ascii_only(filename)?;
    validate_no_homoglyphs(filename)?;
    Ok(())
}

/// Check if filename is safe for shell use (lenient)
///
/// Checks for shell injection safety:
/// - Valid filename
/// - No shell metacharacters
/// - No command injection
/// - No variable expansion
#[must_use]
pub fn is_shell_safe(filename: &str) -> bool {
    is_valid(filename) && is_injection_absent(filename)
}

/// Validate filename is safe for shell use (strict)
pub fn validate_shell_safe_strict(filename: &str) -> ValidationResult {
    validate_strict(filename)?;
    validate_no_injection(filename)?;
    Ok(())
}

/// Check if filename is safe for user uploads (lenient)
///
/// Most restrictive check for untrusted input:
/// - Cross-platform safe
/// - No dangerous extensions
/// - No double extensions
/// - Shell safe
#[must_use]
pub fn is_upload_safe(filename: &str) -> bool {
    is_cross_platform_safe(filename)
        && is_extension_safe(filename)
        && is_double_extension_absent(filename)
        && is_shell_safe(filename)
}

/// Validate filename is safe for user uploads (strict)
pub fn validate_upload_safe_strict(filename: &str) -> ValidationResult {
    validate_cross_platform_strict(filename)?;
    validate_safe_extension(filename)?;
    validate_no_double_extension(filename)?;
    validate_shell_safe_strict(filename)?;
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Core Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_valid() {
        // Valid filenames
        assert!(is_valid("file.txt"));
        assert!(is_valid("file-name_123.txt"));
        assert!(is_valid(".gitignore"));
        assert!(is_valid("名前.txt")); // Unicode is valid at base level

        // Invalid filenames
        assert!(!is_valid(""));
        assert!(!is_valid("file\0.txt"));
        assert!(!is_valid("file\n.txt"));
        assert!(!is_valid("foo/bar.txt"));
        assert!(!is_valid("foo\\bar.txt"));
        assert!(!is_valid("."));
        assert!(!is_valid(".."));
        assert!(!is_valid("$(cmd).txt"));
    }

    #[test]
    fn test_validate_strict() {
        assert!(validate_strict("file.txt").is_ok());

        let err = validate_strict("").expect_err("test");
        assert!(err.to_string().contains("empty"));

        let err = validate_strict("file\0.txt").expect_err("test");
        assert!(err.to_string().contains("null"));

        let err = validate_strict("foo/bar").expect_err("test");
        assert!(err.to_string().contains("path separator"));
    }

    // ------------------------------------------------------------------------
    // Character Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_null_byte_validation() {
        assert!(is_null_bytes_absent("file.txt"));
        assert!(!is_null_bytes_absent("file\0.txt"));

        assert!(validate_no_null_bytes("file.txt").is_ok());
        assert!(validate_no_null_bytes("file\0.txt").is_err());
    }

    #[test]
    fn test_control_character_validation() {
        assert!(is_control_characters_absent("file.txt"));
        assert!(!is_control_characters_absent("file\n.txt"));

        assert!(validate_no_control_characters("file.txt").is_ok());
        assert!(validate_no_control_characters("file\r.txt").is_err());
    }

    #[test]
    fn test_shell_char_validation() {
        assert!(is_shell_chars_absent("file.txt"));
        assert!(!is_shell_chars_absent("file;rm.txt"));

        assert!(validate_no_shell_chars("file.txt").is_ok());
        assert!(validate_no_shell_chars("file|cat.txt").is_err());
    }

    // ------------------------------------------------------------------------
    // Path Separator Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_path_separator_validation() {
        assert!(is_path_separators_absent("file.txt"));
        assert!(!is_path_separators_absent("foo/bar.txt"));
        assert!(!is_path_separators_absent("foo\\bar.txt"));

        assert!(validate_no_path_separators("file.txt").is_ok());
        assert!(validate_no_path_separators("foo/bar.txt").is_err());
    }

    #[test]
    fn test_directory_ref_validation() {
        assert!(is_not_directory_ref("file.txt"));
        assert!(is_not_directory_ref(".gitignore"));
        assert!(!is_not_directory_ref("."));
        assert!(!is_not_directory_ref(".."));

        assert!(validate_not_directory_ref("file.txt").is_ok());
        assert!(validate_not_directory_ref(".").is_err());
    }

    // ------------------------------------------------------------------------
    // Command Injection Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_command_injection_validation() {
        assert!(is_command_injection_absent("file.txt"));
        assert!(!is_command_injection_absent("$(cmd).txt"));
        assert!(!is_command_injection_absent("$HOME.txt"));

        assert!(validate_no_command_injection("file.txt").is_ok());
        assert!(validate_no_command_injection("$(cmd).txt").is_err());
        assert!(validate_no_command_injection("$VAR.txt").is_err());
    }

    #[test]
    fn test_injection_validation() {
        assert!(is_injection_absent("file.txt"));
        assert!(!is_injection_absent("$(cmd).txt"));
        assert!(!is_injection_absent("$VAR.txt"));
        assert!(!is_injection_absent("file;rm.txt"));

        assert!(validate_no_injection("file.txt").is_ok());
        assert!(validate_no_injection("file|cat.txt").is_err());
    }

    // ------------------------------------------------------------------------
    // Reserved Name Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_reserved_name_validation() {
        assert!(is_not_reserved_name("file.txt"));
        assert!(!is_not_reserved_name("CON"));
        assert!(!is_not_reserved_name("con"));
        assert!(!is_not_reserved_name("NUL.txt"));

        assert!(validate_not_reserved_name("file.txt").is_ok());
        let err = validate_not_reserved_name("CON").expect_err("test");
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn test_reserved_windows_chars_validation() {
        assert!(is_reserved_windows_chars_absent("file.txt"));
        assert!(!is_reserved_windows_chars_absent("file<name>.txt"));

        assert!(validate_no_reserved_windows_chars("file.txt").is_ok());
        assert!(validate_no_reserved_windows_chars("file:stream.txt").is_err());
    }

    // ------------------------------------------------------------------------
    // Extension Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_safe_extension_validation() {
        assert!(is_extension_safe("file.txt"));
        assert!(is_extension_safe("file.pdf"));
        assert!(!is_extension_safe("file.exe"));
        assert!(!is_extension_safe("file.bat"));

        assert!(validate_safe_extension("file.txt").is_ok());
        let err = validate_safe_extension("file.exe").expect_err("test");
        assert!(err.to_string().contains("dangerous"));
    }

    #[test]
    fn test_allowed_extension_validation() {
        let allowed = &["txt", "pdf", "doc"];

        assert!(is_extension_allowed("file.txt", allowed));
        assert!(is_extension_allowed("file.TXT", allowed));
        assert!(!is_extension_allowed("file.exe", allowed));

        assert!(validate_allowed_extension("file.pdf", allowed).is_ok());
        let err = validate_allowed_extension("file.exe", allowed).expect_err("test");
        assert!(err.to_string().contains("not in allowed"));
    }

    #[test]
    fn test_double_extension_validation() {
        assert!(is_double_extension_absent("file.txt"));
        assert!(!is_double_extension_absent("file.txt.exe"));

        assert!(validate_no_double_extension("file.txt").is_ok());
        let err = validate_no_double_extension("file.txt.exe").expect_err("test");
        assert!(err.to_string().contains("multiple extensions"));
    }

    // ------------------------------------------------------------------------
    // Length Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_empty_validation() {
        assert!(is_not_empty("file.txt"));
        assert!(!is_not_empty(""));

        assert!(validate_not_empty("file.txt").is_ok());
        assert!(validate_not_empty("").is_err());
    }

    #[test]
    fn test_length_validation() {
        assert!(is_within_length("file.txt", 100));
        assert!(!is_within_length("file.txt", 5));

        assert!(validate_within_length("file.txt", 100).is_ok());
        let err = validate_within_length("file.txt", 5).expect_err("test");
        assert!(err.to_string().contains("exceeds"));

        assert!(is_length_valid("file.txt"));
        assert!(!is_length_valid(""));
    }

    // ------------------------------------------------------------------------
    // Unicode Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ascii_only_validation() {
        assert!(is_ascii_only("file.txt"));
        assert!(!is_ascii_only("文件.txt"));
        assert!(!is_ascii_only("café.txt"));

        assert!(validate_ascii_only("file.txt").is_ok());
        assert!(validate_ascii_only("名前.txt").is_err());
    }

    #[test]
    fn test_homoglyph_validation() {
        assert!(is_homoglyphs_absent("file.txt"));
        // Cyrillic 'а' (U+0430)
        assert!(!is_homoglyphs_absent("p\u{0430}ypal.txt"));

        assert!(validate_no_homoglyphs("file.txt").is_ok());
        assert!(validate_no_homoglyphs("p\u{0430}ypal.txt").is_err());
    }

    #[test]
    fn test_bidi_control_validation() {
        assert!(is_bidi_control_absent("file.txt"));
        assert!(!is_bidi_control_absent("file\u{202E}.txt"));

        assert!(validate_no_bidi_control("file.txt").is_ok());
        assert!(validate_no_bidi_control("file\u{202E}.txt").is_err());
    }

    // ------------------------------------------------------------------------
    // Pattern Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_pattern_validation() {
        assert!(is_pattern_found("file.txt", "*.txt"));
        assert!(!is_pattern_found("file.pdf", "*.txt"));

        assert!(validate_pattern_found("file.txt", "*.txt").is_ok());
        let err = validate_pattern_found("file.pdf", "*.txt").expect_err("test");
        assert!(err.to_string().contains("does not match"));
    }

    // ------------------------------------------------------------------------
    // Composite Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_safe() {
        assert!(is_safe("file.txt"));
        assert!(is_safe("file-name_123.txt"));
        assert!(!is_safe("")); // empty
        assert!(!is_safe("CON")); // reserved
        assert!(!is_safe("../file.txt")); // path separator
        assert!(!is_safe("file\u{202E}.txt")); // bidi
    }

    #[test]
    fn test_validate_safe_strict() {
        assert!(validate_safe_strict("file.txt").is_ok());

        assert!(validate_safe_strict("CON").is_err());
        assert!(validate_safe_strict("").is_err());
    }

    #[test]
    fn test_is_cross_platform_safe() {
        assert!(is_cross_platform_safe("file.txt"));
        assert!(is_cross_platform_safe("file-name_123.txt"));
        assert!(!is_cross_platform_safe("file<name>.txt")); // Windows reserved char
        assert!(!is_cross_platform_safe("文件.txt")); // non-ASCII
        assert!(!is_cross_platform_safe("p\u{0430}ypal.txt")); // homoglyph
    }

    #[test]
    fn test_is_shell_safe() {
        assert!(is_shell_safe("file.txt"));
        assert!(is_shell_safe("file-name_123.txt"));
        assert!(!is_shell_safe("$(cmd).txt"));
        assert!(!is_shell_safe("file;rm.txt"));
        assert!(!is_shell_safe("$VAR.txt"));
    }

    #[test]
    fn test_is_upload_safe() {
        assert!(is_upload_safe("file.txt"));
        assert!(is_upload_safe("document.pdf"));
        assert!(!is_upload_safe("file.exe")); // dangerous extension
        assert!(!is_upload_safe("file.txt.exe")); // double extension
        assert!(!is_upload_safe("$(cmd).txt")); // injection
        assert!(!is_upload_safe("文件.txt")); // non-ASCII
    }

    #[test]
    fn test_validate_upload_safe_strict() {
        assert!(validate_upload_safe_strict("file.txt").is_ok());
        assert!(validate_upload_safe_strict("report-2024.pdf").is_ok());

        assert!(validate_upload_safe_strict("file.exe").is_err());
        assert!(validate_upload_safe_strict("file.txt.exe").is_err());
        assert!(validate_upload_safe_strict("$(cmd).txt").is_err());
    }
}
