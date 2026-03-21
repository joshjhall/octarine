//! Builder API for filename operations
//!
//! Provides a fluent builder interface for filename detection, validation,
//! sanitization, and construction operations.
//!
//! ## Example
//!
//! ```ignore
//! use octarine::primitives::paths::filename::FilenameBuilder;
//!
//! let fb = FilenameBuilder::new();
//!
//! // Detection
//! assert!(fb.is_extension_present("file.txt"));
//! assert!(fb.is_threat_present("$(cmd).txt"));
//!
//! // Validation
//! assert!(fb.is_valid("file.txt"));
//! assert!(fb.validate_filename("file.txt").is_ok());
//!
//! // Sanitization
//! let clean = fb.sanitize("../file;rm.txt").expect("test");
//! assert!(!clean.contains(".."));
//!
//! // Construction
//! let new_name = fb.set_extension("file.txt", "pdf");
//! assert_eq!(new_name, "file.pdf");
//! ```

// Allow from_* naming convention - these are construction methods via builder, not conversions
#![allow(clippy::wrong_self_convention)]

use std::borrow::Cow;

use super::{construction, detection, sanitization, validation};
use crate::primitives::types::Problem;

/// Builder for filename operations
///
/// Provides a unified API for all filename-related operations:
/// detection, validation, sanitization, and construction.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::FilenameBuilder;
///
/// let fb = FilenameBuilder::new();
///
/// // Quick checks
/// if fb.is_valid(user_input) && fb.has_safe_extension(user_input) {
///     let safe_name = fb.sanitize(user_input).expect("test");
///     // Use safe_name
/// }
/// # let user_input = "safe.txt";
/// ```
#[derive(Debug, Clone, Default)]
pub struct FilenameBuilder;

impl FilenameBuilder {
    /// Create a new filename builder
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::filename::FilenameBuilder;
    ///
    /// let fb = FilenameBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Check if filename has any security threat
    #[must_use]
    pub fn is_threat_present(&self, filename: &str) -> bool {
        detection::is_threat_present(filename)
    }

    /// Detect all security issues in a filename
    #[must_use]
    pub fn detect_issues(&self, filename: &str) -> Vec<&'static str> {
        detection::detect_all_issues(filename)
    }

    /// Check if filename has path separators
    #[must_use]
    pub fn is_path_separators_present(&self, filename: &str) -> bool {
        detection::is_path_separators_present(filename)
    }

    /// Check if filename has null bytes
    #[must_use]
    pub fn is_null_bytes_present(&self, filename: &str) -> bool {
        detection::is_null_bytes_present(filename)
    }

    /// Check if filename has control characters
    #[must_use]
    pub fn is_control_characters_present(&self, filename: &str) -> bool {
        detection::is_control_characters_present(filename)
    }

    /// Check if filename has dangerous shell characters
    #[must_use]
    pub fn is_shell_chars_present(&self, filename: &str) -> bool {
        detection::is_dangerous_shell_chars_present(filename)
    }

    /// Check if filename has command substitution patterns
    #[must_use]
    pub fn is_command_substitution_present(&self, filename: &str) -> bool {
        detection::is_command_substitution_present(filename)
    }

    /// Check if filename has variable expansion patterns
    #[must_use]
    pub fn is_variable_expansion_present(&self, filename: &str) -> bool {
        detection::is_variable_expansion_present(filename)
    }

    /// Check if filename has any injection pattern
    #[must_use]
    pub fn is_injection_present(&self, filename: &str) -> bool {
        detection::is_injection_pattern_present(filename)
    }

    /// Check if filename is a Windows reserved name
    #[must_use]
    pub fn is_reserved_name(&self, filename: &str) -> bool {
        detection::is_reserved_name(filename)
    }

    /// Check if filename is a dot file (hidden)
    #[must_use]
    pub fn is_dot_file(&self, filename: &str) -> bool {
        detection::is_dot_file(filename)
    }

    /// Check if filename is a directory reference (. or ..)
    #[must_use]
    pub fn is_directory_ref(&self, filename: &str) -> bool {
        detection::is_directory_ref(filename)
    }

    /// Check if filename has an extension
    #[must_use]
    pub fn is_extension_present(&self, filename: &str) -> bool {
        detection::is_extension_present(filename)
    }

    /// Find the extension of a filename
    #[must_use]
    pub fn find_extension<'a>(&self, filename: &'a str) -> Option<&'a str> {
        detection::find_extension(filename)
    }

    /// Get the stem of a filename
    #[must_use]
    pub fn stem<'a>(&self, filename: &'a str) -> &'a str {
        detection::stem(filename)
    }

    /// Check if filename has double extension
    #[must_use]
    pub fn is_double_extension_present(&self, filename: &str) -> bool {
        detection::is_double_extension_present(filename)
    }

    /// Check if filename has dangerous extension
    #[must_use]
    pub fn is_dangerous_extension_present(&self, filename: &str) -> bool {
        detection::is_dangerous_extension_present(filename)
    }

    /// Check if extension matches expected value
    #[must_use]
    pub fn is_extension_found(&self, filename: &str, expected: &str) -> bool {
        detection::is_extension_found(filename, expected)
    }

    /// Check if extension is in allowed list
    #[must_use]
    pub fn is_extension_in_list(&self, filename: &str, allowed: &[&str]) -> bool {
        detection::is_extension_in_list(filename, allowed)
    }

    /// Check if filename has non-ASCII characters
    #[must_use]
    pub fn is_non_ascii_present(&self, filename: &str) -> bool {
        detection::is_non_ascii_present(filename)
    }

    /// Check if filename has Unicode homoglyphs
    #[must_use]
    pub fn is_homoglyphs_present(&self, filename: &str) -> bool {
        detection::is_homoglyphs_present(filename)
    }

    /// Check if filename has bidirectional control characters
    #[must_use]
    pub fn is_bidi_control_present(&self, filename: &str) -> bool {
        detection::is_bidi_control_present(filename)
    }

    /// Check if filename matches pattern
    #[must_use]
    pub fn is_pattern_found(&self, filename: &str, pattern: &str) -> bool {
        detection::is_pattern_found(filename, pattern)
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Check if filename is valid (lenient)
    #[must_use]
    pub fn is_valid(&self, filename: &str) -> bool {
        validation::is_valid(filename)
    }

    /// Validate filename
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_filename(&self, filename: &str) -> Result<(), Problem> {
        validation::validate_strict(filename)
    }

    /// Check if filename is safe for filesystem use
    #[must_use]
    pub fn is_safe(&self, filename: &str) -> bool {
        validation::is_safe(filename)
    }

    /// Validate filename is safe for filesystem use
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_safe(&self, filename: &str) -> Result<(), Problem> {
        validation::validate_safe_strict(filename)
    }

    /// Check if filename is cross-platform safe
    #[must_use]
    pub fn is_cross_platform_safe(&self, filename: &str) -> bool {
        validation::is_cross_platform_safe(filename)
    }

    /// Validate filename is cross-platform safe
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_cross_platform(&self, filename: &str) -> Result<(), Problem> {
        validation::validate_cross_platform_strict(filename)
    }

    /// Check if filename is shell safe
    #[must_use]
    pub fn is_shell_safe(&self, filename: &str) -> bool {
        validation::is_shell_safe(filename)
    }

    /// Validate filename is shell safe
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_shell_safe(&self, filename: &str) -> Result<(), Problem> {
        validation::validate_shell_safe_strict(filename)
    }

    /// Check if filename is safe for uploads
    #[must_use]
    pub fn is_upload_safe(&self, filename: &str) -> bool {
        validation::is_upload_safe(filename)
    }

    /// Validate filename is safe for uploads
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_upload_safe(&self, filename: &str) -> Result<(), Problem> {
        validation::validate_upload_safe_strict(filename)
    }

    /// Check if filename has safe extension
    #[must_use]
    pub fn is_extension_safe(&self, filename: &str) -> bool {
        validation::is_extension_safe(filename)
    }

    /// Check if filename has allowed extension
    #[must_use]
    pub fn is_extension_allowed(&self, filename: &str, allowed: &[&str]) -> bool {
        validation::is_extension_allowed(filename, allowed)
    }

    /// Validate extension is in allowed list
    pub fn validate_allowed_extension(
        &self,
        filename: &str,
        allowed: &[&str],
    ) -> Result<(), Problem> {
        validation::validate_allowed_extension(filename, allowed)
    }

    /// Check if filename is within length limit
    #[must_use]
    pub fn is_within_length(&self, filename: &str, max_length: usize) -> bool {
        validation::is_within_length(filename, max_length)
    }

    /// Validate filename is within length limit
    pub fn validate_within_length(&self, filename: &str, max_length: usize) -> Result<(), Problem> {
        validation::validate_within_length(filename, max_length)
    }

    // ========================================================================
    // Sanitization Methods
    // ========================================================================

    /// Sanitize filename (lenient)
    pub fn sanitize(&self, filename: &str) -> Result<String, Problem> {
        sanitization::sanitize(filename)
    }

    /// Sanitize filename (strict)
    pub fn sanitize_strict(&self, filename: &str) -> Result<String, Problem> {
        sanitization::sanitize_strict(filename)
    }

    /// Sanitize filename with specific context
    pub fn sanitize_with_context(
        &self,
        filename: &str,
        context: sanitization::SanitizationContext,
    ) -> Result<String, Problem> {
        sanitization::sanitize_with_context(filename, context)
    }

    /// Strip null bytes from filename
    #[must_use]
    pub fn strip_null_bytes<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::strip_null_bytes(filename)
    }

    /// Strip control characters from filename
    #[must_use]
    pub fn strip_control_chars<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::strip_control_chars(filename)
    }

    /// Strip path separators from filename
    #[must_use]
    pub fn strip_path_separators<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::strip_path_separators(filename)
    }

    /// Strip shell metacharacters from filename
    #[must_use]
    pub fn strip_shell_chars<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::strip_shell_chars(filename)
    }

    /// Replace spaces with underscores
    #[must_use]
    pub fn replace_spaces<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::replace_spaces(filename)
    }

    /// Replace spaces with hyphens
    #[must_use]
    pub fn replace_spaces_with_hyphens<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::replace_spaces_with_hyphens(filename)
    }

    /// Shell escape filename
    #[must_use]
    pub fn shell_escape(&self, filename: &str) -> String {
        sanitization::shell_escape(filename)
    }

    /// Shell escape filename (strict)
    pub fn shell_escape_strict(&self, filename: &str) -> Result<String, Problem> {
        sanitization::shell_escape_strict(filename)
    }

    /// Normalize filename case
    #[must_use]
    pub fn normalize_case<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::normalize_case(filename)
    }

    /// Normalize extension case
    #[must_use]
    pub fn normalize_extension<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        sanitization::normalize_extension(filename)
    }

    /// Generate safe filename from any input
    #[must_use]
    pub fn to_safe_filename(&self, filename: &str) -> String {
        sanitization::to_safe_filename(filename)
    }

    /// Generate safe filename with fallback
    #[must_use]
    pub fn to_safe_filename_or(&self, filename: &str, fallback: &str) -> String {
        sanitization::to_safe_filename_or(filename, fallback)
    }

    // ========================================================================
    // Construction Methods
    // ========================================================================

    /// Set extension of filename
    #[must_use]
    pub fn set_extension(&self, filename: &str, extension: &str) -> String {
        construction::set_extension(filename, extension)
    }

    /// Set extension of filename (strict)
    pub fn set_extension_strict(&self, filename: &str, extension: &str) -> Result<String, Problem> {
        construction::set_extension_strict(filename, extension)
    }

    /// Add extension to filename
    #[must_use]
    pub fn add_extension(&self, filename: &str, extension: &str) -> String {
        construction::add_extension(filename, extension)
    }

    /// Add extension to filename (strict)
    pub fn add_extension_strict(&self, filename: &str, extension: &str) -> Result<String, Problem> {
        construction::add_extension_strict(filename, extension)
    }

    /// Strip extension from filename
    #[must_use]
    pub fn strip_extension(&self, filename: &str) -> String {
        construction::strip_extension(filename)
    }

    /// Strip extension from filename (strict)
    pub fn strip_extension_strict(&self, filename: &str) -> Result<String, Problem> {
        construction::strip_extension_strict(filename)
    }

    /// Strip all extensions from filename
    #[must_use]
    pub fn strip_all_extensions(&self, filename: &str) -> String {
        construction::strip_all_extensions(filename)
    }

    /// Replace stem of filename
    #[must_use]
    pub fn with_stem(&self, filename: &str, new_stem: &str) -> String {
        construction::with_stem(filename, new_stem)
    }

    /// Replace stem of filename (strict)
    pub fn with_stem_strict(&self, filename: &str, new_stem: &str) -> Result<String, Problem> {
        construction::with_stem_strict(filename, new_stem)
    }

    /// Construct filename from parts
    #[must_use]
    pub fn from_parts(&self, stem: &str, extension: &str) -> String {
        construction::from_parts(stem, extension)
    }

    /// Construct filename from parts (strict)
    pub fn from_parts_strict(&self, stem: &str, extension: &str) -> Result<String, Problem> {
        construction::from_parts_strict(stem, extension)
    }

    /// Append suffix to stem
    #[must_use]
    pub fn append_to_stem(&self, filename: &str, suffix: &str) -> String {
        construction::append_to_stem(filename, suffix)
    }

    /// Append suffix to stem (strict)
    pub fn append_to_stem_strict(&self, filename: &str, suffix: &str) -> Result<String, Problem> {
        construction::append_to_stem_strict(filename, suffix)
    }

    /// Add number suffix to filename
    #[must_use]
    pub fn with_number(&self, filename: &str, number: u32) -> String {
        construction::with_number(filename, number)
    }

    /// Add zero-padded number suffix to filename
    #[must_use]
    pub fn with_padded_number(&self, filename: &str, number: u32, width: usize) -> String {
        construction::with_padded_number(filename, number, width)
    }

    /// Generate timestamp-based filename
    #[must_use]
    pub fn with_timestamp(&self, prefix: &str, extension: &str) -> String {
        construction::with_timestamp(prefix, extension)
    }

    /// Generate UUID-based filename
    #[must_use]
    pub fn with_uuid(&self, prefix: &str, extension: &str) -> String {
        construction::with_uuid(prefix, extension)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> FilenameBuilder {
        FilenameBuilder::new()
    }

    // ------------------------------------------------------------------------
    // Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detection_methods() {
        let fb = builder();

        assert!(fb.is_threat_present("$(cmd).txt"));
        assert!(!fb.is_threat_present("file.txt"));

        assert!(fb.is_path_separators_present("foo/bar.txt"));
        assert!(!fb.is_path_separators_present("file.txt"));

        assert!(fb.is_null_bytes_present("file\0.txt"));
        assert!(fb.is_control_characters_present("file\n.txt"));
        assert!(fb.is_shell_chars_present("file;rm.txt"));

        assert!(fb.is_command_substitution_present("$(cmd).txt"));
        assert!(fb.is_variable_expansion_present("$HOME.txt"));
        assert!(fb.is_injection_present("file;rm.txt"));

        assert!(fb.is_reserved_name("CON"));
        assert!(fb.is_dot_file(".gitignore"));
        assert!(fb.is_directory_ref(".."));
    }

    #[test]
    fn test_extension_detection() {
        let fb = builder();

        assert!(fb.is_extension_present("file.txt"));
        assert!(!fb.is_extension_present("file"));

        assert_eq!(fb.find_extension("file.txt"), Some("txt"));
        assert_eq!(fb.stem("file.txt"), "file");

        assert!(fb.is_double_extension_present("file.txt.exe"));
        assert!(fb.is_dangerous_extension_present("file.exe"));

        assert!(fb.is_extension_found("file.TXT", "txt"));
        assert!(fb.is_extension_in_list("file.txt", &["txt", "pdf"]));
    }

    #[test]
    fn test_unicode_detection() {
        let fb = builder();

        assert!(fb.is_non_ascii_present("文件.txt"));
        assert!(fb.is_homoglyphs_present("p\u{0430}ypal.txt"));
        assert!(fb.is_bidi_control_present("file\u{202E}.txt"));
    }

    #[test]
    fn test_pattern_matching() {
        let fb = builder();

        assert!(fb.is_pattern_found("file.txt", "*.txt"));
        assert!(fb.is_pattern_found("file123.txt", "file???.txt"));
        assert!(!fb.is_pattern_found("file.pdf", "*.txt"));
    }

    // ------------------------------------------------------------------------
    // Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validation_methods() {
        let fb = builder();

        assert!(fb.is_valid("file.txt"));
        assert!(!fb.is_valid("../file.txt"));

        assert!(fb.validate_filename("file.txt").is_ok());
        assert!(fb.validate_filename("../file.txt").is_err());

        assert!(fb.is_safe("file.txt"));
        assert!(!fb.is_safe("CON"));

        assert!(fb.is_cross_platform_safe("file.txt"));
        assert!(!fb.is_cross_platform_safe("文件.txt"));

        assert!(fb.is_shell_safe("file.txt"));
        assert!(!fb.is_shell_safe("file;rm.txt"));

        assert!(fb.is_upload_safe("file.txt"));
        assert!(!fb.is_upload_safe("file.exe"));
    }

    #[test]
    fn test_extension_validation() {
        let fb = builder();

        assert!(fb.is_extension_safe("file.txt"));
        assert!(!fb.is_extension_safe("file.exe"));

        let allowed = &["txt", "pdf"];
        assert!(fb.is_extension_allowed("file.txt", allowed));
        assert!(!fb.is_extension_allowed("file.exe", allowed));

        assert!(fb.validate_allowed_extension("file.txt", allowed).is_ok());
    }

    #[test]
    fn test_length_validation() {
        let fb = builder();

        assert!(fb.is_within_length("file.txt", 100));
        assert!(!fb.is_within_length("file.txt", 5));

        assert!(fb.validate_within_length("file.txt", 100).is_ok());
        assert!(fb.validate_within_length("file.txt", 5).is_err());
    }

    // ------------------------------------------------------------------------
    // Sanitization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitization_methods() {
        let fb = builder();

        assert_eq!(fb.sanitize("file\0.txt").expect("test"), "file.txt");
        assert!(fb.sanitize_strict("file.txt").is_ok());
        assert!(fb.sanitize_strict("../file.txt").is_err());

        assert_eq!(fb.strip_null_bytes("file\0.txt").as_ref(), "file.txt");
        assert_eq!(fb.strip_control_chars("file\n.txt").as_ref(), "file.txt");
        assert_eq!(
            fb.strip_path_separators("foo/bar.txt").as_ref(),
            "foobar.txt"
        );
        assert_eq!(fb.strip_shell_chars("file;rm.txt").as_ref(), "filerm.txt");
    }

    #[test]
    fn test_space_replacement() {
        let fb = builder();

        assert_eq!(fb.replace_spaces("my file.txt").as_ref(), "my_file.txt");
        assert_eq!(
            fb.replace_spaces_with_hyphens("my file.txt").as_ref(),
            "my-file.txt"
        );
    }

    #[test]
    fn test_shell_escape() {
        let fb = builder();

        assert_eq!(fb.shell_escape("file.txt"), "'file.txt'");
        assert_eq!(fb.shell_escape("file's.txt"), "'file'\\''s.txt'");

        assert!(fb.shell_escape_strict("file.txt").is_ok());
        assert!(fb.shell_escape_strict("file\0.txt").is_err());
    }

    #[test]
    fn test_normalization() {
        let fb = builder();

        assert_eq!(fb.normalize_case("FILE.TXT").as_ref(), "file.txt");
        assert_eq!(fb.normalize_extension("file.TXT").as_ref(), "file.txt");
    }

    #[test]
    fn test_safe_filename_generation() {
        let fb = builder();

        assert_eq!(fb.to_safe_filename("file.txt"), "file.txt");
        assert_eq!(fb.to_safe_filename(""), "unnamed");
        assert_eq!(fb.to_safe_filename_or("", "default.txt"), "default.txt");
    }

    // ------------------------------------------------------------------------
    // Construction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_extension_manipulation() {
        let fb = builder();

        assert_eq!(fb.set_extension("file.txt", "pdf"), "file.pdf");
        assert_eq!(fb.add_extension("file.txt", "gz"), "file.txt.gz");
        assert_eq!(fb.strip_extension("file.txt"), "file");
        assert_eq!(fb.strip_all_extensions("file.tar.gz"), "file");
    }

    #[test]
    fn test_stem_manipulation() {
        let fb = builder();

        assert_eq!(fb.with_stem("file.txt", "document"), "document.txt");
        assert!(fb.with_stem_strict("file.txt", "document").is_ok());
        assert!(fb.with_stem_strict("file.txt", "../hack").is_err());
    }

    #[test]
    fn test_parts_construction() {
        let fb = builder();

        assert_eq!(fb.from_parts("file", "txt"), "file.txt");
        assert!(fb.from_parts_strict("file", "txt").is_ok());
        assert!(fb.from_parts_strict("file", "exe").is_err());
    }

    #[test]
    fn test_suffix_operations() {
        let fb = builder();

        assert_eq!(fb.append_to_stem("file.txt", "_backup"), "file_backup.txt");
        assert!(fb.append_to_stem_strict("file.txt", "_backup").is_ok());
    }

    #[test]
    fn test_numbered_filenames() {
        let fb = builder();

        assert_eq!(fb.with_number("file.txt", 1), "file_1.txt");
        assert_eq!(fb.with_padded_number("file.txt", 1, 3), "file_001.txt");
    }

    #[test]
    fn test_generated_filenames() {
        let fb = builder();

        let ts_name = fb.with_timestamp("log", "txt");
        assert!(ts_name.starts_with("log_"));
        assert!(ts_name.ends_with(".txt"));

        let uuid_name = fb.with_uuid("upload", "jpg");
        assert!(uuid_name.starts_with("upload_"));
        assert!(uuid_name.ends_with(".jpg"));
    }
}
