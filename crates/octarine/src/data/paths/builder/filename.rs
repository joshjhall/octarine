//! Filename operations builder with observability
//!
//! Wraps `primitives::data::paths::FilenameBuilder` with observe instrumentation.
//!
//! Provides detection, validation, sanitization, and construction operations
//! for filenames with full audit trail.
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::FilenameBuilder;
//!
//! let fb = FilenameBuilder::new();
//!
//! // Detection
//! if fb.is_threat_present("$(cmd).txt") {
//!     // Handle threat
//! }
//!
//! // Validation
//! fb.validate_filename("document.pdf").unwrap();
//!
//! // Sanitization
//! let safe = fb.sanitize("../file;rm.txt").unwrap();
//!
//! // Construction
//! let new_name = fb.set_extension("file.txt", "pdf");
//! ```

use std::borrow::Cow;
use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{increment_by, record};
use crate::primitives::data::paths::FilenameBuilder as PrimitiveFilenameBuilder;

// Re-export SanitizationContext from local types module
pub use crate::data::paths::types::SanitizationContext;

crate::define_metrics! {
    threats_detected => "data.paths.filename.threats_detected",
    sanitize_ms => "data.paths.filename.sanitize_ms",
    validated => "data.paths.filename.validated",
}

/// Filename operations builder with observability
///
/// Provides comprehensive filename handling with audit trail.
#[derive(Debug, Clone, Default)]
pub struct FilenameBuilder {
    emit_events: bool,
}

impl FilenameBuilder {
    /// Create a new filename builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Check if filename has any security threat
    #[must_use]
    pub fn is_threat_present(&self, filename: &str) -> bool {
        let result = PrimitiveFilenameBuilder::new().is_threat_present(filename);
        if self.emit_events && result {
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all security issues in a filename
    #[must_use]
    pub fn detect_issues(&self, filename: &str) -> Vec<&'static str> {
        PrimitiveFilenameBuilder::new().detect_issues(filename)
    }

    /// Check if filename has path separators
    #[must_use]
    pub fn is_path_separators_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_path_separators_present(filename)
    }

    /// Check if filename has null bytes
    #[must_use]
    pub fn is_null_bytes_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_null_bytes_present(filename)
    }

    /// Check if filename has control characters
    #[must_use]
    pub fn is_control_characters_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_control_characters_present(filename)
    }

    /// Check if filename has dangerous shell characters
    #[must_use]
    pub fn is_shell_chars_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_shell_chars_present(filename)
    }

    /// Check if filename has command substitution patterns
    #[must_use]
    pub fn is_command_substitution_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_command_substitution_present(filename)
    }

    /// Check if filename has variable expansion patterns
    #[must_use]
    pub fn is_variable_expansion_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_variable_expansion_present(filename)
    }

    /// Check if filename has any injection pattern
    #[must_use]
    pub fn is_injection_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_injection_present(filename)
    }

    /// Check if filename is a Windows reserved name (CON, PRN, etc.)
    #[must_use]
    pub fn is_reserved_name(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_reserved_name(filename)
    }

    /// Check if filename is a dot file (hidden)
    #[must_use]
    pub fn is_dot_file(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_dot_file(filename)
    }

    /// Check if filename is a directory reference (. or ..)
    #[must_use]
    pub fn is_directory_ref(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_directory_ref(filename)
    }

    /// Check if filename has an extension
    #[must_use]
    pub fn is_extension_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_extension_present(filename)
    }

    /// Find the extension of a filename
    #[must_use]
    pub fn find_extension<'a>(&self, filename: &'a str) -> Option<&'a str> {
        PrimitiveFilenameBuilder::new().find_extension(filename)
    }

    /// Get the stem of a filename (without extension)
    #[must_use]
    pub fn stem<'a>(&self, filename: &'a str) -> &'a str {
        PrimitiveFilenameBuilder::new().stem(filename)
    }

    /// Check if filename has double extension (file.txt.exe)
    #[must_use]
    pub fn is_double_extension_present(&self, filename: &str) -> bool {
        let result = PrimitiveFilenameBuilder::new().is_double_extension_present(filename);
        if self.emit_events && result {
            observe::warn("double_extension_detected", "Double extension in filename");
        }
        result
    }

    /// Check if filename has dangerous extension (.exe, .bat, etc.)
    #[must_use]
    pub fn is_dangerous_extension_present(&self, filename: &str) -> bool {
        let result = PrimitiveFilenameBuilder::new().is_dangerous_extension_present(filename);
        if self.emit_events && result {
            observe::warn("dangerous_extension", "Dangerous file extension detected");
        }
        result
    }

    /// Check if extension matches expected value (case-insensitive)
    #[must_use]
    pub fn is_extension_found(&self, filename: &str, expected: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_extension_found(filename, expected)
    }

    /// Check if extension is in allowed list
    #[must_use]
    pub fn is_extension_in_list(&self, filename: &str, allowed: &[&str]) -> bool {
        PrimitiveFilenameBuilder::new().is_extension_in_list(filename, allowed)
    }

    /// Check if filename has non-ASCII characters
    #[must_use]
    pub fn is_non_ascii_present(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_non_ascii_present(filename)
    }

    /// Check if filename has Unicode homoglyphs
    #[must_use]
    pub fn is_homoglyphs_present(&self, filename: &str) -> bool {
        let result = PrimitiveFilenameBuilder::new().is_homoglyphs_present(filename);
        if self.emit_events && result {
            observe::warn("homoglyphs_detected", "Unicode homoglyphs in filename");
        }
        result
    }

    /// Check if filename has bidirectional control characters
    #[must_use]
    pub fn is_bidi_control_present(&self, filename: &str) -> bool {
        let result = PrimitiveFilenameBuilder::new().is_bidi_control_present(filename);
        if self.emit_events && result {
            observe::warn(
                "bidi_control_detected",
                "Bidirectional control chars in filename",
            );
        }
        result
    }

    /// Check if filename matches pattern (glob-style)
    #[must_use]
    pub fn is_pattern_found(&self, filename: &str, pattern: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_pattern_found(filename, pattern)
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Check if filename is valid (lenient)
    #[must_use]
    pub fn is_valid(&self, filename: &str) -> bool {
        let result = PrimitiveFilenameBuilder::new().is_valid(filename);
        if self.emit_events {
            increment_by(metric_names::validated(), 1);
        }
        result
    }

    /// Validate filename
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_filename(&self, filename: &str) -> Result<(), Problem> {
        PrimitiveFilenameBuilder::new().validate_filename(filename)
    }

    /// Check if filename is safe for filesystem use
    #[must_use]
    pub fn is_safe(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_safe(filename)
    }

    /// Validate filename is safe for filesystem use
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_safe(&self, filename: &str) -> Result<(), Problem> {
        PrimitiveFilenameBuilder::new().validate_safe(filename)
    }

    /// Check if filename is cross-platform safe
    #[must_use]
    pub fn is_cross_platform_safe(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_cross_platform_safe(filename)
    }

    /// Validate filename is cross-platform safe
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_cross_platform(&self, filename: &str) -> Result<(), Problem> {
        PrimitiveFilenameBuilder::new().validate_cross_platform(filename)
    }

    /// Check if filename is shell safe
    #[must_use]
    pub fn is_shell_safe(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_shell_safe(filename)
    }

    /// Validate filename is shell safe
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_shell_safe(&self, filename: &str) -> Result<(), Problem> {
        PrimitiveFilenameBuilder::new().validate_shell_safe(filename)
    }

    /// Check if filename is safe for uploads
    #[must_use]
    pub fn is_upload_safe(&self, filename: &str) -> bool {
        let result = PrimitiveFilenameBuilder::new().is_upload_safe(filename);
        if self.emit_events && !result {
            observe::warn("unsafe_upload_filename", "Filename not safe for upload");
        }
        result
    }

    /// Validate filename is safe for uploads
    ///
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    pub fn validate_upload_safe(&self, filename: &str) -> Result<(), Problem> {
        PrimitiveFilenameBuilder::new().validate_upload_safe(filename)
    }

    /// Check if filename has safe extension
    #[must_use]
    pub fn is_extension_safe(&self, filename: &str) -> bool {
        PrimitiveFilenameBuilder::new().is_extension_safe(filename)
    }

    /// Check if filename has allowed extension
    #[must_use]
    pub fn is_extension_allowed(&self, filename: &str, allowed: &[&str]) -> bool {
        PrimitiveFilenameBuilder::new().is_extension_allowed(filename, allowed)
    }

    /// Validate extension is in allowed list
    pub fn validate_allowed_extension(
        &self,
        filename: &str,
        allowed: &[&str],
    ) -> Result<(), Problem> {
        PrimitiveFilenameBuilder::new().validate_allowed_extension(filename, allowed)
    }

    /// Check if filename is within length limit
    #[must_use]
    pub fn is_within_length(&self, filename: &str, max_length: usize) -> bool {
        PrimitiveFilenameBuilder::new().is_within_length(filename, max_length)
    }

    /// Validate filename is within length limit
    pub fn validate_within_length(&self, filename: &str, max_length: usize) -> Result<(), Problem> {
        PrimitiveFilenameBuilder::new().validate_within_length(filename, max_length)
    }

    // ========================================================================
    // Sanitization Methods
    // ========================================================================

    /// Sanitize filename (lenient)
    pub fn sanitize(&self, filename: &str) -> Result<String, Problem> {
        let start = Instant::now();
        let result = PrimitiveFilenameBuilder::new().sanitize(filename);

        if self.emit_events {
            record(
                metric_names::sanitize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    /// Sanitize filename strictly
    pub fn sanitize_strict(&self, filename: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().sanitize_strict(filename)
    }

    /// Sanitize filename with specific context
    pub fn sanitize_with_context(
        &self,
        filename: &str,
        context: SanitizationContext,
    ) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().sanitize_with_context(filename, context.into())
    }

    /// Strip null bytes from filename
    #[must_use]
    pub fn strip_null_bytes<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().strip_null_bytes(filename)
    }

    /// Strip control characters from filename
    #[must_use]
    pub fn strip_control_chars<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().strip_control_chars(filename)
    }

    /// Strip path separators from filename
    #[must_use]
    pub fn strip_path_separators<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().strip_path_separators(filename)
    }

    /// Strip shell metacharacters from filename
    #[must_use]
    pub fn strip_shell_chars<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().strip_shell_chars(filename)
    }

    /// Replace spaces with underscores
    #[must_use]
    pub fn replace_spaces<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().replace_spaces(filename)
    }

    /// Replace spaces with hyphens
    #[must_use]
    pub fn replace_spaces_with_hyphens<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().replace_spaces_with_hyphens(filename)
    }

    /// Shell escape filename
    #[must_use]
    pub fn shell_escape(&self, filename: &str) -> String {
        PrimitiveFilenameBuilder::new().shell_escape(filename)
    }

    /// Shell escape filename strictly
    pub fn shell_escape_strict(&self, filename: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().shell_escape_strict(filename)
    }

    /// Normalize filename case (lowercase)
    #[must_use]
    pub fn normalize_case<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().normalize_case(filename)
    }

    /// Normalize extension case (lowercase)
    #[must_use]
    pub fn normalize_extension<'a>(&self, filename: &'a str) -> Cow<'a, str> {
        PrimitiveFilenameBuilder::new().normalize_extension(filename)
    }

    /// Generate safe filename from any input
    #[must_use]
    pub fn to_safe_filename(&self, filename: &str) -> String {
        PrimitiveFilenameBuilder::new().to_safe_filename(filename)
    }

    /// Generate safe filename with fallback
    #[must_use]
    pub fn to_safe_filename_or(&self, filename: &str, fallback: &str) -> String {
        PrimitiveFilenameBuilder::new().to_safe_filename_or(filename, fallback)
    }

    // ========================================================================
    // Construction Methods
    // ========================================================================

    /// Set extension of filename
    #[must_use]
    pub fn set_extension(&self, filename: &str, extension: &str) -> String {
        PrimitiveFilenameBuilder::new().set_extension(filename, extension)
    }

    /// Set extension strictly (validates extension)
    pub fn set_extension_strict(&self, filename: &str, extension: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().set_extension_strict(filename, extension)
    }

    /// Add extension to filename
    #[must_use]
    pub fn add_extension(&self, filename: &str, extension: &str) -> String {
        PrimitiveFilenameBuilder::new().add_extension(filename, extension)
    }

    /// Add extension strictly
    pub fn add_extension_strict(&self, filename: &str, extension: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().add_extension_strict(filename, extension)
    }

    /// Strip extension from filename
    #[must_use]
    pub fn strip_extension(&self, filename: &str) -> String {
        PrimitiveFilenameBuilder::new().strip_extension(filename)
    }

    /// Strip extension strictly
    pub fn strip_extension_strict(&self, filename: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().strip_extension_strict(filename)
    }

    /// Strip all extensions from filename
    #[must_use]
    pub fn strip_all_extensions(&self, filename: &str) -> String {
        PrimitiveFilenameBuilder::new().strip_all_extensions(filename)
    }

    /// Replace stem of filename
    #[must_use]
    pub fn with_stem(&self, filename: &str, new_stem: &str) -> String {
        PrimitiveFilenameBuilder::new().with_stem(filename, new_stem)
    }

    /// Replace stem strictly
    pub fn with_stem_strict(&self, filename: &str, new_stem: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().with_stem_strict(filename, new_stem)
    }

    /// Construct filename from parts
    #[must_use]
    pub fn from_parts(&self, stem: &str, extension: &str) -> String {
        PrimitiveFilenameBuilder::new().from_parts(stem, extension)
    }

    /// Construct filename from parts strictly
    pub fn from_parts_strict(&self, stem: &str, extension: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().from_parts_strict(stem, extension)
    }

    /// Append suffix to stem
    #[must_use]
    pub fn append_to_stem(&self, filename: &str, suffix: &str) -> String {
        PrimitiveFilenameBuilder::new().append_to_stem(filename, suffix)
    }

    /// Append suffix to stem strictly
    pub fn append_to_stem_strict(&self, filename: &str, suffix: &str) -> Result<String, Problem> {
        PrimitiveFilenameBuilder::new().append_to_stem_strict(filename, suffix)
    }

    /// Add number suffix to filename
    #[must_use]
    pub fn with_number(&self, filename: &str, number: u32) -> String {
        PrimitiveFilenameBuilder::new().with_number(filename, number)
    }

    /// Add zero-padded number suffix to filename
    #[must_use]
    pub fn with_padded_number(&self, filename: &str, number: u32, width: usize) -> String {
        PrimitiveFilenameBuilder::new().with_padded_number(filename, number, width)
    }

    /// Generate timestamp-based filename
    #[must_use]
    pub fn with_timestamp(&self, prefix: &str, extension: &str) -> String {
        PrimitiveFilenameBuilder::new().with_timestamp(prefix, extension)
    }

    /// Generate UUID-based filename
    #[must_use]
    pub fn with_uuid(&self, prefix: &str, extension: &str) -> String {
        PrimitiveFilenameBuilder::new().with_uuid(prefix, extension)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = FilenameBuilder::new();
        assert!(builder.emit_events);

        let silent = FilenameBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = FilenameBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_filename_detection() {
        let fb = FilenameBuilder::silent();

        assert!(fb.is_threat_present("$(cmd).txt"));
        assert!(!fb.is_threat_present("file.txt"));
        assert!(fb.is_path_separators_present("foo/bar.txt"));
        assert!(fb.is_reserved_name("CON"));
        assert!(fb.is_double_extension_present("file.txt.exe"));
    }

    #[test]
    fn test_filename_validation() {
        let fb = FilenameBuilder::new();

        assert!(fb.is_valid("file.txt"));
        assert!(!fb.is_valid("../file.txt"));
        assert!(fb.validate_filename("file.txt").is_ok());
        assert!(fb.validate_filename("../file.txt").is_err());
        assert!(fb.is_safe("file.txt"));
        assert!(!fb.is_safe("CON"));
        assert!(fb.is_upload_safe("document.pdf"));
        assert!(!fb.is_upload_safe("script.exe"));
    }

    #[test]
    fn test_filename_sanitization() {
        let fb = FilenameBuilder::new();

        let clean = fb.sanitize("../file;rm.txt").expect("should sanitize");
        assert!(!clean.contains(".."));
        assert!(!clean.contains(";"));

        assert_eq!(fb.shell_escape("file.txt"), "'file.txt'");
        assert_eq!(fb.to_safe_filename(""), "unnamed");
    }

    #[test]
    fn test_filename_construction() {
        let fb = FilenameBuilder::new();

        assert_eq!(fb.set_extension("file.txt", "pdf"), "file.pdf");
        assert_eq!(fb.add_extension("file.txt", "gz"), "file.txt.gz");
        assert_eq!(fb.strip_extension("file.txt"), "file");
        assert_eq!(fb.with_stem("file.txt", "document"), "document.txt");
        assert_eq!(fb.from_parts("doc", "pdf"), "doc.pdf");
        assert_eq!(fb.with_number("file.txt", 1), "file_1.txt");
    }

    // ========================================================================
    // Detection: accessor + classification wrappers.
    // ========================================================================

    #[test]
    fn test_detection_accessors() {
        let fb = FilenameBuilder::silent();

        // Extension accessors.
        assert_eq!(fb.find_extension("archive.tar.gz"), Some("gz"));
        assert_eq!(fb.find_extension("noext"), None);
        assert_eq!(fb.stem("report.pdf"), "report");
        assert!(fb.is_extension_present("a.txt"));
        assert!(!fb.is_extension_present("a"));

        // Extension matching.
        assert!(fb.is_extension_found("photo.JPG", "jpg")); // case-insensitive
        assert!(fb.is_extension_in_list("main.rs", &["rs", "toml"]));
        assert!(!fb.is_extension_in_list("main.py", &["rs", "toml"]));

        // Classification.
        assert!(fb.is_dot_file(".bashrc"));
        assert!(!fb.is_dot_file("file.txt"));
        assert!(fb.is_directory_ref(".."));
        assert!(fb.is_directory_ref("."));
        assert!(!fb.is_directory_ref("dir"));
    }

    #[test]
    fn test_detection_threat_predicates() {
        let fb = FilenameBuilder::silent();

        assert!(fb.is_null_bytes_present("a\0b"));
        assert!(!fb.is_null_bytes_present("ab"));
        assert!(fb.is_control_characters_present("a\nb"));
        assert!(fb.is_shell_chars_present("a;b"));
        assert!(fb.is_command_substitution_present("$(id)"));
        // is_variable_expansion_present matches the $VAR form ($ followed by a
        // letter/underscore); the ${VAR} brace form is not this function's job.
        assert!(fb.is_variable_expansion_present("back$HOME.txt"));
        assert!(!fb.is_variable_expansion_present("plain.txt"));
        assert!(fb.is_injection_present("file`whoami`.txt"));
        assert!(fb.is_dangerous_extension_present("evil.exe"));
        assert!(!fb.is_dangerous_extension_present("doc.pdf"));
        assert!(fb.is_non_ascii_present("café.txt"));
        assert!(!fb.is_non_ascii_present("cafe.txt"));
    }

    // ========================================================================
    // Validation wrappers (strict-by-default per Issue #182).
    // ========================================================================

    #[test]
    fn test_validation_wrappers() {
        let fb = FilenameBuilder::new();

        // Cross-platform: reserved names / trailing dots are rejected.
        assert!(fb.is_cross_platform_safe("document.txt"));
        assert!(fb.validate_cross_platform("document.txt").is_ok());
        assert!(!fb.is_cross_platform_safe("CON"));
        assert!(fb.validate_cross_platform("CON").is_err());

        // Shell safety.
        assert!(fb.is_shell_safe("plain.txt"));
        assert!(!fb.is_shell_safe("a;rm -rf b"));
        assert!(fb.validate_shell_safe("plain.txt").is_ok());
        assert!(fb.validate_shell_safe("a;b").is_err());

        // Upload safety + validation.
        assert!(fb.validate_upload_safe("photo.png").is_ok());
        assert!(fb.validate_upload_safe("shell.exe").is_err());

        // Extension allow-list.
        assert!(fb.is_extension_allowed("image.png", &["png", "jpg"]));
        assert!(!fb.is_extension_allowed("image.gif", &["png", "jpg"]));
        assert!(
            fb.validate_allowed_extension("image.png", &["png", "jpg"])
                .is_ok()
        );
        assert!(
            fb.validate_allowed_extension("image.gif", &["png", "jpg"])
                .is_err()
        );

        // Extension safety.
        assert!(fb.is_extension_safe("notes.txt"));
        assert!(!fb.is_extension_safe("payload.bat"));
    }

    #[test]
    fn test_length_validation() {
        let fb = FilenameBuilder::new();
        assert!(fb.is_within_length("short.txt", 255));
        assert!(!fb.is_within_length("aaaa.txt", 4));
        assert!(fb.validate_within_length("short.txt", 255).is_ok());
        assert!(fb.validate_within_length("toolong.txt", 3).is_err());
    }

    #[test]
    fn test_validate_safe_and_generic_validate() {
        let fb = FilenameBuilder::new();
        assert!(fb.validate_safe("file.txt").is_ok());
        assert!(fb.validate_safe("CON").is_err());
    }

    // ========================================================================
    // Sanitization: strip / replace / normalize / to_safe wrappers.
    // ========================================================================

    #[test]
    fn test_strip_wrappers() {
        let fb = FilenameBuilder::silent();

        assert_eq!(fb.strip_null_bytes("a\0b.txt"), "ab.txt");
        assert_eq!(fb.strip_control_chars("a\nb.txt"), "ab.txt");
        // Path separators removed (Cow may borrow or own).
        assert!(!fb.strip_path_separators("a/b\\c.txt").contains('/'));
        assert!(!fb.strip_path_separators("a/b\\c.txt").contains('\\'));
        // Shell metacharacters removed.
        let cleaned = fb.strip_shell_chars("a;b|c.txt");
        assert!(!cleaned.contains(';'));
        assert!(!cleaned.contains('|'));
    }

    #[test]
    fn test_replace_and_normalize_wrappers() {
        let fb = FilenameBuilder::silent();

        assert_eq!(fb.replace_spaces("my file.txt"), "my_file.txt");
        assert_eq!(fb.replace_spaces_with_hyphens("my file.txt"), "my-file.txt");
        assert_eq!(fb.normalize_case("MyFile.TXT"), "myfile.txt");
        // Only the extension is lowercased.
        assert_eq!(fb.normalize_extension("Report.PDF"), "Report.pdf");
    }

    #[test]
    fn test_sanitize_context_and_strict() {
        let fb = FilenameBuilder::new();

        // Strict sanitization REJECTS (errors) when threats are present, and
        // passes a clean name through unchanged.
        assert_eq!(fb.sanitize_strict("clean.txt").expect("clean"), "clean.txt");
        assert!(
            fb.sanitize_strict("../a;b.txt").is_err(),
            "strict sanitize must reject threats, not strip them"
        );

        // Lenient sanitize DOES strip threats.
        let lenient = fb.sanitize("../a;b.txt").expect("lenient");
        assert!(!lenient.contains(".."));
        assert!(!lenient.contains(';'));

        // Context-driven sanitization for a secure file.
        let secure = fb
            .sanitize_with_context("weird name!.txt", SanitizationContext::SecureFile)
            .expect("context");
        assert!(!secure.is_empty());

        // to_safe_filename fallback for empty/garbage input.
        assert_eq!(fb.to_safe_filename(""), "unnamed");
        assert_eq!(fb.to_safe_filename_or("", "fallback"), "fallback");
    }

    #[test]
    fn test_shell_escape_wrappers() {
        let fb = FilenameBuilder::new();
        assert_eq!(fb.shell_escape("file.txt"), "'file.txt'");
        // Strict shell escape errors on control chars / null bytes.
        assert!(fb.shell_escape_strict("clean.txt").is_ok());
        assert!(fb.shell_escape_strict("bad\0.txt").is_err());
    }

    // ========================================================================
    // Construction: strict variants + stem / part manipulation.
    // ========================================================================

    #[test]
    fn test_construction_strict_and_stem() {
        let fb = FilenameBuilder::new();

        assert_eq!(
            fb.set_extension_strict("file.txt", "pdf").expect("strict"),
            "file.pdf"
        );
        assert!(fb.set_extension_strict("file.txt", "e/x").is_err());

        assert_eq!(fb.strip_all_extensions("a.tar.gz"), "a");
        assert_eq!(fb.append_to_stem("file.txt", "_v2"), "file_v2.txt");
        assert_eq!(fb.with_padded_number("f.txt", 7, 3), "f_007.txt");

        assert_eq!(
            fb.from_parts_strict("doc", "pdf").expect("parts"),
            "doc.pdf"
        );
        assert_eq!(
            fb.with_stem_strict("old.txt", "new").expect("stem"),
            "new.txt"
        );
    }

    #[test]
    fn test_timestamp_and_uuid_construction() {
        let fb = FilenameBuilder::new();

        // Timestamp-based filename carries the prefix and extension.
        let ts = fb.with_timestamp("backup", "tar");
        assert!(ts.starts_with("backup"));
        assert!(ts.ends_with(".tar"));

        // UUID-based filenames are unique across calls and well-formed.
        let a = fb.with_uuid("upload", "bin");
        let b = fb.with_uuid("upload", "bin");
        assert!(a.starts_with("upload"));
        assert!(a.ends_with(".bin"));
        assert_ne!(a, b, "UUID filenames must be unique");
    }

    #[test]
    fn test_pattern_matching_and_detect_issues() {
        let fb = FilenameBuilder::silent();
        assert!(fb.is_pattern_found("report.txt", "*.txt"));
        assert!(!fb.is_pattern_found("report.md", "*.txt"));

        // detect_issues surfaces problems for a hostile filename.
        let issues = fb.detect_issues("../$(id).txt");
        assert!(!issues.is_empty());
        // A clean filename yields no issues.
        assert!(fb.detect_issues("clean.txt").is_empty());
    }
}
