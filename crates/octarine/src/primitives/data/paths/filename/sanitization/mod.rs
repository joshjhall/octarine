//! Filename sanitization functions
//!
//! Provides sanitization functions to clean and transform filenames for safe use.
//!
//! ## Sanitization Philosophy
//!
//! Sanitization functions:
//! - Use detection functions to identify threats
//! - Transform or reject based on context
//! - Have both lenient (transform) and strict (reject) variants
//! - Are context-aware (different rules for different uses)
//!
//! ## Sanitization Contexts
//!
//! | Context | Use Case | Security Level |
//! |---------|----------|----------------|
//! | `UserFile` | User-generated content | Medium - allow Unicode |
//! | `SystemFile` | System/application files | High - ASCII only |
//! | `SecureFile` | Security-sensitive files | Maximum - most restrictive |
//! | `ConfigFile` | Configuration files | High - no shell chars |
//! | `UploadFile` | Untrusted uploads | Maximum - most restrictive |
//!
//! ## Module Organization
//!
//! - [`context`] - Context-specific sanitization implementations
//! - [`removal`] - Character removal functions
//! - [`transform`] - Replacement, normalization, and prefix handling
//! - [`shell`] - Shell escaping functions
//! - [`composite`] - High-level composite sanitization functions

// Allow "File" suffix on variants - they describe file contexts, not actual files
#![allow(clippy::enum_variant_names)]

mod composite;
mod context;
mod removal;
mod shell;
mod transform;

use super::{detection, validation};
use crate::primitives::types::Problem;

// ============================================================================
// Result Type
// ============================================================================

/// Result type for sanitization operations
pub type SanitizationResult = Result<String, Problem>;

// ============================================================================
// Context Enum
// ============================================================================

/// Sanitization context determining rules applied
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SanitizationContext {
    /// User-generated filenames (medium security)
    /// - Allows Unicode
    /// - Removes dangerous characters
    /// - Preserves dots and extensions
    #[default]
    UserFile,

    /// System/application filenames (high security)
    /// - ASCII only
    /// - Removes all special characters
    /// - Preserves extensions
    SystemFile,

    /// Security-sensitive filenames (maximum security)
    /// - ASCII alphanumeric and limited punctuation only
    /// - Most restrictive
    SecureFile,

    /// Configuration filenames (high security)
    /// - No shell metacharacters
    /// - Allows dots and underscores
    ConfigFile,

    /// Untrusted file uploads (maximum security)
    /// - Most restrictive
    /// - No dangerous extensions
    /// - No double extensions
    UploadFile,
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if character is a bidirectional control character
pub(crate) fn is_bidi_char(c: char) -> bool {
    matches!(
        c,
        '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    )
}

// ============================================================================
// Core Sanitization Functions
// ============================================================================

/// Sanitize filename using default context (UserFile)
///
/// Removes dangerous characters while preserving the filename structure.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::sanitize("file\0.txt").expect("test"), "file.txt");
/// assert_eq!(sanitization::sanitize("../file.txt").expect("test"), "file.txt");
/// assert_eq!(sanitization::sanitize("$(cmd).txt").expect("test"), "cmd.txt");
/// ```
pub fn sanitize(filename: &str) -> SanitizationResult {
    sanitize_with_context(filename, SanitizationContext::UserFile)
}

/// Sanitize filename (strict - reject if threats found)
///
/// Returns error if any security threats are detected.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert!(sanitization::sanitize_strict("file.txt").is_ok());
/// assert!(sanitization::sanitize_strict("../file.txt").is_err());
/// ```
pub fn sanitize_strict(filename: &str) -> SanitizationResult {
    validation::validate_safe_strict(filename)?;
    Ok(filename.to_string())
}

/// Sanitize filename with specific context
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization::{sanitize_with_context, SanitizationContext};
///
/// let result = sanitize_with_context("File Name.txt", SanitizationContext::SystemFile);
/// assert_eq!(result.expect("test"), "FileName.txt");
///
/// let result = sanitize_with_context("$(cmd).exe", SanitizationContext::UploadFile);
/// // Dangerous extension rejected in upload context
/// assert!(result.is_err());
/// ```
pub fn sanitize_with_context(filename: &str, ctx: SanitizationContext) -> SanitizationResult {
    // Empty check
    if detection::is_empty(filename) {
        return Err(Problem::validation("Filename cannot be empty"));
    }

    // Apply context-specific sanitization
    match ctx {
        SanitizationContext::UserFile => context::sanitize_user_file(filename),
        SanitizationContext::SystemFile => context::sanitize_system_file(filename),
        SanitizationContext::SecureFile => context::sanitize_secure_file(filename),
        SanitizationContext::ConfigFile => context::sanitize_config_file(filename),
        SanitizationContext::UploadFile => context::sanitize_upload_file(filename),
    }
}

// ============================================================================
// Re-exports
// ============================================================================

// Character removal
pub use removal::{
    strip_bidi_chars, strip_control_chars, strip_non_ascii, strip_null_bytes,
    strip_path_separators, strip_reserved_windows_chars, strip_shell_chars,
};

// Transformation
pub use transform::{
    collapse_separators, normalize_case, normalize_extension, prefix_reserved, replace_spaces,
    replace_spaces_with_hyphens, strip_leading_dots, trim_filename,
};

// Shell escaping
pub use shell::{shell_escape, shell_escape_strict};

// Composite sanitization
pub use composite::{sanitize_all_threats, to_safe_filename, to_safe_filename_or};

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_sanitize() {
        // Basic sanitization
        assert_eq!(sanitize("file.txt").expect("test"), "file.txt");
        assert_eq!(sanitize("file\0.txt").expect("test"), "file.txt");
        assert_eq!(sanitize("file\n.txt").expect("test"), "file.txt");

        // Path separators removed
        assert_eq!(sanitize("foo/bar.txt").expect("test"), "foobar.txt");
        assert_eq!(sanitize("foo\\bar.txt").expect("test"), "foobar.txt");

        // Shell chars removed
        assert_eq!(sanitize("file;rm.txt").expect("test"), "filerm.txt");
        assert_eq!(sanitize("$(cmd).txt").expect("test"), "cmd.txt");

        // Empty fails
        assert!(sanitize("").is_err());
        assert!(sanitize("\0\0\0").is_err());
    }

    #[test]
    fn test_sanitize_strict() {
        assert!(sanitize_strict("file.txt").is_ok());
        assert!(sanitize_strict("file-name_123.txt").is_ok());

        // Threats rejected
        assert!(sanitize_strict("file\0.txt").is_err());
        assert!(sanitize_strict("../file.txt").is_err());
        assert!(sanitize_strict("$(cmd).txt").is_err());
    }

    #[test]
    fn test_sanitize_with_context() {
        // UserFile context
        assert_eq!(
            sanitize_with_context("文件.txt", SanitizationContext::UserFile).expect("test"),
            "文件.txt"
        );

        // SystemFile context
        assert_eq!(
            sanitize_with_context("my file.txt", SanitizationContext::SystemFile).expect("test"),
            "my_file.txt"
        );

        // UploadFile context - dangerous extension rejected
        assert!(sanitize_with_context("file.exe", SanitizationContext::UploadFile).is_err());
    }
}
