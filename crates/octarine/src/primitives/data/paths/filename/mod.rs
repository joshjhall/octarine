//! Filename domain for path operations
//!
//! This module provides filename validation, sanitization, and construction
//! with comprehensive security checks.
//!
//! ## Architecture
//!
//! The filename domain is organized into four layers:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  FilenameBuilder                                                │
//! │  (Unified API for all filename operations)                      │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          │                   │                   │
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │   detection     │ │   validation    │ │  sanitization   │
//! │                 │ │                 │ │                 │
//! │ - has_*         │ │ - is_*          │ │ - sanitize_*    │
//! │ - is_*          │ │ - validate_*    │ │ - remove_*      │
//! │ - get_*         │ │ - has_*         │ │ - replace_*     │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//!                              │
//!                              ▼
//!                    ┌─────────────────┐
//!                    │  construction   │
//!                    │                 │
//!                    │ - set_extension │
//!                    │ - with_stem     │
//!                    │ - from_parts    │
//!                    └─────────────────┘
//! ```
//!
//! ## Security Standards
//!
//! Follows OWASP filename security guidelines:
//! - Detect and reject command injection patterns
//! - Validate against reserved Windows names
//! - Remove dangerous characters
//! - Prevent double extension attacks
//! - Detect Unicode homoglyphs and bidi attacks
//!
//! ## Quick Start
//!
//! ```ignore
//! use octarine::primitives::paths::filename::FilenameBuilder;
//!
//! let fb = FilenameBuilder::new();
//!
//! // Validate user input
//! if fb.is_upload_safe(user_input) {
//!     let safe_name = fb.sanitize(user_input)?;
//!     // Use safe_name for file operations
//! }
//! # let user_input = "safe.txt";
//! ```
//!
//! ## Module Functions vs Builder
//!
//! You can use either the module functions directly or the builder API:
//!
//! ```ignore
//! use octarine::primitives::paths::filename::{detection, validation, sanitization, construction};
//! use octarine::primitives::paths::filename::FilenameBuilder;
//!
//! // Using module functions directly
//! let has_threat = detection::is_threat_present("$(cmd).txt");
//! let is_valid = validation::is_valid("file.txt");
//! let clean = sanitization::sanitize("../file.txt");
//! let new_name = construction::set_extension("file.txt", "pdf");
//!
//! // Using builder (same functionality)
//! let fb = FilenameBuilder::new();
//! let has_threat = fb.is_threat_present("$(cmd).txt");
//! let is_valid = fb.is_valid("file.txt");
//! let clean = fb.sanitize("../file.txt");
//! let new_name = fb.set_extension("file.txt", "pdf");
//! ```
//!
//! ## Sanitization Contexts
//!
//! Different contexts apply different security rules:
//!
//! ```ignore
//! use octarine::primitives::paths::filename::sanitization::{
//!     sanitize_with_context, SanitizationContext
//! };
//!
//! // User files: allow Unicode, remove dangerous chars
//! let name = sanitize_with_context("文件.txt", SanitizationContext::UserFile)?;
//!
//! // System files: ASCII only, strict rules
//! let name = sanitize_with_context("file.txt", SanitizationContext::SystemFile)?;
//!
//! // Upload files: maximum security, no dangerous extensions
//! let name = sanitize_with_context("upload.txt", SanitizationContext::UploadFile)?;
//! ```

pub mod builder;
pub mod construction;
pub mod detection;
pub mod sanitization;
pub mod validation;

// Re-export builder for convenience
pub use builder::FilenameBuilder;

// Re-export result types
pub use construction::ConstructionResult;
pub use sanitization::SanitizationResult;
pub use validation::ValidationResult;

// Re-export commonly used enums
pub use sanitization::SanitizationContext;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_module_integration() {
        // Detection
        assert!(detection::is_threat_present("$(cmd).txt"));
        assert!(!detection::is_threat_present("file.txt"));
        assert!(detection::is_path_separators_present("foo/bar.txt"));
        assert!(detection::is_reserved_name("CON"));
        assert!(detection::is_double_extension_present("file.txt.exe"));

        // Validation
        assert!(validation::is_valid("file.txt"));
        assert!(!validation::is_valid("../file.txt"));
        assert!(validation::validate_strict("file.txt").is_ok());
        assert!(validation::is_upload_safe("document.pdf"));
        assert!(!validation::is_upload_safe("malware.exe"));

        // Sanitization
        assert_eq!(
            sanitization::sanitize("file\0.txt").expect("test"),
            "file.txt"
        );
        assert!(sanitization::sanitize_strict("file.txt").is_ok());
        assert!(sanitization::sanitize_strict("$(cmd).txt").is_err());

        // Construction
        assert_eq!(construction::set_extension("file.txt", "pdf"), "file.pdf");
        assert_eq!(construction::strip_extension("file.txt"), "file");
        assert_eq!(construction::from_parts("doc", "pdf"), "doc.pdf");
    }

    #[test]
    fn test_builder_integration() {
        let fb = FilenameBuilder::new();

        // Detection via builder
        assert!(fb.is_threat_present("$(cmd).txt"));
        assert!(!fb.is_threat_present("file.txt"));
        assert!(fb.is_extension_present("file.txt"));
        assert_eq!(fb.find_extension("file.txt"), Some("txt"));

        // Validation via builder
        assert!(fb.is_valid("file.txt"));
        assert!(fb.is_safe("file.txt"));
        assert!(fb.is_upload_safe("document.pdf"));
        assert!(!fb.is_upload_safe("script.exe"));

        // Sanitization via builder
        assert_eq!(fb.sanitize("../file.txt").expect("test"), "file.txt");
        assert_eq!(fb.strip_null_bytes("file\0.txt").as_ref(), "file.txt");
        assert_eq!(fb.shell_escape("file.txt"), "'file.txt'");

        // Construction via builder
        assert_eq!(fb.set_extension("file.txt", "pdf"), "file.pdf");
        assert_eq!(fb.add_extension("file.txt", "gz"), "file.txt.gz");
        assert_eq!(fb.with_stem("old.txt", "new"), "new.txt");
        assert_eq!(fb.with_number("file.txt", 1), "file_1.txt");
    }

    #[test]
    fn test_security_patterns() {
        let fb = FilenameBuilder::new();

        // Command injection
        assert!(fb.is_threat_present("$(whoami).txt"));
        assert!(fb.is_threat_present("${HOME}.txt"));
        assert!(fb.is_threat_present("`id`.txt"));
        assert!(!fb.is_valid("$(cmd).txt"));

        // Path traversal
        assert!(fb.is_path_separators_present("../secret"));
        assert!(fb.is_path_separators_present("..\\secret"));
        assert!(!fb.is_valid("../file.txt"));

        // Reserved names
        assert!(fb.is_reserved_name("CON"));
        assert!(fb.is_reserved_name("NUL.txt"));
        assert!(!fb.is_safe("CON"));

        // Shell metacharacters
        assert!(fb.is_shell_chars_present("file;rm.txt"));
        assert!(fb.is_shell_chars_present("file|cat.txt"));
        assert!(!fb.is_shell_safe("file;rm.txt"));

        // Dangerous extensions
        assert!(fb.is_dangerous_extension_present("file.exe"));
        assert!(!fb.is_upload_safe("file.bat"));

        // Double extensions
        assert!(fb.is_double_extension_present("file.txt.exe"));
        assert!(!fb.is_upload_safe("file.txt.exe"));
    }

    #[test]
    fn test_unicode_security() {
        let fb = FilenameBuilder::new();

        // Non-ASCII
        assert!(fb.is_non_ascii_present("文件.txt"));
        assert!(!fb.is_cross_platform_safe("文件.txt"));

        // Homoglyphs (Cyrillic 'а' looks like Latin 'a')
        assert!(fb.is_homoglyphs_present("p\u{0430}ypal.txt"));
        assert!(!fb.is_cross_platform_safe("p\u{0430}ypal.txt"));

        // Bidirectional control
        assert!(fb.is_bidi_control_present("file\u{202E}txt.exe"));
        assert!(!fb.is_safe("file\u{202E}.txt"));
    }

    #[test]
    fn test_extension_operations() {
        let fb = FilenameBuilder::new();

        // Get/set extension
        assert_eq!(fb.find_extension("file.txt"), Some("txt"));
        assert_eq!(fb.find_extension("file"), None);
        assert_eq!(fb.set_extension("file.txt", "pdf"), "file.pdf");

        // Add/strip extension
        assert_eq!(fb.add_extension("file.txt", "gz"), "file.txt.gz");
        assert_eq!(fb.strip_extension("file.txt"), "file");
        assert_eq!(fb.strip_all_extensions("file.tar.gz"), "file");

        // Extension validation
        assert!(fb.is_extension_found("file.TXT", "txt"));
        assert!(fb.is_extension_in_list("file.txt", &["txt", "pdf"]));
        assert!(fb.is_extension_safe("file.txt"));
        assert!(!fb.is_extension_safe("file.exe"));
    }

    #[test]
    fn test_sanitization_contexts() {
        // User file context - allows Unicode
        let result = sanitization::sanitize_with_context(
            "文件.txt",
            sanitization::SanitizationContext::UserFile,
        );
        assert!(result.is_ok());
        assert_eq!(result.expect("test"), "文件.txt");

        // System file context - ASCII only
        let result = sanitization::sanitize_with_context(
            "文件.txt",
            sanitization::SanitizationContext::SystemFile,
        );
        assert!(result.is_ok());
        assert_eq!(result.expect("test"), "txt");

        // Upload context - strict security
        let result = sanitization::sanitize_with_context(
            "file.exe",
            sanitization::SanitizationContext::UploadFile,
        );
        assert!(result.is_err()); // Dangerous extension

        // Config file context - no shell chars
        let result = sanitization::sanitize_with_context(
            "config;rm.yaml",
            sanitization::SanitizationContext::ConfigFile,
        );
        assert!(result.is_ok());
        assert_eq!(result.expect("test"), "configrm.yaml");
    }

    #[test]
    fn test_filename_construction() {
        let fb = FilenameBuilder::new();

        // From parts
        assert_eq!(fb.from_parts("file", "txt"), "file.txt");
        assert!(fb.from_parts_strict("file", "txt").is_ok());
        assert!(fb.from_parts_strict("file", "exe").is_err()); // Dangerous

        // With stem
        assert_eq!(fb.with_stem("old.txt", "new"), "new.txt");
        assert!(fb.with_stem_strict("old.txt", "../hack").is_err());

        // Append to stem
        assert_eq!(fb.append_to_stem("file.txt", "_backup"), "file_backup.txt");

        // Numbered
        assert_eq!(fb.with_number("file.txt", 1), "file_1.txt");
        assert_eq!(fb.with_padded_number("file.txt", 1, 3), "file_001.txt");
    }

    #[test]
    fn test_safe_filename_generation() {
        let fb = FilenameBuilder::new();

        // From dangerous input
        assert_eq!(fb.to_safe_filename(""), "unnamed");
        assert_eq!(fb.to_safe_filename("///"), "unnamed");
        assert_eq!(fb.to_safe_filename("file.txt"), "file.txt");
        assert_eq!(fb.to_safe_filename_or("", "default.txt"), "default.txt");

        // Timestamp/UUID generation
        let ts = fb.with_timestamp("log", "txt");
        assert!(ts.starts_with("log_"));
        assert!(ts.ends_with(".txt"));

        let uuid = fb.with_uuid("upload", "jpg");
        assert!(uuid.starts_with("upload_"));
        assert!(uuid.ends_with(".jpg"));
    }

    #[test]
    fn test_shell_escaping() {
        let fb = FilenameBuilder::new();

        assert_eq!(fb.shell_escape("file.txt"), "'file.txt'");
        assert_eq!(fb.shell_escape("file's.txt"), "'file'\\''s.txt'");
        assert_eq!(fb.shell_escape("file name.txt"), "'file name.txt'");

        assert!(fb.shell_escape_strict("file.txt").is_ok());
        assert!(fb.shell_escape_strict("file\0.txt").is_err());
    }

    #[test]
    fn test_edge_cases() {
        let fb = FilenameBuilder::new();

        // Dot files
        assert!(fb.is_dot_file(".gitignore"));
        assert!(!fb.is_dot_file("."));
        assert!(!fb.is_dot_file(".."));
        assert_eq!(fb.find_extension(".gitignore"), None);
        assert_eq!(fb.find_extension(".git.config"), Some("config"));

        // Directory references
        assert!(fb.is_directory_ref("."));
        assert!(fb.is_directory_ref(".."));
        assert!(!fb.is_valid("."));
        assert!(!fb.is_valid(".."));

        // Empty and whitespace
        assert!(!fb.is_valid(""));
        assert!(fb.sanitize("").is_err());
        assert_eq!(fb.to_safe_filename("   "), "unnamed");

        // Very long filename
        let long_name = "a".repeat(300);
        assert!(!fb.is_within_length(&long_name, 255));
    }
}
