// Allow dead code and unused imports - this module is being built incrementally
// and not all items are used yet. They will be used when security module migrates.
#![allow(dead_code)]
#![allow(unused_imports)]

//! Path primitives module
//!
//! Pure path security and manipulation functions with ZERO rust-core dependencies
//! beyond the common utilities.
//!
//! # Architecture Layer
//!
//! This is **Layer 1 (primitives)** of the three-layer architecture:
//! - **Layer 1 (primitives)**: Pure utilities, no internal dependencies
//! - **Layer 2 (observe)**: Uses primitives only
//! - **Layer 3 (security, runtime)**: Uses primitives + observe
//!
//! # Module Organization
//!
//! ## Current Structure (Issues #51-55)
//!
//! ```text
//! primitives/paths/
//! ├── types.rs                     ◀── Type definitions (Issue #52) ✅
//! ├── builder.rs                   ◀── PathBuilder API (Issue #52) ✅
//! ├── common/                      ◀── Foundation module (Issue #51) ✅
//! │   ├── patterns/                (detection patterns)
//! │   │   ├── traversal.rs         (.. patterns, encoded variants)
//! │   │   ├── injection.rs         (command injection patterns)
//! │   │   ├── characters.rs        (null bytes, control characters)
//! │   │   ├── encoding.rs          (double encoding, URL encoding)
//! │   │   └── platform.rs          (Windows/Unix path patterns)
//! │   ├── normalization.rs         (separator normalization)
//! │   └── construction/            (path building primitives)
//! │       ├── join.rs              (join segments safely)
//! │       ├── resolve.rs           (absolute↔relative with base)
//! │       └── components.rs        (parent, filename, extension)
//! ├── characteristic/              ◀── Path characteristics (Issue #53) ✅
//! │   ├── detection.rs             (detection functions)
//! │   └── builder.rs               (CharacteristicBuilder)
//! ├── filetype/                    ◀── File type detection (Issue #54) ✅
//! │   ├── detection.rs             (file category detection)
//! │   └── builder.rs               (FiletypeBuilder)
//! └── format/                      ◀── Format detection/conversion (Issue #55) ✅
//!     ├── detection.rs             (format detection)
//!     ├── conversion.rs            (format conversion)
//!     └── builder.rs               (FormatBuilder)
//! ```
//!
//! ## Complete Structure (Issues #51-58)
//!
//! ```text
//! primitives/paths/
//! ├── types.rs                     (shared types - Issue #52) ✅
//! ├── builder.rs                   (PathBuilder - Issue #52) ✅
//! ├── common/                      (shared utilities - Issue #51) ✅
//! ├── characteristic/              (path characteristics - Issue #53) ✅
//! ├── filetype/                    (file type detection - Issue #54) ✅
//! ├── format/                      (format detection/conversion - Issue #55) ✅
//! ├── boundary/                    (boundary validation - Issue #57) ✅
//! └── filename/                    (filename operations - Issue #58) ✅
//!
//! primitives/security/paths/       (security - Issue #56, moved for consistency) ✅
//! └── ...                          (detection, validation, sanitization)
//! ```
//!
//! # Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only string transformations
//! 3. **Reusable**: Used by observe/pii and security modules
//! 4. **Type-Safe API**: Domain-specific validation strategies
//! 5. **Zero-Copy**: Uses `Cow<str>` where possible for efficiency
//!
//! # Security Standards
//!
//! All security checks follow OWASP guidelines and address:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization
//!
//! # Usage
//!
//! ## Pattern Detection
//!
//! ```ignore
//! use octarine::primitives::paths::common::patterns::{traversal, injection, characters};
//!
//! // Check for security threats
//! if traversal::has_any_traversal(user_path) {
//!     return Err(Problem::validation("Path traversal detected"));
//! }
//!
//! if injection::has_any_injection(user_path) {
//!     return Err(Problem::validation("Command injection detected"));
//! }
//!
//! if characters::has_dangerous_characters(user_path) {
//!     return Err(Problem::validation("Dangerous characters detected"));
//! }
//! ```
//!
//! ## Path Normalization
//!
//! ```ignore
//! use octarine::primitives::paths::common::normalization;
//!
//! // Normalize separators
//! let unix_path = normalization::to_forward_slashes("path\\to\\file");
//! // Returns: "path/to/file"
//!
//! // Full normalization
//! let clean = normalization::normalize_unix("path\\\\to//file/");
//! // Returns: "path/to/file"
//! ```
//!
//! ## Path Construction
//!
//! ```ignore
//! use octarine::primitives::paths::common::construction::{join, components, resolve};
//!
//! // Join paths
//! let full = join::join_unix("base/dir", "file.txt");
//! // Returns: "base/dir/file.txt"
//!
//! // Extract components
//! let parent = components::find_parent("path/to/file.txt");
//! // Returns: Some("path/to")
//!
//! // Clean paths (resolve . and ..)
//! let cleaned = resolve::clean_path("path/to/../other/./file");
//! // Returns: "path/other/file"
//! ```
//!
//! ## PathBuilder API (Recommended)
//!
//! ```ignore
//! use crate::primitives::paths::PathBuilder;
//!
//! let builder = PathBuilder::new();
//!
//! // Detection
//! let path_type = builder.detect_path_type("/etc/passwd");
//! let threats = builder.detect_threats("../../../etc/passwd");
//!
//! // Validation
//! let is_safe = builder.is_safe("/home/user/file.txt");
//! let result = builder.validate("../etc/passwd");
//!
//! // Construction
//! let full = builder.join("base", "file.txt");
//! let parent = builder.find_parent("/app/data/file.txt");
//! ```

// Common utilities (internal to paths/)
mod common;

// Type definitions
pub(crate) mod types;

// Builder API
pub(crate) mod builder;

// Domain modules
pub(crate) mod boundary;
pub(crate) mod characteristic;
pub(crate) mod filename;
pub(crate) mod filetype;
pub(crate) mod format;

// NOTE: Security module has moved to primitives::data::security::paths

// Re-export types for crate-internal use
pub(crate) use types::{
    BoundaryStrategy, FileCategory, FilenameSanitizationStrategy, PathDetectionResult, PathMatch,
    PathSanitizationStrategy, PathType, PathValidationResult, Platform, SecurityThreat,
};

// Re-export format types for crate-internal use
pub(crate) use format::{PathFormat, SeparatorStyle};

// Re-export filename sanitization context for crate-internal use
pub(crate) use filename::SanitizationContext;

// Re-export builder for crate-internal use
pub(crate) use builder::PathBuilder;

// Re-export characteristic module builder for crate-internal use
pub(crate) use characteristic::CharacteristicBuilder;

// Re-export filetype module builder for crate-internal use
pub(crate) use filetype::FiletypeBuilder;

// Re-export format module builder for crate-internal use
pub(crate) use format::FormatBuilder;

// NOTE: SecurityBuilder has moved to primitives::data::security::paths::SecurityBuilder

// Re-export boundary module builder for crate-internal use
pub(crate) use boundary::BoundaryBuilder;

// Re-export filename module builder for crate-internal use
pub(crate) use filename::FilenameBuilder;

// NOTE: Raw functions from common/ are NOT re-exported.
// All access to path operations should go through the builders:
// - PathBuilder (main entry point)
// - CharacteristicBuilder
// - FiletypeBuilder
// - FormatBuilder
// - BoundaryBuilder
// - FilenameBuilder
//
// NOTE: SecurityBuilder has moved to crate::primitives::security::paths

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::primitives::security::paths::SecurityBuilder;

    /// Integration test: Security validation workflow (via SecurityBuilder)
    #[test]
    fn test_security_workflow() {
        let security = SecurityBuilder::new();

        // Safe path
        let safe_path = "uploads/user123/document.pdf";
        assert!(!security.is_traversal_present(safe_path));
        assert!(!security.is_command_injection_present(safe_path));
        assert!(!security.is_null_bytes_present(safe_path));

        // Unsafe paths - traversal
        assert!(security.is_traversal_present("../../../etc/passwd"));
        assert!(security.is_encoded_traversal_present("..%2f..%2fetc"));

        // Unsafe paths - injection
        assert!(security.is_command_injection_present("file$(whoami).txt"));
        assert!(security.is_variable_expansion_present("${HOME}/file"));

        // Unsafe paths - characters
        assert!(security.is_null_bytes_present("file\0.txt"));
    }

    /// Integration test: Path manipulation workflow (via PathBuilder)
    #[test]
    fn test_manipulation_workflow() {
        let builder = PathBuilder::new();

        // Join and normalize
        let path = builder.join_unix("base", "subdir/file.txt");
        assert_eq!(path, "base/subdir/file.txt");

        // Extract components
        assert_eq!(builder.find_parent(&path), Some("base/subdir"));
        assert_eq!(builder.filename(&path), "file.txt");
        assert_eq!(builder.stem(&path), "file");
        assert_eq!(builder.find_extension(&path), Some("txt"));

        // Clean complex path (resolve . and ..)
        let complex = "base/dir/../other/./file.txt";
        let cleaned = builder.clean_path(complex);
        assert_eq!(cleaned, "base/other/file.txt");
    }

    /// Test platform detection (via CharacteristicBuilder)
    #[test]
    fn test_platform_detection() {
        let chars = CharacteristicBuilder::new();

        // Unix paths
        assert!(chars.is_unix_path("/home/user/file"));
        assert!(chars.is_unix_path("relative/path"));

        // Windows paths
        assert!(chars.is_windows_path("C:\\Windows\\System32"));
        assert!(chars.is_windows_path("\\\\server\\share"));

        // Portable paths
        assert!(chars.is_portable("relative/path/file.txt"));
        assert!(!chars.is_portable("/absolute/path"));
        assert!(!chars.is_portable("C:\\Windows"));
    }

    /// Test PathBuilder integration
    #[test]
    fn test_path_builder() {
        let builder = PathBuilder::new();

        // Path type detection
        assert_eq!(
            builder.detect_path_type("/etc/passwd"),
            PathType::UnixAbsolute
        );
        assert_eq!(
            builder.detect_path_type("C:\\Windows"),
            PathType::WindowsAbsolute
        );
        assert_eq!(
            builder.detect_path_type("relative/path"),
            PathType::UnixRelative
        );

        // Security detection
        assert!(builder.is_traversal_present("../../../etc/passwd"));
        assert!(builder.is_command_injection_present("$(whoami)"));
        assert!(builder.is_safe("safe/path/file.txt"));

        // Construction
        assert_eq!(builder.join("base", "file.txt"), "base/file.txt");
        assert_eq!(
            builder.find_parent("/home/user/file.txt"),
            Some("/home/user")
        );
        assert_eq!(builder.filename("/home/user/file.txt"), "file.txt");
    }

    /// Test types
    #[test]
    fn test_types() {
        // PathType
        assert!(PathType::UnixAbsolute.is_absolute());
        assert!(!PathType::UnixRelative.is_absolute());
        assert_eq!(PathType::WindowsAbsolute.platform(), Platform::Windows);

        // SecurityThreat
        assert_eq!(SecurityThreat::Traversal.cwe(), "CWE-22");
        assert_eq!(SecurityThreat::CommandInjection.severity(), 5);

        // FileCategory
        assert!(FileCategory::Credential.is_sensitive());
        assert!(FileCategory::Executable.is_executable());
    }

    /// Test CharacteristicBuilder integration
    #[test]
    fn test_characteristic_builder() {
        let builder = CharacteristicBuilder::new();

        // Absolute/relative detection
        assert!(builder.is_absolute("/etc/passwd"));
        assert!(builder.is_absolute("C:\\Windows"));
        assert!(builder.is_relative("relative/path"));

        // Hidden file detection
        assert!(builder.is_hidden(".gitignore"));
        assert!(!builder.is_hidden("visible.txt"));
        assert!(builder.is_hidden_component_present(".git/config"));

        // Path type detection
        assert_eq!(
            builder.detect_path_type("/etc/passwd"),
            PathType::UnixAbsolute
        );
        assert_eq!(
            builder.detect_path_type("C:\\Windows"),
            PathType::WindowsAbsolute
        );

        // Platform detection
        assert_eq!(builder.detect_platform("/home/user"), Platform::Unix);
        assert_eq!(builder.detect_platform("C:\\Windows"), Platform::Windows);

        // Extension detection
        assert!(builder.is_extension_present("file.txt"));
        assert_eq!(builder.find_extension("file.txt"), Some("txt"));

        // Depth calculation
        assert_eq!(builder.calculate_path_depth("a/b/c"), 3);
    }

    /// Test FiletypeBuilder integration
    #[test]
    fn test_filetype_builder() {
        let builder = FiletypeBuilder::new();

        // File category detection
        assert_eq!(builder.detect("photo.jpg"), FileCategory::Image);
        assert_eq!(builder.detect("main.rs"), FileCategory::SourceCode);
        assert_eq!(builder.detect("config.json"), FileCategory::Config);
        assert_eq!(builder.detect(".env"), FileCategory::Credential);

        // Media checks
        assert!(builder.is_image("photo.jpg"));
        assert!(builder.is_audio("song.mp3"));
        assert!(builder.is_video("movie.mp4"));
        assert!(builder.is_media("photo.jpg"));

        // Document checks
        assert!(builder.is_document("report.pdf"));
        assert!(builder.is_document("data.xlsx"));

        // Code checks
        assert!(builder.is_code("main.rs"));
        assert!(builder.is_code("script.sh"));
        assert!(builder.is_config("Cargo.toml"));

        // Security-sensitive checks
        assert!(builder.is_security_sensitive(".env"));
        assert!(builder.is_security_sensitive("server.key"));
        assert!(builder.is_security_sensitive("id_rsa"));
        assert!(!builder.is_security_sensitive("readme.txt"));

        // Extension extraction
        assert_eq!(builder.find_extension("photo.JPG"), Some("jpg".to_string()));
        assert!(builder.is_extension_found("photo.jpg", "JPG"));
    }

    /// Test PathBuilder filetype integration
    #[test]
    fn test_path_builder_filetype() {
        let builder = PathBuilder::new();

        // File category detection
        assert_eq!(
            builder.detect_file_category("photo.jpg"),
            FileCategory::Image
        );
        assert_eq!(
            builder.detect_file_category("main.rs"),
            FileCategory::SourceCode
        );

        // Category checks via PathBuilder
        assert!(builder.is_image("photo.jpg"));
        assert!(builder.is_code("main.rs"));
        assert!(builder.is_security_sensitive(".env"));
        assert!(builder.is_archive("backup.zip"));

        // PathDetectionResult includes file category
        let result = builder.detect("/path/to/main.rs");
        assert_eq!(result.file_category, Some(FileCategory::SourceCode));

        let result = builder.detect("/home/user/.env");
        assert_eq!(result.file_category, Some(FileCategory::Credential));
    }

    /// Test FormatBuilder integration
    #[test]
    fn test_format_builder() {
        use format::PathFormat;

        let builder = FormatBuilder::new();

        // Format detection
        assert_eq!(builder.detect("/mnt/c/Users"), PathFormat::Wsl);
        assert_eq!(builder.detect("C:\\Windows"), PathFormat::Windows);
        assert_eq!(builder.detect("C:/Windows"), PathFormat::PowerShell);
        assert_eq!(builder.detect("/etc/passwd"), PathFormat::Unix);
        assert_eq!(builder.detect("relative/path"), PathFormat::Portable);

        // Format checks
        assert!(builder.is_mixed_separators_present("path/to\\file"));
        assert!(builder.is_redundant_separators_present("path//to/file"));
        assert!(builder.is_trailing_separator_present("path/to/dir/"));
        assert!(builder.is_leading_dot_slash_present("./path"));
        assert!(builder.is_format_issues_present("path//to\\file/"));
        assert!(builder.is_consistent_format("path/to/file"));

        // Path type detection
        assert!(builder.is_drive_letter_present("C:\\Windows"));
        assert!(builder.is_unc_path("\\\\server\\share"));
        assert!(builder.is_wsl_path("/mnt/c/Users"));

        // Separator conversion
        assert_eq!(
            builder.convert_to_unix("path\\to\\file").as_ref(),
            "path/to/file"
        );
        assert_eq!(
            builder.convert_to_windows("path/to/file").as_ref(),
            "path\\to\\file"
        );
        assert_eq!(
            builder.normalize_separators("path/to\\file/test").as_ref(),
            "path/to/file/test"
        );

        // Cross-platform conversion
        assert_eq!(
            builder.convert_to_wsl("C:\\Users\\file"),
            Some("/mnt/c/Users/file".to_string())
        );
        assert_eq!(
            builder.wsl_to_windows("/mnt/c/Users/file"),
            Some("C:\\Users\\file".to_string())
        );
        assert_eq!(
            builder.convert_to_portable("C:\\Users\\file").as_ref(),
            "Users/file"
        );
    }

    /// Test SecurityBuilder integration
    #[test]
    fn test_security_builder() {
        use super::types::PathSanitizationStrategy;

        let builder = SecurityBuilder::new();

        // Detection
        assert!(builder.is_threat_present("../../../etc/passwd"));
        assert!(builder.is_threat_present("$(whoami)"));
        assert!(!builder.is_threat_present("safe/path.txt"));

        let threats = builder.detect_threats("../$(whoami)");
        assert!(threats.contains(&SecurityThreat::Traversal));
        assert!(threats.contains(&SecurityThreat::CommandInjection));

        // Specific threat detection
        assert!(builder.is_traversal_present("../secret"));
        assert!(builder.is_encoded_traversal_present("%2e%2e"));
        assert!(builder.is_command_injection_present("$(cmd)"));
        assert!(builder.is_variable_expansion_present("$HOME"));
        assert!(builder.is_shell_metacharacters_present("file;ls"));
        assert!(builder.is_null_bytes_present("file\0.txt"));
        assert!(builder.is_control_characters_present("file\n.txt"));
        assert!(builder.is_double_encoding_present("%252e"));

        // Validation
        assert!(builder.is_secure("safe/path.txt"));
        assert!(!builder.is_secure("../secret"));
        assert!(builder.validate_path("safe/path").is_ok());
        assert!(builder.validate_path("../secret").is_err());

        // Sanitization
        let clean = builder.sanitize("../etc/passwd").expect("test");
        assert!(!clean.contains(".."));

        assert!(builder.sanitize_strict("safe/path").is_ok());
        assert!(builder.sanitize_strict("$(cmd)").is_err());

        // Strategy-based sanitization
        assert!(
            builder
                .sanitize_with("../etc", PathSanitizationStrategy::Strict)
                .is_err()
        );
        let clean = builder
            .sanitize_with("../etc", PathSanitizationStrategy::Clean)
            .expect("test");
        assert!(!clean.contains(".."));
        let escaped = builder
            .sanitize_with("../etc", PathSanitizationStrategy::Escape)
            .expect("test");
        assert!(escaped.contains("[DOT_DOT]"));

        // Helper operations
        assert_eq!(builder.strip_traversal("../etc"), "etc");
        assert_eq!(builder.strip_null_bytes("file\0.txt"), "file.txt");
        assert_eq!(
            builder.normalize_separators("path\\to\\file"),
            "path/to/file"
        );
    }

    /// Test BoundaryBuilder integration
    #[test]
    fn test_boundary_builder() {
        let boundary = BoundaryBuilder::new("/app/data");

        // Validation
        assert!(boundary.is_within("file.txt"));
        assert!(boundary.is_within("subdir/file.txt"));
        assert!(!boundary.is_within("../secret"));
        assert!(!boundary.is_within("../../etc/passwd"));
        assert_eq!(boundary.calculate_escape_depth("../secret"), 1);
        assert_eq!(boundary.calculate_escape_depth("../../etc"), 2);
        assert_eq!(boundary.calculate_depth("file.txt"), Some(1));
        assert_eq!(boundary.calculate_depth("dir/file.txt"), Some(2));

        // Sanitization
        assert!(boundary.constrain_strict("file.txt").is_ok());
        assert!(boundary.constrain_strict("../secret").is_err());
        assert!(boundary.constrain_strict("$(whoami)").is_err());
        assert_eq!(boundary.constrain("../secret"), "/app/data");
        assert_eq!(boundary.resolve("docs/file.txt"), "/app/data/docs/file.txt");

        // Construction
        let joined = boundary.join_strict("docs", "report.pdf").expect("test");
        assert_eq!(joined, "/app/data/docs/report.pdf");
        assert!(boundary.join_strict("docs", "../../../etc").is_err());

        // Jail pattern
        let jail = boundary.jail();
        assert_eq!(jail("file.txt"), "/app/data/file.txt");
        assert_eq!(jail("../escape"), "/app/data");

        // Multiple path validation
        assert!(boundary.is_all_within(&["file1.txt", "dir/file2.txt"]));
        assert!(!boundary.is_all_within(&["file1.txt", "../escape"]));

        // Boundary nesting
        assert!(boundary.is_boundary_contained("/app/data/users"));
        assert!(!boundary.is_boundary_contained("/app/other"));

        // Utility functions
        assert_eq!(
            boundary.strip_escape_components("../file.txt").as_ref(),
            "file.txt"
        );
        assert_eq!(boundary.strip_null_bytes("file\0.txt").as_ref(), "file.txt");
    }

    /// Test FilenameBuilder integration
    #[test]
    fn test_filename_builder() {
        let fb = FilenameBuilder::new();

        // Detection
        assert!(fb.is_threat_present("$(cmd).txt"));
        assert!(!fb.is_threat_present("file.txt"));
        assert!(fb.is_path_separators_present("foo/bar.txt"));
        assert!(fb.is_reserved_name("CON"));
        assert!(fb.is_double_extension_present("file.txt.exe"));

        // Extension detection
        assert!(fb.is_extension_present("file.txt"));
        assert_eq!(fb.find_extension("file.txt"), Some("txt"));
        assert_eq!(fb.stem("file.txt"), "file");
        assert!(fb.is_dangerous_extension_present("file.exe"));

        // Validation
        assert!(fb.is_valid("file.txt"));
        assert!(!fb.is_valid("../file.txt"));
        assert!(fb.is_safe("file.txt"));
        assert!(!fb.is_safe("CON"));
        assert!(fb.is_upload_safe("document.pdf"));
        assert!(!fb.is_upload_safe("script.exe"));

        // Sanitization
        assert_eq!(fb.sanitize("../file;rm.txt").expect("test"), "filerm.txt");
        assert!(fb.sanitize_strict("file.txt").is_ok());
        assert!(fb.sanitize_strict("$(cmd).txt").is_err());

        // Shell escaping
        assert_eq!(fb.shell_escape("file.txt"), "'file.txt'");
        assert_eq!(fb.shell_escape("file's.txt"), "'file'\\''s.txt'");

        // Construction
        assert_eq!(fb.set_extension("file.txt", "pdf"), "file.pdf");
        assert_eq!(fb.add_extension("file.txt", "gz"), "file.txt.gz");
        assert_eq!(fb.strip_extension("file.txt"), "file");
        assert_eq!(fb.with_stem("old.txt", "new"), "new.txt");
        assert_eq!(fb.from_parts("doc", "pdf"), "doc.pdf");
        assert_eq!(fb.with_number("file.txt", 1), "file_1.txt");

        // Safe filename generation
        assert_eq!(fb.to_safe_filename(""), "unnamed");
        assert_eq!(fb.to_safe_filename_or("", "default.txt"), "default.txt");
    }
}
