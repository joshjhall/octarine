//! Shared patterns for path detection and validation
//!
//! This module provides reusable detection patterns for path security operations.
//! These patterns are used by validation and sanitization layers.
//!
//! # Pattern Categories
//!
//! - **traversal**: Directory traversal detection (`..`, encoded variants, absolute paths)
//! - **injection**: Command injection patterns (`$()`, backticks, metacharacters)
//! - **characters**: Dangerous character detection (null bytes, control characters)
//! - **encoding**: URL encoding attack detection (double encoding)
//! - **platform**: Platform-specific path detection (Windows vs Unix)
//!
//! # Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Detection Only**: Functions return `bool`, not `Result`
//! 3. **Reusable**: Used across validation, sanitization, and conversion layers
//! 4. **No Dependencies**: Only `std` library, no observe module
//!
//! # Security Standards
//!
//! All patterns follow OWASP guidelines and address:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization
//!
//! # Example Usage
//!
//! ```ignore
//! use octarine::primitives::paths::common::patterns::{traversal, injection, characters};
//!
//! // Check for traversal attempts
//! if traversal::is_any_traversal_present(user_path) {
//!     return Err(Problem::validation("Path traversal detected"));
//! }
//!
//! // Check for command injection
//! if injection::is_any_injection_present(user_path) {
//!     return Err(Problem::validation("Command injection detected"));
//! }
//!
//! // Check for dangerous characters
//! if characters::is_dangerous_characters_present(user_path) {
//!     return Err(Problem::validation("Dangerous characters detected"));
//! }
//! ```

pub mod characters;
pub mod encoding;
pub mod injection;
pub mod platform;
pub mod traversal;

// Re-export commonly used functions for convenience
// Note: Some items may be unused currently but are exported for future domain modules
#[allow(unused_imports)]
pub use characters::{
    is_control_characters_present, is_dangerous_characters_present, is_empty,
    is_empty_or_whitespace, is_null_bytes_present, is_whitespace_only,
    is_windows_invalid_chars_present,
};
#[allow(unused_imports)]
pub use encoding::{
    count_encoding_layers, is_encoding_attack_present, is_multiple_encoding_present,
    is_url_encoding_present,
};
#[allow(unused_imports)]
pub use injection::{
    is_any_injection_present, is_any_injection_present_strict, is_command_substitution_present,
    is_redirection_present, is_shell_metacharacters_present, is_variable_expansion_present,
};
#[allow(unused_imports)]
pub use platform::{
    is_absolute, is_backslashes_present, is_drive_letter_present, is_forward_slashes_present,
    is_mixed_separators_present, is_portable, is_relative, is_unc_path, is_unix_style,
    is_windows_style, starts_with_current_dir, starts_with_home_dir, starts_with_parent_dir,
};
#[allow(unused_imports)]
pub use traversal::{
    count_parent_references, is_absolute_path_present, is_any_traversal_present,
    is_encoded_traversal_present, is_parent_references_present,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    /// Comprehensive security pattern test
    /// Tests that common attack vectors are detected
    #[test]
    fn test_common_attack_vectors() {
        // Directory traversal
        assert!(is_any_traversal_present("../../../etc/passwd"));
        assert!(is_any_traversal_present("/etc/passwd"));
        assert!(is_any_traversal_present("..%2f..%2fetc"));

        // Command injection
        assert!(is_any_injection_present("$(whoami)"));
        assert!(is_any_injection_present("`id`"));
        assert!(is_any_injection_present("${HOME}"));
        assert!(is_any_injection_present("file;rm -rf /"));

        // Dangerous characters
        assert!(is_dangerous_characters_present("file\0.txt"));
        assert!(is_dangerous_characters_present("path\n.txt"));

        // Encoding attacks
        assert!(is_encoding_attack_present("%252e%252e")); // Double encoded ..
    }

    /// Test that safe paths pass all checks
    #[test]
    fn test_safe_paths() {
        let safe_paths = [
            "path/to/file.txt",
            "relative/path",
            "file.txt",
            "dir/subdir/file",
            "file-name_with.dots.txt",
            "CamelCase/Path",
        ];

        for path in safe_paths {
            assert!(
                !is_any_traversal_present(path),
                "False positive traversal: {}",
                path
            );
            assert!(
                !is_any_injection_present(path),
                "False positive injection: {}",
                path
            );
            assert!(
                !is_dangerous_characters_present(path),
                "False positive dangerous: {}",
                path
            );
            assert!(
                !is_encoding_attack_present(path),
                "False positive encoding: {}",
                path
            );
        }
    }

    /// Test platform detection consistency
    #[test]
    fn test_platform_detection_consistency() {
        // Windows paths
        assert!(is_windows_style("C:\\Windows"));
        assert!(!is_unix_style("C:\\Windows"));

        // Unix paths
        assert!(is_unix_style("/home/user"));
        assert!(!is_windows_style("/home/user"));

        // Portable paths work on both
        assert!(is_portable("path/to/file"));
        assert!(!is_portable("/absolute/path"));
        assert!(!is_portable("C:\\Windows"));
    }
}
