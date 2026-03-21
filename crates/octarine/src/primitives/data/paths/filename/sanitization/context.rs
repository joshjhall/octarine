//! Context-specific sanitization implementations
//!
//! Provides sanitization functions for each context type:
//! - User files (medium security)
//! - System files (high security)
//! - Secure files (maximum security)
//! - Config files (high security)
//! - Upload files (maximum security)

use super::super::detection;
use crate::primitives::types::Problem;

use super::{SanitizationResult, is_bidi_char};

// ============================================================================
// Context-Specific Sanitization
// ============================================================================

/// Sanitize for user file context
pub fn sanitize_user_file(filename: &str) -> SanitizationResult {
    let mut result = String::with_capacity(filename.len());

    for c in filename.chars() {
        // Skip dangerous characters
        if c == '\0'
            || c.is_ascii_control()
            || c == '/'
            || c == '\\'
            || detection::DANGEROUS_SHELL_CHARS.contains(&c)
        {
            continue;
        }
        // Skip bidirectional control
        if is_bidi_char(c) {
            continue;
        }
        result.push(c);
    }

    // Remove leading .. sequences (parent directory references)
    while result.starts_with("..") {
        result = result[2..].to_string();
        // Also remove any leading dots that remain after ..
        while result.starts_with('.') && !result.starts_with("..") && result.len() > 1 {
            result = result[1..].to_string();
        }
    }

    // Remove embedded .. sequences
    while result.contains("..") {
        result = result.replace("..", ".");
    }

    // Ensure not empty after sanitization
    if result.is_empty() {
        return Err(Problem::validation(
            "Filename is empty after removing dangerous characters",
        ));
    }

    // Check reserved names
    if detection::is_reserved_name(&result) {
        result = format!("_{}", result);
    }

    // Trim leading/trailing spaces (problematic on some filesystems)
    let result = result.trim_matches(|c| c == ' ').to_string();
    if result.is_empty() || result == "." || result == ".." {
        return Err(Problem::validation("Invalid filename after sanitization"));
    }

    Ok(result)
}

/// Sanitize for system file context
pub fn sanitize_system_file(filename: &str) -> SanitizationResult {
    let mut result = String::with_capacity(filename.len());

    for c in filename.chars() {
        // Only allow safe ASCII characters
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            result.push(c);
        }
        // Replace spaces with underscore
        else if c == ' ' {
            result.push('_');
        }
        // Skip everything else
    }

    if result.is_empty() {
        return Err(Problem::validation(
            "Filename is empty after removing non-ASCII characters",
        ));
    }

    // Check reserved names
    if detection::is_reserved_name(&result) {
        result = format!("_{}", result);
    }

    // Ensure doesn't start with dot (hidden file) unless intended
    let result = result.trim_start_matches('.').to_string();
    if result.is_empty() {
        return Err(Problem::validation("Invalid filename after sanitization"));
    }

    Ok(result)
}

/// Sanitize for secure file context
pub fn sanitize_secure_file(filename: &str) -> SanitizationResult {
    let mut result = String::with_capacity(filename.len());
    let mut last_was_separator = false;

    for c in filename.chars() {
        // Only allow most basic characters
        if c.is_ascii_alphanumeric() {
            result.push(c);
            last_was_separator = false;
        } else if (c == '_' || c == '-') && !last_was_separator {
            result.push('_');
            last_was_separator = true;
        } else if c == '.' {
            // Allow single dot for extension
            result.push('.');
            last_was_separator = false;
        }
        // Skip everything else
    }

    if result.is_empty() {
        return Err(Problem::validation(
            "Filename is empty after strict sanitization",
        ));
    }

    // Normalize multiple dots
    while result.contains("..") {
        result = result.replace("..", ".");
    }

    // Check reserved names
    if detection::is_reserved_name(&result) {
        result = format!("file_{}", result);
    }

    // Ensure doesn't start with dot or underscore
    let result = result
        .trim_start_matches('.')
        .trim_start_matches('_')
        .to_string();
    if result.is_empty() {
        return Err(Problem::validation("Invalid filename after sanitization"));
    }

    Ok(result)
}

/// Sanitize for config file context
pub fn sanitize_config_file(filename: &str) -> SanitizationResult {
    let mut result = String::with_capacity(filename.len());

    for c in filename.chars() {
        // Allow alphanumeric, dot, underscore, hyphen
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            result.push(c);
        }
        // Skip everything else including shell chars
    }

    if result.is_empty() {
        return Err(Problem::validation(
            "Filename is empty after removing shell characters",
        ));
    }

    // Check reserved names
    if detection::is_reserved_name(&result) {
        result = format!("cfg_{}", result);
    }

    Ok(result)
}

/// Sanitize for upload file context
pub fn sanitize_upload_file(filename: &str) -> SanitizationResult {
    // Start with secure sanitization
    let result = sanitize_secure_file(filename)?;

    // Additional upload-specific checks
    if detection::is_dangerous_extension_present(&result) {
        return Err(Problem::validation(format!(
            "Dangerous file extension not allowed for uploads: .{}",
            detection::find_extension(&result).unwrap_or("unknown")
        )));
    }

    if detection::is_double_extension_present(&result) {
        return Err(Problem::validation(
            "Double extensions not allowed for uploads",
        ));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_user_file_context() {
        // Allows Unicode
        assert_eq!(sanitize_user_file("文件.txt").expect("test"), "文件.txt");
        assert_eq!(sanitize_user_file("café.txt").expect("test"), "café.txt");

        // Removes dangerous chars
        assert_eq!(
            sanitize_user_file("file;rm.txt").expect("test"),
            "filerm.txt"
        );
    }

    #[test]
    fn test_system_file_context() {
        // ASCII only
        assert_eq!(sanitize_system_file("file.txt").expect("test"), "file.txt");
        assert_eq!(sanitize_system_file("文件.txt").expect("test"), "txt");

        // Spaces to underscores
        assert_eq!(
            sanitize_system_file("my file.txt").expect("test"),
            "my_file.txt"
        );

        // No hidden files
        assert_eq!(sanitize_system_file(".hidden").expect("test"), "hidden");
    }

    #[test]
    fn test_secure_file_context() {
        // Very restrictive
        assert_eq!(sanitize_secure_file("file.txt").expect("test"), "file.txt");
        assert_eq!(
            sanitize_secure_file("file_name.txt").expect("test"),
            "file_name.txt"
        );
        assert_eq!(
            sanitize_secure_file("file name.txt").expect("test"),
            "filename.txt"
        );

        // Reserved name prefixed
        assert_eq!(sanitize_secure_file("CON").expect("test"), "file_CON");
    }

    #[test]
    fn test_config_file_context() {
        assert_eq!(
            sanitize_config_file("app.config").expect("test"),
            "app.config"
        );
        assert_eq!(
            sanitize_config_file("my-app.yaml").expect("test"),
            "my-app.yaml"
        );
        assert_eq!(
            sanitize_config_file("config;rm.txt").expect("test"),
            "configrm.txt"
        );
    }

    #[test]
    fn test_upload_file_context() {
        // Safe files allowed
        assert_eq!(
            sanitize_upload_file("document.pdf").expect("test"),
            "document.pdf"
        );
        assert_eq!(
            sanitize_upload_file("image.jpg").expect("test"),
            "image.jpg"
        );

        // Dangerous extensions rejected
        assert!(sanitize_upload_file("file.exe").is_err());
        assert!(sanitize_upload_file("file.bat").is_err());

        // Double extensions rejected
        assert!(sanitize_upload_file("file.txt.exe").is_err());
    }
}
