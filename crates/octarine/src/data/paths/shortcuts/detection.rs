//! Detection shortcuts
//!
//! Convenience functions for path detection operations.

use crate::primitives::security::paths::SecurityBuilder;

use super::super::PathBuilder;
use super::super::types::{FileCategory, PathDetectionResult, PathType, Platform};

// ============================================================
// DETECTION SHORTCUTS
// ============================================================

/// Perform comprehensive path detection
///
/// Returns detailed information about path type, threats, and file category.
pub fn detect_path(path: &str) -> PathDetectionResult {
    PathBuilder::new().detect(path)
}

/// Detect the path type (Unix absolute, Windows, etc.)
pub fn detect_path_type(path: &str) -> PathType {
    PathBuilder::new().detect_path_type(path)
}

/// Detect the platform of a path
pub fn detect_platform(path: &str) -> Platform {
    PathBuilder::new().detect_platform(path)
}

/// Detect the file category from extension
pub fn detect_file_category(path: &str) -> FileCategory {
    PathBuilder::new().detect_file_category(path)
}

/// Check if path is safe (no security threats)
pub fn is_safe_path(path: &str) -> bool {
    PathBuilder::new().is_safe(path)
}

/// Check if path has any security threat
pub fn is_path_threat_present(path: &str) -> bool {
    PathBuilder::new().is_threat_present(path)
}

/// Check if path has path traversal (../)
pub fn is_path_traversal_present(path: &str) -> bool {
    PathBuilder::new().is_traversal_present(path)
}

/// Check if path has command injection patterns
pub fn is_command_injection_present(path: &str) -> bool {
    PathBuilder::new().is_command_injection_present(path)
}

/// Check if path has variable expansion ($VAR, ${VAR})
pub fn is_variable_expansion_present(path: &str) -> bool {
    SecurityBuilder::new().is_variable_expansion_present(path)
}

/// Check if path has shell metacharacters
pub fn is_shell_metacharacters_present(path: &str) -> bool {
    SecurityBuilder::new().is_shell_metacharacters_present(path)
}

/// Check if path has null bytes
pub fn is_null_bytes_present(path: &str) -> bool {
    SecurityBuilder::new().is_null_bytes_present(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_detection_shortcuts() {
        assert!(is_path_traversal_present("../../../etc/passwd"));
        assert!(is_command_injection_present("$(whoami)"));
        assert!(!is_path_threat_present("safe/path.txt"));
        assert!(is_safe_path("safe/path.txt"));
    }
}
