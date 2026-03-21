//! 1Password reference sanitization
//!
//! Handles op:// references for 1Password CLI integration.

use crate::observe::Problem;

/// Check if a path is a 1Password reference
pub(in crate::data::paths) fn is_op_reference(path: &str) -> bool {
    path.starts_with("op://")
}

/// Sanitize a 1Password reference
///
/// 1Password references follow the format: op://vault/item/field
/// We validate the structure but don't modify the reference.
pub(in crate::data::paths) fn sanitize_op_reference(path: &str) -> Result<String, Problem> {
    if !is_op_reference(path) {
        return Err(Problem::validation(
            "Not a valid 1Password reference (must start with op://)",
        ));
    }

    // Extract the path portion after op://
    let reference = &path[5..]; // Skip "op://"

    if reference.is_empty() {
        return Err(Problem::validation(
            "1Password reference cannot be empty after op://",
        ));
    }

    // Check for dangerous patterns
    if reference.contains("..") {
        return Err(Problem::security(
            "Path traversal not allowed in 1Password references",
        ));
    }

    if reference.contains('\0') {
        return Err(Problem::security(
            "Null bytes not allowed in 1Password references",
        ));
    }

    // Check for shell metacharacters that could cause issues
    let dangerous_chars = ['$', '`', ';', '|', '&', '>', '<', '\n', '\r'];
    for c in dangerous_chars {
        if reference.contains(c) {
            return Err(Problem::security(format!(
                "Character '{}' not allowed in 1Password references",
                c
            )));
        }
    }

    // Validate basic structure: should have at least vault/item
    let parts: Vec<&str> = reference.split('/').collect();
    if parts.len() < 2 {
        return Err(Problem::validation(
            "1Password reference must have at least vault/item (e.g., op://vault/item)",
        ));
    }

    // Validate each part is non-empty
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            // Use saturating_add to avoid clippy arithmetic_side_effects warning
            let position = i.saturating_add(1);
            return Err(Problem::validation(format!(
                "1Password reference has empty component at position {position}",
            )));
        }
    }

    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_op_reference() {
        assert!(is_op_reference("op://vault/item"));
        assert!(is_op_reference("op://vault/item/field"));
        assert!(is_op_reference("op://my-vault/my-item/password"));
        assert!(!is_op_reference("/etc/passwd"));
        assert!(!is_op_reference("file://path"));
        assert!(!is_op_reference("op:/missing-slash"));
    }

    #[test]
    fn test_sanitize_op_reference_valid() {
        assert!(sanitize_op_reference("op://vault/item").is_ok());
        assert!(sanitize_op_reference("op://vault/item/field").is_ok());
        assert!(sanitize_op_reference("op://my-vault/my-item/password").is_ok());
        assert!(sanitize_op_reference("op://Personal/GitHub/token").is_ok());
    }

    #[test]
    fn test_sanitize_op_reference_rejects_traversal() {
        assert!(sanitize_op_reference("op://vault/../other/item").is_err());
        assert!(sanitize_op_reference("op://..").is_err());
    }

    #[test]
    fn test_sanitize_op_reference_rejects_shell_chars() {
        assert!(sanitize_op_reference("op://vault/item;whoami").is_err());
        assert!(sanitize_op_reference("op://vault/$HOME").is_err());
        assert!(sanitize_op_reference("op://vault/`id`").is_err());
    }

    #[test]
    fn test_sanitize_op_reference_rejects_invalid_structure() {
        assert!(sanitize_op_reference("op://").is_err());
        assert!(sanitize_op_reference("op://vault").is_err()); // needs at least vault/item
        assert!(sanitize_op_reference("op://vault//item").is_err()); // empty component
    }

    #[test]
    fn test_sanitize_op_reference_rejects_non_op() {
        assert!(sanitize_op_reference("/etc/passwd").is_err());
        assert!(sanitize_op_reference("file://path").is_err());
    }
}
