//! Boundary domain for path operations
//!
//! This module provides path containment validation, sanitization, and
//! construction within designated boundaries (directory jailing).
//!
//! ## Architecture
//!
//! The boundary domain is organized into three layers:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  BoundaryBuilder                                                │
//! │  (Unified API for all boundary operations)                      │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │   validation    │ │  sanitization   │ │  construction   │
//! │                 │ │                 │ │                 │
//! │ - is_within_*   │ │ - constrain_*   │ │ - join_within_* │
//! │ - validate_*    │ │ - resolve_*     │ │ - extend_*      │
//! │ - escape_*      │ │ - create_jail_* │ │ - sibling_*     │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```
//!
//! ## Security Standards
//!
//! Follows OWASP directory jailing guidelines:
//! - Validate paths stay within designated boundaries
//! - Detect and prevent traversal escape attempts
//! - Validate command injection and dangerous patterns
//! - Support multiple boundary enforcement
//!
//! ## Quick Start
//!
//! ```ignore
//! use octarine::primitives::paths::boundary::BoundaryBuilder;
//!
//! let boundary = BoundaryBuilder::new("/app/data");
//!
//! // Check if path is safe
//! if boundary.is_within(user_input) {
//!     let full_path = boundary.resolve(user_input);
//!     // Use full_path safely
//! } else {
//!     let depth = boundary.escape_depth(user_input);
//!     eprintln!("Path escapes boundary by {} levels", depth);
//! }
//! # let user_input = "safe/path";
//! ```
//!
//! ## Module Functions vs Builder
//!
//! You can use either the module functions directly or the builder API:
//!
//! ```ignore
//! use octarine::primitives::paths::boundary::{validation, sanitization, construction};
//! use octarine::primitives::paths::boundary::BoundaryBuilder;
//!
//! // Using module functions directly
//! let is_safe = validation::is_within_boundary("path", "/app");
//! let safe = sanitization::constrain_to_boundary("../etc", "/app");
//! let joined = construction::join_within_boundary_strict("/app", "", "file.txt");
//!
//! // Using builder (same functionality)
//! let boundary = BoundaryBuilder::new("/app");
//! let is_safe = boundary.is_within("path");
//! let safe = boundary.constrain("../etc");
//! let joined = boundary.join_strict("", "file.txt");
//! ```

pub(crate) mod builder;
pub(crate) mod construction;
pub(crate) mod sanitization;
pub(crate) mod validation;

// Re-export builder for convenience
pub use builder::BoundaryBuilder;

// Re-export result types
pub use construction::ConstructionResult;
pub use sanitization::SanitizationResult;
pub use validation::ValidationResult;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_module_integration() {
        // Validation
        assert!(validation::is_within_boundary("file.txt", "/app"));
        assert!(!validation::is_within_boundary("../secret", "/app"));
        assert!(validation::validate_within_boundary_strict("file.txt", "/app").is_ok());

        // Sanitization
        assert!(sanitization::constrain_to_boundary_strict("file.txt", "/app").is_ok());
        assert!(sanitization::constrain_to_boundary_strict("../secret", "/app").is_err());
        assert_eq!(
            sanitization::constrain_to_boundary("../secret", "/app"),
            "/app"
        );

        // Construction
        let joined =
            construction::join_within_boundary_strict("/app", "docs", "file.txt").expect("test");
        assert_eq!(joined, "/app/docs/file.txt");
    }

    #[test]
    fn test_builder_integration() {
        let boundary = BoundaryBuilder::new("/app/data");

        // Validation
        assert!(boundary.is_within("file.txt"));
        assert!(!boundary.is_within("../secret"));
        assert_eq!(boundary.calculate_escape_depth("../../etc"), 2);
        assert_eq!(boundary.calculate_depth("dir/file.txt"), Some(2));

        // Sanitization
        assert!(boundary.constrain_strict("file.txt").is_ok());
        assert!(boundary.constrain_strict("../secret").is_err());
        assert_eq!(boundary.constrain("../secret"), "/app/data");

        // Construction
        let joined = boundary.join_strict("docs", "report.pdf").expect("test");
        assert_eq!(joined, "/app/data/docs/report.pdf");
    }

    #[test]
    fn test_jail_pattern() {
        let boundary = BoundaryBuilder::new("/app/data");

        // Create jail
        let jail = boundary.jail();

        // Safe paths pass through
        assert_eq!(jail("file.txt"), "/app/data/file.txt");
        assert_eq!(jail("docs/report.pdf"), "/app/data/docs/report.pdf");

        // Escape attempts return boundary
        assert_eq!(jail("../secret"), "/app/data");
        assert_eq!(jail("../../etc/passwd"), "/app/data");

        // Injection attempts return boundary
        assert_eq!(jail("$(whoami)"), "/app/data");
        assert_eq!(jail("file;rm"), "/app/data");
    }

    #[test]
    fn test_strict_jail_pattern() {
        let boundary = BoundaryBuilder::new("/app/data");

        // Create strict jail
        let jail = boundary.jail_strict();

        // Safe paths pass through
        assert!(jail("file.txt").is_ok());
        assert!(jail("docs/report.pdf").is_ok());

        // Escape attempts fail
        assert!(jail("../secret").is_err());
        assert!(jail("../../etc/passwd").is_err());

        // Injection attempts fail
        assert!(jail("$(whoami)").is_err());
        assert!(jail("file;rm").is_err());
    }

    #[test]
    fn test_security_checks() {
        let boundary = BoundaryBuilder::new("/app");

        // Command injection rejected
        assert!(boundary.constrain_strict("$(whoami)").is_err());
        assert!(boundary.constrain_strict("${HOME}").is_err());
        assert!(boundary.constrain_strict("`id`").is_err());
        assert!(boundary.constrain_strict("$VAR").is_err());

        // Shell metacharacters rejected
        assert!(boundary.constrain_strict("file;rm").is_err());
        assert!(boundary.constrain_strict("file|cat").is_err());
        assert!(boundary.constrain_strict("file&bg").is_err());

        // Null bytes rejected
        assert!(boundary.constrain_strict("file\0.txt").is_err());

        // Control characters rejected
        assert!(boundary.constrain_strict("file\nname").is_err());
    }

    #[test]
    fn test_multiple_boundaries() {
        // Test nested boundaries
        let boundaries = &["/app", "/app/data", "/app/data/user"];

        let result =
            sanitization::enforce_multiple_boundaries_strict("file.txt", boundaries).expect("test");
        assert!(result.starts_with("/app/data/user"));

        // Escape attempt fails
        assert!(sanitization::enforce_multiple_boundaries_strict("../escape", boundaries).is_err());
    }

    #[test]
    fn test_boundary_nesting() {
        let outer = BoundaryBuilder::new("/app");

        assert!(outer.is_boundary_contained("/app/data"));
        assert!(outer.is_boundary_contained("/app/data/user"));
        assert!(!outer.is_boundary_contained("/var"));
        assert!(!outer.is_boundary_contained("/app-other"));
    }

    #[test]
    fn test_path_depth() {
        let boundary = BoundaryBuilder::new("/app");

        assert_eq!(boundary.calculate_depth("file.txt"), Some(1));
        assert_eq!(boundary.calculate_depth("dir/file.txt"), Some(2));
        assert_eq!(boundary.calculate_depth("a/b/c/d.txt"), Some(4));
        assert_eq!(boundary.calculate_depth("../escape"), None);
    }

    #[test]
    fn test_boundary_root() {
        let boundary = BoundaryBuilder::new("/app");

        assert!(boundary.is_at_root("file.txt"));
        assert!(boundary.is_at_root("document.pdf"));
        assert!(!boundary.is_at_root("subdir/file.txt"));
        assert!(!boundary.is_at_root("a/b/c.txt"));
    }

    #[test]
    fn test_utility_functions() {
        let boundary = BoundaryBuilder::new("/app");

        // Strip escape components
        assert_eq!(
            boundary.strip_escape_components("../file.txt").as_ref(),
            "file.txt"
        );
        assert_eq!(
            boundary
                .strip_escape_components("../../etc/passwd")
                .as_ref(),
            "etc/passwd"
        );

        // Strip null bytes
        assert_eq!(boundary.strip_null_bytes("file\0.txt").as_ref(), "file.txt");

        // Strip control characters
        assert_eq!(
            boundary.strip_control_chars("file\nname").as_ref(),
            "filename"
        );
    }
}
