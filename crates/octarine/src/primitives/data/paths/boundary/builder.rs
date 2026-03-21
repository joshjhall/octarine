//! Builder API for boundary operations
//!
//! Provides a fluent builder interface for boundary validation, sanitization,
//! and construction operations on paths.
//!
//! ## Example
//!
//! ```ignore
//! use octarine::primitives::paths::boundary::BoundaryBuilder;
//!
//! let boundary = BoundaryBuilder::new("/app/data");
//!
//! // Validation
//! assert!(boundary.is_within("file.txt"));
//! assert!(!boundary.is_within("../secret"));
//!
//! // Sanitization
//! let safe = boundary.constrain("../etc/passwd");
//! assert_eq!(safe, "/app/data");
//!
//! // Construction
//! let path = boundary.join("docs", "report.pdf").expect("test");
//! assert_eq!(path, "/app/data/docs/report.pdf");
//! ```

use super::{construction, sanitization, validation};
use crate::primitives::types::Problem;

/// Builder for boundary-constrained path operations
///
/// Provides a unified API for all boundary-related path operations:
/// validation, sanitization, and construction.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::boundary::BoundaryBuilder;
///
/// let boundary = BoundaryBuilder::new("/app/data");
///
/// // Check if paths are safe
/// if boundary.is_within(user_input) {
///     // Safe to use
///     let full_path = boundary.resolve(user_input);
/// } else {
///     // Handle escape attempt
///     let escape_depth = boundary.escape_depth(user_input);
///     eprintln!("Path escapes by {} levels", escape_depth);
/// }
/// # let user_input = "safe/path";
/// ```
#[derive(Debug, Clone)]
pub struct BoundaryBuilder {
    boundary: String,
}

impl BoundaryBuilder {
    /// Create a new boundary builder
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// ```
    #[must_use]
    pub fn new(boundary: &str) -> Self {
        Self {
            boundary: boundary.to_string(),
        }
    }

    /// Get the boundary path
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Check if boundary specification is valid
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// assert!(BoundaryBuilder::new("/app/data").is_valid_boundary());
    /// assert!(!BoundaryBuilder::new("").is_valid_boundary());
    /// assert!(!BoundaryBuilder::new("relative").is_valid_boundary());
    /// ```
    #[must_use]
    pub fn is_valid_boundary(&self) -> bool {
        validation::is_valid_boundary(&self.boundary)
    }

    /// Validate boundary specification (strict)
    pub fn validate_boundary(&self) -> Result<(), Problem> {
        validation::validate_boundary_specification_strict(&self.boundary)
    }

    /// Check if path is within the boundary (lenient)
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// assert!(boundary.is_within("file.txt"));
    /// assert!(boundary.is_within("subdir/file.txt"));
    /// assert!(!boundary.is_within("../secret"));
    /// ```
    #[must_use]
    pub fn is_within(&self, path: &str) -> bool {
        validation::is_within_boundary(path, &self.boundary)
    }

    /// Validate path is within boundary (strict)
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// assert!(boundary.validate_within("file.txt").is_ok());
    /// assert!(boundary.validate_within("../secret").is_err());
    /// ```
    pub fn validate_within(&self, path: &str) -> Result<(), Problem> {
        validation::validate_within_boundary_strict(path, &self.boundary)
    }

    /// Check if path would escape the boundary
    #[must_use]
    pub fn would_escape(&self, path: &str) -> bool {
        validation::would_escape_boundary(path, &self.boundary)
    }

    /// Calculate the escape depth of a path
    ///
    /// Returns how many levels the path would escape.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// assert_eq!(boundary.calculate_escape_depth("file.txt"), 0);
    /// assert_eq!(boundary.calculate_escape_depth("../secret"), 1);
    /// assert_eq!(boundary.calculate_escape_depth("../../etc"), 2);
    /// ```
    #[must_use]
    pub fn calculate_escape_depth(&self, path: &str) -> usize {
        validation::calculate_escape_depth(path, &self.boundary)
    }

    /// Calculate the depth of a path within the boundary
    ///
    /// Returns `None` if path escapes the boundary.
    #[must_use]
    pub fn calculate_depth(&self, path: &str) -> Option<usize> {
        validation::calculate_boundary_depth(path, &self.boundary)
    }

    /// Calculate the depth of a path within the boundary (strict)
    pub fn calculate_depth_strict(&self, path: &str) -> Result<usize, Problem> {
        validation::calculate_boundary_depth_strict(path, &self.boundary)
    }

    /// Check if path is at the boundary root (depth 1)
    #[must_use]
    pub fn is_at_root(&self, path: &str) -> bool {
        validation::is_at_boundary_root(path, &self.boundary)
    }

    /// Validate path is at boundary root (strict)
    pub fn validate_at_root(&self, path: &str) -> Result<(), Problem> {
        validation::validate_at_boundary_root_strict(path, &self.boundary)
    }

    /// Check if all paths are within the boundary
    #[must_use]
    pub fn is_all_within(&self, paths: &[&str]) -> bool {
        validation::is_all_within_boundary(paths, &self.boundary)
    }

    /// Validate all paths are within boundary (strict)
    pub fn validate_all_within(&self, paths: &[&str]) -> Result<(), Problem> {
        validation::validate_all_within_boundary_strict(paths, &self.boundary)
    }

    /// Check if this boundary contains another boundary
    #[must_use]
    pub fn is_boundary_contained(&self, inner: &str) -> bool {
        validation::is_boundary_contained(&self.boundary, inner)
    }

    /// Validate boundary nesting (strict)
    pub fn validate_contains(&self, inner: &str) -> Result<(), Problem> {
        validation::validate_boundary_nesting_strict(&self.boundary, inner)
    }

    // ========================================================================
    // Sanitization Methods
    // ========================================================================

    /// Constrain path to boundary (strict)
    ///
    /// Validates and returns the path if safe, or error if it would escape.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// assert!(boundary.constrain_strict("file.txt").is_ok());
    /// assert!(boundary.constrain_strict("../secret").is_err());
    /// assert!(boundary.constrain_strict("$(whoami)").is_err());
    /// ```
    pub fn constrain_strict(&self, path: &str) -> Result<String, Problem> {
        sanitization::constrain_to_boundary_strict(path, &self.boundary)
    }

    /// Constrain path to boundary (lenient)
    ///
    /// Always returns a safe path. Returns boundary if path would escape.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// assert_eq!(boundary.constrain("file.txt"), "/app/data/file.txt");
    /// assert_eq!(boundary.constrain("../secret"), "/app/data");
    /// ```
    #[must_use]
    pub fn constrain(&self, path: &str) -> String {
        sanitization::constrain_to_boundary(path, &self.boundary)
    }

    /// Resolve path within boundary (strict)
    ///
    /// Joins boundary and path, simplifies, and validates.
    pub fn resolve_strict(&self, path: &str) -> Result<String, Problem> {
        sanitization::resolve_within_boundary_strict(path, &self.boundary)
    }

    /// Resolve path within boundary (lenient)
    ///
    /// Always returns a path within the boundary.
    #[must_use]
    pub fn resolve(&self, path: &str) -> String {
        sanitization::resolve_within_boundary(path, &self.boundary)
    }

    /// Create a jail closure (strict)
    ///
    /// Returns a closure that validates paths within this boundary.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// let jail = boundary.jail_strict();
    ///
    /// assert!(jail("file.txt").is_ok());
    /// assert!(jail("../escape").is_err());
    /// ```
    pub fn jail_strict(&self) -> impl Fn(&str) -> Result<String, Problem> + '_ {
        sanitization::create_jail_strict(&self.boundary)
    }

    /// Create a jail closure (lenient)
    ///
    /// Returns a closure that always returns a safe path.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// let jail = boundary.jail();
    ///
    /// assert_eq!(jail("file.txt"), "/app/data/file.txt");
    /// assert_eq!(jail("../escape"), "/app/data");
    /// ```
    pub fn jail(&self) -> impl Fn(&str) -> String + '_ {
        sanitization::create_jail(&self.boundary)
    }

    // ========================================================================
    // Construction Methods
    // ========================================================================

    /// Join paths within boundary (strict)
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app/data");
    /// let result = boundary.join_strict("docs", "report.pdf").expect("test");
    /// assert_eq!(result, "/app/data/docs/report.pdf");
    /// ```
    pub fn join_strict(&self, base: &str, segment: &str) -> Result<String, Problem> {
        construction::join_within_boundary_strict(&self.boundary, base, segment)
    }

    /// Join paths within boundary (lenient)
    ///
    /// Always returns a path within the boundary.
    #[must_use]
    pub fn join(&self, base: &str, segment: &str) -> String {
        construction::join_within_boundary(&self.boundary, base, segment)
    }

    /// Resolve relative path within boundary (strict)
    pub fn resolve_relative_strict(&self, base: &str, path: &str) -> Result<String, Problem> {
        construction::resolve_relative_within_strict(&self.boundary, base, path)
    }

    /// Resolve relative path within boundary (lenient)
    #[must_use]
    pub fn resolve_relative(&self, base: &str, path: &str) -> String {
        construction::resolve_relative_within(&self.boundary, base, path)
    }

    /// Extend with multiple segments (strict)
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::boundary::BoundaryBuilder;
    ///
    /// let boundary = BoundaryBuilder::new("/app");
    /// let result = boundary.extend_strict(&["data", "users", "john"]).expect("test");
    /// assert_eq!(result, "/app/data/users/john");
    /// ```
    pub fn extend_strict(&self, segments: &[&str]) -> Result<String, Problem> {
        construction::extend_within_boundary_strict(&self.boundary, segments)
    }

    /// Extend with multiple segments (lenient)
    #[must_use]
    pub fn extend(&self, segments: &[&str]) -> String {
        construction::extend_within_boundary(&self.boundary, segments)
    }

    /// Get sibling path (strict)
    pub fn sibling_strict(&self, path: &str, sibling_name: &str) -> Result<String, Problem> {
        construction::sibling_within_boundary_strict(&self.boundary, path, sibling_name)
    }

    /// Get sibling path (lenient)
    #[must_use]
    pub fn sibling(&self, path: &str, sibling_name: &str) -> String {
        construction::sibling_within_boundary(&self.boundary, path, sibling_name)
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /// Strip escape components from a path
    ///
    /// Returns the path with `..` and absolute prefixes removed.
    #[must_use]
    pub fn strip_escape_components<'a>(&self, path: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::strip_escape_components(path)
    }

    /// Strip null bytes from a path
    #[must_use]
    pub fn strip_null_bytes<'a>(&self, path: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::strip_null_bytes(path)
    }

    /// Strip control characters from a path
    #[must_use]
    pub fn strip_control_chars<'a>(&self, path: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::strip_control_chars(path)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> BoundaryBuilder {
        BoundaryBuilder::new("/app/data")
    }

    // ------------------------------------------------------------------------
    // Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_valid_boundary() {
        assert!(builder().is_valid_boundary());
        assert!(BoundaryBuilder::new("/").is_valid_boundary());
        assert!(!BoundaryBuilder::new("").is_valid_boundary());
        assert!(!BoundaryBuilder::new("relative").is_valid_boundary());
    }

    #[test]
    fn test_is_within() {
        let b = builder();
        assert!(b.is_within("file.txt"));
        assert!(b.is_within("subdir/file.txt"));
        assert!(b.is_within("a/b/c.txt"));
        assert!(!b.is_within("../secret"));
        assert!(!b.is_within("../../etc/passwd"));
    }

    #[test]
    fn test_validate_within() {
        let b = builder();
        assert!(b.validate_within("file.txt").is_ok());
        assert!(b.validate_within("../secret").is_err());
    }

    #[test]
    fn test_would_escape() {
        let b = builder();
        assert!(!b.would_escape("file.txt"));
        assert!(b.would_escape("../secret"));
    }

    #[test]
    fn test_calculate_escape_depth() {
        let b = builder();
        assert_eq!(b.calculate_escape_depth("file.txt"), 0);
        assert_eq!(b.calculate_escape_depth("../secret"), 1);
        assert_eq!(b.calculate_escape_depth("../../etc"), 2);
        assert_eq!(b.calculate_escape_depth("../../../root"), 3);
    }

    #[test]
    fn test_calculate_depth() {
        let b = builder();
        assert_eq!(b.calculate_depth("file.txt"), Some(1));
        assert_eq!(b.calculate_depth("dir/file.txt"), Some(2));
        assert_eq!(b.calculate_depth("a/b/c"), Some(3));
        assert_eq!(b.calculate_depth("../secret"), None);
    }

    #[test]
    fn test_is_at_root() {
        let b = builder();
        assert!(b.is_at_root("file.txt"));
        assert!(!b.is_at_root("subdir/file.txt"));
        assert!(!b.is_at_root("../outside"));
    }

    #[test]
    fn test_is_all_within() {
        let b = builder();
        assert!(b.is_all_within(&["file1.txt", "dir/file2.txt"]));
        assert!(!b.is_all_within(&["file1.txt", "../escape"]));
    }

    #[test]
    fn test_contains_boundary() {
        let b = builder();
        assert!(b.is_boundary_contained("/app/data/users"));
        assert!(!b.is_boundary_contained("/app/other"));
        assert!(!b.is_boundary_contained("/var"));
    }

    // ------------------------------------------------------------------------
    // Sanitization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_constrain_strict() {
        let b = builder();
        assert!(b.constrain_strict("file.txt").is_ok());
        assert!(b.constrain_strict("../secret").is_err());
        assert!(b.constrain_strict("$(whoami)").is_err());
    }

    #[test]
    fn test_constrain() {
        let b = builder();
        assert_eq!(b.constrain("file.txt"), "/app/data/file.txt");
        assert_eq!(b.constrain("../secret"), "/app/data");
        assert_eq!(b.constrain("$(whoami)"), "/app/data");
    }

    #[test]
    fn test_resolve() {
        let b = builder();
        assert_eq!(b.resolve("docs/file.txt"), "/app/data/docs/file.txt");
        assert_eq!(b.resolve("../escape"), "/app/data");
    }

    #[test]
    fn test_jail() {
        let b = builder();
        let jail = b.jail();
        assert_eq!(jail("file.txt"), "/app/data/file.txt");
        assert_eq!(jail("../escape"), "/app/data");
    }

    #[test]
    fn test_jail_strict() {
        let b = builder();
        let jail = b.jail_strict();
        assert!(jail("file.txt").is_ok());
        assert!(jail("../escape").is_err());
    }

    // ------------------------------------------------------------------------
    // Construction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_join_strict() {
        let b = builder();
        let result = b.join_strict("docs", "file.txt").expect("test");
        assert_eq!(result, "/app/data/docs/file.txt");

        assert!(b.join_strict("docs", "../../../etc").is_err());
    }

    #[test]
    fn test_join() {
        let b = builder();
        assert_eq!(b.join("docs", "file.txt"), "/app/data/docs/file.txt");
        assert!(b.join("docs", "../../../etc").starts_with("/app/data"));
    }

    #[test]
    fn test_resolve_relative_strict() {
        let b = builder();
        let result = b
            .resolve_relative_strict("/app/data/docs", "file.txt")
            .expect("test");
        assert_eq!(result, "/app/data/docs/file.txt");

        let result = b
            .resolve_relative_strict("/app/data/a/b", "../c.txt")
            .expect("test");
        assert_eq!(result, "/app/data/a/c.txt");
    }

    #[test]
    fn test_extend_strict() {
        let b = BoundaryBuilder::new("/app");
        let result = b.extend_strict(&["data", "users", "john"]).expect("test");
        assert_eq!(result, "/app/data/users/john");

        assert!(b.extend_strict(&["..", "..", "etc"]).is_err());
    }

    #[test]
    fn test_extend() {
        let b = BoundaryBuilder::new("/app");
        assert_eq!(b.extend(&["data", "users"]), "/app/data/users");
        assert_eq!(b.extend(&["..", "..", "etc"]), "/app");
    }

    #[test]
    fn test_sibling_strict() {
        let b = builder();
        let result = b
            .sibling_strict("/app/data/old.txt", "new.txt")
            .expect("test");
        assert_eq!(result, "/app/data/new.txt");
    }

    #[test]
    fn test_sibling() {
        let b = builder();
        assert_eq!(
            b.sibling("/app/data/old.txt", "new.txt"),
            "/app/data/new.txt"
        );
    }

    // ------------------------------------------------------------------------
    // Utility Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_strip_escape_components() {
        let b = builder();
        assert_eq!(
            b.strip_escape_components("../file.txt").as_ref(),
            "file.txt"
        );
        assert_eq!(b.strip_escape_components("../../etc").as_ref(), "etc");
    }

    #[test]
    fn test_strip_null_bytes() {
        let b = builder();
        assert_eq!(b.strip_null_bytes("file\0.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_strip_control_chars() {
        let b = builder();
        assert_eq!(b.strip_control_chars("file\nname").as_ref(), "filename");
    }

    // ------------------------------------------------------------------------
    // Getter Test
    // ------------------------------------------------------------------------

    #[test]
    fn test_boundary_getter() {
        let b = builder();
        assert_eq!(b.boundary(), "/app/data");
    }
}
