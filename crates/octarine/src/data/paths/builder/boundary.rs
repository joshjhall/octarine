//! Boundary operations builder with observability
//!
//! Wraps `primitives::data::paths::BoundaryBuilder` with observe instrumentation.
//!
//! Provides directory jailing operations to ensure paths stay within a boundary.
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::BoundaryBuilder;
//!
//! let boundary = BoundaryBuilder::new("/app/data");
//!
//! // Validation
//! assert!(boundary.is_within("file.txt"));
//! assert!(!boundary.is_within("../secret"));
//!
//! // Resolution
//! let full = boundary.resolve("file.txt");
//! assert_eq!(full, "/app/data/file.txt");
//!
//! // Jailing
//! let safe = boundary.constrain("../escape");
//! assert_eq!(safe, "/app/data");
//! ```

use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{MetricName, record};
use crate::primitives::data::paths::BoundaryBuilder as PrimitiveBoundaryBuilder;

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn validate_ms() -> MetricName {
        MetricName::new("data.paths.boundary.validate_ms").expect("valid metric name")
    }

    pub fn constrain_ms() -> MetricName {
        MetricName::new("data.paths.boundary.constrain_ms").expect("valid metric name")
    }
}

/// Boundary operations builder with observability
///
/// Provides directory jailing and boundary validation with audit trail.
#[derive(Debug, Clone)]
pub struct BoundaryBuilder {
    boundary: String,
    emit_events: bool,
}

impl BoundaryBuilder {
    /// Create a new boundary builder with observe events enabled
    #[must_use]
    pub fn new(boundary: impl Into<String>) -> Self {
        Self {
            boundary: boundary.into(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent(boundary: impl Into<String>) -> Self {
        Self {
            boundary: boundary.into(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Get the boundary path
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Check if path is within the boundary
    #[must_use]
    pub fn is_within(&self, path: &str) -> bool {
        PrimitiveBoundaryBuilder::new(&self.boundary).is_within(path)
    }

    /// Validate a path is within the boundary
    ///
    /// Returns `Ok(())` if the path is within the boundary, `Err` if it escapes.
    /// This is the primary boundary validation method per Issue #182 naming conventions.
    pub fn validate_path_in_boundary(&self, path: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = PrimitiveBoundaryBuilder::new(&self.boundary).constrain_strict(path);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result.is_err() {
                observe::warn(
                    "boundary_violation",
                    format!("Path '{}' violates boundary '{}'", path, self.boundary),
                );
            }
        }

        result.map(|_| ())
    }

    /// Check if all paths are within boundary
    #[must_use]
    pub fn is_all_within(&self, paths: &[&str]) -> bool {
        PrimitiveBoundaryBuilder::new(&self.boundary).is_all_within(paths)
    }

    /// Calculate escape depth (how many levels path tries to escape)
    #[must_use]
    pub fn calculate_escape_depth(&self, path: &str) -> usize {
        PrimitiveBoundaryBuilder::new(&self.boundary).calculate_escape_depth(path)
    }

    /// Calculate depth within boundary
    #[must_use]
    pub fn calculate_depth(&self, path: &str) -> Option<usize> {
        PrimitiveBoundaryBuilder::new(&self.boundary).calculate_depth(path)
    }

    /// Calculate depth strictly (returns error if path escapes)
    pub fn calculate_depth_strict(&self, path: &str) -> Result<usize, Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).calculate_depth_strict(path)
    }

    /// Check if this boundary is valid
    #[must_use]
    pub fn is_valid_boundary(&self) -> bool {
        PrimitiveBoundaryBuilder::new(&self.boundary).is_valid_boundary()
    }

    /// Validate boundary specification
    pub fn validate_boundary(&self) -> Result<(), Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).validate_boundary()
    }

    /// Validate that path is within boundary
    pub fn validate_within(&self, path: &str) -> Result<(), Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).validate_within(path)
    }

    /// Check if path would escape boundary
    #[must_use]
    pub fn would_escape(&self, path: &str) -> bool {
        PrimitiveBoundaryBuilder::new(&self.boundary).would_escape(path)
    }

    /// Check if path is at boundary root
    #[must_use]
    pub fn is_at_root(&self, path: &str) -> bool {
        PrimitiveBoundaryBuilder::new(&self.boundary).is_at_root(path)
    }

    /// Validate that path is at boundary root
    pub fn validate_at_root(&self, path: &str) -> Result<(), Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).validate_at_root(path)
    }

    /// Validate that all paths are within boundary
    pub fn validate_all_within(&self, paths: &[&str]) -> Result<(), Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).validate_all_within(paths)
    }

    /// Validate that this boundary contains another
    pub fn validate_contains(&self, inner: &str) -> Result<(), Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).validate_contains(inner)
    }

    // ========================================================================
    // Sanitization Methods
    // ========================================================================

    /// Constrain path to boundary (lenient)
    ///
    /// If path escapes, returns the boundary itself.
    #[must_use]
    pub fn constrain(&self, path: &str) -> String {
        let start = Instant::now();
        let result = PrimitiveBoundaryBuilder::new(&self.boundary).constrain(path);

        if self.emit_events {
            record(
                metric_names::constrain_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result == self.boundary && !path.is_empty() {
                observe::info(
                    "path_constrained",
                    format!("Path '{}' constrained to boundary", path),
                );
            }
        }

        result
    }

    /// Constrain path strictly - returns error if escape attempted
    pub fn constrain_strict(&self, path: &str) -> Result<String, Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).constrain_strict(path)
    }

    // ========================================================================
    // Resolution Methods
    // ========================================================================

    /// Resolve path within boundary
    ///
    /// Returns full path: boundary + path
    #[must_use]
    pub fn resolve(&self, path: &str) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary).resolve(path)
    }

    /// Join paths within boundary (strict)
    pub fn join_strict(&self, base: &str, path: &str) -> Result<String, Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).join_strict(base, path)
    }

    /// Join paths within boundary (lenient)
    #[must_use]
    pub fn join(&self, base: &str, path: &str) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary).join(base, path)
    }

    /// Resolve path strictly within boundary
    pub fn resolve_strict(&self, path: &str) -> Result<String, Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).resolve_strict(path)
    }

    /// Resolve relative path strictly within boundary
    pub fn resolve_relative_strict(&self, base: &str, path: &str) -> Result<String, Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).resolve_relative_strict(base, path)
    }

    /// Resolve relative path within boundary (lenient)
    #[must_use]
    pub fn resolve_relative(&self, base: &str, path: &str) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary).resolve_relative(base, path)
    }

    /// Extend boundary with segments (strict)
    pub fn extend_strict(&self, segments: &[&str]) -> Result<String, Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).extend_strict(segments)
    }

    /// Extend boundary with segments (lenient)
    #[must_use]
    pub fn extend(&self, segments: &[&str]) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary).extend(segments)
    }

    /// Get sibling path strictly within boundary
    pub fn sibling_strict(&self, path: &str, sibling_name: &str) -> Result<String, Problem> {
        PrimitiveBoundaryBuilder::new(&self.boundary).sibling_strict(path, sibling_name)
    }

    /// Get sibling path within boundary (lenient)
    #[must_use]
    pub fn sibling(&self, path: &str, sibling_name: &str) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary).sibling(path, sibling_name)
    }

    /// Create a jail function for this boundary
    ///
    /// Returns a closure that constrains any path to the boundary.
    pub fn jail(&self) -> impl Fn(&str) -> String + '_ {
        move |path| self.constrain(path)
    }

    /// Create a strict jail function for this boundary
    ///
    /// Returns a closure that returns an error if path escapes.
    pub fn jail_strict(&self) -> impl Fn(&str) -> Result<String, Problem> + '_ {
        move |path| self.constrain_strict(path)
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /// Check if this boundary contains another boundary
    #[must_use]
    pub fn is_boundary_contained(&self, other: &str) -> bool {
        PrimitiveBoundaryBuilder::new(&self.boundary).is_boundary_contained(other)
    }

    /// Strip escape components from path
    #[must_use]
    pub fn strip_escape_components(&self, path: &str) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary)
            .strip_escape_components(path)
            .into_owned()
    }

    /// Strip null bytes from path
    #[must_use]
    pub fn strip_null_bytes(&self, path: &str) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary)
            .strip_null_bytes(path)
            .into_owned()
    }

    /// Strip control characters from path
    #[must_use]
    pub fn strip_control_chars(&self, path: &str) -> String {
        PrimitiveBoundaryBuilder::new(&self.boundary)
            .strip_control_chars(path)
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = BoundaryBuilder::new("/app/data");
        assert!(builder.emit_events);

        let silent = BoundaryBuilder::silent("/app/data");
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = BoundaryBuilder::new("/app/data").with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_boundary_validation() {
        let boundary = BoundaryBuilder::silent("/app/data");

        assert!(boundary.is_within("file.txt"));
        assert!(boundary.is_within("subdir/file.txt"));
        assert!(!boundary.is_within("../secret"));
        assert!(!boundary.is_within("../../etc/passwd"));

        assert!(boundary.validate_path_in_boundary("file.txt").is_ok());
        assert!(boundary.validate_path_in_boundary("../escape").is_err());
    }

    #[test]
    fn test_boundary_constrain() {
        let boundary = BoundaryBuilder::new("/app/data");

        assert_eq!(boundary.constrain("file.txt"), "/app/data/file.txt");
        assert_eq!(boundary.constrain("../secret"), "/app/data");
    }

    #[test]
    fn test_boundary_resolve() {
        let boundary = BoundaryBuilder::new("/app/data");

        assert_eq!(boundary.resolve("file.txt"), "/app/data/file.txt");
        assert_eq!(
            boundary.resolve("docs/report.pdf"),
            "/app/data/docs/report.pdf"
        );
    }

    #[test]
    fn test_boundary_depth() {
        let boundary = BoundaryBuilder::new("/app/data");

        assert_eq!(boundary.calculate_escape_depth("../secret"), 1);
        assert_eq!(boundary.calculate_escape_depth("../../etc"), 2);
        assert_eq!(boundary.calculate_depth("file.txt"), Some(1));
        assert_eq!(boundary.calculate_depth("dir/file.txt"), Some(2));
    }

    #[test]
    fn test_boundary_jail() {
        let boundary = BoundaryBuilder::new("/app/data");
        let jail = boundary.jail();

        assert_eq!(jail("file.txt"), "/app/data/file.txt");
        assert_eq!(jail("../escape"), "/app/data");
    }
}
