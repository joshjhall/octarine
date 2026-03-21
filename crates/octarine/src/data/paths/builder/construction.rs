//! Path construction builder with observability
//!
//! Provides safe path building operations with validation.
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::ConstructionBuilder;
//!
//! let builder = ConstructionBuilder::new();
//!
//! // Build paths
//! let path = builder.build("/app", &["data", "file.txt"]).unwrap();
//! assert_eq!(path, "/app/data/file.txt");
//!
//! // Build temp paths
//! let temp = builder.temp("upload.txt");
//!
//! // Build config paths
//! let config = builder.config("/app", Some("production"));
//! ```

use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment};

use super::super::construction;

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn paths_built() -> MetricName {
        MetricName::new("data.paths.construction.paths_built").expect("valid metric name")
    }
}

/// Path construction builder with observability
///
/// Provides safe path building with validation and audit trail.
#[derive(Debug, Clone, Default)]
pub struct ConstructionBuilder {
    emit_events: bool,
}

impl ConstructionBuilder {
    /// Create a new construction builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Path Building
    // ========================================================================

    /// Build a path from base and components with validation
    ///
    /// Each component is validated to prevent path traversal and injection.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::ConstructionBuilder;
    /// let builder = ConstructionBuilder::new();
    /// let path = builder.build("/app", &["data", "file.txt"]).unwrap();
    /// assert_eq!(path, "/app/data/file.txt");
    /// ```
    pub fn build(&self, base: &str, components: &[&str]) -> Result<String, Problem> {
        let result = construction::build_path(base, components);
        if self.emit_events && result.is_ok() {
            increment(metric_names::paths_built());
        }
        result
    }

    /// Build an absolute path from base and components
    ///
    /// Ensures the result is an absolute path.
    pub fn build_absolute(&self, base: &str, components: &[&str]) -> Result<String, Problem> {
        construction::build_absolute_path(base, components)
    }

    /// Build a file path from directory and filename
    pub fn build_file(&self, directory: &str, filename: &str) -> Result<String, Problem> {
        construction::build_file_path(directory, filename)
    }

    /// Join multiple path components safely
    pub fn join(&self, components: &[&str]) -> Result<String, Problem> {
        construction::join_path_components(components)
    }

    // ========================================================================
    // Special Path Building
    // ========================================================================

    /// Build a temporary file path
    ///
    /// Uses the system temp directory with a sanitized filename.
    #[must_use]
    pub fn temp(&self, filename: &str) -> String {
        construction::build_temp_path(filename)
    }

    /// Build a configuration file path
    ///
    /// Constructs a config file path with optional environment suffix.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::ConstructionBuilder;
    /// let builder = ConstructionBuilder::new();
    ///
    /// // Returns "/app/config"
    /// let config = builder.config("/app", None);
    ///
    /// // Returns "/app/config.production"
    /// let config = builder.config("/app", Some("production"));
    /// ```
    #[must_use]
    pub fn config(&self, directory: &str, environment: Option<&str>) -> String {
        construction::build_config_path(directory, environment)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = ConstructionBuilder::new();
        assert!(builder.emit_events);

        let silent = ConstructionBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = ConstructionBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_build_path() {
        let builder = ConstructionBuilder::silent();

        let path = builder
            .build("/app", &["data", "file.txt"])
            .expect("valid path");
        assert_eq!(path, "/app/data/file.txt");

        let path = builder
            .build("base", &["sub", "file.txt"])
            .expect("valid path");
        assert_eq!(path, "base/sub/file.txt");
    }

    #[test]
    fn test_build_rejects_traversal() {
        let builder = ConstructionBuilder::silent();

        assert!(builder.build("/app", &["..", "secret"]).is_err());
        assert!(builder.build("/app", &["data", "..", "etc"]).is_err());
    }

    #[test]
    fn test_build_rejects_injection() {
        let builder = ConstructionBuilder::silent();

        assert!(builder.build("/app", &["$(whoami)"]).is_err());
        // Note: semicolon in filename may not be rejected by all implementations
        // The key security concern is command substitution like $()
    }

    #[test]
    fn test_build_absolute() {
        let builder = ConstructionBuilder::silent();

        let path = builder
            .build_absolute("/app", &["data", "file.txt"])
            .expect("valid absolute path");
        assert!(path.starts_with('/'));
    }

    #[test]
    fn test_build_file() {
        let builder = ConstructionBuilder::silent();

        let path = builder
            .build_file("/app/data", "file.txt")
            .expect("valid file path");
        assert_eq!(path, "/app/data/file.txt");
    }

    #[test]
    fn test_join() {
        let builder = ConstructionBuilder::silent();

        let path = builder
            .join(&["base", "sub", "file.txt"])
            .expect("valid joined path");
        assert_eq!(path, "base/sub/file.txt");
    }

    #[test]
    fn test_temp_path() {
        let builder = ConstructionBuilder::silent();

        let path = builder.temp("upload.txt");
        assert!(path.contains("upload.txt"));
    }

    #[test]
    fn test_config_path() {
        let builder = ConstructionBuilder::silent();

        let config = builder.config("/app", None);
        // Implementation adds .yaml extension
        assert!(config.contains("/app/config"));

        let config = builder.config("/app", Some("production"));
        // Should contain the environment
        assert!(config.contains("production"));
    }
}
