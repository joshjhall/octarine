//! Path operations builders with observability
//!
//! This module provides builders for all path operations, wrapping
//! `primitives::data::paths` with observe instrumentation.
//!
//! # Builder Organization
//!
//! Each builder focuses on a specific domain:
//!
//! - [`SecurityBuilder`] - Security detection, validation, and sanitization
//! - [`BoundaryBuilder`] - Directory jailing and boundary validation
//! - [`FilenameBuilder`] - Filename operations (detection, validation, sanitization, construction)
//! - [`CharacteristicBuilder`] - Path type and platform detection
//! - [`FiletypeBuilder`] - File category detection
//! - [`FormatBuilder`] - Format detection and conversion
//! - [`HomeBuilder`] - Home directory expansion and collapse
//! - [`PathContextBuilder`] - Context-specific sanitization (env, ssh, credential, op)
//! - [`ConstructionBuilder`] - Safe path building
//! - [`LenientBuilder`] - Lenient sanitization (always returns a value)
//!
//! # Unified PathBuilder
//!
//! [`PathBuilder`] provides a unified API that delegates to specialized builders.
//! Use it when you need multiple types of operations or prefer a single entry point.
//!
//! Methods on `PathBuilder` are split across files in the `path_builder/`
//! subdirectory by concern (characteristic, filetype, security, filename,
//! construction, format, home, context, building, lenient, boundary).
//! Constructors and the methods that emit metrics directly (`detect`,
//! `is_safe`, `validate_detailed`, `validate_path`, `sanitize`) stay in
//! this file so the `define_metrics!`-generated `metric_names` module
//! remains in scope.
//!
//! # Examples
//!
//! ## Using Specialized Builders
//!
//! ```
//! use octarine::data::paths::{SecurityBuilder, FilenameBuilder};
//!
//! // Security operations
//! let security = SecurityBuilder::new();
//! if security.is_traversal_present("../secret") {
//!     // Handle threat
//! }
//!
//! // Filename operations
//! let fb = FilenameBuilder::new();
//! let safe = fb.sanitize("dangerous_file.txt").unwrap();
//! ```
//!
//! ## Using PathBuilder
//!
//! ```
//! use octarine::data::paths::PathBuilder;
//!
//! let builder = PathBuilder::new();
//!
//! // Detection
//! let path_type = builder.detect_path_type("/etc/passwd");
//!
//! // Validation
//! builder.validate_path("safe/path").unwrap();
//!
//! // Sanitization
//! let clean = builder.sanitize("file.txt").unwrap();
//! ```

// Specialized builders (security is now in crate::security::paths)
mod boundary;
mod characteristic;
mod construction;
mod context;
mod filename;
mod filetype;
mod format;
mod home;
mod lenient;

// PathBuilder method clusters, organized by concern
mod path_builder;

// Re-export all specialized builders
pub use boundary::BoundaryBuilder;
pub use characteristic::CharacteristicBuilder;
pub use construction::ConstructionBuilder;
pub use context::PathContextBuilder;
pub use filename::FilenameBuilder;
pub use filetype::FiletypeBuilder;
pub use format::{FormatBuilder, PathFormat};
pub use home::HomeBuilder;
pub use lenient::LenientBuilder;

// SecurityBuilder is re-exported from its canonical location in security::paths
use crate::security::paths::SecurityBuilder;

use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{increment_by, record};
use crate::primitives::data::paths::PathBuilder as PrimitivePathBuilder;

use crate::data::paths::types::{PathDetectionResult, PathValidationResult, Platform};
use crate::security::paths::PathSanitizationStrategy;

crate::define_metrics! {
    detect_ms => "data.paths.detect_ms",
    validate_ms => "data.paths.validate_ms",
    validated => "data.paths.validated",
}

/// Unified path operations builder with observability
///
/// Provides a single entry point for all path operations, delegating to
/// specialized builders internally.
///
/// # Examples
///
/// ```
/// use octarine::data::paths::PathBuilder;
///
/// let builder = PathBuilder::new();
///
/// // Detection
/// let path_type = builder.detect_path_type("/etc/passwd");
/// let threats = builder.detect_threats("../$(cmd)");
///
/// // Validation
/// builder.validate_path("safe/path").unwrap();
///
/// // Sanitization
/// let clean = builder.sanitize("file.txt").unwrap();
///
/// // With boundary
/// let jailed = PathBuilder::new().boundary("/app/data");
/// jailed.validate_path("file.txt").unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct PathBuilder {
    boundary: Option<String>,
    platform: Platform,
    emit_events: bool,
}

impl PathBuilder {
    /// Create a new PathBuilder with auto platform detection and observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            boundary: None,
            platform: Platform::Auto,
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            boundary: None,
            platform: Platform::Auto,
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Create PathBuilder for specific platform
    ///
    /// This affects platform-dependent operations like `join()`.
    #[must_use]
    pub fn for_platform(platform: Platform) -> Self {
        Self {
            boundary: None,
            platform,
            emit_events: true,
        }
    }

    /// Set a boundary directory for path operations
    ///
    /// When set, validation and sanitization operations will enforce
    /// that paths remain within this boundary (directory jailing).
    #[must_use]
    pub fn boundary(mut self, path: impl Into<String>) -> Self {
        self.boundary = Some(path.into());
        self
    }

    /// Create a boundary builder for directory jailing operations
    #[must_use]
    pub fn with_boundary(&self, boundary: &str) -> BoundaryBuilder {
        BoundaryBuilder::new(boundary)
    }

    // ========================================================================
    // METRIC-EMITTING METHODS
    //
    // These stay in this file because they reference the file-local
    // `metric_names` module generated by `define_metrics!` above. Pure
    // delegators live in submodules under `path_builder/`.
    // ========================================================================

    /// Perform comprehensive path detection
    #[must_use]
    pub fn detect(&self, path: &str) -> PathDetectionResult {
        let start = Instant::now();
        let result = PrimitivePathBuilder::new().detect(path);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if !result.threats.is_empty() {
                observe::warn(
                    "path_threats_detected",
                    format!("Security threats detected: {}", result.threats.len()),
                );
            }
        }

        result.into()
    }

    /// Check if path is safe
    #[must_use]
    pub fn is_safe(&self, path: &str) -> bool {
        let result = if let Some(ref boundary) = self.boundary {
            BoundaryBuilder::silent(boundary).is_within(path)
                && SecurityBuilder::silent().is_secure(path)
        } else {
            SecurityBuilder::silent().is_secure(path)
        };

        if self.emit_events {
            increment_by(metric_names::validated(), 1);
        }
        result
    }

    /// Validate path with detailed results
    ///
    /// Returns a `PathValidationResult` with detailed validation information.
    /// For simple pass/fail validation, use [`Self::validate_path`] instead.
    #[must_use]
    pub fn validate_detailed(&self, path: &str) -> PathValidationResult {
        let start = Instant::now();
        let result = PrimitivePathBuilder::new().validate(path);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result.into()
    }

    /// Validate a path - rejects any security threats
    ///
    /// Returns `Ok(())` if the path is safe, `Err` if it contains threats.
    /// For detailed validation results, use [`Self::validate_detailed`].
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the path:
    /// - Contains path traversal patterns (e.g., `..`)
    /// - Contains null bytes or control characters
    /// - Escapes the configured boundary (if set)
    /// - Contains other security threats
    pub fn validate_path(&self, path: &str) -> Result<(), Problem> {
        if let Some(ref boundary) = self.boundary {
            BoundaryBuilder::new(boundary).validate_path_in_boundary(path)?;
        }
        SecurityBuilder::new().validate_path(path)
    }

    /// Sanitize a path by removing threats
    ///
    /// Cleans the path by removing traversal patterns and dangerous characters.
    /// For lenient cleaning, use [`Self::to_safe_filename`] on the filename.
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if:
    /// - The path contains irredeemable threats that cannot be safely removed
    /// - The sanitized result would be empty or invalid
    /// - Boundary constraints cannot be satisfied (if boundary is set)
    pub fn sanitize(&self, path: &str) -> Result<String, Problem> {
        if let Some(ref boundary) = self.boundary {
            let constrained = BoundaryBuilder::new(boundary).constrain(path);
            SecurityBuilder::new().sanitize(&constrained)
        } else {
            SecurityBuilder::new().sanitize(path)
        }
    }

    /// Sanitize with a specific strategy
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the path cannot be sanitized using
    /// the specified strategy, or if the result would be empty/invalid.
    pub fn sanitize_with(
        &self,
        path: &str,
        strategy: PathSanitizationStrategy,
    ) -> Result<String, Problem> {
        SecurityBuilder::new().sanitize_with(path, strategy)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::data::paths::types::PathType;

    #[test]
    fn test_builder_creation() {
        let builder = PathBuilder::new();
        assert!(builder.emit_events);

        let silent = PathBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = PathBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_path_builder_detection() {
        let builder = PathBuilder::silent();

        assert_eq!(
            builder.detect_path_type("/etc/passwd"),
            PathType::UnixAbsolute
        );
        assert_eq!(
            builder.detect_path_type("C:\\Windows"),
            PathType::WindowsAbsolute
        );
        assert!(builder.is_traversal_present("../secret"));
        assert!(builder.is_command_injection_present("$(cmd)"));
    }

    #[test]
    fn test_path_builder_validation() {
        let builder = PathBuilder::new();

        assert!(builder.is_safe("safe/path.txt"));
        assert!(!builder.is_safe("../secret"));
        assert!(builder.validate_path("safe/path").is_ok());
        assert!(builder.validate_path("../secret").is_err());
    }

    #[test]
    fn test_path_builder_sanitization() {
        let builder = PathBuilder::new();

        let clean = builder.sanitize("../etc/passwd").expect("should sanitize");
        assert!(!clean.contains(".."));
    }

    #[test]
    fn test_path_builder_with_boundary() {
        let builder = PathBuilder::new().boundary("/app/data");

        assert!(builder.is_within_boundary("file.txt"));
        assert!(!builder.is_within_boundary("../secret"));
        assert!(builder.validate_path("file.txt").is_ok());
        assert!(builder.validate_path("../escape").is_err());
    }
}
