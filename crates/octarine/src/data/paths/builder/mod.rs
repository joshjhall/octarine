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

use crate::data::paths::types::{
    FileCategory, PathDetectionResult, PathType, PathValidationResult, Platform,
};
use crate::primitives::data::paths::Platform as PrimitivePlatform;
use crate::security::paths::{PathSanitizationStrategy, SecurityThreat};

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
    // PATH TYPE DETECTION (delegates to CharacteristicBuilder)
    // ========================================================================

    /// Detect the type of a path
    #[must_use]
    pub fn detect_path_type(&self, path: &str) -> PathType {
        CharacteristicBuilder::new().detect_path_type(path)
    }

    /// Detect the platform of a path
    #[must_use]
    pub fn detect_platform(&self, path: &str) -> Platform {
        CharacteristicBuilder::new().detect_platform(path)
    }

    /// Check if path is absolute
    #[must_use]
    pub fn is_absolute(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_absolute(path)
    }

    /// Check if path is relative
    #[must_use]
    pub fn is_relative(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_relative(path)
    }

    /// Check if path is portable
    #[must_use]
    pub fn is_portable(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_portable(path)
    }

    /// Check if path is Unix-style
    #[must_use]
    pub fn is_unix_style(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_unix_path(path)
    }

    /// Check if path is Windows-style
    #[must_use]
    pub fn is_windows_style(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_windows_path(path)
    }

    // ========================================================================
    // FILE TYPE DETECTION (delegates to FiletypeBuilder)
    // ========================================================================

    /// Detect the file category
    #[must_use]
    pub fn detect_file_category(&self, path: &str) -> FileCategory {
        FiletypeBuilder::new().detect(path)
    }

    /// Check if file is an image
    #[must_use]
    pub fn is_image(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_image(path)
    }

    /// Check if file is audio
    #[must_use]
    pub fn is_audio(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_audio(path)
    }

    /// Check if file is video
    #[must_use]
    pub fn is_video(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_video(path)
    }

    /// Check if file is media
    #[must_use]
    pub fn is_media(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_media(path)
    }

    /// Check if file is a document
    #[must_use]
    pub fn is_document(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_document(path)
    }

    /// Check if file is source code
    #[must_use]
    pub fn is_code(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_code(path)
    }

    /// Check if file is a config file
    #[must_use]
    pub fn is_config(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_config(path)
    }

    /// Check if file is an executable
    #[must_use]
    pub fn is_executable(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_executable(path)
    }

    /// Check if file is an archive
    #[must_use]
    pub fn is_archive(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_archive(path)
    }

    /// Check if file is security-sensitive
    #[must_use]
    pub fn is_security_sensitive(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_security_sensitive(path)
    }

    // ========================================================================
    // SECURITY DETECTION (delegates to SecurityBuilder)
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

    /// Detect all security threats
    #[must_use]
    pub fn detect_threats(&self, path: &str) -> Vec<SecurityThreat> {
        SecurityBuilder::new().detect_threats(path)
    }

    /// Check if path has any security threat
    #[must_use]
    pub fn is_threat_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_threat_present(path)
    }

    /// Check if path has traversal
    #[must_use]
    pub fn is_traversal_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_traversal_present(path)
    }

    /// Check if path has encoded traversal
    #[must_use]
    pub fn is_encoded_traversal_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_encoded_traversal_present(path)
    }

    /// Check if path has command injection
    #[must_use]
    pub fn is_command_injection_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_command_injection_present(path)
    }

    /// Check if path has variable expansion
    #[must_use]
    pub fn is_variable_expansion_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_variable_expansion_present(path)
    }

    /// Check if path has shell metacharacters
    #[must_use]
    pub fn is_shell_metacharacters_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_shell_metacharacters_present(path)
    }

    /// Check if path has null bytes
    #[must_use]
    pub fn is_null_bytes_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_null_bytes_present(path)
    }

    /// Check if path has control characters
    #[must_use]
    pub fn is_control_characters_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_control_characters_present(path)
    }

    /// Check if path has double encoding
    #[must_use]
    pub fn is_double_encoding_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_double_encoding_present(path)
    }

    // ========================================================================
    // VALIDATION
    // ========================================================================

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

    // ========================================================================
    // SANITIZATION
    // ========================================================================

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

    // ========================================================================
    // FILENAME OPERATIONS (delegates to FilenameBuilder)
    // ========================================================================

    /// Validate a filename
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the filename:
    /// - Is invalid (empty, too long, or contains invalid characters)
    /// - Is unsafe (contains traversal or dangerous patterns)
    pub fn validate_filename(&self, filename: &str) -> Result<(), Problem> {
        let fb = FilenameBuilder::new();
        if !fb.is_valid(filename) {
            return Err(Problem::validation(format!(
                "Invalid filename: {}",
                filename
            )));
        }
        if !fb.is_safe(filename) {
            return Err(Problem::validation(format!(
                "Unsafe filename: {}",
                filename
            )));
        }
        Ok(())
    }

    /// Validate a filename for uploads
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the filename is not safe for uploads
    /// (contains dangerous extensions, hidden prefixes, or security threats).
    pub fn validate_upload_filename(&self, filename: &str) -> Result<(), Problem> {
        let fb = FilenameBuilder::new();
        if !fb.is_upload_safe(filename) {
            return Err(Problem::validation(format!(
                "Unsafe upload filename: {}",
                filename
            )));
        }
        Ok(())
    }

    /// Sanitize a filename
    ///
    /// Removes dangerous characters and patterns from a filename.
    /// For lenient cleaning that always returns a value, use [`Self::to_safe_filename`].
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the filename cannot be safely sanitized
    /// or would become empty/invalid after removing dangerous content.
    pub fn sanitize_filename(&self, filename: &str) -> Result<String, Problem> {
        FilenameBuilder::new().sanitize(filename)
    }

    /// Get a safe filename
    #[must_use]
    pub fn to_safe_filename(&self, filename: &str) -> String {
        FilenameBuilder::new().to_safe_filename(filename)
    }

    /// Get filename from path
    #[must_use]
    pub fn filename<'a>(&self, path: &'a str) -> &'a str {
        PrimitivePathBuilder::new().filename(path)
    }

    /// Get file extension
    #[must_use]
    pub fn find_extension<'a>(&self, path: &'a str) -> Option<&'a str> {
        PrimitivePathBuilder::new().find_extension(path)
    }

    /// Get filename stem
    #[must_use]
    pub fn stem<'a>(&self, path: &'a str) -> &'a str {
        PrimitivePathBuilder::new().stem(path)
    }

    // ========================================================================
    // PATH CONSTRUCTION
    // ========================================================================

    /// Join two path segments
    ///
    /// Uses the platform set via `for_platform()` or `Platform::Auto` by default.
    #[must_use]
    pub fn join(&self, base: &str, path: &str) -> String {
        let prim_platform: PrimitivePlatform = self.platform.into();
        PrimitivePathBuilder::for_platform(prim_platform).join(base, path)
    }

    /// Join paths with Unix separators
    #[must_use]
    pub fn join_unix(&self, base: &str, path: &str) -> String {
        PrimitivePathBuilder::new().join_unix(base, path)
    }

    /// Join paths with Windows separators
    #[must_use]
    pub fn join_windows(&self, base: &str, path: &str) -> String {
        PrimitivePathBuilder::new().join_windows(base, path)
    }

    /// Get parent directory
    #[must_use]
    pub fn find_parent<'a>(&self, path: &'a str) -> Option<&'a str> {
        PrimitivePathBuilder::new().find_parent(path)
    }

    /// Split path into components
    #[must_use]
    pub fn split<'a>(&self, path: &'a str) -> Vec<&'a str> {
        PrimitivePathBuilder::new().split(path)
    }

    /// Clean path by resolving . and .. components
    #[must_use]
    pub fn clean_path_components(&self, path: &str) -> String {
        PrimitivePathBuilder::new().clean_path(path)
    }

    /// Convert a relative path to absolute by resolving against a base
    #[must_use]
    pub fn to_absolute_path(&self, base: &str, path: &str) -> String {
        PrimitivePathBuilder::new().to_absolute_path(base, path)
    }

    /// Convert an absolute path to a relative path from one location to another
    #[must_use]
    pub fn to_relative_path(&self, from: &str, to: &str) -> String {
        PrimitivePathBuilder::new().to_relative_path(from, to)
    }

    // ========================================================================
    // FORMAT CONVERSION (delegates to FormatBuilder)
    // ========================================================================

    /// Detect the format of a path
    #[must_use]
    pub fn detect_format(&self, path: &str) -> PathFormat {
        FormatBuilder::new().detect(path)
    }

    /// Convert path to a specific format
    #[must_use]
    pub fn convert_format(&self, path: &str, target: PathFormat) -> String {
        FormatBuilder::new().convert(path, target).into_owned()
    }

    /// Convert to Unix format
    #[must_use]
    pub fn to_unix(&self, path: &str) -> String {
        FormatBuilder::new().convert_to_unix(path).into_owned()
    }

    /// Convert to Windows format
    #[must_use]
    pub fn to_windows(&self, path: &str) -> String {
        FormatBuilder::new().convert_to_windows(path).into_owned()
    }

    /// Normalize path
    #[must_use]
    pub fn normalize(&self, path: &str) -> String {
        PrimitivePathBuilder::new().normalize_unix(path)
    }

    /// Convert to WSL path
    #[must_use]
    pub fn to_wsl(&self, path: &str) -> Option<String> {
        FormatBuilder::new().convert_to_wsl(path)
    }

    /// Convert WSL to Windows path
    #[must_use]
    pub fn wsl_to_windows(&self, path: &str) -> Option<String> {
        FormatBuilder::new().wsl_to_windows(path)
    }

    // ========================================================================
    // HOME DIRECTORY (delegates to HomeBuilder)
    // ========================================================================

    /// Check for home reference
    #[must_use]
    pub fn is_home_reference_present(&self, path: &str) -> bool {
        HomeBuilder::new().is_reference_present(path)
    }

    /// Expand home directory
    pub fn expand_home(&self, path: &str) -> Result<String, Problem> {
        HomeBuilder::new().expand(path)
    }

    /// Collapse home directory
    #[must_use]
    pub fn collapse_home(&self, path: &str) -> String {
        HomeBuilder::new().collapse(path)
    }

    // ========================================================================
    // CONTEXT-SPECIFIC (delegates to PathContextBuilder)
    // ========================================================================

    /// Check if env path
    #[must_use]
    pub fn is_env_path(&self, path: &str) -> bool {
        PathContextBuilder::new().is_env_path(path)
    }

    /// Sanitize env path
    pub fn sanitize_env_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_env(path)
    }

    /// Check if SSH path
    #[must_use]
    pub fn is_ssh_path(&self, path: &str) -> bool {
        PathContextBuilder::new().is_ssh_path(path)
    }

    /// Sanitize SSH path
    pub fn sanitize_ssh_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_ssh(path)
    }

    /// Check if credential path
    #[must_use]
    pub fn is_credential_path(&self, path: &str) -> bool {
        PathContextBuilder::new().is_credential_path(path)
    }

    /// Sanitize credential path
    pub fn sanitize_credential_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_credential(path)
    }

    /// Sanitize certificate path
    pub fn sanitize_certificate_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_certificate(path)
    }

    /// Sanitize keystore path
    pub fn sanitize_keystore_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_keystore(path)
    }

    /// Sanitize secret path
    pub fn sanitize_secret_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_secret(path)
    }

    /// Sanitize backup path
    pub fn sanitize_backup_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_backup(path)
    }

    /// Check if op reference
    #[must_use]
    pub fn is_op_reference(&self, path: &str) -> bool {
        PathContextBuilder::new().is_op_reference(path)
    }

    /// Sanitize op reference
    pub fn sanitize_op_reference(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_op(path)
    }

    // ========================================================================
    // PATH BUILDING (delegates to ConstructionBuilder)
    // ========================================================================

    /// Build path from components
    pub fn build_path(&self, base: &str, components: &[&str]) -> Result<String, Problem> {
        ConstructionBuilder::new().build(base, components)
    }

    /// Build absolute path
    pub fn build_absolute_path(&self, base: &str, components: &[&str]) -> Result<String, Problem> {
        ConstructionBuilder::new().build_absolute(base, components)
    }

    /// Build file path
    pub fn build_file_path(&self, directory: &str, filename: &str) -> Result<String, Problem> {
        ConstructionBuilder::new().build_file(directory, filename)
    }

    /// Build temp path
    #[must_use]
    pub fn build_temp_path(&self, filename: &str) -> String {
        ConstructionBuilder::new().temp(filename)
    }

    /// Build config path
    #[must_use]
    pub fn build_config_path(&self, directory: &str, environment: Option<&str>) -> String {
        ConstructionBuilder::new().config(directory, environment)
    }

    /// Join components
    pub fn join_components(&self, components: &[&str]) -> Result<String, Problem> {
        ConstructionBuilder::new().join(components)
    }

    // ========================================================================
    // LENIENT SANITIZATION (delegates to LenientBuilder)
    // ========================================================================

    /// Clean path (lenient)
    #[must_use]
    pub fn clean_path(&self, path: &str) -> String {
        LenientBuilder::new().clean_path(path)
    }

    /// Clean user path (lenient)
    #[must_use]
    pub fn clean_user_path(&self, path: &str) -> String {
        LenientBuilder::new().clean_user_path(path)
    }

    /// Clean filename (lenient)
    #[must_use]
    pub fn clean_filename(&self, filename: &str) -> String {
        LenientBuilder::new().clean_filename(filename)
    }

    /// Clean separators (lenient)
    #[must_use]
    pub fn clean_separators(&self, path: &str) -> String {
        LenientBuilder::new().clean_separators(path)
    }

    // ========================================================================
    // BOUNDARY OPERATIONS
    // ========================================================================

    /// Check if within boundary
    #[must_use]
    pub fn is_within_boundary(&self, path: &str) -> bool {
        if let Some(ref boundary) = self.boundary {
            BoundaryBuilder::new(boundary).is_within(path)
        } else {
            true
        }
    }

    /// Resolve path in boundary
    pub fn resolve_in_boundary(&self, path: &str) -> Result<String, Problem> {
        if let Some(ref boundary) = self.boundary {
            let bb = BoundaryBuilder::new(boundary);
            if !bb.is_within(path) {
                return Err(Problem::validation("Path escapes boundary"));
            }
            Ok(bb.resolve(path))
        } else {
            Ok(path.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

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
