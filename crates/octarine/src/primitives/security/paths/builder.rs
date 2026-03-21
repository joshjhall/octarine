//! Builder API for path security operations
//!
//! Provides a fluent builder interface for security detection, validation,
//! and sanitization operations on paths.
//!
//! ## Example
//!
//! ```ignore
//! use octarine::primitives::paths::security::SecurityBuilder;
//! use octarine::primitives::paths::types::PathSanitizationStrategy;
//!
//! let security = SecurityBuilder::new();
//!
//! // Detection
//! assert!(security.is_threat_present("../../../etc/passwd"));
//! let threats = security.detect_threats("../$(whoami)");
//! assert!(!threats.is_empty());
//!
//! // Validation
//! assert!(security.is_secure("safe/path.txt"));
//! assert!(security.validate_path("safe/path.txt").is_ok());
//!
//! // Sanitization
//! let clean = security.sanitize("../etc/passwd").expect("test");
//! assert!(!clean.contains(".."));
//! ```

use super::{detection, sanitization, validation};
use crate::primitives::data::paths::types::{PathSanitizationStrategy, SecurityThreat};
use crate::primitives::types::Problem;

/// Builder for path security operations
///
/// Provides a unified API for all security-related path operations:
/// detection, validation, and sanitization.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::SecurityBuilder;
///
/// let security = SecurityBuilder::new();
///
/// // Quick threat check
/// if security.is_threat_present(user_input) {
///     // Handle malicious input
/// }
///
/// // Or get detailed threats
/// let threats = security.detect_threats(user_input);
/// for threat in &threats {
///     println!("Detected: {}", threat);
/// }
/// # let user_input = "safe";
/// ```
#[derive(Debug, Clone, Default)]
pub struct SecurityBuilder;

impl SecurityBuilder {
    /// Create a new security builder
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    ///
    /// let security = SecurityBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Detect all security threats in a path
    ///
    /// Returns a vector of all detected threats.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    /// use octarine::primitives::paths::types::SecurityThreat;
    ///
    /// let security = SecurityBuilder::new();
    /// let threats = security.detect_threats("../$(whoami)");
    ///
    /// assert!(threats.contains(&SecurityThreat::Traversal));
    /// assert!(threats.contains(&SecurityThreat::CommandInjection));
    /// ```
    #[must_use]
    pub fn detect_threats(&self, path: &str) -> Vec<SecurityThreat> {
        detection::detect_threats(path)
    }

    /// Check if path has any security threat
    ///
    /// Quick boolean check for any threat.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    ///
    /// let security = SecurityBuilder::new();
    /// assert!(security.is_threat_present("../secret"));
    /// assert!(!security.is_threat_present("safe/path.txt"));
    /// ```
    #[must_use]
    pub fn is_threat_present(&self, path: &str) -> bool {
        detection::is_threat_present(path)
    }

    /// Check for traversal attacks
    #[must_use]
    pub fn is_traversal_present(&self, path: &str) -> bool {
        detection::is_traversal_present(path)
    }

    /// Check for encoded traversal attacks
    #[must_use]
    pub fn is_encoded_traversal_present(&self, path: &str) -> bool {
        detection::is_encoded_traversal_present(path)
    }

    /// Check for any traversal (basic, encoded, or absolute path)
    #[must_use]
    pub fn is_any_traversal_present(&self, path: &str) -> bool {
        detection::is_any_traversal_present(path)
    }

    /// Check for command injection
    #[must_use]
    pub fn is_command_injection_present(&self, path: &str) -> bool {
        detection::is_command_injection_present(path)
    }

    /// Check for variable expansion
    #[must_use]
    pub fn is_variable_expansion_present(&self, path: &str) -> bool {
        detection::is_variable_expansion_present(path)
    }

    /// Check for shell metacharacters
    #[must_use]
    pub fn is_shell_metacharacters_present(&self, path: &str) -> bool {
        detection::is_shell_metacharacters_present(path)
    }

    /// Check for any injection (command, variable, metacharacters)
    #[must_use]
    pub fn is_injection_present(&self, path: &str) -> bool {
        detection::is_injection_present(path)
    }

    /// Check for null bytes
    #[must_use]
    pub fn is_null_bytes_present(&self, path: &str) -> bool {
        detection::is_null_bytes_present(path)
    }

    /// Check for control characters
    #[must_use]
    pub fn is_control_characters_present(&self, path: &str) -> bool {
        detection::is_control_characters_present(path)
    }

    /// Check for dangerous characters (null bytes or control chars)
    #[must_use]
    pub fn is_dangerous_characters_present(&self, path: &str) -> bool {
        detection::is_dangerous_characters_present(path)
    }

    /// Check for double encoding
    #[must_use]
    pub fn is_double_encoding_present(&self, path: &str) -> bool {
        detection::is_double_encoding_present(path)
    }

    /// Check if path is absolute
    #[must_use]
    pub fn is_absolute(&self, path: &str) -> bool {
        detection::is_absolute_path_present(path)
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Check if path is secure (lenient)
    ///
    /// Returns `true` if no security threats detected.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    ///
    /// let security = SecurityBuilder::new();
    /// assert!(security.is_secure("safe/path.txt"));
    /// assert!(!security.is_secure("../secret"));
    /// ```
    #[must_use]
    pub fn is_secure(&self, path: &str) -> bool {
        validation::validate_secure(path)
    }

    /// Validate path is secure
    ///
    /// Returns `Ok(())` if secure, or detailed error.
    /// Per Issue #182: validation is strict by default (no `_strict` suffix).
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    ///
    /// let security = SecurityBuilder::new();
    /// assert!(security.validate_path("safe/path.txt").is_ok());
    ///
    /// let err = security.validate_path("../secret").expect_err("test");
    /// assert!(err.to_string().contains("security"));
    /// ```
    pub fn validate_path(&self, path: &str) -> Result<(), Problem> {
        validation::validate_secure_strict(path)
    }

    /// Check if path has no traversal (lenient)
    #[must_use]
    pub fn is_traversal_safe(&self, path: &str) -> bool {
        validation::validate_no_any_traversal(path)
    }

    /// Validate path has no traversal (strict)
    pub fn validate_no_traversal(&self, path: &str) -> Result<(), Problem> {
        validation::validate_no_any_traversal_strict(path)
    }

    /// Check if path has no injection (lenient)
    #[must_use]
    pub fn is_injection_safe(&self, path: &str) -> bool {
        validation::validate_no_injection(path)
    }

    /// Validate path has no injection (strict)
    pub fn validate_no_injection(&self, path: &str) -> Result<(), Problem> {
        validation::validate_no_injection_strict(path)
    }

    /// Check if path is relative (lenient)
    #[must_use]
    pub fn is_relative(&self, path: &str) -> bool {
        validation::validate_relative(path)
    }

    /// Validate path is relative (strict)
    pub fn validate_relative(&self, path: &str) -> Result<(), Problem> {
        validation::validate_relative_strict(path)
    }

    /// Check if path is not empty (lenient)
    #[must_use]
    pub fn is_not_empty(&self, path: &str) -> bool {
        validation::validate_not_empty(path)
    }

    /// Validate path is not empty (strict)
    pub fn validate_not_empty(&self, path: &str) -> Result<(), Problem> {
        validation::validate_not_empty_strict(path)
    }

    // ========================================================================
    // Sanitization Methods
    // ========================================================================

    /// Sanitize path using default strategy (Clean)
    ///
    /// Removes dangerous patterns and returns sanitized path.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    ///
    /// let security = SecurityBuilder::new();
    /// let clean = security.sanitize("../../../etc/passwd").expect("test");
    /// assert!(!clean.contains(".."));
    /// ```
    pub fn sanitize(&self, path: &str) -> Result<String, Problem> {
        sanitization::sanitize(path)
    }

    /// Sanitize path using specified strategy
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    /// use octarine::primitives::paths::types::PathSanitizationStrategy;
    ///
    /// let security = SecurityBuilder::new();
    ///
    /// // Strict: reject if threats found
    /// assert!(security.sanitize_with("../etc", PathSanitizationStrategy::Strict).is_err());
    ///
    /// // Clean: remove threats
    /// let clean = security.sanitize_with("../etc", PathSanitizationStrategy::Clean).expect("test");
    /// assert!(!clean.contains(".."));
    ///
    /// // Escape: for display
    /// let escaped = security.sanitize_with("../etc", PathSanitizationStrategy::Escape).expect("test");
    /// assert!(escaped.contains("[DOT_DOT]"));
    /// ```
    pub fn sanitize_with(
        &self,
        path: &str,
        strategy: PathSanitizationStrategy,
    ) -> Result<String, Problem> {
        sanitization::sanitize_with(path, strategy)
    }

    /// Sanitize path in strict mode (reject if threats found)
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    ///
    /// let security = SecurityBuilder::new();
    /// assert!(security.sanitize_strict("safe/path.txt").is_ok());
    /// assert!(security.sanitize_strict("../secret").is_err());
    /// ```
    pub fn sanitize_strict(&self, path: &str) -> Result<String, Problem> {
        sanitization::sanitize_strict(path)
    }

    /// Sanitize path for display (escape threats)
    ///
    /// The result is NOT safe for filesystem operations.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use octarine::primitives::paths::security::SecurityBuilder;
    ///
    /// let security = SecurityBuilder::new();
    /// let escaped = security.escape_for_display("../$(whoami)").expect("test");
    /// assert!(escaped.contains("[DOT_DOT]"));
    /// assert!(escaped.contains("[DOLLAR_PAREN]"));
    /// ```
    pub fn escape_for_display(&self, path: &str) -> Result<String, Problem> {
        sanitization::sanitize_escape(path)
    }

    /// Strip traversal sequences from path
    #[must_use]
    pub fn strip_traversal(&self, path: &str) -> String {
        sanitization::strip_traversal(path)
    }

    /// Strip null bytes from path
    #[must_use]
    pub fn strip_null_bytes(&self, path: &str) -> String {
        sanitization::strip_null_bytes(path)
    }

    /// Strip control characters from path
    #[must_use]
    pub fn strip_control_characters(&self, path: &str) -> String {
        sanitization::strip_control_characters(path)
    }

    /// Normalize path separators
    #[must_use]
    pub fn normalize_separators(&self, path: &str) -> String {
        sanitization::normalize_path_separators(path)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> SecurityBuilder {
        SecurityBuilder::new()
    }

    // ------------------------------------------------------------------------
    // Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_threats() {
        let threats = builder().detect_threats("../$(whoami)");
        assert!(threats.contains(&SecurityThreat::Traversal));
        assert!(threats.contains(&SecurityThreat::CommandInjection));
    }

    #[test]
    fn test_is_threat_present() {
        assert!(builder().is_threat_present("../secret"));
        assert!(builder().is_threat_present("$(cmd)"));
        assert!(!builder().is_threat_present("safe/path"));
    }

    #[test]
    fn test_is_traversal_present() {
        assert!(builder().is_traversal_present("../etc"));
        assert!(!builder().is_traversal_present("safe"));
    }

    #[test]
    fn test_is_injection_present() {
        assert!(builder().is_injection_present("$(cmd)"));
        assert!(builder().is_injection_present("$VAR"));
        assert!(builder().is_injection_present("file;ls"));
        assert!(!builder().is_injection_present("safe"));
    }

    #[test]
    fn test_is_dangerous_characters_present() {
        assert!(builder().is_dangerous_characters_present("\0"));
        assert!(builder().is_dangerous_characters_present("\n"));
        assert!(!builder().is_dangerous_characters_present("safe"));
    }

    // ------------------------------------------------------------------------
    // Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_secure() {
        assert!(builder().is_secure("safe/path.txt"));
        assert!(!builder().is_secure("../secret"));
        assert!(!builder().is_secure("$(cmd)"));
    }

    #[test]
    fn test_validate_path() {
        assert!(builder().validate_path("safe/path").is_ok());
        assert!(builder().validate_path("../secret").is_err());
    }

    #[test]
    fn test_is_traversal_safe() {
        assert!(builder().is_traversal_safe("safe/path"));
        assert!(!builder().is_traversal_safe("../secret"));
        assert!(!builder().is_traversal_safe("%2e%2e"));
        assert!(!builder().is_traversal_safe("/absolute"));
    }

    #[test]
    fn test_is_relative() {
        assert!(builder().is_relative("relative/path"));
        assert!(!builder().is_relative("/absolute"));
        assert!(!builder().is_relative("C:\\Windows"));
    }

    // ------------------------------------------------------------------------
    // Sanitization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitize() {
        let result = builder().sanitize("../etc/passwd").expect("test");
        assert!(!result.contains(".."));
    }

    #[test]
    fn test_sanitize_with_strategies() {
        let b = builder();

        // Clean
        assert!(
            b.sanitize_with("../etc", PathSanitizationStrategy::Clean)
                .is_ok()
        );

        // Strict
        assert!(
            b.sanitize_with("../etc", PathSanitizationStrategy::Strict)
                .is_err()
        );

        // Escape
        let escaped = b
            .sanitize_with("../etc", PathSanitizationStrategy::Escape)
            .expect("test");
        assert!(escaped.contains("[DOT_DOT]"));
    }

    #[test]
    fn test_sanitize_strict() {
        assert!(builder().sanitize_strict("safe/path").is_ok());
        assert!(builder().sanitize_strict("../secret").is_err());
    }

    #[test]
    fn test_escape_for_display() {
        let escaped = builder().escape_for_display("../$(whoami)").expect("test");
        assert!(escaped.contains("[DOT_DOT]"));
        assert!(escaped.contains("[DOLLAR_PAREN]"));
    }

    #[test]
    fn test_strip_traversal() {
        assert_eq!(builder().strip_traversal("../etc"), "etc");
        assert_eq!(builder().strip_traversal("a/../b"), "a/b");
    }

    #[test]
    fn test_strip_null_bytes() {
        assert_eq!(builder().strip_null_bytes("file\0.txt"), "file.txt");
    }

    #[test]
    fn test_normalize_separators() {
        assert_eq!(
            builder().normalize_separators("path\\to\\file"),
            "path/to/file"
        );
        assert_eq!(
            builder().normalize_separators("path//to///file"),
            "path/to/file"
        );
    }
}
