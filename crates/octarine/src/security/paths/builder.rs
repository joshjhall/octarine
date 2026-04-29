//! Security operations builder with observability
//!
//! Wraps `primitives::security::paths::SecurityBuilder` with observe instrumentation.
//!
//! # Security Checks
//!
//! All security checks follow OWASP guidelines and address:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization
//!
//! # Examples
//!
//! ```rust
//! use octarine::security::paths::SecurityBuilder;
//!
//! let security = SecurityBuilder::new();
//!
//! // Detection
//! if security.is_traversal_present("../etc/passwd") {
//!     // Handle threat
//! }
//!
//! // Validation
//! security.validate_path("safe/path").unwrap();
//!
//! // Sanitization
//! let clean = security.sanitize("../file.txt").unwrap();
//! ```

use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::data::paths::PathSanitizationStrategy as PrimitiveSanitizationStrategy;
use crate::primitives::security::paths::SecurityBuilder as PrimitiveSecurityBuilder;

use super::types::{PathSanitizationStrategy, SecurityThreat};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn threats_detected() -> MetricName {
        MetricName::new("security.paths.threats_detected").expect("valid metric name")
    }

    pub fn validate_ms() -> MetricName {
        MetricName::new("security.paths.validate_ms").expect("valid metric name")
    }

    pub fn sanitize_ms() -> MetricName {
        MetricName::new("security.paths.sanitize_ms").expect("valid metric name")
    }
}

/// Security operations builder with observability
///
/// Provides comprehensive security detection, validation, and sanitization
/// for paths with full audit trail via observe.
#[derive(Debug, Clone, Default)]
pub struct SecurityBuilder {
    emit_events: bool,
}

impl SecurityBuilder {
    /// Create a new security builder with observe events enabled
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
    // Detection Methods
    // ========================================================================

    /// Check if path has any security threat
    #[must_use]
    pub fn is_threat_present(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_threat_present(path)
    }

    /// Detect all security threats in a path
    #[must_use]
    pub fn detect_threats(&self, path: &str) -> Vec<SecurityThreat> {
        let threats = PrimitiveSecurityBuilder::new().detect_threats(path);

        if self.emit_events && !threats.is_empty() {
            increment_by(metric_names::threats_detected(), threats.len() as u64);
        }

        threats.into_iter().map(SecurityThreat::from).collect()
    }

    /// Check if path is secure (no threats)
    #[must_use]
    pub fn is_secure(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_secure(path)
    }

    /// Check if path has path traversal (../)
    #[must_use]
    pub fn is_traversal_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_traversal_present(path);
        if self.emit_events && result {
            observe::warn("path_traversal_detected", "Path traversal pattern detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has encoded traversal (%2e%2e)
    #[must_use]
    pub fn is_encoded_traversal_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_encoded_traversal_present(path);
        if self.emit_events && result {
            observe::warn(
                "encoded_traversal_detected",
                "Encoded path traversal detected",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has command injection patterns
    #[must_use]
    pub fn is_command_injection_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_command_injection_present(path);
        if self.emit_events && result {
            observe::error(
                "command_injection_detected",
                "Command injection pattern detected in path",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has variable expansion ($VAR, ${VAR})
    #[must_use]
    pub fn is_variable_expansion_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_variable_expansion_present(path);
        if self.emit_events && result {
            observe::warn("variable_expansion_detected", "Variable expansion in path");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has shell metacharacters (; | & etc.)
    #[must_use]
    pub fn is_shell_metacharacters_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_shell_metacharacters_present(path);
        if self.emit_events && result {
            observe::warn(
                "shell_metacharacters_detected",
                "Shell metacharacters in path",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has null bytes
    #[must_use]
    pub fn is_null_bytes_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_null_bytes_present(path);
        if self.emit_events && result {
            observe::error("null_bytes_detected", "Null bytes detected in path");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has control characters
    #[must_use]
    pub fn is_control_characters_present(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_control_characters_present(path)
    }

    /// Check if path has double encoding attacks (%252e)
    #[must_use]
    pub fn is_double_encoding_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_double_encoding_present(path);
        if self.emit_events && result {
            observe::warn(
                "double_encoding_detected",
                "Double encoding attack detected",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has any type of traversal (plain or encoded)
    #[must_use]
    pub fn is_any_traversal_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_any_traversal_present(path);
        if self.emit_events && result {
            observe::warn("any_traversal_detected", "Path traversal detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has any injection pattern (command, variable, shell)
    #[must_use]
    pub fn is_injection_present(&self, path: &str) -> bool {
        let result = PrimitiveSecurityBuilder::new().is_injection_present(path);
        if self.emit_events && result {
            observe::error("injection_detected", "Injection pattern detected in path");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if path has dangerous characters
    #[must_use]
    pub fn is_dangerous_characters_present(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_dangerous_characters_present(path)
    }

    /// Check if path is absolute
    #[must_use]
    pub fn is_absolute(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_absolute(path)
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Validate a path - rejects any security threats
    ///
    /// Returns `Ok(())` if the path is safe, `Err` if it contains threats.
    /// This is the strict validation that rejects paths with any security issues.
    pub fn validate_path(&self, path: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = PrimitiveSecurityBuilder::new().validate_path(path);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if let Err(ref e) = result {
                observe::warn(
                    "path_validation_failed",
                    format!("Validation failed: {}", e),
                );
            }
        }

        result
    }

    /// Check if path is safe from traversal attacks
    #[must_use]
    pub fn is_traversal_safe(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_traversal_safe(path)
    }

    /// Validate that path has no traversal
    pub fn validate_no_traversal(&self, path: &str) -> Result<(), Problem> {
        PrimitiveSecurityBuilder::new().validate_no_traversal(path)
    }

    /// Check if path is safe from injection attacks
    #[must_use]
    pub fn is_injection_safe(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_injection_safe(path)
    }

    /// Validate that path has no injection
    pub fn validate_no_injection(&self, path: &str) -> Result<(), Problem> {
        PrimitiveSecurityBuilder::new().validate_no_injection(path)
    }

    /// Check if path is relative
    #[must_use]
    pub fn is_relative(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_relative(path)
    }

    /// Validate that path is relative
    pub fn validate_relative(&self, path: &str) -> Result<(), Problem> {
        PrimitiveSecurityBuilder::new().validate_relative(path)
    }

    /// Check if path is not empty
    #[must_use]
    pub fn is_not_empty(&self, path: &str) -> bool {
        PrimitiveSecurityBuilder::new().is_not_empty(path)
    }

    /// Validate that path is not empty
    pub fn validate_not_empty(&self, path: &str) -> Result<(), Problem> {
        PrimitiveSecurityBuilder::new().validate_not_empty(path)
    }

    // ========================================================================
    // Sanitization Methods
    // ========================================================================

    /// Sanitize a path by removing threats
    ///
    /// Uses the default "Clean" strategy which removes dangerous patterns.
    /// For lenient cleaning that always returns a value, use path cleaning functions.
    pub fn sanitize(&self, path: &str) -> Result<String, Problem> {
        let start = Instant::now();
        let original_len = path.len();

        let result = PrimitiveSecurityBuilder::new().sanitize(path);

        if self.emit_events
            && let Ok(ref sanitized) = result
        {
            let modified = sanitized != path;
            record(
                metric_names::sanitize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if modified {
                observe::info(
                    "path_sanitized",
                    format!(
                        "Path modified: {} -> {} bytes",
                        original_len,
                        sanitized.len()
                    ),
                );
            }
        }

        result
    }

    /// Sanitize with a specific strategy
    pub fn sanitize_with(
        &self,
        path: &str,
        strategy: PathSanitizationStrategy,
    ) -> Result<String, Problem> {
        let prim_strategy: PrimitiveSanitizationStrategy = strategy.into();
        PrimitiveSecurityBuilder::new().sanitize_with(path, prim_strategy)
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Strip traversal patterns from path
    #[must_use]
    pub fn strip_traversal(&self, path: &str) -> String {
        PrimitiveSecurityBuilder::new().strip_traversal(path)
    }

    /// Strip null bytes from path
    #[must_use]
    pub fn strip_null_bytes(&self, path: &str) -> String {
        PrimitiveSecurityBuilder::new().strip_null_bytes(path)
    }

    /// Normalize path separators
    #[must_use]
    pub fn normalize_separators(&self, path: &str) -> String {
        PrimitiveSecurityBuilder::new().normalize_separators(path)
    }

    /// Strip control characters from path
    #[must_use]
    pub fn strip_control_characters(&self, path: &str) -> String {
        PrimitiveSecurityBuilder::new().strip_control_characters(path)
    }

    /// Escape path for safe display
    pub fn escape_for_display(&self, path: &str) -> Result<String, Problem> {
        PrimitiveSecurityBuilder::new().escape_for_display(path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::metrics::{flush_for_testing, snapshot};
    use std::sync::Mutex;

    /// Serializes metrics-touching tests within this file so they don't race
    /// each other on the shared global registry.
    static METRICS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_builder_creation() {
        let builder = SecurityBuilder::new();
        assert!(builder.emit_events);

        let silent = SecurityBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = SecurityBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_security_detection() {
        let security = SecurityBuilder::silent();

        assert!(security.is_threat_present("../etc/passwd"));
        assert!(security.is_threat_present("$(whoami)"));
        assert!(!security.is_threat_present("safe/path.txt"));

        assert!(security.is_traversal_present("../secret"));
        assert!(security.is_command_injection_present("$(cmd)"));
        assert!(security.is_null_bytes_present("file\0.txt"));
    }

    #[test]
    fn test_security_validation() {
        let security = SecurityBuilder::new();

        assert!(security.is_secure("safe/path.txt"));
        assert!(!security.is_secure("../secret"));
        assert!(security.validate_path("safe/path").is_ok());
        assert!(security.validate_path("../secret").is_err());
    }

    #[test]
    fn test_security_sanitization() {
        let security = SecurityBuilder::new();

        let clean = security.sanitize("../etc/passwd").expect("should sanitize");
        assert!(!clean.contains(".."));

        assert!(security.sanitize("safe/path").is_ok());
    }

    #[test]
    fn test_metrics_validate_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = SecurityBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("security.paths.validate_ms")
            .map_or(0, |h| h.count);

        let _ = builder.validate_path("safe/path");
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("security.paths.validate_ms")
            .map_or(0, |h| h.count);
        assert!(after > before, "validate_ms should record");
    }

    #[test]
    fn test_metrics_threats_detected_counter() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = SecurityBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .counters
            .get("security.paths.threats_detected")
            .map_or(0, |c| c.value);

        assert!(builder.is_traversal_present("../etc/passwd"));
        flush_for_testing();

        let after = snapshot()
            .counters
            .get("security.paths.threats_detected")
            .map_or(0, |c| c.value);
        assert!(after > before, "threats_detected should increment");
    }

    #[test]
    fn test_silent_mode_emits_no_metrics() {
        // Structural test: `silent()` returns a builder with emit_events=false,
        // and every metric call site in this module is gated by `if self.emit_events`.
        // A behavioral delta-assertion would race with concurrent tests across the
        // workspace that hit these same global metric names via shortcuts/facade.
        let builder = SecurityBuilder::silent();
        assert!(!builder.emit_events);

        // Sanity: invoking through the silent builder still works functionally.
        assert!(builder.is_threat_present("../etc/passwd"));
        assert!(builder.validate_path("safe/path").is_ok());
        assert!(builder.sanitize("../etc/passwd").is_ok());
    }

    #[test]
    fn test_paths_edge_cases() {
        // Edge-case inputs flagged by the audit (umbrella #181 / issue #274):
        // empty string, unicode, Windows separators on Linux, very long paths.
        // The contract is "well-defined behavior, no panic" — exact ok/err
        // depends on the primitive's policy, so we just exercise the path.
        let security = SecurityBuilder::silent();

        // Empty string — should be handled (validate_not_empty rejects).
        let _ = security.validate_path("");
        let _ = security.is_threat_present("");

        // Unicode path: non-ASCII filename should not crash the validator.
        // A bare unicode filename has no traversal/injection markers, so it
        // is expected to pass the strict validator.
        assert!(security.validate_path("café/file.txt").is_ok());

        // Windows separators on a Linux host: backslashes are not directory
        // separators here, so this is a single filename containing `\`. It
        // contains no threats and should validate.
        assert!(security.validate_path("foo\\bar.txt").is_ok());

        // Long path: 4096 chars (typical PATH_MAX). Should not panic; either
        // accepted or rejected for length, both are acceptable behaviors.
        let long_path = "a/".repeat(2048);
        let _ = security.validate_path(&long_path);
        let _ = security.is_threat_present(&long_path);
    }
}
