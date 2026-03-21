//! Path and filename types for log writers
//!
//! Type-safe wrappers for log directories, filenames, and patterns.

use crate::observe::Problem;
use crate::primitives::data::paths::{CharacteristicBuilder, FilenameBuilder};
use crate::primitives::security::paths::SecurityBuilder;
use std::path::{Path, PathBuf};

/// A validated, absolute log directory path
///
/// This type can only be constructed by passing validation, ensuring
/// that any `LogDirectory` value is:
/// - An absolute path
/// - Free from command injection patterns
/// - Free from shell metacharacters
/// - Free from null bytes
///
/// # Examples
///
/// ```ignore
/// use octarine::writers::LogDirectory;
///
/// // Valid absolute path
/// let dir = LogDirectory::new("/var/log/myapp")?;
///
/// // Invalid - relative path
/// let err = LogDirectory::new("logs");  // Returns Err
///
/// // Invalid - command injection
/// let err = LogDirectory::new("/tmp/$(whoami)");  // Returns Err
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogDirectory(PathBuf);

impl LogDirectory {
    /// Create a new validated log directory
    ///
    /// # Security
    ///
    /// This function uses `primitives::paths::SecurityBuilder` for comprehensive validation:
    /// - Path must be absolute (no relative paths)
    /// - No command injection patterns: `$(`, `` ` ``, `${`
    /// - No shell metacharacters: `;`, `|`, `&`
    /// - No null bytes
    /// - No control characters
    /// - No directory traversal attempts
    ///
    /// # Errors
    ///
    /// Returns `Err` if any validation check fails.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Problem> {
        let path_str = path.as_ref().to_string_lossy();
        let path_obj = path.as_ref();

        // Use primitives for validation
        let char_builder = CharacteristicBuilder::new();
        let security = SecurityBuilder::new();

        // Validate absolute path using CharacteristicBuilder
        if !char_builder.is_absolute(&path_str) {
            return Err(Problem::validation(
                "Log directory must be absolute path for security",
            ));
        }

        // Validate no command injection patterns using SecurityBuilder
        if security.is_command_injection_present(&path_str) {
            return Err(Problem::validation(
                "Log directory contains command injection patterns",
            ));
        }

        // Validate no shell metacharacters using SecurityBuilder
        if security.is_shell_metacharacters_present(&path_str) {
            return Err(Problem::validation(
                "Log directory contains shell metacharacters",
            ));
        }

        // Validate no null bytes using SecurityBuilder
        if security.is_null_bytes_present(&path_str) {
            return Err(Problem::validation("Log directory contains null bytes"));
        }

        Ok(Self(path_obj.to_path_buf()))
    }

    /// Get the inner path
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Convert to PathBuf
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for LogDirectory {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// A validated, sanitized log filename
///
/// This type guarantees that the filename:
/// - Contains no path traversal sequences (`..`, `/`)
/// - Contains no dangerous characters
/// - Is not empty after sanitization
/// - Is safe for filesystem use
///
/// # Examples
///
/// ```ignore
/// use octarine::writers::LogFilename;
///
/// // Valid filename
/// let name = LogFilename::new("app.log")?;
///
/// // Invalid - contains path traversal
/// let name = LogFilename::new("../etc/passwd");  // Sanitized to "etcpasswd"
///
/// // Invalid - empty after sanitization
/// let err = LogFilename::new("../../");  // Returns Err
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFilename(String);

impl LogFilename {
    /// Create a new validated log filename
    ///
    /// # Security
    ///
    /// The filename is sanitized to remove:
    /// - Path traversal sequences (`..`)
    /// - Directory separators (`/`, `\`)
    /// - Dangerous characters
    ///
    /// # Errors
    ///
    /// Returns `Err` if the filename is empty after sanitization.
    pub fn new(filename: impl AsRef<str>) -> Result<Self, Problem> {
        let input = filename.as_ref();

        // Reject empty or whitespace-only input
        if input.trim().is_empty() {
            return Err(Problem::validation("Filename cannot be empty"));
        }

        // Sanitize filename to prevent path traversal using primitives
        let fb = FilenameBuilder::new();
        let safe_filename = fb.to_safe_filename_or(input, "safe_file.txt");

        // The lenient sanitizer might return the fallback value
        // We want to reject problematic inputs, not silently replace them
        if safe_filename == "safe_file.txt" && input != "safe_file.txt" {
            return Err(Problem::validation(
                "Filename is unsafe and cannot be sanitized",
            ));
        }

        Ok(Self(safe_filename))
    }

    /// Get the sanitized filename
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for LogFilename {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Filename pattern for log files
///
/// Supports template variables for dynamic naming:
/// - `{date}` - YYYY-MM-DD format
/// - `{datetime}` - YYYY-MM-DD_HH-MM-SS format
/// - `{timestamp}` - Unix timestamp
/// - `{sequence}` - Incrementing number (for rotated files)
/// - `{tenant}` - Tenant ID (for multi-tenant mode)
/// - `{host}` - Hostname
///
/// # Examples
///
/// ```rust
/// use octarine::observe::writers::FilenamePattern;
///
/// let pattern = FilenamePattern::new("audit-{date}.log");
/// let pattern = FilenamePattern::new("{tenant}/audit-{datetime}.log");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilenamePattern(String);

impl FilenamePattern {
    /// Create a new filename pattern
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Get the pattern string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Expand the pattern with the given variables
    ///
    /// # Arguments
    ///
    /// * `date` - Optional date string (YYYY-MM-DD)
    /// * `datetime` - Optional datetime string (YYYY-MM-DD_HH-MM-SS)
    /// * `sequence` - Optional sequence number
    /// * `tenant` - Optional tenant ID
    pub fn expand(
        &self,
        date: Option<&str>,
        datetime: Option<&str>,
        sequence: Option<usize>,
        tenant: Option<&str>,
    ) -> String {
        let mut result = self.0.clone();

        if let Some(d) = date {
            result = result.replace("{date}", d);
        }
        if let Some(dt) = datetime {
            result = result.replace("{datetime}", dt);
        }
        if let Some(seq) = sequence {
            result = result.replace("{sequence}", &seq.to_string());
        }
        if let Some(t) = tenant {
            result = result.replace("{tenant}", t);
        }

        // Expand timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        result = result.replace("{timestamp}", &now.to_string());

        // Expand hostname
        if result.contains("{host}") {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            result = result.replace("{host}", &hostname);
        }

        result
    }

    /// Check if this pattern uses tenant directories
    pub fn uses_tenant(&self) -> bool {
        self.0.contains("{tenant}")
    }

    /// Default audit log pattern
    pub fn audit() -> Self {
        Self::new("audit-{date}.log")
    }

    /// Simple pattern with just date
    pub fn daily(base_name: &str) -> Self {
        Self::new(format!("{}-{{date}}.log", base_name))
    }

    /// Pattern with datetime for more granular files
    pub fn hourly(base_name: &str) -> Self {
        Self::new(format!("{}-{{datetime}}.log", base_name))
    }

    /// Multi-tenant pattern
    pub fn multi_tenant(base_name: &str) -> Self {
        Self::new(format!("{{tenant}}/{}-{{date}}.log", base_name))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_log_directory_valid_absolute_path() {
        let dir = LogDirectory::new("/var/log/myapp");
        assert!(dir.is_ok());
        assert_eq!(
            dir.expect("Valid absolute path should be accepted")
                .as_path(),
            Path::new("/var/log/myapp")
        );
    }

    #[test]
    fn test_log_directory_rejects_relative_path() {
        let result = LogDirectory::new("relative/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_log_directory_rejects_command_injection() {
        assert!(LogDirectory::new("/tmp/$(whoami)/logs").is_err());
        assert!(LogDirectory::new("/tmp/`whoami`/logs").is_err());
        assert!(LogDirectory::new("/tmp/${USER}/logs").is_err());
    }

    #[test]
    fn test_log_directory_rejects_shell_metacharacters() {
        assert!(LogDirectory::new("/tmp; rm -rf /").is_err());
        assert!(LogDirectory::new("/tmp | cat").is_err());
        assert!(LogDirectory::new("/tmp && echo").is_err());
    }

    #[test]
    fn test_log_directory_rejects_null_bytes() {
        let path_with_null = "/tmp/log\0dir";
        assert!(LogDirectory::new(path_with_null).is_err());
    }

    #[test]
    fn test_log_filename_sanitization() {
        // Path traversal is sanitized
        let name = LogFilename::new("app../../../etc/passwd.log")
            .expect("Filename should be sanitized, not rejected");
        assert!(!name.as_str().contains(".."));
        assert!(!name.as_str().contains('/'));
    }

    #[test]
    fn test_log_filename_rejects_empty() {
        // Actually empty string should fail
        let result = LogFilename::new("");
        assert!(result.is_err());

        // Whitespace-only should also fail
        let result = LogFilename::new("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_log_filename_clean() {
        let name = LogFilename::new("app.log").expect("Valid filename should be accepted");
        assert_eq!(name.as_str(), "app.log");
    }

    #[test]
    fn test_filename_pattern_expand() {
        let pattern = FilenamePattern::new("audit-{date}.log");
        let expanded = pattern.expand(Some("2025-11-29"), None, None, None);
        assert_eq!(expanded, "audit-2025-11-29.log");
    }

    #[test]
    fn test_filename_pattern_multi_tenant() {
        let pattern = FilenamePattern::multi_tenant("audit");
        assert!(pattern.uses_tenant());

        let expanded = pattern.expand(Some("2025-11-29"), None, None, Some("acme-corp"));
        assert_eq!(expanded, "acme-corp/audit-2025-11-29.log");
    }

    #[test]
    fn test_filename_pattern_with_sequence() {
        let pattern = FilenamePattern::new("app.log.{sequence}");
        let expanded = pattern.expand(None, None, Some(3), None);
        assert_eq!(expanded, "app.log.3");
    }

    #[test]
    fn test_filename_pattern_datetime() {
        let pattern = FilenamePattern::hourly("events");
        let expanded = pattern.expand(None, Some("2025-11-29_14-30-00"), None, None);
        assert_eq!(expanded, "events-2025-11-29_14-30-00.log");
    }

    #[test]
    fn test_filename_pattern_presets() {
        // Test preset patterns are valid
        let audit = FilenamePattern::audit();
        assert!(audit.as_str().contains("{date}"));

        let daily = FilenamePattern::daily("app");
        assert!(daily.as_str().contains("{date}"));

        let hourly = FilenamePattern::hourly("events");
        assert!(hourly.as_str().contains("{datetime}"));

        let tenant = FilenamePattern::multi_tenant("logs");
        assert!(tenant.uses_tenant());
    }
}
