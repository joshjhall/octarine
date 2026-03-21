//! Context-specific sanitization builder with observability
//!
//! Provides specialized sanitization for different security contexts:
//! environment files, SSH paths, credentials, and 1Password references.
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::PathContextBuilder;
//!
//! let ctx = PathContextBuilder::new();
//!
//! // Environment files
//! let safe_env = ctx.sanitize_env(".env.production").unwrap();
//!
//! // SSH files
//! let safe_ssh = ctx.sanitize_ssh(".ssh/id_rsa").unwrap();
//!
//! // 1Password references
//! let safe_op = ctx.sanitize_op("op://vault/item/field").unwrap();
//! ```

use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment};

use super::super::context;

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn context_sanitized() -> MetricName {
        MetricName::new("data.paths.context.sanitized").expect("valid metric name")
    }
}

/// Context-specific sanitization builder with observability
///
/// Provides specialized path sanitization for security-sensitive contexts.
#[derive(Debug, Clone, Default)]
pub struct PathContextBuilder {
    emit_events: bool,
}

impl PathContextBuilder {
    /// Create a new context builder with observe events enabled
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
    // Environment Files
    // ========================================================================

    /// Check if a path appears to be an environment file
    #[must_use]
    pub fn is_env_path(&self, path: &str) -> bool {
        context::is_env_path(path)
    }

    /// Sanitize an environment file path
    ///
    /// Applies strict security checks appropriate for .env files.
    pub fn sanitize_env(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_env_path(path)
    }

    // ========================================================================
    // SSH Files
    // ========================================================================

    /// Check if a path appears to be an SSH-related file
    #[must_use]
    pub fn is_ssh_path(&self, path: &str) -> bool {
        context::is_ssh_path(path)
    }

    /// Sanitize an SSH file path
    ///
    /// Applies strict security checks appropriate for SSH files.
    pub fn sanitize_ssh(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_ssh_path(path)
    }

    // ========================================================================
    // Credential Files
    // ========================================================================

    /// Check if a path appears to be a credential file
    #[must_use]
    pub fn is_credential_path(&self, path: &str) -> bool {
        context::is_credential_path(path)
    }

    /// Sanitize a credential file path
    ///
    /// Applies strict security checks for credential/secret files.
    pub fn sanitize_credential(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_credential_path(path)
    }

    /// Sanitize a certificate file path
    pub fn sanitize_certificate(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_certificate_path(path)
    }

    /// Sanitize a keystore file path
    pub fn sanitize_keystore(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_keystore_path(path)
    }

    /// Sanitize a secret file path
    pub fn sanitize_secret(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_secret_path(path)
    }

    /// Sanitize a backup file path
    pub fn sanitize_backup(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_backup_path(path)
    }

    // ========================================================================
    // 1Password References
    // ========================================================================

    /// Check if a path is a 1Password reference (op://)
    #[must_use]
    pub fn is_op_reference(&self, path: &str) -> bool {
        context::is_op_reference(path)
    }

    /// Sanitize a 1Password reference
    ///
    /// Validates the op:// reference format and checks for injection.
    pub fn sanitize_op(&self, path: &str) -> Result<String, Problem> {
        context::sanitize_op_reference(path)
    }

    // ========================================================================
    // Auto-Detection
    // ========================================================================

    /// Sanitize path based on auto-detected context
    ///
    /// Automatically detects the context and applies appropriate sanitization.
    pub fn sanitize_auto(&self, path: &str) -> Result<String, Problem> {
        let result = if self.is_op_reference(path) {
            self.sanitize_op(path)
        } else if self.is_ssh_path(path) {
            self.sanitize_ssh(path)
        } else if self.is_env_path(path) {
            self.sanitize_env(path)
        } else if self.is_credential_path(path) {
            self.sanitize_credential(path)
        } else {
            // Fall back to general security sanitization
            crate::data::paths::builder::SecurityBuilder::silent().sanitize(path)
        };

        if self.emit_events && result.is_ok() {
            increment(metric_names::context_sanitized());
        }

        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = PathContextBuilder::new();
        assert!(builder.emit_events);

        let silent = PathContextBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = PathContextBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_env_path() {
        let ctx = PathContextBuilder::silent();

        assert!(ctx.is_env_path(".env"));
        assert!(ctx.is_env_path(".env.local"));
        assert!(ctx.is_env_path("config/.env"));
        assert!(!ctx.is_env_path("config.yaml"));

        assert!(ctx.sanitize_env(".env").is_ok());
        assert!(ctx.sanitize_env("../.env").is_err());
    }

    #[test]
    fn test_ssh_path() {
        let ctx = PathContextBuilder::silent();

        assert!(ctx.is_ssh_path(".ssh/id_rsa"));
        assert!(ctx.is_ssh_path("~/.ssh/authorized_keys"));
        assert!(!ctx.is_ssh_path("/etc/passwd"));

        assert!(ctx.sanitize_ssh(".ssh/id_rsa").is_ok());
        assert!(ctx.sanitize_ssh("../.ssh/id_rsa").is_err());
    }

    #[test]
    fn test_credential_path() {
        let ctx = PathContextBuilder::silent();

        assert!(ctx.is_credential_path("credentials.json"));
        assert!(ctx.is_credential_path("secrets/api_key"));

        assert!(ctx.sanitize_credential("credentials.json").is_ok());
        assert!(ctx.sanitize_credential("../credentials.json").is_err());
    }

    #[test]
    fn test_op_reference() {
        let ctx = PathContextBuilder::silent();

        assert!(ctx.is_op_reference("op://vault/item"));
        assert!(ctx.is_op_reference("op://vault/item/field"));
        assert!(!ctx.is_op_reference("/etc/passwd"));

        assert!(ctx.sanitize_op("op://vault/item").is_ok());
        assert!(ctx.sanitize_op("op://vault/../other").is_err());
        assert!(ctx.sanitize_op("op://vault/item;whoami").is_err());
    }

    #[test]
    fn test_auto_detection() {
        let ctx = PathContextBuilder::silent();

        // Each type should be auto-detected and sanitized appropriately
        assert!(ctx.sanitize_auto(".env").is_ok());
        assert!(ctx.sanitize_auto(".ssh/id_rsa").is_ok());
        assert!(ctx.sanitize_auto("op://vault/item").is_ok());
        assert!(ctx.sanitize_auto("safe/path.txt").is_ok());

        // Dangerous paths should fail
        assert!(ctx.sanitize_auto("../.env").is_err());
    }
}
