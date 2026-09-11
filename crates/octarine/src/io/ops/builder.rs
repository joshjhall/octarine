//! Builder for `SecureFileOps`
//!
//! `SecureFileOpsBuilder` provides a fluent configuration API that defers
//! to the in-place `SecureFileOpsConfig`.

use crate::primitives::io::file::WriteOptions;

use super::config::{AuditLevel, SecureFileOpsConfig};
use super::core::SecureFileOps;

/// Builder for SecureFileOps
///
/// # Observability
///
/// File operations record timing (`io.file.read_duration_ms`,
/// `io.file.write_duration_ms`, `io.file.lock_duration_ms`) and counts
/// (`io.file.read_count`, `io.file.write_count`, `io.file.lock_count`,
/// `io.file.read_bytes`, `io.file.write_bytes`).
///
/// Events and metrics are governed by [`audit_level`](Self::audit_level) and
/// [`metrics`](Self::metrics). [`silent()`](Self::silent) and
/// [`with_events()`](Self::with_events) set both at once, matching the
/// `silent()` convention used by the other Layer 3 builders.
#[derive(Debug, Default)]
pub struct SecureFileOpsBuilder {
    config: SecureFileOpsConfig,
}

impl SecureFileOpsBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder that emits no events and records no metrics
    ///
    /// Equivalent to `SecureFileOpsBuilder::new().with_events(false)`. Use for
    /// bulk operations, or where file paths must not reach the audit trail.
    pub fn silent() -> Self {
        Self::new().with_events(false)
    }

    /// Enable or disable observe events and metrics together
    ///
    /// Disabling sets `audit_level` to [`AuditLevel::Off`] and turns metrics
    /// off; enabling restores the default [`AuditLevel::Full`] and metrics on.
    /// For independent control use [`audit_level`](Self::audit_level) and
    /// [`metrics`](Self::metrics).
    pub fn with_events(mut self, emit: bool) -> Self {
        self.config.audit_level = if emit {
            AuditLevel::Full
        } else {
            AuditLevel::Off
        };
        self.config.metrics_enabled = emit;
        self
    }

    /// Set audit level
    pub fn audit_level(mut self, level: AuditLevel) -> Self {
        self.config.audit_level = level;
        self
    }

    /// Enable or disable metrics
    pub fn metrics(mut self, enabled: bool) -> Self {
        self.config.metrics_enabled = enabled;
        self
    }

    /// Enable or disable magic byte validation
    pub fn validate_magic(mut self, enabled: bool) -> Self {
        self.config.validate_magic = enabled;
        self
    }

    /// Set default write options
    pub fn default_write_options(mut self, options: WriteOptions) -> Self {
        self.config.default_write_options = options;
        self
    }

    /// Build the SecureFileOps
    pub fn build(self) -> SecureFileOps {
        SecureFileOps::with_config(self.config)
    }
}
