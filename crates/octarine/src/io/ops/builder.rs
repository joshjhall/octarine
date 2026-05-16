//! Builder for `SecureFileOps`
//!
//! `SecureFileOpsBuilder` provides a fluent configuration API that defers
//! to the in-place `SecureFileOpsConfig`.

use crate::primitives::io::file::WriteOptions;

use super::config::{AuditLevel, SecureFileOpsConfig};
use super::core::SecureFileOps;

/// Builder for SecureFileOps
#[derive(Debug, Default)]
pub struct SecureFileOpsBuilder {
    config: SecureFileOpsConfig,
}

impl SecureFileOpsBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
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
