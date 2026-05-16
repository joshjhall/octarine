//! Configuration types for `SecureFileOps`
//!
//! Contains `AuditLevel`, `SecureFileOpsConfig`, and the three config preset
//! constructors (`secure()`, `development()`, `performance()`).

use crate::primitives::io::file::WriteOptions;

/// Audit level for file operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditLevel {
    /// No logging (not recommended for production)
    Off,
    /// Log errors only
    Errors,
    /// Log errors and warnings
    Warnings,
    /// Log all operations (default)
    #[default]
    Full,
    /// Log all operations with debug details
    Debug,
}

/// Configuration for SecureFileOps
#[derive(Debug, Clone)]
pub struct SecureFileOpsConfig {
    /// Audit level for logging
    pub audit_level: AuditLevel,
    /// Whether to record metrics
    pub metrics_enabled: bool,
    /// Whether to validate magic bytes on read
    pub validate_magic: bool,
    /// Default write options
    pub default_write_options: WriteOptions,
}

impl Default for SecureFileOpsConfig {
    fn default() -> Self {
        Self {
            audit_level: AuditLevel::Full,
            metrics_enabled: true,
            validate_magic: false, // Opt-in for magic validation
            default_write_options: WriteOptions::default(),
        }
    }
}

impl SecureFileOpsConfig {
    /// Create config for high-security environments
    pub fn secure() -> Self {
        Self {
            audit_level: AuditLevel::Full,
            metrics_enabled: true,
            validate_magic: true,
            default_write_options: WriteOptions::for_secrets(),
        }
    }

    /// Create config for development (verbose logging)
    pub fn development() -> Self {
        Self {
            audit_level: AuditLevel::Debug,
            metrics_enabled: true,
            validate_magic: false,
            default_write_options: WriteOptions::default(),
        }
    }

    /// Create config for performance-critical scenarios
    pub fn performance() -> Self {
        Self {
            audit_level: AuditLevel::Errors,
            metrics_enabled: false,
            validate_magic: false,
            default_write_options: WriteOptions::default(),
        }
    }
}
