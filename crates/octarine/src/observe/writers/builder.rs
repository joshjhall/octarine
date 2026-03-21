//! Builder for FileWriter with type-safe configuration
//!
//! This module provides a builder pattern with compile-time guarantees
//! that required configuration is provided.

use super::file::FileWriter;
use super::types::{DurabilityMode, LogDirectory, LogFilename, LogFormat, RotationConfig};
use crate::observe::Problem;
use crate::observe::types::Severity;
use crate::primitives::io::file::FileMode;

/// Builder for creating a FileWriter with type-safe configuration
///
/// This builder ensures that required fields (log_dir and filename) are
/// provided at construction time, while optional fields can be configured
/// through builder methods.
///
/// # Examples
///
/// ```ignore
/// use octarine::writers::{FileWriterBuilder, LogDirectory, LogFilename, Severity};
/// use octarine::writers::DurabilityMode;
///
/// let writer = FileWriterBuilder::new(
///     LogDirectory::new("/var/log/myapp")?,
///     LogFilename::new("app.log")?,
/// )
/// .with_min_severity(Severity::Warning)
/// .with_rotation(RotationConfig::production())
/// .with_durability(DurabilityMode::OnFlush)  // For compliance
/// .build()
/// .await?;
/// ```
#[derive(Debug)]
pub struct FileWriterBuilder {
    log_dir: LogDirectory,
    filename: LogFilename,
    min_severity: Severity,
    rotation: RotationConfig,
    /// File permissions for log files (default: LOG_FILE = 0640)
    file_mode: FileMode,
    /// Directory permissions (default: LOG_DIR = 0750)
    dir_mode: FileMode,
    /// Durability mode (default: OnRotation)
    durability: DurabilityMode,
    /// Log output format (default: HumanReadable)
    format: LogFormat,
}

impl FileWriterBuilder {
    /// Create a new FileWriter builder
    ///
    /// Required fields must be provided at construction time,
    /// ensuring they cannot be forgotten.
    ///
    /// # Arguments
    ///
    /// * `log_dir` - Validated log directory (absolute path)
    /// * `filename` - Sanitized log filename
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = FileWriterBuilder::new(
    ///     LogDirectory::new("/var/log")?,
    ///     LogFilename::new("app.log")?,
    /// );
    /// ```
    pub fn new(log_dir: LogDirectory, filename: LogFilename) -> Self {
        Self {
            log_dir,
            filename,
            min_severity: Severity::Info,
            rotation: RotationConfig::default(),
            file_mode: FileMode::LOG_FILE,
            dir_mode: FileMode::LOG_DIR,
            durability: DurabilityMode::default(),
            format: LogFormat::default(),
        }
    }

    /// Set the minimum severity level for logging
    ///
    /// Events with severity below this level will be filtered out.
    ///
    /// Default: `Severity::Info`
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Set the log rotation configuration
    ///
    /// Controls when and how log files are rotated.
    ///
    /// Default: `RotationConfig::production()` (100MB, 5 backups)
    pub fn with_rotation(mut self, rotation: RotationConfig) -> Self {
        self.rotation = rotation;
        self
    }

    /// Set the file permissions for log files
    ///
    /// Default: `FileMode::LOG_FILE` (0640 - owner rw, group r)
    ///
    /// # Security Note
    ///
    /// For sensitive logs, consider using `FileMode::PRIVATE` (0600).
    pub fn with_file_mode(mut self, mode: FileMode) -> Self {
        self.file_mode = mode;
        self
    }

    /// Set the directory permissions for the log directory
    ///
    /// Default: `FileMode::LOG_DIR` (0750 - owner rwx, group rx)
    pub fn with_dir_mode(mut self, mode: FileMode) -> Self {
        self.dir_mode = mode;
        self
    }

    /// Set the durability mode for writes
    ///
    /// Controls when data is synced to disk.
    ///
    /// Default: `DurabilityMode::OnRotation`
    ///
    /// # Compliance Recommendations
    ///
    /// - **SOC 2 / HIPAA**: Use `OnFlush` or `Immediate`
    /// - **General production**: Use `OnRotation` (default)
    /// - **Debug / High volume**: Use `OsManaged`
    pub fn with_durability(mut self, durability: DurabilityMode) -> Self {
        self.durability = durability;
        self
    }

    /// Set the log output format
    ///
    /// Controls how events are formatted when written to log files.
    ///
    /// Default: `LogFormat::HumanReadable`
    ///
    /// # Format Options
    ///
    /// - **HumanReadable**: Traditional log format for human consumption
    /// - **JsonLines**: Structured JSON format for log aggregation and querying
    ///
    /// # Compliance Recommendations
    ///
    /// - **SOC 2**: Use `JsonLines` for queryable audit trails
    /// - **HIPAA**: Use `JsonLines` for structured PHI access logs
    /// - **PCI DSS**: Use `JsonLines` for log integrity verification
    ///
    /// # Example
    ///
    /// ```ignore
    /// let writer = FileWriterBuilder::new(log_dir, filename)
    ///     .with_format(LogFormat::JsonLines)
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Build the FileWriter
    ///
    /// Creates the log directory if it doesn't exist and initializes
    /// the file writer.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Directory creation fails
    /// - File system permissions are insufficient
    pub(super) async fn build(self) -> Result<FileWriter, Problem> {
        FileWriter::from_builder(self).await
    }

    /// Get the log directory
    pub(super) fn log_dir(&self) -> &LogDirectory {
        &self.log_dir
    }

    /// Get the filename
    pub(super) fn filename(&self) -> &LogFilename {
        &self.filename
    }

    /// Get the minimum severity
    pub(super) fn min_severity(&self) -> Severity {
        self.min_severity
    }

    /// Get the rotation config
    pub(super) fn rotation(&self) -> &RotationConfig {
        &self.rotation
    }

    /// Get the file mode
    pub(super) fn file_mode(&self) -> FileMode {
        self.file_mode
    }

    /// Get the directory mode
    pub(super) fn dir_mode(&self) -> FileMode {
        self.dir_mode
    }

    /// Get the durability mode
    pub(super) fn durability(&self) -> DurabilityMode {
        self.durability
    }

    /// Get the log format
    pub(super) fn format(&self) -> LogFormat {
        self.format
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_builder_required_fields() {
        let temp_dir = tempdir().expect("create temp dir");
        let log_path = temp_dir.path().join("logs");
        let log_dir = LogDirectory::new(log_path.to_str().expect("valid utf-8"))
            .expect("Valid absolute path should work");
        let filename = LogFilename::new("test.log").expect("Valid filename should work");

        let builder = FileWriterBuilder::new(log_dir, filename);

        // Should be able to build with just required fields
        builder.build().await.expect("Builder should succeed");
    }

    #[tokio::test]
    async fn test_builder_with_options() {
        let temp_dir = tempdir().expect("create temp dir");
        let log_path = temp_dir.path().join("logs");
        let log_dir = LogDirectory::new(log_path.to_str().expect("valid utf-8"))
            .expect("Valid absolute path should work");
        let filename = LogFilename::new("test.log").expect("Valid filename should work");

        let builder = FileWriterBuilder::new(log_dir, filename)
            .with_min_severity(Severity::Warning)
            .with_rotation(RotationConfig::testing());

        let writer = builder.build().await.expect("Builder should succeed");

        // Verify configuration was applied (we'll add getters to FileWriter)
        drop(writer);
    }

    #[tokio::test]
    async fn test_builder_with_custom_permissions() {
        let temp_dir = tempdir().expect("create temp dir");
        let log_path = temp_dir.path().join("secure_logs");
        let log_dir = LogDirectory::new(log_path.to_str().expect("valid utf-8"))
            .expect("Valid absolute path should work");
        let filename = LogFilename::new("secure.log").expect("Valid filename should work");

        let builder = FileWriterBuilder::new(log_dir, filename)
            .with_file_mode(FileMode::PRIVATE) // 0600
            .with_dir_mode(FileMode::new(0o700)); // owner-only directory

        builder.build().await.expect("Builder should succeed");
    }

    #[tokio::test]
    async fn test_builder_with_durability() {
        let temp_dir = tempdir().expect("create temp dir");
        let log_path = temp_dir.path().join("durable_logs");
        let log_dir = LogDirectory::new(log_path.to_str().expect("valid utf-8"))
            .expect("Valid absolute path should work");
        let filename = LogFilename::new("audit.log").expect("Valid filename should work");

        let builder =
            FileWriterBuilder::new(log_dir, filename).with_durability(DurabilityMode::OnFlush);

        builder.build().await.expect("Builder should succeed");
    }
}
