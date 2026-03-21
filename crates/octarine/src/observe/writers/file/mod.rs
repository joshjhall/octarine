//! File writer for production logging
//!
//! Writes observability events to log files with rotation, compression, and PII scanning.
//!
//! ## Security Features
//!
//! - **Path Sanitization**: All paths validated using security module
//! - **Directory Boundary**: Logs confined to specified directory
//! - **Filename Validation**: Prevents path traversal through filenames
//! - **PII Scanning**: Defense-in-depth - scans output before writing
//! - **Size Limits**: Rotation prevents disk exhaustion attacks
//!
//! ## Defense-in-Depth PII Protection
//!
//! FileWriter provides a **second layer** of PII scanning:
//! 1. Scans the final output message before writing to disk
//! 2. Catches any PII that bypassed event-level redaction
//! 3. Ensures compliance even if `.skip_pii_redaction()` was used incorrectly
//!
//! This defense-in-depth approach meets:
//! - **PCI DSS 3.4**: Multiple barriers prevent credit cards in log files
//! - **SOC 2**: Demonstrates robust logging controls with file persistence
//! - **HIPAA**: Final PHI check before persistent storage
//!
//! ## Log Rotation
//!
//! Rotation is triggered when ANY of these conditions are met:
//! - **Size-based**: File exceeds `max_file_size`
//! - **Time-based**: Based on schedule (Hourly, Daily, Weekly)
//! - **Age-based**: File exceeds `max_age`
//!
//! ## Compression
//!
//! Rotated files can be automatically compressed with gzip:
//! - Configurable compression level (1-9)
//! - Compressed files have `.gz` extension
//! - Reduces storage requirements significantly
//!
//! ## Retention Enforcement
//!
//! Automatic cleanup of old log files:
//! - Delete files older than `retention_days`
//! - Keep maximum of `max_backups` files
//! - Compliant with SOC2, HIPAA, GDPR retention requirements
//!
//! ## Multi-Tenant Support
//!
//! - Per-tenant subdirectories
//! - Pattern-based filenames with `{tenant}` variable
//!
//! ## Example
//!
//! FileWriter is internal infrastructure. Users can configure log types
//! using public types:
//!
//! ```rust
//! use octarine::observe::writers::{LogDirectory, LogFilename, RotationConfig, RotationSchedule};
//!
//! // Type-safe path construction with validation
//! let log_dir = LogDirectory::new("/var/log/myapp").expect("valid log directory");
//! let filename = LogFilename::new("app.log").expect("valid filename");
//!
//! // Rotation configuration
//! let rotation = RotationConfig::builder()
//!     .schedule(RotationSchedule::Daily)
//!     .compress_rotated(true)
//!     .retention_days(90)
//!     .build();
//! ```

mod core;
mod query;
mod rotation;

use super::Writer;
use super::builder::FileWriterBuilder;
use super::query::{AuditQuery, QueryResult, Queryable};
#[cfg(test)]
use super::types::{LogDirectory, LogFilename, RotationConfig};
use super::types::{LogFormat, RotationSchedule, SeverityFilter, WriterError, WriterHealthStatus};
use crate::observe::Problem;
use crate::observe::types::{Event, Severity};
use crate::primitives::io::file::FileMode;
use crate::primitives::runtime::r#async::{CircuitBreaker, RetryPolicy};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::fs::File;
use tokio::sync::Mutex;

/// File writer for observability events
pub(in crate::observe::writers) struct FileWriter {
    /// Directory for log files (validated and secured)
    pub(super) log_dir: PathBuf,
    /// Base filename (sanitized)
    pub(super) filename: String,
    /// Minimum severity to log
    pub(super) min_severity: Severity,
    /// Maximum file size before rotation (bytes)
    pub(super) max_file_size: u64,
    /// Maximum number of backup files to keep
    pub(super) max_backups: usize,
    /// Time-based rotation schedule
    pub(super) rotation_schedule: RotationSchedule,
    /// Maximum age of file before rotation
    pub(super) max_age: Option<Duration>,
    /// Whether to compress rotated files
    pub(super) compress_rotated: bool,
    /// Compression level (1-9)
    pub(super) compression_level: u32,
    /// Retention period in days
    pub(super) retention_days: Option<u32>,
    /// File permissions for log files
    pub(super) file_mode: FileMode,
    /// Directory permissions
    #[allow(dead_code)]
    pub(super) dir_mode: FileMode,
    /// Durability mode for writes
    #[allow(dead_code)]
    pub(super) durability: super::types::DurabilityMode,
    /// Log output format (HumanReadable or JsonLines)
    pub(super) format: LogFormat,
    /// Current log file handle
    pub(super) file: Mutex<Option<File>>,
    /// Time when the current log file was opened
    #[allow(dead_code)]
    pub(super) file_opened_at: Mutex<Option<SystemTime>>,
    /// Circuit breaker for filesystem operations
    pub(super) fs_circuit_breaker: Arc<CircuitBreaker>,
    /// Retry policy for transient failures
    pub(super) retry_policy: RetryPolicy,
    /// Timeout for individual file operations
    pub(super) operation_timeout: Duration,
}

impl FileWriter {
    /// Create a FileWriter from a builder (internal use)
    ///
    /// This is the primary constructor, called by FileWriterBuilder.
    /// Users should use FileWriterBuilder::new() instead.
    pub(in crate::observe::writers) async fn from_builder(
        builder: FileWriterBuilder,
    ) -> Result<Self, Problem> {
        core::from_builder(builder).await
    }

    /// Legacy constructor for backward compatibility with tests
    ///
    /// # Deprecated
    ///
    /// Use `FileWriterBuilder` instead for type-safe construction.
    ///
    /// This method performs runtime validation that the builder
    /// enforces at compile time.
    #[cfg(test)]
    pub(super) async fn new(log_dir: &str, filename: &str) -> Result<Self, Problem> {
        let log_dir = LogDirectory::new(log_dir)?;
        let filename = LogFilename::new(filename)?;
        FileWriterBuilder::new(log_dir, filename).build().await
    }

    /// Legacy constructor with rotation for backward compatibility with tests
    ///
    /// # Deprecated
    ///
    /// Use `FileWriterBuilder` instead.
    #[cfg(test)]
    pub(super) async fn with_rotation(
        log_dir: &str,
        filename: &str,
        max_file_size: u64,
        max_backups: usize,
    ) -> Result<Self, Problem> {
        let log_dir = LogDirectory::new(log_dir)?;
        let filename = LogFilename::new(filename)?;
        FileWriterBuilder::new(log_dir, filename)
            .with_rotation(RotationConfig::new(max_file_size, max_backups))
            .build()
            .await
    }

    /// Legacy method for backward compatibility with tests
    #[cfg(test)]
    pub(super) fn with_min_severity(self, severity: Severity) -> Self {
        // This is now handled by the builder, but we keep it for test compatibility
        Self {
            min_severity: severity,
            ..self
        }
    }

    /// Get the current log file path
    pub(super) fn current_log_path(&self) -> PathBuf {
        self.log_dir.join(&self.filename)
    }

    /// Get the path for a rotated log file
    pub(super) fn rotated_log_path(&self, index: usize) -> PathBuf {
        self.log_dir.join(format!("{}.{}", self.filename, index))
    }

    /// Get the number of deleted files from the last retention enforcement
    ///
    /// Call this after `enforce_retention()` to see how many files were cleaned up.
    pub async fn enforce_retention_now(&self) -> Result<usize, Problem> {
        rotation::enforce_retention(self).await
    }

    /// Write event synchronously (for testing)
    #[cfg(test)]
    async fn write_event(&self, event: &Event) -> Result<(), Problem> {
        use tokio::io::AsyncWriteExt;

        // Check severity filter
        if event.severity < self.min_severity {
            return Ok(());
        }

        let log_line = core::format_event(self, event);
        let mut file_guard = core::get_file(self).await?;

        if let Some(ref mut file) = *file_guard {
            file.write_all(log_line.as_bytes()).await.map_err(|e| {
                Problem::operation_failed(format!("Failed to write to log file: {}", e))
            })?;

            file.flush().await.map_err(|e| {
                Problem::operation_failed(format!("Failed to flush log file: {}", e))
            })?;
        }

        Ok(())
    }
}

#[async_trait]
impl Writer for FileWriter {
    async fn write(&self, event: &Event) -> Result<(), WriterError> {
        // Check severity filter
        if event.severity < self.min_severity {
            return Ok(());
        }

        let log_line = core::format_event(self, event);
        let mut file_guard = core::get_file(self).await.map_err(WriterError::from)?;

        if let Some(ref mut file) = *file_guard {
            use tokio::io::AsyncWriteExt;
            file.write_all(log_line.as_bytes()).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), WriterError> {
        let mut file_guard = self.file.lock().await;
        if let Some(ref mut file) = *file_guard {
            use tokio::io::AsyncWriteExt;
            file.flush().await?;
        }
        Ok(())
    }

    fn health_check(&self) -> WriterHealthStatus {
        // Check if the circuit breaker is healthy
        if !self.fs_circuit_breaker.can_proceed() {
            return WriterHealthStatus::Unhealthy;
        }

        // For async health checks, we return based on circuit breaker state
        // A more thorough check would need to be async
        WriterHealthStatus::Healthy
    }

    fn name(&self) -> &'static str {
        "file"
    }

    fn severity_filter(&self) -> SeverityFilter {
        SeverityFilter::with_min_severity(self.min_severity)
    }
}

/// Queryable implementation for FileWriter (JSONL format only)
///
/// When using JSONL format, FileWriter supports querying stored events.
/// This enables compliance reporting, debugging, and audit analysis
/// directly from log files without external tools.
///
/// # Limitations
///
/// - Only works with `LogFormat::JsonLines` format
/// - Human-readable format returns an error
/// - Reads files synchronously in a blocking task
///
/// # Performance
///
/// For large log files, consider:
/// - Using date-based queries to limit scanned files
/// - Using the `limit` parameter for pagination
/// - Archiving old logs to cold storage
#[async_trait]
impl Queryable for FileWriter {
    async fn query(&self, audit_query: &AuditQuery) -> Result<QueryResult, WriterError> {
        query::query_events(self, audit_query).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::observe::types::{Event, EventType};

    #[tokio::test]
    async fn test_new_validates_paths() {
        // Relative paths should be rejected
        let result = FileWriter::new("relative/path", "app.log").await;
        assert!(result.is_err());

        // Command injection should be caught
        let result = FileWriter::new("/tmp/$(whoami)/logs", "app.log").await;
        assert!(result.is_err());

        // Shell metacharacters should be caught
        let result = FileWriter::new("/tmp; rm -rf /", "app.log").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_filename_sanitization() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_filename_sanitization");
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        // Dangerous filename should be sanitized
        let log_dir_str = log_dir
            .to_str()
            .expect("Temp dir path should be valid UTF-8");
        let writer = FileWriter::new(log_dir_str, "app../../../etc/passwd.log")
            .await
            .expect("FileWriter should accept and sanitize dangerous filename");

        // Filename should have traversal sequences removed
        assert!(!writer.filename.contains(".."));
        assert!(!writer.filename.contains('/'));

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_severity_filter() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_severity");
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_str = log_dir
            .to_str()
            .expect("Temp dir path should be valid UTF-8");
        let writer = FileWriter::new(log_dir_str, "test.log")
            .await
            .expect("Failed to create FileWriter")
            .with_min_severity(Severity::Warning);

        // Debug and Info should be filtered out
        let debug_event = Event::new(EventType::Debug, "Debug message");
        writer
            .write_event(&debug_event)
            .await
            .expect("Failed to write debug event");

        let info_event = Event::new(EventType::Info, "Info message");
        writer
            .write_event(&info_event)
            .await
            .expect("Failed to write info event");

        // Warning should be logged
        let warning_event = Event::new(EventType::Warning, "Warning message");
        writer
            .write_event(&warning_event)
            .await
            .expect("Failed to write warning event");
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure file is closed
        drop(writer);

        // Read log file
        let log_path = log_dir.join("test.log");
        let contents = tokio::fs::read_to_string(&log_path)
            .await
            .expect("Failed to read log file");

        // Only warning should be present
        assert!(!contents.contains("Debug message"));
        assert!(!contents.contains("Info message"));
        assert!(contents.contains("Warning message"));

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_health_check() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_health");
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_str = log_dir
            .to_str()
            .expect("Temp dir path should be valid UTF-8");
        let writer = FileWriter::new(log_dir_str, "test.log")
            .await
            .expect("Failed to create FileWriter");

        // Health check should pass
        assert!(writer.health_check().is_healthy());

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }
}
