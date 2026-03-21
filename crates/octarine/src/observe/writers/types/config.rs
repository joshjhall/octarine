//! Writer configuration types
//!
//! Common configuration for writers and rotation settings.

use super::SeverityFilter;
use std::time::Duration;

/// Common configuration for writers
///
/// Provides sensible defaults and presets for different environments.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Number of events to batch before writing
    pub batch_size: usize,

    /// Maximum time to wait before flushing a partial batch
    pub flush_interval: Duration,

    /// Maximum number of events to buffer
    pub buffer_size: usize,

    /// Severity filter
    pub severity_filter: SeverityFilter,

    /// Whether to block when buffer is full
    pub block_on_full: bool,

    /// Maximum retries on failure
    pub max_retries: usize,

    /// Base delay between retries
    pub retry_delay: Duration,
}

impl WriterConfig {
    /// Configuration for production use
    ///
    /// - Batches of 100 events
    /// - Flush every 5 seconds
    /// - 10,000 event buffer
    /// - Info and above severity
    pub fn production() -> Self {
        Self {
            batch_size: 100,
            flush_interval: Duration::from_secs(5),
            buffer_size: 10_000,
            severity_filter: SeverityFilter::production(),
            block_on_full: false,
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
        }
    }

    /// Configuration for development use
    ///
    /// - No batching (immediate writes)
    /// - Include debug events
    /// - Smaller buffer
    pub fn development() -> Self {
        Self {
            batch_size: 1,
            flush_interval: Duration::from_millis(100),
            buffer_size: 1_000,
            severity_filter: SeverityFilter::all(),
            block_on_full: true,
            max_retries: 1,
            retry_delay: Duration::from_millis(10),
        }
    }

    /// Configuration for high-throughput scenarios
    ///
    /// - Large batches
    /// - Larger buffer
    /// - Drop events on overflow
    pub fn high_throughput() -> Self {
        Self {
            batch_size: 500,
            flush_interval: Duration::from_secs(10),
            buffer_size: 100_000,
            severity_filter: SeverityFilter::production(),
            block_on_full: false,
            max_retries: 2,
            retry_delay: Duration::from_millis(50),
        }
    }
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self::production()
    }
}

/// Schedule for time-based log rotation
///
/// Determines when log files should be rotated based on time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RotationSchedule {
    /// Rotate logs every hour
    Hourly,
    /// Rotate logs daily at midnight
    #[default]
    Daily,
    /// Rotate logs weekly (Sunday at midnight)
    Weekly,
    /// Only rotate based on size (no time-based rotation)
    SizeOnly,
    /// Never rotate (for testing or special cases)
    Never,
}

/// Log output format
///
/// Controls how events are formatted when written to log files.
///
/// # Choosing a Format
///
/// - **HumanReadable**: Best for development and manual log inspection
/// - **JsonLines**: Best for log aggregation (ELK, Splunk), querying, and compliance
///
/// # Compliance Considerations
///
/// - **SOC 2**: JSONL recommended for tamper-evident audit trails
/// - **HIPAA**: JSONL enables structured PHI access logging
/// - **PCI DSS**: JSONL supports log integrity verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable format (default)
    ///
    /// Format: `[timestamp] LEVEL operation: message context`
    ///
    /// Best for development, debugging, and manual inspection.
    /// Easier to read in terminals and log viewers.
    #[default]
    HumanReadable,

    /// JSON Lines format (one JSON object per line)
    ///
    /// Each line is a complete, valid JSON object containing:
    /// - `id`: Event UUID
    /// - `timestamp`: ISO 8601 timestamp
    /// - `severity`: Log level
    /// - `event_type`: Type of event
    /// - `message`: Event message
    /// - `context`: Structured context (tenant, user, operation, etc.)
    /// - `metadata`: Additional key-value data
    ///
    /// Best for:
    /// - Log aggregation systems (ELK Stack, Splunk, Datadog)
    /// - Programmatic log analysis
    /// - Compliance requirements (queryable audit trails)
    /// - Long-term archival with schema preservation
    JsonLines,
}

impl LogFormat {
    /// Check if this format is human readable
    pub fn is_human_readable(&self) -> bool {
        matches!(self, Self::HumanReadable)
    }

    /// Check if this format is structured (JSON)
    pub fn is_structured(&self) -> bool {
        matches!(self, Self::JsonLines)
    }

    /// Get the recommended file extension for this format
    pub fn file_extension(&self) -> &'static str {
        match self {
            Self::HumanReadable => "log",
            Self::JsonLines => "jsonl",
        }
    }
}

/// Durability mode for log writes
///
/// Controls when data is synced to disk, trading off between
/// performance and data safety. Higher durability = slower writes.
///
/// # Compliance Considerations
///
/// - **SOC 2**: Use `OnFlush` or `Immediate` for audit logs
/// - **HIPAA**: Use `Immediate` for PHI-related events
/// - **PCI DSS**: Use `OnFlush` minimum for transaction logs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DurabilityMode {
    /// Sync handled by OS (fastest, least safe)
    ///
    /// Data may be lost on crash. Suitable for debug logs
    /// or high-volume non-critical events.
    OsManaged,

    /// Sync when files are rotated (balanced)
    ///
    /// Data since last rotation may be lost on crash.
    /// Good balance for most production use cases.
    #[default]
    OnRotation,

    /// Sync on explicit flush calls (recommended for compliance)
    ///
    /// Provides good durability with reasonable performance.
    /// Suitable for audit logs and compliance scenarios.
    OnFlush,

    /// Sync after every write (slowest, safest)
    ///
    /// Maximum durability, significant performance impact.
    /// Use only for critical compliance requirements.
    Immediate,
}

/// Configuration for log rotation
///
/// Controls when and how log files are rotated to prevent
/// disk exhaustion and manage log file sizes.
///
/// # Rotation Triggers
///
/// Rotation is triggered when ANY of these conditions are met:
/// - File size exceeds `max_file_size`
/// - Time interval reached (based on `schedule`)
/// - File age exceeds `max_age` (if set)
///
/// # Example
///
/// ```rust
/// use octarine::observe::writers::{RotationConfig, RotationSchedule};
/// use std::time::Duration;
///
/// let config = RotationConfig::builder()
///     .max_file_size(50 * 1024 * 1024)  // 50 MB
///     .schedule(RotationSchedule::Daily)
///     .max_backups(7)
///     .compress_rotated(true)
///     .retention_days(30)
///     .build();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationConfig {
    /// Maximum file size in bytes before rotation
    pub max_file_size: u64,
    /// Maximum number of backup files to keep
    pub max_backups: usize,
    /// Time-based rotation schedule
    pub schedule: RotationSchedule,
    /// Maximum age of the current log file before rotation
    pub max_age: Option<Duration>,
    /// Whether to compress rotated files with gzip
    pub compress_rotated: bool,
    /// Compression level (1-9, higher = better compression, slower)
    pub compression_level: u32,
    /// Number of days to retain rotated files (for retention enforcement)
    pub retention_days: Option<u32>,
}

impl RotationConfig {
    /// Create a new rotation configuration
    pub fn new(max_file_size: u64, max_backups: usize) -> Self {
        Self {
            max_file_size,
            max_backups,
            schedule: RotationSchedule::SizeOnly,
            max_age: None,
            compress_rotated: false,
            compression_level: 6,
            retention_days: None,
        }
    }

    /// Create a builder for more detailed configuration
    pub fn builder() -> RotationConfigBuilder {
        RotationConfigBuilder::default()
    }

    /// Default configuration for production use
    /// - 100 MB max file size
    /// - Daily rotation
    /// - 5 backup files
    /// - Compression enabled
    /// - 90 day retention (SOC2 minimum)
    pub fn production() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100 MB
            max_backups: 5,
            schedule: RotationSchedule::Daily,
            max_age: Some(Duration::from_secs(24 * 60 * 60)), // 24 hours
            compress_rotated: true,
            compression_level: 6,
            retention_days: Some(90),
        }
    }

    /// Configuration for development use
    /// - 10 MB max file size
    /// - Size-only rotation
    /// - 3 backup files
    /// - No compression
    /// - 7 day retention
    pub fn development() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024, // 10 MB
            max_backups: 3,
            schedule: RotationSchedule::SizeOnly,
            max_age: None,
            compress_rotated: false,
            compression_level: 1,
            retention_days: Some(7),
        }
    }

    /// Configuration for testing
    /// - 1 MB max file size
    /// - Size-only rotation
    /// - 2 backup files
    /// - No compression
    pub fn testing() -> Self {
        Self {
            max_file_size: 1024 * 1024, // 1 MB
            max_backups: 2,
            schedule: RotationSchedule::SizeOnly,
            max_age: None,
            compress_rotated: false,
            compression_level: 1,
            retention_days: None,
        }
    }

    /// High compliance configuration
    /// - 50 MB max file size
    /// - Hourly rotation
    /// - 24 backup files (24 hours)
    /// - Compression enabled
    /// - 365 day retention (PCI-DSS)
    pub fn high_compliance() -> Self {
        Self {
            max_file_size: 50 * 1024 * 1024, // 50 MB
            max_backups: 24,
            schedule: RotationSchedule::Hourly,
            max_age: Some(Duration::from_secs(60 * 60)), // 1 hour
            compress_rotated: true,
            compression_level: 9,
            retention_days: Some(365),
        }
    }
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self::production()
    }
}

/// Builder for RotationConfig
#[derive(Debug, Default)]
pub struct RotationConfigBuilder {
    max_file_size: Option<u64>,
    max_backups: Option<usize>,
    schedule: Option<RotationSchedule>,
    max_age: Option<Duration>,
    compress_rotated: Option<bool>,
    compression_level: Option<u32>,
    retention_days: Option<u32>,
}

impl RotationConfigBuilder {
    /// Set maximum file size in bytes
    pub fn max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = Some(size);
        self
    }

    /// Set maximum number of backup files
    pub fn max_backups(mut self, backups: usize) -> Self {
        self.max_backups = Some(backups);
        self
    }

    /// Set rotation schedule
    pub fn schedule(mut self, schedule: RotationSchedule) -> Self {
        self.schedule = Some(schedule);
        self
    }

    /// Set maximum age before rotation
    pub fn max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }

    /// Enable or disable compression of rotated files
    pub fn compress_rotated(mut self, compress: bool) -> Self {
        self.compress_rotated = Some(compress);
        self
    }

    /// Set compression level (1-9)
    pub fn compression_level(mut self, level: u32) -> Self {
        self.compression_level = Some(level.clamp(1, 9));
        self
    }

    /// Set retention period in days
    pub fn retention_days(mut self, days: u32) -> Self {
        self.retention_days = Some(days);
        self
    }

    /// Build the configuration
    pub fn build(self) -> RotationConfig {
        let defaults = RotationConfig::production();
        RotationConfig {
            max_file_size: self.max_file_size.unwrap_or(defaults.max_file_size),
            max_backups: self.max_backups.unwrap_or(defaults.max_backups),
            schedule: self.schedule.unwrap_or(defaults.schedule),
            max_age: self.max_age.or(defaults.max_age),
            compress_rotated: self.compress_rotated.unwrap_or(defaults.compress_rotated),
            compression_level: self.compression_level.unwrap_or(defaults.compression_level),
            retention_days: self.retention_days.or(defaults.retention_days),
        }
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
    fn test_rotation_config_defaults() {
        let config = RotationConfig::default();
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert_eq!(config.max_backups, 5);
        assert_eq!(config.schedule, RotationSchedule::Daily);
        assert!(config.compress_rotated);
        assert_eq!(config.retention_days, Some(90));
    }

    #[test]
    fn test_rotation_config_presets() {
        let prod = RotationConfig::production();
        assert_eq!(prod.max_file_size, 100 * 1024 * 1024);
        assert_eq!(prod.schedule, RotationSchedule::Daily);
        assert!(prod.compress_rotated);

        let dev = RotationConfig::development();
        assert_eq!(dev.max_file_size, 10 * 1024 * 1024);
        assert_eq!(dev.schedule, RotationSchedule::SizeOnly);
        assert!(!dev.compress_rotated);

        let test = RotationConfig::testing();
        assert_eq!(test.max_file_size, 1024 * 1024);
        assert_eq!(test.schedule, RotationSchedule::SizeOnly);
    }

    #[test]
    fn test_rotation_config_high_compliance() {
        let config = RotationConfig::high_compliance();
        assert_eq!(config.schedule, RotationSchedule::Hourly);
        assert_eq!(config.max_backups, 24);
        assert!(config.compress_rotated);
        assert_eq!(config.compression_level, 9);
        assert_eq!(config.retention_days, Some(365));
    }

    #[test]
    fn test_rotation_config_builder() {
        let config = RotationConfig::builder()
            .max_file_size(50 * 1024 * 1024)
            .max_backups(10)
            .schedule(RotationSchedule::Weekly)
            .compress_rotated(true)
            .compression_level(8)
            .retention_days(180)
            .build();

        assert_eq!(config.max_file_size, 50 * 1024 * 1024);
        assert_eq!(config.max_backups, 10);
        assert_eq!(config.schedule, RotationSchedule::Weekly);
        assert!(config.compress_rotated);
        assert_eq!(config.compression_level, 8);
        assert_eq!(config.retention_days, Some(180));
    }

    #[test]
    fn test_rotation_schedule_default() {
        let schedule = RotationSchedule::default();
        assert_eq!(schedule, RotationSchedule::Daily);
    }

    #[test]
    fn test_log_format_default() {
        let format = LogFormat::default();
        assert_eq!(format, LogFormat::HumanReadable);
    }

    #[test]
    fn test_log_format_properties() {
        // HumanReadable
        let human = LogFormat::HumanReadable;
        assert!(human.is_human_readable());
        assert!(!human.is_structured());
        assert_eq!(human.file_extension(), "log");

        // JsonLines
        let jsonl = LogFormat::JsonLines;
        assert!(!jsonl.is_human_readable());
        assert!(jsonl.is_structured());
        assert_eq!(jsonl.file_extension(), "jsonl");
    }
}
