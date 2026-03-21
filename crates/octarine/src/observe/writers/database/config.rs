//! Configuration types for database writers

use std::time::Duration;

/// Configuration for database writers
///
/// Controls batching, flushing, and retention behavior.
///
/// # Example
///
/// ```rust
/// use octarine::observe::writers::DatabaseWriterConfig;
/// use std::time::Duration;
///
/// let config = DatabaseWriterConfig::builder()
///     .table_name("audit_events")
///     .batch_size(100)
///     .flush_interval(Duration::from_secs(5))
///     .retention_days(90)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct DatabaseWriterConfig {
    /// Table name for audit events
    pub table_name: String,

    /// Number of events to batch before writing
    pub batch_size: usize,

    /// Maximum time to wait before flushing a partial batch
    pub flush_interval: Duration,

    /// Number of days to retain events (for retention enforcement)
    pub retention_days: u32,

    /// Whether to automatically run migrations on startup
    pub auto_migrate: bool,

    /// Maximum number of retries for failed writes
    pub max_retries: usize,

    /// Base delay between retries (with exponential backoff)
    pub retry_delay: Duration,
}

impl DatabaseWriterConfig {
    /// Create a builder for configuration
    pub fn builder() -> DatabaseWriterConfigBuilder {
        DatabaseWriterConfigBuilder::default()
    }

    /// Production configuration
    ///
    /// - 100 event batches
    /// - 5 second flush interval
    /// - 90 day retention (SOC2 minimum)
    pub fn production() -> Self {
        Self {
            table_name: "audit_events".to_string(),
            batch_size: 100,
            flush_interval: Duration::from_secs(5),
            retention_days: 90,
            auto_migrate: false,
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
        }
    }

    /// Development configuration
    ///
    /// - Smaller batches for faster feedback
    /// - Shorter retention
    /// - Auto-migrate enabled
    pub fn development() -> Self {
        Self {
            table_name: "audit_events".to_string(),
            batch_size: 10,
            flush_interval: Duration::from_secs(1),
            retention_days: 7,
            auto_migrate: true,
            max_retries: 1,
            retry_delay: Duration::from_millis(50),
        }
    }

    /// High-compliance configuration
    ///
    /// - Longer retention (1 year for PCI-DSS)
    /// - More retries for reliability
    pub fn high_compliance() -> Self {
        Self {
            table_name: "audit_events".to_string(),
            batch_size: 100,
            flush_interval: Duration::from_secs(5),
            retention_days: 365,
            auto_migrate: false,
            max_retries: 5,
            retry_delay: Duration::from_millis(200),
        }
    }
}

impl Default for DatabaseWriterConfig {
    fn default() -> Self {
        Self::production()
    }
}

/// Builder for DatabaseWriterConfig
#[derive(Debug, Default)]
pub struct DatabaseWriterConfigBuilder {
    table_name: Option<String>,
    batch_size: Option<usize>,
    flush_interval: Option<Duration>,
    retention_days: Option<u32>,
    auto_migrate: Option<bool>,
    max_retries: Option<usize>,
    retry_delay: Option<Duration>,
}

impl DatabaseWriterConfigBuilder {
    /// Set the table name
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = Some(name.into());
        self
    }

    /// Set the batch size
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Set the flush interval
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = Some(interval);
        self
    }

    /// Set the retention period in days
    pub fn retention_days(mut self, days: u32) -> Self {
        self.retention_days = Some(days);
        self
    }

    /// Enable or disable auto-migration
    pub fn auto_migrate(mut self, enabled: bool) -> Self {
        self.auto_migrate = Some(enabled);
        self
    }

    /// Set the maximum number of retries
    pub fn max_retries(mut self, retries: usize) -> Self {
        self.max_retries = Some(retries);
        self
    }

    /// Set the base retry delay
    pub fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = Some(delay);
        self
    }

    /// Build the configuration
    pub fn build(self) -> DatabaseWriterConfig {
        let defaults = DatabaseWriterConfig::production();
        DatabaseWriterConfig {
            table_name: self.table_name.unwrap_or(defaults.table_name),
            batch_size: self.batch_size.unwrap_or(defaults.batch_size),
            flush_interval: self.flush_interval.unwrap_or(defaults.flush_interval),
            retention_days: self.retention_days.unwrap_or(defaults.retention_days),
            auto_migrate: self.auto_migrate.unwrap_or(defaults.auto_migrate),
            max_retries: self.max_retries.unwrap_or(defaults.max_retries),
            retry_delay: self.retry_delay.unwrap_or(defaults.retry_delay),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_production_defaults() {
        let config = DatabaseWriterConfig::production();
        assert_eq!(config.table_name, "audit_events");
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.retention_days, 90);
        assert!(!config.auto_migrate);
    }

    #[test]
    fn test_development_config() {
        let config = DatabaseWriterConfig::development();
        assert_eq!(config.batch_size, 10);
        assert_eq!(config.retention_days, 7);
        assert!(config.auto_migrate);
    }

    #[test]
    fn test_high_compliance_config() {
        let config = DatabaseWriterConfig::high_compliance();
        assert_eq!(config.retention_days, 365);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_builder() {
        let config = DatabaseWriterConfig::builder()
            .table_name("custom_audit")
            .batch_size(50)
            .retention_days(180)
            .build();

        assert_eq!(config.table_name, "custom_audit");
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.retention_days, 180);
        // Defaults should be applied for unset values
        assert_eq!(config.flush_interval, Duration::from_secs(5));
    }
}
