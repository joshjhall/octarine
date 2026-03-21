//! DatabaseWriter implementation
//!
//! Wraps a database backend to provide event batching, retries, and retention.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

use crate::observe::types::Event;
use crate::observe::writers::Writer;
use crate::observe::writers::types::{SeverityFilter, WriterError, WriterHealthStatus};

use super::config::DatabaseWriterConfig;
use super::query::AuditQuery;
use super::traits::{DatabaseBackend, QueryResult};

/// Database writer for audit event persistence
///
/// Provides batching, automatic retries, and retention enforcement.
/// Works with any backend implementing the `DatabaseBackend` trait.
///
/// # Example
///
/// ```rust
/// use octarine::observe::writers::{DatabaseWriter, DatabaseWriterConfig, InMemoryBackend};
///
/// let backend = InMemoryBackend::new();
/// let config = DatabaseWriterConfig::development();
/// let writer = DatabaseWriter::new(backend, config);
///
/// // Writer is now ready to receive events via the Writer trait
/// ```
pub struct DatabaseWriter<B: DatabaseBackend> {
    backend: Arc<B>,
    config: DatabaseWriterConfig,
    batch: RwLock<Vec<Event>>,
    last_flush: RwLock<Instant>,
    health: RwLock<WriterHealthStatus>,
    consecutive_failures: RwLock<usize>,
}

impl<B: DatabaseBackend> DatabaseWriter<B> {
    /// Create a new database writer with the given backend and config
    pub fn new(backend: B, config: DatabaseWriterConfig) -> Self {
        Self {
            backend: Arc::new(backend),
            config,
            batch: RwLock::new(Vec::new()),
            last_flush: RwLock::new(Instant::now()),
            health: RwLock::new(WriterHealthStatus::Healthy),
            consecutive_failures: RwLock::new(0),
        }
    }

    /// Create with default production config
    pub fn production(backend: B) -> Self {
        Self::new(backend, DatabaseWriterConfig::production())
    }

    /// Create with development config
    pub fn development(backend: B) -> Self {
        Self::new(backend, DatabaseWriterConfig::development())
    }

    /// Create with high compliance config
    pub fn high_compliance(backend: B) -> Self {
        Self::new(backend, DatabaseWriterConfig::high_compliance())
    }

    /// Query events from the database
    pub async fn query(&self, query: AuditQuery) -> Result<QueryResult, WriterError> {
        self.backend.query_events(&query).await
    }

    /// Get a single event by ID
    pub async fn get_event(&self, id: uuid::Uuid) -> Result<Option<Event>, WriterError> {
        self.backend.get_event(id).await
    }

    /// Count events matching a query
    pub async fn count(&self, query: AuditQuery) -> Result<usize, WriterError> {
        self.backend.count_events(&query).await
    }

    /// Run retention cleanup
    ///
    /// Deletes events older than the configured retention period.
    /// Returns the number of events deleted.
    pub async fn enforce_retention(&self) -> Result<usize, WriterError> {
        self.backend.delete_before(self.config.retention_days).await
    }

    /// Run database migrations (if supported by backend)
    pub async fn migrate(&self) -> Result<(), WriterError> {
        self.backend.migrate().await
    }

    /// Check if the batch should be flushed
    async fn should_flush(&self) -> bool {
        let batch = self.batch.read().await;
        let last_flush = self.last_flush.read().await;

        batch.len() >= self.config.batch_size || last_flush.elapsed() >= self.config.flush_interval
    }

    /// Flush the batch to the database with retries
    async fn flush_batch(&self) -> Result<usize, WriterError> {
        let events = {
            let mut batch = self.batch.write().await;
            std::mem::take(&mut *batch)
        };

        if events.is_empty() {
            return Ok(0);
        }

        let mut last_error = None;
        let mut delay = self.config.retry_delay;

        for attempt in 0..=self.config.max_retries {
            match self.backend.store_events(&events).await {
                Ok(count) => {
                    // Reset failure tracking on success
                    *self.consecutive_failures.write().await = 0;
                    *self.health.write().await = WriterHealthStatus::Healthy;
                    *self.last_flush.write().await = Instant::now();
                    return Ok(count);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(delay).await;
                        // Exponential backoff (capped at 10 seconds)
                        delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(10));
                    }
                }
            }
        }

        // All retries failed
        let mut failures = self.consecutive_failures.write().await;
        *failures = failures.saturating_add(1);

        // Update health status based on consecutive failures
        let mut health = self.health.write().await;
        *health = if *failures >= 3 {
            WriterHealthStatus::Unhealthy
        } else {
            WriterHealthStatus::Degraded
        };

        // Re-add events to batch for next attempt
        let mut batch = self.batch.write().await;
        batch.extend(events);

        Err(last_error.unwrap_or(WriterError::Other("Unknown error".to_string())))
    }

    /// Get the current configuration
    pub fn config(&self) -> &DatabaseWriterConfig {
        &self.config
    }

    /// Get a reference to the backend
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[async_trait]
impl<B: DatabaseBackend + 'static> Writer for DatabaseWriter<B> {
    async fn write(&self, event: &Event) -> Result<(), WriterError> {
        // Add to batch
        {
            let mut batch = self.batch.write().await;
            batch.push(event.clone());
        }

        // Flush if needed
        if self.should_flush().await {
            self.flush_batch().await?;
        }

        Ok(())
    }

    async fn write_batch(&self, events: &[Event]) -> Result<usize, WriterError> {
        if events.is_empty() {
            return Ok(0);
        }

        // Add all to batch
        {
            let mut batch = self.batch.write().await;
            batch.extend(events.iter().cloned());
        }

        // Force flush for batch writes
        self.flush_batch().await
    }

    async fn flush(&self) -> Result<(), WriterError> {
        self.flush_batch().await?;
        Ok(())
    }

    fn health_check(&self) -> WriterHealthStatus {
        // Try to get current health status without blocking
        self.health
            .try_read()
            .map(|h| *h)
            .unwrap_or(WriterHealthStatus::Degraded)
    }

    fn name(&self) -> &'static str {
        self.backend.name()
    }

    fn severity_filter(&self) -> SeverityFilter {
        // Database writers typically capture all events for compliance
        SeverityFilter::all()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::types::EventType;
    use crate::observe::writers::database::traits::InMemoryBackend;

    fn test_event() -> Event {
        Event::new(EventType::Info, "Test event")
    }

    #[tokio::test]
    async fn test_database_writer_write() {
        let backend = InMemoryBackend::new();
        let config = DatabaseWriterConfig::builder().batch_size(10).build();
        let writer = DatabaseWriter::new(backend, config);

        writer
            .write(&test_event())
            .await
            .expect("write should succeed");

        // Event should be in batch but not flushed yet
        let batch = writer.batch.read().await;
        assert_eq!(batch.len(), 1);
    }

    #[tokio::test]
    async fn test_database_writer_batch_flush() {
        let backend = InMemoryBackend::new();
        let config = DatabaseWriterConfig::builder().batch_size(2).build();
        let writer = DatabaseWriter::new(backend, config);

        writer
            .write(&test_event())
            .await
            .expect("first write should succeed");
        writer
            .write(&test_event())
            .await
            .expect("second write should succeed");

        // Should have triggered flush
        let events = writer.backend.all_events();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_database_writer_manual_flush() {
        let backend = InMemoryBackend::new();
        let config = DatabaseWriterConfig::builder().batch_size(100).build();
        let writer = DatabaseWriter::new(backend, config);

        writer
            .write(&test_event())
            .await
            .expect("write should succeed");
        writer.flush().await.expect("flush should succeed");

        let events = writer.backend.all_events();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_database_writer_write_batch() {
        let backend = InMemoryBackend::new();
        let writer = DatabaseWriter::development(backend);

        let events: Vec<Event> = (0..5).map(|_| test_event()).collect();
        let count = writer
            .write_batch(&events)
            .await
            .expect("write_batch should succeed");

        assert_eq!(count, 5);
        assert_eq!(writer.backend.all_events().len(), 5);
    }

    #[tokio::test]
    async fn test_database_writer_query() {
        let backend = InMemoryBackend::new();
        let writer = DatabaseWriter::development(backend);

        let events: Vec<Event> = (0..3).map(|_| test_event()).collect();
        writer
            .write_batch(&events)
            .await
            .expect("write_batch should succeed");

        let result = writer
            .query(AuditQuery::default())
            .await
            .expect("query should succeed");
        assert_eq!(result.events.len(), 3);
    }

    #[tokio::test]
    async fn test_database_writer_count() {
        let backend = InMemoryBackend::new();
        let writer = DatabaseWriter::development(backend);

        let events: Vec<Event> = (0..5).map(|_| test_event()).collect();
        writer
            .write_batch(&events)
            .await
            .expect("write_batch should succeed");

        let count = writer
            .count(AuditQuery::default())
            .await
            .expect("count should succeed");
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn test_database_writer_health() {
        let backend = InMemoryBackend::new();
        let writer = DatabaseWriter::development(backend);

        assert_eq!(writer.health_check(), WriterHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_database_writer_config_access() {
        let backend = InMemoryBackend::new();
        let config = DatabaseWriterConfig::high_compliance();
        let writer = DatabaseWriter::new(backend, config);

        assert_eq!(writer.config().retention_days, 365);
    }

    #[tokio::test]
    async fn test_database_writer_empty_batch() {
        let backend = InMemoryBackend::new();
        let writer = DatabaseWriter::development(backend);

        let count = writer
            .write_batch(&[])
            .await
            .expect("write_batch should succeed");
        assert_eq!(count, 0);
    }
}
