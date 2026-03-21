//! In-memory writer for testing and development
//!
//! `MemoryWriter` stores events in memory with support for querying.
//! Useful for:
//! - Unit and integration tests
//! - Development and debugging
//! - Short-lived applications that don't need persistence
//!
//! # Example
//!
//! ```rust
//! use octarine::observe::writers::{MemoryWriter, Writer, Queryable, AuditQuery};
//! use octarine::observe::{Event, EventType};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let writer = MemoryWriter::new();
//!
//! // Write some events
//! let event = Event::new(EventType::Info, "Test event");
//! writer.write(&event).await?;
//!
//! // Query events back
//! let result = writer.query(&AuditQuery::default()).await?;
//! assert_eq!(result.events.len(), 1);
//!
//! // Clear for next test
//! writer.clear();
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::RwLock;

use super::Writer;
use super::query::{AuditQuery, QueryResult, Queryable, filter_events, paginate_events};
use super::types::{WriterError, WriterHealthStatus};
use crate::observe::types::Event;

/// In-memory event writer for testing
///
/// Stores events in a bounded deque with thread-safe access.
/// Supports both writing and querying events.
///
/// # Thread Safety
///
/// All operations are thread-safe using `RwLock`.
///
/// # Capacity
///
/// By default, stores up to 10,000 events. Older events are
/// automatically removed when capacity is exceeded.
#[derive(Debug)]
pub struct MemoryWriter {
    /// Stored events (bounded deque)
    events: RwLock<VecDeque<Event>>,
    /// Maximum number of events to store
    max_events: usize,
}

impl Default for MemoryWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryWriter {
    /// Create a new memory writer with default capacity (10,000 events)
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }

    /// Create a memory writer with custom capacity
    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(max_events)),
            max_events,
        }
    }

    /// Get all stored events
    ///
    /// Returns a clone of all events. Useful for test assertions.
    pub fn all_events(&self) -> Vec<Event> {
        self.events
            .read()
            .map(|e| e.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get the number of stored events
    pub fn len(&self) -> usize {
        self.events.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if the writer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all stored events
    pub fn clear(&self) {
        if let Ok(mut events) = self.events.write() {
            events.clear();
        }
    }

    /// Get the most recent N events
    pub fn recent(&self, count: usize) -> Vec<Event> {
        self.events
            .read()
            .map(|e| e.iter().rev().take(count).cloned().collect())
            .unwrap_or_default()
    }
}

#[async_trait]
impl Writer for MemoryWriter {
    async fn write(&self, event: &Event) -> Result<(), WriterError> {
        let mut events = self
            .events
            .write()
            .map_err(|e| WriterError::Other(format!("Lock poisoned: {e}")))?;

        // Remove oldest if at capacity
        while events.len() >= self.max_events {
            events.pop_front();
        }

        events.push_back(event.clone());
        Ok(())
    }

    async fn write_batch(&self, batch: &[Event]) -> Result<usize, WriterError> {
        let mut events = self
            .events
            .write()
            .map_err(|e| WriterError::Other(format!("Lock poisoned: {e}")))?;

        let mut count: usize = 0;
        for event in batch {
            // Remove oldest if at capacity
            while events.len() >= self.max_events {
                events.pop_front();
            }
            events.push_back(event.clone());
            count = count.saturating_add(1);
        }

        Ok(count)
    }

    async fn flush(&self) -> Result<(), WriterError> {
        // No buffering - nothing to flush
        Ok(())
    }

    fn health_check(&self) -> WriterHealthStatus {
        // Check if lock is not poisoned
        match self.events.read() {
            Ok(_) => WriterHealthStatus::Healthy,
            Err(_) => WriterHealthStatus::Unhealthy,
        }
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}

#[async_trait]
impl Queryable for MemoryWriter {
    async fn query(&self, query: &AuditQuery) -> Result<QueryResult, WriterError> {
        let events = self
            .events
            .read()
            .map_err(|e| WriterError::Other(format!("Lock poisoned: {e}")))?;

        let all_events: Vec<Event> = events.iter().cloned().collect();
        let filtered = filter_events(&all_events, query);
        Ok(paginate_events(filtered, query))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::observe::types::{EventType, Severity};

    fn test_event(msg: &str) -> Event {
        Event::new(EventType::Info, msg)
    }

    #[tokio::test]
    async fn test_memory_writer_write_and_read() {
        let writer = MemoryWriter::new();

        writer
            .write(&test_event("event 1"))
            .await
            .expect("write should succeed");
        writer
            .write(&test_event("event 2"))
            .await
            .expect("write should succeed");

        assert_eq!(writer.len(), 2);
        assert!(!writer.is_empty());

        let events = writer.all_events();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_memory_writer_capacity() {
        let writer = MemoryWriter::with_capacity(3);

        for i in 0..5 {
            writer
                .write(&test_event(&format!("event {i}")))
                .await
                .expect("write should succeed");
        }

        // Should only have last 3 events
        assert_eq!(writer.len(), 3);

        let events = writer.all_events();
        assert!(
            events
                .first()
                .map(|e| e.message.contains("event 2"))
                .unwrap_or(false)
        );
        assert!(
            events
                .get(1)
                .map(|e| e.message.contains("event 3"))
                .unwrap_or(false)
        );
        assert!(
            events
                .get(2)
                .map(|e| e.message.contains("event 4"))
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn test_memory_writer_query() {
        let writer = MemoryWriter::new();

        // Write events with different types
        let info = Event::new(EventType::Info, "info event");
        let warning = Event::new(EventType::Warning, "warning event");
        let error = Event::new(EventType::SystemError, "error event");

        writer.write(&info).await.expect("write should succeed");
        writer.write(&warning).await.expect("write should succeed");
        writer.write(&error).await.expect("write should succeed");

        // Query by severity
        let query = AuditQuery {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };

        let result = writer.query(&query).await.expect("query should succeed");
        assert_eq!(result.events.len(), 2); // Warning + Error
    }

    #[tokio::test]
    async fn test_memory_writer_query_pagination() {
        let writer = MemoryWriter::new();

        for i in 0..10 {
            writer
                .write(&test_event(&format!("event {i}")))
                .await
                .expect("write should succeed");
        }

        let query = AuditQuery {
            limit: Some(3),
            offset: Some(2),
            ascending: true,
            ..Default::default()
        };

        let result = writer.query(&query).await.expect("query should succeed");
        assert_eq!(result.events.len(), 3);
        assert_eq!(result.total_count, Some(10));
        assert!(result.has_more);

        // Check order (ascending = oldest first)
        assert!(
            result
                .events
                .first()
                .map(|e| e.message.contains("event 2"))
                .unwrap_or(false)
        );
        assert!(
            result
                .events
                .get(1)
                .map(|e| e.message.contains("event 3"))
                .unwrap_or(false)
        );
        assert!(
            result
                .events
                .get(2)
                .map(|e| e.message.contains("event 4"))
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn test_memory_writer_clear() {
        let writer = MemoryWriter::new();

        writer
            .write(&test_event("test"))
            .await
            .expect("write should succeed");
        assert_eq!(writer.len(), 1);

        writer.clear();
        assert_eq!(writer.len(), 0);
        assert!(writer.is_empty());
    }

    #[tokio::test]
    async fn test_memory_writer_recent() {
        let writer = MemoryWriter::new();

        for i in 0..5 {
            writer
                .write(&test_event(&format!("event {i}")))
                .await
                .expect("write should succeed");
        }

        let recent = writer.recent(2);
        assert_eq!(recent.len(), 2);
        assert!(
            recent
                .first()
                .map(|e| e.message.contains("event 4"))
                .unwrap_or(false)
        ); // Most recent first
        assert!(
            recent
                .get(1)
                .map(|e| e.message.contains("event 3"))
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn test_memory_writer_batch_write() {
        let writer = MemoryWriter::new();

        let events: Vec<Event> = (0..5)
            .map(|i| test_event(&format!("batch event {i}")))
            .collect();

        let count = writer
            .write_batch(&events)
            .await
            .expect("batch write should succeed");
        assert_eq!(count, 5);
        assert_eq!(writer.len(), 5);
    }

    #[test]
    fn test_memory_writer_health_check() {
        let writer = MemoryWriter::new();
        assert!(matches!(writer.health_check(), WriterHealthStatus::Healthy));
    }

    #[test]
    fn test_memory_writer_name() {
        let writer = MemoryWriter::new();
        assert_eq!(writer.name(), "memory");
    }
}
