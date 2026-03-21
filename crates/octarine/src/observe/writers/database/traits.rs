//! Database backend trait for pluggable storage
//!
//! Provides an abstraction layer so users can implement their own
//! database backends without depending on specific database libraries.

use async_trait::async_trait;
use uuid::Uuid;

use crate::observe::types::Event;
use crate::observe::writers::query::ParseErrorInfo;
use crate::observe::writers::types::WriterError;

use super::query::AuditQuery;

/// Result of a query operation
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// Events matching the query
    pub events: Vec<Event>,

    /// Total count (for pagination)
    pub total_count: Option<usize>,

    /// Whether there are more results
    pub has_more: bool,

    /// Parse errors encountered during query (for JSONL file reading)
    ///
    /// For database backends, this will always be empty since there's no
    /// file parsing involved. It's included for API consistency.
    pub parse_errors: Vec<ParseErrorInfo>,
}

impl QueryResult {
    /// Create an empty result
    pub fn empty() -> Self {
        Self {
            events: Vec::new(),
            total_count: Some(0),
            has_more: false,
            parse_errors: Vec::new(),
        }
    }

    /// Create a result from events
    pub fn from_events(events: Vec<Event>) -> Self {
        Self {
            events,
            total_count: None,
            has_more: false,
            parse_errors: Vec::new(),
        }
    }

    /// Check if any parse errors occurred
    pub fn is_parse_error_present(&self) -> bool {
        !self.parse_errors.is_empty()
    }

    /// Get the count of parse errors
    pub fn parse_error_count(&self) -> usize {
        self.parse_errors.len()
    }
}

/// Trait for database backend implementations
///
/// Implement this trait to add support for a new database backend.
/// The library provides optional implementations for PostgreSQL and SQLite
/// via feature flags.
///
/// # Example Implementation
///
/// ```rust,no_run
/// use octarine::observe::writers::{DatabaseBackend, QueryResult, AuditQuery, WriterError};
/// use octarine::observe::Event;
/// use async_trait::async_trait;
///
/// struct MyBackend {
///     // Your database connection
/// }
///
/// #[async_trait]
/// impl DatabaseBackend for MyBackend {
///     async fn store_events(&self, events: &[Event]) -> Result<usize, WriterError> {
///         // Insert events into your database
///         todo!()
///     }
///
///     async fn query_events(&self, query: &AuditQuery) -> Result<QueryResult, WriterError> {
///         // Query events from your database
///         todo!()
///     }
///
///     async fn delete_before(&self, retention_days: u32) -> Result<usize, WriterError> {
///         // Delete old events for retention
///         todo!()
///     }
///
///     async fn health_check(&self) -> Result<(), WriterError> {
///         // Verify database connection
///         todo!()
///     }
///
///     fn name(&self) -> &'static str {
///         "my-backend"
///     }
/// }
/// ```
#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    /// Store events in the database
    ///
    /// Returns the number of events successfully stored.
    /// Should handle duplicates gracefully (idempotent on event ID).
    async fn store_events(&self, events: &[Event]) -> Result<usize, WriterError>;

    /// Query events from the database
    ///
    /// Applies filters from the query and returns matching events.
    async fn query_events(&self, query: &AuditQuery) -> Result<QueryResult, WriterError>;

    /// Delete events older than retention period
    ///
    /// Used for GDPR compliance and storage management.
    /// Returns the number of events deleted.
    async fn delete_before(&self, retention_days: u32) -> Result<usize, WriterError>;

    /// Check database connection health
    async fn health_check(&self) -> Result<(), WriterError>;

    /// Get a single event by ID
    async fn get_event(&self, id: Uuid) -> Result<Option<Event>, WriterError> {
        let query = AuditQuery::builder().correlation_id(id).limit(1).build();

        let result = self.query_events(&query).await?;
        Ok(result.events.into_iter().find(|e| e.id == id))
    }

    /// Count events matching a query
    async fn count_events(&self, query: &AuditQuery) -> Result<usize, WriterError> {
        let result = self.query_events(query).await?;
        Ok(result.total_count.unwrap_or(result.events.len()))
    }

    /// Run database migrations
    ///
    /// Default implementation does nothing. Override for auto-migration support.
    async fn migrate(&self) -> Result<(), WriterError> {
        Ok(())
    }

    /// Backend name for logging and health checks
    fn name(&self) -> &'static str;
}

/// A no-op backend for testing
///
/// Stores nothing, returns empty results. Useful for tests that don't need
/// actual database persistence.
#[derive(Debug, Default, Clone)]
pub struct NoOpBackend;

#[async_trait]
impl DatabaseBackend for NoOpBackend {
    async fn store_events(&self, events: &[Event]) -> Result<usize, WriterError> {
        Ok(events.len())
    }

    async fn query_events(&self, _query: &AuditQuery) -> Result<QueryResult, WriterError> {
        Ok(QueryResult::empty())
    }

    async fn delete_before(&self, _retention_days: u32) -> Result<usize, WriterError> {
        Ok(0)
    }

    async fn health_check(&self) -> Result<(), WriterError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

/// An in-memory backend for testing
///
/// Stores events in memory with thread-safe access.
/// Useful for integration tests that need to verify event storage.
#[derive(Debug, Default)]
pub struct InMemoryBackend {
    events: std::sync::RwLock<Vec<Event>>,
}

impl InMemoryBackend {
    /// Create a new in-memory backend
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all stored events (for test assertions)
    pub fn all_events(&self) -> Vec<Event> {
        self.events.read().map(|e| e.clone()).unwrap_or_default()
    }

    /// Clear all stored events
    pub fn clear(&self) {
        if let Ok(mut events) = self.events.write() {
            events.clear();
        }
    }
}

#[async_trait]
impl DatabaseBackend for InMemoryBackend {
    async fn store_events(&self, events: &[Event]) -> Result<usize, WriterError> {
        let mut stored = self
            .events
            .write()
            .map_err(|e| WriterError::Other(format!("Lock poisoned: {e}")))?;

        let count = events.len();
        stored.extend(events.iter().cloned());
        Ok(count)
    }

    async fn query_events(&self, query: &AuditQuery) -> Result<QueryResult, WriterError> {
        let events = self
            .events
            .read()
            .map_err(|e| WriterError::Other(format!("Lock poisoned: {e}")))?;

        let mut filtered: Vec<Event> = events
            .iter()
            .filter(|e| {
                // Time range filter
                if query.since.is_some_and(|since| e.timestamp < since) {
                    return false;
                }
                if query.until.is_some_and(|until| e.timestamp >= until) {
                    return false;
                }

                // Event type filter
                if query
                    .event_types
                    .as_ref()
                    .is_some_and(|types| !types.contains(&e.event_type))
                {
                    return false;
                }

                // Severity filter
                if query
                    .min_severity
                    .is_some_and(|min_severity| e.severity < min_severity)
                {
                    return false;
                }

                // Tenant filter
                if query.tenant_id.as_ref().is_some_and(|tenant| {
                    e.context.tenant_id.as_ref().map(|t| t.as_str()) != Some(tenant.as_str())
                }) {
                    return false;
                }

                // User filter
                if query.user_id.as_ref().is_some_and(|user| {
                    e.context.user_id.as_ref().map(|u| u.as_str()) != Some(user.as_str())
                }) {
                    return false;
                }

                // Correlation ID filter
                if query
                    .correlation_id
                    .is_some_and(|corr| e.context.correlation_id != corr)
                {
                    return false;
                }

                // Security relevant filter
                if query.security_relevant_only && !e.context.security_relevant {
                    return false;
                }

                // PII filter
                if query.contains_pii_only && !e.context.contains_pii {
                    return false;
                }

                // PHI filter
                if query.contains_phi_only && !e.context.contains_phi {
                    return false;
                }

                true
            })
            .cloned()
            .collect();

        // Sort
        if query.ascending {
            filtered.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        } else {
            filtered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        }

        let total_count = filtered.len();

        // Pagination
        if let Some(offset) = query.offset {
            filtered = filtered.into_iter().skip(offset).collect();
        }
        if let Some(limit) = query.limit {
            filtered.truncate(limit);
        }

        let has_more = query.limit.is_some_and(|l| filtered.len() >= l);

        Ok(QueryResult {
            events: filtered,
            total_count: Some(total_count),
            has_more,
            parse_errors: Vec::new(),
        })
    }

    #[allow(clippy::arithmetic_side_effects)] // chrono's checked_sub is not available for DateTime - Duration
    async fn delete_before(&self, retention_days: u32) -> Result<usize, WriterError> {
        let cutoff = chrono::Duration::try_days(i64::from(retention_days))
            .map(|d| chrono::Utc::now() - d)
            .unwrap_or_else(chrono::Utc::now);

        let mut events = self
            .events
            .write()
            .map_err(|e| WriterError::Other(format!("Lock poisoned: {e}")))?;

        let before_count = events.len();
        events.retain(|e| e.timestamp >= cutoff);

        Ok(before_count.saturating_sub(events.len()))
    }

    async fn health_check(&self) -> Result<(), WriterError> {
        // Check if lock is not poisoned
        let _guard = self
            .events
            .read()
            .map_err(|e| WriterError::Other(format!("Lock poisoned: {e}")))?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "in-memory"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::types::{EventType, Severity};

    fn test_event(event_type: EventType) -> Event {
        Event::new(event_type, "Test event")
    }

    #[tokio::test]
    async fn test_noop_backend() {
        let backend = NoOpBackend;

        let events = vec![test_event(EventType::Info)];
        let stored = backend
            .store_events(&events)
            .await
            .expect("store should succeed");
        assert_eq!(stored, 1);

        let result = backend
            .query_events(&AuditQuery::default())
            .await
            .expect("query should succeed");
        assert!(result.events.is_empty());

        backend
            .health_check()
            .await
            .expect("health check should pass");
    }

    #[tokio::test]
    async fn test_in_memory_backend_store_and_query() {
        let backend = InMemoryBackend::new();

        let events = vec![test_event(EventType::Info), test_event(EventType::Warning)];

        let stored = backend
            .store_events(&events)
            .await
            .expect("store should succeed");
        assert_eq!(stored, 2);

        let result = backend
            .query_events(&AuditQuery::default())
            .await
            .expect("query should succeed");
        assert_eq!(result.events.len(), 2);
    }

    #[tokio::test]
    async fn test_in_memory_backend_severity_filter() {
        let backend = InMemoryBackend::new();

        let events = vec![
            test_event(EventType::Info),
            test_event(EventType::SystemError), // This is Critical severity
        ];
        backend
            .store_events(&events)
            .await
            .expect("store should succeed");

        let query = AuditQuery::builder().min_severity(Severity::Error).build();

        let result = backend
            .query_events(&query)
            .await
            .expect("query should succeed");
        assert_eq!(result.events.len(), 1);
    }

    #[tokio::test]
    async fn test_in_memory_backend_pagination() {
        let backend = InMemoryBackend::new();

        let events: Vec<Event> = (0..10).map(|_| test_event(EventType::Info)).collect();
        backend
            .store_events(&events)
            .await
            .expect("store should succeed");

        let query = AuditQuery::builder().limit(3).build();

        let result = backend
            .query_events(&query)
            .await
            .expect("query should succeed");
        assert_eq!(result.events.len(), 3);
        assert!(result.has_more);
        assert_eq!(result.total_count, Some(10));
    }

    #[tokio::test]
    async fn test_in_memory_backend_delete_before() {
        let backend = InMemoryBackend::new();

        let events = vec![test_event(EventType::Info)];
        backend
            .store_events(&events)
            .await
            .expect("store should succeed");

        // Delete events older than 0 days (all events)
        let deleted = backend
            .delete_before(0)
            .await
            .expect("delete should succeed");
        assert_eq!(deleted, 1);

        let result = backend
            .query_events(&AuditQuery::default())
            .await
            .expect("query should succeed");
        assert!(result.events.is_empty());
    }

    #[tokio::test]
    async fn test_query_result_helpers() {
        let empty = QueryResult::empty();
        assert!(empty.events.is_empty());
        assert_eq!(empty.total_count, Some(0));
        assert!(!empty.has_more);

        let events = vec![test_event(EventType::Info)];
        let result = QueryResult::from_events(events);
        assert_eq!(result.events.len(), 1);
        assert!(!result.has_more);
    }
}
