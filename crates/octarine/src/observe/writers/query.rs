//! Query types and traits for event retrieval
//!
//! Provides generic querying capabilities for writers, enabling compliance
//! reporting, debugging, and audit analysis across different storage backends.
//!
//! # Architecture
//!
//! Query support is provided through two mechanisms:
//!
//! 1. **`Queryable` trait** - For writers that support in-place querying
//!    (e.g., FileWriter reading from log files, MemoryWriter)
//!
//! 2. **`DatabaseBackend` trait** - For database-backed writers (see `database` module)
//!
//! # Use Cases
//!
//! - **Compliance Reporting**: Query all security events in a time period
//! - **Debugging**: Find events by correlation ID to trace requests
//! - **Auditing**: List all actions by a specific user (GDPR data subject access)
//! - **Monitoring**: Count failed operations over time

use async_trait::async_trait;

use super::types::WriterError;
use crate::observe::types::Event;

// Re-export query types from database module for convenience
// These are generic enough to be used by any queryable writer
#[cfg(feature = "database")]
pub use super::database::{AuditQuery, QueryResult};

// ParseErrorInfo is always needed (for FileWriter query)
// Define it unconditionally so it's available with or without database feature
/// Information about a parse error encountered during query
#[derive(Debug, Clone)]
pub struct ParseErrorInfo {
    /// Path to the file containing the error
    pub file_path: String,
    /// Line number (1-indexed) where the error occurred
    pub line_number: usize,
    /// The error message from the parser
    pub error: String,
    /// Preview of the problematic line (truncated for safety)
    pub line_preview: String,
}

impl ParseErrorInfo {
    /// Create a new parse error info
    ///
    /// Line preview is truncated to 100 chars to avoid memory issues with very long lines
    pub fn new(file_path: String, line_number: usize, error: String, line: &str) -> Self {
        let line_preview = if line.len() > 100 {
            format!("{}...", &line[..100])
        } else {
            line.to_string()
        };
        Self {
            file_path,
            line_number,
            error,
            line_preview,
        }
    }
}

// When database feature is not enabled, we need local definitions
#[cfg(not(feature = "database"))]
mod query_types {
    use super::ParseErrorInfo;
    use crate::observe::types::{EventType, Severity};
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    /// Query parameters for retrieving events
    ///
    /// Supports filtering by time range, event types, severity, and context.
    #[derive(Debug, Clone, Default)]
    pub struct AuditQuery {
        /// Start of time range (inclusive)
        pub since: Option<DateTime<Utc>>,
        /// End of time range (exclusive)
        pub until: Option<DateTime<Utc>>,
        /// Filter by event types
        pub event_types: Option<Vec<EventType>>,
        /// Minimum severity level
        pub min_severity: Option<Severity>,
        /// Filter by tenant ID
        pub tenant_id: Option<String>,
        /// Filter by user ID
        pub user_id: Option<String>,
        /// Filter by correlation ID
        pub correlation_id: Option<Uuid>,
        /// Filter by resource type
        pub resource_type: Option<String>,
        /// Filter by resource ID
        pub resource_id: Option<String>,
        /// Only include security-relevant events
        pub security_relevant_only: bool,
        /// Only include events with PII
        pub contains_pii_only: bool,
        /// Only include events with PHI
        pub contains_phi_only: bool,
        /// Maximum number of results
        pub limit: Option<usize>,
        /// Offset for pagination
        pub offset: Option<usize>,
        /// Order by timestamp ascending (default: descending)
        pub ascending: bool,
    }

    /// Result of a query operation
    #[derive(Debug, Clone)]
    pub struct QueryResult {
        /// Events matching the query
        pub events: Vec<crate::observe::types::Event>,
        /// Total count (for pagination)
        pub total_count: Option<usize>,
        /// Whether there are more results
        pub has_more: bool,
        /// Parse errors encountered during query (for JSONL file reading)
        ///
        /// These are lines that could not be parsed as valid events.
        /// The query still succeeds with the valid events, but these
        /// errors are reported for diagnostics.
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
        pub fn from_events(events: Vec<crate::observe::types::Event>) -> Self {
            Self {
                events,
                total_count: None,
                has_more: false,
                parse_errors: Vec::new(),
            }
        }

        /// Create a result from events with parse errors
        pub fn from_events_with_errors(
            events: Vec<crate::observe::types::Event>,
            parse_errors: Vec<ParseErrorInfo>,
        ) -> Self {
            Self {
                events,
                total_count: None,
                has_more: false,
                parse_errors,
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
}

#[cfg(not(feature = "database"))]
pub use query_types::{AuditQuery, QueryResult};

/// Trait for writers that support querying stored events
///
/// Implement this trait to enable event retrieval from a writer.
/// This is useful for:
/// - Compliance reporting (query events by time range)
/// - Debugging (find events by correlation ID)
/// - User data access requests (GDPR - find events for a user)
///
/// # Example
///
/// ```rust,ignore
/// use octarine::writers::{Queryable, AuditQuery, QueryResult};
///
/// async fn compliance_report(writer: &impl Queryable) -> Result<Vec<Event>, WriterError> {
///     let query = AuditQuery::security_events(30); // Last 30 days
///     let result = writer.query(&query).await?;
///     Ok(result.events)
/// }
/// ```
#[async_trait]
pub trait Queryable: Send + Sync {
    /// Query stored events matching the filter criteria
    ///
    /// Returns events that match all specified filters in the query.
    /// Results are paginated using `limit` and `offset`.
    async fn query(&self, query: &AuditQuery) -> Result<QueryResult, WriterError>;

    /// Count events matching the query (more efficient than query + len)
    ///
    /// Default implementation queries and counts, but backends can override
    /// for more efficient counting (e.g., SQL COUNT(*)).
    async fn count(&self, query: &AuditQuery) -> Result<usize, WriterError> {
        let result = self.query(query).await?;
        Ok(result.total_count.unwrap_or(result.events.len()))
    }

    /// Get a single event by ID
    ///
    /// Returns `None` if no event with that ID exists.
    async fn get(&self, id: uuid::Uuid) -> Result<Option<Event>, WriterError> {
        // Default implementation uses correlation_id filter
        // Implementations may override for efficiency
        let query = AuditQuery {
            correlation_id: Some(id),
            limit: Some(1),
            ..Default::default()
        };
        let result = self.query(&query).await?;
        Ok(result.events.into_iter().find(|e| e.id == id))
    }
}

/// Filter events in memory using AuditQuery criteria
///
/// This is a utility function for implementing `Queryable` on in-memory
/// or file-based writers that load events into memory.
pub fn filter_events(events: &[Event], query: &AuditQuery) -> Vec<Event> {
    events
        .iter()
        .filter(|e| {
            // Time range filter
            if let Some(since) = query.since
                && e.timestamp < since
            {
                return false;
            }
            if let Some(until) = query.until
                && e.timestamp >= until
            {
                return false;
            }

            // Event type filter
            if let Some(ref types) = query.event_types
                && !types.contains(&e.event_type)
            {
                return false;
            }

            // Severity filter
            if let Some(min_severity) = query.min_severity
                && e.severity < min_severity
            {
                return false;
            }

            // Tenant filter
            if let Some(ref tenant) = query.tenant_id
                && e.context.tenant_id.as_ref().map(|t| t.as_str()) != Some(tenant.as_str())
            {
                return false;
            }

            // User filter
            if let Some(ref user) = query.user_id
                && e.context.user_id.as_ref().map(|u| u.as_str()) != Some(user.as_str())
            {
                return false;
            }

            // Correlation ID filter
            if let Some(corr) = query.correlation_id
                && e.context.correlation_id != corr
            {
                return false;
            }

            // Resource filters
            if let Some(ref res_type) = query.resource_type
                && e.context.resource_type.as_ref() != Some(res_type)
            {
                return false;
            }
            if let Some(ref res_id) = query.resource_id
                && e.context.resource_id.as_ref() != Some(res_id)
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
        .collect()
}

/// Sort and paginate events according to query parameters
///
/// This is a utility function for implementing `Queryable`.
/// Paginate filtered events with sorting
///
/// Applies sorting, offset, and limit to a filtered event list.
/// Does not include parse errors - use `paginate_events_with_errors` for that.
pub fn paginate_events(events: Vec<Event>, query: &AuditQuery) -> QueryResult {
    paginate_events_with_errors(events, query, Vec::new())
}

/// Paginate filtered events with sorting and include parse errors
///
/// Applies sorting, offset, and limit to a filtered event list,
/// and includes any parse errors encountered during file reading.
pub fn paginate_events_with_errors(
    mut events: Vec<Event>,
    query: &AuditQuery,
    parse_errors: Vec<ParseErrorInfo>,
) -> QueryResult {
    // Sort
    if query.ascending {
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    } else {
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    }

    let total_count = events.len();

    // Apply offset
    if let Some(offset) = query.offset {
        events = events.into_iter().skip(offset).collect();
    }

    // Apply limit
    let has_more = query.limit.is_some_and(|l| events.len() > l);
    if let Some(limit) = query.limit {
        events.truncate(limit);
    }

    QueryResult {
        events,
        total_count: Some(total_count),
        has_more,
        parse_errors,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::observe::types::{EventType, Severity};

    fn test_event(event_type: EventType) -> Event {
        Event::new(event_type, "Test event")
    }

    #[test]
    fn test_filter_by_event_type() {
        let events = vec![
            test_event(EventType::Info),
            test_event(EventType::Warning),
            test_event(EventType::SystemError),
        ];

        let query = AuditQuery {
            event_types: Some(vec![EventType::Warning, EventType::SystemError]),
            ..Default::default()
        };

        let filtered = filter_events(&events, &query);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_by_severity() {
        let events = vec![
            test_event(EventType::Info),        // Info severity
            test_event(EventType::Warning),     // Warning severity
            test_event(EventType::SystemError), // Critical severity
        ];

        let query = AuditQuery {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };

        let filtered = filter_events(&events, &query);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_paginate_events() {
        let events: Vec<Event> = (0..10).map(|_| test_event(EventType::Info)).collect();

        let query = AuditQuery {
            limit: Some(3),
            offset: Some(2),
            ..Default::default()
        };

        let result = paginate_events(events, &query);
        assert_eq!(result.events.len(), 3);
        assert_eq!(result.total_count, Some(10));
        assert!(result.has_more);
    }

    #[test]
    fn test_paginate_no_more_results() {
        let events: Vec<Event> = (0..5).map(|_| test_event(EventType::Info)).collect();

        let query = AuditQuery {
            limit: Some(10), // More than available
            ..Default::default()
        };

        let result = paginate_events(events, &query);
        assert_eq!(result.events.len(), 5);
        assert!(!result.has_more);
    }

    #[test]
    fn test_empty_query_returns_all() {
        let events = vec![test_event(EventType::Info), test_event(EventType::Warning)];

        let query = AuditQuery::default();
        let filtered = filter_events(&events, &query);
        assert_eq!(filtered.len(), 2);
    }
}
