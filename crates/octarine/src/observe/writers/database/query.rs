//! Query types for audit event retrieval
//!
//! Provides structured queries for compliance reporting and audit analysis.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::observe::types::{EventType, Severity};

/// Query parameters for retrieving audit events
///
/// Supports filtering by time range, event types, severity, and context.
/// Used for compliance reporting and audit analysis.
///
/// # Example
///
/// ```rust
/// use octarine::observe::writers::AuditQuery;
/// use octarine::observe::{EventType, Severity};
/// use chrono::{Utc, Duration};
///
/// let query = AuditQuery::builder()
///     .since(Utc::now() - Duration::days(30))
///     .event_types(vec![EventType::AuthenticationError, EventType::AuthorizationError])
///     .min_severity(Severity::Warning)
///     .security_relevant_only(true)
///     .build();
/// ```
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

    /// Filter by correlation ID (find related events)
    pub correlation_id: Option<Uuid>,

    /// Filter by resource type
    pub resource_type: Option<String>,

    /// Filter by resource ID
    pub resource_id: Option<String>,

    /// Only include security-relevant events
    pub security_relevant_only: bool,

    /// Only include events with PII (for data subject access requests)
    pub contains_pii_only: bool,

    /// Only include events with PHI (for HIPAA audits)
    pub contains_phi_only: bool,

    /// Maximum number of results
    pub limit: Option<usize>,

    /// Offset for pagination
    pub offset: Option<usize>,

    /// Order by timestamp ascending (default: descending)
    pub ascending: bool,
}

impl AuditQuery {
    /// Create a new query builder
    pub fn builder() -> AuditQueryBuilder {
        AuditQueryBuilder::default()
    }

    /// Query for the last N days
    #[allow(clippy::arithmetic_side_effects)] // chrono's checked_sub is not available for DateTime - Duration
    pub fn last_days(days: i64) -> Self {
        Self {
            since: chrono::Duration::try_days(days).map(|d| Utc::now() - d),
            ..Default::default()
        }
    }

    /// Query for security events in the last N days
    #[allow(clippy::arithmetic_side_effects)] // chrono's checked_sub is not available for DateTime - Duration
    pub fn security_events(days: i64) -> Self {
        Self {
            since: chrono::Duration::try_days(days).map(|d| Utc::now() - d),
            security_relevant_only: true,
            ..Default::default()
        }
    }

    /// Query for failed authentication attempts
    #[allow(clippy::arithmetic_side_effects)] // chrono's checked_sub is not available for DateTime - Duration
    pub fn failed_auth(days: i64) -> Self {
        Self {
            since: chrono::Duration::try_days(days).map(|d| Utc::now() - d),
            event_types: Some(vec![
                EventType::AuthenticationError,
                EventType::AuthorizationError,
                EventType::LoginFailure,
            ]),
            ..Default::default()
        }
    }

    /// Query for events by correlation ID (trace a request)
    pub fn by_correlation(correlation_id: Uuid) -> Self {
        Self {
            correlation_id: Some(correlation_id),
            ascending: true, // Show in chronological order
            ..Default::default()
        }
    }

    /// Query for events affecting a specific user (GDPR data subject request)
    #[allow(clippy::arithmetic_side_effects)] // chrono's checked_sub is not available for DateTime - Duration
    pub fn user_events(user_id: impl Into<String>, days: i64) -> Self {
        Self {
            user_id: Some(user_id.into()),
            since: chrono::Duration::try_days(days).map(|d| Utc::now() - d),
            ascending: true,
            ..Default::default()
        }
    }
}

/// Builder for AuditQuery
#[derive(Debug, Default)]
pub struct AuditQueryBuilder {
    query: AuditQuery,
}

impl AuditQueryBuilder {
    /// Set the start time (inclusive)
    pub fn since(mut self, time: DateTime<Utc>) -> Self {
        self.query.since = Some(time);
        self
    }

    /// Set the end time (exclusive)
    pub fn until(mut self, time: DateTime<Utc>) -> Self {
        self.query.until = Some(time);
        self
    }

    /// Filter by event types
    pub fn event_types(mut self, types: Vec<EventType>) -> Self {
        self.query.event_types = Some(types);
        self
    }

    /// Set minimum severity level
    pub fn min_severity(mut self, severity: Severity) -> Self {
        self.query.min_severity = Some(severity);
        self
    }

    /// Filter by tenant ID
    pub fn tenant_id(mut self, id: impl Into<String>) -> Self {
        self.query.tenant_id = Some(id.into());
        self
    }

    /// Filter by user ID
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.query.user_id = Some(id.into());
        self
    }

    /// Filter by correlation ID
    pub fn correlation_id(mut self, id: Uuid) -> Self {
        self.query.correlation_id = Some(id);
        self
    }

    /// Filter by resource type
    pub fn resource_type(mut self, resource_type: impl Into<String>) -> Self {
        self.query.resource_type = Some(resource_type.into());
        self
    }

    /// Filter by resource ID
    pub fn resource_id(mut self, id: impl Into<String>) -> Self {
        self.query.resource_id = Some(id.into());
        self
    }

    /// Only include security-relevant events
    pub fn security_relevant_only(mut self, only: bool) -> Self {
        self.query.security_relevant_only = only;
        self
    }

    /// Only include events containing PII
    pub fn pii_only(mut self, only: bool) -> Self {
        self.query.contains_pii_only = only;
        self
    }

    /// Only include events containing PHI
    pub fn phi_only(mut self, only: bool) -> Self {
        self.query.contains_phi_only = only;
        self
    }

    /// Set maximum results
    pub fn limit(mut self, limit: usize) -> Self {
        self.query.limit = Some(limit);
        self
    }

    /// Set offset for pagination
    pub fn offset(mut self, offset: usize) -> Self {
        self.query.offset = Some(offset);
        self
    }

    /// Order by timestamp ascending
    pub fn ascending(mut self) -> Self {
        self.query.ascending = true;
        self
    }

    /// Order by timestamp descending (default)
    pub fn descending(mut self) -> Self {
        self.query.ascending = false;
        self
    }

    /// Build the query
    pub fn build(self) -> AuditQuery {
        self.query
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_last_days_query() {
        let query = AuditQuery::last_days(30);
        assert!(query.since.is_some());
        assert!(query.until.is_none());
        assert!(!query.security_relevant_only);
    }

    #[test]
    fn test_security_events_query() {
        let query = AuditQuery::security_events(7);
        assert!(query.since.is_some());
        assert!(query.security_relevant_only);
    }

    #[test]
    fn test_failed_auth_query() {
        let query = AuditQuery::failed_auth(1);
        assert!(query.since.is_some());
        let types = query.event_types.expect("event_types should be set");
        assert!(types.contains(&EventType::AuthenticationError));
        assert!(types.contains(&EventType::LoginFailure));
    }

    #[test]
    fn test_builder() {
        let query = AuditQuery::builder()
            .tenant_id("acme-corp")
            .min_severity(Severity::Warning)
            .security_relevant_only(true)
            .limit(100)
            .build();

        assert_eq!(query.tenant_id, Some("acme-corp".to_string()));
        assert_eq!(query.min_severity, Some(Severity::Warning));
        assert!(query.security_relevant_only);
        assert_eq!(query.limit, Some(100));
    }

    #[test]
    fn test_correlation_query() {
        let id = Uuid::new_v4();
        let query = AuditQuery::by_correlation(id);
        assert_eq!(query.correlation_id, Some(id));
        assert!(query.ascending); // Chronological order
    }

    #[test]
    fn test_user_events_query() {
        let query = AuditQuery::user_events("user123", 90);
        assert_eq!(query.user_id, Some("user123".to_string()));
        assert!(query.since.is_some());
        assert!(query.ascending);
    }
}
