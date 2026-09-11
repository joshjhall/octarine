//! SQLite backend for audit event persistence
//!
//! This module requires the `sqlite` feature flag.
//!
//! Useful for local development and testing without a full database setup.
//!
//! # Example
//!
//! ```rust,no_run
//! use octarine::observe::writers::{SqliteBackend, DatabaseBackend, DatabaseWriter, DatabaseWriterConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // In-memory database for testing
//! let backend = SqliteBackend::in_memory().await?;
//! backend.migrate().await?;
//!
//! // File-based database for persistence
//! let backend = SqliteBackend::file("audit.db").await?;
//! backend.migrate().await?;
//!
//! let writer = DatabaseWriter::development(backend);
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow};

use crate::observe::types::Event;
use crate::observe::writers::types::WriterError;

use super::common::{self, EventRow, SqlDialect};
use super::query::AuditQuery;
use super::traits::{DatabaseBackend, QueryResult};

/// SQLite backend for audit event persistence
///
/// Provides a lightweight SQLite backend suitable for:
/// - Local development
/// - Testing
/// - Small deployments
/// - Embedded applications
///
/// # Table Schema
///
/// The `audit_events` table is created with the following schema:
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS audit_events (
///     id TEXT PRIMARY KEY,
///     timestamp TEXT NOT NULL,
///     event_type TEXT NOT NULL,
///     severity TEXT NOT NULL,
///     message TEXT NOT NULL,
///     operation TEXT,
///     tenant_id TEXT,
///     user_id TEXT,
///     correlation_id TEXT NOT NULL,
///     resource_type TEXT,
///     resource_id TEXT,
///     module_path TEXT,
///     file TEXT,
///     line INTEGER,
///     contains_pii INTEGER DEFAULT 0,
///     contains_phi INTEGER DEFAULT 0,
///     security_relevant INTEGER DEFAULT 0,
///     metadata TEXT,
///     created_at TEXT DEFAULT (datetime('now'))
/// );
/// ```
pub struct SqliteBackend {
    pool: SqlitePool,
}

impl SqliteBackend {
    /// Create an in-memory SQLite database
    ///
    /// Data is lost when the backend is dropped.
    /// Useful for testing.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::observe::writers::SqliteBackend;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let backend = SqliteBackend::in_memory().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn in_memory() -> Result<Self, WriterError> {
        // Use shared cache mode to allow multiple connections to same in-memory db
        Self::connect("sqlite::memory:?cache=shared").await
    }

    /// Create a file-based SQLite database
    ///
    /// Data is persisted to the specified file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::observe::writers::SqliteBackend;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let backend = SqliteBackend::file("./audit.db").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn file(path: &str) -> Result<Self, WriterError> {
        Self::connect(&format!("sqlite:{path}?mode=rwc")).await
    }

    /// Connect with a custom connection string
    async fn connect(connection_string: &str) -> Result<Self, WriterError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .min_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(connection_string)
            .await
            .map_err(|e| WriterError::Configuration(format!("Failed to connect to SQLite: {e}")))?;

        Ok(Self { pool })
    }

    /// Create from an existing connection pool
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Get a reference to the underlying connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Build the WHERE clause and bind values from a query
    ///
    /// Delegates to [`common::build_where_clause`] with the SQLite dialect:
    /// anonymous `?` placeholders bound in order, and integer boolean
    /// literals to match the `INTEGER` columns in this backend's schema.
    fn build_where_clause(query: &AuditQuery) -> (String, Vec<String>) {
        common::build_where_clause(query, SqlDialect::Sqlite)
    }

    /// Parse a database row into an Event
    ///
    /// SQLite has no native UUID, timestamp, or boolean types, so those
    /// columns are stored as `TEXT`/`INTEGER` and coerced here. The resulting
    /// native values are assembled into an [`Event`] by
    /// [`common::assemble_event`].
    fn row_to_event(row: &SqliteRow) -> Result<Event, WriterError> {
        let id_str: String = row
            .try_get("id")
            .map_err(|e| WriterError::Other(format!("Failed to get id: {e}")))?;
        let id = uuid::Uuid::parse_str(&id_str)
            .map_err(|e| WriterError::Other(format!("Failed to parse id: {e}")))?;

        let timestamp_str: String = row
            .try_get("timestamp")
            .map_err(|e| WriterError::Other(format!("Failed to get timestamp: {e}")))?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| WriterError::Other(format!("Failed to parse timestamp: {e}")))?;

        let event_type: String = row
            .try_get("event_type")
            .map_err(|e| WriterError::Other(format!("Failed to get event_type: {e}")))?;
        let severity: String = row
            .try_get("severity")
            .map_err(|e| WriterError::Other(format!("Failed to get severity: {e}")))?;
        let message: String = row
            .try_get("message")
            .map_err(|e| WriterError::Other(format!("Failed to get message: {e}")))?;

        let correlation_id_str: String = row
            .try_get("correlation_id")
            .map_err(|e| WriterError::Other(format!("Failed to get correlation_id: {e}")))?;
        let correlation_id = uuid::Uuid::parse_str(&correlation_id_str)
            .map_err(|e| WriterError::Other(format!("Failed to parse correlation_id: {e}")))?;

        let line: i32 = row.try_get("line").unwrap_or(0);

        // SQLite stores booleans as integers
        let contains_pii: i32 = row.try_get("contains_pii").unwrap_or(0);
        let contains_phi: i32 = row.try_get("contains_phi").unwrap_or(0);
        let security_relevant: i32 = row.try_get("security_relevant").unwrap_or(0);

        // Metadata is stored as a JSON string rather than a JSON column
        let metadata_str: Option<String> = row.try_get("metadata").ok();
        let metadata: Option<serde_json::Value> =
            metadata_str.and_then(|s| serde_json::from_str(&s).ok());

        Ok(common::assemble_event(EventRow {
            id,
            timestamp,
            event_type,
            severity,
            message,
            operation: row.try_get("operation").unwrap_or_default(),
            tenant_id: row.try_get("tenant_id").ok(),
            user_id: row.try_get("user_id").ok(),
            correlation_id,
            resource_type: row.try_get("resource_type").ok(),
            resource_id: row.try_get("resource_id").ok(),
            module_path: row.try_get("module_path").unwrap_or_default(),
            file: row.try_get("file").unwrap_or_default(),
            line: line as u32,
            contains_pii: contains_pii != 0,
            contains_phi: contains_phi != 0,
            security_relevant: security_relevant != 0,
            metadata,
        }))
    }
}

#[async_trait]
impl DatabaseBackend for SqliteBackend {
    async fn store_events(&self, events: &[Event]) -> Result<usize, WriterError> {
        if events.is_empty() {
            return Ok(0);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| WriterError::Other(format!("Failed to begin transaction: {e}")))?;

        let mut count: usize = 0;

        for event in events {
            let metadata_json = serde_json::to_string(&event.metadata).ok();

            let result = sqlx::query(
                r#"
                INSERT OR IGNORE INTO audit_events (
                    id, timestamp, event_type, severity, message,
                    operation, tenant_id, user_id, correlation_id,
                    resource_type, resource_id, module_path, file, line,
                    contains_pii, contains_phi, security_relevant, metadata
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5,
                    ?6, ?7, ?8, ?9,
                    ?10, ?11, ?12, ?13, ?14,
                    ?15, ?16, ?17, ?18
                )
                "#,
            )
            .bind(event.id.to_string())
            .bind(event.timestamp.to_rfc3339())
            .bind(format!("{:?}", event.event_type))
            .bind(format!("{:?}", event.severity))
            .bind(&event.message)
            .bind(&event.context.operation)
            .bind(event.context.tenant_id.as_ref().map(|t| t.as_str()))
            .bind(event.context.user_id.as_ref().map(|u| u.as_str()))
            .bind(event.context.correlation_id.to_string())
            .bind(&event.context.resource_type)
            .bind(&event.context.resource_id)
            .bind(&event.context.module_path)
            .bind(&event.context.file)
            .bind(event.context.line as i32)
            .bind(i32::from(event.context.contains_pii))
            .bind(i32::from(event.context.contains_phi))
            .bind(i32::from(event.context.security_relevant))
            .bind(metadata_json)
            .execute(&mut *tx)
            .await
            .map_err(|e| WriterError::Other(format!("Failed to insert event: {e}")))?;

            count = count.saturating_add(result.rows_affected() as usize);
        }

        tx.commit()
            .await
            .map_err(|e| WriterError::Other(format!("Failed to commit transaction: {e}")))?;

        Ok(count)
    }

    async fn query_events(&self, query: &AuditQuery) -> Result<QueryResult, WriterError> {
        let (where_clause, params) = Self::build_where_clause(query);

        let order = if query.ascending { "ASC" } else { "DESC" };
        let limit_clause = query
            .limit
            .map(|l| format!("LIMIT {l}"))
            .unwrap_or_default();
        let offset_clause = query
            .offset
            .map(|o| format!("OFFSET {o}"))
            .unwrap_or_default();

        let sql = format!(
            "SELECT * FROM audit_events {where_clause} ORDER BY timestamp {order} {limit_clause} {offset_clause}"
        );

        let mut stmt = sqlx::query(sqlx::AssertSqlSafe(sql));
        for p in &params {
            stmt = stmt.bind(p);
        }
        let rows: Vec<SqliteRow> = stmt
            .fetch_all(&self.pool)
            .await
            .map_err(|e| WriterError::Other(format!("Failed to query events: {e}")))?;

        let events: Result<Vec<Event>, WriterError> = rows.iter().map(Self::row_to_event).collect();
        let events = events?;

        let count_sql = format!("SELECT COUNT(*) as count FROM audit_events {where_clause}");
        let mut count_stmt = sqlx::query_scalar(sqlx::AssertSqlSafe(count_sql));
        for p in &params {
            count_stmt = count_stmt.bind(p);
        }
        let total_count: i64 = count_stmt.fetch_one(&self.pool).await.unwrap_or(0);

        let has_more = query.limit.is_some_and(|l| events.len() >= l);

        Ok(QueryResult {
            events,
            total_count: Some(total_count as usize),
            has_more,
            parse_errors: Vec::new(),
        })
    }

    async fn delete_before(&self, retention_days: u32) -> Result<usize, WriterError> {
        // SQLite date math
        let result = sqlx::query("DELETE FROM audit_events WHERE timestamp < datetime('now', ?)")
            .bind(format!("-{retention_days} days"))
            .execute(&self.pool)
            .await
            .map_err(|e| WriterError::Other(format!("Failed to delete old events: {e}")))?;

        Ok(result.rows_affected() as usize)
    }

    async fn health_check(&self) -> Result<(), WriterError> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| WriterError::Other(format!("Health check failed: {e}")))?;

        Ok(())
    }

    async fn migrate(&self) -> Result<(), WriterError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                operation TEXT,
                tenant_id TEXT,
                user_id TEXT,
                correlation_id TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                module_path TEXT,
                file TEXT,
                line INTEGER,
                contains_pii INTEGER DEFAULT 0,
                contains_phi INTEGER DEFAULT 0,
                security_relevant INTEGER DEFAULT 0,
                metadata TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| WriterError::Other(format!("Migration failed (create table): {e}")))?;

        // Create indexes separately (SQLite doesn't support multiple statements in one query)
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_id ON audit_events(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit_events(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_correlation_id ON audit_events(correlation_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events(severity)",
        ];

        for index_sql in indexes {
            sqlx::query(index_sql)
                .execute(&self.pool)
                .await
                .map_err(|e| WriterError::Other(format!("Migration failed (create index): {e}")))?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "sqlite"
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::observe::types::{EventContext, EventType, Severity, TenantId, UserId};

    fn test_event() -> Event {
        Event::new(EventType::Info, "Test event")
    }

    #[tokio::test]
    async fn test_sqlite_in_memory() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");

        backend.migrate().await.expect("migration should succeed");
        backend
            .health_check()
            .await
            .expect("health check should pass");
    }

    #[tokio::test]
    async fn test_sqlite_store_and_query() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");

        let events = vec![test_event(), test_event()];
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
    async fn test_sqlite_query_filters() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");

        let events = vec![
            Event::new(EventType::Info, "Info event"),
            Event::new(EventType::Warning, "Warning event"),
            Event::new(EventType::SystemError, "Error event"),
        ];
        backend
            .store_events(&events)
            .await
            .expect("store should succeed");

        // Filter by severity
        let query = AuditQuery::builder()
            .min_severity(Severity::Warning)
            .build();
        let result = backend
            .query_events(&query)
            .await
            .expect("query should succeed");
        // Warning and Error (Critical severity)
        assert_eq!(result.events.len(), 2);
    }

    #[tokio::test]
    async fn test_sqlite_pagination() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");

        let events: Vec<Event> = (0..10).map(|_| test_event()).collect();
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
    async fn test_sqlite_delete_before() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");

        // Insert an event with a backdated timestamp
        let mut event = test_event();
        // Set timestamp to 100 days ago
        event.timestamp = chrono::Utc::now() - chrono::Duration::days(100);
        let events = vec![event];
        backend
            .store_events(&events)
            .await
            .expect("store should succeed");

        // Delete events older than 90 days
        let deleted = backend
            .delete_before(90)
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
    async fn test_sqlite_idempotent_insert() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");

        let event = test_event();
        let events = vec![event.clone()];

        // First insert
        let stored1 = backend
            .store_events(&events)
            .await
            .expect("store should succeed");
        assert_eq!(stored1, 1);

        // Second insert (same event ID) should be ignored
        let stored2 = backend
            .store_events(&events)
            .await
            .expect("store should succeed");
        assert_eq!(stored2, 0); // No new rows

        let result = backend
            .query_events(&AuditQuery::default())
            .await
            .expect("query should succeed");
        assert_eq!(result.events.len(), 1); // Still just one event
    }

    // ===== SQL Injection Regression Tests =====

    /// Classic SQL injection payload targeting the audit table.
    const INJECTION_PAYLOAD: &str = "'; DROP TABLE audit_events; --";

    /// Build an event with a fully populated context so filter tests have
    /// known values to match against.
    fn event_with_context(
        tenant: Option<&str>,
        user: Option<&str>,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
    ) -> Event {
        let ctx = EventContext {
            tenant_id: tenant.map(|t| TenantId::new(t).expect("valid tenant id")),
            user_id: user.map(|u| UserId::new(u).expect("valid user id")),
            resource_type: resource_type.map(str::to_string),
            resource_id: resource_id.map(str::to_string),
            ..EventContext::default()
        };
        Event::new(EventType::Info, "Test event").with_context(ctx)
    }

    /// Assert that the `audit_events` table is intact and contains the
    /// expected number of rows after a query with a malicious filter.
    async fn assert_table_intact(backend: &SqliteBackend, expected_rows: usize) {
        let result = backend
            .query_events(&AuditQuery::default())
            .await
            .expect("baseline query must still succeed — table likely dropped");
        assert_eq!(
            result.events.len(),
            expected_rows,
            "audit_events table rows missing after injection attempt"
        );
    }

    #[tokio::test]
    async fn test_sqlite_injection_tenant_id() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");
        backend
            .store_events(&[test_event(), test_event()])
            .await
            .expect("store should succeed");

        let malicious = AuditQuery::builder().tenant_id(INJECTION_PAYLOAD).build();
        let result = backend
            .query_events(&malicious)
            .await
            .expect("query must treat payload as a literal, not execute it");
        assert_eq!(result.events.len(), 0);
        assert_table_intact(&backend, 2).await;
    }

    #[tokio::test]
    async fn test_sqlite_injection_user_id() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");
        backend
            .store_events(&[test_event(), test_event()])
            .await
            .expect("store should succeed");

        let malicious = AuditQuery::builder().user_id(INJECTION_PAYLOAD).build();
        let result = backend
            .query_events(&malicious)
            .await
            .expect("query must treat payload as a literal, not execute it");
        assert_eq!(result.events.len(), 0);
        assert_table_intact(&backend, 2).await;
    }

    #[tokio::test]
    async fn test_sqlite_injection_resource_type() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");
        backend
            .store_events(&[test_event(), test_event()])
            .await
            .expect("store should succeed");

        let malicious = AuditQuery::builder()
            .resource_type(INJECTION_PAYLOAD)
            .build();
        let result = backend
            .query_events(&malicious)
            .await
            .expect("query must treat payload as a literal, not execute it");
        assert_eq!(result.events.len(), 0);
        assert_table_intact(&backend, 2).await;
    }

    #[tokio::test]
    async fn test_sqlite_injection_resource_id() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");
        backend
            .store_events(&[test_event(), test_event()])
            .await
            .expect("store should succeed");

        let malicious = AuditQuery::builder().resource_id(INJECTION_PAYLOAD).build();
        let result = backend
            .query_events(&malicious)
            .await
            .expect("query must treat payload as a literal, not execute it");
        assert_eq!(result.events.len(), 0);
        assert_table_intact(&backend, 2).await;
    }

    /// Positive case: confirm that parameterized binding hasn't regressed the
    /// happy path — a legitimate tenant filter matches the right row.
    #[tokio::test]
    async fn test_sqlite_filter_by_tenant_id_matches() {
        let backend = SqliteBackend::in_memory()
            .await
            .expect("in_memory should succeed");
        backend.migrate().await.expect("migration should succeed");

        let events = vec![
            event_with_context(Some("tenant-a"), None, None, None),
            event_with_context(Some("tenant-b"), None, None, None),
            event_with_context(Some("tenant-a"), None, None, None),
        ];
        backend
            .store_events(&events)
            .await
            .expect("store should succeed");

        let query = AuditQuery::builder().tenant_id("tenant-a").build();
        let result = backend
            .query_events(&query)
            .await
            .expect("query should succeed");
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.total_count, Some(2));
    }
}
