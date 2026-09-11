//! PostgreSQL backend for audit event persistence
//!
//! This module requires the `postgres` feature flag.
//!
//! # Example
//!
//! Pre-existing example - ignored at compile until adapted.
//! ```rust,ignore
//! use octarine::observe::writers::{
//!     PostgresBackend, DatabaseWriter, DatabaseWriterConfig, DatabaseBackend
//! };
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let backend = PostgresBackend::connect("postgres://user:pass@localhost/db").await?;
//!     backend.migrate().await?; // Create audit_events table
//!
//!     let writer = DatabaseWriter::new(backend, DatabaseWriterConfig::production());
//!     Ok(())
//! }
//! ```

use async_trait::async_trait;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};

use crate::observe::types::Event;
use crate::observe::writers::types::WriterError;

use super::common::{self, EventRow, SqlDialect};
use super::query::AuditQuery;
use super::traits::{DatabaseBackend, QueryResult};

/// PostgreSQL backend for audit event persistence
///
/// Provides a full-featured PostgreSQL backend with:
/// - Connection pooling (via sqlx)
/// - Efficient batch inserts
/// - Automatic migrations
/// - Full query support
///
/// # Connection Pooling
///
/// The backend uses sqlx's connection pool with sensible defaults:
/// - Max connections: 10
/// - Min connections: 1
/// - Acquire timeout: 30 seconds
///
/// # Table Schema
///
/// The `audit_events` table is created with the following schema:
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS audit_events (
///     id UUID PRIMARY KEY,
///     timestamp TIMESTAMPTZ NOT NULL,
///     event_type VARCHAR(50) NOT NULL,
///     severity VARCHAR(20) NOT NULL,
///     message TEXT NOT NULL,
///     operation VARCHAR(255),
///     tenant_id VARCHAR(100),
///     user_id VARCHAR(100),
///     correlation_id UUID NOT NULL,
///     resource_type VARCHAR(100),
///     resource_id VARCHAR(255),
///     module_path VARCHAR(255),
///     file VARCHAR(255),
///     line INTEGER,
///     contains_pii BOOLEAN DEFAULT FALSE,
///     contains_phi BOOLEAN DEFAULT FALSE,
///     security_relevant BOOLEAN DEFAULT FALSE,
///     metadata JSONB,
///     created_at TIMESTAMPTZ DEFAULT NOW()
/// );
/// ```
pub struct PostgresBackend {
    pool: PgPool,
}

impl PostgresBackend {
    /// Connect to a PostgreSQL database
    ///
    /// # Arguments
    ///
    /// * `connection_string` - PostgreSQL connection URL
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::observe::writers::PostgresBackend;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let backend = PostgresBackend::connect("postgres://user:pass@localhost/db").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(connection_string: &str) -> Result<Self, WriterError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(connection_string)
            .await
            .map_err(|e| {
                WriterError::Configuration(format!("Failed to connect to PostgreSQL: {e}"))
            })?;

        Ok(Self { pool })
    }

    /// Create from an existing connection pool
    ///
    /// Useful when you want to share a pool across multiple components.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the underlying connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Build the WHERE clause and bind values from a query
    ///
    /// Delegates to [`common::build_where_clause`] with the PostgreSQL
    /// dialect: positional `$N` placeholders and native `TRUE` boolean
    /// literals.
    fn build_where_clause(query: &AuditQuery) -> (String, Vec<String>) {
        common::build_where_clause(query, SqlDialect::Postgres)
    }

    /// Parse a database row into an Event
    ///
    /// PostgreSQL stores UUIDs, timestamps, booleans, and metadata in their
    /// native column types, so extraction needs no coercion. The values are
    /// assembled into an [`Event`] by [`common::assemble_event`].
    fn row_to_event(row: &PgRow) -> Result<Event, WriterError> {
        let id: uuid::Uuid = row
            .try_get("id")
            .map_err(|e| WriterError::Other(format!("Failed to get id: {e}")))?;
        let timestamp: chrono::DateTime<chrono::Utc> = row
            .try_get("timestamp")
            .map_err(|e| WriterError::Other(format!("Failed to get timestamp: {e}")))?;
        let event_type: String = row
            .try_get("event_type")
            .map_err(|e| WriterError::Other(format!("Failed to get event_type: {e}")))?;
        let severity: String = row
            .try_get("severity")
            .map_err(|e| WriterError::Other(format!("Failed to get severity: {e}")))?;
        let message: String = row
            .try_get("message")
            .map_err(|e| WriterError::Other(format!("Failed to get message: {e}")))?;
        let correlation_id: uuid::Uuid = row
            .try_get("correlation_id")
            .map_err(|e| WriterError::Other(format!("Failed to get correlation_id: {e}")))?;

        let line: i32 = row.try_get("line").unwrap_or(0);

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
            contains_pii: row.try_get("contains_pii").unwrap_or(false),
            contains_phi: row.try_get("contains_phi").unwrap_or(false),
            security_relevant: row.try_get("security_relevant").unwrap_or(false),
            metadata: row.try_get("metadata").ok(),
        }))
    }
}

#[async_trait]
impl DatabaseBackend for PostgresBackend {
    async fn store_events(&self, events: &[Event]) -> Result<usize, WriterError> {
        if events.is_empty() {
            return Ok(0);
        }

        // Use a transaction for batch insert
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| WriterError::Other(format!("Failed to begin transaction: {e}")))?;

        let mut count: usize = 0;

        for event in events {
            let result = sqlx::query(
                r#"
                INSERT INTO audit_events (
                    id, timestamp, event_type, severity, message,
                    operation, tenant_id, user_id, correlation_id,
                    resource_type, resource_id, module_path, file, line,
                    contains_pii, contains_phi, security_relevant, metadata
                ) VALUES (
                    $1, $2, $3, $4, $5,
                    $6, $7, $8, $9,
                    $10, $11, $12, $13, $14,
                    $15, $16, $17, $18
                )
                ON CONFLICT (id) DO NOTHING
                "#,
            )
            .bind(event.id)
            .bind(event.timestamp)
            .bind(format!("{:?}", event.event_type))
            .bind(format!("{:?}", event.severity))
            .bind(&event.message)
            .bind(&event.context.operation)
            .bind(event.context.tenant_id.as_ref().map(|t| t.as_str()))
            .bind(event.context.user_id.as_ref().map(|u| u.as_str()))
            .bind(event.context.correlation_id)
            .bind(&event.context.resource_type)
            .bind(&event.context.resource_id)
            .bind(&event.context.module_path)
            .bind(&event.context.file)
            .bind(event.context.line as i32)
            .bind(event.context.contains_pii)
            .bind(event.context.contains_phi)
            .bind(event.context.security_relevant)
            .bind(serde_json::to_value(&event.metadata).ok())
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
        let rows: Vec<PgRow> = stmt
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
        let result = sqlx::query("DELETE FROM audit_events WHERE timestamp < NOW() - $1::interval")
            .bind(format!("{retention_days} days"))
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
                id UUID PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                event_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                message TEXT NOT NULL,
                operation VARCHAR(255),
                tenant_id VARCHAR(100),
                user_id VARCHAR(100),
                correlation_id UUID NOT NULL,
                resource_type VARCHAR(100),
                resource_id VARCHAR(255),
                module_path VARCHAR(255),
                file VARCHAR(255),
                line INTEGER,
                contains_pii BOOLEAN DEFAULT FALSE,
                contains_phi BOOLEAN DEFAULT FALSE,
                security_relevant BOOLEAN DEFAULT FALSE,
                metadata JSONB,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_id ON audit_events(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit_events(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_correlation_id ON audit_events(correlation_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events(severity);
            CREATE INDEX IF NOT EXISTS idx_audit_events_security ON audit_events(security_relevant) WHERE security_relevant = TRUE;
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| WriterError::Other(format!("Migration failed: {e}")))?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "postgres"
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // Note: These tests require a running PostgreSQL instance
    // They are marked as ignored by default and can be run with:
    // cargo test --features postgres -- --ignored

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database"]
    async fn test_postgres_connect() {
        let backend = PostgresBackend::connect("postgres://localhost/test_audit")
            .await
            .expect("connect should succeed");

        backend
            .health_check()
            .await
            .expect("health check should pass");
    }

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database"]
    async fn test_postgres_migrate() {
        let backend = PostgresBackend::connect("postgres://localhost/test_audit")
            .await
            .expect("connect should succeed");

        backend.migrate().await.expect("migration should succeed");
    }

    // =========================================================================
    // Connection-failure I/O path (no database required)
    // =========================================================================

    /// A malformed connection string must fail during `PgPoolOptions::connect`
    /// URL parsing and be mapped to `WriterError::Configuration` — the same
    /// error-mapping closure used for every connect failure. This exercises
    /// the failure branch of `connect()` without any network wait.
    #[tokio::test]
    async fn test_connect_malformed_url_is_configuration_error() {
        let result = PostgresBackend::connect("not-a-postgres-url").await;
        let err = result.err().expect("malformed URL must not connect");
        assert!(
            matches!(err, WriterError::Configuration(_)),
            "expected Configuration error, got {err:?}"
        );
    }

    /// Connecting to a closed TCP port also maps to `WriterError::Configuration`.
    /// `PostgresBackend::connect` hardcodes a 30s `acquire_timeout`, so this
    /// genuinely-unreachable path is slow and is `#[ignore]`d by default; the
    /// fast malformed-URL test above covers the same mapping closure, and
    /// `runtime::database::pool`'s unreachable test covers the TCP-refused
    /// branch with a short, configurable timeout. Run manually:
    /// `cargo test --features postgres -- --ignored unreachable`.
    #[tokio::test]
    #[ignore = "slow: connect() hardcodes a 30s acquire_timeout"]
    async fn test_connect_unreachable_is_configuration_error() {
        let result = PostgresBackend::connect("postgres://user:pass@127.0.0.1:1/none").await;
        let err = result.err().expect("closed port must not connect");
        assert!(
            matches!(err, WriterError::Configuration(_)),
            "expected Configuration error, got {err:?}"
        );
    }
}
