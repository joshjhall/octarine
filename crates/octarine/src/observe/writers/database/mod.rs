//! Database writers for audit event persistence
//!
//! This module provides database-backed writers for persisting audit events
//! to comply with retention requirements (SOC2, HIPAA, PCI-DSS, GDPR).
//!
//! # Feature Flags
//!
//! Database support is optional and requires feature flags:
//!
//! - `database` - Core types and traits (no database deps)
//! - `postgres` - PostgreSQL backend via sqlx
//! - `sqlite` - SQLite backend via sqlx (for local dev/testing)
//!
//! # Architecture
//!
//! The module uses a trait-based abstraction allowing users to implement
//! their own database backends:
//!
//! ```rust,no_run
//! use octarine::observe::writers::{DatabaseBackend, DatabaseWriter, DatabaseWriterConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Implement your own database backend
//! // struct MyDatabaseBackend { /* ... */ }
//! // impl DatabaseBackend for MyDatabaseBackend { /* ... */ }
//! // let writer = DatabaseWriter::new(backend, config);
//! # Ok(())
//! # }
//! ```
//!
//! # Compliance
//!
//! - **SOC2 CC7.1**: Audit log retention (90 days minimum)
//! - **HIPAA §164.312(b)**: Audit controls with queryable history
//! - **GDPR Article 5(1)(e)**: Storage limitation with enforced retention
//! - **PCI-DSS 10.7**: Retain audit trail for at least one year

mod config;
mod query;
mod traits;
mod writer;

pub use config::DatabaseWriterConfig;
pub use query::AuditQuery;
pub use traits::{DatabaseBackend, InMemoryBackend, NoOpBackend, QueryResult};
pub use writer::DatabaseWriter;

// Feature-gated backends
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::PostgresBackend;

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteBackend;
