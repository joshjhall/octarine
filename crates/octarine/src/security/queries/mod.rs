//! Query security with built-in observability
//!
//! This module provides query injection prevention for SQL, NoSQL, LDAP,
//! and GraphQL. All operations are instrumented with observe for
//! compliance-grade audit trails.
//!
//! # Architecture
//!
//! This is **Layer 3 (security/queries)** - wraps primitives with observe:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │               security/queries/ (Public API)                │
//! │  - QueryBuilder with observe instrumentation                │
//! │  - Shortcuts for common operations                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │            primitives/security/queries/ (Internal)          │
//! │  - Pure detection, validation, sanitization logic           │
//! │  - No logging, no side effects                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # OWASP A03:2021 Coverage
//!
//! | Query Type | CWE | Description |
//! |------------|-----|-------------|
//! | SQL | CWE-89 | SQL Injection |
//! | NoSQL | CWE-943 | NoSQL Injection |
//! | LDAP | CWE-90 | LDAP Injection |
//! | GraphQL | CWE-1021 | GraphQL Abuse |
//!
//! # Usage
//!
//! ## Shortcuts (Recommended)
//!
//! ```ignore
//! use octarine::security::queries::{
//!     validate_sql_parameter,
//!     validate_nosql_value,
//!     validate_ldap_filter,
//!     is_sql_injection_present,
//! };
//!
//! // Validation (returns Result)
//! validate_sql_parameter(user_input)?;
//!
//! // Detection (returns bool)
//! if is_sql_injection_present(user_input) {
//!     // Handle threat
//! }
//! ```
//!
//! ## QueryBuilder (Unified API)
//!
//! ```ignore
//! use octarine::security::queries::QueryBuilder;
//!
//! let builder = QueryBuilder::new();
//!
//! // SQL validation
//! builder.validate_sql_parameter(user_input)?;
//!
//! // Escaping (when parameterized queries aren't possible)
//! let safe = builder.escape_sql_string(user_input);
//! ```

mod builder;
mod shortcuts;

pub use builder::QueryBuilder;
pub use shortcuts::*;

// Re-export key types from primitives
pub use crate::primitives::security::queries::{
    GraphqlAnalysis, GraphqlConfig, GraphqlSchema, QueryThreat, QueryType,
};
