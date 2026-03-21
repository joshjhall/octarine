//! Query security primitives for injection prevention
//!
//! This module provides detection, validation, and sanitization for
//! SQL, NoSQL, LDAP, and GraphQL injection attacks.
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Security Coverage (OWASP A03:2021 - Injection)
//!
//! | Query Type | CWE | Description |
//! |------------|-----|-------------|
//! | SQL | CWE-89 | SQL Injection |
//! | NoSQL | CWE-943 | NoSQL Injection |
//! | LDAP | CWE-90 | LDAP Injection |
//! | GraphQL | CWE-1021 | GraphQL Injection |
//!
//! # Submodules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`sql`] | SQL injection detection, validation, escaping |
//! | [`nosql`] | NoSQL operator injection detection |
//! | [`ldap`] | LDAP filter injection, RFC 4515 escaping |
//! | [`graphql`] | GraphQL introspection, complexity analysis |
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::security::queries::QuerySecurityBuilder;
//!
//! let builder = QuerySecurityBuilder::new();
//!
//! // SQL injection detection
//! if builder.is_sql_injection_present(user_input) {
//!     // Block or sanitize
//! }
//!
//! // LDAP escaping
//! let safe_filter = builder.escape_ldap_filter(user_input);
//! ```

#[cfg(feature = "database")]
mod builder;
#[cfg(feature = "database")]
mod graphql;
#[cfg(feature = "database")]
mod ldap;
#[cfg(feature = "database")]
mod nosql;
#[cfg(feature = "database")]
mod sql;
#[cfg(feature = "database")]
mod types;

// Public API: Builder + Types + Data structures
#[cfg(feature = "database")]
pub use builder::QuerySecurityBuilder;
#[cfg(feature = "database")]
pub use graphql::GraphqlSchema;
#[cfg(feature = "database")]
pub use types::{GraphqlAnalysis, GraphqlConfig, QueryThreat, QueryType};
