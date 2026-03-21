//! GraphQL injection detection and prevention
//!
//! Provides detection and validation for GraphQL abuse (CWE-1021).
//!
//! # Threat Categories
//!
//! | Threat | Description | Example |
//! |--------|-------------|---------|
//! | Introspection | Schema discovery | `{ __schema { types { name } } }` |
//! | Alias bombing | DoS via aliases | `{ a1: user, a2: user, ... }` |
//! | Field duplication | DoS via field spam | Excessive field selection |
//! | Depth attack | Deeply nested queries | Excessive nesting |
//!
//! # Note
//!
//! This module will be fully implemented in Phase 4.

pub(super) mod analysis;
pub(super) mod detection;
pub(super) mod patterns;
pub mod schema; // Keep pub - GraphqlSchema is a data type exposed to consumers
pub(super) mod validation;

// Internal re-exports for use by the builder
pub(super) use analysis::analyze_graphql_query;
pub(super) use detection::{detect_graphql_threats, is_graphql_injection_present};
pub(super) use validation::validate_graphql_query;

// Public re-export of data type
pub use schema::GraphqlSchema;
