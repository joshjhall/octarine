//! Query security types re-exported from primitives
//!
//! Follows the same pattern as `security::formats::types` — lifts the
//! `pub(crate)` primitives types into this crate's public API without a
//! wrapper layer. Use this module as the canonical import path for query
//! security types from downstream code.

pub use crate::primitives::security::queries::{
    GraphqlAnalysis, GraphqlConfig, GraphqlSchema, QueryThreat, QueryType,
};
