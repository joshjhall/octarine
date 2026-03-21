//! Database connection primitives
//!
//! Core types for database connections. These are internal primitives
//! used by higher-layer modules. For the public API, see `runtime::database`.
//!
//! Note: `DatabaseConfigCore` is currently unused but available for future
//! use if we need internal database configuration without the public API.

mod config;

// Allow unused - primitive available for future internal use
#[allow(unused_imports)]
pub(crate) use config::DatabaseConfigCore;
