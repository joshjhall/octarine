//! Problem type definitions
//!
//! Re-exports the foundation Problem and Result types from primitives/types.
//! The actual type definitions live in `primitives::types::problem` to avoid
//! circular dependencies.

// Re-export from primitives/types
pub use crate::primitives::types::{Problem, Result};
