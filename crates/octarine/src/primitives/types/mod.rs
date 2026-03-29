//! Core type definitions for octarine
//!
//! Foundation types shared across all modules. These are pure types with no
//! dependencies on observe or other internal modules.
//!
//! ## Module Contents
//!
//! - `problem` - Error type hierarchy (`Problem`, `Result`)
//! - `dates` - Date parsing utilities
//! - `network` - Network types (`PortRange`)
//!
//! ## Architecture Note
//!
//! This is the **central definition** location for shared types. Types are
//! defined once here and re-exported from domain modules where they're used.
//!
//! ## Type Re-export Pattern
//!
//! Types follow a three-layer pattern:
//!
//! 1. **Central definition**: Types are defined here in `primitives/types/`
//! 2. **Domain re-exports**: Domain modules re-export types they use:
//!    - `primitives::data::security::network::PortRange`
//!    - `primitives::data::identifiers::IdentifierType`
//! 3. **Public API wrappers**: Layer 3 creates wrapper types for the public API
//!
//! This allows:
//! - Single source of truth (types defined once)
//! - Ergonomic imports from logical namespaces
//! - No type conflicts (all paths resolve to same type)
//!
//! ### Example
//!
//! ```ignore
//! // Central definition
//! // primitives/types/network.rs
//! pub enum PortRange { ... }
//!
//! // Domain re-export
//! // primitives/security/network/builder.rs
//! pub use crate::primitives::types::PortRange;
//!
//! // Consumer uses domain path
//! use crate::primitives::security::network::PortRange;
//! ```

mod dates;
mod network;
mod problem;

// Re-export commonly used types
#[allow(unused_imports)]
pub(crate) use dates::{
    get_current_year, is_leap_year, parse_eu_date, parse_iso_date, parse_us_date,
};
pub use network::PortRange;
pub use problem::{Problem, Result};
