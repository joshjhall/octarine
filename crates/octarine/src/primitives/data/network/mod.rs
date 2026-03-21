// Allow unused imports until this module is integrated with higher layers
#![allow(unused_imports)]

//! Network data primitives module - FORMAT concerns
//!
//! Pure network-related normalization utilities with ZERO rust-core dependencies.
//!
//! # Architecture Layer
//!
//! This is **Layer 1 (primitives)** of the three-layer architecture:
//! - **Layer 1 (primitives)**: Pure utilities, no internal dependencies
//! - **Layer 2 (observe)**: Uses primitives only
//! - **Layer 3 (data, security, runtime)**: Uses primitives + observe
//!
//! # Three Orthogonal Concerns
//!
//! This module handles FORMAT concerns for network data:
//! - `primitives::data::network` - FORMAT: "How should this URL/hostname be normalized?"
//! - `primitives::security::network` - THREATS: "Is this URL/host dangerous?"
//! - `primitives::identifiers::network` - CLASSIFICATION: "Is this an IP/URL/MAC?"
//!
//! # Module Organization
//!
//! ```text
//! primitives/data/network/
//! ├── mod.rs              - Module root and re-exports
//! └── url.rs              - URL path normalization
//! ```
//!
//! # Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only string transformations
//! 3. **Reusable**: Used by observe and higher-layer modules
//! 4. **Zero-Copy**: Uses `Cow<str>` where possible for efficiency

mod url;

// Re-export URL normalization functions
pub use url::{NormalizeUrlPathOptions, normalize_url_path, normalize_url_path_with_options};

// Re-export path segment normalization (for metrics)
pub use url::{
    ID_PLACEHOLDER, PathPattern, UUID_PLACEHOLDER, normalize_path_segments,
    normalize_path_segments_with_patterns,
};
