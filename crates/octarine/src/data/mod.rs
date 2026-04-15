// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! Data operations with built-in security and observability
//!
//! This module provides data handling operations for paths, text,
//! and other data types. All operations wrap primitives with observe instrumentation
//! for compliance-grade audit trails.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    data/ (Public API)                       │
//! │  - PathBuilder, TextBuilder, UrlNormalizationBuilder        │
//! │  - Shortcuts for common operations                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  primitives/data/ (Internal)                │
//! │  - Pure detection, validation, sanitization logic           │
//! │  - No logging, no side effects                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - `network` - URL path normalization
//! - `paths` - Path detection, validation, and sanitization
//! - `text` - Text sanitization and detection (log injection, control characters)
//!
//! # Examples
//!
//! ## Path Operations
//!
//! ```
//! use octarine::data::paths::{validate_path, sanitize_filename, is_path_traversal_present};
//!
//! // Path validation (returns Result)
//! validate_path("safe/path").unwrap();
//!
//! // Path sanitization
//! let clean = sanitize_filename("file.txt").unwrap();
//!
//! // Path detection (returns bool)
//! if is_path_traversal_present("../etc/passwd") {
//!     // Handle security threat
//! }
//! ```
//!
//! ## Using Builders (Complex Workflows)
//!
//! ```
//! use octarine::data::paths::PathBuilder;
//!
//! // Path builder
//! let builder = PathBuilder::new().boundary("/app/data");
//! let result = builder.sanitize("user/file.txt").unwrap();
//! ```
//!
//! # Security Features
//!
//! All operations include:
//! - Automatic threat detection (traversal, injection, etc.)
//! - Observe events for audit trails
//! - Metrics for monitoring
//! - Configurable security levels

mod facade;

#[cfg(feature = "formats")]
pub mod formats;
pub mod network;
pub mod paths;
pub mod text;

// Re-export the Data facade at module level
pub use facade::Data;

// No flat re-exports - access via submodule namespace:
// - data::network::UrlNormalizationBuilder, data::network::NormalizeUrlPathOptions
// - data::text::TextBuilder, data::text::TextConfig
// - data::paths::PathBuilder
// - identifiers::RedactionToken
// - security::queries::QueryBuilder (requires "database" feature)
