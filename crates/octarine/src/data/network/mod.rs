// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! Network data operations with built-in observability
//!
//! This module provides network data normalization and formatting operations
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Architecture
//!
//! This is **Layer 3 (data)** - wraps primitives with observe instrumentation:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  data/network (Public API)                  │
//! │  - UrlNormalizationBuilder                                  │
//! │  - Shortcuts for common operations                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │              primitives/data/network (Internal)             │
//! │  - Pure normalization functions                             │
//! │  - No logging, no side effects                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **URL Path Normalization**: Canonicalize URL paths for consistent handling
//! - **Slash Handling**: Collapse multiple slashes, remove trailing slashes
//! - **Dot Segment Removal**: Handle `.` and `..` in paths per RFC 3986
//!
//! # Note on Security Operations
//!
//! For SSRF detection, URL validation, and other security operations,
//! use [`crate::security::network`] instead. This module focuses on
//! FORMAT concerns (normalization), not THREATS (security).
//!
//! # Examples
//!
//! ```ignore
//! use octarine::data::network::{normalize_url_path, NormalizeUrlPathOptions};
//!
//! // Basic normalization
//! let normalized = normalize_url_path("/api/users/");
//! assert_eq!(normalized, "/api/users");
//!
//! // With custom options
//! let options = NormalizeUrlPathOptions::for_metrics();
//! let normalized = normalize_url_path_with_options("/API/Users/", &options);
//! assert_eq!(normalized, "/api/users");
//! ```

mod builder;
mod shortcuts;
mod types;

// Re-export the builder
pub use builder::UrlNormalizationBuilder;

// Re-export types for public API
pub use types::{NormalizeUrlPathOptions, PathPattern};

// Re-export shortcuts at module level
pub use shortcuts::*;
