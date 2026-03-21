// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! Path security operations with built-in observability
//!
//! This module provides path security detection, validation, and sanitization
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Architecture
//!
//! This is **Layer 3 (security)** - wraps primitives with observe instrumentation:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  security/paths (Public API)                │
//! │  - SecurityBuilder                                          │
//! │  - Shortcuts for common operations                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │              primitives/security/paths (Internal)           │
//! │  - Pure detection, validation functions                     │
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
//! - **Threat Detection**: Identify path traversal, injection, and encoding attacks
//! - **Validation**: Enforce security policies on paths
//! - **Sanitization**: Remove dangerous patterns from paths
//!
//! # Security Standards
//!
//! All operations follow OWASP guidelines and address:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization
//!
//! # Note on Path Formatting
//!
//! For path normalization, format conversion, and other FORMAT concerns,
//! use [`crate::data::paths`] instead. This module focuses on
//! THREATS (security), not FORMAT (normalization).
//!
//! # Examples
//!
//! ```ignore
//! use octarine::security::paths::{SecurityBuilder, is_path_traversal_present};
//!
//! // Quick detection
//! if is_path_traversal_present("../etc/passwd") {
//!     // Handle threat
//! }
//!
//! // Builder pattern
//! let security = SecurityBuilder::new();
//! let threats = security.detect_threats("../$(cmd)/file");
//! ```

mod builder;
mod shortcuts;
mod types;

// Re-export the builder
pub use builder::SecurityBuilder;

// Re-export types - canonical location for security-related path types
pub use types::{PathSanitizationStrategy, SecurityThreat};

// Re-export shortcuts at module level
pub use shortcuts::*;
