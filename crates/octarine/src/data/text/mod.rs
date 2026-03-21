// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! Text operations with built-in observability
//!
//! This module provides text sanitization and detection operations
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Architecture
//!
//! This is **Layer 3 (data)** - wraps primitives with observe instrumentation:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    data/text (Public API)                   │
//! │  - TextBuilder (octarine::data::TextBuilder)                │
//! │  - Shortcuts (octarine::data::text::shortcut_name)          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  primitives/data/text (Internal)            │
//! │  - Pure detection, sanitization functions                   │
//! │  - No logging, no side effects                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Features
//!
//! - **Log Injection Prevention**: Escape/strip dangerous characters
//! - **CRLF Injection Prevention**: Handle newlines and carriage returns
//! - **Control Character Detection**: Find dangerous control sequences
//! - **ANSI Escape Handling**: Strip terminal escape sequences
//!
//! # Examples
//!
//! ## Quick Sanitization (Shortcuts)
//!
//! ```ignore
//! use octarine::data::text::{sanitize_for_log, is_log_safe};
//!
//! // Check if text needs sanitization
//! if !is_log_safe(user_input) {
//!     let safe = sanitize_for_log(user_input);
//!     println!("User said: {}", safe);
//! }
//! ```
//!
//! ## Builder Pattern
//!
//! ```ignore
//! use octarine::data::TextBuilder;
//!
//! // Fluent API for complex operations
//! let safe = TextBuilder::new(user_input)
//!     .strip_ansi()
//!     .sanitize_for_log()
//!     .truncate(100)
//!     .finish();
//! ```
//!
//! # Observe Integration
//!
//! All operations emit observe events for security-relevant detections:
//! - Dangerous control characters → warning event
//! - Null bytes → warning event
//! - ANSI escapes → debug event (common in terminal output)
//! - Bidi overrides → warning event (potential spoofing)

// Private submodules
mod builder;
pub mod shortcuts;
mod types;

// Re-export the builder at data level (octarine::data::TextBuilder)
pub use builder::TextBuilder;

// Re-export TextConfig wrapper type (not the primitive)
pub use types::TextConfig;

// Re-export shortcuts at text level (octarine::data::text::shortcut_name)
pub use shortcuts::*;
