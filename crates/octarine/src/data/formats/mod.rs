//! Structured data format parsing and serialization (Layer 3)
//!
//! This module provides format handling for JSON, XML, and YAML with
//! observe instrumentation for audit trails.
//!
//! # Features
//!
//! - Parse JSON, XML, and YAML content
//! - Serialize data to structured formats
//! - Automatic format detection from content or extension
//! - Pretty-printing and formatting options
//!
//! # Security
//!
//! For security-related format operations (XXE prevention, YAML unsafe tag
//! detection), see [`crate::security::formats`].
//!
//! # Examples
//!
//! ```ignore
//! use octarine::data::formats::{parse_json, parse_xml, detect_format};
//! use octarine::data::formats::FormatType;
//!
//! // Parse JSON
//! let value = parse_json(r#"{"key": "value"}"#)?;
//!
//! // Detect format from content
//! if let Some(format) = detect_format("<root/>") {
//!     assert!(matches!(format, FormatType::Xml));
//! }
//! ```

mod builder;
mod shortcuts;
mod types;

// Re-export builder
pub use builder::FormatBuilder;

// Re-export types from primitives
pub use types::{FormatType, ParseOptions};

// Re-export shortcuts
pub use shortcuts::*;
