//! Unified secure format handling (Layer 3)
//!
//! This module brings together data, security, and I/O concerns for
//! structured data formats (JSON, XML, YAML) into a single, safe API.
//!
//! # Design Philosophy
//!
//! Most users should use this module. It provides:
//! - Security validation before parsing (XXE prevention, unsafe tag detection)
//! - Convenient file I/O with format detection
//! - Full observability with audit trails
//!
//! For bespoke workflows, use the individual modules:
//! - `data::formats` - Pure parsing/serialization
//! - `security::formats` - Threat detection
//! - `io::formats` - File operations
//!
//! # Examples
//!
//! ```ignore
//! use octarine::runtime::formats::{SecureJsonReader, SecureXmlReader, SecureYamlReader};
//!
//! // Safe JSON parsing
//! let json = SecureJsonReader::new().parse(r#"{"key": "value"}"#)?;
//!
//! // Safe XML parsing with XXE prevention
//! let xml = SecureXmlReader::new().parse("<root><child/></root>")?;
//!
//! // Safe YAML parsing with code execution prevention
//! let yaml = SecureYamlReader::new().parse("key: value")?;
//!
//! // Read files safely
//! let config = SecureJsonReader::new().read_file("config.json")?;
//! ```

mod json;
mod xml;
mod yaml;

// Re-export secure readers
pub use json::SecureJsonReader;
pub use xml::SecureXmlReader;
pub use yaml::SecureYamlReader;

// Re-export types from other modules for convenience
pub use crate::data::formats::FormatType;
pub use crate::security::formats::{JsonPolicy, XmlPolicy, YamlPolicy};
