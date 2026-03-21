//! Structured data format operations - FORMAT concerns
//!
//! Pure parsing and serialization for JSON, XML, and YAML formats with ZERO
//! dependencies beyond the format parsing libraries.
//!
//! ## Architecture
//!
//! This is part of **Layer 1 (primitives)** - used by observe and runtime modules.
//! This module answers: "How should this structured data be PARSED/SERIALIZED?"
//!
//! For other concerns, see:
//! - `primitives::security::formats` - THREATS: "Is this dangerous?" (XXE, unsafe tags)
//! - `io::formats` - I/O: "How do I read/write files?"
//! - `runtime::formats` - UNIFIED: "Do the safe thing for me"
//!
//! ## Module Structure
//!
//! - `types` - Shared types (FormatType, ParseOptions)
//! - `json` - JSON parsing and serialization
//! - `xml` - XML parsing and serialization
//! - `yaml` - YAML parsing and serialization
//! - `builder` - FormatBuilder unified API
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Security Checks**: That's the security module's job
//! 3. **No File I/O**: That's the io module's job
//! 4. **Reusable**: Used by security, io, and runtime modules

#[cfg(feature = "formats")]
mod types;

#[cfg(feature = "formats")]
pub(crate) mod builder;
#[cfg(feature = "formats")]
pub(crate) mod json;
#[cfg(feature = "formats")]
pub(crate) mod xml;
#[cfg(feature = "formats")]
pub(crate) mod yaml;

// Re-export types when feature is enabled
#[cfg(feature = "formats")]
pub use types::{FormatType, ParseOptions};

// Re-export builder when feature is enabled
#[cfg(feature = "formats")]
pub use builder::FormatBuilder;

// Re-export XML types when feature is enabled
#[cfg(feature = "formats")]
pub use xml::XmlDocument;
