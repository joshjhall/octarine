//! Structured data format security - THREAT concerns
//!
//! Detection and validation for security threats in XML, JSON, and YAML.
//! This module answers: "Is this structured data dangerous?"
//!
//! ## Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! ## Security Coverage
//!
//! | Format | Threat | CWE | Description |
//! |--------|--------|-----|-------------|
//! | XML | XXE External | CWE-611 | External entity file/URL access |
//! | XML | XXE Parameter | CWE-611 | Parameter entity injection |
//! | XML | Billion Laughs | CWE-776 | Entity expansion DoS |
//! | XML | DTD Present | CWE-827 | DOCTYPE declaration |
//! | JSON | Depth Exceeded | CWE-400 | Nesting bomb DoS |
//! | JSON | Size Exceeded | CWE-400 | Large payload DoS |
//! | YAML | Unsafe Tag | CWE-502 | Deserialization code execution |
//! | YAML | Anchor Bomb | CWE-776 | Alias expansion DoS |
//!
//! ## Usage
//!
//! ```ignore
//! use octarine::primitives::security::formats::FormatSecurityBuilder;
//!
//! let security = FormatSecurityBuilder::new();
//!
//! // XML XXE detection
//! if security.is_xxe_present(xml_input) {
//!     // Block dangerous XML
//! }
//!
//! // YAML unsafe tag detection
//! if security.is_yaml_unsafe(yaml_input) {
//!     // Block dangerous YAML
//! }
//!
//! // Validation with policy
//! security.validate_xml(&xml_input, &XmlPolicy::strict())?;
//! ```

mod builder;
mod json;
mod types;
mod xml;
mod yaml;

// Re-export types
pub use types::{FormatThreat, JsonPolicy, XmlPolicy, YamlPolicy};

// Re-export builder
pub use builder::FormatSecurityBuilder;
