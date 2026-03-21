//! Format security operations with observability (Layer 3)
//!
//! This module provides security threat detection and validation for
//! structured data formats (JSON, XML, YAML) with observe instrumentation.
//!
//! # Features
//!
//! - XXE (XML External Entity) detection and prevention
//! - YAML unsafe tag detection (code execution prevention)
//! - JSON depth/size limit enforcement
//! - Billion Laughs attack detection
//!
//! # CWE Coverage
//!
//! | Threat | CWE | Description |
//! |--------|-----|-------------|
//! | XXE External Entity | CWE-611 | Improper Restriction of XML External Entity Reference |
//! | XXE Parameter Entity | CWE-611 | Same as above |
//! | Billion Laughs | CWE-776 | Improper Restriction of Recursive Entity References |
//! | DTD Processing | CWE-827 | Improper Control of Document Type Definition |
//! | JSON Depth | CWE-400 | Uncontrolled Resource Consumption |
//! | YAML Code Exec | CWE-94 | Improper Control of Generation of Code |
//! | YAML Deserialization | CWE-502 | Deserialization of Untrusted Data |
//!
//! # Examples
//!
//! ```ignore
//! use octarine::security::formats::{is_xxe_present, is_yaml_unsafe, validate_xml_safe};
//!
//! // Check for XXE attacks
//! if is_xxe_present(xml_input) {
//!     // Block dangerous XML
//! }
//!
//! // Check for unsafe YAML
//! if is_yaml_unsafe(yaml_input) {
//!     // Block code execution
//! }
//!
//! // Validate with policy
//! validate_xml_safe(xml_input)?;
//! ```

mod builder;
mod shortcuts;
mod types;

// Re-export builder
pub use builder::FormatSecurityBuilder;

// Re-export types
pub use types::{FormatThreat, JsonPolicy, XmlPolicy, YamlPolicy};

// Re-export shortcuts
pub use shortcuts::*;
