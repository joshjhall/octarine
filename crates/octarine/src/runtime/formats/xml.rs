//! Secure XML reader
//!
//! Validates XML against XXE attacks before parsing.

use std::path::Path;

use crate::observe::{debug, info};
use crate::primitives::data::formats::{FormatBuilder, XmlDocument};
use crate::primitives::security::formats::{FormatSecurityBuilder, XmlPolicy};
use crate::primitives::types::Result;

/// Secure XML reader with XXE prevention
///
/// Validates XML input against XXE attacks and DTD policies before
/// parsing. Use this for untrusted input.
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::formats::SecureXmlReader;
///
/// let reader = SecureXmlReader::new();
/// let doc = reader.parse("<root><child/></root>")?;
///
/// // With custom policy (allow DTD)
/// use octarine::security::formats::XmlPolicy;
/// let reader = SecureXmlReader::with_policy(XmlPolicy { allow_dtd: true, allow_external_entities: false });
/// ```
#[derive(Debug, Clone)]
pub struct SecureXmlReader {
    policy: XmlPolicy,
    format: FormatBuilder,
    security: FormatSecurityBuilder,
}

impl Default for SecureXmlReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureXmlReader {
    /// Create a new secure XML reader with default strict policy
    ///
    /// By default, DTD and external entities are blocked.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: XmlPolicy::strict(),
            format: FormatBuilder::new(),
            security: FormatSecurityBuilder::new(),
        }
    }

    /// Create a secure XML reader with a custom policy
    #[must_use]
    pub fn with_policy(policy: XmlPolicy) -> Self {
        Self {
            policy,
            format: FormatBuilder::new(),
            security: FormatSecurityBuilder::new(),
        }
    }

    /// Parse XML string securely
    ///
    /// Validates against XXE and the security policy before parsing.
    pub fn parse(&self, input: &str) -> Result<XmlDocument> {
        debug("runtime.format", "Securely parsing XML");

        // Validate security (XXE prevention)
        self.security.validate_xml(input, &self.policy)?;

        // Parse
        let result = self.format.parse_xml(input)?;

        info("runtime.format", "XML parsed successfully");
        Ok(result)
    }

    /// Read and parse an XML file securely
    pub fn read_file(&self, path: impl AsRef<Path>) -> Result<XmlDocument> {
        let path = path.as_ref();
        debug(
            "runtime.format",
            format!("Securely reading XML file: {}", path.display()),
        );

        // Read file
        let content = std::fs::read_to_string(path)?;

        // Validate and parse
        self.parse(&content)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_secure_xml_reader_parse() {
        let reader = SecureXmlReader::new();
        let result = reader.parse("<root><child/></root>");
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_xml_reader_blocks_xxe() {
        let reader = SecureXmlReader::new();

        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root/>"#;
        let result = reader.parse(xxe);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_xml_reader_blocks_dtd_by_default() {
        let reader = SecureXmlReader::new();

        let dtd = "<!DOCTYPE html><html/>";
        let result = reader.parse(dtd);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_xml_reader_allows_dtd_with_policy() {
        let reader = SecureXmlReader::with_policy(XmlPolicy::permissive());

        let dtd = "<!DOCTYPE html><html/>";
        let result = reader.parse(dtd);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_xml_reader_read_file() {
        let reader = SecureXmlReader::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.xml");

        std::fs::write(&path, "<root><child/></root>").expect("write file");

        let result = reader.read_file(&path);
        assert!(result.is_ok());
    }
}
