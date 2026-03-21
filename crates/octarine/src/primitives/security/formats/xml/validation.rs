//! XML security validation
//!
//! Validates XML input against security policies.

use crate::primitives::types::{Problem, Result};

use super::super::types::XmlPolicy;
use super::detection::{detect_xml_threats, has_dtd_declaration, is_xxe_present};

/// Validate that XML input is safe according to the given policy
///
/// Returns `Ok(())` if the input passes all security checks,
/// or an error describing the threat.
pub(crate) fn validate_xml_safe(input: &str, policy: &XmlPolicy) -> Result<()> {
    // Check for XXE (always blocked unless explicitly allowed)
    if !policy.allow_external_entities && is_xxe_present(input) {
        return Err(Problem::Validation(
            "XML contains external entity reference (XXE attack pattern)".into(),
        ));
    }

    // Check for DTD
    if !policy.allow_dtd && has_dtd_declaration(input) {
        return Err(Problem::Validation(
            "XML contains DOCTYPE declaration (DTD not allowed by policy)".into(),
        ));
    }

    // Check for other threats
    let threats = detect_xml_threats(input);
    for threat in threats {
        // Skip DTD if allowed
        if matches!(threat, super::super::types::FormatThreat::DtdPresent) && policy.allow_dtd {
            continue;
        }

        // Skip XXE if external entities allowed (unusual but possible)
        if matches!(
            threat,
            super::super::types::FormatThreat::XxeExternalEntity
                | super::super::types::FormatThreat::XxeParameterEntity
        ) && policy.allow_external_entities
        {
            continue;
        }

        // All other threats are always blocked
        return Err(Problem::Validation(format!(
            "XML security threat detected: {}",
            threat
        )));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_clean_xml() {
        let policy = XmlPolicy::strict();
        let result = validate_xml_safe("<root><child/></root>", &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_xxe() {
        let policy = XmlPolicy::strict();
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;

        let result = validate_xml_safe(xxe, &policy);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("external entity")
        );
    }

    #[test]
    fn test_validate_rejects_dtd_by_default() {
        let policy = XmlPolicy::strict();
        let result = validate_xml_safe("<!DOCTYPE html>", &policy);

        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("DOCTYPE")
        );
    }

    #[test]
    fn test_validate_allows_dtd_when_permitted() {
        let policy = XmlPolicy::permissive();
        let result = validate_xml_safe("<!DOCTYPE html><html/>", &policy);

        // Should pass - DTD is allowed in permissive mode
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_xxe_even_in_permissive() {
        let policy = XmlPolicy::permissive();
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;

        let result = validate_xml_safe(xxe, &policy);
        assert!(result.is_err());
    }
}
