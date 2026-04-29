//! Generic identifier detection shortcuts.
//!
//! Cross-domain detection helpers that delegate to [`IdentifierBuilder`](super::super::IdentifierBuilder).

use super::super::IdentifierBuilder;
use super::super::types::{IdentifierMatch, IdentifierType};

/// Detect the type of identifier from a value
///
/// Returns None if the value doesn't match any known identifier type.
#[must_use]
pub fn detect_identifier(value: &str) -> Option<IdentifierType> {
    IdentifierBuilder::new().detect(value)
}

/// Scan text for all identifiers
///
/// Returns a list of all identifier matches found in the text.
#[must_use]
pub fn scan_identifiers(text: &str) -> Vec<IdentifierMatch> {
    IdentifierBuilder::new().scan_text(text)
}

/// Check if text contains any identifiers
#[must_use]
pub fn is_identifiers_present(text: &str) -> bool {
    IdentifierBuilder::new().is_identifiers_present(text)
}

/// Check if text contains PII (personally identifiable information)
#[must_use]
pub fn is_pii_present(text: &str) -> bool {
    IdentifierBuilder::new().is_pii_present(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_detect_identifier() {
        assert_eq!(
            detect_identifier("user@example.com"),
            Some(IdentifierType::Email)
        );
        assert_eq!(
            detect_identifier("192.168.1.1"),
            Some(IdentifierType::IpAddress)
        );
    }

    #[test]
    fn test_is_pii_present() {
        assert!(is_pii_present("Contact: user@example.com"));
        assert!(!is_pii_present("Just random text"));
    }
}
