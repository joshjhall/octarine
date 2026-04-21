//! Core PersonalIdentifierBuilder struct and constructor

use super::super::super::types::IdentifierType;

use super::super::conversion;
use super::super::detection;

// Re-export types for convenience
pub use conversion::PhoneFormatStyle;

/// Builder for personal identifier operations
///
/// Provides access to detection, validation, sanitization, and conversion
/// functions for personal identifiers (PII).
#[derive(Debug, Clone, Copy, Default)]
pub struct PersonalIdentifierBuilder;

impl PersonalIdentifierBuilder {
    /// Create a new PersonalIdentifierBuilder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Find personal identifier type from input string
    ///
    /// Returns the type of personal identifier detected, or None if not recognized.
    #[must_use]
    pub fn find(&self, value: &str) -> Option<IdentifierType> {
        detection::find_personal_identifier(value)
    }

    /// Check if value is a personal identifier
    #[must_use]
    pub fn is_personal_identifier(&self, value: &str) -> bool {
        detection::is_personal_identifier(value)
    }

    /// Detect personal identifier type (dual-API contract alias).
    ///
    /// Companion to [`Self::is_personal_identifier`]; returns the matched
    /// `IdentifierType` instead of a bool. Semantically identical to
    /// [`Self::find`] — kept for contract consistency with other domains.
    #[must_use]
    pub fn detect_personal_identifier(&self, value: &str) -> Option<IdentifierType> {
        detection::detect_personal_identifier(value)
    }

    /// Check if value is PII (any personal identifier)
    #[must_use]
    pub fn is_pii(&self, value: &str) -> bool {
        detection::is_pii(value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = PersonalIdentifierBuilder::new();
        assert!(builder.is_pii("user@example.com"));
    }
}
