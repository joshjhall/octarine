//! Detection methods for PersonalIdentifierBuilder

use super::super::super::types::{IdentifierMatch, IdentifierType, PhoneRegion};

use super::super::detection;
use super::core::PersonalIdentifierBuilder;

impl PersonalIdentifierBuilder {
    /// Check if value is an email address
    #[must_use]
    pub fn is_email(&self, value: &str) -> bool {
        detection::is_email(value)
    }

    /// Check if value is a phone number
    #[must_use]
    pub fn is_phone_number(&self, value: &str) -> bool {
        detection::is_phone_number(value)
    }

    /// Detect all email addresses in text
    #[must_use]
    pub fn detect_emails_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_emails_in_text(text)
    }

    /// Detect all phone numbers in text
    #[must_use]
    pub fn detect_phones_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_phones_in_text(text)
    }

    /// Detect all personal names in text
    #[must_use]
    pub fn detect_names_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_names_in_text(text)
    }

    /// Detect all birthdates in text
    #[must_use]
    pub fn detect_birthdates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_birthdates_in_text(text)
    }

    /// Detect all personal identifiers in text
    #[must_use]
    pub fn detect_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_all_pii_in_text(text)
    }

    /// Check if personal identifiers are present in text
    #[must_use]
    pub fn is_pii_present(&self, text: &str) -> bool {
        detection::is_pii_present(text)
    }

    /// Check if value is a personal name
    #[must_use]
    pub fn is_name(&self, value: &str) -> bool {
        detection::is_name(value)
    }

    /// Check if value is a birthdate
    #[must_use]
    pub fn is_birthdate(&self, value: &str) -> bool {
        detection::is_birthdate(value)
    }

    /// Check if value is a username
    #[must_use]
    pub fn is_username(&self, value: &str) -> bool {
        detection::is_username(value)
    }

    /// Detect all usernames in text
    #[must_use]
    pub fn detect_usernames_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_usernames_in_text(text)
    }

    /// Find phone number region from phone number
    #[must_use]
    pub fn find_phone_region(&self, phone: &str) -> Option<PhoneRegion> {
        detection::find_phone_region(phone)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_find_email() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder.find("user@example.com"),
            Some(IdentifierType::Email)
        );
    }

    #[test]
    fn test_find_phone() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder.find("+15551234567"),
            Some(IdentifierType::PhoneNumber)
        );
    }

    #[test]
    fn test_is_email() {
        let builder = PersonalIdentifierBuilder::new();
        assert!(builder.is_email("user@example.com"));
        assert!(!builder.is_email("not-an-email"));
    }

    #[test]
    fn test_is_phone_number() {
        let builder = PersonalIdentifierBuilder::new();
        assert!(builder.is_phone_number("+15551234567"));
        assert!(!builder.is_phone_number("not-a-phone"));
    }

    #[test]
    fn test_detect_emails_in_text() {
        let builder = PersonalIdentifierBuilder::new();
        let matches = builder.detect_emails_in_text("Contact: user@example.com or admin@test.org");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_detect_phones_in_text() {
        let builder = PersonalIdentifierBuilder::new();
        let matches = builder.detect_phones_in_text("Call +1-555-123-4567 or (555) 234-5678");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_detect_names_in_text() {
        let builder = PersonalIdentifierBuilder::new();
        let matches = builder.detect_names_in_text("Contact John Smith");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_birthdates_in_text() {
        let builder = PersonalIdentifierBuilder::new();
        let matches = builder.detect_birthdates_in_text("Born on 1990-05-15");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_find_phone_region() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder.find_phone_region("+14155551234"),
            Some(PhoneRegion::NorthAmerica)
        );
        assert_eq!(
            builder.find_phone_region("+441234567890"),
            Some(PhoneRegion::Uk)
        );
        assert_eq!(
            builder.find_phone_region("+491234567890"),
            Some(PhoneRegion::Germany)
        );
    }
}
