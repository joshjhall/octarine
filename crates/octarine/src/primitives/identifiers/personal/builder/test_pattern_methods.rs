//! Test pattern detection methods for PersonalIdentifierBuilder

use super::super::detection;
use super::super::validation;
use super::core::PersonalIdentifierBuilder;

impl PersonalIdentifierBuilder {
    /// Check if email is a known test/sample pattern
    #[must_use]
    pub fn is_test_email(&self, email: &str) -> bool {
        detection::is_test_email(email)
    }

    /// Check if phone number is a known test/sample pattern
    #[must_use]
    pub fn is_test_phone(&self, phone: &str) -> bool {
        detection::is_test_phone(phone)
    }

    /// Check if birthdate is a known test/sample pattern
    #[must_use]
    pub fn is_test_birthdate(&self, date: &str) -> bool {
        validation::is_test_birthdate(date)
    }
}
