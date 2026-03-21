//! Conversion methods for PersonalIdentifierBuilder

use crate::primitives::Problem;

use super::super::conversion;
use super::core::{PersonalIdentifierBuilder, PhoneFormatStyle};

impl PersonalIdentifierBuilder {
    /// Normalize phone to E.164 format (+15551234567)
    pub fn normalize_phone_e164(
        &self,
        phone: &str,
        default_country: &str,
    ) -> Result<String, Problem> {
        conversion::normalize_phone_e164(phone, default_country)
    }

    /// Format phone for display
    #[must_use]
    #[allow(clippy::wrong_self_convention)] // Builder pattern uses &self consistently
    pub fn to_phone_display(&self, phone: &str, style: PhoneFormatStyle) -> String {
        conversion::to_phone_display(phone, style)
    }

    /// Normalize email address (lowercase, trim)
    pub fn normalize_email(&self, email: &str) -> Result<String, Problem> {
        conversion::normalize_email(email)
    }

    /// Calculate age from birthdate
    pub fn calculate_age(&self, birthdate: &str) -> Result<u32, Problem> {
        conversion::calculate_age(birthdate)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_normalize_phone_e164() {
        let builder = PersonalIdentifierBuilder::new();
        let result = builder
            .normalize_phone_e164("5551234567", "US")
            .expect("should normalize phone");
        assert_eq!(result, "+15551234567");
    }

    #[test]
    fn test_to_phone_display() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder.to_phone_display("5551234567", PhoneFormatStyle::National),
            "(555) 123-4567"
        );
    }

    #[test]
    fn test_normalize_email() {
        let builder = PersonalIdentifierBuilder::new();
        let result = builder
            .normalize_email("User@Example.COM")
            .expect("should normalize email");
        assert_eq!(result, "user@example.com");

        // Gmail special handling
        let result = builder
            .normalize_email("user.name+tag@gmail.com")
            .expect("should normalize gmail");
        assert_eq!(result, "username@gmail.com");
    }
}
