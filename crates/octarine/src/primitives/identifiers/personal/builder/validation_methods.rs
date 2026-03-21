//! Validation methods for PersonalIdentifierBuilder

use super::super::super::types::PhoneRegion;
use crate::primitives::Problem;

use super::super::validation;
use super::core::PersonalIdentifierBuilder;

impl PersonalIdentifierBuilder {
    /// Validate email format (returns Result)
    pub fn validate_email(&self, email: &str) -> Result<(), Problem> {
        validation::validate_email(email)
    }

    /// Validate phone number format (returns Result with region)
    pub fn validate_phone(&self, phone: &str) -> Result<PhoneRegion, Problem> {
        validation::validate_phone(phone)
    }

    /// Validate username format (returns Result)
    pub fn validate_username(&self, username: &str) -> Result<(), Problem> {
        validation::validate_username(username)
    }

    /// Validate birthdate format (returns Result)
    pub fn validate_birthdate(&self, date: &str) -> Result<(), Problem> {
        validation::validate_birthdate(date)
    }

    /// Validate personal name format (returns Result)
    pub fn validate_name(&self, name: &str) -> Result<(), Problem> {
        validation::validate_name(name)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_email() {
        let builder = PersonalIdentifierBuilder::new();
        assert!(builder.validate_email("user@example.com").is_ok());
        assert!(builder.validate_email("invalid").is_err());
    }

    #[test]
    fn test_validate_phone() {
        let builder = PersonalIdentifierBuilder::new();
        assert!(builder.validate_phone("+14155552671").is_ok());
        assert!(builder.validate_phone("123").is_err());
    }
}
