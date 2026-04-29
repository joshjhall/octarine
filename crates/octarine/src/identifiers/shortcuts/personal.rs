//! Personal identifier shortcuts (email, phone, name, birthdate, username).
//!
//! Convenience functions over [`PersonalBuilder`](super::super::PersonalBuilder).

use crate::observe::Problem;
use crate::primitives::identifiers::{
    BirthdateRedactionStrategy, EmailRedactionStrategy, NameRedactionStrategy, PersonalTextPolicy,
    PhoneRedactionStrategy, UsernameRedactionStrategy,
};

use super::super::PersonalBuilder;
use super::super::types::{IdentifierMatch, PhoneRegion};

// ============================================================
// EMAIL SHORTCUTS
// ============================================================

/// Check if value is an email address
#[must_use]
pub fn is_email(value: &str) -> bool {
    PersonalBuilder::new().is_email(value)
}

/// Validate an email address (returns Result)
pub fn validate_email(email: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_email(email)
}

/// Find all emails in text
#[must_use]
pub fn find_emails(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_emails_in_text(text)
}

/// Redact an email address (shows first character and domain)
#[must_use]
pub fn redact_email(email: &str) -> String {
    PersonalBuilder::new().redact_email_with_strategy(email, EmailRedactionStrategy::ShowFirst)
}

/// Redact all emails in text (complete redaction)
#[must_use]
pub fn redact_emails(text: &str) -> String {
    PersonalBuilder::new().redact_emails_in_text_with_policy(text, PersonalTextPolicy::Complete)
}

// ============================================================
// PHONE SHORTCUTS
// ============================================================

/// Check if value is a phone number
#[must_use]
pub fn is_phone(value: &str) -> bool {
    PersonalBuilder::new().is_phone_number(value)
}

/// Validate a phone number (returns detected region)
pub fn validate_phone(phone: &str) -> Result<PhoneRegion, Problem> {
    PersonalBuilder::new().validate_phone(phone)
}

/// Find all phone numbers in text
#[must_use]
pub fn find_phones(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_phones_in_text(text)
}

/// Redact a phone number (shows last 4 digits)
#[must_use]
pub fn redact_phone(phone: &str) -> String {
    PersonalBuilder::new().redact_phone_with_strategy(phone, PhoneRedactionStrategy::ShowLastFour)
}

/// Redact all phone numbers in text (complete redaction)
#[must_use]
pub fn redact_phones(text: &str) -> String {
    PersonalBuilder::new().redact_phones_in_text_with_policy(text, PersonalTextPolicy::Complete)
}

// ============================================================
// NAME SHORTCUTS
// ============================================================

/// Check if value is a person's name
#[must_use]
pub fn is_name(value: &str) -> bool {
    PersonalBuilder::new().is_name(value)
}

/// Validate a person's name
pub fn validate_name(name: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_name(name)
}

/// Find all names in text
#[must_use]
pub fn find_names(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_names_in_text(text)
}

/// Redact a name (shows initials only)
#[must_use]
pub fn redact_name(name: &str) -> String {
    PersonalBuilder::new().redact_name_with_strategy(name, NameRedactionStrategy::ShowInitials)
}

// ============================================================
// BIRTHDATE SHORTCUTS
// ============================================================

/// Check if value is a birthdate
#[must_use]
pub fn is_birthdate(value: &str) -> bool {
    PersonalBuilder::new().is_birthdate(value)
}

/// Validate a birthdate
pub fn validate_birthdate(date: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_birthdate(date)
}

/// Find all birthdates in text
#[must_use]
pub fn find_birthdates(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_birthdates_in_text(text)
}

/// Redact a birthdate (shows year only)
#[must_use]
pub fn redact_birthdate(date: &str) -> String {
    PersonalBuilder::new()
        .redact_birthdate_with_strategy(date, BirthdateRedactionStrategy::ShowYear)
}

// ============================================================
// USERNAME SHORTCUTS
// ============================================================

/// Check if value is a username
#[must_use]
pub fn is_username(value: &str) -> bool {
    PersonalBuilder::new().is_username(value)
}

/// Validate a username
pub fn validate_username(username: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_username(username)
}

/// Redact a username (replaces with token)
#[must_use]
pub fn redact_username(username: &str) -> String {
    PersonalBuilder::new().redact_username_with_strategy(username, UsernameRedactionStrategy::Token)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_email_shortcuts() {
        assert!(is_email("user@example.com"));
        assert!(!is_email("not-an-email"));
        assert!(validate_email("user@example.com").is_ok());
    }

    #[test]
    fn test_redaction_shortcuts() {
        let redacted = redact_email("user@example.com");
        assert!(!redacted.contains("user@example.com"));
    }

    #[test]
    fn test_validate_phone_shortcut() {
        assert!(validate_phone("+14155551234").is_ok());
        assert!(validate_phone("not-a-phone").is_err());
    }

    #[test]
    fn test_name_shortcuts() {
        assert!(is_name("John Smith"));
        assert!(!is_name("x"));
        assert!(validate_name("John Smith").is_ok());
        assert!(!find_names("Contact John Smith for details").is_empty());
        let redacted = redact_name("John Smith");
        assert!(!redacted.contains("John Smith"));
    }

    #[test]
    fn test_birthdate_shortcuts() {
        assert!(is_birthdate("1990-01-15"));
        assert!(!is_birthdate("not-a-date"));
        assert!(validate_birthdate("1990-01-15").is_ok());
        assert!(validate_birthdate("not-a-date").is_err());
        let redacted = redact_birthdate("1990-01-15");
        assert!(!redacted.contains("1990-01-15"));
    }

    #[test]
    fn test_username_shortcuts() {
        assert!(is_username("john_doe"));
        assert!(!is_username("@"));
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("@").is_err());
        let redacted = redact_username("john_doe");
        assert!(!redacted.contains("john_doe"));
    }
}
