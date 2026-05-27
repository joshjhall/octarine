//! Personal identifier shortcuts (email, phone, name, birthdate, username).
//!
//! Convenience functions over [`PersonalBuilder`](super::super::PersonalBuilder).

use crate::observe::Problem;
use crate::primitives::identifiers::{
    AgeRedactionStrategy, BirthdateRedactionStrategy, EmailRedactionStrategy,
    NameRedactionStrategy, NrpRedactionStrategy, PersonalTextPolicy, PhoneRedactionStrategy,
    UsernameRedactionStrategy,
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

// ============================================================
// AGE SHORTCUTS (HIPAA Safe Harbor §164.514)
// ============================================================

/// Check if value contains an age expression
#[must_use]
pub fn is_age(value: &str) -> bool {
    PersonalBuilder::new().is_age(value)
}

/// HIPAA Safe Harbor §164.514(b)(2)(i)(B): true when input contains an
/// age > 89.
#[must_use]
pub fn is_age_over_89(value: &str) -> bool {
    PersonalBuilder::new().is_age_over_89(value)
}

/// Extract the first numeric age value from text.
#[must_use]
pub fn find_age_value(text: &str) -> Option<u8> {
    PersonalBuilder::new().find_age_value(text)
}

/// Validate an age expression or bare numeric age
pub fn validate_age(value: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_age(value)
}

/// Find all age expressions in text
#[must_use]
pub fn find_ages(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_ages_in_text(text)
}

/// Redact an age value (default: HIPAA-friendly 10-year bucket)
#[must_use]
pub fn redact_age(value: &str) -> String {
    PersonalBuilder::new().redact_age_with_strategy(value, AgeRedactionStrategy::Bucket10Year)
}

// ============================================================
// NATIONALITY SHORTCUTS (GDPR Article 9)
// ============================================================

/// Check if value contains a nationality reference
#[must_use]
pub fn is_nationality(value: &str) -> bool {
    PersonalBuilder::new().is_nationality(value)
}

/// Validate that input contains a nationality reference
pub fn validate_nationality(value: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_nationality(value)
}

/// Find all nationality references in text
#[must_use]
pub fn find_nationalities(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_nationalities_in_text(text)
}

/// Redact a nationality value (default: token replacement)
#[must_use]
pub fn redact_nationality(value: &str) -> String {
    PersonalBuilder::new().redact_nationality_with_strategy(value, NrpRedactionStrategy::Token)
}

// ============================================================
// RELIGION SHORTCUTS (GDPR Article 9)
// ============================================================

/// Check if value contains a religion reference
#[must_use]
pub fn is_religion(value: &str) -> bool {
    PersonalBuilder::new().is_religion(value)
}

/// Validate that input contains a religion reference
pub fn validate_religion(value: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_religion(value)
}

/// Find all religion references in text
#[must_use]
pub fn find_religions(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_religions_in_text(text)
}

/// Redact a religion value (default: token replacement)
#[must_use]
pub fn redact_religion(value: &str) -> String {
    PersonalBuilder::new().redact_religion_with_strategy(value, NrpRedactionStrategy::Token)
}

// ============================================================
// POLITICAL AFFILIATION SHORTCUTS (GDPR Article 9)
// ============================================================

/// Check if value contains a political-affiliation reference
#[must_use]
pub fn is_political_affiliation(value: &str) -> bool {
    PersonalBuilder::new().is_political_affiliation(value)
}

/// Validate that input contains a political-affiliation reference
pub fn validate_political_affiliation(value: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_political_affiliation(value)
}

/// Find all political-affiliation references in text
#[must_use]
pub fn find_political_affiliations(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_political_affiliations_in_text(text)
}

/// Redact a political-affiliation value (default: token replacement)
#[must_use]
pub fn redact_political_affiliation(value: &str) -> String {
    PersonalBuilder::new()
        .redact_political_affiliation_with_strategy(value, NrpRedactionStrategy::Token)
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

    // ── Age shortcuts ────────────────────────────────────────────────

    #[test]
    fn test_age_shortcuts() {
        assert!(is_age("the 42-year-old patient"));
        assert!(!is_age("no age here"));
        assert_eq!(find_age_value("the 42-year-old patient"), Some(42));
        assert_eq!(find_age_value("age 65"), Some(65));
        assert_eq!(find_age_value("in her eighties"), Some(80));
        assert!(validate_age("42").is_ok());
        assert!(validate_age("not an age").is_err());
        assert!(!find_ages("the 42-year-old patient").is_empty());
        // Default redaction is 10-year bucket
        assert_eq!(redact_age("42"), "40-49");
    }

    #[test]
    fn test_is_age_over_89_shortcut() {
        assert!(is_age_over_89("95"));
        assert!(is_age_over_89("the 92-year-old patient"));
        assert!(is_age_over_89("in her nineties"));
        assert!(!is_age_over_89("42"));
        assert!(!is_age_over_89("not a number"));
    }

    // ── NRP shortcuts (GDPR Article 9) ───────────────────────────────

    #[test]
    fn test_nationality_shortcuts() {
        assert!(is_nationality("He is American"));
        assert!(!is_nationality("the weather is nice"));
        assert!(validate_nationality("American").is_ok());
        assert!(validate_nationality("not a real demonym").is_err());
        assert!(!find_nationalities("She is Japanese").is_empty());
        assert_eq!(redact_nationality("American"), "[NATIONALITY]");
    }

    #[test]
    fn test_religion_shortcuts() {
        assert!(is_religion("Catholic priest"));
        assert!(!is_religion("the database query"));
        assert!(validate_religion("Buddhist").is_ok());
        assert!(validate_religion("not a religion").is_err());
        assert!(!find_religions("she is Hindu").is_empty());
        assert_eq!(redact_religion("Catholic"), "[RELIGION]");
    }

    #[test]
    fn test_political_affiliation_shortcuts() {
        assert!(is_political_affiliation("Democrat senator"));
        assert!(!is_political_affiliation("the meeting is at 3pm"));
        assert!(validate_political_affiliation("Republican").is_ok());
        assert!(validate_political_affiliation("apolitical").is_err());
        assert!(!find_political_affiliations("Labour party").is_empty());
        assert_eq!(
            redact_political_affiliation("Democrat"),
            "[POLITICAL_AFFILIATION]"
        );
    }
}
