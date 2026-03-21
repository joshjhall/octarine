//! Sanitization methods for PersonalIdentifierBuilder

use crate::primitives::Problem;

use super::super::redaction::{
    BirthdateRedactionStrategy, EmailRedactionStrategy, NameRedactionStrategy,
    PhoneRedactionStrategy, TextRedactionPolicy, UsernameRedactionStrategy,
};
use super::super::sanitization;
use super::core::PersonalIdentifierBuilder;

impl PersonalIdentifierBuilder {
    /// Redact email with explicit redaction strategy
    #[must_use]
    pub fn redact_email_with_strategy(
        &self,
        email: &str,
        strategy: EmailRedactionStrategy,
    ) -> String {
        sanitization::redact_email_with_strategy(email, strategy)
    }

    /// Redact phone with explicit redaction strategy
    #[must_use]
    pub fn redact_phone_with_strategy(
        &self,
        phone: &str,
        strategy: PhoneRedactionStrategy,
    ) -> String {
        sanitization::redact_phone_with_strategy(phone, strategy)
    }

    /// Redact username with explicit redaction strategy
    #[must_use]
    pub fn redact_username_with_strategy(
        &self,
        username: &str,
        strategy: UsernameRedactionStrategy,
    ) -> String {
        sanitization::redact_username_with_strategy(username, strategy)
    }

    /// Redact name with explicit redaction strategy
    #[must_use]
    pub fn redact_name_with_strategy(&self, name: &str, strategy: NameRedactionStrategy) -> String {
        sanitization::redact_name_with_strategy(name, strategy)
    }

    /// Redact birthdate with explicit redaction strategy
    #[must_use]
    pub fn redact_birthdate_with_strategy(
        &self,
        date: &str,
        strategy: BirthdateRedactionStrategy,
    ) -> String {
        sanitization::redact_birthdate_with_strategy(date, strategy)
    }

    /// Sanitize email address (validate and normalize to lowercase)
    pub fn sanitize_email(&self, email: &str) -> Result<String, Problem> {
        sanitization::sanitize_email(email)
    }

    /// Sanitize phone number (validate and convert to E.164 format)
    pub fn sanitize_phone(&self, phone: &str) -> Result<String, Problem> {
        sanitization::sanitize_phone(phone)
    }

    /// Sanitize name (validate and normalize to title case)
    pub fn sanitize_name(&self, name: &str) -> Result<String, Problem> {
        sanitization::sanitize_name(name)
    }

    /// Sanitize birthdate (validate and convert to ISO 8601 format)
    pub fn sanitize_birthdate(&self, date: &str) -> Result<String, Problem> {
        sanitization::sanitize_birthdate(date)
    }

    /// Redact all emails in text with explicit text policy
    #[must_use]
    pub fn redact_emails_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_emails_in_text(text, policy).into_owned()
    }

    /// Redact all emails in text with explicit email redaction strategy
    #[must_use]
    pub fn redact_emails_in_text_with_strategy(
        &self,
        text: &str,
        strategy: EmailRedactionStrategy,
    ) -> String {
        sanitization::redact_emails_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Redact all phones in text with explicit text policy
    #[must_use]
    pub fn redact_phones_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_phones_in_text(text, policy).into_owned()
    }

    /// Redact all phones in text with explicit phone redaction strategy
    #[must_use]
    pub fn redact_phones_in_text_with_strategy(
        &self,
        text: &str,
        strategy: PhoneRedactionStrategy,
    ) -> String {
        sanitization::redact_phones_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Redact all names in text with explicit text policy
    #[must_use]
    pub fn redact_names_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_names_in_text(text, policy).into_owned()
    }

    /// Redact all birthdates in text with explicit text policy
    #[must_use]
    pub fn redact_birthdates_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_birthdates_in_text(text, policy).into_owned()
    }

    /// Redact all personal identifiers in text with explicit policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_in_text(text, policy)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_email_with_strategy() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder
                .redact_email_with_strategy("user@example.com", EmailRedactionStrategy::ShowFirst),
            "u***@example.com"
        );
        assert_eq!(
            builder.redact_email_with_strategy("user@example.com", EmailRedactionStrategy::Token),
            "[EMAIL]"
        );
        assert_eq!(
            builder.redact_email_with_strategy("invalid", EmailRedactionStrategy::Token),
            "[EMAIL]"
        );
    }

    #[test]
    fn test_redact_phone_with_strategy() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder.redact_phone_with_strategy(
                "+1-555-123-4567",
                PhoneRedactionStrategy::ShowLastFour
            ),
            "***-***-4567"
        );
        assert_eq!(
            builder.redact_phone_with_strategy("123", PhoneRedactionStrategy::Token),
            "[PHONE]"
        );
    }

    #[test]
    fn test_redact_username_with_strategy() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder.redact_username_with_strategy(
                "john_doe",
                UsernameRedactionStrategy::ShowFirstAndLast
            ),
            "j******e"
        );
    }

    #[test]
    fn test_sanitize_email() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder
                .sanitize_email("User@Example.COM")
                .expect("should sanitize valid email"),
            "user@example.com"
        );
        assert!(builder.sanitize_email("invalid").is_err());
    }

    #[test]
    fn test_sanitize_phone() {
        let builder = PersonalIdentifierBuilder::new();
        let result = builder
            .sanitize_phone("(555) 123-4567")
            .expect("should sanitize valid phone");
        assert!(result.starts_with("+1"));
        assert!(builder.sanitize_phone("invalid").is_err());
    }

    #[test]
    fn test_sanitize_name() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder
                .sanitize_name("John Smith")
                .expect("should sanitize valid name"),
            "John Smith"
        );
        assert!(builder.sanitize_name("invalid").is_err());
    }

    #[test]
    fn test_sanitize_birthdate() {
        let builder = PersonalIdentifierBuilder::new();
        assert_eq!(
            builder
                .sanitize_birthdate("05/15/1990")
                .expect("should sanitize valid birthdate"),
            "1990-05-15"
        );
        assert!(builder.sanitize_birthdate("invalid").is_err());
    }

    #[test]
    fn test_redact_all_in_text_with_policy() {
        let builder = PersonalIdentifierBuilder::new();
        let text = "Email: user@example.com, Phone: +1-555-123-4567";
        let result = builder.redact_all_in_text_with_policy(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[EMAIL]"));
        assert!(result.contains("[PHONE]"));
    }
}
