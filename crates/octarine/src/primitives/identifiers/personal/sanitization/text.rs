//! Text redaction (find and replace in text)
//!
//! Functions for redacting personal identifiers within text content.

use super::super::detection;
use super::super::redaction::TextRedactionPolicy;
use std::borrow::Cow;

use super::birthdate::redact_birthdate_with_strategy;
use super::email::redact_email_with_strategy;
use super::name::redact_name_with_strategy;
use super::phone::redact_phone_with_strategy;

// ============================================================================
// Public API
// ============================================================================

/// Redact all email addresses in text using generic redaction policy
///
/// Maps the policy to appropriate email strategy:
/// - `Partial` → `ShowFirst` (u***@example.com)
/// - `Complete` → `Token` ([EMAIL])
/// - `Anonymous` → `Anonymous` ([REDACTED])
/// - `None` → No redaction
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no emails found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{TextRedactionPolicy, redact_emails_in_text};
///
/// let text = "Contact: user@example.com";
/// assert_eq!(
///     redact_emails_in_text(text, TextRedactionPolicy::Complete),
///     "Contact: [EMAIL]"
/// );
/// ```
#[must_use]
pub fn redact_emails_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let matches = detection::detect_emails_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let email_strategy = policy.to_email_strategy();
    let mut result = text.to_string();
    // Process in reverse to maintain correct positions
    for m in matches.iter().rev() {
        let email = &text[m.start..m.end];
        let redacted = redact_email_with_strategy(email, email_strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all phone numbers in text using generic redaction policy
///
/// Maps the policy to appropriate phone strategy:
/// - `Partial` → `ShowLastFour` (***-***-4567, PCI-DSS compliant)
/// - `Complete` → `Token` ([PHONE])
/// - `Anonymous` → `Anonymous` ([REDACTED])
/// - `None` → No redaction
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no phones found, owned if replacements made.
#[must_use]
pub fn redact_phones_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let matches = detection::detect_phones_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let phone_strategy = policy.to_phone_strategy();
    let mut result = text.to_string();
    // Process in reverse to maintain correct positions
    for m in matches.iter().rev() {
        let phone = &text[m.start..m.end];
        let redacted = redact_phone_with_strategy(phone, phone_strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all personal names in text using generic redaction policy
///
/// Maps the policy to appropriate name strategy:
/// - `Partial` → `ShowInitials` (J. S.)
/// - `Complete` → `Token` ([NAME])
/// - `Anonymous` → `Anonymous` ([REDACTED])
/// - `None` → No redaction
///
/// # Security Note
///
/// Name detection is heuristic-based with high false positive rate.
/// Consider context validation for production systems.
#[must_use]
pub fn redact_names_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let matches = detection::detect_names_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let name_strategy = policy.to_name_strategy();
    let mut result = text.to_string();
    // Process in reverse to maintain correct positions
    for m in matches.iter().rev() {
        let name = &text[m.start..m.end];
        let redacted = redact_name_with_strategy(name, name_strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all birthdates in text using generic redaction policy
///
/// Maps the policy to appropriate birthdate strategy:
/// - `Partial` → `ShowYear` (****-**-** (1990))
/// - `Complete` → `Token` ([DATE])
/// - `Anonymous` → `Anonymous` ([REDACTED])
/// - `None` → No redaction
#[must_use]
pub fn redact_birthdates_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let matches = detection::detect_birthdates_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let birthdate_strategy = policy.to_birthdate_strategy();
    let mut result = text.to_string();
    // Process in reverse to maintain correct positions
    for m in matches.iter().rev() {
        let birthdate = &text[m.start..m.end];
        let redacted = redact_birthdate_with_strategy(birthdate, birthdate_strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all personal identifiers in text using generic redaction policy
///
/// Comprehensive redaction for emails, phones, names, and birthdates using
/// consistent policy mappings:
/// - `Partial` → ShowFirst (email), ShowLastFour (phone), ShowInitials (name), ShowYear (birthdate)
/// - `Complete` → Type-specific tokens ([EMAIL], [PHONE], [NAME], [DATE])
/// - `Anonymous` → Generic [REDACTED] for all types
/// - `None` → No redaction
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{TextRedactionPolicy, redact_all_in_text};
///
/// let text = "Contact John Smith at user@example.com or +1-555-123-4567";
/// let result = redact_all_in_text(text, TextRedactionPolicy::Complete);
/// // Result: "Contact [NAME] at [EMAIL] or [PHONE]"
/// ```
#[must_use]
pub fn redact_all_in_text(text: &str, policy: TextRedactionPolicy) -> String {
    let result = redact_emails_in_text(text, policy);
    let result = redact_phones_in_text(&result, policy);
    let result = redact_names_in_text(&result, policy);
    let result = redact_birthdates_in_text(&result, policy);

    result.into_owned()
}

// ============================================================================
// Strategy-based text redaction (for observe/pii module)
// ============================================================================

use super::super::redaction::{EmailRedactionStrategy, PhoneRedactionStrategy};

/// Redact all email addresses in text using a specific strategy
///
/// Unlike `redact_emails_in_text` which takes a generic policy, this function
/// takes a domain-specific strategy for fine-grained control.
#[must_use]
pub fn redact_emails_in_text_with_strategy(
    text: &str,
    strategy: EmailRedactionStrategy,
) -> Cow<'_, str> {
    if matches!(strategy, EmailRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_emails_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let email = &text[m.start..m.end];
        let redacted = redact_email_with_strategy(email, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all phone numbers in text using a specific strategy
///
/// Unlike `redact_phones_in_text` which takes a generic policy, this function
/// takes a domain-specific strategy for fine-grained control.
#[must_use]
pub fn redact_phones_in_text_with_strategy(
    text: &str,
    strategy: PhoneRedactionStrategy,
) -> Cow<'_, str> {
    if matches!(strategy, PhoneRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_phones_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let phone = &text[m.start..m.end];
        let redacted = redact_phone_with_strategy(phone, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_emails_in_text() {
        let text = "Contact: user@example.com";
        let result = redact_emails_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[EMAIL]"));
        assert!(!result.contains("user@example.com"));
    }

    #[test]
    fn test_redact_emails_multiple() {
        let text = "Emails: user@example.com, admin@company.org";
        let result = redact_emails_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result.matches("[EMAIL]").count(), 2);
    }

    #[test]
    fn test_redact_phones_in_text() {
        let text = "Call +1-555-123-4567";
        let result = redact_phones_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[PHONE]"));
    }

    #[test]
    fn test_redact_names_in_text() {
        let text = "Contact John Smith for details";
        let result = redact_names_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[NAME]"));
    }

    #[test]
    fn test_redact_birthdates_in_text() {
        let text = "Born on 1990-05-15";
        let result = redact_birthdates_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[DATE]"));
    }

    #[test]
    fn test_redact_all_in_text() {
        let text = "Contact John Smith at user@example.com or +1-555-123-4567. Born: 1990-05-15";
        let result = redact_all_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[EMAIL]"));
        assert!(result.contains("[PHONE]"));
        assert!(result.contains("[NAME]"));
        assert!(result.contains("[DATE]"));
    }

    #[test]
    fn test_no_redaction_in_clean_text() {
        let text = "This text contains no personal identifiers";
        let result = redact_all_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_cow_optimization() {
        // Clean text should return borrowed
        let text = "Clean text";
        let result = redact_emails_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "Email: user@example.com";
        let result = redact_emails_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Owned(_)));
    }
}
