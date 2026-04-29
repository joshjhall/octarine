//! Email marketing API key detection (Mailchimp, Mailgun, Resend, Brevo).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Mailchimp API key
///
/// Mailchimp keys are 32 hex characters followed by a datacenter suffix (-us1 to -us20)
#[must_use]
pub fn is_mailchimp_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_MAILCHIMP.is_match(trimmed)
}

/// Check if value is a Mailgun API key
///
/// Mailgun keys start with "key-" followed by 32 alphanumeric characters
#[must_use]
pub fn is_mailgun_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_MAILGUN.is_match(trimmed)
}

/// Check if value is a Resend API key
///
/// Resend keys start with "re_" followed by 32+ alphanumeric characters
#[must_use]
pub fn is_resend_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_RESEND.is_match(trimmed)
}

/// Check if value is a Brevo (Sendinblue) API key
///
/// Brevo keys start with "xkeysib-" followed by 64 hex characters, a dash,
/// and 16 alphanumeric characters
#[must_use]
pub fn is_brevo_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_BREVO.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_mailchimp_key() {
        // Valid Mailchimp API key (32 hex chars + datacenter suffix)
        // Constructed at runtime to avoid triggering secret scanners
        let key1 = format!("{}{}-us6", "abcdef1234567890", "abcdef1234567890");
        assert!(is_mailchimp_key(&key1));
        let key2 = format!("{}{}-us1", "0123456789abcdef", "0123456789abcdef");
        assert!(is_mailchimp_key(&key2));
        let key3 = format!("{}{}-us20", "abcdef1234567890", "abcdef1234567890");
        assert!(is_mailchimp_key(&key3));
        // Invalid: wrong suffix
        let bad_suffix = format!("{}{}-eu1", "abcdef1234567890", "abcdef1234567890");
        assert!(!is_mailchimp_key(&bad_suffix));
        // Invalid: too short hex
        assert!(!is_mailchimp_key("abcdef1234567890-us6"));
        // Invalid: non-hex chars
        assert!(!is_mailchimp_key("ghijkl1234567890ghijkl1234567890-us6"));
    }

    #[test]
    fn test_is_mailgun_key() {
        // Valid Mailgun API key (key- + 32 alnum chars)
        assert!(is_mailgun_key(&format!(
            "key-{}",
            "ABCDEFghijklmnopqrstuv1234567890"
        )));
        // Invalid: wrong prefix
        assert!(!is_mailgun_key(&format!(
            "ky-{}",
            "ABCDEFghijklmnopqrstuv1234567890"
        )));
        // Invalid: too short
        assert!(!is_mailgun_key("key-short"));
    }

    #[test]
    fn test_is_resend_key() {
        // Valid Resend API key (re_ + 32+ alnum chars)
        assert!(is_resend_key(&format!(
            "re_{}",
            "ABCDEFghijklmnopqrstuv1234567890ab"
        )));
        // Invalid: wrong prefix
        assert!(!is_resend_key(&format!(
            "rx_{}",
            "ABCDEFghijklmnopqrstuv1234567890ab"
        )));
        // Invalid: too short
        assert!(!is_resend_key("re_short"));
    }

    #[test]
    fn test_is_brevo_key() {
        // Valid Brevo API key (xkeysib- + 64 hex + - + 16 alnum)
        let hex64 = "a".repeat(64);
        let alnum16 = "B".repeat(16);
        assert!(is_brevo_key(&format!("xkeysib-{hex64}-{alnum16}")));
        // Invalid: wrong prefix
        assert!(!is_brevo_key(&format!("xkeysic-{hex64}-{alnum16}")));
        // Invalid: hex too short
        let hex32 = "a".repeat(32);
        assert!(!is_brevo_key(&format!("xkeysib-{hex32}-{alnum16}")));
    }
}
