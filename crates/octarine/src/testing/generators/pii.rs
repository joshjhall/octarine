//! PII Data Generators
//!
//! Generators for fake PII data used in testing redaction and detection.
//! All generated data is fake and safe for testing.

use proptest::prelude::*;

// ============================================================================
// SSN Generators
// ============================================================================

/// Generate fake Social Security Numbers
///
/// Produces SSNs in various formats:
/// - `123-45-6789`
/// - `123 45 6789`
/// - `123456789`
///
/// # Note
///
/// All generated SSNs are fake and use area numbers that are invalid
/// or reserved for testing (e.g., 000, 666, 900-999).
pub fn arb_ssn() -> impl Strategy<Value = String> {
    // Use test-safe area numbers (987 is common for testing)
    let area = prop_oneof![Just("987"), Just("900"), Just("999"),];

    let group = (1..=99u32).prop_map(|n| format!("{:02}", n));
    let serial = (1..=9999u32).prop_map(|n| format!("{:04}", n));

    (area, group, serial).prop_flat_map(|(a, g, s)| {
        prop_oneof![
            Just(format!("{}-{}-{}", a, g, s)),
            Just(format!("{} {} {}", a, g, s)),
            Just(format!("{}{}{}", a, g, s)),
        ]
    })
}

/// Generate SSN-like strings that should NOT match as SSNs
///
/// Useful for testing false positive rates.
pub fn arb_non_ssn() -> impl Strategy<Value = String> {
    prop_oneof![
        // Too short
        Just("123-45-678".to_string()),
        // Too long
        Just("123-45-67890".to_string()),
        // All zeros (invalid)
        Just("000-00-0000".to_string()),
        // Phone number format
        Just("(123) 456-7890".to_string()),
        // Random numbers
        (100000000u64..999999999u64).prop_map(|n| n.to_string()),
    ]
}

// ============================================================================
// Credit Card Generators
// ============================================================================

/// Generate fake credit card numbers that pass Luhn check
///
/// Uses test card number prefixes that are reserved for testing.
pub fn arb_credit_card() -> impl Strategy<Value = String> {
    prop_oneof![
        // Visa test cards
        Just("4111111111111111".to_string()),
        Just("4012888888881881".to_string()),
        // Mastercard test cards
        Just("5555555555554444".to_string()),
        Just("5105105105105100".to_string()),
        // Amex test cards
        Just("378282246310005".to_string()),
        Just("371449635398431".to_string()),
        // Discover test cards
        Just("6011111111111117".to_string()),
        // With separators
        Just("4111-1111-1111-1111".to_string()),
        Just("4111 1111 1111 1111".to_string()),
    ]
}

/// Generate credit card-like strings that should NOT match
pub fn arb_non_credit_card() -> impl Strategy<Value = String> {
    prop_oneof![
        // Wrong length
        Just("411111111111".to_string()),
        // Fails Luhn
        Just("4111111111111112".to_string()),
        // Not a card prefix
        Just("1234567890123456".to_string()),
    ]
}

// ============================================================================
// Email Generators
// ============================================================================

/// Generate fake email addresses
pub fn arb_email() -> impl Strategy<Value = String> {
    let local_part = "[a-z][a-z0-9._-]{2,20}";
    let domain = prop_oneof![
        Just("example.com"),
        Just("test.org"),
        Just("fake.net"),
        Just("testing.io"),
    ];

    (local_part, domain).prop_map(|(local, domain)| format!("{}@{}", local, domain))
}

/// Generate invalid email-like strings
pub fn arb_invalid_email() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("notanemail".to_string()),
        Just("@nodomain.com".to_string()),
        Just("noat.com".to_string()),
        Just("spaces in@email.com".to_string()),
        Just("double@@at.com".to_string()),
    ]
}

// ============================================================================
// Phone Number Generators
// ============================================================================

/// Generate fake US phone numbers
pub fn arb_phone() -> impl Strategy<Value = String> {
    let area = (200..=999u32).prop_map(|n| format!("{}", n));
    let exchange = (200..=999u32).prop_map(|n| format!("{}", n));
    let subscriber = (1000..=9999u32).prop_map(|n| format!("{}", n));

    (area, exchange, subscriber).prop_flat_map(|(a, e, s)| {
        prop_oneof![
            Just(format!("({}) {}-{}", a, e, s)),
            Just(format!("{}-{}-{}", a, e, s)),
            Just(format!("{}.{}.{}", a, e, s)),
            Just(format!("+1{}{}{}", a, e, s)),
            Just(format!("1-{}-{}-{}", a, e, s)),
        ]
    })
}

// ============================================================================
// IP Address Generators
// ============================================================================

/// Generate IPv4 addresses
pub fn arb_ipv4() -> impl Strategy<Value = String> {
    (0..=255u8, 0..=255u8, 0..=255u8, 0..=255u8)
        .prop_map(|(a, b, c, d)| format!("{}.{}.{}.{}", a, b, c, d))
}

/// Generate private IPv4 addresses
pub fn arb_private_ipv4() -> impl Strategy<Value = String> {
    prop_oneof![
        // 10.0.0.0/8
        (0..=255u8, 0..=255u8, 0..=255u8).prop_map(|(b, c, d)| format!("10.{}.{}.{}", b, c, d)),
        // 172.16.0.0/12
        (16..=31u8, 0..=255u8, 0..=255u8).prop_map(|(b, c, d)| format!("172.{}.{}.{}", b, c, d)),
        // 192.168.0.0/16
        (0..=255u8, 0..=255u8).prop_map(|(c, d)| format!("192.168.{}.{}", c, d)),
    ]
}

// ============================================================================
// API Key / Secret Generators
// ============================================================================

/// Generate fake API key patterns
pub fn arb_api_key() -> impl Strategy<Value = String> {
    let key_chars = "[A-Za-z0-9]{32,64}";

    prop_oneof![
        // Plain key
        key_chars.prop_map(|k| k),
        // With prefix
        key_chars.prop_map(|k| format!("sk_{}", k)),
        key_chars.prop_map(|k| format!("pk_{}", k)),
        key_chars.prop_map(|k| format!("api_{}", k)),
        // AWS-style
        Just("AKIAIOSFODNN7EXAMPLE".to_string()),
        // GitHub-style
        Just("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string()),
    ]
}

/// Generate password field patterns
pub fn arb_password_field() -> impl Strategy<Value = String> {
    let password = "[A-Za-z0-9!@#$%^&*]{8,32}";

    prop_oneof![
        // JSON
        password.prop_map(|p| format!(r#""password": "{}""#, p)),
        password.prop_map(|p| format!(r#""passwd": "{}""#, p)),
        // Config file
        password.prop_map(|p| format!("password={}", p)),
        password.prop_map(|p| format!("PASSWORD={}", p)),
        // URL
        password.prop_map(|p| format!("user:{}@host", p)),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    #[test]
    fn test_ssn_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_ssn();

        for _ in 0..20 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            // Should be 9 digits with optional separators
            let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
            assert_eq!(digits.len(), 9, "SSN should have 9 digits: {}", value);
        }
    }

    #[test]
    fn test_credit_card_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_credit_card();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
            assert!(
                digits.len() >= 15 && digits.len() <= 16,
                "Card should have 15-16 digits: {}",
                value
            );
        }
    }

    #[test]
    fn test_email_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_email();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            assert!(value.contains('@'), "Email should contain @: {}", value);
            assert!(value.contains('.'), "Email should contain .: {}", value);
        }
    }

    #[test]
    fn test_phone_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_phone();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
            assert!(
                digits.len() >= 10,
                "Phone should have at least 10 digits: {}",
                value
            );
        }
    }
}
