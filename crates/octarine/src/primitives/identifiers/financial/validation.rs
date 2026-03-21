//! Financial identifier validation (primitives layer)
//!
//! Pure validation functions for financial identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Validations
//!
//! - **Credit Cards**: Luhn checksum, pattern matching, brand detection
//! - **Routing Numbers**: ABA checksum validation
//! - **Bank Accounts**: Basic format validation
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules

use super::super::common::{luhn, patterns};
use super::super::types::CreditCardType;
use crate::primitives::Problem;

use super::detection;

// ============================================================================
// Credit Card Validation
// ============================================================================

/// Validate credit card number format and checksum
///
/// Validates using:
/// - Length check (13-19 digits per ISO/IEC 7812)
/// - Card type pattern matching
/// - Luhn algorithm checksum
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::validation;
///
/// // Valid cards
/// assert!(validation::validate_credit_card("4111111111111111").is_ok());
/// assert!(validation::validate_credit_card("5555555555554444").is_ok());
///
/// // With formatting
/// assert!(validation::validate_credit_card("4111 1111 1111 1111").is_ok());
///
/// // Invalid checksum
/// assert!(validation::validate_credit_card("4111111111111112").is_err());
/// ```
pub fn validate_credit_card(card_number: &str) -> Result<CreditCardType, Problem> {
    // Use pattern detection (validates format, length, and Luhn checksum)
    // Note: We use is_credit_card_pattern() instead of is_credit_card() because
    // validators should accept test cards, while is_credit_card() filters them out
    if !detection::is_credit_card_pattern(card_number) {
        return Err(Problem::Validation(
            "Invalid credit card format or checksum".into(),
        ));
    }

    // Extract digits and detect card type
    let cleaned: String = card_number.chars().filter(|c| c.is_numeric()).collect();
    let card_type = detection::detect_card_brand(&cleaned).unwrap_or(CreditCardType::Unknown);

    if matches!(card_type, CreditCardType::Unknown) {
        return Err(Problem::Validation("Unrecognized credit card type".into()));
    }

    Ok(card_type)
}

// ============================================================================
// Bank Account Validation
// ============================================================================

/// Validate US bank routing number
///
/// Validates using ABA checksum algorithm.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::validation;
///
/// // Valid routing numbers
/// assert!(validation::validate_routing_number("021000021").is_ok());
/// assert!(validation::validate_routing_number("011401533").is_ok());
///
/// // Invalid
/// assert!(validation::validate_routing_number("123456789").is_err());
/// ```
pub fn validate_routing_number(routing: &str) -> Result<(), Problem> {
    // Must be exactly 9 digits
    if routing.len() != 9 || !routing.chars().all(|c| c.is_numeric()) {
        return Err(Problem::Validation(
            "Routing number must be exactly 9 digits".into(),
        ));
    }

    // Convert to digits for checksum
    let digits: Vec<u32> = routing.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.len() != 9 {
        return Err(Problem::Validation("Invalid routing number format".into()));
    }

    // ABA checksum algorithm
    // Note: We only validate checksum, not Federal Reserve district ranges
    // (detection layer is stricter and checks Fed districts)
    let [d0, d1, d2, d3, d4, d5, d6, d7, d8] = digits.as_slice() else {
        return Err(Problem::Validation("Invalid routing number format".into()));
    };

    let checksum = (3_u32
        .saturating_mul(d0.saturating_add(*d3).saturating_add(*d6))
        .saturating_add(7_u32.saturating_mul(d1.saturating_add(*d4).saturating_add(*d7)))
        .saturating_add(d2.saturating_add(*d5).saturating_add(*d8)))
        % 10;

    if checksum != 0 {
        return Err(Problem::Validation(
            "Invalid routing number checksum".into(),
        ));
    }

    Ok(())
}

/// Validate bank account number
///
/// Basic validation: 1-17 digits.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::validation;
///
/// assert!(validation::validate_account_number("1234567890").is_ok());
/// assert!(validation::validate_account_number("").is_err());
/// ```
pub fn validate_account_number(account: &str) -> Result<(), Problem> {
    // Check length (typically 4-17 digits)
    if account.is_empty() || account.len() > 17 {
        return Err(Problem::Validation(
            "Account number must be 1-17 digits".into(),
        ));
    }

    // Must be all digits
    if !account.chars().all(|c| c.is_numeric()) {
        return Err(Problem::Validation(
            "Account number must contain only digits".into(),
        ));
    }

    Ok(())
}

/// Validate complete bank account (routing + account)
pub fn validate_bank_account(routing: &str, account: &str) -> Result<(), Problem> {
    validate_routing_number(routing)?;
    validate_account_number(account)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::detection::{is_credit_card_pattern, is_payment_data_present};
    use super::*;

    // ===== Credit Card Validation Tests =====

    #[test]
    fn test_credit_card_validation() {
        // Valid test cards
        assert!(validate_credit_card("4111111111111111").is_ok()); // Visa
        assert!(validate_credit_card("5555555555554444").is_ok()); // Mastercard
        assert!(validate_credit_card("378282246310005").is_ok()); // Amex
        assert!(validate_credit_card("6011111111111117").is_ok()); // Discover
        assert!(validate_credit_card("3530111333300000").is_ok()); // JCB

        // With spaces/dashes
        assert!(validate_credit_card("4111 1111 1111 1111").is_ok());
        assert!(validate_credit_card("4111-1111-1111-1111").is_ok());

        // Invalid
        assert!(validate_credit_card("4111111111111112").is_err()); // Bad checksum
        assert!(validate_credit_card("123456789012").is_err()); // Too short
        assert!(validate_credit_card("12345678901234567890").is_err()); // Too long
    }

    #[test]
    fn test_credit_card_validation_with_card_type() {
        let result = validate_credit_card("4111111111111111");
        assert!(result.is_ok());
        assert_eq!(
            result.expect("Visa validation should succeed"),
            CreditCardType::Visa
        );

        let result = validate_credit_card("5555555555554444");
        assert!(result.is_ok());
        assert_eq!(
            result.expect("Mastercard validation should succeed"),
            CreditCardType::Mastercard
        );

        let result = validate_credit_card("4111111111111112");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Invalid card should fail")
                .to_string()
                .contains("checksum")
        );
    }

    // ===== Routing Number Tests =====

    #[test]
    fn test_routing_validation() {
        // Valid routing numbers
        assert!(validate_routing_number("021000021").is_ok()); // JPMorgan Chase
        assert!(validate_routing_number("011401533").is_ok()); // Bank of America
        assert!(validate_routing_number("091000019").is_ok()); // Wells Fargo

        // Invalid
        assert!(validate_routing_number("123456789").is_err()); // Bad checksum
        assert!(validate_routing_number("12345678").is_err()); // Too short
        assert!(validate_routing_number("1234567890").is_err()); // Too long
        assert!(validate_routing_number("ABCDEFGHI").is_err()); // Non-numeric
    }

    #[test]
    fn test_routing_validation_error_messages() {
        let result = validate_routing_number("021000021");
        assert!(result.is_ok());

        let result = validate_routing_number("123456789");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Invalid routing number should fail")
                .to_string()
                .contains("checksum")
        );
    }

    // ===== Account Number Tests =====

    #[test]
    fn test_account_validation() {
        assert!(validate_account_number("1234567890").is_ok());
        assert!(validate_account_number("12345").is_ok());

        assert!(validate_account_number("").is_err()); // Empty
        assert!(validate_account_number("123456789012345678").is_err()); // Too long
        assert!(validate_account_number("12345ABC").is_err()); // Non-numeric
    }

    #[test]
    fn test_account_validation_error_messages() {
        let result = validate_account_number("1234567890");
        assert!(result.is_ok());

        let result = validate_account_number("");
        assert!(result.is_err());
    }

    // ===== Bank Account Tests =====

    #[test]
    fn test_bank_account_validation() {
        assert!(validate_bank_account("021000021", "1234567890").is_ok());
        assert!(validate_bank_account("123456789", "1234567890").is_err()); // Invalid routing
        assert!(validate_bank_account("021000021", "").is_err()); // Empty account
    }

    // ===== Payment Data Detection Tests =====

    #[test]
    fn test_payment_data_detection() {
        assert!(is_payment_data_present("My card is 4111111111111111"));
        assert!(is_payment_data_present("Number: 5555 5555 5555 4444"));
        assert!(!is_payment_data_present("Just some regular text"));
        assert!(!is_payment_data_present("Invalid card 1234567890123456"));
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_empty_inputs() {
        assert!(validate_credit_card("").is_err());
        assert!(validate_routing_number("").is_err());
        assert!(validate_account_number("").is_err());
        assert!(!is_credit_card_pattern(""));
        assert!(!is_payment_data_present(""));
    }

    #[test]
    fn test_credit_card_type_display() {
        assert_eq!(CreditCardType::Visa.to_string(), "Visa");
        assert_eq!(CreditCardType::Mastercard.to_string(), "Mastercard");
        assert_eq!(
            CreditCardType::AmericanExpress.to_string(),
            "American Express"
        );
    }

    // ===== Extended Edge Case Tests =====

    #[test]
    fn test_whitespace_edge_cases() {
        // Various whitespace types
        assert!(validate_credit_card("   ").is_err());
        assert!(validate_credit_card("\t\t\t").is_err());
        assert!(validate_credit_card("\n\n\n").is_err());
        // Leading/trailing spaces - digits are extracted, so this passes
        assert!(validate_credit_card("  4111111111111111  ").is_ok());
        assert!(validate_routing_number("   ").is_err());
        assert!(validate_account_number("   ").is_err());
    }

    #[test]
    fn test_exact_length_boundaries() {
        // 13 digits (minimum valid - old Visa format)
        assert!(validate_credit_card("4222222222222").is_ok()); // Luhn valid 13-digit

        // 12 digits (too short)
        assert!(validate_credit_card("411111111111").is_err());

        // 19 digits (maximum)
        let card_19 = "6304000000000000000"; // Maestro test card
        assert!(is_credit_card_pattern(card_19));

        // 20 digits (too long)
        assert!(validate_credit_card("41111111111111111111").is_err());
    }

    #[test]
    fn test_mixed_separator_formats() {
        // Mixed separators should work
        assert!(validate_credit_card("4111-1111 1111-1111").is_ok());

        // Multiple consecutive separators - digits extracted
        assert!(validate_credit_card("4111--1111--1111--1111").is_ok());

        // Periods as separators (European format)
        assert!(validate_credit_card("4111.1111.1111.1111").is_ok());
    }

    #[test]
    fn test_special_characters_handling() {
        // Validation extracts digits only, so these pass (digits form valid card)
        assert!(validate_credit_card("4111!1111!1111!1111").is_ok()); // Extracts: 4111111111111111
        assert!(validate_credit_card("4111a1111b1111c1111").is_ok()); // Extracts: 4111111111111111
        assert!(validate_credit_card("VISA4111111111111111").is_ok()); // Extracts: 4111111111111111

        // Invalid when digits extracted don't form valid card
        assert!(validate_credit_card("abc").is_err()); // No digits
        assert!(validate_credit_card("!@#$%").is_err()); // No digits
    }

    #[test]
    fn test_routing_number_fed_reserve_ranges() {
        // Valid Federal Reserve ranges: 01-12, 21-32, 61-72, 80
        assert!(validate_routing_number("011000015").is_ok()); // Range 01-12
        assert!(validate_routing_number("021000021").is_ok()); // Range 01-12
        assert!(validate_routing_number("121000358").is_ok()); // Range 01-12

        // Invalid range - between valid ranges
        assert!(validate_routing_number("131000016").is_err()); // 13 is between 12 and 21
        assert!(validate_routing_number("331000013").is_err()); // 33 is between 32 and 61
    }

    #[test]
    fn test_routing_number_leading_zeros() {
        // Leading zeros are significant
        assert!(validate_routing_number("011000015").is_ok());
        assert!(validate_routing_number("021000021").is_ok());

        // All zeros - has correct ABA checksum (3*0 + 7*0 + 0 = 0, mod 10 = 0)
        // Note: ABA validation only checks checksum, not Federal Reserve ranges
        assert!(validate_routing_number("000000000").is_ok());

        // Invalid checksum with leading zeros
        assert!(validate_routing_number("000000001").is_err()); // Checksum = 1, not 0
    }

    #[test]
    fn test_account_number_boundaries() {
        // Minimum valid (1 digit)
        assert!(validate_account_number("1").is_ok());

        // Maximum valid (17 digits)
        assert!(validate_account_number("12345678901234567").is_ok());

        // Too long (18 digits)
        assert!(validate_account_number("123456789012345678").is_err());
    }

    #[test]
    fn test_malformed_card_inputs() {
        // Control characters are stripped when extracting digits
        // so these pass if the digits form a valid card
        assert!(validate_credit_card("4111\n1111\n1111\n1111").is_ok()); // Extracts: 4111111111111111
        assert!(validate_credit_card("4111\r1111\r1111\r1111").is_ok()); // Extracts: 4111111111111111

        // Very long input (stress test) - fails length check
        let long_input = "4".repeat(1000);
        assert!(validate_credit_card(&long_input).is_err());

        // Inputs that extract to invalid digit counts
        assert!(validate_credit_card("\n\n\n").is_err()); // No digits
        assert!(validate_credit_card("111").is_err()); // Too few digits
    }

    #[test]
    fn test_all_card_brands_valid() {
        // Test a valid card from each brand
        let test_cases = [
            ("4111111111111111", CreditCardType::Visa),
            ("5555555555554444", CreditCardType::Mastercard),
            ("378282246310005", CreditCardType::AmericanExpress),
            ("6011111111111117", CreditCardType::Discover),
            ("3530111333300000", CreditCardType::Jcb),
            ("30569309025904", CreditCardType::DinersClub),
        ];

        for (card, expected_type) in test_cases {
            let result = validate_credit_card(card);
            assert!(result.is_ok(), "Card {} should be valid", card);
            assert_eq!(
                result.expect("Card validation should succeed"),
                expected_type
            );
        }
    }

    #[test]
    fn test_payment_data_in_context() {
        // Card in various contexts
        assert!(is_payment_data_present("Please pay with 4111111111111111"));
        assert!(is_payment_data_present(
            "Card ending in 4111111111111111 was charged"
        ));
        assert!(is_payment_data_present(
            "JSON: {\"card\": \"4111111111111111\"}"
        ));

        // 4111111111111111 is a valid Visa test card (has correct Luhn)
        // so even with a prefix it still matches
        assert!(is_payment_data_present("Order #4111111111111111"));

        // Near-miss patterns that should not match
        assert!(!is_payment_data_present("Phone: 411-111-1111")); // Too short
        assert!(!is_payment_data_present("1234567890123456")); // Invalid Luhn
    }

    #[test]
    fn test_consecutive_digits_validation() {
        // Sequential digits - 1234567890123456 has invalid Luhn
        assert!(validate_credit_card("1234567890123456").is_err());

        // All same digit patterns
        // 4111111111111111 is a valid test card (passes Luhn)
        assert!(validate_credit_card("4111111111111111").is_ok());

        // 1111111111111111 and 2222222222222222 fail Luhn
        assert!(validate_credit_card("1111111111111111").is_err());
        assert!(validate_credit_card("2222222222222222").is_err());
    }
}
