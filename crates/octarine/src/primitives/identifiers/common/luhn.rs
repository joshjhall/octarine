//! Luhn algorithm implementation for credit card validation
//!
//! The Luhn algorithm (mod-10 checksum) is used to validate credit card numbers,
//! IMEI numbers, and other identifier sequences. This is the shared implementation
//! used across detection and validation modules.
//!
//! # Algorithm
//!
//! Starting from the rightmost digit (check digit):
//! 1. Double every second digit from right to left
//! 2. If doubling results in a two-digit number, subtract 9
//! 3. Sum all digits
//! 4. If sum % 10 == 0, the number is valid
//!
//! # References
//!
//! - [ISO/IEC 7812](https://en.wikipedia.org/wiki/ISO/IEC_7812) - Identification cards
//! - [Luhn algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm) - Wikipedia
//!
//! # Examples
//!
//! ```ignore
//! use crate::primitives::identifiers::common::luhn;
//!
//! // Valid credit card number
//! assert!(luhn::is_valid("4532015112830366"));
//!
//! // Invalid checksum
//! assert!(!luhn::is_valid("4532015112830367"));
//!
//! // Too short
//! assert!(!luhn::is_valid("123"));
//! ```

/// Check if a number string passes Luhn validation
///
/// # Arguments
///
/// * `number` - The number string to validate (digits only)
///
/// # Returns
///
/// * `true` - If the number passes Luhn validation (valid checksum)
/// * `false` - If the number fails validation or contains non-digits
///
/// # Algorithm
///
/// Implements the Luhn mod-10 checksum algorithm:
/// 1. Starting from the rightmost digit, double every second digit
/// 2. If doubling results in a number > 9, subtract 9 (equivalent to summing digits)
/// 3. Sum all digits
/// 4. Valid if sum % 10 == 0
///
/// # Examples
///
/// ```ignore
/// // Valid Visa card
/// assert!(is_valid("4532015112830366"));
///
/// // Invalid checksum
/// assert!(!is_valid("4532015112830367"));
///
/// // Non-digit characters
/// assert!(!is_valid("4532-0151-1283-0366")); // Contains dashes
/// ```
///
/// # Security Considerations
///
/// - This validates format only, not whether the card is active or belongs to someone
/// - Always validate card type (BIN ranges) in addition to Luhn checksum
/// - Never log full card numbers, even if Luhn-valid
///
/// # Implementation Notes
///
/// This implementation:
/// - Returns `false` for any non-digit characters (caller must pre-filter)
/// - Returns `false` for empty strings
/// - Uses integer arithmetic (no string conversions in loop)
/// - Time complexity: O(n) where n is string length
pub fn is_valid(number: &str) -> bool {
    if number.is_empty() {
        return false;
    }

    let mut sum: u32 = 0;
    let mut alternate = false;

    // Process digits from right to left
    for ch in number.chars().rev() {
        // Convert character to digit
        if let Some(mut digit) = ch.to_digit(10) {
            // Double every second digit
            if alternate {
                digit = digit.saturating_mul(2);
                // If result > 9, subtract 9 (equivalent to summing the two digits)
                if digit > 9 {
                    digit = digit.saturating_sub(9);
                }
            }
            sum = sum.saturating_add(digit);
            alternate = !alternate;
        } else {
            // Non-digit character found - invalid
            return false;
        }
    }

    // Valid if sum is divisible by 10
    sum.is_multiple_of(10)
}

/// Validate a number string using Luhn with minimum length check
///
/// This is a convenience wrapper that enforces a minimum length
/// (typically 13 for credit cards per ISO/IEC 7812).
///
/// # Arguments
///
/// * `number` - The number string to validate (digits only)
/// * `min_length` - Minimum required length
///
/// # Returns
///
/// * `true` - If the number is at least min_length and passes Luhn validation
/// * `false` - If the number is too short, invalid, or contains non-digits
///
/// # Examples
///
/// ```ignore
/// // Valid credit card (13+ digits)
/// assert!(is_valid_with_min_length("4532015112830366", 13));
///
/// // Too short (< 13 digits)
/// assert!(!is_valid_with_min_length("123456789", 13));
/// ```
pub fn is_valid_with_min_length(number: &str, min_length: usize) -> bool {
    number.len() >= min_length && is_valid(number)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_valid_credit_cards() {
        // Visa
        assert!(is_valid("4532015112830366"));
        assert!(is_valid("4556737586899855"));

        // Mastercard
        assert!(is_valid("5425233430109903"));
        assert!(is_valid("2221000000000009"));

        // Amex
        assert!(is_valid("374245455400126"));
        assert!(is_valid("378282246310005"));

        // Discover
        assert!(is_valid("6011111111111117"));
        assert!(is_valid("6011000990139424"));
    }

    #[test]
    fn test_invalid_checksums() {
        // Last digit modified
        assert!(!is_valid("4532015112830367")); // Changed last digit
        assert!(!is_valid("5425233430109904")); // Changed last digit
        assert!(!is_valid("374245455400127")); // Changed last digit
    }

    #[test]
    fn test_non_digit_characters() {
        // Spaces
        assert!(!is_valid("4532 0151 1283 0366"));

        // Dashes
        assert!(!is_valid("4532-0151-1283-0366"));

        // Letters
        assert!(!is_valid("453201511283036X"));

        // Mixed
        assert!(!is_valid("4532-ABCD-1283-0366"));
    }

    #[test]
    fn test_edge_cases() {
        // Empty string
        assert!(!is_valid(""));

        // Single digit
        assert!(is_valid("0")); // 0 % 10 == 0

        // Two digits
        assert!(!is_valid("12"));

        // All zeros
        assert!(is_valid("0000000000000000"));
    }

    #[test]
    fn test_minimum_length() {
        // Valid card, meets minimum
        assert!(is_valid_with_min_length("4532015112830366", 13));

        // Valid Luhn but too short
        assert!(!is_valid_with_min_length("0", 13));

        // Exactly minimum length (13 digits)
        assert!(is_valid_with_min_length("4532015112830", 13));

        // Below minimum
        assert!(!is_valid_with_min_length("123456789012", 13));
    }

    #[test]
    fn test_luhn_algorithm_steps() {
        // Test with "79927398713" (valid Luhn)
        // From right: 3, 1, 7, 8, 9, 3, 7, 2, 9, 9, 7
        // Double alternate: 3, 2, 7, 16->7, 9, 6, 7, 4, 9, 18->9, 7
        // Sum: 3+2+7+7+9+6+7+4+9+9+7 = 70
        // 70 % 10 == 0 ✓
        assert!(is_valid("79927398713"));

        // Modify last digit to make invalid
        assert!(!is_valid("79927398714")); // Sum would be 71
    }

    #[test]
    fn test_common_test_cards() {
        // These are well-known test card numbers from payment processors
        assert!(is_valid("4111111111111111")); // Visa test card
        assert!(is_valid("5555555555554444")); // Mastercard test card
        assert!(is_valid("378282246310005")); // Amex test card
        assert!(is_valid("6011111111111117")); // Discover test card
        assert!(is_valid("3530111333300000")); // JCB test card
    }
}
