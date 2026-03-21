//! Common masking and redaction strategies for identifiers
//!
//! This module provides reusable helper functions for masking, redacting, and
//! sanitizing sensitive identifiers. These utilities eliminate code duplication
//! across different identifier types (payment, personal, government, etc.).
//!
//! # Masking Strategies
//!
//! - **show_first_n**: Shows first N characters, masks the rest
//! - **show_last_n**: Shows last N characters, masks the rest
//! - **show_first_and_last**: Shows first M and last N, masks middle
//! - **mask_all**: Replaces all characters with mask character
//! - **mask_middle**: Shows edges, masks middle section
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::common::masking;
//!
//! // Show last 4 digits (common for credit cards, SSN)
//! let masked = masking::show_last_n("1234567890", 4, '*');
//! assert_eq!(masked, "******7890");
//!
//! // Show first 6 and last 4 (PCI-DSS compliant for credit cards)
//! let masked = masking::show_first_and_last("4242424242424242", 6, 4, '*');
//! assert_eq!(masked, "424242******4242");
//!
//! // Extract digits only
//! let digits = masking::digits_only("123-45-6789");
//! assert_eq!(digits, "123456789");
//! ```

/// Extract only digit characters from a string
///
/// Useful for normalizing identifiers that may contain formatting characters
/// (hyphens, spaces, etc.) before applying masking strategies.
///
/// # Arguments
///
/// * `value` - The input string
///
/// # Returns
///
/// String containing only ASCII digit characters (0-9)
///
/// # Examples
///
/// ```ignore
/// let digits = digits_only("123-45-6789");
/// assert_eq!(digits, "123456789");
///
/// let digits = digits_only("(555) 123-4567");
/// assert_eq!(digits, "5551234567");
/// ```
pub fn digits_only(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Extract only alphanumeric characters from a string
///
/// Useful for normalizing identifiers before masking.
///
/// # Arguments
///
/// * `value` - The input string
///
/// # Returns
///
/// String containing only alphanumeric characters
pub fn alphanumeric_only(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Show only the first N characters, mask the rest
///
/// # Arguments
///
/// * `value` - The input string
/// * `show_count` - Number of characters to show from the beginning
/// * `mask_char` - Character to use for masking (typically '*')
///
/// # Returns
///
/// Masked string showing first N characters
///
/// # Examples
///
/// ```ignore
/// let masked = show_first_n("1234567890", 4, '*');
/// assert_eq!(masked, "1234******");
///
/// let masked = show_first_n("ABC", 5, '*'); // Shorter than show_count
/// assert_eq!(masked, "ABC");
/// ```
pub fn show_first_n(value: &str, show_count: usize, mask_char: char) -> String {
    let chars: Vec<char> = value.chars().collect();
    let char_count = chars.len();

    if char_count <= show_count {
        return value.to_string();
    }

    let visible: String = chars
        .get(..show_count)
        .map_or_else(String::new, |s| s.iter().collect());
    let mask_len = char_count.saturating_sub(show_count);
    format!("{}{}", visible, mask_char.to_string().repeat(mask_len))
}

/// Show only the last N characters, mask the rest
///
/// Common pattern for SSN (last 4), phone numbers (last 4), etc.
///
/// # Arguments
///
/// * `value` - The input string
/// * `show_count` - Number of characters to show from the end
/// * `mask_char` - Character to use for masking (typically '*')
///
/// # Returns
///
/// Masked string showing last N characters
///
/// # Examples
///
/// ```ignore
/// let masked = show_last_n("1234567890", 4, '*');
/// assert_eq!(masked, "******7890");
///
/// let masked = show_last_n("ABC", 5, '*'); // Shorter than show_count
/// assert_eq!(masked, "ABC");
/// ```
pub fn show_last_n(value: &str, show_count: usize, mask_char: char) -> String {
    let chars: Vec<char> = value.chars().collect();
    let char_count = chars.len();

    if char_count <= show_count {
        return value.to_string();
    }

    let mask_len = char_count.saturating_sub(show_count);
    let visible: String = chars
        .get(mask_len..)
        .map_or_else(String::new, |s| s.iter().collect());
    format!("{}{}", mask_char.to_string().repeat(mask_len), visible)
}

/// Show first M and last N characters, mask the middle
///
/// PCI-DSS compliant pattern: show first 6 and last 4 of credit card.
///
/// # Arguments
///
/// * `value` - The input string
/// * `first_count` - Number of characters to show from the beginning
/// * `last_count` - Number of characters to show from the end
/// * `mask_char` - Character to use for masking (typically '*')
///
/// # Returns
///
/// Masked string showing first M and last N characters
///
/// # Examples
///
/// ```ignore
/// // PCI-DSS compliant credit card masking
/// let masked = show_first_and_last("4242424242424242", 6, 4, '*');
/// assert_eq!(masked, "424242******4242");
///
/// // Show first 3 and last 4 of SSN
/// let masked = show_first_and_last("123456789", 3, 4, '*');
/// assert_eq!(masked, "123**6789");
/// ```
pub fn show_first_and_last(
    value: &str,
    first_count: usize,
    last_count: usize,
    mask_char: char,
) -> String {
    let chars: Vec<char> = value.chars().collect();
    let char_count = chars.len();
    let total_visible = first_count.saturating_add(last_count);

    if char_count <= total_visible {
        return value.to_string();
    }

    let first: String = chars
        .get(..first_count)
        .map_or_else(String::new, |s| s.iter().collect());
    let last: String = chars
        .get(char_count.saturating_sub(last_count)..)
        .map_or_else(String::new, |s| s.iter().collect());
    let mask_len = char_count.saturating_sub(total_visible);

    format!(
        "{}{}{}",
        first,
        mask_char.to_string().repeat(mask_len),
        last
    )
}

/// Mask all characters with the specified mask character
///
/// Useful for complete redaction while preserving length information.
///
/// # Arguments
///
/// * `value` - The input string
/// * `mask_char` - Character to use for masking (typically '*')
///
/// # Returns
///
/// String with all characters replaced by mask_char
///
/// # Examples
///
/// ```ignore
/// let masked = mask_all("password123", '*');
/// assert_eq!(masked, "***********");
/// ```
pub fn mask_all(value: &str, mask_char: char) -> String {
    mask_char.to_string().repeat(value.chars().count())
}

/// Mask the middle section, showing edges
///
/// Shows `edge_count` characters on each side, masks the middle.
///
/// # Arguments
///
/// * `value` - The input string
/// * `edge_count` - Number of characters to show on each side
/// * `mask_char` - Character to use for masking (typically '*')
///
/// # Returns
///
/// Masked string showing edges
///
/// # Examples
///
/// ```ignore
/// let masked = mask_middle("1234567890", 2, '*');
/// assert_eq!(masked, "12******90");
/// ```
pub fn mask_middle(value: &str, edge_count: usize, mask_char: char) -> String {
    show_first_and_last(value, edge_count, edge_count, mask_char)
}

/// Create a mask of a specific length
///
/// Helper function to create mask strings of arbitrary length.
///
/// # Arguments
///
/// * `length` - Length of the mask string
/// * `mask_char` - Character to use for masking (typically '*')
///
/// # Returns
///
/// String of `mask_char` repeated `length` times
///
/// # Examples
///
/// ```ignore
/// let mask = create_mask(5, '*');
/// assert_eq!(mask, "*****");
/// ```
pub fn create_mask(length: usize, mask_char: char) -> String {
    mask_char.to_string().repeat(length)
}

/// Mask digits while preserving separators
///
/// Useful for SSN, phone numbers, credit cards with formatting.
/// Only masks digit characters, preserving hyphens, spaces, etc.
///
/// # Arguments
///
/// * `value` - The input string with formatting
/// * `show_last` - Number of trailing digits to show (0 for total masking)
/// * `mask_char` - Character to use for masking digits (typically '*')
///
/// # Returns
///
/// String with digits masked but separators preserved
///
/// # Examples
///
/// ```ignore
/// let masked = mask_digits_preserve_format("123-45-6789", 4, '*');
/// assert_eq!(masked, "***-**-6789");
///
/// let masked = mask_digits_preserve_format("(555) 123-4567", 4, '*');
/// assert_eq!(masked, "(***) ***-4567");
/// ```
pub fn mask_digits_preserve_format(value: &str, show_last: usize, mask_char: char) -> String {
    let digits: Vec<char> = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let total_digits = digits.len();

    if show_last == 0 {
        // Mask all digits
        return value
            .chars()
            .map(|c| if c.is_ascii_digit() { mask_char } else { c })
            .collect();
    }

    if show_last >= total_digits {
        // Show all digits
        return value.to_string();
    }

    let mask_count = total_digits.saturating_sub(show_last);
    let mut digit_index: usize = 0;

    value
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                digit_index = digit_index.saturating_add(1);
                if digit_index <= mask_count {
                    mask_char
                } else {
                    c
                }
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Helper Function Tests =====

    #[test]
    fn test_digits_only() {
        assert_eq!(digits_only("123-45-6789"), "123456789");
        assert_eq!(digits_only("(555) 123-4567"), "5551234567");
        assert_eq!(digits_only("4242-4242-4242-4242"), "4242424242424242");
        assert_eq!(digits_only("no digits here"), "");
    }

    #[test]
    fn test_alphanumeric_only() {
        assert_eq!(alphanumeric_only("ABC-123"), "ABC123");
        assert_eq!(alphanumeric_only("test@example.com"), "testexamplecom");
        assert_eq!(alphanumeric_only("!!!"), "");
    }

    // ===== show_first_n Tests =====

    #[test]
    fn test_show_first_n() {
        assert_eq!(show_first_n("1234567890", 4, '*'), "1234******");
        assert_eq!(show_first_n("ABCDEFGH", 3, '*'), "ABC*****");
    }

    #[test]
    fn test_show_first_n_short_value() {
        // Value shorter than show_count
        assert_eq!(show_first_n("ABC", 5, '*'), "ABC");
        assert_eq!(show_first_n("123", 10, '*'), "123");
    }

    // ===== show_last_n Tests =====

    #[test]
    fn test_show_last_n() {
        assert_eq!(show_last_n("1234567890", 4, '*'), "******7890");
        assert_eq!(show_last_n("ABCDEFGH", 3, '*'), "*****FGH");
    }

    #[test]
    fn test_show_last_n_short_value() {
        // Value shorter than show_count
        assert_eq!(show_last_n("ABC", 5, '*'), "ABC");
        assert_eq!(show_last_n("123", 10, '*'), "123");
    }

    // ===== show_first_and_last Tests =====

    #[test]
    fn test_show_first_and_last() {
        // PCI-DSS compliant credit card masking
        assert_eq!(
            show_first_and_last("4242424242424242", 6, 4, '*'),
            "424242******4242"
        );

        // SSN pattern
        assert_eq!(show_first_and_last("123456789", 3, 4, '*'), "123**6789");
    }

    #[test]
    fn test_show_first_and_last_short_value() {
        // Value shorter than total visible
        assert_eq!(show_first_and_last("ABCD", 3, 3, '*'), "ABCD");
        assert_eq!(show_first_and_last("12345", 2, 4, '*'), "12345");
    }

    // ===== mask_all Tests =====

    #[test]
    fn test_mask_all() {
        assert_eq!(mask_all("password123", '*'), "***********");
        assert_eq!(mask_all("secret", '#'), "######");
        assert_eq!(mask_all("", '*'), "");
    }

    // ===== mask_middle Tests =====

    #[test]
    fn test_mask_middle() {
        assert_eq!(mask_middle("1234567890", 2, '*'), "12******90");
        assert_eq!(mask_middle("ABCDEFGH", 1, '*'), "A******H");
    }

    #[test]
    fn test_mask_middle_short_value() {
        assert_eq!(mask_middle("ABCD", 3, '*'), "ABCD");
    }

    // ===== create_mask Tests =====

    #[test]
    fn test_create_mask() {
        assert_eq!(create_mask(5, '*'), "*****");
        assert_eq!(create_mask(10, '#'), "##########");
        assert_eq!(create_mask(0, '*'), "");
    }

    // ===== mask_digits_preserve_format Tests =====

    #[test]
    fn test_mask_digits_preserve_format_ssn() {
        // Show last 4 digits of SSN
        assert_eq!(
            mask_digits_preserve_format("123-45-6789", 4, '*'),
            "***-**-6789"
        );

        // Total masking
        assert_eq!(
            mask_digits_preserve_format("123-45-6789", 0, '*'),
            "***-**-****"
        );
    }

    #[test]
    fn test_mask_digits_preserve_format_phone() {
        assert_eq!(
            mask_digits_preserve_format("(555) 123-4567", 4, '*'),
            "(***) ***-4567"
        );

        assert_eq!(
            mask_digits_preserve_format("555-123-4567", 4, '*'),
            "***-***-4567"
        );
    }

    #[test]
    fn test_mask_digits_preserve_format_credit_card() {
        assert_eq!(
            mask_digits_preserve_format("4242-4242-4242-4242", 4, '*'),
            "****-****-****-4242"
        );
    }

    #[test]
    fn test_mask_digits_preserve_format_show_all() {
        // show_last >= total digits
        assert_eq!(
            mask_digits_preserve_format("123-45-6789", 10, '*'),
            "123-45-6789"
        );
    }

    // ===== UTF-8 Safety Tests =====

    #[test]
    fn test_unicode_show_first_n() {
        // Multi-byte characters (emoji, accented chars)
        assert_eq!(show_first_n("café", 4, '*'), "café");
        assert_eq!(show_first_n("café!", 4, '*'), "café*");

        // Emoji (4-byte UTF-8)
        assert_eq!(show_first_n("😀😀😀😀", 2, '*'), "😀😀**");
        assert_eq!(show_first_n("A😀B😀C", 3, '*'), "A😀B**");
    }

    #[test]
    fn test_unicode_show_last_n() {
        assert_eq!(show_last_n("café", 2, '*'), "**fé");
        assert_eq!(show_last_n("😀😀😀😀", 2, '*'), "**😀😀");
        assert_eq!(show_last_n("A😀B😀C", 2, '*'), "***😀C");
    }

    #[test]
    fn test_unicode_show_first_and_last() {
        assert_eq!(show_first_and_last("😀1234😀", 1, 1, '*'), "😀****😀");
        assert_eq!(show_first_and_last("Ñoño", 1, 1, '*'), "Ñ**o");
    }

    #[test]
    fn test_unicode_mask_all() {
        // Should mask by character count, not byte count
        assert_eq!(mask_all("café", '*'), "****"); // 4 chars, not 5 bytes
        assert_eq!(mask_all("😀😀", '*'), "**"); // 2 chars, not 8 bytes
    }

    #[test]
    fn test_edge_cases() {
        // Empty strings
        assert_eq!(show_first_n("", 5, '*'), "");
        assert_eq!(show_last_n("", 5, '*'), "");
        assert_eq!(mask_all("", '*'), "");

        // Single character
        assert_eq!(show_first_n("X", 1, '*'), "X");
        assert_eq!(show_last_n("X", 1, '*'), "X");
    }
}
