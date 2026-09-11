//! Singapore NRIC/FIN and UEN validation
//!
//! NRIC/FIN format: [STFGM] + 7 digits + check letter
//! - S/T: citizen (born before/after 2000)
//! - F/G: permanent resident (before/after 2000)
//! - M: foreign worker (2022+)
//! - Weights: [2, 7, 6, 5, 4, 3, 2]
//! - Check letter: prefix-dependent lookup tables
//!
//! UEN (Unique Entity Number) — three layout variants, each with its own
//! weighted mod-11 check letter:
//! - Format A (business/ROB): 8 digits + check letter
//! - Format B (local company/ROC): `YYYY` + 5 digits + check letter, where the
//!   registration year may not be in the future
//! - Format C (other entity): `[TSR]` + `YY` + 2-letter entity type + 4 digits
//!   + check letter, where the entity type must be one of 39 published codes
//!
//! `validate_singapore_uen` checks layout only; `validate_singapore_uen_with_checksum`
//! additionally verifies the check letter, registration year, and entity type.

use crate::primitives::types::Problem;

/// Weights for NRIC/FIN checksum
const WEIGHTS: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];

/// Check letter table for S/T prefix (citizens)
const CHECK_ST: &[u8] = b"JZIHGFEDCBA";

/// Check letter table for F/G prefix (permanent residents)
const CHECK_FG: &[u8] = b"XWUTRQPNMLK";

/// Check letter table for M prefix (foreign workers, 2022+)
const CHECK_M: &[u8] = b"KLJNPQRTUWX";

/// Valid NRIC/FIN prefix characters
const VALID_PREFIXES: &[char] = &['S', 'T', 'F', 'G', 'M'];

/// Weights for UEN format A (business/ROB): 8 digits + check letter
const UEN_A_WEIGHTS: [u32; 8] = [10, 4, 9, 3, 8, 2, 7, 1];

/// Check letter alphabet for UEN format A
const UEN_A_ALPHABET: &[u8] = b"XMKECAWLJDB";

/// Weights for UEN format B (local company/ROC): 9 digits + check letter
const UEN_B_WEIGHTS: [u32; 9] = [10, 8, 6, 4, 9, 7, 5, 3, 1];

/// Check letter alphabet for UEN format B
const UEN_B_ALPHABET: &[u8] = b"ZKCMDNERGWH";

/// Weights for UEN format C (other entity): 9 alphanumeric chars + check letter
const UEN_C_WEIGHTS: [u32; 9] = [4, 3, 5, 3, 10, 2, 2, 5, 7];

/// Alphanumeric alphabet for UEN format C — index doubles as the character's
/// numeric value. Deliberately omits `I`, `O`, `Y`, and `Z` to avoid visual
/// ambiguity with `1`, `0`, and `2`.
const UEN_C_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWX0123456789";

/// Constant subtracted from the format C weighted sum before the mod-11 reduction
const UEN_C_OFFSET: u32 = 5;

/// Valid leading characters for UEN format C
const UEN_C_PREFIXES: &[char] = &['T', 'S', 'R'];

/// Published two-letter entity type codes for UEN format C
const UEN_C_ENTITY_TYPES: &[&str] = &[
    "LP", "LL", "FC", "PF", "RF", "MQ", "MM", "NB", "CC", "CS", "MB", "FM", "GS", "DP", "CP", "NR",
    "CM", "CD", "MD", "HS", "VH", "CH", "MH", "CL", "XL", "CX", "HC", "RP", "TU", "TC", "FB", "FN",
    "PA", "PB", "SS", "MC", "SM", "GA", "GB",
];

// ============================================================================
// Validation
// ============================================================================

/// Validate Singapore NRIC/FIN format (without checksum)
///
/// Checks: 9 characters, valid prefix, 7 digits, trailing letter.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_singapore_nric(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Singapore NRIC/FIN cannot be empty".to_string(),
        ));
    }

    if trimmed.len() != 9 {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN must be 9 characters, got {}",
            trimmed.len()
        )));
    }

    let chars: Vec<char> = trimmed.chars().collect();

    // Validate prefix
    let prefix = chars.first().copied().unwrap_or(' ');
    if !VALID_PREFIXES.contains(&prefix) {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN prefix must be S, T, F, G, or M; got '{}'",
            prefix
        )));
    }

    // Validate 7 digits
    for (i, &ch) in chars.iter().skip(1).take(7).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Singapore NRIC/FIN position {} must be a digit, got '{}'",
                i.saturating_add(2),
                ch
            )));
        }
    }

    // Validate trailing letter
    let last = chars.get(8).copied().unwrap_or(' ');
    if !last.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN must end with a letter, got '{}'",
            last
        )));
    }

    Ok(())
}

/// Validate Singapore NRIC/FIN with weighted checksum and check letter
///
/// Weights: [2, 7, 6, 5, 4, 3, 2]
/// Check letter determined by prefix-dependent lookup table.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_singapore_nric_with_checksum(value: &str) -> Result<(), Problem> {
    validate_singapore_nric(value)?;

    let trimmed = value.trim().to_uppercase();
    let chars: Vec<char> = trimmed.chars().collect();

    let prefix = chars.first().copied().unwrap_or(' ');

    // Extract 7 digits
    let digits: Vec<u32> = chars
        .iter()
        .skip(1)
        .take(7)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 7 {
        return Err(Problem::Validation(
            "Singapore NRIC/FIN must have 7 digits".to_string(),
        ));
    }

    // Calculate weighted sum
    let mut sum: u32 = 0;
    for (i, &weight) in WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    // Add offset for T/G prefixes (born after 2000)
    if prefix == 'T' || prefix == 'G' {
        sum = sum.saturating_add(4);
    } else if prefix == 'M' {
        sum = sum.saturating_add(3);
    }

    let remainder = (sum % 11) as usize;

    // Select check letter table based on prefix
    let check_table = match prefix {
        'S' | 'T' => CHECK_ST,
        'F' | 'G' => CHECK_FG,
        'M' => CHECK_M,
        _ => {
            return Err(Problem::Validation(format!("Unknown prefix '{}'", prefix)));
        }
    };

    let expected = check_table.get(remainder).copied().unwrap_or(b'?') as char;
    let actual = chars.get(8).copied().unwrap_or(' ');

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN check letter failed: expected '{}', got '{}'",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if a Singapore NRIC/FIN is a test/dummy pattern
#[must_use]
pub fn is_test_singapore_nric(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 9 {
        return false;
    }

    // All-zero digits
    let digits: String = upper.chars().skip(1).take(7).collect();
    if digits == "0000000" {
        return true;
    }

    // All-same digits
    if let Some(first) = digits.chars().next()
        && digits.chars().all(|c| c == first)
    {
        return true;
    }

    false
}

// ============================================================================
// UEN Validation
// ============================================================================

/// Validate Singapore UEN layout
///
/// Accepts the three published layouts:
/// - Business (ROB): 8 digits + uppercase check letter
/// - Local company (ROC): 9 digits + uppercase check letter
/// - Other entity: T + 2 digits + 2 uppercase letters + 4 digits + uppercase check letter
///
/// The check letter has no publicly documented algorithm, so it is not verified.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value does not match any layout.
pub fn validate_singapore_uen(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Singapore UEN cannot be empty".to_string(),
        ));
    }

    if is_business_uen(&trimmed) || is_local_company_uen(&trimmed) || is_other_entity_uen(&trimmed)
    {
        Ok(())
    } else {
        Err(Problem::Validation(format!(
            "Singapore UEN does not match any known layout (business / local company / other entity): '{}'",
            trimmed
        )))
    }
}

/// Validate a Singapore UEN with its layout-specific weighted mod-11 checksum
///
/// Dispatches on length and leading character, then verifies the trailing check
/// letter against the layout's own weight table and alphabet:
/// - Format A (9 chars, all digits but the last): weights `[10,4,9,3,8,2,7,1]`
/// - Format B (10 chars, leading digit): weights `[10,8,6,4,9,7,5,3,1]`, and the
///   `YYYY` registration year may not be in the future
/// - Format C (10 chars, leading letter): weights `[4,3,5,3,10,2,2,5,7]` over an
///   alphanumeric alphabet, with a `[TSR]` prefix and a whitelisted entity type
///
/// Format C treats its whole 9-character body as opaque alphanumeric input to
/// the checksum (matching Presidio): only the prefix and the entity type are
/// constrained positionally, so the `YY` and trailing runs are not separately
/// required to be digits — a letter there is caught by the check letter.
///
/// The per-layout helpers carry `get(..)` guards that the length dispatch below
/// already makes unreachable; they are defense-in-depth against a future change
/// to the dispatch, not branches any input can reach today.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value matches no layout, carries an
/// out-of-alphabet character, has a future registration year, has an
/// unrecognized entity type, or fails its check letter.
pub fn validate_singapore_uen_with_checksum(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Singapore UEN cannot be empty".to_string(),
        ));
    }

    let chars: Vec<char> = trimmed.chars().collect();
    let leading_is_alpha = chars.first().is_some_and(char::is_ascii_alphabetic);

    match chars.len() {
        9 => validate_uen_format_a(&chars),
        10 if leading_is_alpha => validate_uen_format_c(&chars),
        10 => validate_uen_format_b(&chars),
        other => Err(Problem::Validation(format!(
            "Singapore UEN must be 9 or 10 characters, got {}",
            other
        ))),
    }
}

/// Check if a Singapore UEN is a test/dummy pattern
#[must_use]
pub fn is_test_singapore_uen(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if !(is_business_uen(&upper) || is_local_company_uen(&upper) || is_other_entity_uen(&upper)) {
        return false;
    }

    let chars: Vec<char> = upper.chars().collect();
    // All-zero digits or all-same digits within the digit portion
    let digit_chars: String = chars.iter().filter(|c| c.is_ascii_digit()).collect();
    if digit_chars.is_empty() {
        return false;
    }
    if digit_chars.chars().all(|c| c == '0') {
        return true;
    }
    if let Some(first) = digit_chars.chars().next()
        && digit_chars.chars().all(|c| c == first)
    {
        return true;
    }
    false
}

fn is_business_uen(value: &str) -> bool {
    // 8 digits + uppercase letter
    if value.len() != 9 {
        return false;
    }
    let chars: Vec<char> = value.chars().collect();
    chars.iter().take(8).all(|c| c.is_ascii_digit())
        && chars.get(8).is_some_and(|c| c.is_ascii_uppercase())
}

fn is_local_company_uen(value: &str) -> bool {
    // 9 digits + uppercase letter
    if value.len() != 10 {
        return false;
    }
    let chars: Vec<char> = value.chars().collect();
    chars.iter().take(9).all(|c| c.is_ascii_digit())
        && chars.get(9).is_some_and(|c| c.is_ascii_uppercase())
}

fn is_other_entity_uen(value: &str) -> bool {
    // T + 2 digits + 2 letters + 4 digits + check letter
    if value.len() != 10 {
        return false;
    }
    let chars: Vec<char> = value.chars().collect();
    let head_t = chars.first() == Some(&'T');
    let year_digits = chars.iter().skip(1).take(2).all(|c| c.is_ascii_digit());
    let two_letters = chars.iter().skip(3).take(2).all(|c| c.is_ascii_uppercase());
    let four_digits = chars.iter().skip(5).take(4).all(|c| c.is_ascii_digit());
    let check = chars.get(9).is_some_and(|c| c.is_ascii_uppercase());
    head_t && year_digits && two_letters && four_digits && check
}

/// Sum `digits[i] * weights[i]` for a digit-only UEN body
///
/// Returns `Err` if any character is not an ASCII digit.
fn uen_digit_weighted_sum(body: &[char], weights: &[u32], layout: &str) -> Result<u32, Problem> {
    let mut sum: u32 = 0;
    for (c, weight) in body.iter().zip(weights.iter()) {
        let digit = c.to_digit(10).ok_or_else(|| {
            Problem::Validation(format!(
                "Singapore UEN ({}) expects digits before the check letter, got '{}'",
                layout, c
            ))
        })?;
        sum = sum.saturating_add(digit.saturating_mul(*weight));
    }
    Ok(sum)
}

/// Look up the check letter at `index` in `alphabet`
fn uen_check_letter(alphabet: &[u8], index: usize) -> Result<char, Problem> {
    alphabet
        .get(index)
        .map(|b| char::from(*b))
        .ok_or_else(|| Problem::Validation("Singapore UEN checksum index out of range".to_string()))
}

/// Compare the computed check letter against the supplied one
fn uen_compare_check(actual: Option<&char>, expected: char, layout: &str) -> Result<(), Problem> {
    match actual {
        Some(a) if *a == expected => Ok(()),
        Some(a) => Err(Problem::Validation(format!(
            "Singapore UEN ({}) check letter failed: expected '{}', got '{}'",
            layout, expected, a
        ))),
        None => Err(Problem::Validation(format!(
            "Singapore UEN ({}) is missing its check letter",
            layout
        ))),
    }
}

/// Validate UEN format A: 8 digits + weighted mod-11 check letter
fn validate_uen_format_a(chars: &[char]) -> Result<(), Problem> {
    let body = chars
        .get(..UEN_A_WEIGHTS.len())
        .ok_or_else(|| Problem::Validation("Singapore UEN (business) is too short".to_string()))?;

    let sum = uen_digit_weighted_sum(body, &UEN_A_WEIGHTS, "business")?;
    let expected = uen_check_letter(UEN_A_ALPHABET, (sum % 11) as usize)?;
    uen_compare_check(chars.get(UEN_A_WEIGHTS.len()), expected, "business")
}

/// Validate UEN format B: `YYYY` + 5 digits + weighted mod-11 check letter
///
/// Rejects a registration year later than the current year.
fn validate_uen_format_b(chars: &[char]) -> Result<(), Problem> {
    let body = chars.get(..UEN_B_WEIGHTS.len()).ok_or_else(|| {
        Problem::Validation("Singapore UEN (local company) is too short".to_string())
    })?;

    let year_digits = body
        .get(..4)
        .ok_or_else(|| {
            Problem::Validation("Singapore UEN (local company) has no year".to_string())
        })?
        .iter()
        .collect::<String>();
    let year: u32 = year_digits.parse().map_err(|_| {
        Problem::Validation(format!(
            "Singapore UEN (local company) registration year is not numeric: '{}'",
            year_digits
        ))
    })?;

    let current_year = current_year();
    if year > current_year {
        return Err(Problem::Validation(format!(
            "Singapore UEN (local company) registration year {} is in the future (current year {})",
            year, current_year
        )));
    }

    let sum = uen_digit_weighted_sum(body, &UEN_B_WEIGHTS, "local company")?;
    let expected = uen_check_letter(UEN_B_ALPHABET, (sum % 11) as usize)?;
    uen_compare_check(chars.get(UEN_B_WEIGHTS.len()), expected, "local company")
}

/// Validate UEN format C: `[TSR]` + `YY` + entity type + 4 digits + check letter
fn validate_uen_format_c(chars: &[char]) -> Result<(), Problem> {
    let body = chars.get(..UEN_C_WEIGHTS.len()).ok_or_else(|| {
        Problem::Validation("Singapore UEN (other entity) is too short".to_string())
    })?;

    let prefix = chars.first().copied().unwrap_or(' ');
    if !UEN_C_PREFIXES.contains(&prefix) {
        return Err(Problem::Validation(format!(
            "Singapore UEN (other entity) must start with T, S, or R, got '{}'",
            prefix
        )));
    }

    let entity_type: String = body
        .get(3..5)
        .ok_or_else(|| {
            Problem::Validation("Singapore UEN (other entity) has no entity type".to_string())
        })?
        .iter()
        .collect();
    if !UEN_C_ENTITY_TYPES.contains(&entity_type.as_str()) {
        return Err(Problem::Validation(format!(
            "Singapore UEN (other entity) has unrecognized entity type '{}'",
            entity_type
        )));
    }

    let mut sum: u32 = 0;
    for (c, weight) in body.iter().zip(UEN_C_WEIGHTS.iter()) {
        let value = UEN_C_ALPHABET
            .iter()
            .position(|b| char::from(*b) == *c)
            .ok_or_else(|| {
                Problem::Validation(format!(
                    "Singapore UEN (other entity) contains character '{}' outside the UEN alphabet",
                    c
                ))
            })?;
        sum = sum.saturating_add((value as u32).saturating_mul(*weight));
    }

    // Presidio subtracts 5 before the mod-11 reduction; add 11 first so the
    // subtraction cannot underflow for a small weighted sum.
    let index = (sum.saturating_add(11).saturating_sub(UEN_C_OFFSET) % 11) as usize;
    let expected = uen_check_letter(UEN_C_ALPHABET, index)?;
    uen_compare_check(chars.get(UEN_C_WEIGHTS.len()), expected, "other entity")
}

/// Current calendar year (UTC), used to reject future registration years
fn current_year() -> u32 {
    use chrono::Datelike;
    let year = chrono::Utc::now().year();
    u32::try_from(year).unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // Helper to compute check letter for given prefix + 7 digits
    fn compute_check_letter(prefix: char, digits: &[u32; 7]) -> char {
        let mut sum: u32 = 0;
        for (i, &weight) in WEIGHTS.iter().enumerate() {
            sum = sum.saturating_add(digits.get(i).copied().unwrap_or(0).saturating_mul(weight));
        }

        if prefix == 'T' || prefix == 'G' {
            sum = sum.saturating_add(4);
        } else if prefix == 'M' {
            sum = sum.saturating_add(3);
        }

        let remainder = (sum % 11) as usize;
        let table = match prefix {
            'S' | 'T' => CHECK_ST,
            'F' | 'G' => CHECK_FG,
            'M' => CHECK_M,
            _ => CHECK_ST,
        };

        table.get(remainder).copied().unwrap_or(b'?') as char
    }

    fn make_valid_nric(prefix: char, digits: [u32; 7]) -> String {
        let check = compute_check_letter(prefix, &digits);
        let digit_str: String = digits
            .iter()
            .map(|d| char::from_digit(*d, 10).unwrap_or('0'))
            .collect();
        format!("{}{}{}", prefix, digit_str, check)
    }

    #[test]
    fn test_validate_nric_valid_format() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        assert!(validate_singapore_nric(&nric).is_ok());
    }

    #[test]
    fn test_validate_nric_all_prefixes() {
        for &prefix in VALID_PREFIXES {
            let nric = make_valid_nric(prefix, [1, 2, 3, 4, 5, 6, 7]);
            assert!(
                validate_singapore_nric(&nric).is_ok(),
                "Prefix {} should be valid",
                prefix
            );
        }
    }

    #[test]
    fn test_validate_nric_invalid_prefix() {
        assert!(validate_singapore_nric("A1234567B").is_err());
        assert!(validate_singapore_nric("X1234567B").is_err());
    }

    #[test]
    fn test_validate_nric_wrong_length() {
        assert!(validate_singapore_nric("S123456A").is_err()); // 8 chars
        assert!(validate_singapore_nric("S12345678AB").is_err()); // 11 chars
    }

    #[test]
    fn test_validate_nric_empty() {
        assert!(validate_singapore_nric("").is_err());
    }

    #[test]
    fn test_validate_nric_with_checksum_s_prefix() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid S-prefix NRIC should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_t_prefix() {
        let nric = make_valid_nric('T', [0, 1, 2, 3, 4, 5, 6]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid T-prefix NRIC should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_f_prefix() {
        let nric = make_valid_nric('F', [1, 2, 3, 4, 5, 6, 7]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid F-prefix FIN should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_g_prefix() {
        let nric = make_valid_nric('G', [9, 8, 7, 6, 5, 4, 3]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid G-prefix FIN should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_m_prefix() {
        let nric = make_valid_nric('M', [1, 2, 3, 4, 5, 6, 7]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid M-prefix FIN should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_invalid() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        // Tamper with check letter
        let mut chars: Vec<char> = nric.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_singapore_nric_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_nric_lowercase_accepted() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        let lower = nric.to_lowercase();
        assert!(validate_singapore_nric_with_checksum(&lower).is_ok());
    }

    #[test]
    fn test_is_test_nric() {
        assert!(is_test_singapore_nric("S0000000A"));
        assert!(is_test_singapore_nric("S1111111A"));
        assert!(!is_test_singapore_nric("S1234567A"));
    }

    #[test]
    fn test_is_test_nric_wrong_length() {
        assert!(!is_test_singapore_nric("S12345"));
        assert!(!is_test_singapore_nric(""));
    }

    // ===== UEN Tests =====

    #[test]
    fn test_validate_uen_business_layout() {
        assert!(validate_singapore_uen("12345678K").is_ok());
    }

    #[test]
    fn test_validate_uen_local_company_layout() {
        assert!(validate_singapore_uen("201912345K").is_ok());
    }

    #[test]
    fn test_validate_uen_other_entity_layout() {
        assert!(validate_singapore_uen("T12LL1234A").is_ok());
    }

    #[test]
    fn test_validate_uen_lowercase_accepted() {
        assert!(validate_singapore_uen("12345678k").is_ok());
        assert!(validate_singapore_uen("t12ll1234a").is_ok());
    }

    #[test]
    fn test_validate_uen_rejects_empty() {
        assert!(validate_singapore_uen("").is_err());
        assert!(validate_singapore_uen("   ").is_err());
    }

    #[test]
    fn test_validate_uen_rejects_wrong_shape() {
        assert!(validate_singapore_uen("ABCDEFGH").is_err());
        assert!(validate_singapore_uen("1234567K").is_err()); // 7 digits + letter (too short)
        assert!(validate_singapore_uen("T12LL123A").is_err()); // other-entity with 3 digits
    }

    #[test]
    fn test_is_test_uen_all_zeros() {
        assert!(is_test_singapore_uen("00000000A"));
        assert!(is_test_singapore_uen("000000000A"));
    }

    #[test]
    fn test_is_test_uen_all_same_digit() {
        assert!(is_test_singapore_uen("11111111K"));
    }

    #[test]
    fn test_is_test_uen_real_value() {
        assert!(!is_test_singapore_uen("201912345K"));
    }

    #[test]
    fn test_is_test_uen_rejects_invalid_layout() {
        assert!(!is_test_singapore_uen("not a uen"));
    }

    // ========================================================================
    // UEN checksum validation
    // ========================================================================

    // Format A: 8 digits + weighted mod-11 check letter
    const VALID_UEN_A: &str = "12345678M";
    // Format B: YYYY + 5 digits + weighted mod-11 check letter
    const VALID_UEN_B: &str = "201912345R";
    // Format C: [TSR] + YY + entity type + 4 digits + check letter
    const VALID_UEN_C: &str = "T12LL1234C";

    #[test]
    fn test_uen_checksum_format_a_valid() {
        assert!(validate_singapore_uen_with_checksum(VALID_UEN_A).is_ok());
        assert!(validate_singapore_uen_with_checksum("53012345B").is_ok());
    }

    #[test]
    fn test_uen_checksum_format_a_rejects_bad_check_letter() {
        // Layout-valid but the check letter should be 'M', not 'K'
        let err = validate_singapore_uen_with_checksum("12345678K")
            .expect_err("bad format A check letter must be rejected");
        assert!(err.to_string().contains("check letter"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_format_a_accepts_lowercase() {
        assert!(validate_singapore_uen_with_checksum("12345678m").is_ok());
    }

    #[test]
    fn test_uen_checksum_format_b_valid() {
        assert!(validate_singapore_uen_with_checksum(VALID_UEN_B).is_ok());
        assert!(validate_singapore_uen_with_checksum("202400123R").is_ok());
    }

    #[test]
    fn test_uen_checksum_format_b_rejects_bad_check_letter() {
        let err = validate_singapore_uen_with_checksum("201912345K")
            .expect_err("bad format B check letter must be rejected");
        assert!(err.to_string().contains("check letter"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_format_b_rejects_future_year() {
        // 2099 is checksum-correct ('Z') so the ONLY reason to reject is the year
        assert!(
            validate_singapore_uen_with_checksum("209912345Z").is_err(),
            "checksum-correct future-year UEN must still be rejected"
        );
        let err = validate_singapore_uen_with_checksum("209912345Z")
            .expect_err("future registration year must be rejected");
        assert!(err.to_string().contains("future"), "got: {}", err);
        assert!(err.to_string().contains("2099"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_format_c_valid() {
        assert!(validate_singapore_uen_with_checksum(VALID_UEN_C).is_ok());
        assert!(validate_singapore_uen_with_checksum("T12CC0001L").is_ok());
        assert!(validate_singapore_uen_with_checksum("S98FC0001D").is_ok());
        assert!(validate_singapore_uen_with_checksum("R05GS9999G").is_ok());
    }

    #[test]
    fn test_uen_checksum_format_c_rejects_bad_check_letter() {
        let err = validate_singapore_uen_with_checksum("T12LL1234A")
            .expect_err("bad format C check letter must be rejected");
        assert!(err.to_string().contains("check letter"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_format_c_rejects_unknown_entity_type() {
        // 'ZZ' is not among the 39 published entity type codes
        let err = validate_singapore_uen_with_checksum("T12ZZ1234C")
            .expect_err("unwhitelisted entity type must be rejected");
        assert!(err.to_string().contains("entity type"), "got: {}", err);
        assert!(err.to_string().contains("ZZ"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_format_c_rejects_bad_prefix() {
        // 'X' is outside the {T, S, R} prefix set
        let err = validate_singapore_uen_with_checksum("X12LL1234C")
            .expect_err("prefix outside T/S/R must be rejected");
        assert!(err.to_string().contains("T, S, or R"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_format_c_rejects_out_of_alphabet_char() {
        // 'I' and 'O' are deliberately absent from the format C alphabet.
        // 'IO' is not a whitelisted entity type either, so place them in the
        // trailing digit run to exercise the alphabet lookup specifically.
        let err = validate_singapore_uen_with_checksum("T12LLI234C")
            .expect_err("character outside the UEN alphabet must be rejected");
        assert!(err.to_string().contains("alphabet"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_rejects_empty_and_wrong_length() {
        assert!(validate_singapore_uen_with_checksum("").is_err());
        assert!(validate_singapore_uen_with_checksum("   ").is_err());
        // 8 chars — no layout
        assert!(validate_singapore_uen_with_checksum("1234567K").is_err());
        // 11 chars — no layout
        assert!(validate_singapore_uen_with_checksum("2019123456K").is_err());
    }

    #[test]
    fn test_uen_checksum_rejects_non_digit_body() {
        // Format A body must be digits
        assert!(validate_singapore_uen_with_checksum("1234567AM").is_err());
        // Format B body must be digits too. A non-digit in the YYYY run is
        // caught by the year parse, which reports the offending year.
        let err = validate_singapore_uen_with_checksum("2O1912345R")
            .expect_err("non-digit in the format B year must be rejected");
        assert!(err.to_string().contains("not numeric"), "got: {}", err);
        // A non-digit after the year reaches the weighted-sum arm instead, so
        // both format B digit guards are covered.
        let err = validate_singapore_uen_with_checksum("20191234OR")
            .expect_err("non-digit in the format B serial must be rejected");
        assert!(err.to_string().contains("expects digits"), "got: {}", err);
    }

    #[test]
    fn test_uen_checksum_formats_b_and_c_accept_lowercase() {
        // Case normalization must apply to every layout, not just format A.
        assert!(validate_singapore_uen_with_checksum("201912345r").is_ok());
        assert!(validate_singapore_uen_with_checksum("t12ll1234c").is_ok());
    }

    #[test]
    fn test_uen_format_only_variant_is_unchanged() {
        // The format-only validator must keep accepting layout-valid values
        // whose check letter does not verify — it is deliberately lenient.
        assert!(validate_singapore_uen("12345678K").is_ok());
        assert!(validate_singapore_uen("201912345K").is_ok());
        assert!(validate_singapore_uen("T12LL1234A").is_ok());
        // And it still rejects bad layouts
        assert!(validate_singapore_uen("not a uen").is_err());
        assert!(validate_singapore_uen("").is_err());
    }
}
