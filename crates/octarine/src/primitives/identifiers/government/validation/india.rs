//! India Aadhaar, PAN, GSTIN, vehicle registration, voter ID, and passport validation
//!
//! - Aadhaar: 12-digit number with Verhoeff checksum (starts with 2-9)
//! - PAN: 10-character alphanumeric (AAAAA9999A) with holder type at position 4
//! - GSTIN: 15-char alphanumeric (state + PAN + entity + Z + check) with MOD-36 checksum
//! - Vehicle Registration: state code + district + optional series + number
//! - Voter ID (EPIC): 3 letters + 7 digits
//! - Indian Passport: type letter (P/S/D) + 7 digits

use crate::primitives::types::Problem;

// ============================================================================
// Verhoeff Checksum Tables
// ============================================================================

/// Verhoeff multiplication table (d5 group)
#[rustfmt::skip]
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// Verhoeff permutation table
#[rustfmt::skip]
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Valid PAN holder type codes at position 4 (0-indexed)
const VALID_PAN_HOLDER_TYPES: &[char] = &[
    'A', // Association of Persons
    'B', // Body of Individuals
    'C', // Company
    'F', // Firm
    'G', // Government
    'H', // Hindu Undivided Family
    'J', // Artificial Juridical Person
    'L', // Local Authority
    'P', // Individual (Person)
    'T', // Trust
];

// ============================================================================
// Aadhaar Validation
// ============================================================================

/// Validate India Aadhaar format (without checksum)
///
/// Checks: 12 digits, starts with 2-9.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_aadhaar(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    if digits.len() != 12 {
        return Err(Problem::Validation(format!(
            "Aadhaar must be 12 digits, got {}",
            digits.len()
        )));
    }

    let first = digits.first().copied().unwrap_or(0);
    if first < 2 {
        return Err(Problem::Validation(format!(
            "Aadhaar cannot start with {}, must start with 2-9",
            first
        )));
    }

    Ok(())
}

/// Validate India Aadhaar with Verhoeff checksum
///
/// Uses the Verhoeff algorithm: processes digits right-to-left using
/// d5 multiplication table and permutation cycling.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_india_aadhaar_with_checksum(value: &str) -> Result<(), Problem> {
    validate_india_aadhaar(value)?;

    let digits = extract_digits(value)?;
    if !verhoeff_validate(&digits) {
        return Err(Problem::Validation(
            "Aadhaar Verhoeff checksum failed".to_string(),
        ));
    }

    Ok(())
}

/// Check if an Aadhaar is a test/dummy pattern
#[must_use]
pub fn is_test_india_aadhaar(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if clean.len() != 12 {
        return false;
    }

    // All same digits
    if let Some(first) = clean.chars().next()
        && clean.chars().all(|c| c == first)
    {
        return true;
    }

    false
}

// ============================================================================
// PAN Validation
// ============================================================================

/// Validate India PAN format
///
/// Format: AAAAA9999A (5 uppercase letters + 4 digits + 1 uppercase letter)
/// Position 4 (0-indexed) must be a valid holder type code.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_pan(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("PAN cannot be empty".to_string()));
    }

    let upper = trimmed.to_uppercase();
    if upper.len() != 10 {
        return Err(Problem::Validation(format!(
            "PAN must be 10 characters, got {}",
            upper.len()
        )));
    }

    let chars: Vec<char> = upper.chars().collect();

    // First 5 must be letters
    for (i, &ch) in chars.iter().take(5).enumerate() {
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "PAN position {} must be a letter, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Next 4 must be digits
    for (i, &ch) in chars.iter().skip(5).take(4).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "PAN position {} must be a digit, got '{}'",
                i.saturating_add(6),
                ch
            )));
        }
    }

    // Last must be a letter
    let last = chars.get(9).copied().unwrap_or(' ');
    if !last.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "PAN position 10 must be a letter, got '{}'",
            last
        )));
    }

    // Position 4 (0-indexed) must be a valid holder type
    let holder_type = chars.get(3).copied().unwrap_or(' ');
    if !VALID_PAN_HOLDER_TYPES.contains(&holder_type) {
        return Err(Problem::Validation(format!(
            "PAN holder type '{}' at position 4 is not valid (expected one of: {:?})",
            holder_type, VALID_PAN_HOLDER_TYPES
        )));
    }

    Ok(())
}

/// Check if a PAN is a test/dummy pattern
#[must_use]
pub fn is_test_india_pan(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 10 {
        return false;
    }

    // Common test patterns
    matches!(upper.as_str(), "AAAAA0000A" | "ABCDE1234F" | "ZZZZZ9999Z")
}

// ============================================================================
// GSTIN Validation
// ============================================================================

/// Validate India GSTIN format (without checksum)
///
/// Format: NN AAAAA NNNN A [1-9A-Z] Z [0-9A-Z] (15 characters)
/// - Positions 1-2: state code (01-37)
/// - Positions 3-12: embedded PAN (5 letters + 4 digits + 1 letter)
/// - Position 13: entity number (1-9 or A-Z)
/// - Position 14: literal 'Z'
/// - Position 15: check character (alphanumeric)
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_gstin(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("GSTIN cannot be empty".to_string()));
    }

    let upper = trimmed.to_uppercase();
    if upper.len() != 15 {
        return Err(Problem::Validation(format!(
            "GSTIN must be 15 characters, got {}",
            upper.len()
        )));
    }

    let chars: Vec<char> = upper.chars().collect();

    // Positions 0-1: state code digits
    for (i, &ch) in chars.iter().take(2).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "GSTIN position {} must be a digit (state code), got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // State code must be 01-37 (current Indian states/UTs use 01-37; 99 reserved for other-territory)
    let state_str: String = chars.iter().take(2).collect();
    if let Ok(state) = state_str.parse::<u32>()
        && !(1..=37).contains(&state)
        && state != 99
    {
        return Err(Problem::Validation(format!(
            "GSTIN state code '{}' is not valid (expected 01-37 or 99)",
            state_str
        )));
    }

    // Positions 2-6: PAN letters
    for (i, &ch) in chars.iter().skip(2).take(5).enumerate() {
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "GSTIN position {} must be a letter (PAN), got '{}'",
                i.saturating_add(3),
                ch
            )));
        }
    }

    // Positions 7-10: PAN digits
    for (i, &ch) in chars.iter().skip(7).take(4).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "GSTIN position {} must be a digit (PAN), got '{}'",
                i.saturating_add(8),
                ch
            )));
        }
    }

    // Position 11: PAN check letter
    let pan_check = chars.get(11).copied().unwrap_or(' ');
    if !pan_check.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "GSTIN position 12 must be a letter (PAN check), got '{}'",
            pan_check
        )));
    }

    // Position 12: entity number (1-9 or A-Z)
    let entity = chars.get(12).copied().unwrap_or(' ');
    if !(entity.is_ascii_uppercase() || ('1'..='9').contains(&entity)) {
        return Err(Problem::Validation(format!(
            "GSTIN position 13 must be 1-9 or A-Z (entity), got '{}'",
            entity
        )));
    }

    // Position 13: literal 'Z'
    let z = chars.get(13).copied().unwrap_or(' ');
    if z != 'Z' {
        return Err(Problem::Validation(format!(
            "GSTIN position 14 must be 'Z', got '{}'",
            z
        )));
    }

    // Position 14: check character (alphanumeric)
    let check = chars.get(14).copied().unwrap_or(' ');
    if !(check.is_ascii_uppercase() || check.is_ascii_digit()) {
        return Err(Problem::Validation(format!(
            "GSTIN position 15 must be alphanumeric (check), got '{}'",
            check
        )));
    }

    Ok(())
}

/// Validate India GSTIN with MOD-36 checksum
///
/// Algorithm (per GSTN specification):
/// - Map each char to value (0-9 → 0-9, A-Z → 10-35)
/// - For positions 0-13: multiply by weight (1 if position even, 2 if odd)
/// - If product ≥ 36, sum its quotient and remainder mod 36
/// - Sum the 14 weighted values
/// - Check digit = (36 - (sum mod 36)) mod 36
/// - Compare to position 14
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or checksum is invalid.
pub fn validate_india_gstin_with_checksum(value: &str) -> Result<(), Problem> {
    validate_india_gstin(value)?;

    let upper = value.trim().to_uppercase();
    let chars: Vec<char> = upper.chars().collect();

    let expected = chars.get(14).copied().unwrap_or(' ');
    let expected_val = char_to_base36(expected).ok_or_else(|| {
        Problem::Validation(format!(
            "GSTIN check char '{}' is not a valid base-36 digit",
            expected
        ))
    })?;

    let mut sum: u32 = 0;
    for (i, &ch) in chars.iter().take(14).enumerate() {
        let val = char_to_base36(ch).ok_or_else(|| {
            Problem::Validation(format!(
                "GSTIN char '{}' at position {} is not a valid base-36 digit",
                ch,
                i.saturating_add(1)
            ))
        })?;
        let weight: u32 = if i % 2 == 0 { 1 } else { 2 };
        let product = val.saturating_mul(weight);
        // If product >= 36, sum its quotient and remainder (digit-sum in base 36)
        let contribution = if product >= 36 {
            product
                .checked_div(36)
                .unwrap_or(0)
                .saturating_add(product % 36)
        } else {
            product
        };
        sum = sum.saturating_add(contribution);
    }

    let computed = (36u32.saturating_sub(sum % 36)) % 36;
    if computed != expected_val {
        return Err(Problem::Validation(format!(
            "GSTIN MOD-36 checksum failed (expected '{}', computed '{}')",
            expected,
            base36_to_char(computed).unwrap_or('?')
        )));
    }

    Ok(())
}

/// Check if a GSTIN is a test/dummy pattern
#[must_use]
pub fn is_test_india_gstin(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 15 {
        return false;
    }
    // Repeated digits in state code (00, 11, etc. — not valid real codes 01-37)
    let first_two: String = upper.chars().take(2).collect();
    matches!(first_two.as_str(), "00" | "99")
        || matches!(
            upper.as_str(),
            "27AAAPL1234C1Z5" | "29AAAPL1234C1Z0" | "07AAAAA0000A1Z0"
        )
}

// ============================================================================
// Vehicle Registration Validation
// ============================================================================

/// Validate India vehicle registration (license plate) format
///
/// Format: state code (2 letters) + district code (1-2 digits) + series (1-3
/// letters) + number (1-4 digits). Spaces and hyphens between segments are
/// accepted and normalized away.
///
/// State codes (e.g., MH, DL, KA) are not enforced against a closed list —
/// new codes are issued periodically and lists vary by source.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_vehicle_registration(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Vehicle registration cannot be empty".to_string(),
        ));
    }

    let normalized: String = trimmed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();

    if normalized.len() < 5 || normalized.len() > 10 {
        return Err(Problem::Validation(format!(
            "Vehicle registration must be 5-10 chars (excl. separators), got {}",
            normalized.len()
        )));
    }

    let chars: Vec<char> = normalized.chars().collect();

    // First 2 chars must be uppercase letters (state code)
    for (i, &ch) in chars.iter().take(2).enumerate() {
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "Vehicle registration position {} must be a letter (state code), got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Walk the rest: 1-2 digits, then 1-3 letters, then 1-4 digits
    let rest: &[char] = chars.get(2..).unwrap_or(&[]);
    let mut idx = 0;

    let mut district_digits: u8 = 0;
    while idx < rest.len() && rest.get(idx).is_some_and(char::is_ascii_digit) && district_digits < 2
    {
        idx = idx.saturating_add(1);
        district_digits = district_digits.saturating_add(1);
    }
    if district_digits == 0 {
        return Err(Problem::Validation(
            "Vehicle registration must have 1-2 district digits after state code".to_string(),
        ));
    }

    let mut series_letters: u8 = 0;
    while idx < rest.len()
        && rest.get(idx).is_some_and(|c| c.is_ascii_uppercase())
        && series_letters < 3
    {
        idx = idx.saturating_add(1);
        series_letters = series_letters.saturating_add(1);
    }
    if series_letters == 0 {
        return Err(Problem::Validation(
            "Vehicle registration must have 1-3 series letters".to_string(),
        ));
    }

    let mut number_digits: u8 = 0;
    while idx < rest.len() && rest.get(idx).is_some_and(char::is_ascii_digit) && number_digits < 4 {
        idx = idx.saturating_add(1);
        number_digits = number_digits.saturating_add(1);
    }
    if number_digits == 0 {
        return Err(Problem::Validation(
            "Vehicle registration must end with 1-4 digits".to_string(),
        ));
    }

    if idx != rest.len() {
        return Err(Problem::Validation(format!(
            "Vehicle registration has trailing characters after expected format: '{}'",
            normalized
        )));
    }

    Ok(())
}

/// Check if a vehicle registration is a test/dummy pattern
#[must_use]
pub fn is_test_india_vehicle_registration(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    matches!(
        normalized.as_str(),
        "MH01AA0000" | "DL01AA0000" | "KA01AA0000" | "AA00AA0000"
    )
}

// ============================================================================
// Voter ID (EPIC) Validation
// ============================================================================

/// Validate India Voter ID (EPIC) format
///
/// Format: 3 uppercase letters (state/constituency code) + 7 digits.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_voter_id(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Voter ID cannot be empty".to_string()));
    }

    let upper = trimmed.to_uppercase();
    if upper.len() != 10 {
        return Err(Problem::Validation(format!(
            "Voter ID must be 10 characters (3 letters + 7 digits), got {}",
            upper.len()
        )));
    }

    let chars: Vec<char> = upper.chars().collect();

    for (i, &ch) in chars.iter().take(3).enumerate() {
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "Voter ID position {} must be a letter (state code), got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    for (i, &ch) in chars.iter().skip(3).take(7).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Voter ID position {} must be a digit, got '{}'",
                i.saturating_add(4),
                ch
            )));
        }
    }

    Ok(())
}

/// Check if a Voter ID is a test/dummy pattern
#[must_use]
pub fn is_test_india_voter_id(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 10 {
        return false;
    }
    matches!(
        upper.as_str(),
        "ABC0000000" | "AAA1234567" | "TST0000000" | "TEST000000"
    )
}

// ============================================================================
// Indian Passport Validation
// ============================================================================

/// Valid passport type indicators (position 0)
const VALID_INDIA_PASSPORT_TYPES: &[char] = &[
    'P', // Personal (ordinary)
    'S', // Service
    'D', // Diplomatic
];

/// Validate Indian passport format
///
/// Format: 1 uppercase type indicator (P/S/D) + 7 digits.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_passport(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Indian passport cannot be empty".to_string(),
        ));
    }

    let upper = trimmed.to_uppercase();
    if upper.len() != 8 {
        return Err(Problem::Validation(format!(
            "Indian passport must be 8 characters (letter + 7 digits), got {}",
            upper.len()
        )));
    }

    let chars: Vec<char> = upper.chars().collect();
    let type_char = chars.first().copied().unwrap_or(' ');
    if !VALID_INDIA_PASSPORT_TYPES.contains(&type_char) {
        return Err(Problem::Validation(format!(
            "Indian passport type '{}' is not valid (expected one of: {:?})",
            type_char, VALID_INDIA_PASSPORT_TYPES
        )));
    }

    for (i, &ch) in chars.iter().skip(1).take(7).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Indian passport position {} must be a digit, got '{}'",
                i.saturating_add(2),
                ch
            )));
        }
    }

    Ok(())
}

/// Check if an Indian passport is a test/dummy pattern
#[must_use]
pub fn is_test_india_passport(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 8 {
        return false;
    }
    matches!(
        upper.as_str(),
        "P0000000" | "S0000000" | "D0000000" | "P1234567"
    )
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Extract digits from a value string
fn extract_digits(value: &str) -> Result<Vec<u32>, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Aadhaar cannot be empty".to_string()));
    }

    let digits: Vec<u32> = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    Ok(digits)
}

/// Verhoeff checksum validation
///
/// For a valid number, the Verhoeff checksum should be 0 when
/// processing all digits (including the check digit) right-to-left.
fn verhoeff_validate(digits: &[u32]) -> bool {
    let mut c: u8 = 0;

    for (i, &digit) in digits.iter().rev().enumerate() {
        let p_index = i % 8;
        let p_val = VERHOEFF_P
            .get(p_index)
            .and_then(|row| row.get(digit as usize))
            .copied()
            .unwrap_or(0);
        c = VERHOEFF_D
            .get(c as usize)
            .and_then(|row| row.get(p_val as usize))
            .copied()
            .unwrap_or(0);
    }

    c == 0
}

/// Convert a base-36 char ('0'-'9', 'A'-'Z') to its numeric value (0-35)
fn char_to_base36(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        c.to_digit(10)
    } else if c.is_ascii_uppercase() {
        Some(
            u32::from(c)
                .saturating_sub(u32::from('A'))
                .saturating_add(10),
        )
    } else {
        None
    }
}

/// Convert a base-36 value (0-35) to its char ('0'-'9', 'A'-'Z')
fn base36_to_char(v: u32) -> Option<char> {
    if v < 10 {
        char::from_digit(v, 10)
    } else if v < 36 {
        char::from_u32(u32::from('A').saturating_add(v.saturating_sub(10)))
    } else {
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // Helper to compute Verhoeff check digit for a sequence
    fn verhoeff_compute_check(digits: &[u32]) -> u32 {
        // Inverse table for finding check digit
        const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

        let mut c: u8 = 0;
        // Process digits right-to-left, but shifted by 1 position (check digit at position 0)
        for (i, &digit) in digits.iter().rev().enumerate() {
            let p_index = i.saturating_add(1) % 8;
            let p_val = VERHOEFF_P
                .get(p_index)
                .and_then(|row| row.get(digit as usize))
                .copied()
                .unwrap_or(0);
            c = VERHOEFF_D
                .get(c as usize)
                .and_then(|row| row.get(p_val as usize))
                .copied()
                .unwrap_or(0);
        }

        u32::from(INV.get(c as usize).copied().unwrap_or(0))
    }

    fn make_valid_aadhaar(first_11: &str) -> String {
        let digits: Vec<u32> = first_11
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        let check = verhoeff_compute_check(&digits);
        let all_digits: String = digits
            .iter()
            .map(|d| char::from_digit(*d, 10).unwrap_or('0'))
            .collect();
        format!(
            "{} {} {}{}",
            &all_digits[..4],
            &all_digits[4..8],
            &all_digits[8..],
            check
        )
    }

    // ===== Aadhaar Tests =====

    #[test]
    fn test_validate_aadhaar_valid() {
        assert!(validate_india_aadhaar("2345 6789 0123").is_ok());
    }

    #[test]
    fn test_validate_aadhaar_rejects_start_0() {
        assert!(validate_india_aadhaar("0345 6789 0123").is_err());
    }

    #[test]
    fn test_validate_aadhaar_rejects_start_1() {
        assert!(validate_india_aadhaar("1345 6789 0123").is_err());
    }

    #[test]
    fn test_validate_aadhaar_all_valid_starts() {
        for start in 2..=9 {
            let aadhaar = format!("{start}345 6789 0123");
            assert!(
                validate_india_aadhaar(&aadhaar).is_ok(),
                "Start digit {} should be valid",
                start
            );
        }
    }

    #[test]
    fn test_validate_aadhaar_wrong_length() {
        assert!(validate_india_aadhaar("2345 6789 012").is_err()); // 11 digits
        assert!(validate_india_aadhaar("2345 6789 01234").is_err()); // 13 digits
    }

    #[test]
    fn test_validate_aadhaar_empty() {
        assert!(validate_india_aadhaar("").is_err());
    }

    #[test]
    fn test_validate_aadhaar_with_checksum_valid() {
        let aadhaar = make_valid_aadhaar("23456789012");
        assert!(
            validate_india_aadhaar_with_checksum(&aadhaar).is_ok(),
            "Valid Aadhaar should pass: {}",
            aadhaar
        );
    }

    #[test]
    fn test_validate_aadhaar_with_checksum_invalid() {
        let aadhaar = make_valid_aadhaar("23456789012");
        // Tamper with last digit
        let mut chars: Vec<char> = aadhaar.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_india_aadhaar_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_aadhaar_with_checksum_different_start() {
        let aadhaar = make_valid_aadhaar("98765432101");
        assert!(validate_india_aadhaar_with_checksum(&aadhaar).is_ok());
    }

    #[test]
    fn test_verhoeff_known_value() {
        // Verhoeff("2363" + check) should validate
        let digits = vec![2, 3, 6, 3];
        let check = verhoeff_compute_check(&digits);
        let mut full = digits;
        full.push(check);
        assert!(verhoeff_validate(&full));
    }

    #[test]
    fn test_is_test_aadhaar() {
        assert!(is_test_india_aadhaar("2222 2222 2222"));
        assert!(!is_test_india_aadhaar("2345 6789 0123"));
    }

    #[test]
    fn test_is_test_aadhaar_wrong_length() {
        assert!(!is_test_india_aadhaar("12345"));
        assert!(!is_test_india_aadhaar(""));
    }

    // ===== PAN Tests =====

    #[test]
    fn test_validate_pan_valid_person() {
        assert!(validate_india_pan("ABCPD1234E").is_ok());
    }

    #[test]
    fn test_validate_pan_valid_company() {
        assert!(validate_india_pan("ABCCD1234E").is_ok());
    }

    #[test]
    fn test_validate_pan_all_holder_types() {
        for &holder in VALID_PAN_HOLDER_TYPES {
            let pan = format!("ABC{}D1234E", holder);
            assert!(
                validate_india_pan(&pan).is_ok(),
                "Holder type {} should be valid",
                holder
            );
        }
    }

    #[test]
    fn test_validate_pan_invalid_holder_type() {
        // 'X' is not a valid holder type
        assert!(validate_india_pan("ABCXD1234E").is_err());
    }

    #[test]
    fn test_validate_pan_wrong_length() {
        assert!(validate_india_pan("ABCPD1234").is_err()); // 9 chars
        assert!(validate_india_pan("ABCPD1234EF").is_err()); // 11 chars
    }

    #[test]
    fn test_validate_pan_invalid_format() {
        assert!(validate_india_pan("12345ABCDE").is_err()); // Numbers first
        assert!(validate_india_pan("ABCDEABCDE").is_err()); // Letters where digits should be
    }

    #[test]
    fn test_validate_pan_empty() {
        assert!(validate_india_pan("").is_err());
    }

    #[test]
    fn test_validate_pan_lowercase_accepted() {
        // Should accept lowercase (converts to uppercase)
        assert!(validate_india_pan("abcpd1234e").is_ok());
    }

    #[test]
    fn test_is_test_pan() {
        assert!(is_test_india_pan("AAAAA0000A"));
        assert!(is_test_india_pan("ABCDE1234F"));
        assert!(!is_test_india_pan("ABCPD1234E"));
    }

    // ===== GSTIN Tests =====

    /// Compute valid GSTIN MOD-36 check character for given 14-char prefix
    fn compute_gstin_check(prefix14: &str) -> char {
        let chars: Vec<char> = prefix14.to_uppercase().chars().collect();
        let mut sum: u32 = 0;
        for (i, &ch) in chars.iter().take(14).enumerate() {
            let val = char_to_base36(ch).unwrap_or(0);
            let weight: u32 = if i % 2 == 0 { 1 } else { 2 };
            let product = val.saturating_mul(weight);
            let contribution = if product >= 36 {
                product
                    .checked_div(36)
                    .unwrap_or(0)
                    .saturating_add(product % 36)
            } else {
                product
            };
            sum = sum.saturating_add(contribution);
        }
        let computed = (36u32.saturating_sub(sum % 36)) % 36;
        base36_to_char(computed).unwrap_or('0')
    }

    fn make_valid_gstin(prefix14: &str) -> String {
        let check = compute_gstin_check(prefix14);
        format!("{}{}", prefix14, check)
    }

    #[test]
    fn test_validate_gstin_valid_format() {
        // Just format check (no checksum)
        let gstin = "27AAAPL1234C1Z5";
        assert!(validate_india_gstin(gstin).is_ok());
    }

    #[test]
    fn test_validate_gstin_wrong_length() {
        assert!(validate_india_gstin("27AAAPL1234C1Z").is_err()); // 14 chars
        assert!(validate_india_gstin("27AAAPL1234C1Z55").is_err()); // 16 chars
    }

    #[test]
    fn test_validate_gstin_invalid_state_code() {
        // 38 is currently not a valid state code (range 01-37 plus 99)
        assert!(validate_india_gstin("38AAAPL1234C1Z5").is_err());
        // 99 is reserved for other-territory (accepted)
        assert!(validate_india_gstin("99AAAPL1234C1Z5").is_ok());
    }

    #[test]
    fn test_validate_gstin_missing_z() {
        // Position 14 must be 'Z'
        assert!(validate_india_gstin("27AAAPL1234C1X5").is_err());
    }

    #[test]
    fn test_validate_gstin_empty() {
        assert!(validate_india_gstin("").is_err());
    }

    #[test]
    fn test_validate_gstin_with_checksum_valid() {
        let gstin = make_valid_gstin("27AAAPL1234C1Z");
        assert!(
            validate_india_gstin_with_checksum(&gstin).is_ok(),
            "Computed valid GSTIN should pass: {}",
            gstin
        );
    }

    #[test]
    fn test_validate_gstin_with_checksum_invalid() {
        let gstin = make_valid_gstin("27AAAPL1234C1Z");
        // Tamper with the check character
        let mut chars: Vec<char> = gstin.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_india_gstin_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_gstin_with_checksum_multiple_states() {
        for state in ["01", "07", "27", "29", "33", "37"] {
            let prefix = format!("{}AAAPL1234C1Z", state);
            let gstin = make_valid_gstin(&prefix);
            assert!(
                validate_india_gstin_with_checksum(&gstin).is_ok(),
                "State {} should validate: {}",
                state,
                gstin
            );
        }
    }

    #[test]
    fn test_validate_gstin_lowercase_accepted() {
        let gstin = make_valid_gstin("27AAAPL1234C1Z");
        let lower = gstin.to_lowercase();
        assert!(validate_india_gstin_with_checksum(&lower).is_ok());
    }

    #[test]
    fn test_is_test_gstin() {
        assert!(is_test_india_gstin("00AAAPL1234C1Z5"));
        assert!(is_test_india_gstin("27AAAPL1234C1Z5"));
        assert!(!is_test_india_gstin("33ABCDE1234F1Z9"));
    }

    #[test]
    fn test_char_to_base36_roundtrip() {
        for v in 0..36 {
            let c = base36_to_char(v).expect("valid base36");
            assert_eq!(char_to_base36(c), Some(v));
        }
        assert_eq!(char_to_base36('?'), None);
        assert_eq!(base36_to_char(36), None);
    }

    // ===== Vehicle Registration Tests =====

    #[test]
    fn test_validate_vehicle_reg_valid_compact() {
        // Issue's documented examples
        assert!(validate_india_vehicle_registration("MH02AB1234").is_ok());
        assert!(validate_india_vehicle_registration("DL1C1234").is_ok());
        assert!(validate_india_vehicle_registration("KA01MA1234").is_ok());
    }

    #[test]
    fn test_validate_vehicle_reg_with_spaces() {
        assert!(validate_india_vehicle_registration("MH 02 AB 1234").is_ok());
        assert!(validate_india_vehicle_registration("DL-1-C-1234").is_ok());
    }

    #[test]
    fn test_validate_vehicle_reg_state_codes() {
        // Common state codes mentioned in the issue
        for code in ["MH", "DL", "KA", "TN", "UP", "WB", "GJ", "AP"] {
            let reg = format!("{}01AB1234", code);
            assert!(
                validate_india_vehicle_registration(&reg).is_ok(),
                "State code {} should be valid",
                code
            );
        }
    }

    #[test]
    fn test_validate_vehicle_reg_empty() {
        assert!(validate_india_vehicle_registration("").is_err());
    }

    #[test]
    fn test_validate_vehicle_reg_no_letters_state() {
        // First 2 chars must be letters
        assert!(validate_india_vehicle_registration("12AB1234").is_err());
    }

    #[test]
    fn test_validate_vehicle_reg_no_digits() {
        // Must have digits in district position
        assert!(validate_india_vehicle_registration("MHABCD1234").is_err());
    }

    #[test]
    fn test_validate_vehicle_reg_too_short() {
        assert!(validate_india_vehicle_registration("MH").is_err());
        assert!(validate_india_vehicle_registration("MH1").is_err());
    }

    #[test]
    fn test_validate_vehicle_reg_trailing_chars() {
        // Trailing letters after final digits are invalid
        assert!(validate_india_vehicle_registration("MH02AB1234XYZ").is_err());
    }

    #[test]
    fn test_validate_vehicle_reg_lowercase_accepted() {
        assert!(validate_india_vehicle_registration("mh02ab1234").is_ok());
    }

    #[test]
    fn test_is_test_vehicle_reg() {
        assert!(is_test_india_vehicle_registration("MH01AA0000"));
        assert!(is_test_india_vehicle_registration("AA00AA0000"));
        assert!(!is_test_india_vehicle_registration("MH02AB1234"));
    }

    // ===== Voter ID Tests =====

    #[test]
    fn test_validate_voter_id_valid() {
        assert!(validate_india_voter_id("ABC1234567").is_ok());
        assert!(validate_india_voter_id("XYZ9876543").is_ok());
    }

    #[test]
    fn test_validate_voter_id_wrong_length() {
        assert!(validate_india_voter_id("ABC123456").is_err()); // 9
        assert!(validate_india_voter_id("ABC12345678").is_err()); // 11
    }

    #[test]
    fn test_validate_voter_id_no_letters() {
        assert!(validate_india_voter_id("1231234567").is_err());
    }

    #[test]
    fn test_validate_voter_id_no_digits() {
        assert!(validate_india_voter_id("ABCDEFGHIJ").is_err());
    }

    #[test]
    fn test_validate_voter_id_empty() {
        assert!(validate_india_voter_id("").is_err());
    }

    #[test]
    fn test_validate_voter_id_lowercase_accepted() {
        assert!(validate_india_voter_id("abc1234567").is_ok());
    }

    #[test]
    fn test_is_test_voter_id() {
        assert!(is_test_india_voter_id("ABC0000000"));
        assert!(!is_test_india_voter_id("ABC1234567"));
    }

    // ===== Indian Passport Tests =====

    #[test]
    fn test_validate_india_passport_personal() {
        assert!(validate_india_passport("P1234567").is_ok());
    }

    #[test]
    fn test_validate_india_passport_service() {
        assert!(validate_india_passport("S1234567").is_ok());
    }

    #[test]
    fn test_validate_india_passport_diplomatic() {
        assert!(validate_india_passport("D1234567").is_ok());
    }

    #[test]
    fn test_validate_india_passport_invalid_type() {
        // Only P, S, D are valid type indicators
        assert!(validate_india_passport("A1234567").is_err());
        assert!(validate_india_passport("Z1234567").is_err());
    }

    #[test]
    fn test_validate_india_passport_wrong_length() {
        assert!(validate_india_passport("P123456").is_err()); // 7 chars
        assert!(validate_india_passport("P12345678").is_err()); // 9 chars
    }

    #[test]
    fn test_validate_india_passport_no_digits() {
        assert!(validate_india_passport("PABCDEFG").is_err());
    }

    #[test]
    fn test_validate_india_passport_empty() {
        assert!(validate_india_passport("").is_err());
    }

    #[test]
    fn test_validate_india_passport_lowercase_accepted() {
        assert!(validate_india_passport("p1234567").is_ok());
    }

    #[test]
    fn test_is_test_india_passport() {
        assert!(is_test_india_passport("P0000000"));
        assert!(is_test_india_passport("P1234567"));
        assert!(!is_test_india_passport("P9876543"));
    }
}
