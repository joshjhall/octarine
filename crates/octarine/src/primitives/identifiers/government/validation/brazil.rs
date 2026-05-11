//! Brazil CPF and CNPJ validation
//!
//! - CPF (Cadastro de Pessoas Físicas): 11 digits with mod-11 dual check digits.
//!   Format `NNN.NNN.NNN-NN` or 11 plain digits.
//! - CNPJ (Cadastro Nacional da Pessoa Jurídica): 14 digits with mod-11 dual
//!   check digits using fixed weight sequences. Format `NN.NNN.NNN/NNNN-NN`
//!   or 14 plain digits.
//!
//! Both formats reject all-same-digit inputs (e.g. `111.111.111-11`) — the
//! Brazilian Federal Revenue Service explicitly excludes those even though
//! the mod-11 math would otherwise validate them.

use crate::primitives::types::Problem;

// ============================================================================
// CPF Validation
// ============================================================================

/// Validate Brazil CPF format (without checksum)
///
/// Checks: 11 digits, not all the same digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_brazil_cpf(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    if digits.len() != 11 {
        return Err(Problem::Validation(format!(
            "CPF must be 11 digits, got {}",
            digits.len()
        )));
    }

    if all_same_digit(&digits) {
        return Err(Problem::Validation(
            "CPF cannot have all identical digits".to_string(),
        ));
    }

    Ok(())
}

/// Validate Brazil CPF with mod-11 dual check digits
///
/// First check digit weight sequence: 10, 9, 8, 7, 6, 5, 4, 3, 2.
/// Second check digit weight sequence: 11, 10, 9, 8, 7, 6, 5, 4, 3, 2.
/// Each check digit: `let r = sum % 11; if r < 2 { 0 } else { 11 - r }`.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or checksum is invalid.
pub fn validate_brazil_cpf_with_checksum(value: &str) -> Result<(), Problem> {
    validate_brazil_cpf(value)?;

    let digits = extract_digits(value)?;

    let d10 = cpf_check_digit(&digits, 0, 9, 10);
    if digits.get(9).copied() != Some(d10) {
        return Err(Problem::Validation(
            "CPF first check digit mismatch".to_string(),
        ));
    }

    let d11 = cpf_check_digit(&digits, 0, 10, 11);
    if digits.get(10).copied() != Some(d11) {
        return Err(Problem::Validation(
            "CPF second check digit mismatch".to_string(),
        ));
    }

    Ok(())
}

/// Check if a CPF is a test/dummy pattern (all-same-digit)
#[must_use]
pub fn is_test_brazil_cpf(value: &str) -> bool {
    let Ok(digits) = extract_digits(value) else {
        return false;
    };
    digits.len() == 11 && all_same_digit(&digits)
}

// ============================================================================
// CNPJ Validation
// ============================================================================

/// Validate Brazil CNPJ format (without checksum)
///
/// Checks: 14 digits, not all the same digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_brazil_cnpj(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    if digits.len() != 14 {
        return Err(Problem::Validation(format!(
            "CNPJ must be 14 digits, got {}",
            digits.len()
        )));
    }

    if all_same_digit(&digits) {
        return Err(Problem::Validation(
            "CNPJ cannot have all identical digits".to_string(),
        ));
    }

    Ok(())
}

/// Validate Brazil CNPJ with mod-11 dual check digits
///
/// First check digit weights: 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2.
/// Second check digit weights: 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or checksum is invalid.
pub fn validate_brazil_cnpj_with_checksum(value: &str) -> Result<(), Problem> {
    validate_brazil_cnpj(value)?;

    let digits = extract_digits(value)?;

    const W1: [u32; 12] = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const W2: [u32; 13] = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

    let first_12 = digits.get(..12).unwrap_or(&[]);
    let d13 = mod11_check_digit(first_12, &W1);
    if digits.get(12).copied() != Some(d13) {
        return Err(Problem::Validation(
            "CNPJ first check digit mismatch".to_string(),
        ));
    }

    let first_13 = digits.get(..13).unwrap_or(&[]);
    let d14 = mod11_check_digit(first_13, &W2);
    if digits.get(13).copied() != Some(d14) {
        return Err(Problem::Validation(
            "CNPJ second check digit mismatch".to_string(),
        ));
    }

    Ok(())
}

/// Check if a CNPJ is a test/dummy pattern (all-same-digit)
#[must_use]
pub fn is_test_brazil_cnpj(value: &str) -> bool {
    let Ok(digits) = extract_digits(value) else {
        return false;
    };
    digits.len() == 14 && all_same_digit(&digits)
}

// ============================================================================
// Helpers
// ============================================================================

fn extract_digits(value: &str) -> Result<Vec<u8>, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("input cannot be empty".to_string()));
    }

    // Reject characters that aren't digits, separators, or whitespace.
    for ch in trimmed.chars() {
        if !ch.is_ascii_digit() && !matches!(ch, '.' | '-' | '/' | ' ' | '\t') {
            return Err(Problem::Validation(format!(
                "invalid character '{ch}' in identifier"
            )));
        }
    }

    let digits: Vec<u8> = trimmed
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    Ok(digits)
}

fn all_same_digit(digits: &[u8]) -> bool {
    digits
        .first()
        .is_some_and(|&first| digits.iter().all(|&d| d == first))
}

/// Compute a CPF check digit over `digits[start..start+len]` using descending
/// weights from `start_weight` down to 2.
fn cpf_check_digit(digits: &[u8], start: usize, len: usize, start_weight: u32) -> u8 {
    let mut sum: u32 = 0;
    for i in 0..len {
        let Some(&d) = digits.get(start.saturating_add(i)) else {
            continue;
        };
        let weight = start_weight.saturating_sub(i as u32);
        sum = sum.saturating_add(u32::from(d).saturating_mul(weight));
    }
    let remainder = sum.checked_rem(11).unwrap_or(0);
    if remainder < 2 {
        0
    } else {
        u8::try_from(11_u32.saturating_sub(remainder)).unwrap_or(0)
    }
}

/// Compute a mod-11 check digit over `digits` with fixed `weights`.
fn mod11_check_digit(digits: &[u8], weights: &[u32]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &d) in digits.iter().enumerate() {
        let weight = weights.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(u32::from(d).saturating_mul(weight));
    }
    let remainder = sum.checked_rem(11).unwrap_or(0);
    if remainder < 2 {
        0
    } else {
        u8::try_from(11_u32.saturating_sub(remainder)).unwrap_or(0)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_valid_cpf(first_9: &str) -> String {
        let digits: Vec<u8> = first_9
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();
        assert_eq!(digits.len(), 9, "make_valid_cpf needs 9 digits");
        let mut all = digits.clone();
        let d10 = cpf_check_digit(&all, 0, 9, 10);
        all.push(d10);
        let d11 = cpf_check_digit(&all, 0, 10, 11);
        all.push(d11);
        let s: String = all
            .iter()
            .map(|d| char::from_digit(u32::from(*d), 10).unwrap_or('0'))
            .collect();
        format!("{}.{}.{}-{}", &s[..3], &s[3..6], &s[6..9], &s[9..])
    }

    fn make_valid_cnpj(first_12: &str) -> String {
        let digits: Vec<u8> = first_12
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();
        assert_eq!(digits.len(), 12, "make_valid_cnpj needs 12 digits");
        const W1: [u32; 12] = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        const W2: [u32; 13] = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        let mut all = digits.clone();
        let d13 = mod11_check_digit(&all, &W1);
        all.push(d13);
        let d14 = mod11_check_digit(&all, &W2);
        all.push(d14);
        let s: String = all
            .iter()
            .map(|d| char::from_digit(u32::from(*d), 10).unwrap_or('0'))
            .collect();
        format!(
            "{}.{}.{}/{}-{}",
            &s[..2],
            &s[2..5],
            &s[5..8],
            &s[8..12],
            &s[12..]
        )
    }

    // ===== CPF Format Tests =====

    #[test]
    fn test_validate_cpf_formatted_accepted() {
        assert!(validate_brazil_cpf("123.456.789-09").is_ok());
    }

    #[test]
    fn test_validate_cpf_unformatted_accepted() {
        assert!(validate_brazil_cpf("12345678909").is_ok());
    }

    #[test]
    fn test_validate_cpf_rejects_wrong_length() {
        assert!(validate_brazil_cpf("1234567890").is_err()); // 10
        assert!(validate_brazil_cpf("123456789012").is_err()); // 12
    }

    #[test]
    fn test_validate_cpf_rejects_empty() {
        assert!(validate_brazil_cpf("").is_err());
        assert!(validate_brazil_cpf("   ").is_err());
    }

    #[test]
    fn test_validate_cpf_rejects_invalid_chars() {
        assert!(validate_brazil_cpf("123abc78909").is_err());
    }

    #[test]
    fn test_validate_cpf_rejects_all_same() {
        assert!(validate_brazil_cpf("111.111.111-11").is_err());
        assert!(validate_brazil_cpf("00000000000").is_err());
    }

    // ===== CPF Checksum Tests =====

    #[test]
    fn test_validate_cpf_with_checksum_canonical() {
        // Known valid test CPF from public sources
        assert!(validate_brazil_cpf_with_checksum("111.444.777-35").is_ok());
    }

    #[test]
    fn test_validate_cpf_with_checksum_generated() {
        let cpf = make_valid_cpf("123456789");
        assert!(
            validate_brazil_cpf_with_checksum(&cpf).is_ok(),
            "generated CPF {cpf} should validate"
        );
    }

    #[test]
    fn test_validate_cpf_with_checksum_tampered_first_check() {
        let cpf = make_valid_cpf("123456789");
        let mut chars: Vec<char> = cpf.chars().collect();
        // Tamper digit at position 12 (the first check digit, after the dash)
        let dash_pos = cpf.find('-').expect("formatted CPF contains a dash");
        let target = dash_pos.saturating_add(1);
        if let Some(c) = chars.get_mut(target) {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(
            validate_brazil_cpf_with_checksum(&tampered).is_err(),
            "tampered CPF {tampered} should fail"
        );
    }

    #[test]
    fn test_validate_cpf_with_checksum_tampered_second_check() {
        let cpf = make_valid_cpf("123456789");
        // Flip the last digit
        let mut chars: Vec<char> = cpf.chars().collect();
        if let Some(c) = chars.last_mut() {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_brazil_cpf_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_cpf_with_checksum_all_same_rejected() {
        // Even though the mod-11 math would technically pass for some all-same
        // CPFs, the spec excludes them.
        assert!(validate_brazil_cpf_with_checksum("111.111.111-11").is_err());
        assert!(validate_brazil_cpf_with_checksum("222.222.222-22").is_err());
    }

    // ===== CPF Test Pattern Tests =====

    #[test]
    fn test_is_test_brazil_cpf_detects_all_same() {
        assert!(is_test_brazil_cpf("111.111.111-11"));
        assert!(is_test_brazil_cpf("00000000000"));
    }

    #[test]
    fn test_is_test_brazil_cpf_rejects_real() {
        assert!(!is_test_brazil_cpf("111.444.777-35"));
    }

    #[test]
    fn test_is_test_brazil_cpf_rejects_wrong_length() {
        assert!(!is_test_brazil_cpf("111"));
    }

    // ===== CNPJ Format Tests =====

    #[test]
    fn test_validate_cnpj_formatted_accepted() {
        assert!(validate_brazil_cnpj("11.222.333/0001-81").is_ok());
    }

    #[test]
    fn test_validate_cnpj_unformatted_accepted() {
        assert!(validate_brazil_cnpj("11222333000181").is_ok());
    }

    #[test]
    fn test_validate_cnpj_rejects_wrong_length() {
        assert!(validate_brazil_cnpj("123").is_err());
        assert!(validate_brazil_cnpj("123456789012345").is_err()); // 15
    }

    #[test]
    fn test_validate_cnpj_rejects_empty() {
        assert!(validate_brazil_cnpj("").is_err());
    }

    #[test]
    fn test_validate_cnpj_rejects_all_same() {
        assert!(validate_brazil_cnpj("11.111.111/1111-11").is_err());
    }

    // ===== CNPJ Checksum Tests =====

    #[test]
    fn test_validate_cnpj_with_checksum_canonical() {
        // Known valid public test CNPJ
        assert!(validate_brazil_cnpj_with_checksum("11.222.333/0001-81").is_ok());
    }

    #[test]
    fn test_validate_cnpj_with_checksum_generated() {
        let cnpj = make_valid_cnpj("112223330001");
        assert!(
            validate_brazil_cnpj_with_checksum(&cnpj).is_ok(),
            "generated CNPJ {cnpj} should validate"
        );
    }

    #[test]
    fn test_validate_cnpj_with_checksum_tampered() {
        let cnpj = make_valid_cnpj("112223330001");
        let mut chars: Vec<char> = cnpj.chars().collect();
        if let Some(c) = chars.last_mut() {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_brazil_cnpj_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_cnpj_with_checksum_all_same_rejected() {
        assert!(validate_brazil_cnpj_with_checksum("11.111.111/1111-11").is_err());
    }

    // ===== CNPJ Test Pattern Tests =====

    #[test]
    fn test_is_test_brazil_cnpj_detects_all_same() {
        assert!(is_test_brazil_cnpj("11.111.111/1111-11"));
        assert!(is_test_brazil_cnpj("00000000000000"));
    }

    #[test]
    fn test_is_test_brazil_cnpj_rejects_real() {
        assert!(!is_test_brazil_cnpj("11.222.333/0001-81"));
    }

    // ===== Round-Trip Tests =====

    #[test]
    fn test_cpf_round_trip_multiple_seeds() {
        for seed in &["123456789", "987654321", "111222333", "456789012"] {
            let cpf = make_valid_cpf(seed);
            assert!(
                validate_brazil_cpf_with_checksum(&cpf).is_ok(),
                "CPF from seed {seed} -> {cpf} should validate"
            );
        }
    }

    #[test]
    fn test_cnpj_round_trip_multiple_seeds() {
        for seed in &["112223330001", "987654321000", "456789012345"] {
            let cnpj = make_valid_cnpj(seed);
            assert!(
                validate_brazil_cnpj_with_checksum(&cnpj).is_ok(),
                "CNPJ from seed {seed} -> {cnpj} should validate"
            );
        }
    }
}
