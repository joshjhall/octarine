//! South Korea Driver License validation
//!
//! Format: `NN-NN-NNNNNN-NN` — region (2) + year (2) + serial (6) + check (2).
//! The first two digits are a region code in `11..=28` (Seoul=11, Busan=21,
//! Incheon=22, etc.).
//!
//! The issue spec does not define a public checksum algorithm for the trailing
//! two check digits, so only format and region validation are enforced here.

use crate::primitives::types::Problem;

const DL_DIGIT_COUNT: usize = 12;

/// Valid Korean driver-license region codes (11-28)
const VALID_REGIONS: std::ops::RangeInclusive<u32> = 11..=28;

/// Validate South Korea Driver License format
///
/// Checks:
/// - Exactly 12 digits (dashes optional)
/// - Region code (first two digits) in `11..=28`
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or region is invalid.
pub fn validate_korea_driver_license(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;
    validate_region(&digits)?;
    Ok(())
}

/// Check if a Korea Driver License is a test/dummy pattern
#[must_use]
pub fn is_test_korea_driver_license(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();

    if clean.len() != DL_DIGIT_COUNT {
        return false;
    }

    if let Some(first) = clean.chars().next()
        && clean.chars().all(|c| c == first)
    {
        return true;
    }

    if clean.chars().all(|c| c == '0') {
        return true;
    }

    if clean == "123456789012" {
        return true;
    }

    false
}

// ============================================================================
// Private Helpers
// ============================================================================

fn extract_digits(value: &str) -> Result<Vec<u32>, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Korea Driver License cannot be empty".to_string(),
        ));
    }

    let digits: Vec<u32> = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != DL_DIGIT_COUNT {
        return Err(Problem::Validation(format!(
            "Korea Driver License must contain exactly {} digits, got {}",
            DL_DIGIT_COUNT,
            digits.len()
        )));
    }

    Ok(digits)
}

fn validate_region(digits: &[u32]) -> Result<(), Problem> {
    let region = digits
        .first()
        .copied()
        .unwrap_or(0)
        .saturating_mul(10)
        .saturating_add(digits.get(1).copied().unwrap_or(0));

    if !VALID_REGIONS.contains(&region) {
        return Err(Problem::Validation(format!(
            "Korea Driver License region code must be in {}-{}, got {:02}",
            VALID_REGIONS.start(),
            VALID_REGIONS.end(),
            region
        )));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_korea_driver_license_valid() {
        assert!(validate_korea_driver_license("11-90-123456-78").is_ok());
        assert!(validate_korea_driver_license("28-95-654321-99").is_ok());
    }

    #[test]
    fn test_validate_korea_driver_license_without_dashes() {
        assert!(validate_korea_driver_license("119012345678").is_ok());
    }

    #[test]
    fn test_validate_korea_driver_license_all_regions() {
        for region in 11..=28 {
            let dl = format!("{:02}-90-123456-78", region);
            assert!(
                validate_korea_driver_license(&dl).is_ok(),
                "Region {} should be valid",
                region
            );
        }
    }

    #[test]
    fn test_validate_korea_driver_license_invalid_region_low() {
        assert!(validate_korea_driver_license("10-90-123456-78").is_err());
        assert!(validate_korea_driver_license("00-90-123456-78").is_err());
    }

    #[test]
    fn test_validate_korea_driver_license_invalid_region_high() {
        assert!(validate_korea_driver_license("29-90-123456-78").is_err());
        assert!(validate_korea_driver_license("99-90-123456-78").is_err());
    }

    #[test]
    fn test_validate_korea_driver_license_empty() {
        assert!(validate_korea_driver_license("").is_err());
    }

    #[test]
    fn test_validate_korea_driver_license_wrong_length() {
        assert!(validate_korea_driver_license("11-90-123456-7").is_err());
        assert!(validate_korea_driver_license("11-90-123456-789").is_err());
    }

    #[test]
    fn test_is_test_korea_driver_license() {
        assert!(is_test_korea_driver_license("111111111111"));
        assert!(is_test_korea_driver_license("000000000000"));
        assert!(is_test_korea_driver_license("123456789012"));
        assert!(!is_test_korea_driver_license("11-90-123456-78"));
    }
}
