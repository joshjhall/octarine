//! US Individual Taxpayer Identification Number (ITIN) validation
//!
//! Pure validation functions for IRS-issued ITINs (26 CFR §301.6109-1).
//!
//! # ITIN Format
//!
//! ITINs share the SSN visual layout `XXX-XX-XXXX` but are distinguished by:
//!
//! - **Area**: always `9XX` (`900-999`)
//! - **Middle group**: must be in `{50-65, 70-88, 90-92, 94-99}`
//! - **Serial**: `0001-9999` (`0000` is reserved)
//!
//! The middle-group rule is the load-bearing constraint that separates a real
//! ITIN from "any 9-digit number that starts with 9". Without it, arbitrary
//! identifiers (sequence numbers, hashes) get misclassified.
//!
//! # Authoritative References
//!
//! - IRS Publication 1915 (Understanding Your IRS Individual Taxpayer
//!   Identification Number)
//! - 26 CFR §301.6109-1
//! - Presidio `us_itin_recognizer.py` (cross-reference for the same rule)

use crate::primitives::Problem;

/// Check if an ITIN middle group is in the IRS-assigned range.
///
/// The IRS reserves three blocks within `00-99` for ITIN middle groups:
/// `50-65`, `70-88`, `90-92`, `94-99`. Anything else is a non-ITIN value
/// even if the area is `9XX`.
#[must_use]
pub fn is_valid_itin_group(group: u8) -> bool {
    matches!(
        group,
        50..=65 | 70..=88 | 90..=92 | 94..=99
    )
}

/// Validate an ITIN.
///
/// Enforces format, area, middle-group, and serial constraints. Returns
/// `Ok(())` only for values the IRS could have assigned as an ITIN.
///
/// # Errors
///
/// Returns `Problem::Validation` for any of:
///
/// - Wrong digit count or non-`XXX-XX-XXXX`/`XXXXXXXXX` layout
/// - Area outside `900-999`
/// - Middle group outside `{50-65, 70-88, 90-92, 94-99}`
/// - Serial `0000`
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_itin("900-70-0001").is_ok());
/// assert!(validation::validate_itin("999-88-1234").is_ok());
/// assert!(validation::validate_itin("912-34-5678").is_err()); // group 34 not in IRS range
/// assert!(validation::validate_itin("899-70-0001").is_err()); // area not 9XX
/// ```
pub fn validate_itin(itin: &str) -> Result<(), Problem> {
    let cleaned: String = itin.chars().filter(|c| c.is_ascii_digit()).collect();

    if cleaned.len() != 9 {
        return Err(Problem::Validation("ITIN must be 9 digits".into()));
    }

    // Reject layouts that aren't either bare 9 digits or XXX-XX-XXXX. Allowing
    // arbitrary dash positions (e.g., 1-23-456789) would silently accept
    // SSN/EIN shapes.
    let bare_digits = itin.chars().all(|c| c.is_ascii_digit());
    let dashed = {
        let parts: Vec<&str> = itin.split('-').collect();
        parts.len() == 3
            && parts.first().is_some_and(|p| p.len() == 3)
            && parts.get(1).is_some_and(|p| p.len() == 2)
            && parts.get(2).is_some_and(|p| p.len() == 4)
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
    };
    if !bare_digits && !dashed {
        return Err(Problem::Validation(
            "ITIN format must be XXX-XX-XXXX".into(),
        ));
    }

    let area: u16 = cleaned[0..3]
        .parse()
        .map_err(|_| Problem::Validation("Invalid ITIN area".into()))?;
    let group: u8 = cleaned[3..5]
        .parse()
        .map_err(|_| Problem::Validation("Invalid ITIN middle group".into()))?;
    let serial = &cleaned[5..9];

    if !(900..=999).contains(&area) {
        return Err(Problem::Validation(format!(
            "ITIN area must be 900-999, got {area}"
        )));
    }

    if !is_valid_itin_group(group) {
        return Err(Problem::Validation(format!(
            "Invalid ITIN middle group: {group:02} (must be 50-65, 70-88, 90-92, or 94-99)"
        )));
    }

    if serial == "0000" {
        return Err(Problem::Validation("ITIN serial 0000 is reserved".into()));
    }

    Ok(())
}

/// Check if an ITIN is a known test/sample pattern.
///
/// IRS Publication 1915 does not publish ITIN test ranges (unlike Brookhaven's
/// EIN examples), so this list is conservative: only repeated-digit and
/// obviously synthetic strings are flagged.
#[must_use]
pub fn is_test_itin(itin: &str) -> bool {
    let cleaned: String = itin.chars().filter(|c| c.is_ascii_digit()).collect();

    if cleaned.len() != 9 || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // All same digit (e.g., 999-99-9999) — flagged even though 9 in the middle
    // group is valid, because real ITINs don't repeat.
    if let Some(first) = cleaned.chars().next()
        && cleaned.chars().all(|c| c == first)
    {
        return true;
    }

    // Documentation placeholders observed in Presidio test fixtures.
    let test_itins = ["999991234"];
    test_itins.contains(&cleaned.as_str())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_itin_accepts_valid_middle_groups() {
        // One sample from each IRS block
        assert!(validate_itin("900-50-0001").is_ok()); // start of 50-65
        assert!(validate_itin("900-65-0001").is_ok()); // end of 50-65
        assert!(validate_itin("900-70-0001").is_ok()); // start of 70-88
        assert!(validate_itin("900-88-0001").is_ok()); // end of 70-88
        assert!(validate_itin("900-90-0001").is_ok()); // start of 90-92
        assert!(validate_itin("900-92-0001").is_ok()); // end of 90-92
        assert!(validate_itin("900-94-0001").is_ok()); // start of 94-99
        assert!(validate_itin("900-99-0001").is_ok()); // end of 94-99
    }

    #[test]
    fn test_validate_itin_rejects_gap_middle_groups() {
        // Gaps between IRS-assigned ranges
        assert!(validate_itin("900-01-0001").is_err()); // before 50
        assert!(validate_itin("900-49-0001").is_err()); // just before 50
        assert!(validate_itin("900-66-0001").is_err()); // gap between 65 and 70
        assert!(validate_itin("900-69-0001").is_err()); // gap between 65 and 70
        assert!(validate_itin("900-89-0001").is_err()); // gap between 88 and 90
        assert!(validate_itin("900-93-0001").is_err()); // gap between 92 and 94
    }

    #[test]
    fn test_validate_itin_rejects_non_itin_area() {
        // Area must be 900-999
        assert!(validate_itin("123-70-0001").is_err()); // SSN range
        assert!(validate_itin("517-70-0001").is_err()); // SSN range
        assert!(validate_itin("899-70-0001").is_err()); // just below ITIN
    }

    #[test]
    fn test_validate_itin_rejects_serial_zero() {
        assert!(validate_itin("900-70-0000").is_err());
    }

    #[test]
    fn test_validate_itin_format_errors() {
        // 9-digit bare format is accepted
        assert!(validate_itin("900700001").is_ok());
        // Wrong layout
        assert!(validate_itin("12-345-6789").is_err());
        assert!(validate_itin("1234-56-789").is_err());
        // Wrong digit count
        assert!(validate_itin("900-70-001").is_err());
        assert!(validate_itin("900-70-00012").is_err());
        // Letters
        assert!(validate_itin("ABC-70-0001").is_err());
        // Empty
        assert!(validate_itin("").is_err());
    }

    #[test]
    fn test_validate_itin_issue_acceptance_criteria() {
        // From issue #425: "912-34-5678 rejected" because middle group 34 is
        // outside the IRS-assigned range. The issue's "accepted by
        // validate_itin" line is incorrect — middle group 34 is NOT valid.
        assert!(validate_itin("912-34-5678").is_err());
        // "999-93-1234" rejected per IRS rule (group 93 is in the gap).
        assert!(validate_itin("999-93-1234").is_err());
        // Regular SSN area still rejected by validate_itin (area not 9XX).
        assert!(validate_itin("123-45-6789").is_err());
    }

    #[test]
    fn test_is_valid_itin_group_helper() {
        for g in 50..=65 {
            assert!(is_valid_itin_group(g), "{g} should be valid");
        }
        for g in 70..=88 {
            assert!(is_valid_itin_group(g), "{g} should be valid");
        }
        for g in 90..=92 {
            assert!(is_valid_itin_group(g), "{g} should be valid");
        }
        for g in 94..=99 {
            assert!(is_valid_itin_group(g), "{g} should be valid");
        }
        // Gaps
        for g in [0, 1, 49, 66, 69, 89, 93] {
            assert!(!is_valid_itin_group(g), "{g} should be invalid");
        }
    }

    #[test]
    fn test_is_test_itin() {
        assert!(is_test_itin("999-99-9999")); // all same digit
        assert!(!is_test_itin("900-70-0001"));
        assert!(!is_test_itin("900-70-1234"));
        assert!(!is_test_itin(""));
    }
}
