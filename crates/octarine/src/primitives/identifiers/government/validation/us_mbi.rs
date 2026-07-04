//! US Medicare Beneficiary Identifier (MBI) validation.
//!
//! Pure validation for the CMS-issued MBI that replaced SSN-based Health
//! Insurance Claim Numbers (HICNs) on Medicare cards in 2018.
//!
//! # MBI Format
//!
//! An MBI is exactly 11 characters with a fixed positional structure
//! (`C A AN N A AN N A A N N`):
//!
//! ```text
//! Pos:     1  2   3  4  5   6  7  8  9 10 11
//!   C / N  (pos 1,4,7,10,11) = numeric 0-9
//!   A      (pos 2,5,8,9)     = letter from ACDEFGHJKMNPQRTUVWXY
//!   AN     (pos 3,6)         = numeric OR that same restricted letter set
//! ```
//!
//! The letter alphabet **excludes `S, L, O, I, B, Z`** to avoid visual
//! confusion with digits. The dashed display form is `XXXX-XXX-XXXX`.
//!
//! The positional + excluded-letter rule is the load-bearing constraint that
//! separates a real MBI from "any 11-character alphanumeric string". Without
//! it, arbitrary identifiers get misclassified as Medicare PHI.
//!
//! # Authoritative References
//!
//! - CMS "Understanding the New Medicare Beneficiary Identifier (MBI)"
//! - Presidio `us_mbi_recognizer.py` (cross-reference for the same rule)

use crate::primitives::Problem;

/// The valid MBI letter alphabet: A-Z excluding `S, L, O, I, B, Z`.
const VALID_LETTERS: [char; 20] = [
    'A', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'U', 'V', 'W', 'X',
    'Y',
];

/// Position kind within the fixed 11-character MBI layout.
#[derive(Clone, Copy)]
enum PosKind {
    /// Numeric only (`0-9`).
    Numeric,
    /// Letter from [`VALID_LETTERS`].
    Alpha,
    /// Numeric or a valid letter.
    Alphanumeric,
}

/// The 11 position kinds in order (`C A AN N A AN N A A N N`).
const LAYOUT: [PosKind; 11] = [
    PosKind::Numeric,      // 1
    PosKind::Alpha,        // 2
    PosKind::Alphanumeric, // 3
    PosKind::Numeric,      // 4
    PosKind::Alpha,        // 5
    PosKind::Alphanumeric, // 6
    PosKind::Numeric,      // 7
    PosKind::Alpha,        // 8
    PosKind::Alpha,        // 9
    PosKind::Numeric,      // 10
    PosKind::Numeric,      // 11
];

/// Check whether a character is a valid MBI letter (excluded set removed).
#[must_use]
pub fn is_valid_mbi_letter(c: char) -> bool {
    VALID_LETTERS.contains(&c)
}

/// Validate a US Medicare Beneficiary Identifier (MBI).
///
/// Accepts either the bare 11-character form or the dashed `XXXX-XXX-XXXX`
/// display form. Enforces the full CMS positional layout and the restricted
/// letter alphabet. Returns `Ok(())` only for values CMS could have assigned.
///
/// # Errors
///
/// Returns `Problem::Validation` for any of:
///
/// - Wrong character count (not 11 after removing dashes)
/// - A dashed value whose dashes are not in the `XXXX-XXX-XXXX` positions
/// - A numeric position holding a non-digit
/// - An alphabetic position holding a non-letter or an excluded letter
///   (`S, L, O, I, B, Z`)
/// - An alphanumeric position holding neither a digit nor a valid letter
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_us_mbi("1EG4TE5MK73").is_ok());
/// assert!(validation::validate_us_mbi("1EG4-TE5-MK73").is_ok());
/// assert!(validation::validate_us_mbi("1AB2C3D4EF5").is_err()); // B excluded, F must be numeric
/// ```
pub fn validate_us_mbi(value: &str) -> Result<(), Problem> {
    // Accept the dashed display form only in its exact positions; any other
    // dash placement is rejected rather than silently stripped (which would
    // otherwise accept malformed groupings).
    let uppercased = value.to_ascii_uppercase();
    let cleaned: String = if uppercased.contains('-') {
        let parts: Vec<&str> = uppercased.split('-').collect();
        let well_formed = parts.len() == 3
            && parts.first().is_some_and(|p| p.len() == 4)
            && parts.get(1).is_some_and(|p| p.len() == 3)
            && parts.get(2).is_some_and(|p| p.len() == 4);
        if !well_formed {
            return Err(Problem::Validation(
                "MBI dashed form must be XXXX-XXX-XXXX".into(),
            ));
        }
        parts.concat()
    } else {
        uppercased
    };

    if cleaned.chars().count() != 11 {
        return Err(Problem::Validation(
            "MBI must be 11 characters (excluding dashes)".into(),
        ));
    }

    for (idx, (c, kind)) in cleaned.chars().zip(LAYOUT.iter()).enumerate() {
        let position = idx.saturating_add(1);
        match kind {
            PosKind::Numeric => {
                if !c.is_ascii_digit() {
                    return Err(Problem::Validation(format!(
                        "MBI position {position} must be numeric, got '{c}'"
                    )));
                }
            }
            PosKind::Alpha => {
                if !is_valid_mbi_letter(c) {
                    return Err(Problem::Validation(format!(
                        "MBI position {position} must be a letter excluding S,L,O,I,B,Z, got '{c}'"
                    )));
                }
            }
            PosKind::Alphanumeric => {
                if !c.is_ascii_digit() && !is_valid_mbi_letter(c) {
                    return Err(Problem::Validation(format!(
                        "MBI position {position} must be a digit or a letter excluding S,L,O,I,B,Z, got '{c}'"
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Check whether an MBI is an obvious test/placeholder pattern.
///
/// CMS does not publish reserved MBI test ranges, so this is conservative:
/// only flags values whose numeric and alphabetic positions are each a single
/// repeated character (e.g. `1A1A1A1A1A1`-style synthetic strings). Returns
/// `false` for anything that is not a structurally valid MBI.
#[must_use]
pub fn is_test_us_mbi(value: &str) -> bool {
    if validate_us_mbi(value).is_err() {
        return false;
    }
    let cleaned: String = value
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let digits: Vec<char> = cleaned.chars().filter(char::is_ascii_digit).collect();
    let letters: Vec<char> = cleaned.chars().filter(|c| !c.is_ascii_digit()).collect();

    let all_same = |chars: &[char]| -> bool {
        chars
            .first()
            .is_some_and(|first| chars.iter().all(|c| c == first))
    };

    all_same(&digits) && all_same(&letters)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_us_mbi_accepts_valid() {
        // CMS-shaped valid example (Presidio's documented sample).
        assert!(validate_us_mbi("1EG4TE5MK73").is_ok());
        assert!(validate_us_mbi("1EG4-TE5-MK73").is_ok());
        // Lowercase is normalized.
        assert!(validate_us_mbi("1eg4te5mk73").is_ok());
    }

    #[test]
    fn test_validate_us_mbi_rejects_excluded_letters() {
        // The issue's fixture "1AB2C3D4EF5" is INVALID: 'B' (pos 3) is an
        // excluded letter, and even ignoring that 'F' (pos 10) must be numeric.
        assert!(validate_us_mbi("1AB2C3D4EF5").is_err());
        // Each excluded letter placed in an alpha position is rejected.
        for bad in ['S', 'L', 'O', 'I', 'B', 'Z'] {
            let candidate = format!("1{bad}G4TE5MK73");
            assert!(
                validate_us_mbi(&candidate).is_err(),
                "excluded letter {bad} at pos 2 must be rejected"
            );
        }
    }

    #[test]
    fn test_validate_us_mbi_rejects_wrong_layout() {
        // Starts with a letter (position 1 must be numeric).
        assert!(validate_us_mbi("AEG4TE5MK73").is_err());
        // Position 2 numeric where a letter is required.
        assert!(validate_us_mbi("11G4TE5MK73").is_err());
        // Position 10/11 letters where digits are required.
        assert!(validate_us_mbi("1EG4TE5MKAA").is_err());
    }

    #[test]
    fn test_validate_us_mbi_rejects_bad_length_and_dashes() {
        assert!(validate_us_mbi("1EG4TE5MK7").is_err()); // 10 chars
        assert!(validate_us_mbi("1EG4TE5MK733").is_err()); // 12 chars
        assert!(validate_us_mbi("1EG-4TE5-MK73").is_err()); // wrong dash grouping
        assert!(validate_us_mbi("").is_err());
    }

    #[test]
    fn test_is_valid_mbi_letter() {
        assert!(is_valid_mbi_letter('A'));
        assert!(is_valid_mbi_letter('Y'));
        for excluded in ['S', 'L', 'O', 'I', 'B', 'Z'] {
            assert!(!is_valid_mbi_letter(excluded));
        }
    }

    #[test]
    fn test_is_test_us_mbi() {
        // Not a valid MBI → never a test pattern.
        assert!(!is_test_us_mbi("not-an-mbi"));
        // A real-looking MBI with varied digits/letters is not flagged.
        assert!(!is_test_us_mbi("1EG4TE5MK73"));
    }
}
