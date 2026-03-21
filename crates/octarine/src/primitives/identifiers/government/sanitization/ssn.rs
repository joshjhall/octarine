//! SSN-specific redaction functions
//!
//! Functions for redacting Social Security Numbers with explicit strategies.

use super::super::super::common::masking;

use super::strategy::SsnRedactionStrategy;

// ============================================================================
// SSN Redaction
// ============================================================================

/// Redact SSN with explicit strategy
///
/// # Strategies
///
/// - `Token` → `[SSN]`
/// - `Mask` → `***-**-****`
/// - `Anonymous` → `[Redacted]`
/// - `LastFour` → `***-**-0001`
/// - `FirstFive` → `900-00-****` (RISKY - leaks geographic area)
/// - `Skip` → `900-00-0001` (no redaction)
///
/// # Security Considerations
///
/// - `FirstFive` is RISKY for production (leaks geographic area and issuance period)
/// - The last 4 digits are the most sensitive (unique identifier)
/// - The first 5 (area + group numbers) were geographically based
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_ssn_with_strategy, SsnRedactionStrategy
/// };
///
/// // Complete token redaction
/// let token = redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Token);
/// assert_eq!(token, "[SSN]");
///
/// // Partial redaction (last 4 - safer)
/// let partial = redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::LastFour);
/// assert_eq!(partial, "***-**-0001");
///
/// // Complete masking
/// let masked = redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Mask);
/// assert_eq!(masked, "***-**-****");
/// ```
#[must_use]
pub fn redact_ssn_with_strategy(ssn: &str, strategy: SsnRedactionStrategy) -> String {
    let digits = masking::digits_only(ssn);

    match strategy {
        SsnRedactionStrategy::Token => "[SSN]".to_string(),

        SsnRedactionStrategy::Mask => {
            // Complete masking, preserve format
            masking::mask_digits_preserve_format(ssn, 0, '*')
        }

        SsnRedactionStrategy::Anonymous => "[Redacted]".to_string(),

        SsnRedactionStrategy::LastFour => {
            // Show last 4 digits: "***-**-0001"
            masking::mask_digits_preserve_format(ssn, 4, '*')
        }

        SsnRedactionStrategy::FirstFive => {
            // Show first 5 digits (RISKY): "900-00-****"
            if digits.len() >= 9 {
                // Manually construct format to show first 5, mask last 4
                if ssn.contains('-') {
                    let parts: Vec<&str> = ssn.split('-').collect();
                    if parts.len() == 3 {
                        if let (Some(&p0), Some(&p1)) = (parts.first(), parts.get(1)) {
                            format!("{}-{}-****", p0, p1)
                        } else {
                            format!("{}****", &digits[..5])
                        }
                    } else {
                        format!("{}****", &digits[..5])
                    }
                } else if ssn.contains(' ') {
                    let parts: Vec<&str> = ssn.split(' ').collect();
                    if parts.len() == 3 {
                        if let (Some(&p0), Some(&p1)) = (parts.first(), parts.get(1)) {
                            format!("{} {} ****", p0, p1)
                        } else {
                            format!("{}****", &digits[..5])
                        }
                    } else {
                        format!("{}****", &digits[..5])
                    }
                } else {
                    format!("{}****", &digits[..5])
                }
            } else {
                "[SSN]".to_string()
            }
        }

        SsnRedactionStrategy::Skip => ssn.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_ssn_with_strategies() {
        // Token
        assert_eq!(
            redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Token),
            "[SSN]"
        );

        // Mask
        assert_eq!(
            redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Mask),
            "***-**-****"
        );
        assert_eq!(
            redact_ssn_with_strategy("900 00 0002", SsnRedactionStrategy::Mask),
            "*** ** ****"
        );
        assert_eq!(
            redact_ssn_with_strategy("900000003", SsnRedactionStrategy::Mask),
            "*********"
        );

        // Anonymous
        assert_eq!(
            redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Anonymous),
            "[Redacted]"
        );

        // LastFour
        assert_eq!(
            redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::LastFour),
            "***-**-0001"
        );
        assert_eq!(
            redact_ssn_with_strategy("900 00 0002", SsnRedactionStrategy::LastFour),
            "*** ** 0002"
        );

        // FirstFive (RISKY)
        assert_eq!(
            redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::FirstFive),
            "900-00-****"
        );
        assert_eq!(
            redact_ssn_with_strategy("900 00 0002", SsnRedactionStrategy::FirstFive),
            "900 00 ****"
        );

        // Edge case: short SSN
        assert_eq!(
            redact_ssn_with_strategy("123", SsnRedactionStrategy::FirstFive),
            "[SSN]"
        );

        // Skip
        assert_eq!(
            redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Skip),
            "900-00-0001"
        );
    }

    #[test]
    fn test_multiple_formats() {
        // Dashed format
        assert_eq!(
            redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Token),
            "[SSN]"
        );

        // Space format
        assert_eq!(
            redact_ssn_with_strategy("900 00 0002", SsnRedactionStrategy::Token),
            "[SSN]"
        );

        // No separator
        assert_eq!(
            redact_ssn_with_strategy("900000003", SsnRedactionStrategy::Token),
            "[SSN]"
        );
    }
}
