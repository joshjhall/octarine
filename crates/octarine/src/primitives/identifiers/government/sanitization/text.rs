//! Text redaction functions for government IDs
//!
//! Functions that scan text and redact government identifiers found within,
//! using explicit strategy parameters.

use std::borrow::Cow;

use super::super::super::common::patterns;
use super::redaction::{
    redact_driver_license_with_strategy, redact_national_id_with_strategy,
    redact_passport_with_strategy, redact_tax_id_with_strategy, redact_vehicle_id_with_strategy,
};
use super::ssn::redact_ssn_with_strategy;
use super::strategy::{
    DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    SsnRedactionStrategy, TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};

// ============================================================================
// SSN Text Redaction
// ============================================================================

/// Redact all SSN patterns in text with explicit strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_ssns_in_text_with_strategy, SsnRedactionStrategy
/// };
///
/// let text = "Employee SSN: 900-00-0001";
///
/// // Complete token
/// let safe = redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::Token);
/// assert_eq!(safe, "Employee SSN: [SSN]");
///
/// // Partial last 4
/// let partial = redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::LastFour);
/// assert_eq!(partial, "Employee SSN: ***-**-0001");
/// ```
#[must_use]
pub fn redact_ssns_in_text_with_strategy(
    text: &str,
    strategy: SsnRedactionStrategy,
) -> Cow<'_, str> {
    let mut result = Cow::Borrowed(text);

    for (i, pattern) in patterns::ssn::all().iter().enumerate() {
        if pattern.is_match(&result) {
            // Use captures to extract SSN and optional label
            let owned = pattern
                .replace_all(&result, |caps: &regex::Captures<'_>| {
                    let ssn = if i == 0 {
                        // First pattern has label + SSN in capture groups
                        caps.get(2).map_or("", |m| m.as_str())
                    } else {
                        // Other patterns - entire match is the SSN
                        caps.get(0).map_or("", |m| m.as_str())
                    };

                    let redacted = redact_ssn_with_strategy(ssn, strategy);

                    if i == 0 {
                        // Preserve label: "SSN: 900-00-0001" → "SSN: [SSN]"
                        let label = caps.get(1).map_or("", |m| m.as_str());
                        format!("{}{}", label, redacted)
                    } else {
                        redacted
                    }
                })
                .into_owned();

            result = Cow::Owned(owned);
        }
    }

    result
}

// ============================================================================
// Tax ID Text Redaction
// ============================================================================

/// Redact all tax ID patterns in text with explicit strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_tax_ids_in_text_with_strategy, TaxIdRedactionStrategy
/// };
///
/// let text = "Company EIN: 12-3456789";
///
/// let safe = redact_tax_ids_in_text_with_strategy(text, TaxIdRedactionStrategy::Token);
/// assert_eq!(safe, "Company EIN: [TAX_ID]");
///
/// let prefix = redact_tax_ids_in_text_with_strategy(text, TaxIdRedactionStrategy::ShowPrefix);
/// assert_eq!(prefix, "Company EIN: 12-*******");
/// ```
#[must_use]
pub fn redact_tax_ids_in_text_with_strategy(
    text: &str,
    strategy: TaxIdRedactionStrategy,
) -> Cow<'_, str> {
    let mut result = Cow::Borrowed(text);

    for (i, pattern) in patterns::tax_id::all().iter().enumerate() {
        if pattern.is_match(&result) {
            let owned = pattern
                .replace_all(&result, |caps: &regex::Captures<'_>| {
                    if i == 0 {
                        // First pattern has capture groups - preserve prefix
                        let prefix = caps.get(1).map_or("", |m| m.as_str());
                        let tax_id = caps.get(2).map_or("", |m| m.as_str());
                        let redacted = redact_tax_id_with_strategy(tax_id, strategy);
                        format!("{}{}", prefix, redacted)
                    } else {
                        let tax_id = caps.get(0).map_or("", |m| m.as_str());
                        redact_tax_id_with_strategy(tax_id, strategy)
                    }
                })
                .into_owned();

            result = Cow::Owned(owned);
        }
    }

    result
}

// ============================================================================
// Driver License Text Redaction
// ============================================================================

/// Redact all driver's license patterns in text with explicit strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_driver_licenses_in_text_with_strategy, DriverLicenseRedactionStrategy
/// };
///
/// let text = "DL# D1234567";
///
/// let safe = redact_driver_licenses_in_text_with_strategy(
///     text,
///     DriverLicenseRedactionStrategy::Token
/// );
/// assert_eq!(safe, "DL# [DRIVER_LICENSE]");
/// ```
#[must_use]
pub fn redact_driver_licenses_in_text_with_strategy(
    text: &str,
    strategy: DriverLicenseRedactionStrategy,
) -> Cow<'_, str> {
    let mut result = Cow::Borrowed(text);

    // Check state-specific patterns
    for (_state, pattern) in patterns::driver_license::state_patterns() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let license = caps.get(0).map_or("", |m| m.as_str());
                        redact_driver_license_with_strategy(license, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    // Check generic pattern with context preservation
    if patterns::driver_license::GENERIC.is_match(&result) {
        result = Cow::Owned(
            patterns::driver_license::GENERIC
                .replace_all(&result, |caps: &regex::Captures<'_>| {
                    let prefix = caps.get(1).map_or("", |m| m.as_str());
                    let license = caps.get(2).map_or("", |m| m.as_str());
                    let redacted = redact_driver_license_with_strategy(license, strategy);
                    format!("{}{}", prefix, redacted)
                })
                .into_owned(),
        );
    }

    result
}

// ============================================================================
// Passport Text Redaction
// ============================================================================

/// Redact all passport patterns in text with explicit strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_passports_in_text_with_strategy, PassportRedactionStrategy
/// };
///
/// let text = "Passport: US1234567";
///
/// let safe = redact_passports_in_text_with_strategy(text, PassportRedactionStrategy::Token);
/// assert_eq!(safe, "Passport: [PASSPORT]");
/// ```
#[must_use]
pub fn redact_passports_in_text_with_strategy(
    text: &str,
    strategy: PassportRedactionStrategy,
) -> Cow<'_, str> {
    let mut result = Cow::Borrowed(text);

    for (i, pattern) in patterns::passport::all().iter().enumerate() {
        if pattern.is_match(&result) {
            if i == 0 {
                // First pattern is explicit passport mention - redact completely
                result = Cow::Owned(
                    pattern
                        .replace_all(&result, |caps: &regex::Captures<'_>| {
                            let passport = caps.get(1).map_or("", |m| m.as_str());
                            let redacted = redact_passport_with_strategy(passport, strategy);
                            format!("Passport: {}", redacted)
                        })
                        .into_owned(),
                );
            } else if i == 1 {
                // Second pattern has prefix capture group
                result = Cow::Owned(
                    pattern
                        .replace_all(&result, |caps: &regex::Captures<'_>| {
                            let prefix = caps.get(1).map_or("", |m| m.as_str());
                            let passport = caps.get(2).map_or("", |m| m.as_str());
                            let redacted = redact_passport_with_strategy(passport, strategy);
                            format!("{}{}", prefix, redacted)
                        })
                        .into_owned(),
                );
            } else {
                // Generic pattern - only redact if it looks like passport context
                result = Cow::Owned(
                    pattern
                        .replace_all(&result, |caps: &regex::Captures<'_>| {
                            let matched = &caps[0];
                            if is_likely_passport_context(&result, matched) {
                                redact_passport_with_strategy(matched, strategy)
                            } else {
                                matched.to_string()
                            }
                        })
                        .into_owned(),
                );
            }
        }
    }

    result
}

/// Check if a match is likely a passport based on surrounding context
fn is_likely_passport_context(text: &str, potential_passport: &str) -> bool {
    let context_keywords = ["passport", "pp", "travel", "document"];

    let passport_pos = text.find(potential_passport).unwrap_or(0);
    let start = passport_pos.saturating_sub(20);
    let end = passport_pos
        .saturating_add(potential_passport.len())
        .saturating_add(20)
        .min(text.len());
    let context = &text[start..end].to_lowercase();

    context_keywords
        .iter()
        .any(|&keyword| context.contains(keyword))
}

// ============================================================================
// National ID Text Redaction
// ============================================================================

/// Redact all national ID patterns in text with explicit strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_national_ids_in_text_with_strategy, NationalIdRedactionStrategy
/// };
///
/// let text = "UK NI: AB123456C";
///
/// let safe = redact_national_ids_in_text_with_strategy(
///     text,
///     NationalIdRedactionStrategy::Token
/// );
/// assert!(safe.contains("[NATIONAL_ID]"));
/// ```
#[must_use]
pub fn redact_national_ids_in_text_with_strategy(
    text: &str,
    strategy: NationalIdRedactionStrategy,
) -> Cow<'_, str> {
    let mut result = Cow::Borrowed(text);

    for pattern in patterns::national_id::all() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let national_id = caps.get(0).map_or("", |m| m.as_str());
                        redact_national_id_with_strategy(national_id, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

// ============================================================================
// Vehicle ID Text Redaction
// ============================================================================

/// Redact all vehicle ID patterns in text with explicit strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_vehicle_ids_in_text_with_strategy, VehicleIdRedactionStrategy
/// };
///
/// let text = "VIN: 1HGBH41JXMN109186";
///
/// let safe = redact_vehicle_ids_in_text_with_strategy(text, VehicleIdRedactionStrategy::Token);
/// assert_eq!(safe, "VIN: [VEHICLE_ID]");
/// ```
#[must_use]
pub fn redact_vehicle_ids_in_text_with_strategy(
    text: &str,
    strategy: VehicleIdRedactionStrategy,
) -> Cow<'_, str> {
    let mut result = Cow::Borrowed(text);

    for (i, pattern) in patterns::vehicle_id::all().iter().enumerate() {
        if pattern.is_match(&result) {
            if i == 0 {
                // First pattern has capture groups - preserve prefix
                result = Cow::Owned(
                    pattern
                        .replace_all(&result, |caps: &regex::Captures<'_>| {
                            let prefix = caps.get(1).map_or("", |m| m.as_str());
                            let vin = caps.get(2).map_or("", |m| m.as_str());
                            let redacted = redact_vehicle_id_with_strategy(vin, strategy);
                            format!("{}{}", prefix, redacted)
                        })
                        .into_owned(),
                );
            } else {
                result = Cow::Owned(
                    pattern
                        .replace_all(&result, |caps: &regex::Captures<'_>| {
                            let vin = caps.get(0).map_or("", |m| m.as_str());
                            redact_vehicle_id_with_strategy(vin, strategy)
                        })
                        .into_owned(),
                );
            }
        }
    }

    result
}

// ============================================================================
// Combined Government ID Redaction
// ============================================================================

/// Redact all government-issued ID patterns in text with policy support
///
/// Comprehensive redaction for all government ID types with policy support.
///
/// # Arguments
///
/// * `text` - The text to scan for government identifiers
/// * `policy` - Optional redaction policy (defaults to Complete if None)
///
/// # Policies
///
/// * `Skip` - No redaction (returns original text)
/// * `Partial` - Show partial info (last 4 for SSN, WMI for VIN, etc.)
/// * `Complete` - Type tokens ([SSN], [VEHICLE_ID], etc.)
/// * `Anonymous` - Generic [REDACTED] for all types
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization;
/// use crate::primitives::identifiers::government::redaction::TextRedactionPolicy;
///
/// let text = "SSN: 900-00-0001, VIN: 1HGBH41JXMN109186";
///
/// // Default (Complete)
/// let safe = sanitization::redact_all_government_ids_in_text_with_policy(text, None);
/// assert!(safe.contains("[SSN]"));
///
/// // With policy
/// let partial = sanitization::redact_all_government_ids_in_text_with_policy(
///     text,
///     Some(TextRedactionPolicy::Partial)
/// );
/// assert!(partial.contains("***-**-0001")); // Last 4 visible
/// ```
#[must_use]
pub fn redact_all_government_ids_in_text_with_policy(
    text: &str,
    policy: Option<super::super::redaction::TextRedactionPolicy>,
) -> String {
    let policy = policy.unwrap_or_default();

    // If no redaction, return early
    if !policy.is_active() {
        return text.to_string();
    }

    // Convert policy to individual strategies
    let ssn_strategy = policy.to_ssn_strategy();
    let tax_id_strategy = policy.to_tax_id_strategy();
    let driver_license_strategy = policy.to_driver_license_strategy();
    let passport_strategy = policy.to_passport_strategy();
    let national_id_strategy = policy.to_national_id_strategy();
    let vehicle_id_strategy = policy.to_vehicle_id_strategy();

    // Apply redaction in order
    let result = redact_ssns_in_text_with_strategy(text, ssn_strategy);
    let result = redact_tax_ids_in_text_with_strategy(&result, tax_id_strategy);
    let result = redact_driver_licenses_in_text_with_strategy(&result, driver_license_strategy);
    let result = redact_passports_in_text_with_strategy(&result, passport_strategy);
    let result = redact_national_ids_in_text_with_strategy(&result, national_id_strategy);
    let result = redact_vehicle_ids_in_text_with_strategy(&result, vehicle_id_strategy);

    result.into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ========================================================================
    // SSN Text Tests
    // ========================================================================

    #[test]
    fn test_redact_ssns_in_text() {
        let text = "Employee SSN: 900-00-0001";
        let result = redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::Token);
        assert_eq!(result, "Employee SSN: [SSN]");
    }

    #[test]
    fn test_redact_ssns_in_text_multiple() {
        let text = "SSN: 900-00-0001 and SSN: 900-00-0002";
        let result = redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::Token);
        assert_eq!(result, "SSN: [SSN] and SSN: [SSN]");
    }

    #[test]
    fn test_redact_ssns_in_text_last_four() {
        let text = "Employee SSN: 900-00-0001";
        let result = redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::LastFour);
        assert_eq!(result, "Employee SSN: ***-**-0001");
    }

    // ========================================================================
    // Tax ID Text Tests
    // ========================================================================

    #[test]
    fn test_redact_tax_ids_in_text() {
        let text = "Company EIN: 00-0000001";
        let result = redact_tax_ids_in_text_with_strategy(text, TaxIdRedactionStrategy::Token);
        assert_eq!(result, "Company EIN: [TAX_ID]");
    }

    // ========================================================================
    // Driver License Text Tests
    // ========================================================================

    #[test]
    fn test_redact_driver_licenses_in_text() {
        let text = "DL# A1234567";
        let result = redact_driver_licenses_in_text_with_strategy(
            text,
            DriverLicenseRedactionStrategy::Token,
        );
        assert_eq!(result, "DL# [DRIVER_LICENSE]");
    }

    // ========================================================================
    // Passport Text Tests
    // ========================================================================

    #[test]
    fn test_redact_passports_in_text() {
        let text = "Passport: 123456789";
        let result = redact_passports_in_text_with_strategy(text, PassportRedactionStrategy::Token);
        assert_eq!(result, "Passport: [PASSPORT]");
    }

    // ========================================================================
    // National ID Text Tests
    // ========================================================================

    #[test]
    fn test_redact_national_ids_in_text() {
        let text = "UK NI: AB123456C";
        let result =
            redact_national_ids_in_text_with_strategy(text, NationalIdRedactionStrategy::Token);
        assert!(result.contains("[NATIONAL_ID]"));
    }

    // ========================================================================
    // Vehicle ID Text Tests
    // ========================================================================

    #[test]
    fn test_redact_vehicle_ids_in_text() {
        let text = "VIN: 1HGBH41JXMN109186";
        let result =
            redact_vehicle_ids_in_text_with_strategy(text, VehicleIdRedactionStrategy::Token);
        assert_eq!(result, "VIN: [VEHICLE_ID]");
    }

    // ========================================================================
    // Combined Redaction Tests
    // ========================================================================

    #[test]
    fn test_redact_all_government_ids() {
        use crate::primitives::identifiers::GovernmentTextPolicy;

        let text = "SSN: 900-00-0001, VIN: 1HGBH41JXMN109186, EIN: 00-0000001";
        let result = redact_all_government_ids_in_text_with_policy(
            text,
            Some(GovernmentTextPolicy::Complete),
        );
        assert!(result.contains("[SSN]"));
        assert!(result.contains("[VEHICLE_ID]"));
        assert!(result.contains("[TAX_ID]"));
    }

    #[test]
    fn test_redact_all_government_ids_with_policy() {
        use crate::primitives::identifiers::GovernmentTextPolicy;

        let text = "SSN: 900-00-0001";

        // Partial policy shows last 4
        let partial = redact_all_government_ids_in_text_with_policy(
            text,
            Some(GovernmentTextPolicy::Partial),
        );
        assert!(partial.contains("***-**-0001"));

        // Skip policy returns original
        let none =
            redact_all_government_ids_in_text_with_policy(text, Some(GovernmentTextPolicy::Skip));
        assert_eq!(none, text);
    }

    #[test]
    fn test_no_redaction_in_clean_text() {
        use crate::primitives::identifiers::GovernmentTextPolicy;

        let text = "This text contains no government IDs";
        let result = redact_all_government_ids_in_text_with_policy(
            text,
            Some(GovernmentTextPolicy::Complete),
        );
        assert_eq!(result, text);
    }

    #[test]
    fn test_cow_optimization() {
        // Clean text should return borrowed (no allocation)
        let text = "Clean text";
        let result = redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::Token);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "SSN: 900-00-0001";
        let result = redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::Token);
        assert!(matches!(result, Cow::Owned(_)));
    }
}
