//! Text-based medical identifier redaction functions
//!
//! Functions for scanning and redacting medical identifiers within arbitrary text.
//! Uses `TextRedactionPolicy` for consistent behavior across multiple identifier types.
//!
//! # Usage
//!
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - No redaction
//! - `Partial` - Show some information (sensible defaults per type)
//! - `Complete` - Full token redaction (<MEDICAL_RECORD>, <INSURANCE_INFO>, etc.)
//! - `Anonymous` - Generic [REDACTED] for everything

use super::super::super::common::patterns;
use std::borrow::Cow;

use super::super::redaction::{
    InsuranceRedactionStrategy, MedicalCodeRedactionStrategy, MrnRedactionStrategy,
    NpiRedactionStrategy, PrescriptionRedactionStrategy, TextRedactionPolicy,
};
use super::individual::{
    redact_insurance_number_with_strategy, redact_medical_code_with_strategy,
    redact_mrn_with_strategy, redact_npi_with_strategy, redact_prescription_number_with_strategy,
};

/// Redact all medical record numbers in text using text redaction policy
///
/// Scans text for MRNs and replaces them according to the policy.
/// The policy is mapped to appropriate MRN strategies internally.
///
/// # Arguments
///
/// * `text` - Text to scan for MRNs
/// * `policy` - Text redaction policy (None/Partial/Complete/Anonymous)
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no MRNs found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{TextRedactionPolicy, redact_mrn_in_text};
///
/// let text = "Patient MRN: 12345678";
///
/// // Partial redaction
/// let safe = redact_mrn_in_text(text, TextRedactionPolicy::Partial);
/// assert!(safe.contains("MRN-12****"));
///
/// // Complete redaction
/// let safe = redact_mrn_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[MEDICAL_RECORD]"));
/// ```
#[must_use]
pub fn redact_mrn_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_mrn_strategy();

    // None policy - return as-is
    if matches!(strategy, MrnRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in patterns::medical::mrn() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        redact_mrn_with_strategy(matched, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Redact all health insurance information in text using text redaction policy
///
/// Scans text for insurance information and replaces it according to the policy.
///
/// # Arguments
///
/// * `text` - Text to scan for insurance information
/// * `policy` - Text redaction policy (None/Partial/Complete/Anonymous)
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no insurance info found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{TextRedactionPolicy, redact_insurance_in_text};
///
/// let text = "Policy Number: ABC123456789";
///
/// // Partial redaction - show last 4
/// let safe = redact_insurance_in_text(text, TextRedactionPolicy::Partial);
/// assert!(safe.contains("******6789"));
///
/// // Complete redaction
/// let safe = redact_insurance_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[INSURANCE_INFO]"));
/// ```
#[must_use]
pub fn redact_insurance_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_insurance_strategy();

    // None policy - return as-is
    if matches!(strategy, InsuranceRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in patterns::medical::insurance() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        redact_insurance_number_with_strategy(matched, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Redact all prescription numbers in text using text redaction policy
///
/// Scans text for prescription numbers and replaces them according to the policy.
///
/// # Arguments
///
/// * `text` - Text to scan for prescription numbers
/// * `policy` - Text redaction policy (None/Partial/Complete/Anonymous)
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no prescriptions found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{TextRedactionPolicy, redact_prescriptions_in_text};
///
/// let text = "RX# 123456789";
///
/// // Complete redaction
/// let safe = redact_prescriptions_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[PRESCRIPTION]"));
/// ```
#[must_use]
pub fn redact_prescriptions_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_prescription_strategy();

    // None policy - return as-is
    if matches!(strategy, PrescriptionRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in patterns::medical::prescriptions() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        redact_prescription_number_with_strategy(matched, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Redact all provider IDs (NPI) in text using text redaction policy
///
/// Scans text for NPIs and replaces them according to the policy.
///
/// # Arguments
///
/// * `text` - Text to scan for provider IDs
/// * `policy` - Text redaction policy (None/Partial/Complete/Anonymous)
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no provider IDs found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{TextRedactionPolicy, redact_provider_ids_in_text};
///
/// let text = "Doctor NPI: 1234567890";
///
/// // Partial redaction - show first 4
/// let safe = redact_provider_ids_in_text(text, TextRedactionPolicy::Partial);
/// assert!(safe.contains("1234-***-***"));
///
/// // Complete redaction
/// let safe = redact_provider_ids_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[PROVIDER_ID]"));
/// ```
#[must_use]
pub fn redact_provider_ids_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_npi_strategy();

    // None policy - return as-is
    if matches!(strategy, NpiRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in patterns::medical::provider_ids() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        redact_npi_with_strategy(matched, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Redact all medical codes (ICD-10, CPT) in text using text redaction policy
///
/// Scans text for medical codes and replaces them according to the policy.
///
/// # Arguments
///
/// * `text` - Text to scan for medical codes
/// * `policy` - Text redaction policy (None/Partial/Complete/Anonymous)
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no codes found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{TextRedactionPolicy, redact_medical_codes_in_text};
///
/// let text = "Diagnosis: E11.9, Procedure CPT: 99213";
///
/// // Partial redaction - show category
/// let safe = redact_medical_codes_in_text(text, TextRedactionPolicy::Partial);
/// assert!(safe.contains("[ICD10-E11.*]"));
///
/// // Complete redaction
/// let safe = redact_medical_codes_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[MEDICAL_CODE]"));
/// ```
#[must_use]
pub fn redact_medical_codes_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_medical_code_strategy();

    // None policy - return as-is
    if matches!(strategy, MedicalCodeRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in patterns::medical::medical_codes() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        redact_medical_code_with_strategy(matched, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Redact all medical information in text using text redaction policy
///
/// Comprehensive redaction for all medical identifier types:
/// MRN, insurance, prescriptions, provider IDs, and medical codes.
///
/// # Arguments
///
/// * `text` - Text to scan for all medical identifiers
/// * `policy` - Text redaction policy (None/Partial/Complete/Anonymous)
///
/// # Returns
///
/// String with all medical identifiers redacted according to policy.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{TextRedactionPolicy, redact_all_medical_in_text};
///
/// let text = "Patient MRN: 12345678, Policy: ABC123456, RX: 987654321, NPI: 1234567890";
///
/// // Complete redaction
/// let safe = redact_all_medical_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[MEDICAL_RECORD]"));
/// assert!(safe.contains("[INSURANCE_INFO]"));
/// assert!(safe.contains("[PRESCRIPTION]"));
/// assert!(safe.contains("[PROVIDER_ID]"));
/// ```
/// Redact all DEA numbers in text using text redaction policy
///
/// Scans text for DEA numbers (with checksum validation) and replaces them.
#[must_use]
pub fn redact_dea_numbers_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    if matches!(policy, TextRedactionPolicy::Skip) {
        return Cow::Borrowed(text);
    }

    use super::super::detection;
    let matches = detection::find_dea_numbers_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let token = match policy {
        TextRedactionPolicy::Complete => "[DEA_NUMBER]",
        TextRedactionPolicy::Partial => "[DEA_NUMBER]",
        TextRedactionPolicy::Anonymous => "[REDACTED]",
        TextRedactionPolicy::Skip => return Cow::Borrowed(text),
    };

    let mut result = text.to_string();
    // Replace in reverse order to maintain positions
    for m in matches.iter().rev() {
        result.replace_range(m.start..m.end, token);
    }

    Cow::Owned(result)
}

pub fn redact_all_medical_in_text(text: &str, policy: TextRedactionPolicy) -> String {
    let result = redact_mrn_in_text(text, policy);
    let result = redact_insurance_in_text(&result, policy);
    let result = redact_prescriptions_in_text(&result, policy);
    let result = redact_provider_ids_in_text(&result, policy);
    let result = redact_medical_codes_in_text(&result, policy);
    let result = redact_dea_numbers_in_text(&result, policy);

    result.into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_mrn_in_text() {
        let text = "Patient MRN: 12345678";
        let result = redact_mrn_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[MEDICAL_RECORD]"));
        assert!(!result.contains("12345678"));
    }

    #[test]
    fn test_redact_mrn_multiple() {
        let text = "Patient MRN: 12345678 and Medical Record: 987654321";
        let result = redact_mrn_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.matches("[MEDICAL_RECORD]").count() >= 1);
    }

    #[test]
    fn test_redact_insurance_in_text() {
        let text = "Policy Number: ABC123456789";
        let result = redact_insurance_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[INSURANCE_INFO]"));
        assert!(!result.contains("ABC123456789"));
    }

    #[test]
    fn test_redact_insurance_multiple() {
        let text = "Policy Number: ABC123456789, Member ID: XYZ987654";
        let result = redact_insurance_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.matches("[INSURANCE_INFO]").count() >= 1);
    }

    #[test]
    fn test_redact_prescriptions_in_text() {
        let text = "RX# 123456789";
        let result = redact_prescriptions_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[PRESCRIPTION]"));
        assert!(!result.contains("123456789"));
    }

    #[test]
    fn test_redact_prescriptions_multiple() {
        let text = "RX# 123456789 and Prescription Number: 987654";
        let result = redact_prescriptions_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.matches("[PRESCRIPTION]").count() >= 1);
    }

    #[test]
    fn test_redact_provider_ids_in_text() {
        let text = "Doctor NPI: 1234567890";
        let result = redact_provider_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[PROVIDER_ID]"));
        assert!(!result.contains("1234567890"));
    }

    #[test]
    fn test_redact_provider_ids_multiple() {
        let text = "Doctor NPI: 1234567890 and Provider NPI: 2987654321";
        let result = redact_provider_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.matches("[PROVIDER_ID]").count() >= 1);
    }

    #[test]
    fn test_redact_medical_codes_in_text() {
        let text = "Diagnosis: A01.1, Procedure CPT: 99213";
        let result = redact_medical_codes_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[MEDICAL_CODE]"));
    }

    #[test]
    fn test_redact_medical_codes_multiple() {
        let text = "ICD-10: A01.1 and CPT: 99213";
        let result = redact_medical_codes_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.matches("[MEDICAL_CODE]").count() >= 2);
    }

    #[test]
    fn test_redact_all_medical() {
        let text =
            "Patient MRN: 12345678, Policy: ABC123456, RX: 987654321, Doctor NPI: 1234567890";
        let result = redact_all_medical_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[MEDICAL_RECORD]"));
        assert!(result.contains("[INSURANCE_INFO]"));
        assert!(result.contains("[PRESCRIPTION]"));
        assert!(result.contains("[PROVIDER_ID]"));
    }

    #[test]
    fn test_no_redaction_in_clean_text() {
        let text = "This text contains no medical identifiers";
        let result = redact_all_medical_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_cow_optimization() {
        // Clean text should return borrowed
        let text = "Clean text";
        let result = redact_mrn_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "Patient MRN: 12345678";
        let result = redact_mrn_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(redact_mrn_in_text("", TextRedactionPolicy::Complete), "");
        assert_eq!(
            redact_insurance_in_text("", TextRedactionPolicy::Complete),
            ""
        );
        assert_eq!(
            redact_prescriptions_in_text("", TextRedactionPolicy::Complete),
            ""
        );
        assert_eq!(
            redact_provider_ids_in_text("", TextRedactionPolicy::Complete),
            ""
        );
        assert_eq!(
            redact_medical_codes_in_text("", TextRedactionPolicy::Complete),
            ""
        );
        assert_eq!(
            redact_all_medical_in_text("", TextRedactionPolicy::Complete),
            ""
        );
    }
}
