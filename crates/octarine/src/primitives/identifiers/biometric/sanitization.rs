//! Biometric identifier sanitization (primitives layer)
//!
//! Pure redaction functions for biometric identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Functions
//!
//! ## Individual Redaction
//! - `redact_fingerprint()` - Redact single fingerprint ID
//! - `redact_facial_id()` - Redact single facial recognition ID
//! - `redact_iris_id()` - Redact single iris scan ID
//! - `redact_voice_id()` - Redact single voice print ID
//! - `redact_dna_sequence()` - Redact single DNA sequence
//! - `redact_biometric_template()` - Redact single biometric template
//!
//! ## Text Redaction
//! - `redact_fingerprints_in_text()` - Redact all fingerprints in text
//! - `redact_facial_data_in_text()` - Redact all facial data in text
//! - `redact_iris_scans_in_text()` - Redact all iris scans in text
//! - `redact_voice_prints_in_text()` - Redact all voice prints in text
//! - `redact_dna_sequences_in_text()` - Redact all DNA sequences in text
//! - `redact_biometric_templates_in_text()` - Redact all biometric templates in text
//! - `redact_all_biometric_in_text()` - Redact all biometric data in text

use super::{detection, redaction};
use crate::primitives::data::tokens::RedactionTokenCore;
use redaction::*;
use std::borrow::Cow;

// ============================================================================
// Individual Redaction Functions
// ============================================================================

/// Redact a single fingerprint identifier with custom strategy
///
/// Uses detection to verify input is a valid fingerprint before redacting.
/// Invalid input is treated as potential PII and redacted to token.
///
/// # Arguments
/// * `fingerprint` - The fingerprint ID to redact
/// * `strategy` - How to redact the fingerprint
///
/// # Examples
/// ```ignore
/// use octarine::primitives::identifiers::biometric::{redact_fingerprint_with_strategy, FingerprintRedactionStrategy};
///
/// let fp = "FP-123456789";
/// assert_eq!(redact_fingerprint_with_strategy(fp, FingerprintRedactionStrategy::Token), "[FINGERPRINT]");
/// assert_eq!(redact_fingerprint_with_strategy(fp, FingerprintRedactionStrategy::Anonymous), "[REDACTED]");
/// ```
#[must_use]
pub fn redact_fingerprint_with_strategy(
    fingerprint: &str,
    strategy: FingerprintRedactionStrategy,
) -> String {
    if matches!(strategy, FingerprintRedactionStrategy::Skip) {
        return fingerprint.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_fingerprint(fingerprint) {
        return match strategy {
            FingerprintRedactionStrategy::Skip => fingerprint.to_string(),
            FingerprintRedactionStrategy::ShowSensor | FingerprintRedactionStrategy::Token => {
                RedactionTokenCore::Fingerprint.into()
            }
            FingerprintRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            FingerprintRedactionStrategy::Asterisks => "*".repeat(fingerprint.len()),
            FingerprintRedactionStrategy::Hashes => "#".repeat(fingerprint.len()),
        };
    }

    match strategy {
        FingerprintRedactionStrategy::Skip => fingerprint.to_string(),
        FingerprintRedactionStrategy::ShowSensor => {
            // Try to extract sensor info if present (e.g., "FP-Sensor5-123456")
            if fingerprint.len() <= 6 {
                RedactionTokenCore::Fingerprint.into()
            } else if fingerprint.contains("FP-") {
                format!(
                    "FP-****{}",
                    &fingerprint[fingerprint.len().saturating_sub(2)..]
                )
            } else {
                format!("{}****", &fingerprint[0..4.min(fingerprint.len())])
            }
        }
        FingerprintRedactionStrategy::Token => RedactionTokenCore::Fingerprint.into(),
        FingerprintRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        FingerprintRedactionStrategy::Asterisks => "*".repeat(fingerprint.len()),
        FingerprintRedactionStrategy::Hashes => "#".repeat(fingerprint.len()),
    }
}

/// Redact a single facial recognition identifier with custom strategy
///
/// Uses detection to verify input is a valid facial ID before redacting.
///
/// # Arguments
/// * `facial_id` - The facial recognition ID to redact
/// * `strategy` - How to redact the facial ID
#[must_use]
pub fn redact_facial_id_with_strategy(
    facial_id: &str,
    strategy: FacialIdRedactionStrategy,
) -> String {
    if matches!(strategy, FacialIdRedactionStrategy::Skip) {
        return facial_id.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_facial_recognition(facial_id) {
        return match strategy {
            FacialIdRedactionStrategy::Skip => facial_id.to_string(),
            FacialIdRedactionStrategy::ShowCamera | FacialIdRedactionStrategy::Token => {
                RedactionTokenCore::FacialData.into()
            }
            FacialIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            FacialIdRedactionStrategy::Asterisks => "*".repeat(facial_id.len()),
            FacialIdRedactionStrategy::Hashes => "#".repeat(facial_id.len()),
        };
    }

    match strategy {
        FacialIdRedactionStrategy::Skip => facial_id.to_string(),
        FacialIdRedactionStrategy::ShowCamera => {
            if facial_id.len() <= 6 {
                RedactionTokenCore::FacialData.into()
            } else if facial_id.contains("FACE-") {
                format!(
                    "FACE-****{}",
                    &facial_id[facial_id.len().saturating_sub(2)..]
                )
            } else {
                format!("{}****", &facial_id[0..4.min(facial_id.len())])
            }
        }
        FacialIdRedactionStrategy::Token => RedactionTokenCore::FacialData.into(),
        FacialIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        FacialIdRedactionStrategy::Asterisks => "*".repeat(facial_id.len()),
        FacialIdRedactionStrategy::Hashes => "#".repeat(facial_id.len()),
    }
}

/// Redact a single iris scan identifier with custom strategy
///
/// Uses detection to verify input is a valid iris ID before redacting.
///
/// # Arguments
/// * `iris_id` - The iris scan ID to redact
/// * `strategy` - How to redact the iris ID
#[must_use]
pub fn redact_iris_id_with_strategy(iris_id: &str, strategy: IrisIdRedactionStrategy) -> String {
    if matches!(strategy, IrisIdRedactionStrategy::Skip) {
        return iris_id.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_iris_scan(iris_id) {
        return match strategy {
            IrisIdRedactionStrategy::Skip => iris_id.to_string(),
            IrisIdRedactionStrategy::ShowEye | IrisIdRedactionStrategy::Token => {
                RedactionTokenCore::IrisScan.into()
            }
            IrisIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            IrisIdRedactionStrategy::Asterisks => "*".repeat(iris_id.len()),
            IrisIdRedactionStrategy::Hashes => "#".repeat(iris_id.len()),
        };
    }

    match strategy {
        IrisIdRedactionStrategy::Skip => iris_id.to_string(),
        IrisIdRedactionStrategy::ShowEye => {
            // Try to extract eye info (Left/Right) if present
            if iris_id.len() <= 6 {
                RedactionTokenCore::IrisScan.into()
            } else if iris_id.contains("IRIS-") {
                let eye = if iris_id.contains("Left") {
                    "Left"
                } else if iris_id.contains("Right") {
                    "Right"
                } else {
                    ""
                };
                if eye.is_empty() {
                    format!("IRIS-****{}", &iris_id[iris_id.len().saturating_sub(2)..])
                } else {
                    format!("IRIS-{}-****", eye)
                }
            } else {
                format!("{}****", &iris_id[0..4.min(iris_id.len())])
            }
        }
        IrisIdRedactionStrategy::Token => RedactionTokenCore::IrisScan.into(),
        IrisIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        IrisIdRedactionStrategy::Asterisks => "*".repeat(iris_id.len()),
        IrisIdRedactionStrategy::Hashes => "#".repeat(iris_id.len()),
    }
}

/// Redact a single voice print identifier with custom strategy
///
/// Uses detection to verify input is a valid voice print before redacting.
///
/// # Arguments
/// * `voice_id` - The voice print ID to redact
/// * `strategy` - How to redact the voice print
#[must_use]
pub fn redact_voice_id_with_strategy(voice_id: &str, strategy: VoiceIdRedactionStrategy) -> String {
    if matches!(strategy, VoiceIdRedactionStrategy::Skip) {
        return voice_id.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_voice_print(voice_id) {
        return match strategy {
            VoiceIdRedactionStrategy::Skip => voice_id.to_string(),
            VoiceIdRedactionStrategy::Token => RedactionTokenCore::VoicePrint.into(),
            VoiceIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            VoiceIdRedactionStrategy::Asterisks => "*".repeat(voice_id.len()),
            VoiceIdRedactionStrategy::Hashes => "#".repeat(voice_id.len()),
        };
    }

    match strategy {
        VoiceIdRedactionStrategy::Skip => voice_id.to_string(),
        VoiceIdRedactionStrategy::Token => RedactionTokenCore::VoicePrint.into(),
        VoiceIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        VoiceIdRedactionStrategy::Asterisks => "*".repeat(voice_id.len()),
        VoiceIdRedactionStrategy::Hashes => "#".repeat(voice_id.len()),
    }
}

/// Redact a single DNA sequence with custom strategy
///
/// Uses detection to verify input is a valid DNA sequence before redacting.
///
/// # Arguments
/// * `dna` - The DNA sequence to redact
/// * `strategy` - How to redact the DNA sequence
#[must_use]
pub fn redact_dna_sequence_with_strategy(dna: &str, strategy: DnaRedactionStrategy) -> String {
    if matches!(strategy, DnaRedactionStrategy::Skip) {
        return dna.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_dna_sequence(dna) {
        return match strategy {
            DnaRedactionStrategy::Skip => dna.to_string(),
            DnaRedactionStrategy::ShowMarkerCount | DnaRedactionStrategy::Token => {
                RedactionTokenCore::DnaSequence.into()
            }
            DnaRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            DnaRedactionStrategy::Asterisks => "*".repeat(dna.len()),
            DnaRedactionStrategy::Hashes => "#".repeat(dna.len()),
        };
    }

    match strategy {
        DnaRedactionStrategy::Skip => dna.to_string(),
        DnaRedactionStrategy::ShowMarkerCount => {
            // Count genetic markers (rough approximation - every 4 bases is a marker)
            let marker_count = dna.len() / 4;
            format!("DNA-{}markers-****", marker_count)
        }
        DnaRedactionStrategy::Token => RedactionTokenCore::DnaSequence.into(),
        DnaRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        DnaRedactionStrategy::Asterisks => "*".repeat(dna.len()),
        DnaRedactionStrategy::Hashes => "#".repeat(dna.len()),
    }
}

/// Redact a single biometric template with custom strategy
///
/// Uses detection to verify input is a valid biometric template before redacting.
///
/// # Arguments
/// * `template` - The biometric template to redact
/// * `strategy` - How to redact the template
#[must_use]
pub fn redact_biometric_template_with_strategy(
    template: &str,
    strategy: BiometricTemplateRedactionStrategy,
) -> String {
    if matches!(strategy, BiometricTemplateRedactionStrategy::Skip) {
        return template.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_biometric_template(template) {
        return match strategy {
            BiometricTemplateRedactionStrategy::Skip => template.to_string(),
            BiometricTemplateRedactionStrategy::ShowType
            | BiometricTemplateRedactionStrategy::Token => {
                RedactionTokenCore::BiometricTemplate.into()
            }
            BiometricTemplateRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            BiometricTemplateRedactionStrategy::Asterisks => "*".repeat(template.len()),
            BiometricTemplateRedactionStrategy::Hashes => "#".repeat(template.len()),
        };
    }

    match strategy {
        BiometricTemplateRedactionStrategy::Skip => template.to_string(),
        BiometricTemplateRedactionStrategy::ShowType => {
            // Try to extract template type if present (FMR, ISO, etc.)
            if template.starts_with("FMR") {
                "TEMPLATE-FMR-****".to_string()
            } else if template.starts_with("ISO") {
                "TEMPLATE-ISO-****".to_string()
            } else {
                RedactionTokenCore::BiometricTemplate.into()
            }
        }
        BiometricTemplateRedactionStrategy::Token => RedactionTokenCore::BiometricTemplate.into(),
        BiometricTemplateRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        BiometricTemplateRedactionStrategy::Asterisks => "*".repeat(template.len()),
        BiometricTemplateRedactionStrategy::Hashes => "#".repeat(template.len()),
    }
}

// ============================================================================
// Text Redaction Functions
// ============================================================================

/// Redact all fingerprint identifiers in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
///
/// # Examples
/// ```ignore
/// use octarine::primitives::identifiers::biometric::{redact_fingerprints_in_text, TextRedactionPolicy};
///
/// let text = "User fingerprint: FP-123456789";
/// let result = redact_fingerprints_in_text(text, TextRedactionPolicy::Complete);
/// assert!(result.contains("[FINGERPRINT]"));
/// ```
#[must_use]
pub fn redact_fingerprints_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_fingerprint_strategy();
    if matches!(strategy, FingerprintRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_fingerprints_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    // Process matches in reverse order to maintain string positions
    for m in matches.iter().rev() {
        let redacted = redact_fingerprint_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all facial recognition data in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_facial_data_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_facial_id_strategy();
    if matches!(strategy, FacialIdRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_facial_data_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_facial_id_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all iris scans in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_iris_scans_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_iris_id_strategy();
    if matches!(strategy, IrisIdRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_iris_scans_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_iris_id_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all voice prints in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_voice_prints_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_voice_id_strategy();
    if matches!(strategy, VoiceIdRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_voice_prints_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_voice_id_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all DNA sequences in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_dna_sequences_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_dna_strategy();
    if matches!(strategy, DnaRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_dna_sequences_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_dna_sequence_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all biometric templates in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_biometric_templates_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_biometric_template_strategy();
    if matches!(strategy, BiometricTemplateRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_biometric_templates_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_biometric_template_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all biometric data in text
///
/// Convenience function that applies all biometric redaction functions.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_all_biometric_in_text(text: &str, policy: TextRedactionPolicy) -> String {
    let result = redact_fingerprints_in_text(text, policy);
    let result = redact_facial_data_in_text(&result, policy);
    let result = redact_iris_scans_in_text(&result, policy);
    let result = redact_voice_prints_in_text(&result, policy);
    let result = redact_dna_sequences_in_text(&result, policy);
    let result = redact_biometric_templates_in_text(&result, policy);

    result.into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Individual Redaction Tests - With Strategy =====

    #[test]
    fn test_redact_fingerprint_with_strategy_token() {
        let fp = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        assert_eq!(
            redact_fingerprint_with_strategy(fp, FingerprintRedactionStrategy::Token),
            "[FINGERPRINT]"
        );
    }

    #[test]
    fn test_redact_fingerprint_with_strategy_none() {
        let fp = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        assert_eq!(
            redact_fingerprint_with_strategy(fp, FingerprintRedactionStrategy::Skip),
            fp
        );
    }

    #[test]
    fn test_redact_fingerprint_with_strategy_anonymous() {
        let fp = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        assert_eq!(
            redact_fingerprint_with_strategy(fp, FingerprintRedactionStrategy::Anonymous),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_redact_facial_id_with_strategy_token() {
        let face = "dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc=";
        assert_eq!(
            redact_facial_id_with_strategy(face, FacialIdRedactionStrategy::Token),
            "[FACIAL_DATA]"
        );
    }

    #[test]
    fn test_redact_iris_id_with_strategy_token() {
        let iris = "IRIS1234567890ABCDEF";
        assert_eq!(
            redact_iris_id_with_strategy(iris, IrisIdRedactionStrategy::Token),
            "[IRIS_SCAN]"
        );
    }

    #[test]
    fn test_redact_voice_id_with_strategy_token() {
        let voice = "VP1234567890ABCDEF";
        assert_eq!(
            redact_voice_id_with_strategy(voice, VoiceIdRedactionStrategy::Token),
            "[VOICE_PRINT]"
        );
    }

    #[test]
    fn test_redact_dna_sequence_with_strategy_token() {
        let dna = "ATCGATCGATCGATCGATCG";
        assert_eq!(
            redact_dna_sequence_with_strategy(dna, DnaRedactionStrategy::Token),
            "[DNA_SEQUENCE]"
        );
    }

    #[test]
    fn test_redact_biometric_template_with_strategy_token() {
        let template =
            "FMR: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        assert_eq!(
            redact_biometric_template_with_strategy(
                template,
                BiometricTemplateRedactionStrategy::Token
            ),
            "[BIOMETRIC_TEMPLATE]"
        );
    }

    #[test]
    fn test_redact_fingerprint_with_strategy_invalid_input() {
        let invalid = "not-a-fingerprint";
        assert_eq!(
            redact_fingerprint_with_strategy(invalid, FingerprintRedactionStrategy::Token),
            "[FINGERPRINT]"
        );
    }

    // ===== Text Redaction Tests =====

    #[test]
    fn test_redact_fingerprints_in_text() {
        let text = "User fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let result = redact_fingerprints_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[FINGERPRINT]"));
        assert!(!result.contains("a1b2c3d4"));
    }

    #[test]
    fn test_redact_facial_data_in_text() {
        let text = "face_encoding: dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc=";
        let result = redact_facial_data_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[FACIAL_DATA]"));
    }

    #[test]
    fn test_redact_iris_scans_in_text() {
        let text = "iris_id: IRIS1234567890ABCDEF";
        let result = redact_iris_scans_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[IRIS_SCAN]"));
    }

    #[test]
    fn test_redact_voice_prints_in_text() {
        let text = "voiceprint: VP1234567890ABCDEF";
        let result = redact_voice_prints_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[VOICE_PRINT]"));
    }

    #[test]
    fn test_redact_dna_sequences_in_text() {
        let text = "Sequence: ATCGATCGATCGATCGATCG";
        let result = redact_dna_sequences_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[DNA_SEQUENCE]"));
    }

    #[test]
    fn test_redact_biometric_templates_in_text() {
        let text = "FMR: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let result = redact_biometric_templates_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[BIOMETRIC_TEMPLATE]"));
    }

    #[test]
    fn test_redact_all_biometric() {
        let text = "Auth: fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234, face_encoding: dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc=";
        let result = redact_all_biometric_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[FINGERPRINT]"));
        assert!(result.contains("[FACIAL_DATA]"));
    }

    #[test]
    fn test_no_redaction_in_clean_text() {
        let text = "This text contains no biometric identifiers";
        let result = redact_all_biometric_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_cow_optimization() {
        // Clean text should return borrowed
        let text = "Clean text";
        let result = redact_fingerprints_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let result = redact_fingerprints_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(
            redact_all_biometric_in_text("", TextRedactionPolicy::Complete),
            ""
        );
    }

    #[test]
    fn test_policy_none() {
        let text = "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let result = redact_fingerprints_in_text(text, TextRedactionPolicy::Skip);
        assert_eq!(result, text);
    }
}
