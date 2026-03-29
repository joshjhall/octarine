//! Credential pair detection API.
//!
//! Combines identifier detection, proximity scanning, and pair recognition
//! rules to find credential pairs in text (e.g., AWS access key + secret key
//! within a few lines).
//!
//! # Algorithm
//!
//! 1. Scan text for all identifier types using domain builders
//! 2. Find all pairs of matches within the proximity window
//! 3. Classify proximate pairs using recognition rules
//! 4. Return matches with `High` confidence

use super::super::types::{DetectionConfidence, IdentifierMatch};
use super::proximity::{self, char_distance};
use super::rules;
use super::types::{CorrelationConfig, CorrelationMatch};

/// Detect credential pairs in text using default configuration.
///
/// Scans text for all identifier types, then finds pairs of identifiers
/// that are within the default proximity window (5 lines, 500 chars) and
/// match a known credential pair pattern.
///
/// # Returns
///
/// A vec of `CorrelationMatch` values, each with `High` confidence.
/// Empty if no pairs are found.
#[must_use]
pub(crate) fn detect_credential_pairs(text: &str) -> Vec<CorrelationMatch> {
    detect_credential_pairs_with_config(text, &CorrelationConfig::default())
}

/// Detect credential pairs in text with custom configuration.
///
/// # Arguments
///
/// * `text` - The text to scan for credential pairs
/// * `config` - Custom proximity window and enabled pair types
///
/// # Returns
///
/// A vec of `CorrelationMatch` values, each with `High` confidence.
/// Empty if no pairs are found.
#[must_use]
pub(crate) fn detect_credential_pairs_with_config(
    text: &str,
    config: &CorrelationConfig,
) -> Vec<CorrelationMatch> {
    if text.is_empty() {
        return Vec::new();
    }

    // Step 1: Collect all identifiers from text
    let matches = collect_all_identifiers(text);

    // Delegate to shared logic
    detect_credential_pairs_from_matches(text, &matches, config)
}

/// Detect credential pairs from pre-collected identifier matches.
///
/// This is the shared core algorithm used by both `detect_credential_pairs_with_config`
/// (which scans text first) and `StreamingScanner::detect_credential_pairs` (which
/// uses already-buffered matches).
///
/// # Arguments
///
/// * `text` - The original text (needed for proximity line-distance calculation)
/// * `matches` - Pre-collected identifier matches to correlate
/// * `config` - Custom proximity window and enabled pair types
///
/// # Returns
///
/// A vec of `CorrelationMatch` values, each with `High` confidence.
/// Empty if fewer than 2 matches or no pairs found.
#[must_use]
pub(crate) fn detect_credential_pairs_from_matches(
    text: &str,
    matches: &[IdentifierMatch],
    config: &CorrelationConfig,
) -> Vec<CorrelationMatch> {
    if matches.len() < 2 {
        return Vec::new();
    }

    // Find all pairs within proximity window
    let proximate_pairs = proximity::find_proximate_pairs(text, matches, config);

    // Classify each proximate pair using recognition rules
    let mut results = Vec::new();
    for pair in proximate_pairs {
        let (Some(match_a), Some(match_b)) = (matches.get(pair.index_a), matches.get(pair.index_b))
        else {
            continue;
        };

        if let Some(pair_type) = rules::is_credential_pair(match_a, match_b) {
            // Filter by enabled pairs in config
            if !config.enabled_pairs.contains(&pair_type) {
                continue;
            }

            // Determine primary (earlier) and secondary (later) by position
            let (primary, secondary) = if match_a.start <= match_b.start {
                (match_a.clone(), match_b.clone())
            } else {
                (match_b.clone(), match_a.clone())
            };

            results.push(CorrelationMatch {
                pair_type,
                primary,
                secondary,
                confidence: DetectionConfidence::High,
                proximity_chars: char_distance(match_a, match_b),
            });
        }
    }

    results
}

/// Collect all identifier matches from text using domain builders.
///
/// Scans across personal, network, financial, credential, government,
/// medical, biometric, organizational, and location domains.
fn collect_all_identifiers(text: &str) -> Vec<IdentifierMatch> {
    use super::super::{
        BiometricIdentifierBuilder, CredentialIdentifierBuilder, FinancialIdentifierBuilder,
        GovernmentIdentifierBuilder, LocationIdentifierBuilder, MedicalIdentifierBuilder,
        NetworkIdentifierBuilder, OrganizationalIdentifierBuilder, PersonalIdentifierBuilder,
    };

    let mut all_matches = Vec::new();

    // Personal: emails, phones, names, birthdates
    let personal = PersonalIdentifierBuilder::new();
    all_matches.extend(personal.detect_all_in_text(text));

    // Network: IPs, URLs, UUIDs, MACs, API keys (incl. AWS, Stripe, GitHub, etc.)
    let network = NetworkIdentifierBuilder::new();
    all_matches.extend(network.find_all_in_text(text));

    // Financial: credit cards, bank accounts, routing numbers, payment tokens
    let financial = FinancialIdentifierBuilder::new();
    all_matches.extend(financial.detect_all_in_text(text));

    // Credentials: passwords, PINs, security answers (context-based detection)
    // These return CredentialMatch, convert to IdentifierMatch
    let creds = CredentialIdentifierBuilder::new();
    for cm in creds.detect_passwords(text) {
        all_matches.push(cm.into_identifier_match());
    }
    for cm in creds.detect_pins(text) {
        all_matches.push(cm.into_identifier_match());
    }

    // Government: SSNs, driver licenses, passports, tax IDs, national IDs
    let gov = GovernmentIdentifierBuilder::new();
    all_matches.extend(gov.find_all_in_text(text));

    // Medical: MRNs, insurance IDs, prescriptions, provider IDs
    let medical = MedicalIdentifierBuilder::new();
    all_matches.extend(medical.find_all_in_text(text));

    // Biometric: fingerprints, facial data, etc.
    let biometric = BiometricIdentifierBuilder::new();
    all_matches.extend(biometric.detect_all_in_text(text));

    // Organizational: employee IDs, student IDs, badge numbers
    let org = OrganizationalIdentifierBuilder::new();
    all_matches.extend(org.find_all_in_text(text));

    // Location: GPS coordinates, postal codes, addresses
    let location = LocationIdentifierBuilder::new();
    all_matches.extend(location.find_all_in_text(text));

    all_matches
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::primitives::identifiers::correlation::types::CredentialPairType;
    use crate::primitives::identifiers::types::IdentifierType;

    #[test]
    fn test_empty_text_returns_empty() {
        let result = detect_credential_pairs("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_identifiers_returns_empty() {
        let result = detect_credential_pairs("just some regular text with nothing special");
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_identifier_returns_empty() {
        let result = detect_credential_pairs("user@example.com");
        assert!(result.is_empty());
    }

    #[test]
    fn test_email_password_pair_in_env_format() {
        let text = "username: admin@example.com\npassword: SuperSecret123!";
        let results = detect_credential_pairs(text);

        let username_password = results
            .iter()
            .find(|m| m.pair_type == CredentialPairType::UsernamePasswordPair);
        assert!(
            username_password.is_some(),
            "Expected UsernamePasswordPair, found: {results:?}"
        );

        let pair = username_password.expect("verified above");
        assert_eq!(pair.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_uuid_apikey_detected_as_azure() {
        // UUID (client_id) + API key nearby = AzureServicePrincipal
        let secret = format!("sk_test_{}", "EXAMPLE0000000000KEY01abcdef");
        let text =
            format!("client_id: 550e8400-e29b-41d4-a716-446655440000\nclient_secret: {secret}");
        let results = detect_credential_pairs(&text);

        let azure = results
            .iter()
            .find(|m| m.pair_type == CredentialPairType::AzureServicePrincipal);
        assert!(
            azure.is_some(),
            "Expected AzureServicePrincipal, found: {results:?}"
        );
    }

    #[test]
    fn test_pairs_beyond_proximity_not_matched() {
        // Put identifiers far apart (> 500 chars)
        let padding = "x".repeat(600);
        let text = format!("admin@example.com\n{padding}\npassword: secret123");
        let results = detect_credential_pairs(&text);

        // Even if identifiers are found, they should be too far apart
        let username_password = results
            .iter()
            .find(|m| m.pair_type == CredentialPairType::UsernamePasswordPair);
        assert!(
            username_password.is_none(),
            "Pair should not match beyond proximity: {results:?}"
        );
    }

    #[test]
    fn test_custom_config_filters_enabled_pairs() {
        let text = "username: admin@example.com\npassword: SuperSecret123!";
        let config = CorrelationConfig {
            max_proximity_lines: 5,
            max_proximity_chars: 500,
            // Only enable AWS pairs — should filter out username/password
            enabled_pairs: vec![CredentialPairType::AwsKeyPair],
        };
        let results = detect_credential_pairs_with_config(text, &config);

        let username_password = results
            .iter()
            .find(|m| m.pair_type == CredentialPairType::UsernamePasswordPair);
        assert!(
            username_password.is_none(),
            "UsernamePasswordPair should be filtered when not in enabled_pairs"
        );
    }

    #[test]
    fn test_custom_config_narrow_proximity() {
        let text = "admin@example.com\n\n\npassword: secret123";
        let config = CorrelationConfig {
            max_proximity_lines: 1, // Only 1 line proximity
            max_proximity_chars: 500,
            ..CorrelationConfig::default()
        };
        let results = detect_credential_pairs_with_config(text, &config);

        let username_password = results
            .iter()
            .find(|m| m.pair_type == CredentialPairType::UsernamePasswordPair);
        assert!(
            username_password.is_none(),
            "Pair should not match with narrow proximity window"
        );
    }

    #[test]
    fn test_all_results_have_high_confidence() {
        let text = "username: admin@example.com\npassword: SuperSecret123!";
        let results = detect_credential_pairs(text);

        for result in &results {
            assert_eq!(
                result.confidence,
                DetectionConfidence::High,
                "All correlation matches should have High confidence"
            );
        }
    }

    #[test]
    fn test_primary_before_secondary() {
        let text = "username: admin@example.com\npassword: SuperSecret123!";
        let results = detect_credential_pairs(text);

        for result in &results {
            assert!(
                result.primary.start <= result.secondary.start,
                "Primary should have earlier or equal position: primary.start={}, secondary.start={}",
                result.primary.start,
                result.secondary.start
            );
        }
    }

    #[test]
    fn test_stripe_keypair_detection() {
        // Two Stripe-style API keys: public + secret
        let pk = format!("pk_test_{}", "EXAMPLE0000000000KEY01abcdef");
        let sk = format!("sk_test_{}", "EXAMPLE0000000000KEY02abcdef");
        let text = format!("STRIPE_PUBLISHABLE_KEY={pk}\nSTRIPE_SECRET_KEY={sk}");
        let results = detect_credential_pairs(&text);

        let key_pair = results
            .iter()
            .find(|m| m.pair_type == CredentialPairType::KeyPair);
        assert!(
            key_pair.is_some(),
            "Expected KeyPair for pk_live/sk_live, found: {results:?}"
        );
    }

    #[test]
    fn test_collect_all_identifiers_includes_credentials() {
        let text = "password: hunter2";
        let matches = collect_all_identifiers(text);

        let has_password = matches
            .iter()
            .any(|m| m.identifier_type == IdentifierType::Password);
        assert!(
            has_password,
            "Should detect password via credential builder: {matches:?}"
        );
    }

    #[test]
    fn test_detect_from_matches_same_as_full_detection() {
        let text = "username: admin@example.com\npassword: SuperSecret123!";
        let matches = collect_all_identifiers(text);
        let config = CorrelationConfig::default();

        let from_text = detect_credential_pairs_with_config(text, &config);
        let from_matches = detect_credential_pairs_from_matches(text, &matches, &config);

        assert_eq!(
            from_text.len(),
            from_matches.len(),
            "Pre-collected matches should produce same results as full detection"
        );
        for (a, b) in from_text.iter().zip(from_matches.iter()) {
            assert_eq!(a.pair_type, b.pair_type);
        }
    }
}
