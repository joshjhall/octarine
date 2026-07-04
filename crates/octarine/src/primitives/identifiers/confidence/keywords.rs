//! Per-entity, per-language keyword lookup for context-aware confidence scoring
//!
//! Maps `(identifier type, language)` to contextual keywords that, when found
//! near a pattern match, indicate higher confidence. The keyword data lives in
//! [`crate::primitives::identifiers::common::keywords`], one file per language
//! mirroring Presidio's per-language layout; this module is the lookup over
//! those tables. Keywords are lowercase and drawn from Presidio's
//! context-aware approach.

use crate::primitives::identifiers::IdentifierType;
use crate::primitives::identifiers::common::KeywordLanguage;

// ============================================================================
// Keyword Lookup
// ============================================================================

/// Returns context keywords for the given identifier type in one language.
///
/// Keywords are lowercase strings that, when found in the text window
/// surrounding a pattern match, suggest the match is a true positive.
///
/// Returns an empty slice for identifier types that have no keywords defined
/// in the requested language.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::confidence::{context_keywords, KeywordLanguage};
/// use octarine::primitives::identifiers::IdentifierType;
///
/// let keywords = context_keywords(&IdentifierType::Ssn, KeywordLanguage::En);
/// assert!(keywords.contains(&"social security"));
/// ```
#[must_use]
pub fn context_keywords(
    entity_type: &IdentifierType,
    language: KeywordLanguage,
) -> &'static [&'static str] {
    language
        .keywords()
        .iter()
        .find(|(ty, _)| ty == entity_type)
        .map_or(&[], |(_, keywords)| *keywords)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_ssn_keywords() {
        let keywords = context_keywords(&IdentifierType::Ssn, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"social security"));
        assert!(keywords.contains(&"ssn"));
    }

    #[test]
    fn test_credit_card_keywords() {
        let keywords = context_keywords(&IdentifierType::CreditCard, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"credit card"));
        assert!(keywords.contains(&"card number"));
    }

    #[test]
    fn test_email_keywords() {
        let keywords = context_keywords(&IdentifierType::Email, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"email"));
    }

    #[test]
    fn test_phone_keywords() {
        let keywords = context_keywords(&IdentifierType::PhoneNumber, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"phone"));
        assert!(keywords.contains(&"mobile"));
    }

    #[test]
    fn test_bank_account_keywords() {
        let keywords = context_keywords(&IdentifierType::BankAccount, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"bank account"));
        assert!(keywords.contains(&"iban"));
    }

    #[test]
    fn test_driver_license_keywords() {
        let keywords = context_keywords(&IdentifierType::DriverLicense, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"driver license"));
    }

    #[test]
    fn test_passport_keywords() {
        let keywords = context_keywords(&IdentifierType::Passport, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"passport"));
    }

    #[test]
    fn test_birthdate_keywords() {
        let keywords = context_keywords(&IdentifierType::Birthdate, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"date of birth"));
        assert!(keywords.contains(&"dob"));
    }

    #[test]
    fn test_ip_address_keywords() {
        let keywords = context_keywords(&IdentifierType::IpAddress, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"ip address"));
    }

    #[test]
    fn test_api_key_keywords() {
        let keywords = context_keywords(&IdentifierType::ApiKey, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"api key"));
    }

    #[test]
    fn test_api_key_keywords_resolve_per_language() {
        // The non-Latin ApiKey keywords now live in their own language tables
        // rather than being flat-appended to the English list. Spot-check one
        // keyword per script family. `test_all_keywords_are_lowercase` enforces
        // the lowercase invariant across every entry and language.
        assert!(
            context_keywords(&IdentifierType::ApiKey, KeywordLanguage::Ja).contains(&"apiキー"),
            "Japanese api key missing"
        );
        assert!(
            context_keywords(&IdentifierType::ApiKey, KeywordLanguage::ZhHans).contains(&"api密钥"),
            "Chinese Simplified missing"
        );
        assert!(
            context_keywords(&IdentifierType::ApiKey, KeywordLanguage::ZhHant).contains(&"api密鑰"),
            "Chinese Traditional missing"
        );
        assert!(
            context_keywords(&IdentifierType::ApiKey, KeywordLanguage::Ko).contains(&"api키"),
            "Korean missing"
        );
        assert!(
            context_keywords(&IdentifierType::ApiKey, KeywordLanguage::Ar).contains(&"مفتاح api"),
            "Arabic missing"
        );
        assert!(
            context_keywords(&IdentifierType::ApiKey, KeywordLanguage::Hi).contains(&"एपीआई कुंजी"),
            "Hindi missing"
        );
    }

    #[test]
    fn test_api_key_english_excludes_non_latin() {
        // The English table must no longer carry the non-Latin keywords.
        let en = context_keywords(&IdentifierType::ApiKey, KeywordLanguage::En);
        assert!(!en.contains(&"apiキー"));
        assert!(!en.contains(&"api密钥"));
    }

    #[test]
    fn test_aws_keywords() {
        let keywords = context_keywords(&IdentifierType::AwsAccessKey, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"aws"));
    }

    #[test]
    fn test_personal_name_keywords() {
        let keywords = context_keywords(&IdentifierType::PersonalName, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"name"));
    }

    #[test]
    fn test_routing_number_keywords() {
        let keywords = context_keywords(&IdentifierType::RoutingNumber, KeywordLanguage::En);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"routing"));
    }

    #[test]
    fn test_low3_backfill_non_empty() {
        // LOW-3: entities that previously returned `&[]` now have English
        // context keywords.
        let backfilled = [
            IdentifierType::Iban,
            IdentifierType::CryptoAddress,
            IdentifierType::MacAddress,
            IdentifierType::Url,
            IdentifierType::Jwt,
            IdentifierType::BearerToken,
            IdentifierType::OAuthToken,
            IdentifierType::SshKey,
            IdentifierType::SessionId,
            IdentifierType::Uuid,
            IdentifierType::Username,
            IdentifierType::Password,
            IdentifierType::ConnectionString,
            IdentifierType::HighEntropyString,
            IdentifierType::OnePasswordToken,
            IdentifierType::OnePasswordVaultRef,
            IdentifierType::UrlWithCredentials,
        ];
        for ty in &backfilled {
            assert!(
                !context_keywords(ty, KeywordLanguage::En).is_empty(),
                "LOW-3 backfill missing English keywords for {ty:?}"
            );
        }
    }

    #[test]
    fn test_unknown_type_returns_empty() {
        // Unknown resolves to an empty slice in every language.
        for language in KeywordLanguage::all() {
            assert!(context_keywords(&IdentifierType::Unknown, language).is_empty());
        }
    }

    #[test]
    fn test_all_keywords_are_lowercase() {
        // Walk every identifier type present in every language table and confirm
        // the lowercase invariant holds across all scripts.
        for language in KeywordLanguage::all() {
            for (entity_type, keywords) in language.keywords() {
                for keyword in *keywords {
                    assert_eq!(
                        *keyword,
                        keyword.to_lowercase(),
                        "Keyword '{keyword}' for {entity_type:?} ({language:?}) is not lowercase"
                    );
                }
            }
        }
    }

    #[test]
    fn test_minimum_entity_coverage() {
        // Ensure at least 11 entity types have English keywords (acceptance
        // criteria from the original context-keyword work).
        let all_types = [
            IdentifierType::Ssn,
            IdentifierType::CreditCard,
            IdentifierType::Email,
            IdentifierType::PhoneNumber,
            IdentifierType::BankAccount,
            IdentifierType::DriverLicense,
            IdentifierType::Passport,
            IdentifierType::Birthdate,
            IdentifierType::IpAddress,
            IdentifierType::ApiKey,
            IdentifierType::AwsAccessKey,
            IdentifierType::PersonalName,
            IdentifierType::RoutingNumber,
        ];

        let covered = all_types
            .iter()
            .filter(|t| !context_keywords(t, KeywordLanguage::En).is_empty())
            .count();

        assert!(
            covered >= 11,
            "Expected at least 11 entity types with keywords, got {covered}"
        );
    }

    #[test]
    fn test_every_language_table_resolves() {
        // Every KeywordLanguage variant must resolve to a (possibly empty)
        // table without panicking.
        for language in KeywordLanguage::all() {
            let _ = language.keywords();
        }
    }
}
