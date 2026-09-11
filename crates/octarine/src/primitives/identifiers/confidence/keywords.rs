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
    fn test_country_scoped_types_have_native_keywords() {
        // #667 acceptance: country-specific identifiers resolve in their own
        // language. Each of these returned `&[]` in every language before.
        let cases = [
            (IdentifierType::ItalyFiscalCode, KeywordLanguage::It),
            (IdentifierType::SpainNif, KeywordLanguage::Es),
            (IdentifierType::PolandPesel, KeywordLanguage::Pl),
            (IdentifierType::FinlandHetu, KeywordLanguage::Fi),
            (IdentifierType::KoreaRrn, KeywordLanguage::Ko),
            (IdentifierType::IndiaAadhaar, KeywordLanguage::Hi),
            (IdentifierType::IndiaPan, KeywordLanguage::Hi),
            (IdentifierType::ThailandTnin, KeywordLanguage::Th),
        ];
        for (entity_type, language) in cases {
            assert!(
                !context_keywords(&entity_type, language).is_empty(),
                "{entity_type:?} has no {language:?} keywords"
            );
        }
    }

    #[test]
    fn test_country_scoped_types_are_not_force_fitted() {
        // Coverage is additive, not uniform: an Italian codice fiscale has no
        // Swedish or Thai terminology and must stay empty there rather than
        // being padded with a translation Presidio does not have.
        for language in [
            KeywordLanguage::Sv,
            KeywordLanguage::Th,
            KeywordLanguage::Ar,
        ] {
            assert!(
                context_keywords(&IdentifierType::ItalyFiscalCode, language).is_empty(),
                "ItalyFiscalCode should have no {language:?} keywords"
            );
        }
    }

    #[test]
    fn test_top_entities_covered_in_every_language() {
        // Every non-English language table must cover the core identifier set,
        // not just the BankAccount entry PR #666 shipped.
        let core = [
            IdentifierType::Ssn,
            IdentifierType::CreditCard,
            IdentifierType::Email,
            IdentifierType::PhoneNumber,
            IdentifierType::BankAccount,
            IdentifierType::RoutingNumber,
            IdentifierType::DriverLicense,
            IdentifierType::Passport,
            IdentifierType::Birthdate,
            IdentifierType::IpAddress,
            IdentifierType::ApiKey,
            IdentifierType::PersonalName,
            IdentifierType::Iban,
        ];
        for language in KeywordLanguage::all() {
            for entity_type in &core {
                assert!(
                    !context_keywords(entity_type, language).is_empty(),
                    "{language:?} table is missing {entity_type:?}"
                );
            }
        }
    }

    #[test]
    fn test_no_duplicate_identifier_rows_per_language() {
        // A duplicated key would make the first row win silently in the linear
        // `find`, hiding every keyword in the later row.
        for language in KeywordLanguage::all() {
            let mut seen: Vec<&IdentifierType> = Vec::new();
            for (entity_type, _) in language.keywords() {
                assert!(
                    !seen.contains(&entity_type),
                    "{language:?} lists {entity_type:?} twice"
                );
                seen.push(entity_type);
            }
        }
    }

    #[test]
    fn test_no_empty_keyword_entries() {
        // An empty string keyword would `contains("")` == true and boost every
        // single match unconditionally.
        for language in KeywordLanguage::all() {
            for (entity_type, keywords) in language.keywords() {
                assert!(
                    !keywords.is_empty(),
                    "{language:?} {entity_type:?} has an empty keyword list"
                );
                for keyword in *keywords {
                    assert!(
                        !keyword.trim().is_empty(),
                        "{language:?} {entity_type:?} has a blank keyword"
                    );
                }
            }
        }
    }

    #[test]
    fn test_from_tag_resolves_known_languages() {
        assert_eq!(KeywordLanguage::from_tag("it"), Some(KeywordLanguage::It));
        assert_eq!(KeywordLanguage::from_tag("IT"), Some(KeywordLanguage::It));
        assert_eq!(
            KeywordLanguage::from_tag("it-IT"),
            Some(KeywordLanguage::It)
        );
        assert_eq!(
            KeywordLanguage::from_tag("fr_CA"),
            Some(KeywordLanguage::Fr)
        );
        assert_eq!(
            KeywordLanguage::from_tag("zh-Hans"),
            Some(KeywordLanguage::ZhHans)
        );
        assert_eq!(
            KeywordLanguage::from_tag("zh_hant"),
            Some(KeywordLanguage::ZhHant)
        );
        assert_eq!(
            KeywordLanguage::from_tag("zh-TW"),
            Some(KeywordLanguage::ZhHant)
        );
        // Bare "zh" defaults to Simplified.
        assert_eq!(
            KeywordLanguage::from_tag("zh"),
            Some(KeywordLanguage::ZhHans)
        );
        // Presidio spells Korean "kr" in some language YAMLs.
        assert_eq!(KeywordLanguage::from_tag("kr"), Some(KeywordLanguage::Ko));
    }

    #[test]
    fn test_from_tag_resolves_three_segment_chinese_tags() {
        // script + region, the form the "hant-tw"/"hant-hk"/"hant-mo" arms exist
        // for.
        for tag in ["zh-Hant-TW", "zh-Hant-HK", "zh_hant_mo"] {
            assert_eq!(
                KeywordLanguage::from_tag(tag),
                Some(KeywordLanguage::ZhHant),
                "tag {tag:?} should resolve to Traditional"
            );
        }
        assert_eq!(
            KeywordLanguage::from_tag("zh-Hans-CN"),
            Some(KeywordLanguage::ZhHans)
        );
        // Reverse order (region before script) is not a real BCP-47 spelling and
        // is not special-cased — it falls back to Simplified, like bare "zh".
        assert_eq!(
            KeywordLanguage::from_tag("zh-TW-Hant"),
            Some(KeywordLanguage::ZhHans)
        );
    }

    #[test]
    fn test_from_tag_rejects_unknown() {
        for tag in ["", "klingon", "xx", "zzz-ZZ", "  "] {
            assert_eq!(
                KeywordLanguage::from_tag(tag),
                None,
                "tag {tag:?} should not resolve"
            );
        }
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
