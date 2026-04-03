//! Per-entity keyword dictionaries for context-aware confidence scoring
//!
//! Maps identifier types to contextual keywords that, when found near a
//! pattern match, indicate higher confidence. Keywords are lowercase and
//! drawn from Presidio's context-aware approach.

use crate::primitives::identifiers::IdentifierType;

// ============================================================================
// Keyword Dictionaries
// ============================================================================

/// Returns context keywords for the given identifier type.
///
/// Keywords are lowercase strings that, when found in the text window
/// surrounding a pattern match, suggest the match is a true positive.
///
/// Returns an empty slice for identifier types without defined keywords.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::confidence::context_keywords;
/// use octarine::primitives::identifiers::IdentifierType;
///
/// let keywords = context_keywords(&IdentifierType::Ssn);
/// assert!(keywords.contains(&"social security"));
/// ```
#[must_use]
pub fn context_keywords(entity_type: &IdentifierType) -> &'static [&'static str] {
    match entity_type {
        IdentifierType::Ssn => &[
            "social security",
            "ssn",
            "ss#",
            "social security number",
            "tax id",
            "taxpayer",
            "itin",
            "individual taxpayer",
        ],
        IdentifierType::CreditCard => &[
            "credit card",
            "card number",
            "card no",
            "card #",
            "cc#",
            "cc number",
            "debit card",
            "visa",
            "mastercard",
            "amex",
            "american express",
            "payment card",
            "pan",
        ],
        IdentifierType::Email => &[
            "email",
            "e-mail",
            "mail",
            "email address",
            "contact",
            "send to",
            "reply to",
        ],
        IdentifierType::PhoneNumber => &[
            "phone",
            "telephone",
            "tel",
            "mobile",
            "cell",
            "fax",
            "call",
            "phone number",
            "contact number",
        ],
        IdentifierType::BankAccount => &[
            "bank account",
            "account number",
            "account no",
            "acct",
            "iban",
            "routing",
            "aba",
            "swift",
            "bic",
            "checking",
            "savings",
        ],
        IdentifierType::DriverLicense => &[
            "driver license",
            "driver's license",
            "driving license",
            "dl",
            "dl#",
            "license number",
            "licence",
        ],
        IdentifierType::Passport => &[
            "passport",
            "passport number",
            "passport no",
            "travel document",
        ],
        IdentifierType::Birthdate => &[
            "date of birth",
            "dob",
            "birth date",
            "birthday",
            "born",
            "birth",
        ],
        IdentifierType::IpAddress => &[
            "ip address",
            "ip addr",
            "ip",
            "source ip",
            "destination ip",
            "client ip",
            "server ip",
            "remote addr",
            "host",
        ],
        IdentifierType::ApiKey => &[
            "api key",
            "api_key",
            "apikey",
            "api token",
            "api secret",
            "access key",
            "secret key",
            "auth token",
            "authorization",
        ],
        IdentifierType::AwsAccessKey => &[
            "aws",
            "aws_access_key",
            "aws_secret",
            "access key id",
            "secret access key",
            "iam",
            "amazon web services",
        ],
        IdentifierType::PersonalName => &[
            "name",
            "full name",
            "first name",
            "last name",
            "surname",
            "given name",
            "family name",
            "patient name",
            "customer name",
        ],
        IdentifierType::RoutingNumber => &[
            "routing",
            "routing number",
            "aba",
            "transit number",
            "bank routing",
        ],
        _ => &[],
    }
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
        let keywords = context_keywords(&IdentifierType::Ssn);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"social security"));
        assert!(keywords.contains(&"ssn"));
    }

    #[test]
    fn test_credit_card_keywords() {
        let keywords = context_keywords(&IdentifierType::CreditCard);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"credit card"));
        assert!(keywords.contains(&"card number"));
    }

    #[test]
    fn test_email_keywords() {
        let keywords = context_keywords(&IdentifierType::Email);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"email"));
    }

    #[test]
    fn test_phone_keywords() {
        let keywords = context_keywords(&IdentifierType::PhoneNumber);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"phone"));
        assert!(keywords.contains(&"mobile"));
    }

    #[test]
    fn test_bank_account_keywords() {
        let keywords = context_keywords(&IdentifierType::BankAccount);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"bank account"));
        assert!(keywords.contains(&"iban"));
    }

    #[test]
    fn test_driver_license_keywords() {
        let keywords = context_keywords(&IdentifierType::DriverLicense);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"driver license"));
    }

    #[test]
    fn test_passport_keywords() {
        let keywords = context_keywords(&IdentifierType::Passport);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"passport"));
    }

    #[test]
    fn test_birthdate_keywords() {
        let keywords = context_keywords(&IdentifierType::Birthdate);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"date of birth"));
        assert!(keywords.contains(&"dob"));
    }

    #[test]
    fn test_ip_address_keywords() {
        let keywords = context_keywords(&IdentifierType::IpAddress);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"ip address"));
    }

    #[test]
    fn test_api_key_keywords() {
        let keywords = context_keywords(&IdentifierType::ApiKey);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"api key"));
    }

    #[test]
    fn test_aws_keywords() {
        let keywords = context_keywords(&IdentifierType::AwsAccessKey);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"aws"));
    }

    #[test]
    fn test_personal_name_keywords() {
        let keywords = context_keywords(&IdentifierType::PersonalName);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"name"));
    }

    #[test]
    fn test_routing_number_keywords() {
        let keywords = context_keywords(&IdentifierType::RoutingNumber);
        assert!(!keywords.is_empty());
        assert!(keywords.contains(&"routing"));
    }

    #[test]
    fn test_unknown_type_returns_empty() {
        let keywords = context_keywords(&IdentifierType::Unknown);
        assert!(keywords.is_empty());
    }

    #[test]
    fn test_all_keywords_are_lowercase() {
        let types_with_keywords = [
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

        for entity_type in &types_with_keywords {
            for keyword in context_keywords(entity_type) {
                assert_eq!(
                    *keyword,
                    keyword.to_lowercase(),
                    "Keyword '{}' for {:?} is not lowercase",
                    keyword,
                    entity_type
                );
            }
        }
    }

    #[test]
    fn test_minimum_entity_coverage() {
        // Ensure at least 11 entity types have keywords (acceptance criteria)
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
            .filter(|t| !context_keywords(t).is_empty())
            .count();

        assert!(
            covered >= 11,
            "Expected at least 11 entity types with keywords, got {}",
            covered
        );
    }
}
