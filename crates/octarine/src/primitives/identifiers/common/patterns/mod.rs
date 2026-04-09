//! Shared regex patterns for identifier detection in text
//!
//! This module provides reusable regex patterns for scanning text documents
//! to find various identifier types. These patterns are used by both detection
//! and sanitization layers.
//!
//! # Pattern Categories
//!
//! - **Personal**: SSN, tax IDs, driver licenses, passports, employee/student IDs, national IDs, names, birthdates
//! - **Financial**: Credit cards, payment tokens, routing numbers, bank accounts
//! - **Network**: UUIDs, MAC addresses, IP addresses, URLs, emails, phones, JWTs, API keys
//! - **Medical**: MRN, insurance numbers, NPI, ICD-10, CPT codes
//! - **Biometric**: Fingerprints, face encodings, iris scans, voice prints, DNA
//! - **Location**: Coordinates, addresses, postal codes
//! - **Vehicle**: VIN numbers, license plates
//!
//! # Design Principles
//!
//! - **Conservative matching**: Prefer false negatives over false positives
//! - **Context aware**: Use capture groups to preserve surrounding text
//! - **Performance**: Use lazy_static for one-time compilation
//! - **Extensibility**: Easy to add new patterns per identifier type

pub mod biometric;
pub mod credentials;
pub mod financial;
pub mod location;
pub mod medical;
pub mod network;
pub mod organizational;
pub mod personal;

#[path = "vehicle.rs"]
pub mod vehicle_id;

// Re-export all pattern modules for backward compatibility
pub use financial::{bank_account, credit_card, payment_token, routing_number};
pub use network::{email, phone, username};
pub use personal::{
    australia_abn, australia_tfn, birthdate, driver_license, employee_id, finland_hetu,
    india_aadhaar, india_pan, italy_fiscal_code, korea_rrn, national_id, passport, personal_name,
    poland_pesel, singapore_nric, spain_nie, spain_nif, ssn, student_id, tax_id,
};

// medical, biometric, location, and vehicle modules are already accessible via pub mod declarations
#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_ssn_patterns() {
        // Using invalid SSNs starting with 000 (clearly fake test data)
        assert!(ssn::LABELED.is_match("SSN: 900-00-0001"));
        assert!(ssn::WITH_DASHES.is_match("900-00-0002"));
        assert!(ssn::WITH_SPACES.is_match("900 00 0003"));
        assert!(!ssn::WITH_DASHES.is_match("900000004")); // No separators
    }

    #[test]
    fn test_tax_id_patterns() {
        // Using clearly fake test EINs
        assert!(tax_id::LABELED.is_match("EIN: 00-0000001"));
        assert!(tax_id::EIN_FORMAT.is_match("00-0000002"));
        assert!(tax_id::ITIN_FORMAT.is_match("900-00-0003"));
        assert!(tax_id::FEIN.is_match("Federal EIN: 00-0000004"));
    }

    #[test]
    fn test_driver_license_patterns() {
        assert!(driver_license::GENERIC.is_match("DL# A1234567"));
        assert!(driver_license::GENERIC.is_match("LICENSE: B9876543"));

        let states = driver_license::state_patterns();
        assert!(
            states
                .get("CA")
                .expect("CA pattern should exist")
                .is_match("A1234567")
        ); // California
        assert!(
            states
                .get("TX")
                .expect("TX pattern should exist")
                .is_match("12345678")
        ); // Texas
    }

    #[test]
    fn test_passport_patterns() {
        assert!(passport::EXPLICIT.is_match("Passport: 123456789"));
        assert!(passport::WITH_PREFIX.is_match("PP# 987654321"));
        assert!(passport::GENERIC.is_match("C12345678"));
    }

    #[test]
    fn test_employee_id_patterns() {
        assert!(employee_id::LABELED.is_match("EMP00123"));
        assert!(employee_id::BADGE.is_match("BADGE# 98765"));
        assert!(employee_id::E_NUMBER.is_match("E123456"));
    }

    #[test]
    fn test_student_id_patterns() {
        assert!(student_id::LABELED.is_match("STUDENT# ABC12345"));
        assert!(student_id::S_NUMBER.is_match("S12345678"));
    }

    #[test]
    fn test_national_id_patterns() {
        assert!(national_id::UK_NI.is_match("AB123456C"));
        assert!(national_id::CANADA_SIN.is_match("123-456-789"));
        assert!(national_id::CANADA_SIN.is_match("123 456 789"));
    }

    #[test]
    fn test_vehicle_id_patterns() {
        assert!(vehicle_id::VIN_LABELED.is_match("VIN: 1HGBH41JXMN109186"));
        assert!(vehicle_id::VIN_EXPLICIT.is_match("VIN 1HGBH41JXMN109186"));
        assert!(vehicle_id::LICENSE_PLATE.is_match("ABC-1234"));
    }

    #[test]
    fn test_location_patterns() {
        // GPS coordinates
        assert!(location::DECIMAL_DEGREES.is_match("40.7128, -74.0060"));
        assert!(location::DMS_FORMAT.is_match("40°42'46.0\"N 74°00'21.6\"W"));
        assert!(location::LABELED_LAT.is_match("lat: 40.7128"));
        assert!(location::LABELED_LON.is_match("lon: -74.0060"));

        // Addresses
        assert!(location::US_STREET_ADDRESS.is_match("123 Main Street"));
        assert!(location::PO_BOX.is_match("P.O. Box 12345"));
        assert!(location::APT_SUITE.is_match("Apt 4B"));

        // Postal codes
        assert!(location::US_ZIP.is_match("10001"));
        assert!(location::US_ZIP_PLUS4.is_match("10001-1234"));
        assert!(location::UK_POSTCODE.is_match("SW1A 1AA"));
        assert!(location::CANADA_POSTAL.is_match("K1A 0B1"));
    }

    #[test]
    fn test_email_patterns() {
        assert!(email::STANDARD.is_match("user@example.com"));
        assert!(email::STANDARD.is_match("test.user+tag@domain.co.uk"));
        assert!(!email::STANDARD.is_match("invalid.email"));
    }

    #[test]
    fn test_phone_patterns() {
        assert!(phone::WITH_COUNTRY_CODE.is_match("+1-555-123-4567"));
        assert!(phone::WITH_PARENS.is_match("(555) 123-4567"));
        assert!(phone::STANDARD.is_match("555-123-4567"));
    }

    #[test]
    fn test_credit_card_patterns() {
        // Using known Stripe test card (4242...)
        assert!(credit_card::WITH_SPACES.is_match("4242 4242 4242 4242"));
        assert!(credit_card::WITH_DASHES.is_match("4242-4242-4242-4242"));
        assert!(credit_card::NO_SEPARATOR.is_match("4242424242424242"));
        assert!(credit_card::LABELED.is_match("Card: 4242424242424242"));
    }

    #[test]
    fn test_payment_token_patterns() {
        assert!(payment_token::STRIPE.is_match("tok_EXAMPLE000000000000KEY01abcd"));
        assert!(payment_token::STRIPE.is_match("pm_EXAMPLE000000000000KEY01abcd"));
        assert!(payment_token::PAYPAL.is_match("EC-12345678901234567"));
    }

    #[test]
    fn test_bank_account_patterns() {
        // Using clearly fake IBAN with XX country code
        assert!(bank_account::IBAN.is_match("XX00 TEST 0000 0000 0000 01"));
        assert!(bank_account::LABELED.is_match("Account: 0900000001"));
    }

    // ==================== FALSE POSITIVE TESTS ====================
    // These tests ensure patterns don't match similar but non-sensitive data

    #[test]
    fn test_ssn_false_positives() {
        // Should NOT match dates (common false positive)
        assert!(!ssn::WITH_DASHES.is_match("2024-01-15"));
        assert!(!ssn::WITH_DASHES.is_match("1990-12-31"));

        // Should NOT match version numbers
        assert!(!ssn::WITH_DASHES.is_match("123-45-67890")); // Wrong number of digits
        assert!(!ssn::WITH_DASHES.is_match("12-345-6789")); // Wrong grouping

        // Should NOT match partial numbers
        assert!(!ssn::WITH_DASHES.is_match("12-34-567")); // Too short
        assert!(!ssn::WITH_DASHES.is_match("1234-56-7890")); // Extra digit

        // Should NOT match phone-like patterns
        assert!(!ssn::WITH_SPACES.is_match("555 123 4567")); // 10 digits, not 9
    }

    #[test]
    fn test_tax_id_false_positives() {
        // Should NOT match SSN-like patterns (different grouping)
        assert!(!tax_id::EIN_FORMAT.is_match("123-45-6789")); // SSN format

        // Should NOT match short numbers
        assert!(!tax_id::EIN_FORMAT.is_match("12-34567")); // Only 6 after dash

        // Should NOT match numbers with wrong grouping (no 2-digit prefix)
        assert!(!tax_id::EIN_FORMAT.is_match("1-1234567")); // Only 1 digit before dash
        assert!(!tax_id::EIN_FORMAT.is_match("123-1234567")); // 3 digits before dash
    }

    #[test]
    fn test_email_false_positives() {
        // Should NOT match without @ symbol
        assert!(!email::STANDARD.is_match("user.example.com"));

        // Should NOT match without domain
        assert!(!email::STANDARD.is_match("user@"));

        // Should NOT match without TLD
        assert!(!email::STANDARD.is_match("user@example"));

        // Should NOT match single char TLD
        assert!(!email::STANDARD.is_match("user@example.c"));

        // Should NOT match special chars in wrong places
        assert!(!email::STANDARD.is_match("@example.com"));
    }

    #[test]
    fn test_phone_false_positives() {
        // Should NOT match short numbers
        assert!(!phone::STANDARD.is_match("555-1234"));
        assert!(!phone::STANDARD.is_match("12-345-6789")); // Only 9 digits

        // Should NOT match too many digits
        assert!(!phone::STANDARD.is_match("5555-123-4567")); // 11 digits

        // Should NOT match SSN-formatted numbers
        assert!(!phone::STANDARD.is_match("123-45-6789")); // 3-2-4 is SSN
    }

    #[test]
    fn test_credit_card_false_positives() {
        // Should NOT match 15-digit numbers (wrong length)
        assert!(!credit_card::NO_SEPARATOR.is_match("123456789012345"));

        // Should NOT match 17-digit numbers
        assert!(!credit_card::NO_SEPARATOR.is_match("12345678901234567"));

        // Should NOT match wrong groupings
        assert!(!credit_card::WITH_DASHES.is_match("12345-678-9012-3456")); // 5-3-4-4
        assert!(!credit_card::WITH_SPACES.is_match("12345 678 9012 3456")); // 5-3-4-4
    }

    #[test]
    fn test_passport_false_positives() {
        // Should NOT match too short
        assert!(!passport::EXPLICIT.is_match("Passport: 1234567")); // 7 digits
        assert!(!passport::WITH_PREFIX.is_match("PP# 12345678")); // 8 digits

        // Should NOT match too long
        assert!(!passport::EXPLICIT.is_match("Passport: 1234567890")); // 10 digits
        assert!(!passport::WITH_PREFIX.is_match("PP# 1234567890")); // 10 digits

        // Generic pattern - ensure too short doesn't match
        assert!(!passport::GENERIC.is_match("A12345")); // Only 5 digits
    }

    #[test]
    fn test_employee_id_false_positives() {
        // E_NUMBER should NOT match single letters followed by few digits
        assert!(!employee_id::E_NUMBER.is_match("E123")); // Too short
        assert!(!employee_id::E_NUMBER.is_match("E1234")); // Still too short

        // Should NOT match other prefixes
        assert!(!employee_id::E_NUMBER.is_match("F123456")); // Wrong prefix
    }

    #[test]
    fn test_location_false_positives() {
        // GPS: Should NOT match out-of-range coordinates
        // Note: Regex checks format, not semantic validity, but we test boundaries

        // ZIP: Should NOT match 4-digit numbers
        assert!(!location::US_ZIP.is_match("1234"));
        assert!(!location::US_ZIP.is_match("123456")); // 6 digits

        // ZIP+4: Should NOT match wrong format
        assert!(!location::US_ZIP_PLUS4.is_match("12345-123")); // Only 3 after dash
        assert!(!location::US_ZIP_PLUS4.is_match("12345-12345")); // 5 after dash

        // UK Postcode: Should NOT match wrong format
        assert!(!location::UK_POSTCODE.is_match("12345")); // Numeric only
        assert!(!location::UK_POSTCODE.is_match("ABCD 1AB")); // Too many letters
    }

    #[test]
    fn test_national_id_false_positives() {
        // UK NI: Should NOT match wrong letter/digit patterns
        assert!(!national_id::UK_NI.is_match("A1123456C")); // Only 1 letter at start
        assert!(!national_id::UK_NI.is_match("AB1234567")); // Too many digits
        assert!(!national_id::UK_NI.is_match("AB12345")); // Too few digits
        assert!(!national_id::UK_NI.is_match("AB123456CD")); // 2 letters at end

        // Canada SIN: Should NOT match wrong groupings
        assert!(!national_id::CANADA_SIN.is_match("12-345-6789")); // 2-3-4
        assert!(!national_id::CANADA_SIN.is_match("1234-567-89")); // 4-3-2
    }

    #[test]
    fn test_vehicle_id_false_positives() {
        // VIN: Should NOT match wrong length
        assert!(!vehicle_id::VIN_STANDALONE.is_match("1HGBH41JXMN10918")); // 16 chars
        assert!(!vehicle_id::VIN_STANDALONE.is_match("1HGBH41JXMN1091860")); // 18 chars

        // VIN: Should NOT match invalid characters (I, O, Q excluded)
        assert!(!vehicle_id::VIN_STANDALONE.is_match("1HGIH41JXMN109186")); // Contains I
        assert!(!vehicle_id::VIN_STANDALONE.is_match("1HGOH41JXMN109186")); // Contains O
        assert!(!vehicle_id::VIN_STANDALONE.is_match("1HGQH41JXMN109186")); // Contains Q
    }

    #[test]
    fn test_payment_token_false_positives() {
        // Stripe: Should NOT match wrong prefixes
        assert!(!payment_token::STRIPE.is_match("sk_EXAMPLE000000000000KEY01abcd")); // Secret key prefix
        assert!(!payment_token::STRIPE.is_match("pk_EXAMPLE000000000000KEY01abcd")); // Publishable key

        // Stripe: Should NOT match too short
        assert!(!payment_token::STRIPE.is_match("tok_123456789")); // Only 9 chars after prefix

        // PayPal: Should NOT match wrong length
        assert!(!payment_token::PAYPAL.is_match("EC-1234567890123456")); // 16 chars
        assert!(!payment_token::PAYPAL.is_match("EC-123456789012345678")); // 18 chars
    }

    #[test]
    fn test_personal_name_false_positives() {
        // FIRST_LAST: Should NOT match all lowercase
        assert!(!personal_name::FIRST_LAST.is_match("john smith"));

        // FIRST_LAST: Should NOT match single words
        assert!(!personal_name::FIRST_LAST.is_match("John"));

        // LAST_FIRST: Should NOT match without comma
        assert!(!personal_name::LAST_FIRST.is_match("Smith John"));
    }

    #[test]
    fn test_birthdate_false_positives() {
        // ISO: Should NOT match years outside 1900-2099
        assert!(!birthdate::ISO_FORMAT.is_match("1899-05-15"));
        assert!(!birthdate::ISO_FORMAT.is_match("2100-05-15"));

        // ISO: Should NOT match invalid months
        assert!(!birthdate::ISO_FORMAT.is_match("1990-13-15")); // Month 13
        assert!(!birthdate::ISO_FORMAT.is_match("1990-00-15")); // Month 00

        // ISO: Should NOT match invalid days
        assert!(!birthdate::ISO_FORMAT.is_match("1990-05-32")); // Day 32
        assert!(!birthdate::ISO_FORMAT.is_match("1990-05-00")); // Day 00

        // US format: Same validations
        assert!(!birthdate::US_FORMAT.is_match("13/15/1990")); // Invalid month
        assert!(!birthdate::US_FORMAT.is_match("05/32/1990")); // Invalid day
    }

    #[test]
    fn test_medical_false_positives() {
        // NPI: Must start with 1 or 2
        assert!(!medical::NPI.is_match("NPI: 3123456789")); // Starts with 3
        assert!(!medical::NPI.is_match("NPI: 0123456789")); // Starts with 0

        // NPI: Must be exactly 10 digits
        assert!(!medical::NPI.is_match("NPI: 123456789")); // 9 digits
        assert!(!medical::NPI.is_match("NPI: 12345678901")); // 11 digits
    }

    #[test]
    fn test_biometric_false_positives() {
        // Fingerprint: Should NOT match git commit hashes without context
        // (Regex requires label like "fingerprint:", "fp:", etc.)
        assert!(!biometric::FINGERPRINT_LABELED.is_match("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"));

        // DNA: Should NOT match short sequences
        assert!(!biometric::DNA_SEQUENCE.is_match("ATCGATCGATCGATCGATC")); // Only 19

        // DNA: Should NOT match non-ATCG characters
        assert!(!biometric::DNA_SEQUENCE.is_match("ATCGATCGATCGATCGXYZX")); // Contains XYZ
    }

    #[test]
    fn test_boundary_conditions() {
        // Empty strings should not match
        assert!(!ssn::WITH_DASHES.is_match(""));
        assert!(!email::STANDARD.is_match(""));
        assert!(!phone::STANDARD.is_match(""));
        assert!(!credit_card::NO_SEPARATOR.is_match(""));

        // Whitespace only should not match
        assert!(!ssn::WITH_DASHES.is_match("   "));
        assert!(!email::STANDARD.is_match("   "));
    }

    #[test]
    fn test_context_specificity() {
        // Labeled patterns should require the label
        assert!(ssn::LABELED.is_match("SSN: 900-00-0001"));
        assert!(!ssn::LABELED.is_match("900-00-0001")); // No label

        assert!(passport::EXPLICIT.is_match("Passport: 123456789"));
        assert!(!passport::EXPLICIT.is_match("123456789")); // No label

        assert!(tax_id::LABELED.is_match("EIN: 00-0000001"));
        assert!(!tax_id::LABELED.is_match("00-0000001")); // No label
    }
}
