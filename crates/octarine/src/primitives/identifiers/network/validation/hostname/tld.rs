//! Top-Level Domain (TLD) validation
//!
//! Pure validation functions for TLDs according to IANA/ICANN standards.

use crate::primitives::Problem;

// ============================================================================
// Common TLD List
// ============================================================================

/// Common top-level domains from IANA's official list
///
/// This list includes the most commonly used TLDs as of 2024:
/// - Generic TLDs (gTLDs): .com, .org, .net, etc.
/// - Country Code TLDs (ccTLDs): .us, .uk, .ca, etc.
/// - New gTLDs: .app, .dev, .cloud, etc.
/// - Infrastructure TLD: .arpa
///
/// Note: This is not an exhaustive list. IANA maintains 1,500+ TLDs and the list
/// changes frequently. For comprehensive validation, consider:
/// - Using the IANA TLD list API
/// - Maintaining an updated local copy of the official list
/// - Accepting custom TLDs for internal networks
///
/// See: <https://www.iana.org/domains/root/db>
const COMMON_TLDS: &[&str] = &[
    // Generic TLDs (Original + Common)
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "name",
    "pro",
    "mobi",
    "coop",
    "aero",
    "museum",
    "travel",
    "jobs",
    "cat",
    "tel",
    "asia",
    "post",
    // Popular New gTLDs
    "app",
    "dev",
    "cloud",
    "tech",
    "io",
    "ai",
    "website",
    "site",
    "online",
    "store",
    "shop",
    "blog",
    "digital",
    "email",
    "systems",
    "software",
    "codes",
    "services",
    "solutions",
    "technology",
    "engineering",
    "network",
    "group",
    "company",
    "agency",
    "management",
    "consulting",
    "finance",
    "capital",
    "ventures",
    "partners",
    "holdings",
    "enterprises",
    "business",
    "global",
    "international",
    "world",
    "media",
    "news",
    "live",
    "studio",
    "productions",
    "photos",
    "gallery",
    "graphics",
    "design",
    "art",
    "ink",
    "club",
    "cafe",
    "bar",
    "restaurant",
    "food",
    "recipes",
    "cooking",
    "health",
    "medical",
    "dental",
    "surgery",
    "clinic",
    "care",
    "insurance",
    "lawyer",
    "attorney",
    "legal",
    "law",
    "education",
    "university",
    "college",
    "school",
    "academy",
    "training",
    "courses",
    "builders",
    "construction",
    "realestate",
    "properties",
    "homes",
    "apartments",
    "land",
    "games",
    "gaming",
    "casino",
    "bet",
    "poker",
    "sports",
    "fitness",
    "yoga",
    "golf",
    "football",
    "soccer",
    "basketball",
    "hockey",
    "cricket",
    "tennis",
    "racing",
    // Country Code TLDs (Most Common)
    "us",
    "uk",
    "ca",
    "au",
    "de",
    "fr",
    "it",
    "es",
    "nl",
    "be",
    "ch",
    "at",
    "se",
    "no",
    "dk",
    "fi",
    "pl",
    "cz",
    "pt",
    "gr",
    "ro",
    "hu",
    "ie",
    "nz",
    "sg",
    "hk",
    "jp",
    "kr",
    "cn",
    "tw",
    "in",
    "th",
    "my",
    "id",
    "ph",
    "vn",
    "pk",
    "bd",
    "ae",
    "sa",
    "il",
    "tr",
    "za",
    "ng",
    "eg",
    "ke",
    "gh",
    "br",
    "mx",
    "ar",
    "cl",
    "co",
    "pe",
    "ve",
    "ru",
    "ua",
    "by",
    "kz",
    "ge",
    "am",
    "az",
    // Special/Infrastructure
    "arpa",
    "example",
    "invalid",
    "localhost",
    "test",
    "onion",
    // Additional common TLDs
    "xxx",
    "adult",
    "dating",
    "sex",
    "cam",
    "porn",
    "tokyo",
    "london",
    "nyc",
    "miami",
    "berlin",
    "paris",
    "vegas",
    "city",
    "town",
    "country",
    "community",
    "social",
    "chat",
    "forum",
    "wiki",
    "blog",
    "news",
    "press",
    "today",
    "now",
    "life",
    "style",
    "fun",
    "cool",
    "best",
    "top",
    "vip",
    "plus",
    "pro",
    "express",
    "direct",
    "fast",
    "quick",
    "easy",
    "simple",
    "smart",
    "safe",
    "secure",
    "green",
    "blue",
    "red",
    "gold",
    "black",
    "cheap",
    "sale",
    "discount",
    "deals",
    "bargains",
    "free",
    "gift",
    "win",
];

// ============================================================================
// TLD Extraction and Validation
// ============================================================================

/// Extract TLD from a domain or hostname
///
/// Returns the last label after the final dot.
/// Does not validate the TLD, only extracts it.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::extract_tld;
///
/// assert_eq!(extract_tld("example.com"), Some("com"));
/// assert_eq!(extract_tld("sub.example.com"), Some("com"));
/// assert_eq!(extract_tld("localhost"), Some("localhost"));
/// assert_eq!(extract_tld("example.co.uk"), Some("uk"));
/// assert_eq!(extract_tld(""), None);
/// ```
#[must_use]
pub fn extract_tld(domain: &str) -> Option<&str> {
    if domain.is_empty() {
        return None;
    }

    // Remove trailing dot if present (FQDN format)
    let domain = domain.strip_suffix('.').unwrap_or(domain);

    // Split by dots and take last label
    domain.split('.').next_back()
}

/// Validate TLD format according to ICANN/IANA requirements
///
/// Validates the format of a top-level domain:
/// - Length: 2-63 characters (per RFC 1123)
/// - Characters: Only ASCII letters, digits, and hyphens
/// - Must start and end with alphanumeric
/// - Cannot be all numeric (per ICANN policy)
///
/// This validates FORMAT only, not whether the TLD is registered with IANA.
/// Use `validate_tld_against_iana()` to check against known TLDs.
///
/// For bool check, use `validate_tld_format(..).is_ok()`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::validate_tld_format;
///
/// // Valid TLD formats
/// assert!(validate_tld_format("com").is_ok());
/// assert!(validate_tld_format("io").is_ok());
/// assert!(validate_tld_format("technology").is_ok());
///
/// // Invalid TLD formats
/// assert!(validate_tld_format("c").is_err()); // Too short
/// assert!(validate_tld_format("-com").is_err()); // Starts with hyphen
/// assert!(validate_tld_format("com-").is_err()); // Ends with hyphen
/// assert!(validate_tld_format("123").is_err()); // All numeric
/// ```
pub fn validate_tld_format(tld: &str) -> Result<(), Problem> {
    // Empty check
    if tld.is_empty() {
        return Err(Problem::Validation("TLD cannot be empty".into()));
    }

    // Length check (RFC 1123: min 2, max 63 characters)
    if tld.len() < 2 {
        return Err(Problem::Validation(format!(
            "TLD '{}' too short (minimum 2 characters)",
            tld
        )));
    }

    if tld.len() > 63 {
        return Err(Problem::Validation(format!(
            "TLD '{}' too long ({} characters, max 63)",
            tld,
            tld.len()
        )));
    }

    // Must start with alphanumeric
    let first_char = tld
        .chars()
        .next()
        .ok_or_else(|| Problem::Validation("TLD has no characters".into()))?;

    if !first_char.is_ascii_alphanumeric() {
        return Err(Problem::Validation(format!(
            "TLD '{}' must start with alphanumeric character",
            tld
        )));
    }

    // Must end with alphanumeric
    let last_char = tld
        .chars()
        .last()
        .ok_or_else(|| Problem::Validation("TLD has no characters".into()))?;

    if !last_char.is_ascii_alphanumeric() {
        return Err(Problem::Validation(format!(
            "TLD '{}' must end with alphanumeric character",
            tld
        )));
    }

    // Check all characters
    for c in tld.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' {
            return Err(Problem::Validation(format!(
                "TLD '{}' contains invalid character '{}' (only alphanumeric and hyphens allowed)",
                tld, c
            )));
        }
    }

    // Cannot be all numeric (ICANN policy)
    if tld.chars().all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(format!(
            "TLD '{}' cannot be all numeric (per ICANN policy)",
            tld
        )));
    }

    Ok(())
}

/// Check if TLD is in the common TLD list
///
/// Returns true if the TLD is in the `COMMON_TLDS` list.
/// This list includes ~200 of the most popular TLDs but is not exhaustive.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::is_common_tld;
///
/// assert!(is_common_tld("com"));
/// assert!(is_common_tld("org"));
/// assert!(is_common_tld("io"));
/// assert!(is_common_tld("dev"));
/// assert!(!is_common_tld("xyz123")); // Not a common TLD
/// ```
#[must_use]
pub fn is_common_tld(tld: &str) -> bool {
    let tld_lower = tld.to_lowercase();
    COMMON_TLDS.contains(&tld_lower.as_str())
}

/// Validate TLD against IANA's common TLD list
///
/// Validates that the TLD is in the `COMMON_TLDS` list, which includes ~200
/// of the most popular TLDs from IANA's registry.
///
/// **Important**: This is NOT an exhaustive check against all 1,500+ registered TLDs.
/// IANA frequently adds new TLDs, so this list may not include all valid TLDs.
///
/// For comprehensive validation:
/// - Use IANA's official TLD list API
/// - Maintain an updated local copy
/// - Accept custom TLDs for internal networks
///
/// For bool check, use `validate_tld_against_iana(..).is_ok()`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::validate_tld_against_iana;
///
/// // Common TLDs
/// assert!(validate_tld_against_iana("com").is_ok());
/// assert!(validate_tld_against_iana("org").is_ok());
/// assert!(validate_tld_against_iana("dev").is_ok());
///
/// // Uncommon or new TLDs (may not be in list)
/// // assert!(validate_tld_against_iana("newgTLD").is_err());
/// ```
pub fn validate_tld_against_iana(tld: &str) -> Result<(), Problem> {
    // First validate format
    validate_tld_format(tld)?;

    // Check against common TLD list
    if !is_common_tld(tld) {
        return Err(Problem::Validation(format!(
            "TLD '{}' not found in common TLD list (note: this list is not exhaustive)",
            tld
        )));
    }

    Ok(())
}

/// Validate domain has a valid TLD
///
/// Extracts the TLD from the domain and validates it against the common TLD list.
///
/// For bool check, use `validate_domain_tld(..).is_ok()`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::validate_domain_tld;
///
/// assert!(validate_domain_tld("example.com").is_ok());
/// assert!(validate_domain_tld("sub.example.org").is_ok());
/// assert!(validate_domain_tld("app.dev").is_ok());
/// ```
pub fn validate_domain_tld(domain: &str) -> Result<(), Problem> {
    let tld = extract_tld(domain).ok_or_else(|| Problem::Validation("Domain has no TLD".into()))?;
    validate_tld_against_iana(tld)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_extract_tld() {
        // Basic extraction
        assert_eq!(extract_tld("example.com"), Some("com"));
        assert_eq!(extract_tld("example.org"), Some("org"));
        assert_eq!(extract_tld("example.io"), Some("io"));

        // Subdomain extraction (should get TLD only)
        assert_eq!(extract_tld("sub.example.com"), Some("com"));
        assert_eq!(extract_tld("deep.sub.example.org"), Some("org"));

        // Single label (no dot)
        assert_eq!(extract_tld("localhost"), Some("localhost"));
        assert_eq!(extract_tld("hostname"), Some("hostname"));

        // FQDN with trailing dot
        assert_eq!(extract_tld("example.com."), Some("com"));
        assert_eq!(extract_tld("sub.example.org."), Some("org"));

        // Multi-part TLD (should extract last part only)
        assert_eq!(extract_tld("example.co.uk"), Some("uk"));
        assert_eq!(extract_tld("example.com.au"), Some("au"));

        // Edge cases
        assert_eq!(extract_tld(""), None);
        assert_eq!(extract_tld("."), Some(""));
        assert_eq!(extract_tld(".."), Some(""));
    }

    #[test]
    fn test_validate_tld_format_valid() {
        // Generic TLDs
        assert!(validate_tld_format("com").is_ok());
        assert!(validate_tld_format("org").is_ok());
        assert!(validate_tld_format("net").is_ok());
        assert!(validate_tld_format("edu").is_ok());

        // Country code TLDs
        assert!(validate_tld_format("us").is_ok());
        assert!(validate_tld_format("uk").is_ok());
        assert!(validate_tld_format("ca").is_ok());
        assert!(validate_tld_format("de").is_ok());

        // New gTLDs
        assert!(validate_tld_format("app").is_ok());
        assert!(validate_tld_format("dev").is_ok());
        assert!(validate_tld_format("cloud").is_ok());
        assert!(validate_tld_format("tech").is_ok());
        assert!(validate_tld_format("io").is_ok());

        // Long TLDs
        assert!(validate_tld_format("technology").is_ok());
        assert!(validate_tld_format("international").is_ok());

        // TLDs with hyphens (valid if not at start/end)
        assert!(validate_tld_format("x-test").is_ok());

        // Case insensitive
        assert!(validate_tld_format("COM").is_ok());
        assert!(validate_tld_format("Com").is_ok());
        assert!(validate_tld_format("ORG").is_ok());
    }

    #[test]
    fn test_validate_tld_format_invalid() {
        // Too short (< 2 characters)
        assert!(validate_tld_format("c").is_err());
        assert!(validate_tld_format("x").is_err());

        // Empty
        assert!(validate_tld_format("").is_err());

        // Too long (> 63 characters)
        let long_tld = "a".repeat(64);
        assert!(validate_tld_format(&long_tld).is_err());

        // Starts with hyphen
        assert!(validate_tld_format("-com").is_err());
        assert!(validate_tld_format("-test").is_err());

        // Ends with hyphen
        assert!(validate_tld_format("com-").is_err());
        assert!(validate_tld_format("test-").is_err());

        // All numeric (ICANN policy)
        assert!(validate_tld_format("123").is_err());
        assert!(validate_tld_format("456").is_err());

        // Contains invalid characters
        assert!(validate_tld_format("com_test").is_err());
        assert!(validate_tld_format("com.test").is_err());
        assert!(validate_tld_format("com@test").is_err());
        assert!(validate_tld_format("com#test").is_err());
        assert!(validate_tld_format("com$test").is_err());
        assert!(validate_tld_format("com test").is_err()); // Space
    }

    #[test]
    fn test_is_common_tld() {
        // Generic TLDs
        assert!(is_common_tld("com"));
        assert!(is_common_tld("org"));
        assert!(is_common_tld("net"));
        assert!(is_common_tld("edu"));
        assert!(is_common_tld("gov"));
        assert!(is_common_tld("mil"));
        assert!(is_common_tld("int"));

        // Popular new gTLDs
        assert!(is_common_tld("app"));
        assert!(is_common_tld("dev"));
        assert!(is_common_tld("cloud"));
        assert!(is_common_tld("tech"));
        assert!(is_common_tld("io"));
        assert!(is_common_tld("ai"));

        // Country codes
        assert!(is_common_tld("us"));
        assert!(is_common_tld("uk"));
        assert!(is_common_tld("ca"));
        assert!(is_common_tld("de"));
        assert!(is_common_tld("fr"));
        assert!(is_common_tld("jp"));

        // Case insensitive
        assert!(is_common_tld("COM"));
        assert!(is_common_tld("Com"));
        assert!(is_common_tld("ORG"));

        // Not in list
        assert!(!is_common_tld("xyz123"));
        assert!(!is_common_tld("notreal"));
        assert!(!is_common_tld("fake"));
    }

    #[test]
    fn test_validate_tld_against_iana_valid() {
        // Common gTLDs
        assert!(validate_tld_against_iana("com").is_ok());
        assert!(validate_tld_against_iana("org").is_ok());
        assert!(validate_tld_against_iana("net").is_ok());

        // New gTLDs
        assert!(validate_tld_against_iana("app").is_ok());
        assert!(validate_tld_against_iana("dev").is_ok());
        assert!(validate_tld_against_iana("cloud").is_ok());

        // Country codes
        assert!(validate_tld_against_iana("us").is_ok());
        assert!(validate_tld_against_iana("uk").is_ok());
        assert!(validate_tld_against_iana("ca").is_ok());

        // Case insensitive
        assert!(validate_tld_against_iana("COM").is_ok());
        assert!(validate_tld_against_iana("Com").is_ok());
    }

    #[test]
    fn test_validate_tld_against_iana_invalid() {
        // Not in common list
        assert!(validate_tld_against_iana("xyz123").is_err());
        assert!(validate_tld_against_iana("notreal").is_err());

        // Invalid format (fails format check first)
        assert!(validate_tld_against_iana("c").is_err()); // Too short
        assert!(validate_tld_against_iana("-com").is_err()); // Starts with hyphen
        assert!(validate_tld_against_iana("123").is_err()); // All numeric
        assert!(validate_tld_against_iana("").is_err()); // Empty
    }

    #[test]
    fn test_validate_domain_tld_valid() {
        // Single level domains
        assert!(validate_domain_tld("example.com").is_ok());
        assert!(validate_domain_tld("example.org").is_ok());
        assert!(validate_domain_tld("example.net").is_ok());

        // Subdomains
        assert!(validate_domain_tld("www.example.com").is_ok());
        assert!(validate_domain_tld("sub.example.org").is_ok());
        assert!(validate_domain_tld("api.service.example.com").is_ok());

        // New gTLDs
        assert!(validate_domain_tld("myapp.dev").is_ok());
        assert!(validate_domain_tld("project.app").is_ok());
        assert!(validate_domain_tld("service.cloud").is_ok());

        // FQDN with trailing dot
        assert!(validate_domain_tld("example.com.").is_ok());
        assert!(validate_domain_tld("www.example.org.").is_ok());

        // Case insensitive
        assert!(validate_domain_tld("Example.COM").is_ok());
        assert!(validate_domain_tld("WWW.Example.ORG").is_ok());
    }

    #[test]
    fn test_validate_domain_tld_invalid() {
        // Invalid TLD
        assert!(validate_domain_tld("example.xyz123").is_err());
        assert!(validate_domain_tld("example.notreal").is_err());

        // No TLD
        assert!(validate_domain_tld("").is_err());

        // Single label with invalid TLD
        assert!(validate_domain_tld("invalidtld12345").is_err());
    }

    #[test]
    fn test_validate_tld_format_errors() {
        // Test that validation returns proper errors
        let result = validate_tld_format("");
        assert!(result.is_err());

        let result = validate_tld_format("c");
        assert!(result.is_err());

        let result = validate_tld_format("-com");
        assert!(result.is_err());

        let result = validate_tld_format("123");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_tld_against_iana_errors() {
        // Not in list
        let result = validate_tld_against_iana("xyz123");
        assert!(result.is_err());

        // Invalid format
        let result = validate_tld_against_iana("-com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_domain_tld_errors() {
        // Invalid TLD
        let result = validate_domain_tld("example.xyz123");
        assert!(result.is_err());

        // No TLD
        let result = validate_domain_tld("");
        assert!(result.is_err());
    }

    // ============================================================================
    // Adversarial Tests
    // ============================================================================

    #[test]
    fn test_adversarial_tld_numeric_bypass() {
        // All-numeric TLDs are invalid per ICANN policy
        assert!(validate_tld_format("123").is_err());
        assert!(validate_tld_format("456").is_err());
        assert!(validate_tld_format("000").is_err());
        assert!(validate_tld_format("999").is_err());

        // Mixed alphanumeric should be valid format
        assert!(validate_tld_format("a1").is_ok());
        assert!(validate_tld_format("1a").is_ok());
        assert!(validate_tld_format("a1b2").is_ok());
    }

    #[test]
    fn test_adversarial_tld_homograph() {
        // Cyrillic lookalikes for common TLDs
        assert!(!is_common_tld("сom")); // Cyrillic 'с' instead of 'c'
        assert!(!is_common_tld("оrg")); // Cyrillic 'о' instead of 'o'
        assert!(!is_common_tld("nеt")); // Cyrillic 'е' instead of 'e'
    }

    #[test]
    fn test_adversarial_tld_length_tricks() {
        // Single character (too short)
        assert!(validate_tld_format("c").is_err());
        assert!(validate_tld_format("x").is_err());

        // Exactly 2 characters (minimum valid)
        assert!(validate_tld_format("co").is_ok());
        assert!(validate_tld_format("io").is_ok());

        // Maximum 63 characters (valid)
        let max_tld = "a".repeat(63);
        assert!(validate_tld_format(&max_tld).is_ok());

        // 64 characters (too long)
        let over_max = "a".repeat(64);
        assert!(validate_tld_format(&over_max).is_err());
    }
}

#[cfg(test)]
mod proptests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_no_panic_tld_validation(s in "\\PC*") {
            let _ = validate_tld_format(&s);
            let _ = extract_tld(&s);
        }

        #[test]
        fn prop_tld_format_rules(s in "[a-z]{2,63}") {
            // Alphabetic TLDs of valid length should pass format check
            if s.len() >= 2 && s.len() <= 63 {
                assert!(validate_tld_format(&s).is_ok(), "Valid TLD format rejected: {}", s);
            }
        }

        #[test]
        fn prop_tld_not_numeric(n in 0u32..10000) {
            let numeric_tld = n.to_string();
            // All-numeric TLDs are invalid per ICANN
            assert!(validate_tld_format(&numeric_tld).is_err(), "Numeric TLD accepted: {}", numeric_tld);
        }

        #[test]
        fn prop_tld_extraction_consistency(s in "[a-z]+\\.[a-z]{2,63}") {
            if let Some(tld) = extract_tld(&s) {
                // Extracted TLD should pass format validation
                assert!(validate_tld_format(tld).is_ok(), "Extracted TLD invalid: {}", tld);
            }
        }

        #[test]
        fn prop_domain_tld_includes_format(s in "[a-z]+\\.[a-z]{2,63}") {
            // If domain TLD validation passes, format should pass
            if validate_domain_tld(&s).is_ok() && let Some(tld) = extract_tld(&s) {
                assert!(validate_tld_format(tld).is_ok(), "Domain TLD passed but format failed");
            }
        }
    }
}
