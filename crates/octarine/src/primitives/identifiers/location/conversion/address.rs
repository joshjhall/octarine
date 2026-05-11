//! US street address normalization (USPS Publication 28 conventions)
//!
//! Provides deterministic case and abbreviation normalization for US-format
//! street addresses. Operates as a token-level rewrite over whitespace-
//! separated tokens; commas and ZIP codes are preserved verbatim.
//!
//! # Scope
//!
//! US-locale only. Other locales (UK, CA, JP, ...) have different
//! conventions and are intentionally out of scope. For pure whitespace
//! collapse with validation, see [`super::super::sanitization::sanitize_street_address_strict`].

use super::super::detection;
use crate::primitives::Problem;

// ============================================================================
// Types
// ============================================================================

/// US address normalization mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressNormalization {
    /// Expand abbreviations: `"St"` → `"Street"`, `"N"` → `"North"`,
    /// `"Apt"` → `"Apartment"`. Best for human-readable display and audit
    /// logs.
    Expand,
    /// Use USPS abbreviations: `"Street"` → `"St"`, `"North"` → `"N"`,
    /// `"Apartment"` → `"Apt"`. Matches USPS Publication 28 mailing-
    /// address conventions.
    Abbreviate,
}

// ============================================================================
// Abbreviation Tables
// ============================================================================

// Restricted to suffixes accepted by the address-detection regex so the
// normalized output still validates as a US street address.
const SUFFIX_TABLE: &[(&str, &str)] = &[
    ("st", "Street"),
    ("ave", "Avenue"),
    ("blvd", "Boulevard"),
    ("rd", "Road"),
    ("dr", "Drive"),
    ("ln", "Lane"),
    ("ct", "Court"),
    ("pl", "Place"),
    ("way", "Way"),
];

const DIRECTIONAL_TABLE: &[(&str, &str)] = &[
    ("n", "North"),
    ("s", "South"),
    ("e", "East"),
    ("w", "West"),
    ("ne", "Northeast"),
    ("nw", "Northwest"),
    ("se", "Southeast"),
    ("sw", "Southwest"),
];

const UNIT_TABLE: &[(&str, &str)] = &[("apt", "Apartment"), ("ste", "Suite")];

const STATE_CODES: &[&str] = &[
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS",
    "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY",
    "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV",
    "WI", "WY", "DC", "AS", "GU", "MP", "PR", "VI",
];

// ============================================================================
// Public API
// ============================================================================

/// Normalize a US street address to canonical form.
///
/// Applies USPS Publication 28 conventions for street suffixes, directionals,
/// and unit designators in a single token-level pass. Whitespace is
/// collapsed; commas are preserved; ZIP and ZIP+4 codes pass through
/// unchanged; two-letter state codes are upper-cased.
///
/// The normalized output is re-validated with [`detection::is_street_address`]
/// — inputs whose normalization no longer matches a US-address shape are
/// rejected.
///
/// # Modes
///
/// - [`AddressNormalization::Expand`]: `"St"` → `"Street"`, `"N"` → `"North"`,
///   `"Apt"` → `"Apartment"`. Suited to display and audit output.
/// - [`AddressNormalization::Abbreviate`]: `"Street"` → `"St"`, `"North"` →
///   `"N"`, `"Apartment"` → `"Apt"`. Matches USPS mailing conventions.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::{
///     normalize_us_street_address, AddressNormalization,
/// };
///
/// assert_eq!(
///     normalize_us_street_address("123 main st", AddressNormalization::Expand).unwrap(),
///     "123 Main Street"
/// );
/// assert_eq!(
///     normalize_us_street_address(
///         "456 Oak Avenue NW, Seattle, WA 98101",
///         AddressNormalization::Abbreviate,
///     )
///     .unwrap(),
///     "456 Oak Ave NW, Seattle, WA 98101"
/// );
/// ```
///
/// # Errors
///
/// Returns [`Problem::Validation`] when the input is empty or when the
/// normalized output does not match a recognized US street-address shape.
pub fn normalize_us_street_address(
    input: &str,
    mode: AddressNormalization,
) -> Result<String, Problem> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Address is empty".into()));
    }

    let collapsed: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    let result: String = collapsed
        .split(' ')
        .map(|token| normalize_token(token, mode))
        .collect::<Vec<_>>()
        .join(" ");

    if !detection::is_street_address(&result) {
        return Err(Problem::Validation(
            "Input does not match a recognized US street-address shape".into(),
        ));
    }

    Ok(result)
}

// ============================================================================
// Token-level Helpers
// ============================================================================

fn normalize_token(token: &str, mode: AddressNormalization) -> String {
    let (core, trailing) = split_trailing_punct(token);
    let mapped = map_core(core, mode);
    if trailing.is_empty() {
        mapped
    } else {
        format!("{}{}", mapped, trailing)
    }
}

/// Split a token into its core and trailing punctuation (comma, colon,
/// semicolon, ...). Internal and trailing periods stay with the core so
/// patterns like `"P.O."` and `"St."` are handled by table lookup.
fn split_trailing_punct(s: &str) -> (&str, &str) {
    let trailing_byte_len: usize = s
        .chars()
        .rev()
        .take_while(|c| !c.is_alphanumeric() && *c != '.')
        .map(char::len_utf8)
        .sum();
    let split = s.len().saturating_sub(trailing_byte_len);
    s.split_at(split)
}

fn map_core(core: &str, mode: AddressNormalization) -> String {
    if core.is_empty() {
        return String::new();
    }

    if is_us_zip_token(core) {
        return core.to_string();
    }

    let upper = core.to_ascii_uppercase();
    if core.len() == 2
        && core.chars().all(|c| c.is_ascii_alphabetic())
        && STATE_CODES.contains(&upper.as_str())
    {
        return upper;
    }

    // Strip periods for table lookup so "St" and "St." both resolve.
    let cleaned: String = core.chars().filter(|c| *c != '.').collect();
    let lower = cleaned.to_ascii_lowercase();

    if let Some(mapped) = lookup_directional(&lower, mode) {
        return mapped;
    }
    if let Some(mapped) = lookup_suffix(&lower, mode) {
        return mapped;
    }
    if let Some(mapped) = lookup_unit(&lower, mode) {
        return mapped;
    }

    // Mixed alphanumeric tokens (e.g., "4B", "I-95"): uppercase letters,
    // preserve digits and punctuation.
    if core.chars().any(|c| c.is_ascii_digit()) {
        return core.chars().map(|c| c.to_ascii_uppercase()).collect();
    }

    title_case_word(core)
}

fn lookup_directional(token_lower: &str, mode: AddressNormalization) -> Option<String> {
    DIRECTIONAL_TABLE
        .iter()
        .find(|(short, long)| *short == token_lower || long.eq_ignore_ascii_case(token_lower))
        .map(|(short, long)| match mode {
            AddressNormalization::Expand => (*long).to_string(),
            AddressNormalization::Abbreviate => short.to_ascii_uppercase(),
        })
}

fn lookup_suffix(token_lower: &str, mode: AddressNormalization) -> Option<String> {
    SUFFIX_TABLE
        .iter()
        .find(|(short, long)| *short == token_lower || long.eq_ignore_ascii_case(token_lower))
        .map(|(short, long)| match mode {
            AddressNormalization::Expand => (*long).to_string(),
            AddressNormalization::Abbreviate => capitalize_first(short),
        })
}

fn lookup_unit(token_lower: &str, mode: AddressNormalization) -> Option<String> {
    UNIT_TABLE
        .iter()
        .find(|(short, long)| *short == token_lower || long.eq_ignore_ascii_case(token_lower))
        .map(|(short, long)| match mode {
            AddressNormalization::Expand => (*long).to_string(),
            AddressNormalization::Abbreviate => capitalize_first(short),
        })
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => {
            let mut out = c.to_ascii_uppercase().to_string();
            out.push_str(&chars.as_str().to_ascii_lowercase());
            out
        }
        None => String::new(),
    }
}

fn is_us_zip_token(s: &str) -> bool {
    if s.len() == 5 {
        return s.chars().all(|c| c.is_ascii_digit());
    }
    if s.len() == 10 && s.chars().nth(5) == Some('-') {
        return s.chars().take(5).all(|c| c.is_ascii_digit())
            && s.chars().skip(6).all(|c| c.is_ascii_digit());
    }
    false
}

/// Title-case a single word, respecting internal periods and hyphens so
/// `"p.o."` becomes `"P.O."` and `"mary-jane"` becomes `"Mary-Jane"`.
fn title_case_word(s: &str) -> String {
    s.split_inclusive(['.', '-'])
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) if first.is_ascii_alphabetic() => {
                    let mut out = first.to_ascii_uppercase().to_string();
                    out.push_str(&chars.as_str().to_ascii_lowercase());
                    out
                }
                Some(first) => {
                    let mut out = first.to_string();
                    out.push_str(chars.as_str());
                    out
                }
                None => String::new(),
            }
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    fn expand(s: &str) -> String {
        normalize_us_street_address(s, AddressNormalization::Expand).unwrap()
    }

    fn abbrev(s: &str) -> String {
        normalize_us_street_address(s, AddressNormalization::Abbreviate).unwrap()
    }

    #[test]
    fn expand_lowercase_input() {
        assert_eq!(expand("123 main st"), "123 Main Street");
        assert_eq!(expand("456 oak ave"), "456 Oak Avenue");
        assert_eq!(expand("789 elm rd"), "789 Elm Road");
    }

    #[test]
    fn expand_all_caps_input() {
        assert_eq!(expand("123 MAIN STREET"), "123 Main Street");
        assert_eq!(expand("456 OAK AVE"), "456 Oak Avenue");
    }

    #[test]
    fn abbreviate_long_form() {
        assert_eq!(abbrev("123 Main Street"), "123 Main St");
        assert_eq!(abbrev("456 Oak Avenue"), "456 Oak Ave");
        assert_eq!(abbrev("789 Sunset Boulevard"), "789 Sunset Blvd");
    }

    #[test]
    fn expand_with_directional() {
        assert_eq!(expand("456 oak ave NW"), "456 Oak Avenue Northwest");
        assert_eq!(expand("100 main st N"), "100 Main Street North");
    }

    #[test]
    fn abbreviate_with_directional() {
        assert_eq!(abbrev("456 Oak Avenue Northwest"), "456 Oak Ave NW");
        assert_eq!(abbrev("100 Main Street North"), "100 Main St N");
    }

    #[test]
    fn state_code_preserved_upper() {
        assert_eq!(
            expand("123 main st, los angeles, ca 90001"),
            "123 Main Street, Los Angeles, CA 90001"
        );
    }

    #[test]
    fn zip_codes_preserved() {
        assert_eq!(
            expand("123 main st, seattle, wa 98101-1234"),
            "123 Main Street, Seattle, WA 98101-1234"
        );
    }

    #[test]
    fn period_after_suffix_still_maps() {
        // "St." should expand to "Street" — the trailing period is stripped
        // for table lookup.
        assert_eq!(expand("123 main st."), "123 Main Street");
        assert_eq!(abbrev("123 Main Street."), "123 Main St");
    }

    #[test]
    fn po_box_title_cased() {
        // "P.O." is preserved as a multi-period token; "Box" title-cases.
        assert_eq!(expand("p.o. box 12345"), "P.O. Box 12345");
    }

    #[test]
    fn apt_expand_and_abbreviate() {
        assert_eq!(expand("Apt 4B"), "Apartment 4B");
        assert_eq!(abbrev("Apartment 4B"), "Apt 4B");
        assert_eq!(expand("ste 200"), "Suite 200");
        assert_eq!(abbrev("Suite 200"), "Ste 200");
    }

    #[test]
    fn idempotent() {
        let address = "123 Main Street, San Francisco, CA 94102";
        assert_eq!(expand(address), address);
        assert_eq!(expand(&expand(address)), expand(address));

        let abbreviated = "456 Oak Ave NW, Seattle, WA 98101";
        assert_eq!(abbrev(abbreviated), abbreviated);
        assert_eq!(abbrev(&abbrev(abbreviated)), abbrev(abbreviated));
    }

    #[test]
    fn collapses_interior_whitespace() {
        assert_eq!(expand("  123   main   st  "), "123 Main Street");
        assert_eq!(expand("123\t\tmain\nst"), "123 Main Street");
    }

    #[test]
    fn unit_designator_with_digit_token() {
        // "4B" should preserve its mixed-case digit form.
        assert_eq!(expand("apt 4b"), "Apartment 4B");
        assert_eq!(expand("apt 4B"), "Apartment 4B");
    }

    #[test]
    fn empty_input_rejected() {
        assert!(matches!(
            normalize_us_street_address("", AddressNormalization::Expand),
            Err(Problem::Validation(_))
        ));
        assert!(matches!(
            normalize_us_street_address("   ", AddressNormalization::Expand),
            Err(Problem::Validation(_))
        ));
    }

    #[test]
    fn non_address_input_rejected() {
        // Bare number is not an address.
        assert!(normalize_us_street_address("12345", AddressNormalization::Expand).is_err());
        // Random text is not an address.
        assert!(normalize_us_street_address("just text", AddressNormalization::Expand).is_err());
    }

    #[test]
    fn way_round_trips() {
        // "Way" is a suffix with no shorter form — must round-trip in both modes.
        assert_eq!(expand("123 broad way"), "123 Broad Way");
        assert_eq!(abbrev("123 Broad Way"), "123 Broad Way");
    }

    #[test]
    fn directional_lowercase_input() {
        // Lowercase directional input should still resolve.
        assert_eq!(expand("100 main st n"), "100 Main Street North");
        assert_eq!(expand("100 main st northwest"), "100 Main Street Northwest");
    }

    #[test]
    fn split_trailing_punct_handles_comma() {
        let (core, trailing) = split_trailing_punct("St,");
        assert_eq!(core, "St");
        assert_eq!(trailing, ",");
    }

    #[test]
    fn split_trailing_punct_keeps_period() {
        let (core, trailing) = split_trailing_punct("St.");
        assert_eq!(core, "St.");
        assert_eq!(trailing, "");
    }

    #[test]
    fn is_us_zip_token_basic() {
        assert!(is_us_zip_token("90001"));
        assert!(is_us_zip_token("90001-1234"));
        assert!(!is_us_zip_token("9001"));
        assert!(!is_us_zip_token("ABC12"));
        assert!(!is_us_zip_token("90001-12"));
    }

    #[test]
    fn title_case_word_handles_periods_and_hyphens() {
        assert_eq!(title_case_word("p.o."), "P.O.");
        assert_eq!(title_case_word("MARY-JANE"), "Mary-Jane");
        assert_eq!(title_case_word("mcdonald"), "Mcdonald");
    }
}
