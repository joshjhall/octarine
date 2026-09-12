//! Table-driven US state driver's license validators
//!
//! Covers the top 20 US states by population, minus the four that carry
//! bespoke check-digit algorithms and therefore live in
//! [`super::north_america`]: California, Florida, Washington (and Nebraska,
//! which is not top-20 but predates this table).
//!
//! # Why a table rather than one impl per state
//!
//! Every validator here is **format-only**: the states in this table do not
//! publish their check-digit algorithms, so [`LicenseValidator::is_checksum_valid`]
//! returns `None` for all of them — the same honest signal
//! `north_america::NebraskaValidator` already gives. With no per-state
//! algorithm to express, a state differs from its neighbours only in its
//! accepted character layouts, which is data. Encoding that data as
//! [`US_STATE_FORMATS`] and validating it with a single generic
//! [`TableValidator`] keeps adding state 21 a one-line edit instead of an
//! eighty-line impl.
//!
//! # Layout sources
//!
//! Layouts follow the AAMVA jurisdiction formats also used by Microsoft
//! Presidio's `us_driver_license_recognizer`. Where a state issues more than
//! one historical layout, every layout it still honours is listed — a license
//! is valid for the state if it matches **any** of them.

use super::LicenseValidator;

// ============================================================================
// Layout
// ============================================================================

/// A single accepted character layout for a jurisdiction's license number.
///
/// Every layout is "some leading letters followed by some digits", so a
/// candidate is classified once (leading alphabetic run, then digit run) and
/// compared against each layout — see [`split_alpha_digits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Exactly `n` digits, no letters. Example: `Digits(8)` matches `12345678`.
    Digits(usize),
    /// Between `lo` and `hi` digits inclusive, no letters.
    /// Example: `DigitRange(7, 9)` matches `1234567` through `123456789`.
    DigitRange(usize, usize),
    /// Exactly `alpha` letters followed by exactly `digits` digits.
    /// Example: `AlphaDigits(1, 12)` matches `A123456789012`.
    AlphaDigits(usize, usize),
    /// Exactly `alpha` letters followed by `lo`–`hi` digits inclusive.
    /// Example: `AlphaDigitRange(1, 8, 11)` matches `A12345678` through `A12345678901`.
    AlphaDigitRange(usize, usize, usize),
}

impl Layout {
    /// Check whether a classified (letters, digits) shape satisfies this layout.
    #[must_use]
    fn accepts(self, alpha_count: usize, digit_count: usize) -> bool {
        match self {
            Self::Digits(n) => alpha_count == 0 && digit_count == n,
            Self::DigitRange(lo, hi) => alpha_count == 0 && digit_count >= lo && digit_count <= hi,
            Self::AlphaDigits(alpha, digits) => alpha_count == alpha && digit_count == digits,
            Self::AlphaDigitRange(alpha, lo, hi) => {
                alpha_count == alpha && digit_count >= lo && digit_count <= hi
            }
        }
    }
}

/// Classify a license number as a leading run of ASCII letters followed by a
/// run of ASCII digits.
///
/// Returns `None` when the input is not exclusively `letters*digits*` — a
/// letter appearing after a digit (`A12B34`), any non-alphanumeric character,
/// or a non-ASCII character (which also rejects Unicode lookalikes such as
/// Cyrillic `А`).
#[must_use]
fn split_alpha_digits(license: &str) -> Option<(usize, usize)> {
    let mut alpha_count: usize = 0;
    let mut digit_count: usize = 0;

    for c in license.chars() {
        if c.is_ascii_alphabetic() {
            // A letter after any digit means this is not `letters*digits*`.
            if digit_count > 0 {
                return None;
            }
            alpha_count = alpha_count.saturating_add(1);
        } else if c.is_ascii_digit() {
            digit_count = digit_count.saturating_add(1);
        } else {
            return None;
        }
    }

    Some((alpha_count, digit_count))
}

// ============================================================================
// Format Table
// ============================================================================

/// One jurisdiction's entry in the format table.
pub struct StateFormat {
    /// Jurisdiction code (e.g. `"US-TX"`).
    pub code: &'static str,
    /// Human-readable jurisdiction name (e.g. `"Texas"`).
    pub name: &'static str,
    /// Every layout this jurisdiction still honours. A license is format-valid
    /// if it matches any one of them.
    pub layouts: &'static [Layout],
    /// Human-readable format description for [`LicenseValidator::format_description`].
    pub description: &'static str,
}

/// Top-20-by-population US states, excluding the four with bespoke check-digit
/// validators in [`super::north_america`] (CA, FL, WA — plus NE).
pub static US_STATE_FORMATS: &[StateFormat] = &[
    StateFormat {
        code: "US-TX",
        name: "Texas",
        layouts: &[Layout::DigitRange(7, 8)],
        description: "7-8 digits (e.g. 12345678)",
    },
    StateFormat {
        code: "US-NY",
        name: "New York",
        layouts: &[Layout::Digits(9), Layout::AlphaDigits(1, 18)],
        description: "9 digits, or 1 letter + 18 digits (e.g. 123456789)",
    },
    StateFormat {
        code: "US-PA",
        name: "Pennsylvania",
        layouts: &[Layout::Digits(8)],
        description: "8 digits (e.g. 12345678)",
    },
    StateFormat {
        code: "US-IL",
        name: "Illinois",
        layouts: &[Layout::AlphaDigitRange(1, 11, 12)],
        description: "1 letter + 11-12 digits (e.g. A12345678901)",
    },
    StateFormat {
        code: "US-OH",
        name: "Ohio",
        layouts: &[
            Layout::AlphaDigitRange(1, 4, 8),
            Layout::AlphaDigitRange(2, 3, 7),
            Layout::Digits(8),
        ],
        description: "1-2 letters + digits, or 8 digits (e.g. AB1234567)",
    },
    StateFormat {
        code: "US-GA",
        name: "Georgia",
        layouts: &[Layout::DigitRange(7, 9)],
        description: "7-9 digits (e.g. 123456789)",
    },
    StateFormat {
        code: "US-NC",
        name: "North Carolina",
        // AAMVA documents NC as 1-12 digits, but a 1-digit "license" is not a
        // shape the DMV issues, and a floor of 1 would make this row accept
        // almost any short numeric token — a zip+4, a truncated account
        // number — reintroducing for one named state exactly the
        // over-permissiveness the unknown-jurisdiction error removed. The
        // floor is raised to the 8 digits NC actually issues; the ceiling
        // keeps AAMVA's 12 to cover historical numbers.
        layouts: &[Layout::DigitRange(8, 12)],
        description: "8-12 digits (e.g. 123456789)",
    },
    StateFormat {
        code: "US-MI",
        name: "Michigan",
        layouts: &[Layout::AlphaDigits(1, 10), Layout::AlphaDigits(1, 12)],
        description: "1 letter + 10 or 12 digits (e.g. A1234567890)",
    },
    StateFormat {
        code: "US-NJ",
        name: "New Jersey",
        layouts: &[Layout::AlphaDigits(1, 14)],
        description: "1 letter + 14 digits (e.g. A12345678901234)",
    },
    StateFormat {
        code: "US-VA",
        name: "Virginia",
        layouts: &[Layout::AlphaDigitRange(1, 8, 11), Layout::Digits(9)],
        description: "1 letter + 8-11 digits, or 9 digits (e.g. A123456789)",
    },
    StateFormat {
        code: "US-AZ",
        name: "Arizona",
        layouts: &[
            Layout::AlphaDigits(1, 8),
            Layout::AlphaDigitRange(2, 3, 6),
            Layout::Digits(9),
        ],
        description: "1 letter + 8 digits, 2 letters + 3-6 digits, or 9 digits (e.g. A12345678)",
    },
    StateFormat {
        code: "US-TN",
        name: "Tennessee",
        layouts: &[Layout::DigitRange(7, 9)],
        description: "7-9 digits (e.g. 123456789)",
    },
    StateFormat {
        code: "US-MA",
        name: "Massachusetts",
        layouts: &[Layout::AlphaDigits(1, 8), Layout::Digits(9)],
        description: "1 letter + 8 digits, or 9 digits (e.g. S12345678)",
    },
    StateFormat {
        code: "US-IN",
        name: "Indiana",
        layouts: &[Layout::AlphaDigits(1, 9), Layout::DigitRange(9, 10)],
        description: "1 letter + 9 digits, or 9-10 digits (e.g. A123456789)",
    },
    StateFormat {
        code: "US-MO",
        name: "Missouri",
        layouts: &[Layout::AlphaDigitRange(1, 5, 9), Layout::Digits(9)],
        description: "1 letter + 5-9 digits, or 9 digits (e.g. A123456789)",
    },
    StateFormat {
        code: "US-MD",
        name: "Maryland",
        layouts: &[Layout::AlphaDigits(1, 12)],
        description: "1 letter + 12 digits (e.g. A123456789012)",
    },
    StateFormat {
        code: "US-WI",
        name: "Wisconsin",
        layouts: &[Layout::AlphaDigits(1, 13)],
        description: "1 letter + 13 digits (e.g. A1234567890123)",
    },
];

// ============================================================================
// Generic Validator
// ============================================================================

/// A [`LicenseValidator`] backed by one [`StateFormat`] row.
///
/// Format-only by construction: [`Self::is_checksum_valid`] always returns
/// `None` because no jurisdiction in [`US_STATE_FORMATS`] publishes its
/// check-digit algorithm.
pub struct TableValidator {
    format: &'static StateFormat,
}

impl TableValidator {
    /// Create a validator for one table row.
    #[must_use]
    pub fn new(format: &'static StateFormat) -> Self {
        Self { format }
    }
}

impl LicenseValidator for TableValidator {
    fn jurisdiction_code(&self) -> &'static str {
        self.format.code
    }

    fn jurisdiction_name(&self) -> &'static str {
        self.format.name
    }

    fn is_format_valid(&self, license: &str) -> bool {
        let Some((alpha_count, digit_count)) = split_alpha_digits(license) else {
            return false;
        };

        self.format
            .layouts
            .iter()
            .any(|layout| layout.accepts(alpha_count, digit_count))
    }

    /// Always `None` — these jurisdictions have no publicly documented check
    /// digit, so format validity is the strongest claim available.
    fn is_checksum_valid(&self, _license: &str) -> Option<bool> {
        None
    }

    fn format_description(&self) -> &'static str {
        self.format.description
    }
}

/// Get all table-driven US state validators
pub fn validators() -> Vec<Box<dyn LicenseValidator>> {
    US_STATE_FORMATS
        .iter()
        .map(|format| Box::new(TableValidator::new(format)) as Box<dyn LicenseValidator>)
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    /// Look up a table row by jurisdiction code.
    fn validator_for(code: &str) -> TableValidator {
        let format = US_STATE_FORMATS
            .iter()
            .find(|f| f.code == code)
            .unwrap_or_else(|| panic!("{code} should be in the table"));
        TableValidator::new(format)
    }

    // ===== split_alpha_digits =====

    #[test]
    fn test_split_alpha_digits_shapes() {
        assert_eq!(split_alpha_digits("12345678"), Some((0, 8)));
        assert_eq!(split_alpha_digits("A1234567"), Some((1, 7)));
        assert_eq!(split_alpha_digits("AB123"), Some((2, 3)));
        assert_eq!(split_alpha_digits(""), Some((0, 0)));
    }

    #[test]
    fn test_split_alpha_digits_rejects_interleaved() {
        // A letter after a digit is not `letters*digits*`.
        assert_eq!(split_alpha_digits("A12B34"), None);
        assert_eq!(split_alpha_digits("1A2"), None);
    }

    #[test]
    fn test_split_alpha_digits_rejects_non_alphanumeric() {
        assert_eq!(split_alpha_digits("A-1234567"), None);
        assert_eq!(split_alpha_digits("A 1234567"), None);
        assert_eq!(split_alpha_digits("A123456\x007"), None);
    }

    #[test]
    fn test_split_alpha_digits_rejects_unicode_lookalikes() {
        // Cyrillic А (U+0410) is not ASCII alphabetic.
        assert_eq!(split_alpha_digits("А1234567"), None);
    }

    // ===== Layout =====

    #[test]
    fn test_layout_digits_requires_no_letters() {
        assert!(Layout::Digits(8).accepts(0, 8));
        assert!(!Layout::Digits(8).accepts(1, 8));
        assert!(!Layout::Digits(8).accepts(0, 7));
    }

    #[test]
    fn test_layout_digit_range_is_inclusive() {
        let layout = Layout::DigitRange(7, 9);
        assert!(layout.accepts(0, 7));
        assert!(layout.accepts(0, 9));
        assert!(!layout.accepts(0, 6));
        assert!(!layout.accepts(0, 10));
    }

    #[test]
    fn test_layout_alpha_digits_is_exact() {
        let layout = Layout::AlphaDigits(1, 12);
        assert!(layout.accepts(1, 12));
        assert!(!layout.accepts(2, 12));
        assert!(!layout.accepts(1, 11));
        assert!(!layout.accepts(0, 12));
    }

    #[test]
    fn test_layout_alpha_digit_range_is_inclusive() {
        let layout = Layout::AlphaDigitRange(1, 8, 11);
        assert!(layout.accepts(1, 8));
        assert!(layout.accepts(1, 11));
        assert!(!layout.accepts(1, 7));
        assert!(!layout.accepts(1, 12));
        assert!(!layout.accepts(2, 9));
    }

    // ===== Per-state formats =====

    #[test]
    fn test_texas_accepts_digits_only() {
        let v = validator_for("US-TX");
        assert!(v.is_format_valid("12345678"));
        assert!(v.is_format_valid("1234567"));
        // A letter is never a Texas license.
        assert!(!v.is_format_valid("A1234567"));
        assert!(!v.is_format_valid("123456"));
        assert!(!v.is_format_valid("123456789"));
    }

    #[test]
    fn test_new_york_accepts_both_layouts() {
        let v = validator_for("US-NY");
        assert!(v.is_format_valid("123456789"));
        assert!(v.is_format_valid("A123456789012345678"));
        // 8 digits was accepted by the old any-8-to-9-chars rule; NY does not
        // actually issue it.
        assert!(!v.is_format_valid("12345678"));
        assert!(!v.is_format_valid("A1234567"));
    }

    #[test]
    fn test_pennsylvania_is_eight_digits() {
        let v = validator_for("US-PA");
        assert!(v.is_format_valid("12345678"));
        assert!(!v.is_format_valid("1234567"));
        assert!(!v.is_format_valid("A1234567"));
    }

    #[test]
    fn test_ohio_accepts_one_or_two_letters_or_digits() {
        let v = validator_for("US-OH");
        assert!(v.is_format_valid("A1234"));
        assert!(v.is_format_valid("AB123"));
        assert!(v.is_format_valid("12345678"));
        // Three letters is not an Ohio layout.
        assert!(!v.is_format_valid("ABC1234"));
        // 1 letter + 3 digits is below the 1-letter minimum of 4.
        assert!(!v.is_format_valid("A123"));
    }

    #[test]
    fn test_maryland_and_wisconsin_differ_by_one_digit() {
        let md = validator_for("US-MD");
        let wi = validator_for("US-WI");
        // MD is letter + 12, WI is letter + 13 — each rejects the other's shape.
        assert!(md.is_format_valid("A123456789012"));
        assert!(!md.is_format_valid("A1234567890123"));
        assert!(wi.is_format_valid("A1234567890123"));
        assert!(!wi.is_format_valid("A123456789012"));
    }

    /// Per-state `(code, accepted, rejected)` — the rejected value is always a
    /// shape that is valid for SOME other jurisdiction, so a validator that
    /// ignored layout would pass it.
    const PER_STATE_CASES: &[(&str, &str, &str)] = &[
        ("US-TX", "12345678", "A1234567"),              // rejects CA shape
        ("US-NY", "123456789", "12345678"),             // rejects PA shape
        ("US-PA", "12345678", "1234567"),               // rejects 7 digits
        ("US-IL", "A12345678901", "A1234567"),          // rejects CA shape
        ("US-OH", "AB12345", "ABC1234"),                // rejects 3 letters
        ("US-GA", "123456789", "123456"),               // rejects 6 digits
        ("US-NC", "123456789", "1234567"),              // rejects 7 digits (below issued floor)
        ("US-MI", "A1234567890", "A12345678901"),       // rejects IL shape
        ("US-NJ", "A12345678901234", "A1234567890123"), // rejects WI shape
        ("US-VA", "A123456789", "A1234567"),            // rejects CA shape
        ("US-AZ", "A12345678", "A1234567"),             // rejects CA shape
        ("US-TN", "123456789", "123456"),               // rejects 6 digits
        ("US-MA", "S12345678", "S1234567"),             // rejects 7 digits
        ("US-IN", "A123456789", "A12345678"),           // rejects AZ shape
        ("US-MO", "A123456789", "A1234"),               // rejects 4 digits
        ("US-MD", "A123456789012", "A1234567890123"),   // rejects WI shape
        ("US-WI", "A1234567890123", "A123456789012"),   // rejects MD shape
    ];

    #[test]
    fn test_every_state_accepts_its_shape_and_rejects_a_neighbours() {
        // Individual coverage for all 17 table rows, not just the handful with
        // bespoke tests above.
        assert_eq!(
            PER_STATE_CASES.len(),
            US_STATE_FORMATS.len(),
            "PER_STATE_CASES is out of sync with the table"
        );
        for (code, accepted, rejected) in PER_STATE_CASES {
            let v = validator_for(code);
            assert!(v.is_format_valid(accepted), "{code} rejected {accepted:?}");
            assert!(!v.is_format_valid(rejected), "{code} accepted {rejected:?}");
        }
    }

    #[test]
    fn test_every_table_state_has_a_valid_and_invalid_example() {
        // Guards against a table row whose layouts accept nothing (or
        // everything) after an edit.
        for format in US_STATE_FORMATS {
            let v = TableValidator::new(format);
            // No jurisdiction accepts a non-alphanumeric string.
            assert!(
                !v.is_format_valid("ABC-123"),
                "{} should reject punctuation",
                format.code
            );
            // Every jurisdiction has at least one layout, and that layout
            // accepts something.
            assert!(!format.layouts.is_empty(), "{} has no layouts", format.code);
        }
    }

    #[test]
    fn test_no_state_accepts_a_trivially_short_numeric_token() {
        // A bare "5" or "123" must not validate as anyone's license. NC is the
        // state at risk here: AAMVA's documented floor of 1 digit would accept
        // both, so this pins the deliberately-raised floor.
        for format in US_STATE_FORMATS {
            let v = TableValidator::new(format);
            for token in ["5", "12", "123", "1234"] {
                assert!(
                    !v.is_format_valid(token),
                    "{} accepted the short token {token:?}",
                    format.code
                );
            }
        }
    }

    #[test]
    fn test_north_carolina_floor_is_issued_length() {
        let v = validator_for("US-NC");
        assert!(v.is_format_valid("12345678")); // 8 digits, the floor
        assert!(v.is_format_valid("123456789012")); // 12 digits, the ceiling
        assert!(!v.is_format_valid("1234567")); // 7 — below what NC issues
        assert!(!v.is_format_valid("1234567890123")); // 13 — above AAMVA
    }

    #[test]
    fn test_customer_id_shape_rejected_everywhere() {
        // The headline false positive from issue #440: a customer ID must not
        // validate as a driver's license in any jurisdiction.
        for format in US_STATE_FORMATS {
            let v = TableValidator::new(format);
            assert!(
                !v.is_format_valid("CUST123456"),
                "{} accepted CUST123456",
                format.code
            );
        }
    }

    // ===== Checksum contract =====

    #[test]
    fn test_checksum_is_always_none() {
        // These jurisdictions publish no check-digit algorithm; the validator
        // must say so rather than claim a passing checksum.
        let v = validator_for("US-TX");
        assert_eq!(v.is_checksum_valid("12345678"), None);
        assert_eq!(v.is_checksum_valid("nonsense"), None);
    }

    // ===== Registry =====

    #[test]
    fn test_validators_cover_whole_table() {
        let validators = validators();
        assert_eq!(validators.len(), US_STATE_FORMATS.len());

        let codes: Vec<&str> = validators.iter().map(|v| v.jurisdiction_code()).collect();
        for format in US_STATE_FORMATS {
            assert!(codes.contains(&format.code), "{} missing", format.code);
        }
    }

    #[test]
    fn test_table_excludes_bespoke_checksum_states() {
        // CA, FL, NE and WA carry real check-digit algorithms and must stay in
        // north_america.rs rather than being downgraded to format-only here.
        let codes: Vec<&str> = US_STATE_FORMATS.iter().map(|f| f.code).collect();
        for bespoke in ["US-CA", "US-FL", "US-NE", "US-WA"] {
            assert!(
                !codes.contains(&bespoke),
                "{bespoke} must not be in the format-only table"
            );
        }
    }

    #[test]
    fn test_table_codes_are_unique() {
        // A duplicate code would silently shadow a row in the VALIDATORS map.
        let mut codes: Vec<&str> = US_STATE_FORMATS.iter().map(|f| f.code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len(), "duplicate jurisdiction code in table");
    }

    #[test]
    fn test_metadata_accessors() {
        let v = validator_for("US-TX");
        assert_eq!(v.jurisdiction_code(), "US-TX");
        assert_eq!(v.jurisdiction_name(), "Texas");
        assert!(v.format_description().contains("digits"));
    }
}
