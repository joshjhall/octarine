//! Age expression patterns
//!
//! Patterns for detecting ages in free text. Used by HIPAA Safe Harbor
//! redaction (§164.514(b)(2)(i)(B)) which requires aggregating ages > 89.
//!
//! Capture group 1 always holds the numeric portion (or the decade word
//! for the lexical pattern) so callers can extract the value.

#![allow(clippy::expect_used)]
// SAFETY: All regex patterns in this module are hardcoded and verified at
// compile time. Regex::new() only fails on invalid syntax, caught during
// development. expect() is safe for static patterns that never change.

use once_cell::sync::Lazy;
use regex::Regex;

/// "NN-year-old" / "NN year old" — capture group 1 is the numeric age.
pub static YEAR_OLD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d{1,3})[- ]year[- ]old\b").expect("BUG: Invalid regex pattern"));

/// "age NN" / "aged NN" / "age: NN" — capture group 1 is the numeric age.
pub static AGE_LABEL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bage[d]?\s*[:=]?\s*(\d{1,3})\b").expect("BUG: Invalid regex pattern")
});

/// "NN y.o." / "NN yo" / "NN yrs" — capture group 1 is the numeric age.
pub static SHORT_FORM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(\d{1,3})\s*(?:y\.?o\.?|yrs?\.?)\b").expect("BUG: Invalid regex pattern")
});

/// "in his/her/their twenties|thirties|...|nineties" — capture group 1
/// is the decade word (twenties, thirties, ..., nineties).
pub static DECADE_LEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\bin (?:his|her|their) (twenties|thirties|forties|fifties|sixties|seventies|eighties|nineties)\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// All age patterns in order.
pub fn all() -> Vec<&'static Regex> {
    vec![&*YEAR_OLD, &*AGE_LABEL, &*SHORT_FORM, &*DECADE_LEX]
}
