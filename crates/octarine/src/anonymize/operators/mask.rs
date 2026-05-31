//! Mask operator — positionally masks characters of a span.
//!
//! `Mask` replaces a fixed number of characters at the start (or, with
//! `from_end`, the tail) of a detected span with a mask **unit**. It is the
//! canonical PAN/phone tail-mask transform: mask the leading digits of a card
//! and show the last four, or vice versa.
//!
//! # Octarine vs Presidio
//!
//! Two deliberate improvements over Presidio's `Mask`:
//!
//! - **Multi-character mask units.** Presidio validates `masking_char` to a
//!   single character; octarine accepts any non-empty string, so `"**"` or
//!   `"XX"` are valid units (each masked position expands to the whole unit).
//!   There is no security reason for the single-char limit.
//! - **Explicit rejection of invalid parameters.** Presidio silently no-ops on
//!   a negative `chars_to_mask`; octarine fails fast with a
//!   [`Problem`](octarine_problem::Problem) so a misconfigured pipeline is
//!   caught at [`validate`](Operator::validate) time, before any output is
//!   built.
//!
//! # The transformation is single-sourced
//!
//! The actual masking is performed by the shared primitive
//! `primitives::identifiers::mask_chars`, the same positional masker the PII
//! redactor and identifier sanitizers build on. This operator only parses and
//! validates parameters, then delegates — so "mask N characters" has exactly
//! one implementation.

use octarine_problem::{Problem, Result};
use serde_json::Value;

use super::super::operator::Operator;
use super::super::{OperatorConfig, OperatorType};
use crate::primitives::identifiers::mask_chars;

/// Parameter key holding the mask unit (one or more characters).
const PARAM_MASKING_CHAR: &str = "masking_char";
/// Parameter key holding the number of characters to mask.
const PARAM_CHARS_TO_MASK: &str = "chars_to_mask";
/// Parameter key selecting tail-masking.
const PARAM_FROM_END: &str = "from_end";

/// Masks a fixed number of characters at one end of the matched span.
///
/// Parameters (read from the [`OperatorConfig`]):
///
/// - `masking_char` (**required**): the mask unit, any non-empty string. Each
///   masked character position is replaced by the entire unit, so `"*"` keeps
///   the length and `"XX"` doubles each masked position.
/// - `chars_to_mask` (**required**): a non-negative integer. Values larger than
///   the span's character length are clamped to that length. A negative or
///   non-integer value is rejected.
/// - `from_end` (optional, default `false`): mask the trailing characters
///   instead of the leading ones.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
///
/// use octarine::anonymize::{Mask, Operator, OperatorConfig};
/// use serde_json::json;
///
/// // Tail-mask the last 12 characters of a PAN with '*'.
/// let mut params = HashMap::new();
/// params.insert("masking_char".to_string(), json!("*"));
/// params.insert("chars_to_mask".to_string(), json!(12));
/// params.insert("from_end".to_string(), json!(true));
/// let config = OperatorConfig::with_params("mask", params)?;
///
/// // The leading "4111-11" is kept; the trailing 12 characters become '*'.
/// assert_eq!(
///     Mask.operate("4111-1111-1111-1234", "CREDIT_CARD", &config)?,
///     "4111-11************",
/// );
///
/// // Multi-character mask units are allowed (Presidio rejects these).
/// let mut params = HashMap::new();
/// params.insert("masking_char".to_string(), json!("XX"));
/// params.insert("chars_to_mask".to_string(), json!(3));
/// let config = OperatorConfig::with_params("mask", params)?;
/// assert_eq!(Mask.operate("secret", "PASSWORD", &config)?, "XXXXXXret");
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Mask;

/// The validated `mask` parameter triple: `(unit, chars_to_mask, from_end)`.
type MaskParams = (String, usize, bool);

impl Mask {
    /// Parses and validates the operator parameters once, so
    /// [`validate`](Operator::validate) and [`operate`](Operator::operate)
    /// share a single source of truth.
    fn parse_params(config: &OperatorConfig) -> Result<MaskParams> {
        // masking_char: required, non-empty string.
        let unit = match config.param_str(PARAM_MASKING_CHAR) {
            Some(s) if !s.is_empty() => s.to_string(),
            Some(_) => {
                return Err(Problem::Validation(
                    "mask operator: 'masking_char' must be a non-empty string".to_string(),
                ));
            }
            None => {
                return Err(Problem::Validation(
                    "mask operator: 'masking_char' is required".to_string(),
                ));
            }
        };

        // chars_to_mask: required, non-negative integer. `as_u64` returns None
        // for negative, fractional, or non-numeric values — so the silent
        // no-op on a negative count (the Presidio bug) becomes an explicit
        // failure here.
        let chars_to_mask = match config.params.get(PARAM_CHARS_TO_MASK) {
            Some(value) => value.as_u64().ok_or_else(|| {
                Problem::Validation(format!(
                    "mask operator: 'chars_to_mask' must be a non-negative integer, got {value}"
                ))
            })?,
            None => {
                return Err(Problem::Validation(
                    "mask operator: 'chars_to_mask' is required".to_string(),
                ));
            }
        };
        // usize is 64-bit on supported targets, but guard the cast explicitly so
        // a 32-bit target rejects an out-of-range count rather than truncating.
        let chars_to_mask = usize::try_from(chars_to_mask).map_err(|_| {
            Problem::Validation(format!(
                "mask operator: 'chars_to_mask' ({chars_to_mask}) exceeds the addressable range"
            ))
        })?;

        // from_end: optional bool, default false; reject a present-but-non-bool.
        let from_end = match config.params.get(PARAM_FROM_END) {
            Some(Value::Bool(b)) => *b,
            Some(other) => {
                return Err(Problem::Validation(format!(
                    "mask operator: 'from_end' must be a boolean, got {other}"
                )));
            }
            None => false,
        };

        Ok((unit, chars_to_mask, from_end))
    }
}

impl Operator for Mask {
    fn operate(&self, text: &str, _entity_type: &str, config: &OperatorConfig) -> Result<String> {
        let (unit, chars_to_mask, from_end) = Self::parse_params(config)?;
        Ok(mask_chars(text, &unit, chars_to_mask, from_end))
    }

    /// Validates the `masking_char`, `chars_to_mask`, and `from_end` parameters
    /// up front so a misconfigured operator fails before any output is built.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `masking_char` is missing or empty,
    /// if `chars_to_mask` is missing or not a non-negative integer, or if
    /// `from_end` is present but not a boolean.
    fn validate(&self, config: &OperatorConfig) -> Result<()> {
        Self::parse_params(config).map(|_| ())
    }

    fn operator_name(&self) -> &'static str {
        "mask"
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;

    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    /// Builds a `mask` config from raw JSON params.
    fn mask_config(params: HashMap<String, Value>) -> OperatorConfig {
        OperatorConfig::with_params("mask", params).expect("valid config")
    }

    /// Convenience for the common `(masking_char, chars_to_mask, from_end)` case.
    fn mask_config_of(unit: Value, count: Value, from_end: Option<bool>) -> OperatorConfig {
        let mut params = HashMap::new();
        params.insert(PARAM_MASKING_CHAR.to_string(), unit);
        params.insert(PARAM_CHARS_TO_MASK.to_string(), count);
        if let Some(b) = from_end {
            params.insert(PARAM_FROM_END.to_string(), json!(b));
        }
        mask_config(params)
    }

    #[test]
    fn masks_from_start_by_default() {
        let config = mask_config_of(json!("*"), json!(4), None);
        let out = Mask.operate("1234567890", "X", &config).expect("operate");
        assert_eq!(out, "****567890");
    }

    #[test]
    fn masks_from_end_when_requested() {
        let config = mask_config_of(json!("*"), json!(4), Some(true));
        let out = Mask.operate("1234567890", "X", &config).expect("operate");
        assert_eq!(out, "123456****");
    }

    #[test]
    fn accepts_multi_char_mask_unit() {
        // Octarine beats Presidio: multi-char units are allowed.
        let config = mask_config_of(json!("XX"), json!(2), None);
        let out = Mask.operate("abcd", "X", &config).expect("operate");
        assert_eq!(out, "XXXXcd");

        let config = mask_config_of(json!("**"), json!(2), Some(true));
        let out = Mask.operate("abcd", "X", &config).expect("operate");
        assert_eq!(out, "ab****");
    }

    #[test]
    fn clamps_count_to_char_length() {
        let config = mask_config_of(json!("*"), json!(99), None);
        let out = Mask.operate("abc", "X", &config).expect("operate");
        assert_eq!(out, "***");
    }

    #[test]
    fn rejects_negative_chars_to_mask_not_silent_noop() {
        // The headline anti-pattern: Presidio silently no-ops; octarine rejects.
        let config = mask_config_of(json!("*"), json!(-1), None);
        assert!(Mask.validate(&config).is_err());
        assert!(Mask.operate("abc", "X", &config).is_err());
    }

    #[test]
    fn rejects_fractional_chars_to_mask() {
        let config = mask_config_of(json!("*"), json!(2.5), None);
        assert!(Mask.validate(&config).is_err());
    }

    #[test]
    fn rejects_non_numeric_chars_to_mask() {
        let config = mask_config_of(json!("*"), json!("4"), None);
        assert!(Mask.validate(&config).is_err());
    }

    #[test]
    fn rejects_missing_chars_to_mask() {
        let mut params = HashMap::new();
        params.insert(PARAM_MASKING_CHAR.to_string(), json!("*"));
        let config = mask_config(params);
        assert!(Mask.validate(&config).is_err());
    }

    #[test]
    fn rejects_empty_masking_char() {
        let config = mask_config_of(json!(""), json!(4), None);
        assert!(Mask.validate(&config).is_err());
    }

    #[test]
    fn rejects_non_string_masking_char() {
        let config = mask_config_of(json!(42), json!(4), None);
        assert!(Mask.validate(&config).is_err());
    }

    #[test]
    fn rejects_missing_masking_char() {
        let mut params = HashMap::new();
        params.insert(PARAM_CHARS_TO_MASK.to_string(), json!(4));
        let config = mask_config(params);
        assert!(Mask.validate(&config).is_err());
    }

    #[test]
    fn rejects_non_bool_from_end() {
        let mut params = HashMap::new();
        params.insert(PARAM_MASKING_CHAR.to_string(), json!("*"));
        params.insert(PARAM_CHARS_TO_MASK.to_string(), json!(4));
        params.insert(PARAM_FROM_END.to_string(), json!("yes"));
        let config = mask_config(params);
        assert!(Mask.validate(&config).is_err());
    }

    #[test]
    fn validate_accepts_good_config() {
        let config = mask_config_of(json!("*"), json!(0), Some(false));
        assert!(Mask.validate(&config).is_ok());
    }

    #[test]
    fn masks_by_char_not_byte() {
        // UTF-8 safety: count characters, not bytes.
        let config = mask_config_of(json!("*"), json!(2), Some(true));
        let out = Mask.operate("café", "X", &config).expect("operate");
        assert_eq!(out, "ca**");

        let config = mask_config_of(json!("*"), json!(2), None);
        let out = Mask.operate("😀😀😀😀", "X", &config).expect("operate");
        assert_eq!(out, "**😀😀");
    }

    #[test]
    fn name_and_type() {
        assert_eq!(Mask.operator_name(), "mask");
        assert_eq!(Mask.operator_type(), OperatorType::Anonymize);
    }

    proptest! {
        /// PAN tail-mask: masking the last 12 of a 16-digit-with-separators PAN
        /// always preserves the leading characters verbatim and replaces every
        /// trailing masked position with the mask char.
        #[test]
        fn pan_tail_mask_preserves_prefix_and_masks_tail(
            d in proptest::collection::vec(0u8..10, 16)
        ) {
            // Build "dddd-dddd-dddd-dddd" (19 chars: 16 digits + 3 hyphens).
            const DIGITS: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
            let mut pan = String::new();
            for (i, digit) in d.iter().enumerate() {
                if i > 0 && i % 4 == 0 {
                    pan.push('-');
                }
                pan.push(*DIGITS.get(usize::from(*digit)).unwrap_or(&'0'));
            }

            let config = mask_config_of(json!("*"), json!(12), Some(true));
            let out = Mask.operate(&pan, "CREDIT_CARD", &config).expect("operate");

            let pan_chars: Vec<char> = pan.chars().collect();
            let out_chars: Vec<char> = out.chars().collect();
            // Same total length (single-char unit preserves length).
            prop_assert_eq!(out_chars.len(), pan_chars.len());
            let keep = pan_chars.len().saturating_sub(12);
            // Leading `keep` characters are untouched.
            prop_assert_eq!(out_chars.get(..keep), pan_chars.get(..keep));
            // Every remaining position is the mask char.
            prop_assert!(
                out_chars
                    .get(keep..)
                    .is_some_and(|tail| tail.iter().all(|&c| c == '*'))
            );
        }
    }
}
