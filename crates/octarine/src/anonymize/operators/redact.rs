//! Redact operator — deletes the matched span entirely.
//!
//! `Redact` is the "make it gone" transform: the span is replaced with the
//! empty string, leaving no marker or hint of the original content. It takes no
//! parameters.

use octarine_problem::Result;

use super::super::OperatorConfig;
use super::super::operator::Operator;

/// Removes the matched span by replacing it with an empty string.
///
/// Unlike [`Replace`](super::Replace), which leaves a `<TAG>` placeholder,
/// `Redact` deletes the span outright. This exercises the engine's zero-width
/// replacement path: surrounding text closes up around the deleted span and the
/// recorded output offsets collapse to a single point.
///
/// # Examples
///
/// ```
/// use octarine::anonymize::{Operator, OperatorConfig, Redact};
///
/// let config = OperatorConfig::new("redact")?;
/// assert_eq!(Redact.operate("123-45-6789", "US_SSN", &config)?, "");
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Redact;

impl Operator for Redact {
    fn operate(&self, _text: &str, _entity_type: &str, _config: &OperatorConfig) -> Result<String> {
        Ok(String::new())
    }

    fn operator_name(&self) -> &'static str {
        "redact"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;

    use serde_json::json;

    use super::super::super::OperatorType;
    use super::*;

    #[test]
    fn returns_empty_string() {
        let config = OperatorConfig::new("redact").expect("valid config");
        let out = Redact
            .operate("123-45-6789", "US_SSN", &config)
            .expect("operate");
        assert_eq!(out, "");
    }

    #[test]
    fn ignores_input_and_params() {
        // Redact is unconditional: any input, any (extra) params → empty string.
        let mut params = HashMap::new();
        params.insert("ignored".to_string(), json!("whatever"));
        let config = OperatorConfig::with_params("redact", params).expect("valid config");
        let out = Redact
            .operate("naïve multibyte 🔒", "NOTE", &config)
            .expect("operate");
        assert_eq!(out, "");
    }

    #[test]
    fn validate_is_noop() {
        assert!(
            Redact
                .validate(&OperatorConfig::new("redact").expect("cfg"))
                .is_ok()
        );
    }

    #[test]
    fn name_and_type() {
        assert_eq!(Redact.operator_name(), "redact");
        assert_eq!(Redact.operator_type(), OperatorType::Anonymize);
    }
}
