//! Replace operator — substitutes a fixed value, defaulting to `<ENTITY_TYPE>`.
//!
//! `Replace` is the engine-wide default: when no explicit operator is
//! configured for an entity, the engine applies `Replace`, producing tagged
//! output like `<PERSON>` or `<US_SSN>`.

use octarine_problem::Result;

use super::super::operator::Operator;
use super::super::{OperatorConfig, OperatorType};

/// Parameter key holding the explicit replacement value.
const PARAM_NEW_VALUE: &str = "new_value";

/// Replaces the matched span with a fixed string.
///
/// Behaviour:
///
/// - If the config has a non-empty `new_value` parameter, the span is replaced
///   with that value.
/// - Otherwise the span is replaced with `<{entity_type}>` (the Presidio
///   default), e.g. an entity typed `EMAIL_ADDRESS` becomes `<EMAIL_ADDRESS>`.
///
/// # Examples
///
/// ```
/// use octarine::anonymize::{Operator, OperatorConfig, Replace};
///
/// // Fallback: no new_value configured.
/// let config = OperatorConfig::new("replace")?;
/// assert_eq!(Replace.operate("Jane Roe", "PERSON", &config)?, "<PERSON>");
///
/// // Explicit replacement value.
/// let mut params = std::collections::HashMap::new();
/// params.insert("new_value".to_string(), serde_json::json!("[redacted]"));
/// let config = OperatorConfig::with_params("replace", params)?;
/// assert_eq!(Replace.operate("Jane Roe", "PERSON", &config)?, "[redacted]");
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Replace;

impl Operator for Replace {
    fn operate(&self, _text: &str, entity_type: &str, config: &OperatorConfig) -> Result<String> {
        match config.param_str(PARAM_NEW_VALUE) {
            Some(value) if !value.is_empty() => Ok(value.to_string()),
            _ => Ok(format!("<{entity_type}>")),
        }
    }

    fn operator_name(&self) -> &'static str {
        "replace"
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn config_with_new_value(value: serde_json::Value) -> OperatorConfig {
        let mut params = HashMap::new();
        params.insert(PARAM_NEW_VALUE.to_string(), value);
        OperatorConfig::with_params("replace", params).expect("valid config")
    }

    #[test]
    fn falls_back_to_entity_tag_when_no_new_value() {
        let config = OperatorConfig::new("replace").expect("valid config");
        let out = Replace
            .operate("123-45-6789", "US_SSN", &config)
            .expect("operate");
        assert_eq!(out, "<US_SSN>");
    }

    #[test]
    fn falls_back_to_entity_tag_when_new_value_empty() {
        // An empty new_value is treated as "not provided" — fall back to the tag.
        let config = config_with_new_value(json!(""));
        let out = Replace
            .operate("Jane Roe", "PERSON", &config)
            .expect("operate");
        assert_eq!(out, "<PERSON>");
    }

    #[test]
    fn uses_explicit_new_value() {
        let config = config_with_new_value(json!("[REDACTED]"));
        let out = Replace
            .operate("Jane Roe", "PERSON", &config)
            .expect("operate");
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn ignores_non_string_new_value_and_falls_back() {
        // A non-string new_value is not a usable replacement; fall back.
        let config = config_with_new_value(json!(42));
        let out = Replace
            .operate("x", "PHONE_NUMBER", &config)
            .expect("operate");
        assert_eq!(out, "<PHONE_NUMBER>");
    }

    #[test]
    fn handles_multibyte_entity_and_value() {
        let config = config_with_new_value(json!("«caché»"));
        let out = Replace
            .operate("naïve", "RÉSUMÉ", &config)
            .expect("operate");
        assert_eq!(out, "«caché»");
    }

    #[test]
    fn validate_accepts_any_config() {
        assert!(
            Replace
                .validate(&OperatorConfig::new("replace").expect("cfg"))
                .is_ok()
        );
        assert!(Replace.validate(&config_with_new_value(json!(""))).is_ok());
    }

    #[test]
    fn name_and_type() {
        assert_eq!(Replace.operator_name(), "replace");
        assert_eq!(Replace.operator_type(), OperatorType::Anonymize);
    }
}
