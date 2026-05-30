//! Convenience shortcuts over a default [`AnonymizerEngine`].
//!
//! These free functions cover the common cases without constructing an engine.
//! For custom operators, conflict strategies, or silent mode, build an
//! [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine) directly.

use std::collections::HashMap;

use octarine_problem::Result;

use super::{AnonymizerEngine, EngineResult, OperatorConfig, RecognizerResult};

/// Anonymizes `text`, applying `operators` per entity type.
///
/// Entities with no operator entry fall back to the built-in `replace`
/// operator (producing `<ENTITY_TYPE>`), unless a `DEFAULT` key is present.
///
/// # Errors
///
/// Propagates any [`Problem`](octarine_problem::Problem) from
/// [`AnonymizerEngine::anonymize`].
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use octarine::anonymize::{anonymize, OperatorConfig, RecognizerResult};
///
/// let mut ops = HashMap::new();
/// ops.insert("EMAIL_ADDRESS".to_string(), OperatorConfig::new("redact")?);
/// let results = vec![RecognizerResult::new("EMAIL_ADDRESS", 3, 14, 0.95)?];
/// let out = anonymize("a: foo@bar.com", results, &ops)?;
/// assert_eq!(out.text.as_deref(), Some("a: "));
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
pub fn anonymize(
    text: &str,
    results: Vec<RecognizerResult>,
    operators: &HashMap<String, OperatorConfig>,
) -> Result<EngineResult> {
    AnonymizerEngine::new().anonymize(text, results, operators)
}

/// Anonymizes `text` by deleting every detected span (the `redact` operator).
///
/// # Errors
///
/// Propagates any [`Problem`](octarine_problem::Problem) from
/// [`AnonymizerEngine::anonymize`].
///
/// # Examples
///
/// ```
/// use octarine::anonymize::{redact_all, RecognizerResult};
///
/// let results = vec![RecognizerResult::new("US_SSN", 4, 15, 0.9)?];
/// let out = redact_all("SSN 123-45-6789.", results)?;
/// assert_eq!(out.text.as_deref(), Some("SSN ."));
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
pub fn redact_all(text: &str, results: Vec<RecognizerResult>) -> Result<EngineResult> {
    let redact = OperatorConfig::new("redact")?;
    let mut operators = HashMap::new();
    operators.insert("DEFAULT".to_string(), redact);
    AnonymizerEngine::new().anonymize(text, results, &operators)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn anonymize_shortcut_defaults_to_replace() {
        let results = vec![RecognizerResult::new("PERSON", 0, 3, 0.9).expect("rr")];
        let out = anonymize("Bob waved", results, &HashMap::new()).expect("anon");
        assert_eq!(out.text.as_deref(), Some("<PERSON> waved"));
    }

    #[test]
    fn redact_all_deletes_every_span() {
        let results = vec![
            RecognizerResult::new("PERSON", 0, 3, 0.9).expect("rr"),
            RecognizerResult::new("PERSON", 8, 11, 0.9).expect("rr"),
        ];
        let out = redact_all("Bob and Joe", results).expect("anon");
        assert_eq!(out.text.as_deref(), Some(" and "));
        assert_eq!(out.items.len(), 2);
    }
}
