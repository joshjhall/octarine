//! Integration tests for the Layer 3 `anonymize` engine.
//!
//! Exercises the public `octarine::anonymize` surface — the
//! [`AnonymizerEngine`], the `anonymize`/`redact_all` shortcuts, and the
//! built-in `Replace`/`Redact` operators — through the same re-export paths a
//! downstream consumer uses. The detection inputs are shaped like real
//! recognizer output (`RecognizerResult` spans over a fixed string) so that
//! the end-to-end detect → anonymize flow is covered, not just unit behaviour.

#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use std::collections::HashMap;

use octarine::anonymize::{
    AnonymizerEngine, ConflictResolutionStrategy, Operator, OperatorConfig, OperatorType,
    RecognizerResult, anonymize, redact_all,
};

/// Builds a detection result, panicking on invalid spans (test-only).
fn detect(entity: &str, start: usize, end: usize, score: f64) -> RecognizerResult {
    RecognizerResult::new(entity, start, end, score).expect("valid detection")
}

#[test]
fn default_replace_tags_every_entity() {
    // "Email jane@x.io or call Bob" with two detections.
    //  E0 m1 a2 i3 l4 ' '5 j6 a7 n8 e9 @10 x11 .12 i13 o14 ' '15 o16 r17 ' '18
    //  c19 a20 l21 l22 ' '23 B24 o25 b26
    let text = "Email jane@x.io or call Bob";
    let results = vec![
        detect("EMAIL_ADDRESS", 6, 15, 0.95),
        detect("PERSON", 24, 27, 0.90),
    ];

    let out = anonymize(text, results, &HashMap::new()).expect("anonymize");

    assert_eq!(
        out.text.as_deref(),
        Some("Email <EMAIL_ADDRESS> or call <PERSON>")
    );
    assert_eq!(out.items.len(), 2);

    let email = out.items.first().expect("email item");
    assert_eq!(email.entity_type, "EMAIL_ADDRESS");
    assert_eq!(email.operator.as_deref(), Some("replace"));
    assert_eq!(email.text.as_deref(), Some("<EMAIL_ADDRESS>"));
    // Output offsets index into the rewritten text.
    assert_eq!(
        out.text
            .as_deref()
            .and_then(|t| t.get(email.start..email.end)),
        Some("<EMAIL_ADDRESS>")
    );
}

#[test]
fn per_entity_operator_map_mixes_redact_and_replace() {
    let text = "SSN 123-45-6789 for jane@x.io";
    //  S0 S1 N2 ' '3 [4..15 = "123-45-6789"] ' '15 f16 o17 r18 ' '19 [20..29 = "jane@x.io"]
    let results = vec![
        detect("US_SSN", 4, 15, 0.99),
        detect("EMAIL_ADDRESS", 20, 29, 0.95),
    ];

    let mut operators = HashMap::new();
    operators.insert(
        "US_SSN".to_string(),
        OperatorConfig::new("redact").expect("cfg"),
    );
    // EMAIL_ADDRESS has no entry → falls back to default replace tag.

    let out = anonymize(text, results, &operators).expect("anonymize");

    assert_eq!(out.text.as_deref(), Some("SSN  for <EMAIL_ADDRESS>"));
    assert_eq!(out.items.len(), 2);
}

#[test]
fn redact_all_shortcut_deletes_everything() {
    let text = "Bob met Joe";
    let results = vec![detect("PERSON", 0, 3, 0.9), detect("PERSON", 8, 11, 0.9)];

    let out = redact_all(text, results).expect("redact_all");

    assert_eq!(out.text.as_deref(), Some(" met "));
    assert_eq!(out.items.len(), 2);
    assert!(out.items.iter().all(|i| i.text.as_deref() == Some("")));
}

#[test]
fn explicit_new_value_overrides_default_tag() {
    let text = "Hi Bob";
    let results = vec![detect("PERSON", 3, 6, 0.9)];

    let mut params = HashMap::new();
    params.insert("new_value".to_string(), serde_json::json!("[name]"));
    let mut operators = HashMap::new();
    operators.insert(
        "PERSON".to_string(),
        OperatorConfig::with_params("replace", params).expect("cfg"),
    );

    let out = anonymize(text, results, &operators).expect("anonymize");
    assert_eq!(out.text.as_deref(), Some("Hi [name]"));
}

#[test]
fn overlapping_detections_resolved_by_default_strategy() {
    // Two overlapping spans over "Big Name"; higher score wins under the
    // default MergeSimilarOrContained strategy.
    let text = "Big Name";
    let results = vec![detect("ORG", 0, 8, 0.5), detect("PERSON", 0, 8, 0.9)];

    let out = anonymize(text, results, &HashMap::new()).expect("anonymize");
    assert_eq!(out.text.as_deref(), Some("<PERSON>"));
    assert_eq!(out.items.len(), 1);
}

#[test]
fn unknown_operator_is_rejected() {
    let text = "Bob";
    let results = vec![detect("PERSON", 0, 3, 0.9)];
    let mut operators = HashMap::new();
    operators.insert(
        "PERSON".to_string(),
        OperatorConfig::new("does-not-exist").expect("cfg"),
    );

    let err = anonymize(text, results, &operators);
    assert!(err.is_err(), "unknown operator should error");
}

#[test]
fn engine_accepts_a_custom_operator() {
    // A consumer-supplied operator registered via the builder API.
    struct Star;
    impl Operator for Star {
        fn operate(
            &self,
            text: &str,
            _entity_type: &str,
            _config: &OperatorConfig,
        ) -> Result<String, octarine::observe::Problem> {
            Ok("*".repeat(text.chars().count()))
        }
        fn operator_name(&self) -> &'static str {
            "star"
        }
        fn operator_type(&self) -> OperatorType {
            OperatorType::Anonymize
        }
    }

    let engine = AnonymizerEngine::new()
        .with_operator(Box::new(Star))
        .with_conflict_strategy(ConflictResolutionStrategy::None);

    let mut operators = HashMap::new();
    operators.insert(
        "PERSON".to_string(),
        OperatorConfig::new("star").expect("cfg"),
    );

    let out = engine
        .anonymize("Hi Bob", vec![detect("PERSON", 3, 6, 0.9)], &operators)
        .expect("anonymize");
    assert_eq!(out.text.as_deref(), Some("Hi ***"));
}
