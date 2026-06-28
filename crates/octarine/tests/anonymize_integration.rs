//! Integration tests for the Layer 3 `anonymize` engine.
//!
//! Exercises the public `octarine::anonymize` surface — the
//! [`AnonymizerEngine`], the [`BatchAnonymizerEngine`], the
//! [`BatchDeanonymizeEngine`], the `anonymize`/`redact_all` shortcuts, and the
//! built-in `Replace`/`Redact`/`Encrypt`/`Decrypt` operators — through the same
//! re-export paths a downstream consumer uses. The detection inputs are shaped
//! like real recognizer output (`RecognizerResult` spans over a fixed string)
//! so that the end-to-end detect → anonymize flow is covered, not just unit
//! behaviour.

#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use std::collections::HashMap;

use octarine::anonymize::{
    AnonymizerEngine, BatchAnonymizerEngine, BatchDeanonymizeEngine, ConflictResolutionStrategy,
    Operator, OperatorConfig, OperatorResult, OperatorType, RecognizerResult, anonymize,
    redact_all,
};

/// Builds a detection result, panicking on invalid spans (test-only).
fn detect(entity: &str, start: usize, end: usize, score: f64) -> RecognizerResult {
    RecognizerResult::new(entity, start, end, score).expect("valid detection")
}

/// 32 zero bytes, base64url-no-pad — a fixed AEAD key for round-trip tests.
const KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// A single-entity operator map naming `op` (`encrypt`/`decrypt`) with `KEY_B64`.
fn keyed_ops(op: &str, entity: &str) -> HashMap<String, OperatorConfig> {
    let mut params = HashMap::new();
    params.insert("key".to_string(), serde_json::json!(KEY_B64));
    let mut ops = HashMap::new();
    ops.insert(
        entity.to_string(),
        OperatorConfig::with_params(op, params).expect("cfg"),
    );
    ops
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

#[test]
fn batch_anonymize_list_through_public_api() {
    // The batch engine, reached through the public re-export, anonymizes a
    // small slice with one detection list per text, preserving input order.
    let batch = BatchAnonymizerEngine::new();
    let texts = ["SSN 123-45-6789", "no pii", "call jane@x.io"];
    let results = vec![
        vec![detect("US_SSN", 4, 15, 0.99)],
        vec![],
        vec![detect("EMAIL_ADDRESS", 5, 14, 0.95)],
    ];

    let out = batch
        .anonymize_list(&texts, &results, &HashMap::new())
        .expect("anonymize_list");

    assert_eq!(out.len(), 3);
    assert_eq!(
        out.first().and_then(|r| r.text.as_deref()),
        Some("SSN <US_SSN>")
    );
    assert_eq!(out.get(1).and_then(|r| r.text.as_deref()), Some("no pii"));
    assert_eq!(
        out.get(2).and_then(|r| r.text.as_deref()),
        Some("call <EMAIL_ADDRESS>")
    );
}

#[test]
fn batch_anonymize_dict_through_public_api() {
    // A realistic nested document: anonymize the emails of two users and pass
    // the numeric `age` through unchanged, preserving structure.
    let batch = BatchAnonymizerEngine::new();
    let input = serde_json::json!({
        "users": [
            { "email": "a@b.co", "age": 30 },
            { "email": "c@d.co", "age": 41 },
        ]
    });

    let mut by_path = HashMap::new();
    by_path.insert(
        "users.0.email".to_string(),
        vec![detect("EMAIL_ADDRESS", 0, 6, 0.95)],
    );
    by_path.insert(
        "users.1.email".to_string(),
        vec![detect("EMAIL_ADDRESS", 0, 6, 0.95)],
    );

    let mut operators = HashMap::new();
    operators.insert(
        "EMAIL_ADDRESS".to_string(),
        OperatorConfig::new("redact").expect("cfg"),
    );

    let out = batch
        .anonymize_dict(&input, &by_path, &operators)
        .expect("anonymize_dict");

    assert_eq!(
        out,
        serde_json::json!({
            "users": [
                { "email": "", "age": 30 },
                { "email": "", "age": 41 },
            ]
        })
    );
}

#[test]
fn batch_anonymize_list_length_mismatch_is_rejected() {
    let batch = BatchAnonymizerEngine::new();
    let texts = ["a", "b"];
    let results = vec![vec![]]; // one list for two texts
    let err = batch.anonymize_list(&texts, &results, &HashMap::new());
    assert!(err.is_err(), "length mismatch should error");
}

#[test]
fn batch_deanonymize_list_round_trips_through_public_surface() {
    // Anonymize a batch with `encrypt`, then reverse it with the public
    // `BatchDeanonymizeEngine::deanonymize_list` — the path a real consumer hits
    // (re-export wiring, method signatures, EngineResult.items handoff).
    let texts = ["SSN 123-45-6789.", "SSN 987-65-4321."];
    let results = vec![
        vec![detect("US_SSN", 4, 15, 0.95)],
        vec![detect("US_SSN", 4, 15, 0.95)],
    ];
    let sealed = BatchAnonymizerEngine::new()
        .anonymize_list(&texts, &results, &keyed_ops("encrypt", "US_SSN"))
        .expect("anonymize_list");

    let sealed_texts: Vec<&str> = sealed
        .iter()
        .map(|r| r.text.as_deref().expect("text"))
        .collect();
    let items: Vec<Vec<OperatorResult>> = sealed.iter().map(|r| r.items.clone()).collect();

    let restored = BatchDeanonymizeEngine::new()
        .deanonymize_list(&sealed_texts, &items, &keyed_ops("decrypt", "US_SSN"))
        .expect("deanonymize_list");

    assert_eq!(restored.len(), 2);
    assert_eq!(
        restored.first().and_then(|r| r.text.as_deref()),
        Some("SSN 123-45-6789."),
        "first item round-trips"
    );
    assert_eq!(
        restored.get(1).and_then(|r| r.text.as_deref()),
        Some("SSN 987-65-4321."),
        "second item round-trips"
    );
}

#[test]
fn batch_deanonymize_lenient_keeps_failed_item_anonymized() {
    // Default (lenient) mode: one item that cannot be reversed (wrong key) is
    // left anonymized while the rest of the batch reverses — the documented
    // symmetric-error-semantics contract, checked at the integration level.
    let sealed = BatchAnonymizerEngine::new()
        .anonymize_list(
            &["SSN 123-45-6789."],
            &[vec![detect("US_SSN", 4, 15, 0.95)]],
            &keyed_ops("encrypt", "US_SSN"),
        )
        .expect("anonymize_list");
    let sealed_first = sealed.first().expect("sealed item");
    let sealed_text = sealed_first.text.clone().expect("text");

    let texts = [sealed_text.as_str(), "no pii"];
    let items = vec![sealed_first.items.clone(), vec![]];

    // A different all-ones key fails the tag check on item 0.
    let mut wrong = keyed_ops("decrypt", "US_SSN");
    wrong.insert(
        "US_SSN".to_string(),
        OperatorConfig::with_params("decrypt", {
            let mut p = HashMap::new();
            p.insert(
                "key".to_string(),
                serde_json::json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
            );
            p
        })
        .expect("cfg"),
    );

    let restored = BatchDeanonymizeEngine::new()
        .deanonymize_list(&texts, &items, &wrong)
        .expect("lenient batch must not abort");

    assert_eq!(restored.len(), 2);
    // Item 0 stays anonymized (the safe value); item 1 passes through.
    assert_eq!(
        restored.first().and_then(|r| r.text.as_deref()),
        Some(sealed_text.as_str())
    );
    assert_eq!(
        restored.get(1).and_then(|r| r.text.as_deref()),
        Some("no pii")
    );
}

#[test]
fn batch_deanonymize_strict_aborts_on_failure() {
    // strict() opts into fail-fast: a wrong-key item fails the whole batch.
    let sealed = BatchAnonymizerEngine::new()
        .anonymize_list(
            &["SSN 123-45-6789."],
            &[vec![detect("US_SSN", 4, 15, 0.95)]],
            &keyed_ops("encrypt", "US_SSN"),
        )
        .expect("anonymize_list");
    let sealed_texts: Vec<&str> = sealed
        .iter()
        .map(|r| r.text.as_deref().expect("text"))
        .collect();
    let items: Vec<Vec<OperatorResult>> = sealed.iter().map(|r| r.items.clone()).collect();

    let mut wrong = HashMap::new();
    wrong.insert(
        "US_SSN".to_string(),
        OperatorConfig::with_params("decrypt", {
            let mut p = HashMap::new();
            p.insert(
                "key".to_string(),
                serde_json::json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
            );
            p
        })
        .expect("cfg"),
    );

    let err =
        BatchDeanonymizeEngine::new()
            .strict()
            .deanonymize_list(&sealed_texts, &items, &wrong);
    assert!(err.is_err(), "strict mode should abort on a failed item");
}
